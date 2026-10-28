import os
import time
import json
import uuid
import logging
from flask import Flask, request, jsonify, g
from flask_cors import CORS

from main import hashFunction
from firebase import Firebase
from security import (
    rate_limiter,
    sanitize_string,
    validate_email,
    verify_state_changing_request,
)
from resilience import CIRCUIT_BREAKERS, CircuitBreakerOpenException

try:
    from blueprints.courses import courses_bp
except ImportError:
    from backend.blueprints.courses import courses_bp

# ---------------------------------------------------------
# SRE Requirement: Structured JSON Logging
# ---------------------------------------------------------
class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "instance_id": os.environ.get("INSTANCE_ID", "backend-standalone"),
            "request_id": getattr(record, "request_id", None) or getattr(g, "request_id", "-"),
            "path": getattr(record, "path", None) or (request.path if request else "-"),
            "method": getattr(record, "method", None) or (request.method if request else "-"),
        }
        if hasattr(record, "status_code"):
            log_record["status_code"] = record.status_code
        if hasattr(record, "duration_ms"):
            log_record["duration_ms"] = record.duration_ms
        if hasattr(record, "event_type"):
            log_record["event_type"] = record.event_type
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record)


logger = logging.getLogger("coursesphere")
handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger.handlers = [handler]
logger.setLevel(logging.INFO)

# ---------------------------------------------------------
# Flask Application Setup
# ---------------------------------------------------------
app = Flask(__name__)
INSTANCE_ID = os.environ.get("INSTANCE_ID", "backend-standalone")

# Security Hardening: Restrict CORS origins instead of wildcard '*'
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://localhost,http://127.0.0.1",
    ).split(",")
    if o.strip()
]
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)

# Register courses blueprint safely
app.register_blueprint(courses_bp)

# In-memory Prometheus metrics registry for SRE compliance
METRICS = {
    "http_requests_total": {},
    "http_request_duration_seconds_sum": 0.0,
    "http_request_duration_seconds_count": 0,
    "http_request_duration_buckets": {0.01: 0, 0.05: 0, 0.1: 0, 0.2: 0, 0.5: 0, 1.0: 0, float("inf"): 0},
    "auth_events_total": {"success": 0, "failure": 0, "lockout": 0},
    "rate_limit_exceeded_total": 0,
}

success_response = lambda data, code: (jsonify(data), code)
error_response = lambda error, code: (jsonify({"error": error}), code)


def _get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


@app.before_request
def before_request():
    g.start_time = time.time()
    g.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

    # Exempt observability probes from rate limiting
    if request.path in ("/health", "/metrics"):
        return None

    client_ip = _get_client_ip()

    # 1. Check Brute-Force Lockout
    locked, retry_after = rate_limiter.is_locked_out(client_ip)
    if locked:
        METRICS["auth_events_total"]["lockout"] += 1
        logger.warning(
            f"Blocked request from locked-out IP {client_ip}",
            extra={"event_type": "auth_lockout"},
        )
        resp = jsonify({"error": "Too many failed authentication attempts. Account/IP temporarily locked."})
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        return resp

    # 2. Check General Rate Limiting
    allowed, remaining, retry_after = rate_limiter.check_rate_limit(f"ip:{client_ip}")
    g.rate_limit_remaining = remaining
    if not allowed:
        METRICS["rate_limit_exceeded_total"] += 1
        logger.warning(
            f"Rate limit exceeded for IP {client_ip} on {request.path}",
            extra={"event_type": "rate_limit_exceeded"},
        )
        resp = jsonify({"error": "Rate limit exceeded. Please slow down requests."})
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        return resp

    # 3. Check CSRF / State-Changing Request Protection
    csrf_err = verify_state_changing_request(request, ALLOWED_ORIGINS)
    if csrf_err:
        logger.warning(f"CSRF/Content-Type check failed: {csrf_err}", extra={"event_type": "csrf_blocked"})
        return error_response(csrf_err, 415 if "Content-Type" in csrf_err else 403)


@app.after_request
def after_request(response):
    duration = time.time() - getattr(g, "start_time", time.time())

    # Record Prometheus metrics including latency histogram buckets (for SLI/SLO P95/200ms tracking)
    key = (request.method, request.path, response.status_code)
    METRICS["http_requests_total"][key] = METRICS["http_requests_total"].get(key, 0) + 1
    METRICS["http_request_duration_seconds_sum"] += duration
    METRICS["http_request_duration_seconds_count"] += 1
    for bucket in METRICS["http_request_duration_buckets"]:
        if duration <= bucket:
            METRICS["http_request_duration_buckets"][bucket] += 1

    # Hardening: Comprehensive HTTP Security Headers (OWASP A05)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none';"
    )
    response.headers["X-Request-ID"] = getattr(g, "request_id", "")
    response.headers["X-Served-By"] = INSTANCE_ID
    if hasattr(g, "rate_limit_remaining"):
        response.headers["X-RateLimit-Remaining"] = str(g.rate_limit_remaining)

    # Structured JSON access log
    logger.info(
        f"{request.method} {request.path} {response.status_code} - {duration * 1000:.2f}ms",
        extra={
            "request_id": getattr(g, "request_id", "-"),
            "path": request.path,
            "method": request.method,
            "status_code": response.status_code,
            "duration_ms": round(duration * 1000, 2),
        },
    )
    return response


# ---------------------------------------------------------
# SRE Observability Endpoints: /health & /metrics
# ---------------------------------------------------------
@app.route("/health", methods=["GET"])
def health_check():
    """Liveness and Readiness probe endpoint for Docker & Kubernetes orchestrators."""
    from db import create_connection

    db_status = "healthy"
    try:
        def _ping_db():
            conn = create_connection()
            conn.execute("SELECT 1").fetchall()
            conn.close()

        CIRCUIT_BREAKERS["database"].call(_ping_db)
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "unhealthy"

    cb_states = {name: cb.state_name for name, cb in CIRCUIT_BREAKERS.items()}
    status = "UP" if db_status == "healthy" else "DEGRADED"
    code = 200 if status == "UP" else 503
    return jsonify({
        "status": status,
        "instance_id": INSTANCE_ID,
        "database": db_status,
        "circuit_breakers": cb_states,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }), code


@app.route("/metrics", methods=["GET"])
def metrics():
    """Prometheus-compatible plain text metrics exposition (OpenMetrics format)."""
    lines = [
        "# HELP http_requests_total Total number of HTTP requests processed.",
        "# TYPE http_requests_total counter",
    ]
    for (method, path, status), count in METRICS["http_requests_total"].items():
        lines.append(f'http_requests_total{{method="{method}",path="{path}",status="{status}"}} {count}')

    lines.extend([
        "# HELP http_request_duration_seconds Request duration histogram in seconds.",
        "# TYPE http_request_duration_seconds histogram",
    ])
    for bound, count in METRICS["http_request_duration_buckets"].items():
        le_label = "+Inf" if bound == float("inf") else str(bound)
        lines.append(f'http_request_duration_seconds_bucket{{le="{le_label}"}} {count}')
    lines.extend([
        f'http_request_duration_seconds_sum {METRICS["http_request_duration_seconds_sum"]:.6f}',
        f'http_request_duration_seconds_count {METRICS["http_request_duration_seconds_count"]}',
        "# HELP auth_events_total Total count of authentication events by outcome.",
        "# TYPE auth_events_total counter",
        f'auth_events_total{{status="success"}} {METRICS["auth_events_total"]["success"]}',
        f'auth_events_total{{status="failure"}} {METRICS["auth_events_total"]["failure"]}',
        f'auth_events_total{{status="lockout"}} {METRICS["auth_events_total"]["lockout"]}',
        "# HELP rate_limit_exceeded_total Total requests rejected by rate limiter.",
        "# TYPE rate_limit_exceeded_total counter",
        f'rate_limit_exceeded_total {METRICS["rate_limit_exceeded_total"]}',
        "# HELP circuit_breaker_state Current state of service circuit breakers (0=CLOSED, 1=HALF_OPEN, 2=OPEN).",
        "# TYPE circuit_breaker_state gauge",
    ])
    for name, cb in CIRCUIT_BREAKERS.items():
        lines.append(f'circuit_breaker_state{{service="{name}"}} {cb.state}')

    return "\n".join(lines) + "\n", 200, {"Content-Type": "text/plain; version=0.0.4"}


# ---------------------------------------------------------
# Security Helper: Safe Token Extraction (VULN-04 fix)
# ---------------------------------------------------------
def get_auth_token():
    """
    Extracts Bearer token strictly from the Authorization header (RFC 6750).
    Rejects tokens passed via URL query strings to avoid access log leakage (CWE-598).
    """
    if "id_token" in request.args:
        METRICS["auth_events_total"]["failure"] += 1
        logger.warning(
            "Rejected insecure token passed via URL query parameter.",
            extra={"event_type": "auth_failure"},
        )
        return None, "Insecure token transport: tokens must be transmitted in the Authorization HTTP header, not query parameters."

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, "Missing or malformed Authorization header. Expected 'Bearer <token>'."

    value = auth_header.split("Bearer ", 1)[1].strip()
    if not value or value in {"[object Promise]", "undefined", "null"}:
        return None, "Empty or invalid bearer token provided."
    return value, None


def verify_request_token(token: str):
    """Verifies token and tracks authentication failures for brute-force protection."""
    client_ip = _get_client_ip()
    try:
        decoded = CIRCUIT_BREAKERS["firebase"].call(Firebase.verify_id_token, token)
        METRICS["auth_events_total"]["success"] += 1
        return decoded, None
    except CircuitBreakerOpenException as exc:
        return None, (str(exc), 503)
    except Exception as exc:
        METRICS["auth_events_total"]["failure"] += 1
        locked, retry_after = rate_limiter.record_auth_failure(client_ip)
        logger.warning(
            f"Authentication verification failed for IP {client_ip}: {exc}",
            extra={"event_type": "auth_failure"},
        )
        if locked:
            return None, ("Too many failed authentication attempts. Account/IP locked.", 429)
        return None, ("Invalid or expired authentication token.", 401)


# ---------------------------------------------------------
# Authentication & User Endpoints
# ---------------------------------------------------------
@app.route("/users/create", methods=["POST"])
def create_user():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip()
    password = str(data.get("password", "")).strip()

    if not email:
        return error_response("Email is required", 400)
    if not validate_email(email):
        return error_response("Invalid email address format", 400)
    if not password:
        return error_response("Password is required", 400)
    if len(password) < 6:
        return error_response("Password must be at least 6 characters long", 400)

    try:
        user_result = CIRCUIT_BREAKERS["firebase"].call(Firebase.create_user, email, password)
        METRICS["auth_events_total"]["success"] += 1
        logger.info(f"User created successfully: {email}", extra={"event_type": "user_created"})
        return success_response(user_result, 200)
    except Exception as e:
        METRICS["auth_events_total"]["failure"] += 1
        logger.warning(f"User creation failed: {e}", extra={"event_type": "auth_failure"})
        return error_response("Failed to create user. Verify email format or password policy.", 400)


@app.route("/users/login", methods=["POST"])
def login_user():
    """
    Authenticates user credentials using scrypt password hashing and issues an
    expiring HMAC-SHA256 session token. Protected by brute-force lockout.
    """
    client_ip = _get_client_ip()
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip()
    password = str(data.get("password", "")).strip()

    if not email or not password:
        return error_response("Email and password are required", 400)

    try:
        auth_result = Firebase.authenticate_user(email, password)
        rate_limiter.clear_auth_failures(client_ip)
        METRICS["auth_events_total"]["success"] += 1
        logger.info(f"User logged in successfully: {email}", extra={"event_type": "login_success"})
        return success_response(auth_result, 200)
    except Exception as e:
        METRICS["auth_events_total"]["failure"] += 1
        locked, retry_after = rate_limiter.record_auth_failure(client_ip)
        logger.warning(f"Failed login attempt for {email} from {client_ip}: {e}", extra={"event_type": "login_failure"})
        if locked:
            METRICS["auth_events_total"]["lockout"] += 1
            resp = jsonify({"error": "Account/IP temporarily locked due to repeated failed login attempts."})
            resp.status_code = 429
            resp.headers["Retry-After"] = str(retry_after)
            return resp
        return error_response("Invalid email or password.", 401)


@app.route("/users/info", methods=["POST"])
def set_user_info():
    token, err = get_auth_token()
    data = request.get_json(silent=True) or {}

    if not token:
        token = data.get("id_token")
    if not token:
        return error_response(err or "Authentication required", 401)

    decoded, auth_err = verify_request_token(token)
    if auth_err:
        return error_response(auth_err[0], auth_err[1])

    uid = decoded.get("uid")
    try:
        majors = [sanitize_string(m, 100) for m in (data.get("majors") or []) if isinstance(m, str)]
        minors = [sanitize_string(m, 100) for m in (data.get("minors") or []) if isinstance(m, str)]
        courses = [sanitize_string(c, 100) for c in (data.get("courses") or []) if isinstance(c, str)]
        user_info = {
            "majors": majors,
            "minors": minors,
            "courses": courses,
            "college": sanitize_string(data.get("college", ""), 150),
            "year": sanitize_string(data.get("year", ""), 20),
            "about": sanitize_string(data.get("about", ""), 1000),
        }
        CIRCUIT_BREAKERS["firebase"].call(Firebase.set_user_info, uid, user_info)
        return success_response({"message": "User info set successfully", "uid": uid}, 200)
    except Exception as e:
        logger.error(f"Error setting user info: {e}")
        return error_response("Failed to update user profile.", 400)


@app.route("/users/info", methods=["GET"])
def get_user_info():
    """
    Fixed VULN-04: Accepts authentication ONLY via the Authorization header.
    Rejects tokens passed via URL parameters to prevent leakage in server access logs.
    """
    token, err = get_auth_token()
    if not token:
        return error_response(err, 401)

    decoded, auth_err = verify_request_token(token)
    if auth_err:
        return error_response(auth_err[0], auth_err[1])

    try:
        uid = decoded.get("uid")
        user_info = CIRCUIT_BREAKERS["firebase"].call(Firebase.get_user_info, uid)
        return success_response(user_info or {}, 200)
    except Exception as e:
        logger.warning(f"Error retrieving user info: {e}")
        return error_response("Failed to retrieve user profile.", 400)


@app.route("/users/query", methods=["POST"])
def get_user_query():
    """
    Fixed Missing Authentication (CWE-306): Requires valid Bearer token before
    invoking the LLM QueryManager to prevent unauthorized API quota exhaustion.
    """
    token, err = get_auth_token()
    data = request.get_json(silent=True) or {}
    if not token:
        token = data.get("id_token")
    if not token:
        return error_response(err or "Authentication required to execute queries.", 401)

    decoded, auth_err = verify_request_token(token)
    if auth_err:
        return error_response(auth_err[0], auth_err[1])

    query = str(data.get("query", "")).strip()
    if not query:
        return error_response("Query cannot be empty.", 400)
    if len(query) > 1000:
        return error_response("Query exceeds maximum allowed length of 1000 characters.", 400)

    try:
        from query_manager import QueryManager

        uid = decoded.get("uid")
        user_info = Firebase.get_user_info(uid)
        manager = CIRCUIT_BREAKERS["openai"].call(QueryManager, query, user_info)
        return success_response(manager.response, 200)
    except CircuitBreakerOpenException as e:
        logger.error(f"OpenAI Circuit Breaker open: {e}")
        return error_response("Query service temporarily unavailable. Please try again later.", 503)
    except Exception as e:
        logger.error(f"Error processing user query: {e}")
        return error_response("Error processing request.", 500)


@app.route("/hash", methods=["POST"])
def generate_message_id():
    token, err = get_auth_token()
    if not token:
        return error_response(err, 401)

    decoded, auth_err = verify_request_token(token)
    if auth_err:
        return error_response(auth_err[0], auth_err[1])

    try:
        data = request.get_json(silent=True) or {}
        message_id = hashFunction(data)
        return jsonify({"messageID": message_id}), 200
    except Exception as e:
        logger.error(f"Error generating message id: {e}")
        return error_response("Internal error generating message identifier.", 500)


@app.route("/chats/<chat_id>/messages", methods=["POST"])
def save_chat(chat_id):
    token, err = get_auth_token()
    if not token:
        return error_response(err, 401)

    decoded, auth_err = verify_request_token(token)
    if auth_err:
        return error_response(auth_err[0], auth_err[1])

    try:
        user_id = decoded.get("uid")
        messages = (request.get_json(silent=True) or {}).get("messages", [])
        Firebase.save_chat(user_id, chat_id, messages)
        return jsonify({"message": "Messages saved successfully"}), 200
    except ValueError as ve:
        logger.warning(f"Validation error saving chat messages: {ve}")
        return error_response(str(ve), 400)
    except Exception as e:
        logger.error(f"Error saving chat messages: {e}")
        return error_response("Failed to save chat messages.", 400)


@app.route("/chats/<chat_id>", methods=["DELETE"])
def delete_chat(chat_id):
    token, err = get_auth_token()
    if not token:
        return error_response(err, 401)

    decoded, auth_err = verify_request_token(token)
    if auth_err:
        return error_response(auth_err[0], auth_err[1])

    try:
        user_id = decoded.get("uid")
        Firebase.delete_chat(user_id, chat_id)
        return success_response({"message": "Message deleted successfully"}, 200)
    except ValueError as ve:
        logger.warning(f"Validation error deleting chat: {ve}")
        return error_response(str(ve), 400)
    except Exception as e:
        logger.error(f"Error deleting chat: {e}")
        return error_response("Failed to delete chat session.", 400)


# ---------------------------------------------------------
# Global Error Handlers (VULN-03 Information Disclosure fix)
# ---------------------------------------------------------
@app.errorhandler(404)
def handle_404(e):
    return error_response("Resource not found", 404)


@app.errorhandler(500)
def handle_500(e):
    logger.exception(f"Unhandled Server Error: {e}")
    return error_response("An internal server error occurred.", 500)


if __name__ == "__main__":
    # Fixed VULN-03: debug=True removed for security. Controlled via FLASK_DEBUG env var.
    debug_mode = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5000))
    app.run(host=host, port=port, debug=debug_mode)
