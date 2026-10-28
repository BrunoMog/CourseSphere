import os
import time
import json
import uuid
import logging
import ipaddress
from flask import Flask, request, jsonify, g
from flask_cors import CORS

try:
    from backend.db import create_connection
    from backend.main import hashFunction
    from backend.firebase import Firebase, UserAlreadyExistsError
    from backend.security import (
        rate_limiter,
        sanitize_string,
        validate_email,
        verify_state_changing_request,
    )
    from backend.resilience import CIRCUIT_BREAKERS, CircuitBreakerOpenException
    from backend.blueprints.courses import courses_bp
except ImportError:
    from db import create_connection
    from main import hashFunction
    from firebase import Firebase, UserAlreadyExistsError
    from security import (
        rate_limiter,
        sanitize_string,
        validate_email,
        verify_state_changing_request,
    )
    from resilience import CIRCUIT_BREAKERS, CircuitBreakerOpenException
    from blueprints.courses import courses_bp

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

# Hardening: Enforce maximum HTTP request payload size (1 MB default) against memory exhaustion DoS (CWE-400)
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH_BYTES", 1024 * 1024))

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

HISTOGRAM_BUCKETS = (0.01, 0.05, 0.1, 0.2, 0.5, 1.0, float("inf"))

DEFAULT_TRUSTED_CIDRS = "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128"


def _increment_shared_metric(metric_key: str, delta: float = 1.0):
    """Atomically increments a metric counter/bucket in the shared SQLite store across Gunicorn workers."""
    try:
        conn = create_connection()
        try:
            conn.execute(
                """
                INSERT INTO prometheus_metrics (metric_key, metric_value)
                VALUES (?, ?)
                ON CONFLICT(metric_key) DO UPDATE SET
                    metric_value = prometheus_metrics.metric_value + excluded.metric_value
                """,
                (metric_key, float(delta)),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:
        logger.debug("Telemetry write skipped: %s", exc)


def _read_shared_metrics() -> dict:
    """Reads all accumulated Prometheus metrics across workers from the shared database."""
    try:
        conn = create_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT metric_key, metric_value FROM prometheus_metrics")
            return {row["metric_key"]: float(row["metric_value"]) for row in cur.fetchall()}
        finally:
            conn.close()
    except Exception:
        return {}


success_response = lambda data, code: (jsonify(data), code)
error_response = lambda error, code: (jsonify({"error": error}), code)


def _is_trusted_proxy(remote_addr: str) -> bool:
    """
    Validates whether the immediate peer IP belongs to a configured trusted reverse proxy
    using strict CIDR subnet parsing (RFC 1918 / loopback).
    """
    if os.environ.get("TRUST_PROXY_HEADERS", "0").lower() not in ("1", "true"):
        return False
    if not remote_addr:
        return False
    try:
        peer_ip = ipaddress.ip_address(remote_addr.strip())
    except ValueError:
        return False

    cidr_list = os.environ.get("TRUSTED_PROXY_CIDRS", DEFAULT_TRUSTED_CIDRS).split(",")
    for cidr_str in cidr_list:
        cidr_str = cidr_str.strip()
        if not cidr_str:
            continue
        try:
            network = ipaddress.ip_network(cidr_str, strict=False)
            if peer_ip in network:
                return True
        except ValueError:
            continue
    return False


def _get_client_ip() -> str:
    """
    Resolves the client IP safely without allowing X-Forwarded-For spoofing (CWE-290 / CWE-307).
    - Ignores X-Forwarded-For / X-Real-IP unless `TRUST_PROXY_HEADERS=1` and the immediate peer is in TRUSTED_PROXY_CIDRS.
    - When behind a trusted proxy (e.g., Nginx gateway), uses `X-Real-IP` or the rightmost proxy hop.
    """
    remote_addr = request.remote_addr or "127.0.0.1"
    if _is_trusted_proxy(remote_addr):
        real_ip = request.headers.get("X-Real-IP", "").strip()
        if real_ip:
            return real_ip
        forwarded = request.headers.get("X-Forwarded-For", "").strip()
        if forwarded:
            return forwarded.split(",")[-1].strip()
    return remote_addr


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
        _increment_shared_metric("auth_events_total:lockout", 1.0)
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
        _increment_shared_metric("rate_limit_exceeded_total", 1.0)
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

    # Use Flask route pattern instead of raw request.path to prevent cardinality explosion in Prometheus
    route_label = request.url_rule.rule if request.url_rule else "/unmatched"
    _increment_shared_metric(f"http_req:{request.method}|{route_label}|{response.status_code}", 1.0)
    _increment_shared_metric("http_duration_sum", duration)
    _increment_shared_metric("http_duration_count", 1.0)
    for bucket in HISTOGRAM_BUCKETS:
        if duration <= bucket:
            b_label = "+Inf" if bucket == float("inf") else str(bucket)
            _increment_shared_metric(f"http_bucket:{b_label}", 1.0)

    # Hardening: Comprehensive HTTP Security Headers (OWASP A05)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    if (
        request.is_secure
        or request.headers.get("X-Forwarded-Proto", "").lower() == "https"
        or os.environ.get("ENABLE_HSTS_HEADER", "1") == "1"
    ):
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
    """Prometheus-compatible plain text metrics exposition (OpenMetrics format) aggregated across workers."""
    stored = _read_shared_metrics()
    lines = [
        "# HELP http_requests_total Total number of HTTP requests processed (bounded route cardinality).",
        "# TYPE http_requests_total counter",
    ]
    for key, val in sorted(stored.items()):
        if key.startswith("http_req:"):
            parts = key[len("http_req:"):].split("|")
            if len(parts) == 3:
                method, route_rule, status = parts
                lines.append(f'http_requests_total{{method="{method}",path="{route_rule}",status="{status}"}} {int(val)}')

    lines.extend([
        "# HELP http_request_duration_seconds Request duration histogram in seconds.",
        "# TYPE http_request_duration_seconds histogram",
    ])
    for bound in HISTOGRAM_BUCKETS:
        le_label = "+Inf" if bound == float("inf") else str(bound)
        b_count = int(stored.get(f"http_bucket:{le_label}", 0))
        lines.append(f'http_request_duration_seconds_bucket{{le="{le_label}"}} {b_count}')

    dur_sum = stored.get("http_duration_sum", 0.0)
    dur_count = int(stored.get("http_duration_count", 0))
    auth_success = int(stored.get("auth_events_total:success", 0))
    auth_failure = int(stored.get("auth_events_total:failure", 0))
    auth_lockout = int(stored.get("auth_events_total:lockout", 0))
    rate_exceeded = int(stored.get("rate_limit_exceeded_total", 0))

    lines.extend([
        f"http_request_duration_seconds_sum {dur_sum:.6f}",
        f"http_request_duration_seconds_count {dur_count}",
        "# HELP auth_events_total Total count of authentication events by outcome.",
        "# TYPE auth_events_total counter",
        f'auth_events_total{{status="success"}} {auth_success}',
        f'auth_events_total{{status="failure"}} {auth_failure}',
        f'auth_events_total{{status="lockout"}} {auth_lockout}',
        "# HELP rate_limit_exceeded_total Total requests rejected by rate limiter.",
        "# TYPE rate_limit_exceeded_total counter",
        f"rate_limit_exceeded_total {rate_exceeded}",
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
    Rejects tokens passed via URL query strings or request bodies (CWE-598).
    """
    if "id_token" in request.args:
        _increment_shared_metric("auth_events_total:failure", 1.0)
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
        _increment_shared_metric("auth_events_total:success", 1.0)
        return decoded, None
    except CircuitBreakerOpenException as exc:
        return None, (str(exc), 503)
    except Exception as exc:
        _increment_shared_metric("auth_events_total:failure", 1.0)
        locked, retry_after = rate_limiter.record_auth_failure(client_ip)
        logger.warning(
            f"Authentication verification failed for IP {client_ip}: {exc}",
            extra={"event_type": "auth_failure"},
        )
        if locked:
            _increment_shared_metric("auth_events_total:lockout", 1.0)
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
        _increment_shared_metric("auth_events_total:success", 1.0)
        logger.info(f"User created successfully: {email}", extra={"event_type": "user_created"})
        return success_response(user_result, 200)
    except UserAlreadyExistsError as e:
        _increment_shared_metric("auth_events_total:failure", 1.0)
        logger.warning(f"Duplicate registration blocked for {email}: {e}", extra={"event_type": "duplicate_signup_blocked"})
        return error_response("An account with this email already exists.", 409)
    except Exception as e:
        _increment_shared_metric("auth_events_total:failure", 1.0)
        logger.warning(f"User creation failed: {e}", extra={"event_type": "auth_failure"})
        return error_response("Failed to create user. Verify email format or password policy.", 400)


@app.route("/users/login", methods=["POST"])
def login_user():
    """
    Authenticates user credentials using scrypt password hashing and issues an
    expiring HMAC-SHA256 session token. Protected by IP and account-level brute-force lockout.
    """
    client_ip = _get_client_ip()
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", "")).strip()

    if not email or not password:
        return error_response("Email and password are required", 400)

    account_key = f"acct:{email}"
    acct_locked, acct_retry = rate_limiter.is_locked_out(account_key)
    if acct_locked:
        _increment_shared_metric("auth_events_total:lockout", 1.0)
        resp = jsonify({"error": "Account temporarily locked due to repeated failed login attempts."})
        resp.status_code = 429
        resp.headers["Retry-After"] = str(acct_retry)
        return resp

    try:
        auth_result = Firebase.authenticate_user(email, password)
        rate_limiter.clear_auth_failures(client_ip)
        rate_limiter.clear_auth_failures(account_key)
        _increment_shared_metric("auth_events_total:success", 1.0)
        logger.info(f"User logged in successfully: {email}", extra={"event_type": "login_success"})
        return success_response(auth_result, 200)
    except Exception as e:
        _increment_shared_metric("auth_events_total:failure", 1.0)
        ip_locked, ip_retry = rate_limiter.record_auth_failure(client_ip)
        acct_locked, acct_retry = rate_limiter.record_auth_failure(account_key)
        logger.warning(f"Failed login attempt for {email} from {client_ip}: {e}", extra={"event_type": "login_failure"})
        if ip_locked or acct_locked:
            _increment_shared_metric("auth_events_total:lockout", 1.0)
            retry_after = max(ip_retry, acct_retry)
            resp = jsonify({"error": "Account/IP temporarily locked due to repeated failed login attempts."})
            resp.status_code = 429
            resp.headers["Retry-After"] = str(retry_after)
            return resp
        return error_response("Invalid email or password.", 401)


@app.route("/users/info", methods=["POST"])
def set_user_info():
    """
    Requires authentication exclusively via the Authorization: Bearer header.
    """
    token, err = get_auth_token()
    if not token:
        return error_response(err or "Authentication required", 401)

    decoded, auth_err = verify_request_token(token)
    if auth_err:
        return error_response(auth_err[0], auth_err[1])

    data = request.get_json(silent=True) or {}
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
    Fixed Missing Authentication (CWE-306): Requires valid Bearer token in the Authorization header
    before invoking the LLM QueryManager to prevent unauthorized API quota exhaustion.
    """
    token, err = get_auth_token()
    if not token:
        return error_response(err or "Authentication required to execute queries.", 401)

    decoded, auth_err = verify_request_token(token)
    if auth_err:
        return error_response(auth_err[0], auth_err[1])

    data = request.get_json(silent=True) or {}
    query = str(data.get("query", "")).strip()
    if not query:
        return error_response("Query cannot be empty.", 400)
    if len(query) > 1000:
        return error_response("Query exceeds maximum allowed length of 1000 characters.", 400)

    try:
        try:
            from backend.query_manager import QueryManager
        except ImportError:
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


@app.errorhandler(413)
def handle_413(e):
    return error_response("Payload too large. Maximum allowed request body is 1 MB.", 413)


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
