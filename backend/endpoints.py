import os
import time
import json
import uuid
import logging
from flask import Flask, request, jsonify, g
from flask_cors import CORS

from main import hashFunction
from firebase import Firebase

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
            "request_id": getattr(record, "request_id", None) or getattr(g, "request_id", "-"),
            "path": getattr(record, "path", None) or (request.path if request else "-"),
            "method": getattr(record, "method", None) or (request.method if request else "-"),
        }
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

# Security Hardening: Restrict CORS origins instead of wildcard '*'
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000").split(",")
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)

# Register courses blueprint safely
app.register_blueprint(courses_bp)

# In-memory Prometheus metrics registry for SRE compliance
METRICS = {
    "http_requests_total": {},
    "http_request_duration_seconds_sum": 0.0,
    "http_request_duration_seconds_count": 0,
    "auth_events_total": {"success": 0, "failure": 0}
}


@app.before_request
def before_request():
    g.start_time = time.time()
    g.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))


@app.after_request
def after_request(response):
    duration = time.time() - getattr(g, "start_time", time.time())
    
    # Record metrics
    key = (request.method, request.path, response.status_code)
    METRICS["http_requests_total"][key] = METRICS["http_requests_total"].get(key, 0) + 1
    METRICS["http_request_duration_seconds_sum"] += duration
    METRICS["http_request_duration_seconds_count"] += 1

    # Security Hardening: Default HTTP Security Headers (OWASP A05)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
    response.headers["X-Request-ID"] = getattr(g, "request_id", "")

    # Structured JSON access log
    logger.info(
        f"{request.method} {request.path} {response.status_code} - {duration * 1000:.2f}ms",
        extra={
            "request_id": getattr(g, "request_id", "-"),
            "path": request.path,
            "method": request.method,
            "status_code": response.status_code,
            "duration_ms": round(duration * 1000, 2)
        }
    )
    return response


success_response = lambda data, code: (jsonify(data), code)
error_response = lambda error, code: (jsonify({'error': error}), code)


# ---------------------------------------------------------
# SRE Observability Endpoints: /health & /metrics
# ---------------------------------------------------------
@app.route("/health", methods=["GET"])
def health_check():
    """Liveness and Readiness probe endpoint for container orchestrators."""
    from db import create_connection
    db_status = "healthy"
    try:
        conn = create_connection()
        conn.execute("SELECT 1").fetchall()
        conn.close()
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "unhealthy"

    status = "UP" if db_status == "healthy" else "DEGRADED"
    code = 200 if status == "UP" else 503
    return jsonify({
        "status": status,
        "database": db_status,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }), code


@app.route("/metrics", methods=["GET"])
def metrics():
    """Prometheus-compatible plain text metrics exposition (OpenMetrics format)."""
    lines = [
        "# HELP http_requests_total Total number of HTTP requests processed.",
        "# TYPE http_requests_total counter"
    ]
    for (method, path, status), count in METRICS["http_requests_total"].items():
        lines.append(f'http_requests_total{{method="{method}",path="{path}",status="{status}"}} {count}')
        
    lines.extend([
        "# HELP http_request_duration_seconds Request duration in seconds.",
        "# TYPE http_request_duration_seconds summary",
        f'http_request_duration_seconds_sum {METRICS["http_request_duration_seconds_sum"]:.6f}',
        f'http_request_duration_seconds_count {METRICS["http_request_duration_seconds_count"]}',
        "# HELP auth_events_total Total count of authentication attempts.",
        "# TYPE auth_events_total counter",
        f'auth_events_total{{status="success"}} {METRICS["auth_events_total"]["success"]}',
        f'auth_events_total{{status="failure"}} {METRICS["auth_events_total"]["failure"]}'
    ])
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
        logger.warning("Rejected insecure token passed via URL query parameter.")
        return None, "Insecure token transport: tokens must be transmitted in the Authorization HTTP header, not query parameters."
        
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, "Missing or malformed Authorization header. Expected 'Bearer <token>'."
        
    token = auth_header.split("Bearer ", 1)[1].strip()
    if not token:
        return None, "Empty bearer token provided."
    return token, None


# ---------------------------------------------------------
# Authentication & User Endpoints
# ---------------------------------------------------------
@app.route("/users/create", methods=["POST"])
def create_user():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    
    if not email:
        return error_response("Email is required", 400)
    if not password:
        return error_response("Password is required", 400)
    if len(password) < 6:
        return error_response("Password must be at least 6 characters long", 400)
        
    try:
        user_result = Firebase.create_user(email, password)
        METRICS["auth_events_total"]["success"] += 1
        logger.info(f"User created successfully: {email}")
        return success_response(user_result, 200)
    except Exception as e:
        METRICS["auth_events_total"]["failure"] += 1
        logger.warning(f"User creation failed: {e}")
        return error_response("Failed to create user. Verify email format or password policy.", 400)


@app.route("/users/info", methods=["POST"])
def set_user_info(): 
    token, err = get_auth_token()
    data = request.get_json(silent=True) or {}
    
    # Allow body id_token fallback only if valid, but enforce header preference
    if not token:
        token = data.get("id_token")
    if not token:
        return error_response(err or "Authentication required", 401)
        
    try:
        uid = Firebase.verify_id_token(token).get('uid')
        user_info = {
            "majors": data.get("majors", []),
            "minors": data.get("minors", []),
            "courses": data.get("courses", []),
            "college": data.get("college", ""),
            "year": data.get("year", ""),
            "about": data.get("about", "")
        }
        Firebase.set_user_info(uid, user_info) 
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

    try:
        uid = Firebase.verify_id_token(token).get('uid')
        user_info = Firebase.get_user_info(uid)
        return success_response(user_info or {}, 200)
    except Exception as e:
        logger.warning(f"Error retrieving user info: {e}")
        return error_response("Authentication failed or user profile not found.", 401)


@app.route("/users/query", methods=["POST"])
def get_user_query():
    data = request.get_json(silent=True) or {}
    query = data.get("query", "").strip()
    if not query:
        return error_response("Query cannot be empty.", 400)

    try:
        from query_manager import QueryManager
        token, _ = get_auth_token()
        if not token:
            token = data.get("id_token")
        user_info = Firebase.try_get_user_info(token) if token else None
        manager = QueryManager(query, user_info)
        return success_response(manager.response, 200)
    except Exception as e:
        logger.error(f"Error processing user query: {e}")
        return error_response("Error processing request.", 500)


@app.route('/hash', methods=['POST'])
def generate_message_id():
    token, err = get_auth_token()
    if not token:
        return error_response(err, 401)

    try:
        Firebase.verify_id_token(token)
        data = request.get_json(silent=True) or {}
        message_id = hashFunction(data)
        return jsonify({'messageID': message_id}), 200  
    except Exception as e:
        logger.error(f"Error generating message id: {e}")
        return error_response("Internal error generating message identifier.", 500)


@app.route("/chats/<chat_id>/messages", methods=["POST"])
def save_chat(chat_id):
    token, err = get_auth_token()
    if not token:
        return error_response(err, 401)

    try:
        user_id = Firebase.verify_id_token(token).get('uid')
        messages = (request.get_json(silent=True) or {}).get('messages', [])
        Firebase.save_chat(user_id, chat_id, messages)
        return jsonify({'message': 'Messages saved successfully'}), 200
    except Exception as e:
        logger.error(f"Error saving chat messages: {e}")
        return error_response("Failed to save chat messages.", 400)


@app.route("/chats/<chat_id>", methods=["DELETE"])
def delete_chat(chat_id):
    token, err = get_auth_token()
    if not token:
        return error_response(err, 401)

    try:
        user_id = Firebase.verify_id_token(token).get('uid')
        Firebase.delete_chat(user_id, chat_id)
        return success_response({'message': 'Message deleted successfully'}, 200)
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


if __name__ == '__main__':
    # Fixed VULN-03: debug=True removed for security. Controlled via FLASK_DEBUG env var.
    debug_mode = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    app.run(host=host, port=port, debug=debug_mode)
