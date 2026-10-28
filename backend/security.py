"""
AppSec Hardening Module for CourseSphere:
- Rate Limiting & Brute-Force Account/IP Lockout (CWE-307 / CWE-770)
- Memory-Hard Password Hashing with scrypt & Constant-Time Verification (CWE-916)
- Signed Session Tokens with Expiration (JWT-like HMAC-SHA256 with exp claim)
- Consistent Input Validation & HTML/XSS Sanitization (CWE-20 / CWE-79)
- CSRF & Origin/Content-Type Verification for State-Changing Routes (CWE-352)
"""

import os
import re
import html
import time
import json
import hmac
import base64
import hashlib
import secrets
from threading import Lock
from typing import Tuple, Optional, Dict, Any

SECRET_KEY = os.environ.get(
    "COURSESPHERE_SECRET_KEY",
    "coursesphere-default-dev-secret-key-change-in-prod"
)

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


# ---------------------------------------------------------
# 1. Rate Limiter & Brute-Force Lockout
# ---------------------------------------------------------
class RateLimiter:
    """
    Thread-safe sliding window rate limiter and failed-authentication lockout manager.
    """
    def __init__(
        self,
        default_limit: int = 60,
        window_seconds: int = 60,
        max_failed_auth: int = 5,
        lockout_seconds: int = 300,
    ):
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        self.max_failed_auth = max_failed_auth
        self.lockout_seconds = lockout_seconds
        self._requests: Dict[str, list] = {}
        self._failed_auth: Dict[str, list] = {}
        self._lockouts: Dict[str, float] = {}
        self._lock = Lock()

    def is_locked_out(self, identifier: str) -> Tuple[bool, int]:
        """Checks if an IP or account identifier is currently locked out due to brute force."""
        now = time.time()
        with self._lock:
            unlock_time = self._lockouts.get(identifier, 0.0)
            if unlock_time > now:
                return True, int(unlock_time - now) + 1
            if identifier in self._lockouts:
                del self._lockouts[identifier]
        return False, 0

    def record_auth_failure(self, identifier: str) -> Tuple[bool, int]:
        """Records a failed authentication attempt and triggers lockout if threshold exceeded."""
        now = time.time()
        with self._lock:
            attempts = [t for t in self._failed_auth.get(identifier, []) if now - t < self.window_seconds]
            attempts.append(now)
            self._failed_auth[identifier] = attempts
            if len(attempts) >= self.max_failed_auth:
                unlock_time = now + self.lockout_seconds
                self._lockouts[identifier] = unlock_time
                return True, self.lockout_seconds
        return False, 0

    def clear_auth_failures(self, identifier: str):
        with self._lock:
            self._failed_auth.pop(identifier, None)
            self._lockouts.pop(identifier, None)

    def check_rate_limit(self, key: str, limit: Optional[int] = None) -> Tuple[bool, int, int]:
        """
        Checks whether `key` is within the allowed request rate.
        Returns (allowed: bool, remaining: int, retry_after: int).
        """
        max_reqs = limit or self.default_limit
        now = time.time()
        with self._lock:
            history = [t for t in self._requests.get(key, []) if now - t < self.window_seconds]
            if len(history) >= max_reqs:
                oldest = history[0]
                retry_after = max(1, int(self.window_seconds - (now - oldest)))
                self._requests[key] = history
                return False, 0, retry_after
            history.append(now)
            self._requests[key] = history
            remaining = max(0, max_reqs - len(history))
            return True, remaining, 0

    def reset(self):
        with self._lock:
            self._requests.clear()
            self._failed_auth.clear()
            self._lockouts.clear()


rate_limiter = RateLimiter(
    default_limit=int(os.environ.get("RATE_LIMIT_PER_MINUTE", 60)),
    window_seconds=60,
    max_failed_auth=int(os.environ.get("MAX_FAILED_AUTH_ATTEMPTS", 5)),
    lockout_seconds=int(os.environ.get("AUTH_LOCKOUT_SECONDS", 300)),
)


# ---------------------------------------------------------
# 2. Password Hashing (scrypt) & Expiring Session Tokens
# ---------------------------------------------------------
def hash_password(password: str) -> str:
    """
    Hashes a password using memory-hard scrypt KDF (RFC 7914) with a 16-byte CSPRNG salt.
    Format: scrypt$n$r$p$<salt_hex>$<hash_hex>
    """
    if not password or len(password) < 6:
        raise ValueError("Password must be at least 6 characters long.")
    salt = secrets.token_bytes(16)
    n, r, p = 16384, 8, 1
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32
    )
    return f"scrypt${n}${r}${p}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies a plaintext password against a stored scrypt hash in constant time.
    """
    try:
        parts = stored_hash.split("$")
        if len(parts) != 6 or parts[0] != "scrypt":
            return False
        _, n_str, r_str, p_str, salt_hex, hash_hex = parts
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n_str),
            r=int(r_str),
            p=int(p_str),
            dklen=len(expected),
        )
        return hmac.compare_digest(candidate, expected)
    except Exception:
        return False


def create_session_token(uid: str, ttl_seconds: int = 3600) -> str:
    """
    Generates an HMAC-SHA256 signed token with an explicit expiration timestamp (`exp`).
    """
    now = int(time.time())
    payload = {
        "uid": uid,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": secrets.token_hex(8),
    }
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"csjwt.{payload_b64}.{sig}"


def verify_session_token(token: str) -> Dict[str, Any]:
    """
    Verifies an HMAC-SHA256 signed session token and enforces expiration (`exp`).
    """
    if not token or not token.startswith("csjwt."):
        raise ValueError("Unsupported session token format.")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed session token.")
    _, payload_b64, sig = parts
    expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        raise ValueError("Invalid token signature.")
    padding = "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding).decode("utf-8"))
    if int(time.time()) >= int(payload.get("exp", 0)):
        raise ValueError("Session token has expired.")
    return payload


# ---------------------------------------------------------
# 3. Consistent Input Validation & XSS Sanitization
# ---------------------------------------------------------
def sanitize_string(value: Any, max_length: int = 500) -> str:
    """
    Sanitizes string inputs by trimming whitespace, removing null bytes,
    truncating to max_length, and escaping HTML characters to prevent XSS (CWE-79).
    """
    if value is None:
        return ""
    cleaned = str(value).replace("\x00", "").strip()
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    return html.escape(cleaned, quote=True)


def validate_email(email: str) -> bool:
    if not email or len(email) > 254:
        return False
    return bool(EMAIL_REGEX.match(email))


def validate_course_payload(data: Dict[str, Any], partial: bool = False) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Validates and sanitizes payload for creating or updating a course.
    """
    if not isinstance(data, dict):
        return None, "Invalid JSON payload."

    required = ["name", "semester", "department", "instructor"]
    if not partial:
        for req in required:
            if not data.get(req) or not str(data.get(req)).strip():
                return None, f"Field '{req}' is required."

    sanitized: Dict[str, Any] = {}
    for field in ["name", "semester", "department", "instructor", "description"]:
        if field in data and data[field] is not None:
            val = sanitize_string(data[field], max_length=1000 if field == "description" else 200)
            if not val and field in required:
                return None, f"Field '{field}' cannot be empty."
            sanitized[field] = val

    if "section_id" in data and data["section_id"] is not None:
        try:
            section_id = int(data["section_id"])
            if section_id < 0:
                return None, "Field 'section_id' must be a non-negative integer."
            sanitized["section_id"] = section_id
        except (ValueError, TypeError):
            return None, "Field 'section_id' must be a valid integer."

    return sanitized, None


# ---------------------------------------------------------
# 4. CSRF & State-Changing Request Protection
# ---------------------------------------------------------
def verify_state_changing_request(request, allowed_origins: list) -> Optional[str]:
    """
    Protects state-changing routes (POST, PUT, DELETE, PATCH) against Cross-Site Request Forgery (CSRF):
    1. Enforces 'application/json' Content-Type (prevents HTML form submission CSRF).
    2. Validates 'Origin' header if present against allowed origins.
    """
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        content_type = request.headers.get("Content-Type", "")
        has_body = bool(request.content_length and request.content_length > 0) or bool(request.data) or bool(request.form)
        if has_body and not content_type.lower().startswith("application/json"):
            return "Unsupported Content-Type. State-changing requests must use 'application/json'."

        origin = request.headers.get("Origin")
        if origin and allowed_origins and "*" not in allowed_origins:
            if origin not in allowed_origins:
                return "CSRF validation failed: Origin is not permitted."
    return None
