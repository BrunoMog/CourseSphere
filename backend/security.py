"""
AppSec Hardening Module for CourseSphere:
- Shared Multi-Worker / Multi-Replica Rate Limiting & Brute-Force Lockout (CWE-307 / CWE-770)
- Memory-Hard Password Hashing with scrypt & Constant-Time Verification (CWE-916)
- Signed Session Tokens with Expiration (JWT-like HMAC-SHA256 with exp claim, zero hardcoded secrets)
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

try:
    from backend.db import create_connection
except ImportError:
    from db import create_connection

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_FALLBACK_EPHEMERAL_SECRET = secrets.token_hex(32)


def get_secret_key() -> str:
    """
    Retrieves the cryptographic signing secret from the environment (`COURSESPHERE_SECRET_KEY`).
    - In production (`COURSESPHERE_ENV=production` or `FLASK_ENV=production`), fails closed if unset.
    - In local dev/test without an env var, generates a CSPRNG ephemeral key stored in `app_config`
      so multiple local workers share the same dynamic secret without any hardcoded secret in source code.
    """
    env_key = os.environ.get("COURSESPHERE_SECRET_KEY", "").strip()
    if env_key:
        return env_key

    env_mode = (os.environ.get("COURSESPHERE_ENV") or os.environ.get("FLASK_ENV") or "").lower()
    if env_mode == "production":
        raise RuntimeError(
            "CRITICAL: COURSESPHERE_SECRET_KEY environment variable must be configured in production."
        )

    try:
        conn = create_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT value FROM app_config WHERE key = ?", ("ephemeral_secret_key",))
            row = cur.fetchone()
            if row and row["value"]:
                return str(row["value"])
            generated = secrets.token_hex(32)
            cur.execute(
                "INSERT OR IGNORE INTO app_config (key, value) VALUES (?, ?)",
                ("ephemeral_secret_key", generated),
            )
            conn.commit()
            cur.execute("SELECT value FROM app_config WHERE key = ?", ("ephemeral_secret_key",))
            row = cur.fetchone()
            return str(row["value"]) if row else generated
        finally:
            conn.close()
    except Exception:
        return _FALLBACK_EPHEMERAL_SECRET


# ---------------------------------------------------------
# 1. Shared Rate Limiter & Brute-Force Lockout
# ---------------------------------------------------------
class RateLimiter:
    """
    Multi-process / multi-replica sliding window rate limiter and failed-authentication
    lockout manager backed by the shared database (with thread-safe fallback).
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
        self._lock = Lock()

    def is_locked_out(self, identifier: str) -> Tuple[bool, int]:
        """Checks if an IP or account identifier is currently locked out across any replica."""
        now = time.time()
        with self._lock:
            conn = create_connection()
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT locked_until FROM auth_lockouts WHERE client_key = ?",
                    (identifier,),
                )
                row = cur.fetchone()
                if not row:
                    return False, 0
                unlock_time = float(row["locked_until"] or 0.0)
                if unlock_time > now:
                    return True, int(unlock_time - now) + 1
                if unlock_time > 0.0 and unlock_time <= now:
                    cur.execute("DELETE FROM auth_lockouts WHERE client_key = ?", (identifier,))
                    conn.commit()
                return False, 0
            finally:
                conn.close()

    def record_auth_failure(self, identifier: str) -> Tuple[bool, int]:
        """Records a failed authentication attempt in the shared store and triggers lockout if exceeded."""
        now = time.time()
        with self._lock:
            conn = create_connection()
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT fail_count, window_start, locked_until FROM auth_lockouts WHERE client_key = ?",
                    (identifier,),
                )
                row = cur.fetchone()
                if not row or (now - float(row["window_start"] or 0.0)) >= self.window_seconds:
                    fail_count = 1
                    window_start = now
                else:
                    fail_count = int(row["fail_count"] or 0) + 1
                    window_start = float(row["window_start"])

                locked_until = 0.0
                is_locked = False
                if fail_count >= self.max_failed_auth:
                    locked_until = now + self.lockout_seconds
                    is_locked = True

                cur.execute(
                    """
                    INSERT INTO auth_lockouts (client_key, fail_count, window_start, locked_until)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(client_key) DO UPDATE SET
                        fail_count = excluded.fail_count,
                        window_start = excluded.window_start,
                        locked_until = excluded.locked_until
                    """,
                    (identifier, fail_count, window_start, locked_until),
                )
                conn.commit()
                return is_locked, (self.lockout_seconds if is_locked else 0)
            finally:
                conn.close()

    def clear_auth_failures(self, identifier: str):
        with self._lock:
            conn = create_connection()
            try:
                conn.execute("DELETE FROM auth_lockouts WHERE client_key = ?", (identifier,))
                conn.commit()
            finally:
                conn.close()

    def check_rate_limit(self, key: str, limit: Optional[int] = None) -> Tuple[bool, int, int]:
        """
        Checks whether `key` is within the allowed request rate across all workers/replicas.
        Returns (allowed: bool, remaining: int, retry_after: int).
        """
        max_reqs = limit or self.default_limit
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            conn = create_connection()
            try:
                cur = conn.cursor()
                cur.execute(
                    "DELETE FROM rate_limit_events WHERE bucket_key = ? AND ts <= ?",
                    (key, cutoff),
                )
                cur.execute(
                    "SELECT COUNT(*), MIN(ts) FROM rate_limit_events WHERE bucket_key = ?",
                    (key,),
                )
                row = cur.fetchone()
                count = int(row[0] or 0)
                oldest = float(row[1] or now)
                if count >= max_reqs:
                    conn.commit()
                    retry_after = max(1, int(self.window_seconds - (now - oldest)))
                    return False, 0, retry_after

                cur.execute(
                    "INSERT INTO rate_limit_events (bucket_key, ts) VALUES (?, ?)",
                    (key, now),
                )
                conn.commit()
                remaining = max(0, max_reqs - (count + 1))
                return True, remaining, 0
            finally:
                conn.close()

    def reset(self):
        with self._lock:
            conn = create_connection()
            try:
                conn.execute("DELETE FROM rate_limit_events;")
                conn.execute("DELETE FROM auth_lockouts;")
                conn.commit()
            finally:
                conn.close()


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
    secret_key = get_secret_key()
    now = int(time.time())
    payload = {
        "uid": uid,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": secrets.token_hex(8),
    }
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")
    sig = hmac.new(secret_key.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
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
    secret_key = get_secret_key()
    expected_sig = hmac.new(secret_key.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
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
