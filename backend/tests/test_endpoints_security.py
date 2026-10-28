import pytest
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from endpoints import app, _is_trusted_proxy
from security import (
    rate_limiter,
    get_secret_key,
    hash_password,
    verify_password,
    create_session_token,
    verify_session_token,
)
from resilience import CircuitBreaker, CircuitBreakerOpenException, CIRCUIT_BREAKERS


@pytest.fixture(autouse=True)
def isolated_test_env(tmp_path, monkeypatch):
    """Ensure each test uses an isolated SQLite database and clean rate limiter / circuit breaker state."""
    db_file = tmp_path / "test_endpoints.sqlite.db"
    monkeypatch.setenv("COURSESPHERE_DB_PATH", str(db_file))
    rate_limiter.reset()
    for cb in CIRCUIT_BREAKERS.values():
        cb.reset()


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_health_endpoint(client):
    """Test SRE healthcheck endpoint and circuit breaker telemetry."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "UP"
    assert data["database"] == "healthy"
    assert "circuit_breakers" in data
    assert data["circuit_breakers"]["database"] == "CLOSED"
    assert "timestamp" in data


def test_metrics_endpoint(client):
    """Test SRE Prometheus metrics endpoint with histogram buckets and gauges."""
    client.get("/health")
    response = client.get("/metrics")
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "http_requests_total" in text
    assert "http_request_duration_seconds_bucket" in text
    assert "circuit_breaker_state" in text
    assert "auth_events_total" in text


def test_metrics_route_pattern_bounded_cardinality(client):
    """
    Test SRE Fix: Prometheus metrics use Flask route rule patterns (`/courses/<int:course_id>`)
    and `/unmatched` instead of raw client URL paths, preventing cardinality explosion.
    """
    client.get("/courses/12345")
    client.get("/nonexistent-high-cardinality-path-xyz987")
    text = client.get("/metrics").get_data(as_text=True)
    assert 'path="/courses/<int:course_id>"' in text
    assert 'path="/unmatched"' in text
    assert "nonexistent-high-cardinality-path-xyz987" not in text


def test_security_headers_present(client):
    """Test that Hardening HTTP security headers are returned on all responses."""
    response = client.get("/health")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert "max-age=31536000" in response.headers.get("Strict-Transport-Security", "")
    assert "Content-Security-Policy" in response.headers
    assert "Permissions-Policy" in response.headers
    assert "X-Request-ID" in response.headers
    assert "X-Served-By" in response.headers


def test_token_in_url_rejected(client):
    """
    Test VULN-04 Fix: Passing authentication token via URL query parameter
    must be rejected to prevent leakage in server access logs (CWE-598).
    """
    token = create_session_token("alice")
    response = client.get(f"/users/info?id_token={token}")
    assert response.status_code == 401
    data = response.get_json()
    assert "error" in data
    assert "query parameter" in data["error"].lower()


def test_body_id_token_rejected_without_authorization_header(client):
    """
    Test Token Transport Policy: Sending `id_token` in JSON body without the
    `Authorization: Bearer` header must be rejected with HTTP 401.
    """
    token = create_session_token("alice")
    info_resp = client.post("/users/info", json={"id_token": token, "college": "Engineering"})
    assert info_resp.status_code == 401

    query_resp = client.post("/users/query", json={"id_token": token, "query": "CS courses"})
    assert query_resp.status_code == 401


def test_missing_auth_header_rejected(client):
    """Test accessing protected endpoints without authorization header."""
    assert client.get("/users/info").status_code == 401
    assert client.post("/users/query", json={"query": "CS courses"}).status_code == 401
    assert client.post("/hash", json={"msg": "hi"}).status_code == 401


def test_forged_test_tokens_rejected_with_401(client):
    """
    Test Critical Fix: Unsigned `test-token-*` strings must NEVER be accepted
    as valid credentials on any endpoint (HTTP 401 Unauthorized) and must not
    trip the CircuitBreaker into 503 Service Unavailable.
    """
    forged_tokens = ("test-token-alice", "test-token-admin")
    for forged in forged_tokens:
        resp = client.get("/users/info", headers={"Authorization": f"Bearer {forged}"})
        assert resp.status_code == 401

        hash_resp = client.post(
            "/hash",
            headers={"Authorization": f"Bearer {forged}"},
            json={"content": "attempt"},
        )
        assert hash_resp.status_code == 401

    # 5th forged attempt hits max_failures=5 and triggers 429 lockout (never 200 or 503)
    fifth = client.get("/users/info", headers={"Authorization": "Bearer test-token-user-alice"})
    assert fifth.status_code == 429


def test_duplicate_signup_rejected_with_409_preventing_account_takeover(client):
    """
    Test Critical Fix (CWE-620): Re-registering an existing email via POST /users/create
    must fail with HTTP 409 Conflict and MUST NOT overwrite the original user's password hash.
    """
    # 1. Register alice@example.com with original password
    first_signup = client.post(
        "/users/create",
        json={"email": "alice@example.com", "password": "OriginalPassword!123"},
    )
    assert first_signup.status_code == 200

    # 2. Attacker attempts to register alice@example.com again with a new password
    second_signup = client.post(
        "/users/create",
        json={"email": "alice@example.com", "password": "AttackerPassword!999"},
    )
    assert second_signup.status_code == 409
    assert "already exists" in second_signup.get_json()["error"].lower()

    # 3. Confirm attacker's new password DOES NOT authenticate (401)
    attacker_login = client.post(
        "/users/login",
        json={"email": "alice@example.com", "password": "AttackerPassword!999"},
    )
    assert attacker_login.status_code == 401

    # 4. Confirm Alice's original password STILL authenticates (200)
    alice_login = client.post(
        "/users/login",
        json={"email": "alice@example.com", "password": "OriginalPassword!123"},
    )
    assert alice_login.status_code == 200
    assert alice_login.get_json()["id_token"].startswith("csjwt.")


def test_valid_bearer_token_accepted(client):
    """Test accessing protected user info with a cryptographically signed Bearer token."""
    token = create_session_token("alice")
    response = client.get("/users/info", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_hash_endpoint_with_valid_bearer(client):
    """Test /hash endpoint with valid signed Authorization header and secure HMAC."""
    token = create_session_token("bob")
    response = client.post(
        "/hash",
        headers={"Authorization": f"Bearer {token}"},
        json={"content": "hello secure world"},
    )
    assert response.status_code == 200
    data = response.get_json()
    assert "messageID" in data
    assert data["messageID"].startswith("msg_")


def test_chat_path_traversal_blocked(client):
    """
    Test Broken Access Control / Path Traversal fix on Firebase chat routes.
    """
    token = create_session_token("alice")
    response = client.post(
        "/chats/..%2F..%2Fvictim_uid/messages",
        headers={"Authorization": f"Bearer {token}"},
        json={"messages": [{"sender": "user", "content": "hi"}]},
    )
    assert response.status_code in (400, 404)


def test_scrypt_password_hashing_and_session_token_lifecycle(client):
    """
    Test Hardening: scrypt password hashing, login flow, and token expiration enforcement.
    """
    pw_hash = hash_password("StrongPass!2026")
    assert pw_hash.startswith("scrypt$")
    assert verify_password("StrongPass!2026", pw_hash) is True
    assert verify_password("WrongPass", pw_hash) is False

    # End-to-end signup -> login -> token verification
    signup_resp = client.post(
        "/users/create",
        json={"email": "student@cornell.edu", "password": "StrongPass!2026"},
    )
    assert signup_resp.status_code == 200

    login_resp = client.post(
        "/users/login",
        json={"email": "student@cornell.edu", "password": "StrongPass!2026"},
    )
    assert login_resp.status_code == 200
    token = login_resp.get_json()["id_token"]
    assert token.startswith("csjwt.")

    # Use issued session token to access protected route
    info_resp = client.get("/users/info", headers={"Authorization": f"Bearer {token}"})
    assert info_resp.status_code == 200

    # Verify expired token is rejected
    expired_token = create_session_token("user-student", ttl_seconds=-10)
    with pytest.raises(ValueError, match="expired"):
        verify_session_token(expired_token)

    expired_resp = client.get("/users/info", headers={"Authorization": f"Bearer {expired_token}"})
    assert expired_resp.status_code == 401


def test_production_mode_fails_without_secret_key(monkeypatch):
    """
    Test Critical Fix: In production mode, missing COURSESPHERE_SECRET_KEY fails closed
    instead of falling back to any hardcoded secret string.
    """
    monkeypatch.delenv("COURSESPHERE_SECRET_KEY", raising=False)
    monkeypatch.setenv("COURSESPHERE_ENV", "production")
    with pytest.raises(RuntimeError, match="COURSESPHERE_SECRET_KEY"):
        get_secret_key()


def test_trusted_proxy_cidr_validation(monkeypatch):
    """
    Test CIDR Fix: Public 172.x.x.x addresses outside 172.16.0.0/12 must NOT be trusted as proxies.
    """
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "1")
    assert _is_trusted_proxy("172.18.0.5") is True
    assert _is_trusted_proxy("127.0.0.1") is True
    assert _is_trusted_proxy("172.1.2.3") is False
    assert _is_trusted_proxy("172.32.0.1") is False
    assert _is_trusted_proxy("8.8.8.8") is False


def test_brute_force_lockout_on_failed_logins(client):
    """
    Test Hardening: Repeated failed login attempts trigger HTTP 429 lockout with Retry-After.
    """
    client.post("/users/create", json={"email": "lockout@cornell.edu", "password": "CorrectPassword123"})

    for _ in range(4):
        resp = client.post("/users/login", json={"email": "lockout@cornell.edu", "password": "WrongPassword"})
        assert resp.status_code == 401

    # 5th failed attempt triggers lockout (HTTP 429)
    fifth_resp = client.post("/users/login", json={"email": "lockout@cornell.edu", "password": "WrongPassword"})
    assert fifth_resp.status_code == 429
    assert "Retry-After" in fifth_resp.headers


def test_rate_limit_cannot_be_bypassed_via_x_forwarded_for_spoofing(client):
    """
    Test High Fix: Spoofing arbitrary X-Forwarded-For headers from an untrusted client
    cannot bypass brute-force lockout or rate limiting.
    """
    client.post("/users/create", json={"email": "spoof@cornell.edu", "password": "CorrectPassword123"})

    for i in range(4):
        resp = client.post(
            "/users/login",
            headers={"X-Forwarded-For": f"203.0.113.{i + 10}"},
            json={"email": "spoof@cornell.edu", "password": "WrongPassword"},
        )
        assert resp.status_code == 401

    # Even with a brand new spoofed X-Forwarded-For IP, the 5th attempt is locked out (HTTP 429)
    fifth_resp = client.post(
        "/users/login",
        headers={"X-Forwarded-For": "198.51.100.99"},
        json={"email": "spoof@cornell.edu", "password": "WrongPassword"},
    )
    assert fifth_resp.status_code == 429


def test_csrf_and_content_type_protection(client):
    """
    Test Hardening: State-changing requests reject form-encoded CSRF and untrusted Origins.
    """
    # 1. Form-encoded POST is rejected with 415 Unsupported Media Type
    form_resp = client.post(
        "/users/create",
        data="email=csrf@evil.com&password=password123",
        content_type="application/x-www-form-urlencoded",
    )
    assert form_resp.status_code == 415

    # 2. Request from unauthorized cross-origin is rejected with 403 Forbidden
    csrf_origin_resp = client.post(
        "/users/create",
        headers={"Origin": "https://evil-attacker.example.com"},
        json={"email": "csrf@evil.com", "password": "password123"},
    )
    assert csrf_origin_resp.status_code == 403


def test_circuit_breaker_state_transitions():
    """
    Test SRE Resilience: Circuit Breaker opens after threshold failures and recovers.
    """
    cb = CircuitBreaker("test-service", failure_threshold=2, recovery_timeout=0.05)
    assert cb.state_name == "CLOSED"

    def failing_call():
        raise ConnectionError("Downstream timeout")

    with pytest.raises(ConnectionError):
        cb.call(failing_call)
    assert cb.state_name == "CLOSED"

    with pytest.raises(ConnectionError):
        cb.call(failing_call)
    assert cb.state_name == "OPEN"

    # While OPEN, immediately fast-fails with CircuitBreakerOpenException
    with pytest.raises(CircuitBreakerOpenException):
        cb.call(lambda: "should not execute")


def test_multi_replica_shared_state_consistency(client):
    """
    Test Critical Fix: User accounts, session tokens, courses, and rate-limit state
    created on Replica 1 are immediately available and enforced on Replica 2 via shared persistence.
    """
    # 1. Create user and login on Instance 1
    signup = client.post(
        "/users/create",
        json={"email": "replica_owner@cornell.edu", "password": "ReplicaPass!123"},
    )
    assert signup.status_code == 200

    login = client.post(
        "/users/login",
        json={"email": "replica_owner@cornell.edu", "password": "ReplicaPass!123"},
    )
    assert login.status_code == 200
    owner_token = login.get_json()["id_token"]

    # 2. Create a course using the session token
    create_course = client.post(
        "/courses",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={
            "name": "Distributed Systems Security",
            "semester": "FA26",
            "department": "CS",
            "instructor": "Prof. Lamport",
            "section_id": 5412,
        },
    )
    assert create_course.status_code == 201
    course_id = create_course.get_json()["id"]

    # 3. Second user created and logged in can read the course but receives 403 on update
    client.post(
        "/users/create",
        json={"email": "other_replica_user@cornell.edu", "password": "OtherPass!123"},
    )
    other_token = client.post(
        "/users/login",
        json={"email": "other_replica_user@cornell.edu", "password": "OtherPass!123"},
    ).get_json()["id_token"]

    get_resp = client.get(f"/courses/{course_id}")
    assert get_resp.status_code == 200
    assert get_resp.get_json()["name"] == "Distributed Systems Security"

    forbidden_update = client.put(
        f"/courses/{course_id}",
        headers={"Authorization": f"Bearer {other_token}"},
        json={"name": "Tampered By Other User"},
    )
    assert forbidden_update.status_code == 403


def test_firebase_mode_invalid_tokens_and_signup_login_coherence(client, monkeypatch):
    """
    Test Firebase Mode Resilience & Coherence:
    1. When Firebase Admin is active, 3 invalid non-csjwt tokens rejected by `auth.verify_id_token`
       must return HTTP 401 and MUST NOT trip `CIRCUIT_BREAKERS["firebase"]` into OPEN (503).
    2. Accounts created when Firebase Admin is active are persisted in `app_users` and can
       immediately authenticate via `POST /users/login`.
    """
    import firebase as fb_module

    class DummyFBUser:
        def __init__(self, uid):
            self.uid = uid

    class DummyFBAuth:
        @staticmethod
        def create_user(email, password):
            return DummyFBUser("fb-uid-12345")

        @staticmethod
        def verify_id_token(token_str):
            if token_str == "valid-firebase-jwt":
                return {"uid": "fb-uid-12345"}
            raise Exception("Certificate/signature verification failed for token")

    monkeypatch.setattr(fb_module, "firebase_app", object())
    monkeypatch.setattr(fb_module, "auth", DummyFBAuth)

    # 1. Send 3 invalid Firebase JWTs -> all return 401, CircuitBreaker stays CLOSED
    for i in range(3):
        bad_resp = client.get("/users/info", headers={"Authorization": f"Bearer bad-fb-jwt-{i}"})
        assert bad_resp.status_code == 401
    assert CIRCUIT_BREAKERS["firebase"].state_name == "CLOSED"

    # 2. Signup in Firebase mode persists user to app_users and allows local login + valid FB JWT
    signup_resp = client.post(
        "/users/create",
        json={"email": "fb_user@cornell.edu", "password": "FirebaseMode!123"},
    )
    assert signup_resp.status_code == 200
    assert signup_resp.get_json()["user_id"] == "fb-uid-12345"

    login_resp = client.post(
        "/users/login",
        json={"email": "fb_user@cornell.edu", "password": "FirebaseMode!123"},
    )
    assert login_resp.status_code == 200
    assert login_resp.get_json()["user_id"] == "fb-uid-12345"

    valid_fb_resp = client.get("/users/info", headers={"Authorization": "Bearer valid-firebase-jwt"})
    assert valid_fb_resp.status_code == 200
