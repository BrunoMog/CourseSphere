import pytest
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from endpoints import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_health_endpoint(client):
    """Test SRE healthcheck endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "UP"
    assert data["database"] == "healthy"
    assert "timestamp" in data


def test_metrics_endpoint(client):
    """Test SRE Prometheus metrics endpoint."""
    response = client.get("/metrics")
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "http_requests_total" in text
    assert "http_request_duration_seconds" in text


def test_security_headers_present(client):
    """Test that Hardening HTTP security headers are returned on all responses."""
    response = client.get("/health")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in response.headers
    assert "X-Request-ID" in response.headers


def test_token_in_url_rejected(client):
    """
    Test VULN-04 Fix: Passing authentication token via URL query parameter
    must be rejected to prevent leakage in server access logs (CWE-598).
    """
    response = client.get("/users/info?id_token=test-token-alice")
    assert response.status_code == 401
    data = response.get_json()
    assert "error" in data
    assert "query parameter" in data["error"].lower()


def test_missing_auth_header_rejected(client):
    """Test accessing protected user info without authorization header."""
    response = client.get("/users/info")
    assert response.status_code == 401
    assert "error" in response.get_json()


def test_valid_bearer_token_accepted(client):
    """Test accessing protected user info with valid Bearer token header."""
    response = client.get("/users/info", headers={"Authorization": "Bearer test-token-alice"})
    assert response.status_code == 200


def test_hash_endpoint_with_valid_bearer(client):
    """Test /hash endpoint with valid Authorization header and secure HMAC."""
    response = client.post(
        "/hash",
        headers={"Authorization": "Bearer test-token-bob"},
        json={"content": "hello secure world"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert "messageID" in data
    assert data["messageID"].startswith("msg_")
