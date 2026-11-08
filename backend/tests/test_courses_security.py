import pytest
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db import create_connection
from security import create_session_token
from blueprints.courses import courses_bp
from flask import Flask


@pytest.fixture
def app():
    app = Flask(__name__)
    app.register_blueprint(courses_bp)
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """Use an isolated temporary database for each test."""
    test_db = str(tmp_path / "test_courses.db")
    monkeypatch.setenv("COURSESPHERE_DB_PATH", test_db)
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO courses (id, name, section_id, semester, department, instructor, creator_uid)
        VALUES (1, 'AppSec 101', 101, 'Fall2026', 'CS', 'Dr. Turing', 'alice'),
               (2, 'Data Structures', 102, 'Spring2026', 'CS', 'Dr. Knuth', 'bob');
    """)
    cursor.execute("""
        INSERT INTO course_descriptions (id, description)
        VALUES (1, 'Introduction to application security and defense.');
    """)
    conn.commit()
    conn.close()


def test_get_course_valid(client):
    response = client.get("/courses/1")
    assert response.status_code == 200
    data = response.get_json()
    assert data["name"] == "AppSec 101"
    assert data["instructor"] == "Dr. Turing"


def test_get_course_not_found(client):
    response = client.get("/courses/999")
    assert response.status_code == 404
    assert "error" in response.get_json()


def test_sql_injection_in_semester_parameter(client):
    """
    Verify that SQL injection strings in parameters are treated as literals
    and do not leak unauthorized rows or corrupt SQL execution.
    """
    injection_payload = "' OR '1'='1"
    response = client.get(f"/courses/semester/{injection_payload}")
    assert response.status_code == 404
    data = response.get_json()
    assert "error" in data


def test_sql_injection_union_based(client):
    """
    Verify that UNION-based SQL injection payloads are safely handled.
    """
    injection_payload = "' UNION SELECT 99, 'Hacked', 0, 'Evil', 'CS', 'Hacker', 'evil'--"
    response = client.get(f"/courses/department/{injection_payload}")
    assert response.status_code == 404
    data = response.get_json()
    assert "error" in data


def test_query_filter_parameterized(client):
    response = client.get("/courses?department=CS")
    assert response.status_code == 200
    data = response.get_json()
    assert len(data) == 2


def test_create_course_requires_authentication(client):
    """Unauthenticated users cannot create courses."""
    response = client.post(
        "/courses",
        json={"name": "Cloud Security", "semester": "Fall2026", "department": "CS", "instructor": "Dr. Rivest"},
    )
    assert response.status_code == 401


def test_course_authorization_owner_vs_other_user(client):
    """
    Differential Requirement: Automated test verifying Broken Access Control remediation.
    User 'bob' CANNOT edit or delete a course created by 'alice' (HTTP 403 Forbidden),
    whereas 'alice' CAN edit and delete her own course (HTTP 200 OK).
    """
    alice_token = create_session_token("alice")
    bob_token = create_session_token("bob")

    # 1. Alice creates a new course
    create_resp = client.post(
        "/courses",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "name": "Distributed Systems SRE",
            "section_id": 305,
            "semester": "Fall2026",
            "department": "CS",
            "instructor": "Dr. Lamport",
            "description": "Consensus and fault tolerance.",
        },
    )
    assert create_resp.status_code == 201
    created_course = create_resp.get_json()
    course_id = created_course["id"]
    assert created_course["creator_uid"] == "alice"

    # 2. Bob attempts to edit Alice's course -> Must fail with 403 Forbidden
    bob_edit_resp = client.put(
        f"/courses/{course_id}",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={"name": "Tampered Course Title"},
    )
    assert bob_edit_resp.status_code == 403
    assert "permission" in bob_edit_resp.get_json()["error"].lower()

    # 3. Bob attempts to delete Alice's course -> Must fail with 403 Forbidden
    bob_delete_resp = client.delete(
        f"/courses/{course_id}",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert bob_delete_resp.status_code == 403

    # 4. Alice edits her own course -> Succeeds with 200 OK
    alice_edit_resp = client.put(
        f"/courses/{course_id}",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"name": "Advanced Distributed Systems SRE"},
    )
    assert alice_edit_resp.status_code == 200
    assert alice_edit_resp.get_json()["name"] == "Advanced Distributed Systems SRE"

    # 5. Alice deletes her own course -> Succeeds with 200 OK
    alice_delete_resp = client.delete(
        f"/courses/{course_id}",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert alice_delete_resp.status_code == 200


def test_course_input_xss_sanitization(client):
    """Verify HTML/script tags in course payloads are sanitized against Stored XSS."""
    alice_token = create_session_token("alice")
    resp = client.post(
        "/courses",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "name": "<script>alert('xss')</script>Security",
            "semester": "Fall2026",
            "department": "CS",
            "instructor": "Dr. <img src=x onerror=alert(1)>",
        },
    )
    assert resp.status_code == 201
    body = resp.get_json()
    assert "<script>" not in body["name"]
    assert "&lt;script&gt;" in body["name"]
    assert "<img" not in body["instructor"]
