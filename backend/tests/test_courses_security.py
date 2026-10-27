import pytest
import os
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db import execute_query, create_connection
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
    """Use an isolated in-memory or temporary database for testing."""
    test_db = str(tmp_path / "test_courses.db")
    monkeypatch.setenv("COURSESPHERE_DB_PATH", test_db)
    # Reinitialize schema
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO courses (id, name, section_id, semester, department, instructor)
        VALUES (1, 'AppSec 101', 101, 'Fall2026', 'CS', 'Dr. Turing'),
               (2, 'Data Structures', 102, 'Spring2026', 'CS', 'Dr. Knuth');
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
    injection_payload = "' UNION SELECT 99, 'Hacked', 0, 'Evil', 'CS', 'Hacker'--"
    response = client.get(f"/courses/department/{injection_payload}")
    assert response.status_code == 404
    data = response.get_json()
    assert "error" in data


def test_query_filter_parameterized(client):
    response = client.get("/courses?department=CS")
    assert response.status_code == 200
    data = response.get_json()
    assert len(data) == 2
