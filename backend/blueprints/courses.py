import logging
from flask import Blueprint, jsonify, request

try:
    from backend.db import execute_query
    from backend.firebase import Firebase
    from backend.security import validate_course_payload
except ImportError:
    from db import execute_query
    from firebase import Firebase
    from security import validate_course_payload

courses_bp = Blueprint("courses", __name__)
logger = logging.getLogger("coursesphere")

success_response = lambda data, code: (jsonify(data), code)
error_response = lambda error, code: (jsonify({'error': error}), code)


def _get_authenticated_uid():
    """Extracts and verifies the caller's UID from the Authorization Bearer header."""
    if "id_token" in request.args:
        return None, ("Insecure token transport: tokens must be in the Authorization header.", 401)
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, ("Missing or malformed Authorization header. Expected 'Bearer <token>'.", 401)
    token = auth_header.split("Bearer ", 1)[1].strip()
    if not token:
        return None, ("Empty bearer token provided.", 401)
    try:
        decoded = Firebase.verify_id_token(token)
        uid = decoded.get("uid")
        if not uid:
            return None, ("Invalid token payload.", 401)
        return uid, None
    except Exception as exc:
        logger.warning(f"Course endpoint authentication failure: {exc}")
        return None, ("Invalid or expired authentication token.", 401)


@courses_bp.route("/courses", methods=["GET"])
def get_courses():
    """
    Retrieves courses from the database. Supports optional filtering by
    semester, department, or instructor via query parameters using static parameterized SQL.
    """
    semester = request.args.get("semester")
    department = request.args.get("department")
    instructor = request.args.get("instructor")

    if semester or department or instructor:
        courses = execute_query(
            """
            SELECT * FROM courses
            WHERE (? IS NULL OR semester = ?)
              AND (? IS NULL OR department = ?)
              AND (? IS NULL OR instructor = ?)
            """,
            (semester, semester, department, department, instructor, instructor),
        )
    else:
        courses = execute_query("SELECT * FROM courses")

    return success_response(courses, 200)


@courses_bp.route("/courses", methods=["POST"])
def create_course():
    """
    Creates a new course bound to the authenticated creator's UID.
    """
    uid, auth_err = _get_authenticated_uid()
    if auth_err:
        return error_response(auth_err[0], auth_err[1])

    data = request.get_json(silent=True)
    sanitized, val_err = validate_course_payload(data, partial=False)
    if val_err:
        return error_response(val_err, 400)

    course_id = execute_query(
        """
        INSERT INTO courses (name, section_id, semester, department, instructor, creator_uid)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            sanitized["name"],
            sanitized.get("section_id"),
            sanitized["semester"],
            sanitized["department"],
            sanitized["instructor"],
            uid,
        ),
    )

    if "description" in sanitized:
        execute_query(
            "INSERT OR REPLACE INTO course_descriptions (id, description) VALUES (?, ?)",
            (course_id, sanitized["description"]),
        )

    created = execute_query("SELECT * FROM courses WHERE id = ?", (course_id,))
    logger.info(f"Course id={course_id} created by uid={uid}")
    return success_response(created[0] if created else {"id": course_id}, 201)


@courses_bp.route("/courses/<int:course_id>", methods=["GET"])
def get_course(course_id):
    """
    Retrieves a specific course by its ID using parameterized queries to prevent SQL injection.
    """
    courses = execute_query("SELECT * FROM courses WHERE id = ?", (course_id,))
    if courses:
        return success_response(courses[0] if len(courses) == 1 else courses, 200)
    return error_response("Course not found", 404)


@courses_bp.route("/courses/<int:course_id>", methods=["PUT"])
def update_course(course_id):
    """
    Updates an existing course. Enforces strict Object-Level Authorization (BOLA/IDOR check):
    only the original creator (`creator_uid`) is permitted to modify the course.
    """
    uid, auth_err = _get_authenticated_uid()
    if auth_err:
        return error_response(auth_err[0], auth_err[1])

    existing = execute_query("SELECT * FROM courses WHERE id = ?", (course_id,))
    if not existing:
        return error_response("Course not found", 404)

    course = existing[0]
    if course.get("creator_uid") != uid:
        logger.warning(
            f"Access Control Violation: uid={uid} attempted to edit course id={course_id} owned by {course.get('creator_uid')}"
        )
        return error_response("Forbidden: You do not have permission to edit a course created by another user.", 403)

    data = request.get_json(silent=True)
    sanitized, val_err = validate_course_payload(data, partial=True)
    if val_err:
        return error_response(val_err, 400)

    execute_query(
        """
        UPDATE courses
        SET name = COALESCE(?, name),
            section_id = COALESCE(?, section_id),
            semester = COALESCE(?, semester),
            department = COALESCE(?, department),
            instructor = COALESCE(?, instructor)
        WHERE id = ?
        """,
        (
            sanitized.get("name"),
            sanitized.get("section_id"),
            sanitized.get("semester"),
            sanitized.get("department"),
            sanitized.get("instructor"),
            course_id,
        ),
    )

    if "description" in sanitized:
        execute_query(
            "INSERT OR REPLACE INTO course_descriptions (id, description) VALUES (?, ?)",
            (course_id, sanitized["description"]),
        )

    updated = execute_query("SELECT * FROM courses WHERE id = ?", (course_id,))
    logger.info(f"Course id={course_id} updated by owner uid={uid}")
    return success_response(updated[0], 200)


@courses_bp.route("/courses/<int:course_id>", methods=["DELETE"])
def delete_course(course_id):
    """
    Deletes a course. Enforces strict Object-Level Authorization:
    only the original creator (`creator_uid`) can delete the course.
    """
    uid, auth_err = _get_authenticated_uid()
    if auth_err:
        return error_response(auth_err[0], auth_err[1])

    existing = execute_query("SELECT * FROM courses WHERE id = ?", (course_id,))
    if not existing:
        return error_response("Course not found", 404)

    course = existing[0]
    if course.get("creator_uid") != uid:
        logger.warning(
            f"Access Control Violation: uid={uid} attempted to delete course id={course_id} owned by {course.get('creator_uid')}"
        )
        return error_response("Forbidden: You do not have permission to delete a course created by another user.", 403)

    execute_query("DELETE FROM course_descriptions WHERE id = ?", (course_id,))
    execute_query("DELETE FROM courses WHERE id = ?", (course_id,))
    logger.info(f"Course id={course_id} deleted by owner uid={uid}")
    return success_response({"message": "Course deleted successfully", "id": course_id}, 200)


@courses_bp.route("/courses/description/<int:course_id>", methods=["GET"])
def get_course_description(course_id):
    """
    Retrieves the description of a specific course by its ID using parameterized queries.
    """
    descriptions = execute_query(
        "SELECT description FROM course_descriptions WHERE id = ?", (course_id,)
    )
    if descriptions:
        return success_response(descriptions[0] if len(descriptions) == 1 else descriptions, 200)
    return error_response("Course description not found", 404)


@courses_bp.route("/courses/bysection/<int:section_id>", methods=["GET"])
def get_courses_by_section(section_id):
    """
    Retrieves a list of courses for a specific section using parameterized queries.
    """
    courses = execute_query(
        "SELECT * FROM courses WHERE section_id = ?", (section_id,)
    )
    if not courses:
        return error_response("No courses found for this section", 404)
    return success_response(courses, 200)


@courses_bp.route("/courses/semester/<string:semester>", methods=["GET"])
def get_courses_by_semester(semester):
    """
    Retrieves courses by semester using parameterized queries.
    """
    courses = execute_query(
        "SELECT * FROM courses WHERE semester = ?", (semester,)
    )
    if not courses:
        return error_response("No courses found for this semester", 404)
    return success_response(courses, 200)


@courses_bp.route("/courses/department/<string:department>", methods=["GET"])
def get_courses_by_department(department):
    """
    Retrieves courses by department using parameterized queries.
    """
    courses = execute_query(
        "SELECT * FROM courses WHERE department = ?", (department,)
    )
    if not courses:
        return error_response("No courses found for this department", 404)
    return success_response(courses, 200)


@courses_bp.route("/courses/instructor/<string:instructor>", methods=["GET"])
def get_courses_by_instructor(instructor):
    """
    Retrieves courses by instructor using parameterized queries.
    """
    courses = execute_query(
        "SELECT * FROM courses WHERE instructor = ?", (instructor,)
    )
    if not courses:
        return error_response("No courses found for this instructor", 404)
    return success_response(courses, 200)
