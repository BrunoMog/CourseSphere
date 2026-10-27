from flask import Blueprint, jsonify, request

try:
    from backend.db import execute_query
except ImportError:
    from db import execute_query

courses_bp = Blueprint("courses", __name__)

success_response = lambda data, code: (jsonify(data), code)
error_response = lambda error, code: (jsonify({'error': error}), code)


@courses_bp.route("/courses", methods=["GET"])
def get_courses():
    """
    Retrieves courses from the database. Supports optional filtering by
    semester, department, or instructor via query parameters using safe parameterized queries.
    """
    conditions = []
    params = []
    
    semester = request.args.get("semester")
    if semester:
        conditions.append("semester = ?")
        params.append(semester)
        
    department = request.args.get("department")
    if department:
        conditions.append("department = ?")
        params.append(department)
        
    instructor = request.args.get("instructor")
    if instructor:
        conditions.append("instructor = ?")
        params.append(instructor)

    if conditions:
        query = f"SELECT * FROM courses WHERE {' AND '.join(conditions)}"
        courses = execute_query(query, tuple(params))
    else:
        courses = execute_query("SELECT * FROM courses")
        
    return success_response(courses, 200)


@courses_bp.route("/courses/<int:course_id>", methods=["GET"])
def get_course(course_id):
    """
    Retrieves a specific course by its ID using parameterized queries to prevent SQL injection.
    """
    courses = execute_query("SELECT * FROM courses WHERE id = ?", (course_id,))
    if courses:
        return success_response(courses[0] if len(courses) == 1 else courses, 200)
    return error_response("Course not found", 404)


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
