import sqlite3
import os
from pathlib import Path

# Resolve database path dynamically or from environment variable
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = str(BASE_DIR / "cornell-course-sphere-data" / "roster_reviews.sqlite.db")


def get_db_path():
    return os.environ.get("COURSESPHERE_DB_PATH", DEFAULT_DB_PATH)


def init_db(conn: sqlite3.Connection):
    """Initializes tables and ensures ownership columns exist."""
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            section_id INTEGER,
            semester TEXT,
            department TEXT,
            instructor TEXT,
            creator_uid TEXT DEFAULT 'system'
        );
    """)
    # Ensure creator_uid exists if table was created by an older schema
    cursor.execute("PRAGMA table_info(courses);")
    columns = [row[1] if isinstance(row, tuple) else row["name"] for row in cursor.fetchall()]
    if "creator_uid" not in columns:
        cursor.execute("ALTER TABLE courses ADD COLUMN creator_uid TEXT DEFAULT 'system';")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS course_descriptions (
            id INTEGER PRIMARY KEY,
            description TEXT,
            FOREIGN KEY (id) REFERENCES courses(id) ON DELETE CASCADE
        );
    """)
    conn.commit()


def create_connection():
    db_path = get_db_path()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


def execute_query(query: str, params: tuple = ()) -> list | int:
    """
    Executes a parameterized SQL query safely to prevent SQL injection (CWE-89).

    :param query: SQL statement containing '?' placeholders.
    :param params: Tuple of query parameters.
    :return: List of row dictionaries for SELECT, lastrowid for INSERT, or affected row count otherwise.
    """
    conn = create_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        verb = query.strip().upper().split()[0] if query.strip() else ""
        if verb == "SELECT":
            rows = [dict(row) for row in cursor.fetchall()]
            return rows
        conn.commit()
        if verb == "INSERT":
            return cursor.lastrowid
        return cursor.rowcount
    finally:
        conn.close()


if __name__ == '__main__':
    conn = create_connection()
    conn.close()
    print("Database initialized successfully at:", get_db_path())
