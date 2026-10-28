import os
import shutil
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = str(BASE_DIR / "cornell-course-sphere-data" / "roster_reviews.sqlite.db")

_INITIALIZED_PATHS = set()


def get_db_path() -> str:
    return os.environ.get("COURSESPHERE_DB_PATH", DEFAULT_DB_PATH)


def init_db(conn: sqlite3.Connection):
    """Initializes all application, authentication, rate-limit, and telemetry tables."""
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.execute("PRAGMA busy_timeout=10000;")

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

    # Shared key-value configuration table (for ephemeral dev secret synchronization across workers)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS app_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)

    # Shared user authentication & profile store across Gunicorn workers and container replicas
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS app_users (
            uid TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            user_info_json TEXT DEFAULT '{}',
            created_at REAL DEFAULT (strftime('%s', 'now'))
        );
    """)

    # Shared user chat sessions across workers and replicas
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_chats (
            uid TEXT NOT NULL,
            chat_id TEXT NOT NULL,
            messages_json TEXT DEFAULT '[]',
            updated_at REAL DEFAULT (strftime('%s', 'now')),
            PRIMARY KEY (uid, chat_id)
        );
    """)

    # Shared sliding-window rate limiter & brute-force lockout state across workers/replicas
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rate_limit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bucket_key TEXT NOT NULL,
            ts REAL NOT NULL
        );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_rate_limit_bucket_ts ON rate_limit_events(bucket_key, ts);")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_lockouts (
            client_key TEXT PRIMARY KEY,
            fail_count INTEGER DEFAULT 0,
            window_start REAL DEFAULT 0.0,
            locked_until REAL DEFAULT 0.0
        );
    """)

    # Shared Prometheus metrics counters & histogram buckets across Gunicorn workers
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS prometheus_metrics (
            metric_key TEXT PRIMARY KEY,
            metric_value REAL DEFAULT 0.0
        );
    """)

    conn.commit()


def create_connection() -> sqlite3.Connection:
    db_path = get_db_path()
    parent_dir = os.path.dirname(db_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    # Seed shared volume database from default seed file on first container startup
    if (
        os.environ.get("SEED_SHARED_DB", "0") == "1"
        and db_path != DEFAULT_DB_PATH
        and not os.path.exists(db_path)
        and os.path.exists(DEFAULT_DB_PATH)
    ):
        tmp_seed = f"{db_path}.seed.{os.getpid()}"
        try:
            shutil.copy2(DEFAULT_DB_PATH, tmp_seed)
            os.replace(tmp_seed, db_path)
        except OSError:
            if os.path.exists(tmp_seed):
                os.remove(tmp_seed)

    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000;")
    if db_path not in _INITIALIZED_PATHS:
        init_db(conn)
        _INITIALIZED_PATHS.add(db_path)
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


if __name__ == "__main__":
    connection = create_connection()
    connection.close()
    print("Database initialized successfully at:", get_db_path())
