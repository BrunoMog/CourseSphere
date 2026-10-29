# firebase.py
import os
import re
import json
import time
import hashlib
import logging
import sqlite3
from pathlib import Path

try:
    from backend.db import create_connection
    from backend.security import (
        hash_password,
        verify_password,
        create_session_token,
        verify_session_token,
        sanitize_string,
    )
except ImportError:
    from db import create_connection
    from security import (
        hash_password,
        verify_password,
        create_session_token,
        verify_session_token,
        sanitize_string,
    )

logger = logging.getLogger(__name__)


class UserAlreadyExistsError(ValueError):
    """Raised when attempting to register an email address that already exists."""


try:
    import firebase_admin
    from firebase_admin import credentials, auth, db
    HAS_FIREBASE = True
except ImportError:
    HAS_FIREBASE = False
    firebase_admin = None
    credentials = None
    auth = None
    db = None
    logger.warning("firebase_admin package not installed. Using shared SQLite persistence.")

BASE_DIR = Path(__file__).resolve().parent
CREDS_PATH = os.environ.get("FIREBASE_CREDENTIALS_PATH", str(BASE_DIR / "credentials.json"))
DATABASE_URL = os.environ.get("FIREBASE_DATABASE_URL", "https://coursesphere-8bd9a-default-rtdb.firebaseio.com")

firebase_app = None
if HAS_FIREBASE and os.path.exists(CREDS_PATH):
    try:
        firebase_credentials = credentials.Certificate(CREDS_PATH)
        firebase_admin.initialize_app(firebase_credentials, {"databaseURL": DATABASE_URL})
        firebase_app = firebase_admin.get_app()
    except Exception as e:
        logger.error(f"Error initializing Firebase with credentials at {CREDS_PATH}: {e}")
else:
    logger.info("Operating with shared SQLite user/chat store across workers and replicas.")


def validate_path_identifier(identifier: str, name: str = "ID") -> str:
    """Neutralizes path traversal attempts in resource paths (CWE-22 / BOLA)."""
    if not identifier or not re.match(r"^[a-zA-Z0-9_\-]{1,128}$", str(identifier)):
        raise ValueError(f"Invalid {name}: must contain only alphanumeric, underscore, or hyphen characters.")
    return str(identifier)


class Firebase:
    @staticmethod
    def create_user(email: str, password: str):
        """
        Creates a new user with an scrypt password hash persisted in the shared database.
        Prevents Account Takeover (CWE-620) by rejecting duplicate email registrations
        with UserAlreadyExistsError (mapped to HTTP 409 Conflict) instead of overwriting
        existing credentials.
        """
        normalized_email = email.strip().lower()
        password_hash = hash_password(password)

        conn = create_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM app_users WHERE email = ?", (normalized_email,))
            if cur.fetchone():
                raise UserAlreadyExistsError("An account with this email already exists.")

            if firebase_app and auth:
                try:
                    fb_user = auth.create_user(email=normalized_email, password=password)
                    uid = fb_user.uid
                except Exception as e:
                    if "ALREADY_EXISTS" in str(e).upper():
                        raise UserAlreadyExistsError("An account with this email already exists.")
                    raise Exception(f"Error creating user in Firebase: {str(e)}")
            else:
                clean_prefix = re.sub(r"[^a-zA-Z0-9_\-]", "_", normalized_email.split("@")[0])[:32]
                email_digest = hashlib.sha256(normalized_email.encode("utf-8")).hexdigest()[:8]
                uid = f"user-{clean_prefix}-{email_digest}"

            default_profile = json.dumps({"email": normalized_email, "uid": uid})
            try:
                cur.execute(
                    """
                    INSERT INTO app_users (uid, email, password_hash, user_info_json, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (uid, normalized_email, password_hash, default_profile, time.time()),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                raise UserAlreadyExistsError("An account with this email already exists.")
        finally:
            conn.close()

        return {
            "message": "User created successfully",
            "user_id": uid,
            "email": normalized_email,
        }

    @staticmethod
    def authenticate_user(email: str, password: str) -> dict:
        """
        Authenticates a user against the shared `app_users` table using constant-time scrypt
        verification and issues an expiring HMAC-SHA256 session token.
        """
        normalized_email = email.strip().lower()
        conn = create_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT uid, email, password_hash FROM app_users WHERE email = ?",
                (normalized_email,),
            )
            row = cur.fetchone()
        finally:
            conn.close()

        if not row or not verify_password(password, row["password_hash"]):
            raise ValueError("Invalid email or password.")

        token = create_session_token(row["uid"], ttl_seconds=3600)
        return {
            "id_token": token,
            "user_id": row["uid"],
            "email": row["email"],
            "expires_in": 3600,
        }

    @staticmethod
    def delete_user(uid: str):
        uid = validate_path_identifier(uid, "User ID")
        conn = create_connection()
        try:
            conn.execute("DELETE FROM app_users WHERE uid = ?", (uid,))
            conn.execute("DELETE FROM user_chats WHERE uid = ?", (uid,))
            conn.commit()
        finally:
            conn.close()

        if firebase_app and auth and db:
            try:
                auth.delete_user(uid)
                ref = db.reference(f"users/{uid}")
                ref.delete()
            except Exception as e:
                raise Exception(f"Error deleting user: {str(e)}")

    @staticmethod
    def verify_id_token(id_token: str):
        """
        Verifies an authentication token strictly via cryptographic signature:
        - Accepts HMAC-SHA256 signed session tokens (`csjwt.<payload>.<sig>`) with expiration check.
        - Accepts Firebase Admin JWTs when Firebase is initialized.
        - Never accepts unsigned `test-token-*` strings in any environment.
        """
        if not id_token:
            raise ValueError("Authentication token is required")
        token_str = str(id_token).strip()
        if token_str.startswith("csjwt."):
            return verify_session_token(token_str)
        if not firebase_app or not auth:
            raise ValueError("Invalid or unsigned authentication token.")
        try:
            decoded_token = auth.verify_id_token(token_str)
            return decoded_token
        except (ConnectionError, TimeoutError, OSError) as net_err:
            raise ConnectionError(f"Firebase verification service unreachable: {net_err}") from net_err
        except Exception as e:
            raise ValueError(f"Invalid or expired Firebase ID token: {str(e)}") from e

    @staticmethod
    def set_user_info(uid: str, user_info: dict):
        uid = validate_path_identifier(uid, "User ID")
        conn = create_connection()
        try:
            serialized = json.dumps(user_info)
            cur = conn.cursor()
            cur.execute("SELECT uid FROM app_users WHERE uid = ?", (uid,))
            if cur.fetchone():
                cur.execute(
                    "UPDATE app_users SET user_info_json = ? WHERE uid = ?",
                    (serialized, uid),
                )
            else:
                cur.execute(
                    "INSERT INTO app_users (uid, email, password_hash, user_info_json) VALUES (?, ?, ?, ?)",
                    (uid, f"{uid}@coursesphere.local", "external_auth", serialized),
                )
            conn.commit()
        finally:
            conn.close()

        if firebase_app and db:
            try:
                ref = db.reference(f"users/{uid}/info")
                ref.set(user_info)
            except Exception as e:
                raise Exception(f"Error setting user info: {str(e)}")

    @staticmethod
    def get_user_info(uid: str):
        uid = validate_path_identifier(uid, "User ID")
        if firebase_app and db:
            try:
                ref = db.reference(f"users/{uid}/info")
                return ref.get()
            except Exception as e:
                logger.warning(f"Firebase user info lookup failed for {uid}, falling back to shared store: {e}")

        conn = create_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT user_info_json, email FROM app_users WHERE uid = ?", (uid,))
            row = cur.fetchone()
            if row and row["user_info_json"]:
                return json.loads(row["user_info_json"])
            return {"email": f"{uid}@example.com", "uid": uid}
        finally:
            conn.close()

    @staticmethod
    def try_get_user_info(id_token):
        try:
            return Firebase.get_user_info(Firebase.verify_id_token(id_token).get("uid"))
        except Exception:
            return None

    @staticmethod
    def update_user_info(uid: str, updates: dict):
        uid = validate_path_identifier(uid, "User ID")
        current = Firebase.get_user_info(uid) or {}
        current.update(updates)
        Firebase.set_user_info(uid, current)

    @staticmethod
    def create_document(collection: str, document_id: str, data: dict):
        collection = validate_path_identifier(collection, "Collection")
        document_id = validate_path_identifier(document_id, "Document ID")
        if not firebase_app or not db:
            return
        try:
            ref = db.reference(f"{collection}/{document_id}")
            ref.set(data)
        except Exception as e:
            raise Exception(f"Error creating document: {str(e)}")

    @staticmethod
    def get_document(collection: str, document_id: str):
        collection = validate_path_identifier(collection, "Collection")
        document_id = validate_path_identifier(document_id, "Document ID")
        if not firebase_app or not db:
            return None
        try:
            ref = db.reference(f"{collection}/{document_id}")
            return ref.get()
        except Exception as e:
            raise Exception(f"Error retrieving document: {str(e)}")

    @staticmethod
    def update_document(collection: str, document_id: str, updates: dict):
        collection = validate_path_identifier(collection, "Collection")
        document_id = validate_path_identifier(document_id, "Document ID")
        if not firebase_app or not db:
            return
        try:
            ref = db.reference(f"{collection}/{document_id}")
            ref.update(updates)
        except Exception as e:
            raise Exception(f"Error updating document: {str(e)}")

    @staticmethod
    def delete_document(collection: str, document_id: str):
        collection = validate_path_identifier(collection, "Collection")
        document_id = validate_path_identifier(document_id, "Document ID")
        if not firebase_app or not db:
            return
        try:
            ref = db.reference(f"{collection}/{document_id}")
            ref.delete()
        except Exception as e:
            raise Exception(f"Error deleting document: {str(e)}")

    @staticmethod
    def save_chat(uid: str, chat_id: str, messages: list):
        uid = validate_path_identifier(uid, "User ID")
        chat_id = validate_path_identifier(chat_id, "Chat ID")
        if not isinstance(messages, list):
            raise ValueError("Messages must be a list of dictionaries.")
        if len(messages) > 50:
            raise ValueError("Cannot save more than 50 messages in a single request.")

        sanitized_messages = []
        for message in messages:
            if not isinstance(message, dict):
                raise ValueError("Each message must be a dictionary.")
            sanitized_msg = {}
            for k, v in message.items():
                key_clean = sanitize_string(k, max_length=64)
                val_clean = sanitize_string(v, max_length=2000) if isinstance(v, str) else v
                sanitized_msg[key_clean] = val_clean
            sanitized_messages.append(sanitized_msg)

        conn = create_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT messages_json FROM user_chats WHERE uid = ? AND chat_id = ?",
                (uid, chat_id),
            )
            row = cur.fetchone()
            existing = json.loads(row["messages_json"]) if row and row["messages_json"] else []
            existing.extend(sanitized_messages)
            cur.execute(
                """
                INSERT INTO user_chats (uid, chat_id, messages_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(uid, chat_id) DO UPDATE SET
                    messages_json = excluded.messages_json,
                    updated_at = excluded.updated_at
                """,
                (uid, chat_id, json.dumps(existing), time.time()),
            )
            conn.commit()
        finally:
            conn.close()

        if firebase_app and db:
            try:
                ref = db.reference(f"users/{uid}/chats/{chat_id}/messages")
                for message in sanitized_messages:
                    ref.push(message)
            except Exception as e:
                raise Exception(f"Error saving messages: {str(e)}")

    @staticmethod
    def delete_chat(uid: str, chat_id: str):
        uid = validate_path_identifier(uid, "User ID")
        chat_id = validate_path_identifier(chat_id, "Chat ID")
        conn = create_connection()
        try:
            conn.execute("DELETE FROM user_chats WHERE uid = ? AND chat_id = ?", (uid, chat_id))
            conn.commit()
        finally:
            conn.close()

        if firebase_app and db:
            try:
                ref = db.reference(f"users/{uid}/chats/{chat_id}")
                ref.delete()
            except Exception as e:
                raise Exception(f"Error deleting chat session: {str(e)}")

    @staticmethod
    def list_chats(uid: str) -> list:
        uid = validate_path_identifier(uid, "User ID")
        conn = create_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT chat_id, updated_at FROM user_chats WHERE uid = ? ORDER BY updated_at DESC",
                (uid,),
            )
            rows = cur.fetchall()
            return [
                {
                    "title": row["chat_id"],
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(row["updated_at"] or time.time())),
                }
                for row in rows
            ]
        finally:
            conn.close()
