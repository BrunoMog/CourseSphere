# firebase.py
import os
import re
import logging
from pathlib import Path

try:
    from backend.security import (
        hash_password,
        verify_password,
        create_session_token,
        verify_session_token,
    )
except ImportError:
    from security import (
        hash_password,
        verify_password,
        create_session_token,
        verify_session_token,
    )

logger = logging.getLogger(__name__)

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
    logger.warning("firebase_admin package not installed. Running in mock/standalone mode.")

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
    logger.info("Operating in dev/test mode for Firebase services.")


def validate_path_identifier(identifier: str, name: str = "ID") -> str:
    """Neutralizes path traversal attempts in Firebase database paths (CWE-22 / BOLA)."""
    if not identifier or not re.match(r"^[a-zA-Z0-9_\-]+$", str(identifier)):
        raise ValueError(f"Invalid {name}: must contain only alphanumeric, underscore, or hyphen characters.")
    return str(identifier)


_DEV_USER_STORE = {}
_DEV_CREDENTIALS_STORE = {}
_DEV_CHAT_STORE = {}


class Firebase:
    @staticmethod
    def create_user(email: str, password: str):
        password_hash = hash_password(password)
        if not firebase_app or not auth:
            uid = re.sub(r"[^a-zA-Z0-9_\-]", "_", email.split("@")[0])
            uid = f"dev-uid-{uid}"
            _DEV_CREDENTIALS_STORE[email.lower()] = {
                "uid": uid,
                "email": email,
                "password_hash": password_hash,
            }
            return {
                "message": "User created successfully",
                "user_id": uid,
                "email": email,
            }
        try:
            user = auth.create_user(email=email, password=password)
            return {
                "message": "User created successfully",
                "user_id": user.uid,
                "email": user.email,
            }
        except Exception as e:
            raise Exception(f"Error creating user: {str(e)}")

    @staticmethod
    def authenticate_user(email: str, password: str) -> dict:
        """Authenticates a user with scrypt verification and issues a signed expiring session token."""
        record = _DEV_CREDENTIALS_STORE.get(email.lower())
        if not record or not verify_password(password, record["password_hash"]):
            raise ValueError("Invalid email or password.")
        token = create_session_token(record["uid"], ttl_seconds=3600)
        return {
            "id_token": token,
            "user_id": record["uid"],
            "email": record["email"],
            "expires_in": 3600,
        }

    @staticmethod
    def delete_user(uid: str):
        uid = validate_path_identifier(uid, "User ID")
        if not firebase_app or not auth:
            _DEV_USER_STORE.pop(uid, None)
            return
        try:
            auth.delete_user(uid)
            ref = db.reference(f"users/{uid}")
            ref.delete()
        except Exception as e:
            raise Exception(f"Error deleting user: {str(e)}")

    @staticmethod
    def verify_id_token(id_token: str):
        if not id_token:
            raise ValueError("Authentication token is required")
        token_str = str(id_token).strip()
        if token_str.startswith("csjwt."):
            return verify_session_token(token_str)
        if not firebase_app:
            if token_str.startswith("test-token-"):
                uid = validate_path_identifier(token_str.replace("test-token-", ""), "User ID")
                return {"uid": uid}
            raise RuntimeError("Invalid authentication token.")
        try:
            decoded_token = auth.verify_id_token(token_str)
            return decoded_token
        except Exception as e:
            raise Exception(f"Error verifying ID token: {str(e)}")

    @staticmethod
    def set_user_info(uid: str, user_info: dict):
        uid = validate_path_identifier(uid, "User ID")
        if not firebase_app or not db:
            _DEV_USER_STORE[uid] = user_info
            return
        try:
            ref = db.reference(f"users/{uid}/info")
            ref.set(user_info)
        except Exception as e:
            raise Exception(f"Error setting user info: {str(e)}")

    @staticmethod
    def get_user_info(uid: str):
        uid = validate_path_identifier(uid, "User ID")
        if not firebase_app or not db:
            return _DEV_USER_STORE.get(uid, {"email": f"{uid}@example.com", "uid": uid})
        try:
            ref = db.reference(f"users/{uid}/info")
            user_info = ref.get()
            return user_info
        except Exception as e:
            raise Exception(f"Error getting user info: {str(e)}")

    @staticmethod
    def try_get_user_info(id_token):
        try:
            return Firebase.get_user_info(Firebase.verify_id_token(id_token).get("uid"))
        except Exception:
            return None

    @staticmethod
    def update_user_info(uid: str, updates: dict):
        uid = validate_path_identifier(uid, "User ID")
        if not firebase_app or not db:
            current = _DEV_USER_STORE.get(uid, {})
            current.update(updates)
            _DEV_USER_STORE[uid] = current
            return
        try:
            ref = db.reference(f"users/{uid}/info")
            ref.update(updates)
        except Exception as e:
            raise Exception(f"Error updating user info: {str(e)}")

    @staticmethod
    def create_document(collection: str, document_id: str, data: dict):
        collection = validate_path_identifier(collection, "Collection")
        document_id = validate_path_identifier(document_id, "Document ID")
        try:
            if not firebase_app or not db:
                return
            ref = db.reference(f"{collection}/{document_id}")
            ref.set(data)
        except Exception as e:
            raise Exception(f"Error creating document: {str(e)}")

    @staticmethod
    def get_document(collection: str, document_id: str):
        collection = validate_path_identifier(collection, "Collection")
        document_id = validate_path_identifier(document_id, "Document ID")
        try:
            if not firebase_app or not db:
                return None
            ref = db.reference(f"{collection}/{document_id}")
            return ref.get()
        except Exception as e:
            raise Exception(f"Error retrieving document: {str(e)}")

    @staticmethod
    def update_document(collection: str, document_id: str, updates: dict):
        collection = validate_path_identifier(collection, "Collection")
        document_id = validate_path_identifier(document_id, "Document ID")
        try:
            if not firebase_app or not db:
                return
            ref = db.reference(f"{collection}/{document_id}")
            ref.update(updates)
        except Exception as e:
            raise Exception(f"Error updating document: {str(e)}")

    @staticmethod
    def delete_document(collection: str, document_id: str):
        collection = validate_path_identifier(collection, "Collection")
        document_id = validate_path_identifier(document_id, "Document ID")
        try:
            if not firebase_app or not db:
                return
            ref = db.reference(f"{collection}/{document_id}")
            ref.delete()
        except Exception as e:
            raise Exception(f"Error deleting document: {str(e)}")

    @staticmethod
    def save_chat(uid: str, chat_id: str, messages: list):
        uid = validate_path_identifier(uid, "User ID")
        chat_id = validate_path_identifier(chat_id, "Chat ID")
        try:
            if not isinstance(messages, list):
                raise ValueError("Messages must be a list of dictionaries.")
            for message in messages:
                if not isinstance(message, dict):
                    raise ValueError("Each message must be a dictionary.")

            if not firebase_app or not db:
                existing = _DEV_CHAT_STORE.get((uid, chat_id), [])
                existing.extend(messages)
                _DEV_CHAT_STORE[(uid, chat_id)] = existing
                return

            ref = db.reference(f"users/{uid}/chats/{chat_id}/messages")
            for message in messages:
                ref.push(message)
        except Exception as e:
            raise Exception(f"Error saving messages: {str(e)}")

    @staticmethod
    def delete_chat(uid: str, chat_id: str):
        uid = validate_path_identifier(uid, "User ID")
        chat_id = validate_path_identifier(chat_id, "Chat ID")
        try:
            if not firebase_app or not db:
                _DEV_CHAT_STORE.pop((uid, chat_id), None)
                return
            ref = db.reference(f"users/{uid}/chats/{chat_id}")
            ref.delete()
        except Exception as e:
            raise Exception(f"Error deleting chat session: {str(e)}")
