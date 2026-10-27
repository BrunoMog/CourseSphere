# firebase.py
import os
import re
import logging
from pathlib import Path

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
    """Neutralizes path traversal attempts in Firebase database paths."""
    if not identifier or not re.match(r"^[a-zA-Z0-9_\-]+$", str(identifier)):
        raise ValueError(f"Invalid {name}: must contain only alphanumeric, underscore, or hyphen characters.")
    return str(identifier)

_DEV_USER_STORE = {}


class Firebase:
    @staticmethod
    def create_user(email: str, password: str):
        if not firebase_app or not auth:
            # Dev/Test fallback
            return {
                "message": "User created successfully",
                "user_id": f"dev-uid-{email.split('@')[0]}",
                "email": email
            }
        try:
            user = auth.create_user(email=email, password=password)
            user_data = {
            "message": "User created successfully",
            "user_id": user.uid,
            "email": user.email,
            } 
            return user_data
        except Exception as e:
            raise Exception(f"Error creating user: {str(e)}")
        
    @staticmethod
    def delete_user(uid: str):
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
        if not firebase_app:
            # Development/Testing fallback when credentials are not loaded
            if str(id_token).startswith("test-token-"):
                return {"uid": str(id_token).replace("test-token-", "")}
            raise RuntimeError("Firebase service is not initialized on the server.")
        try:
            decoded_token = auth.verify_id_token(id_token)
            return decoded_token
        except Exception as e:
            raise Exception(f"Error verifying ID token: {str(e)}")

    @staticmethod
    def set_user_info(uid: str, user_info: dict):
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
            return Firebase.get_user_info(Firebase.verify_id_token(id_token).get('uid'))
        except Exception:
            return None



    @staticmethod
    def update_user_info(uid: str, updates: dict):
        try:
            ref = db.reference(f"users/{uid}/info")
            ref.update(updates)
        except Exception as e:
            raise Exception(f"Error updating user info: {str(e)}")
    
    @staticmethod
    def create_document(collection: str, document_id: str, data: dict):
        """
        Creates a document in a specified collection.
        
        :param collection: The name of the collection.
        :param document_id: The ID of the document to create.
        :param data: A dictionary of the data to store in the document.
        """
        try:
            ref = db.reference(f"{collection}/{document_id}")
            ref.set(data)
        except Exception as e:
            raise Exception(f"Error creating document: {str(e)}")

    @staticmethod
    def get_document(collection: str, document_id: str):
        """
        Retrieves a document from a specified collection.
        
        :param collection: The name of the collection.
        :param document_id: The ID of the document to retrieve.
        :return: The document data as a dictionary.
        """
        try:
            ref = db.reference(f"{collection}/{document_id}")
            document = ref.get()
            return document
        except Exception as e:
            raise Exception(f"Error retrieving document: {str(e)}")

    @staticmethod
    def update_document(collection: str, document_id: str, updates: dict):
        """
        Updates a document in a specified collection.
        
        :param collection: The name of the collection.
        :param document_id: The ID of the document to update.
        :param updates: A dictionary of the updates to apply to the document.
        """
        try:
            ref = db.reference(f"{collection}/{document_id}")
            ref.update(updates)
        except Exception as e:
            raise Exception(f"Error updating document: {str(e)}")

    @staticmethod
    def delete_document(collection: str, document_id: str):
        """
        Deletes a document from a specified collection.
        
        :param collection: The name of the collection.
        :param document_id: The ID of the document to delete.
        """
        try:
            ref = db.reference(f"{collection}/{document_id}")
            ref.delete()
        except Exception as e:
            raise Exception(f"Error deleting document: {str(e)}")
        

    @staticmethod
    def save_chat(uid: str, chat_id: str, messages: list):
        uid = validate_path_identifier(uid, "User ID")
        chat_id = validate_path_identifier(chat_id, "Chat ID")
        try:
            if not firebase_app:
                return  # Mock save for local tests
            ref = db.reference(f"users/{uid}/chats/{chat_id}/messages")
            
            # Ensure messages is a list of dictionaries
            if isinstance(messages, list):
                for message in messages:
                    if isinstance(message, dict):
                        ref.push(message)  # Add each message to the Firebase database
                    else:
                        raise ValueError("Each message must be a dictionary.")
            else:
                raise ValueError("Messages must be a list of dictionaries.")
        except Exception as e:
            raise Exception(f"Error saving messages: {str(e)}")

    @staticmethod
    def delete_chat(uid: str, chat_id: str):
        uid = validate_path_identifier(uid, "User ID")
        chat_id = validate_path_identifier(chat_id, "Chat ID")
        try:
            if not firebase_app:
                return  # Mock delete for local tests
            ref = db.reference(f"users/{uid}/chats/{chat_id}")
            ref.delete()  # Deletes the entire chat session
        except Exception as e:
            raise Exception(f"Error deleting chat session: {str(e)}")
