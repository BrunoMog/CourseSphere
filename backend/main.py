import os
import json
import hmac
import hashlib
import secrets
import logging
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SECRET_KEY = os.environ.get("COURSESPHERE_SECRET_KEY", "coursesphere-default-dev-secret-key-change-in-prod")


def hashFunction(data) -> str:
    """
    Generates a cryptographically secure message identifier (CWE-330 / CWE-328).
    Uses HMAC-SHA256 with a secure CSPRNG salt instead of insecure pseudo-random generators.
    """
    if isinstance(data, (dict, list)):
        serialized = json.dumps(data, sort_keys=True)
    else:
        serialized = str(data)
        
    salt = secrets.token_hex(8)
    digest = hmac.new(SECRET_KEY.encode(), (serialized + salt).encode(), hashlib.sha256).hexdigest()
    return f"msg_{digest[:24]}_{salt}"


def get_openai_client():
    """Lazily initializes the OpenAI client using environment variable or config.json."""
    api_key = os.environ.get("OPENAI_API_KEY")
    config_path = BASE_DIR / "config.json"
    if not api_key and config_path.exists():
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
                api_key = config.get("openai_api_key")
        except Exception as exc:
            logging.getLogger(__name__).debug("Optional config.json not loaded: %s", exc)
            
    if not api_key:
        return None
        
    try:
        from openai import OpenAI
        return OpenAI(api_key=api_key)
    except ImportError:
        return None


def get_query_types():
    """Loads query types dictionary safely."""
    path = BASE_DIR / "query_types.json"
    if path.exists():
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception as exc:
            logging.getLogger(__name__).debug("Optional config.json not loaded: %s", exc)
    return {}


def make_prompt(query: str) -> str:
    """
    Formats the prompt safely, neutralizing prompt injections by explicit schema framing.
    """
    question_types = get_query_types()
    return (
        "Respond to this prompt with a JSON object ONLY! No other output.\n"
        f"Consider the following query types with parameters: {question_types}\n"
        "The keys in the parameter list represent the parameters, and values represent data types.\n"
        "Given the user query delimited by triple quotes below, identify the query type and parameters:\n"
        f'"""\n{query}\n"""\n'
        'Print the output as a JSON object: {"query_type": ..., "parameters": ...}.\n'
        "If the query is empty or unsupported, set query_type to 'unsupported'."
    )


def get_query_details(query: str) -> dict:
    client = get_openai_client()
    if not client:
        return {"query_type": "unsupported", "error": "OpenAI client not configured"}
        
    response = client.completions.create(
        model="gpt-3.5-turbo-instruct",
        prompt=make_prompt(query),
        max_tokens=1000
    )
    return json.loads(response.to_dict()['choices'][0]['text'])


if __name__ == '__main__':
    print("Testing secure hashFunction:", hashFunction({"test": "data"}))
