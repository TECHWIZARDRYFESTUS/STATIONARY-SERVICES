import base64
import hashlib
import hmac
import json
import secrets
import time

import bcrypt

PASSWORD_ITERATIONS = 600_000

def hash_password(password: str) -> str:
    encoded_password = password.encode("utf-8")
    if len(encoded_password) > 72:
        raise ValueError("Password must be no more than 72 UTF-8 bytes for bcrypt.")
    return bcrypt.hashpw(encoded_password, bcrypt.gensalt()).decode("ascii")

def verify_password(password: str, password_hash: str) -> bool:
    if password_hash.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            encoded_password = password.encode("utf-8")
            return len(encoded_password) <= 72 and bcrypt.checkpw(
                encoded_password,
                password_hash.encode("ascii"),
            )
        except (ValueError, TypeError, UnicodeEncodeError):
            return False

    try:
        algorithm, iterations, encoded_salt, encoded_digest = password_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(encoded_salt.encode("ascii"))
        expected = base64.urlsafe_b64decode(encoded_digest.encode("ascii"))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False

def password_fingerprint(password_hash: str) -> str:
    return hashlib.sha256(password_hash.encode("utf-8")).hexdigest()

def create_session_token(user_id: int, password_hash: str, secret: str, ttl_seconds: int) -> str:
    payload = json.dumps({
        "user_id": user_id,
        "expires_at": int(time.time()) + ttl_seconds,
        "credential_version": password_fingerprint(password_hash),
    }, separators=(",", ":")).encode("utf-8")
    encoded_payload = base64.urlsafe_b64encode(payload).rstrip(b"=")
    signature = hmac.new(secret.encode("utf-8"), encoded_payload, hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=")
    return f"{encoded_payload.decode('ascii')}.{encoded_signature.decode('ascii')}"

def read_session_token(token: str, secret: str) -> tuple[int, str] | None:
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
        payload_bytes = encoded_payload.encode("ascii")
        signature = base64.urlsafe_b64decode(encoded_signature + "=" * (-len(encoded_signature) % 4))
        expected_signature = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_signature):
            return None
        payload = base64.urlsafe_b64decode(payload_bytes + b"=" * (-len(payload_bytes) % 4))
        data = json.loads(payload)
        if int(data["expires_at"]) <= int(time.time()):
            return None
        user_id = int(data["user_id"])
        credential_version = str(data["credential_version"])
        return (user_id, credential_version) if user_id > 0 else None
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None
