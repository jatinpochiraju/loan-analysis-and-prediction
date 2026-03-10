import os
import hashlib
from cryptography.fernet import Fernet

# In a real system the key would be stored securely and rotated.
FERNET_KEY = os.getenv("FERNET_KEY")
if not FERNET_KEY:
    # generate a key once; for demo purposes only
    FERNET_KEY = Fernet.generate_key().decode()

fernet = Fernet(FERNET_KEY.encode())


def encrypt_pii(data: str) -> str:
    """Encrypt a piece of PII using Fernet and return a text token."""
    if data is None:
        return None
    return fernet.encrypt(data.encode()).decode()


def decrypt_pii(token: str) -> str:
    """Decrypt a Fernet token back to plaintext."""
    if token is None:
        return None
    return fernet.decrypt(token.encode()).decode()


def generate_block_hash(prev_hash: str, user_id: int, amount: float, timestamp) -> str:
    """Compute a SHA-256 hash of the provided block components."""
    pieces = [prev_hash or "", str(user_id), str(amount), str(timestamp)]
    payload = "|".join(pieces)
    return hashlib.sha256(payload.encode()).hexdigest()
