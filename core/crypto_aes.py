"""
ByteENDE core · AES-256-GCM encrypt/decrypt with a password.
AEAD (GCM) is used instead of plain CBC so a tampered ciphertext fails to decrypt
instead of silently returning garbage. Key is derived from the password with PBKDF2.
Output packs salt + nonce + ciphertext+tag into one Base64 string so callers only
ever handle a single string.

Uses the `cryptography` package (OpenSSL-backed, widely available/pre-installed)
rather than pycryptodome - functionally equivalent for this use case.
"""
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
PBKDF2_ITERS = 200_000


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, iterations=PBKDF2_ITERS)
    return kdf.derive(password.encode('utf-8'))


def encrypt(plaintext: str, password: str) -> str:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)  # ct already includes the 16-byte tag
    blob = salt + nonce + ct
    return base64.b64encode(blob).decode('ascii')


def decrypt(blob_b64: str, password: str) -> str:
    try:
        blob = base64.b64decode(blob_b64)
        salt, nonce, ct = blob[:SALT_LEN], blob[SALT_LEN:SALT_LEN + NONCE_LEN], blob[SALT_LEN + NONCE_LEN:]
        key = _derive_key(password, salt)
        aesgcm = AESGCM(key)
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt.decode('utf-8')
    except Exception:
        raise ValueError('Decryption failed - wrong password or corrupted/tampered data')
