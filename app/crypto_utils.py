"""Encryption utilities for sensitive data

IMPORTANT: This implementation uses a fixed salt for PBKDF2 key derivation.
This is intentional to ensure consistent encryption keys across the application.
The security model relies on:
1. A strong, secret SECRET_KEY environment variable
2. Fernet's authenticated encryption (includes integrity check)
3. Database access control

Note: Each encrypted value has its own Fernet token with unique IV/nonce.
The fixed salt is only used for deriving the encryption key from SECRET_KEY.

For migration of existing plaintext data:
- decrypt_value() will attempt decryption first
- If decryption fails (InvalidToken), assumes plaintext and returns as-is
- This allows gradual migration without data loss
"""
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import logging

logger = logging.getLogger(__name__)


def get_encryption_key():
    """Get or generate encryption key from SECRET_KEY"""
    secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Derive a proper encryption key from SECRET_KEY using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'storage-dashboard-salt',  # Fixed salt for consistency
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(secret_key.encode()))
    return key


def encrypt_value(value):
    """Encrypt a string value
    
    Raises:
        ValueError: If encryption fails
    """
    if not value:
        return None
    
    try:
        key = get_encryption_key()
        f = Fernet(key)
        encrypted = f.encrypt(value.encode())
        return encrypted.decode()
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise ValueError(f"Failed to encrypt value: {e}")


def decrypt_value(encrypted_value):
    """Decrypt an encrypted string value
    
    For backward compatibility with existing unencrypted data:
    - Attempts to decrypt the value
    - If decryption fails (InvalidToken), assumes plaintext and returns as-is
    - This allows migration of existing systems without data loss
    
    Returns:
        str: Decrypted value or plaintext if decryption fails
    """
    if not encrypted_value:
        return None
    
    try:
        key = get_encryption_key()
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_value.encode())
        return decrypted.decode()
    except Exception:
        # If decryption fails, assume it's plaintext (for backwards compatibility)
        # This allows migration of existing unencrypted data
        # Next save will encrypt the value
        logger.debug(f"Decryption failed, assuming plaintext (backward compatibility)")
        return encrypted_value
