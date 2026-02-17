"""Encryption utilities for sensitive data"""
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os


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
    """Encrypt a string value"""
    if not value:
        return None
    
    try:
        key = get_encryption_key()
        f = Fernet(key)
        encrypted = f.encrypt(value.encode())
        return encrypted.decode()
    except Exception as e:
        # Log error but don't fail - could fall back to plaintext in development
        print(f"Encryption error: {e}")
        return value


def decrypt_value(encrypted_value):
    """Decrypt an encrypted string value"""
    if not encrypted_value:
        return None
    
    try:
        key = get_encryption_key()
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_value.encode())
        return decrypted.decode()
    except Exception as e:
        # If decryption fails, assume it's plaintext (for backwards compatibility)
        # This allows migration of existing unencrypted data
        return encrypted_value
