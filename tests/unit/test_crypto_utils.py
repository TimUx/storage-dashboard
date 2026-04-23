"""Unit-Tests für Verschlüsselung sensibler Einstellungen."""
import os

import pytest

from app.crypto_utils import decrypt_value, encrypt_value


@pytest.mark.unit
def test_encrypt_decrypt_roundtrip():
    os.environ['SECRET_KEY'] = 'unit-test-secret-key-32chars!!'
    plain = 'my-api-password-123'
    enc = encrypt_value(plain)
    assert enc != plain
    assert decrypt_value(enc) == plain


@pytest.mark.unit
def test_encrypt_none_returns_none():
    os.environ.setdefault('SECRET_KEY', 'unit-test-secret-key-32chars!!')
    assert encrypt_value('') is None
    assert encrypt_value(None) is None


@pytest.mark.unit
def test_decrypt_plaintext_passthrough_for_migration():
    os.environ['SECRET_KEY'] = 'unit-test-secret-key-32chars!!'
    assert decrypt_value('not-a-fernet-token') == 'not-a-fernet-token'
