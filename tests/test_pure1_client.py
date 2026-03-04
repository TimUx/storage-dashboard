"""Tests for the Pure1 REST API client (app/api/pure1_client.py).

All tests run without any network access; the ``requests.post`` call is
patched so we can assert the exact OAuth parameters sent to the token
endpoint without requiring real Pure1 credentials.
"""

import json
import time
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _generate_test_private_key_pem() -> str:
    """Return a freshly-generated 2048-bit RSA private key as a PEM string."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


# ---------------------------------------------------------------------------
# build_pure1_jwt
# ---------------------------------------------------------------------------

class TestBuildPure1Jwt:
    """Unit-tests for the JWT builder."""

    def setup_method(self):
        self.private_key_pem = _generate_test_private_key_pem()

    def test_jwt_has_three_segments(self):
        from app.api.pure1_client import build_pure1_jwt
        jwt = build_pure1_jwt("pure1:apikey:test", self.private_key_pem)
        parts = jwt.split(".")
        assert len(parts) == 3, "JWT must be header.payload.signature"

    def test_jwt_header_alg_is_rs256(self):
        import base64
        from app.api.pure1_client import build_pure1_jwt
        jwt = build_pure1_jwt("pure1:apikey:test", self.private_key_pem)
        header_b64 = jwt.split(".")[0]
        # Add padding back before decoding.
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
        assert header["alg"] == "RS256"
        assert header["typ"] == "JWT"

    def test_jwt_payload_iss_matches_app_id(self):
        import base64
        from app.api.pure1_client import build_pure1_jwt
        app_id = "pure1:apikey:abc123"
        jwt = build_pure1_jwt(app_id, self.private_key_pem)
        payload_b64 = jwt.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
        assert payload["iss"] == app_id

    def test_jwt_payload_contains_iat_and_exp(self):
        import base64
        from app.api.pure1_client import build_pure1_jwt
        before = int(time.time())
        jwt = build_pure1_jwt("pure1:apikey:test", self.private_key_pem)
        after = int(time.time())
        payload_b64 = jwt.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
        assert before <= payload["iat"] <= after
        assert payload["exp"] > payload["iat"]


# ---------------------------------------------------------------------------
# get_pure1_access_token – OAuth request parameters
# ---------------------------------------------------------------------------

class TestGetPure1AccessTokenOAuthParams:
    """Verify that the correct OAuth 2.0 Token Exchange parameters are sent."""

    def setup_method(self):
        self.private_key_pem = _generate_test_private_key_pem()

    def _mock_response(self, token: str = "test-access-token"):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"access_token": token}
        mock_resp.raise_for_status.return_value = None
        return mock_resp

    def test_uses_token_exchange_grant_type(self):
        """grant_type must be token-exchange, not jwt-bearer."""
        from app.api.pure1_client import get_pure1_access_token
        with patch("app.api.pure1_client.requests.post",
                   return_value=self._mock_response()) as mock_post:
            get_pure1_access_token("pure1:apikey:test", self.private_key_pem)
        _, kwargs = mock_post.call_args
        form_data = kwargs.get("data", {})
        assert form_data["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange", (
            "grant_type must be 'urn:ietf:params:oauth:grant-type:token-exchange' "
            "(Pure1 API spec OauthGrantType)"
        )

    def test_uses_subject_token_not_assertion(self):
        """JWT must be sent as subject_token, not assertion."""
        from app.api.pure1_client import get_pure1_access_token
        with patch("app.api.pure1_client.requests.post",
                   return_value=self._mock_response()) as mock_post:
            get_pure1_access_token("pure1:apikey:test", self.private_key_pem)
        _, kwargs = mock_post.call_args
        form_data = kwargs.get("data", {})
        assert "subject_token" in form_data, "JWT must be in 'subject_token' field"
        assert "assertion" not in form_data, "'assertion' field must not be used"

    def test_includes_subject_token_type(self):
        """subject_token_type must be set to the JWT token type URI."""
        from app.api.pure1_client import get_pure1_access_token
        with patch("app.api.pure1_client.requests.post",
                   return_value=self._mock_response()) as mock_post:
            get_pure1_access_token("pure1:apikey:test", self.private_key_pem)
        _, kwargs = mock_post.call_args
        form_data = kwargs.get("data", {})
        assert form_data.get("subject_token_type") == "urn:ietf:params:oauth:token-type:jwt", (
            "subject_token_type must be 'urn:ietf:params:oauth:token-type:jwt'"
        )

    def test_posts_to_correct_url(self):
        from app.api.pure1_client import get_pure1_access_token, PURE1_TOKEN_URL
        with patch("app.api.pure1_client.requests.post",
                   return_value=self._mock_response()) as mock_post:
            get_pure1_access_token("pure1:apikey:test", self.private_key_pem)
        url = mock_post.call_args[0][0]
        assert url == PURE1_TOKEN_URL

    def test_returns_access_token_string(self):
        from app.api.pure1_client import get_pure1_access_token
        with patch("app.api.pure1_client.requests.post",
                   return_value=self._mock_response("my-bearer-token")):
            token = get_pure1_access_token("pure1:apikey:test", self.private_key_pem)
        assert token == "my-bearer-token"
