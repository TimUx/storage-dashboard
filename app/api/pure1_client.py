"""Pure1 REST API client – JWT token generation and subscription-license fetching.

Authentication flow (RS256 JWT → Bearer token):
  1. Build a short-lived JWT signed with the RSA private key.
  2. POST the JWT to Pure1's OAuth endpoint to obtain an access token.
  3. Use that Bearer token for subsequent API calls.

Reference:
  https://support.purestorage.com/bundle/m_pure1_manage_rest_api/page/
  Evergreen_Subscriptions/Evergreen_One/library/common_content/
  t_steps_to_generate_an_authentication_access_token.html
"""
import base64
import json
import logging
import time

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

logger = logging.getLogger(__name__)

PURE1_TOKEN_URL = "https://api.pure1.purestorage.com/oauth2/1.0/token"
PURE1_API_BASE  = "https://api.pure1.purestorage.com/api/1.latest"


def _b64url(data: bytes) -> str:
    """Base64url-encode *data* without padding characters."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def build_pure1_jwt(app_id: str, private_key_pem: str, expiry_seconds: int = 30,
                    passphrase: str | None = None) -> str:
    """Build a signed RS256 JWT suitable for the Pure1 token endpoint.

    Args:
        app_id: The Pure1 application/issuer ID (e.g. ``pure1:apikey:…``).
        private_key_pem: PEM-encoded RSA private key string.
        expiry_seconds: How long (seconds) the JWT is valid (default 30 s is sufficient
                        for the token exchange).
        passphrase: Optional passphrase for an encrypted private key.

    Returns:
        A compact JWT string ``header.payload.signature``.
    """
    now = int(time.time())
    header_b64  = _b64url(json.dumps({"typ": "JWT", "alg": "RS256"}, separators=(",", ":")).encode())
    payload_b64 = _b64url(
        json.dumps({"iss": app_id, "iat": now, "exp": now + expiry_seconds}, separators=(",", ":")).encode()
    )
    signing_input = f"{header_b64}.{payload_b64}".encode()

    pem_bytes = private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem
    pass_bytes = passphrase.encode() if isinstance(passphrase, str) else passphrase
    private_key = serialization.load_pem_private_key(pem_bytes, password=pass_bytes)
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b64}.{payload_b64}.{_b64url(signature)}"


def get_pure1_access_token(app_id: str, private_key_pem: str,
                           passphrase: str | None = None) -> str:
    """Exchange a freshly-built JWT for a Pure1 Bearer access token.

    Args:
        app_id: Pure1 application ID.
        private_key_pem: PEM-encoded RSA private key.
        passphrase: Optional passphrase for an encrypted private key.

    Returns:
        Access token string.

    Raises:
        requests.HTTPError: If the token endpoint returns an error response.
        KeyError: If the response JSON does not contain ``access_token``.
    """
    jwt_token = build_pure1_jwt(app_id, private_key_pem, passphrase=passphrase)
    resp = requests.post(
        PURE1_TOKEN_URL,
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt_token,
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def fetch_subscription_licenses(app_id: str, private_key_pem: str,
                                 passphrase: str | None = None) -> list:
    """Fetch all Pure1 subscription licenses and return the ``items`` list.

    Args:
        app_id: Pure1 application ID.
        private_key_pem: PEM-encoded RSA private key.
        passphrase: Optional passphrase for an encrypted private key.

    Returns:
        List of subscription-license dicts as returned by the Pure1 API.

    Raises:
        requests.HTTPError: On non-2xx API responses.
    """
    token = get_pure1_access_token(app_id, private_key_pem, passphrase=passphrase)
    resp = requests.get(
        f"{PURE1_API_BASE}/subscription-licenses",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("items", [])
