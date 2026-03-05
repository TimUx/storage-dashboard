"""Pure1 REST API client – JWT token generation and subscription-license fetching.

Authentication flow (RS256 JWT → Bearer token):
  1. Build a long-lived JWT signed with the RSA private key.
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

# ── Hardcoded Pure1 metric names for subscription-license historical data ─────
# These exact names are confirmed by the Pure1 REST API (1.latest).
METRIC_RESERVED       = "subscription_license_reserved_space"
METRIC_ON_DEMAND      = "subscription_license_on_demand_space"
METRIC_EFFECTIVE_USED = "subscription_license_effective_used_space"

# Weekly resolution in milliseconds (604 800 000 ms = 7 days).
# Pure1 retains weekly SoD metrics for up to ~2 years.
WEEKLY_MS = 604_800_000


def _b64url(data: bytes) -> str:
    """Base64url-encode *data* without padding characters."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def build_pure1_jwt(app_id: str, private_key_pem: str, expiry_seconds: int = 31556952,
                    passphrase: str | None = None) -> str:
    """Build a signed RS256 JWT suitable for the Pure1 token endpoint.

    The default expiry of 31 556 952 seconds (≈ 1 Gregorian year,
    365.2425 × 86 400 s) mirrors the exact value used in the official
    Pure Storage reference script (pure1:apikey token exchange utility by
    Cody Hosterman, Pure Storage 2020).

    The payload includes exactly the claims expected by the Pure1 OAuth
    token endpoint (matching the official Pure Storage reference script by
    Cody Hosterman, Pure Storage 2020):

    * ``iss`` – issuer: the Pure1 application ID.
    * ``iat`` / ``exp`` – issued-at / expiry timestamps (seconds since
      UNIX epoch, standard JWT).

    Note: ``sub`` and ``aud`` are intentionally omitted.  The JWT is sent as
    an ``Authorization: Bearer`` header (not as a ``subject_token`` form
    field), and the Pure1 token endpoint does not require these additional
    claims in that usage pattern.

    Args:
        app_id: The Pure1 application/issuer ID (e.g. ``pure1:apikey:…``).
        private_key_pem: PEM-encoded RSA private key string.
        expiry_seconds: How long (seconds) the JWT is valid.  Defaults to
                        31 556 952 (one Gregorian year), matching the official
                        Pure Storage script exactly.
        passphrase: Optional passphrase for an encrypted private key.

    Returns:
        A compact JWT string ``header.payload.signature``.
    """
    now = int(time.time())
    header_b64  = _b64url(json.dumps({"typ": "JWT", "alg": "RS256"}, separators=(",", ":")).encode())
    payload_b64 = _b64url(
        json.dumps(
            {
                "iss": app_id,
                "iat": now,
                "exp": now + expiry_seconds,
            },
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header_b64}.{payload_b64}".encode()

    pem_bytes = private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem
    pass_bytes = passphrase.encode() if isinstance(passphrase, str) else passphrase
    private_key = serialization.load_pem_private_key(pem_bytes, password=pass_bytes)
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b64}.{payload_b64}.{_b64url(signature)}"


def get_pure1_access_token(app_id: str, private_key_pem: str,
                           passphrase: str | None = None,
                           proxies: dict | None = None) -> str:
    """Exchange a freshly-built JWT for a Pure1 Bearer access token.

    The Pure1 REST API token endpoint (``POST /oauth2/1.0/token``) expects the
    JWT to be submitted as the ``subject_token`` form field together with
    ``subject_token_type=urn:ietf:params:oauth:token-type:jwt`` and
    ``grant_type=urn:ietf:params:oauth:grant-type:token-exchange``.

    Reference: Pure1 REST API Swagger – ``POST /oauth2/1.0/token``.

    Args:
        app_id: Pure1 application ID.
        private_key_pem: PEM-encoded RSA private key.
        passphrase: Optional passphrase for an encrypted private key.
        proxies: Optional requests-compatible proxy dict, e.g.
                 ``{'http': 'http://proxy:8080', 'https': 'http://proxy:8080'}``.

    Returns:
        Access token string.

    Raises:
        requests.HTTPError: If the token endpoint returns an error response.
        KeyError: If the response JSON does not contain ``access_token``.
    """
    jwt_token = build_pure1_jwt(app_id, private_key_pem, passphrase=passphrase)
    logger.debug(
        "Pure1 token request: POST %s  subject_token=<jwt>  grant_type=token-exchange",
        PURE1_TOKEN_URL,
    )
    resp = requests.post(
        PURE1_TOKEN_URL,
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "subject_token": jwt_token,
        },
        timeout=15,
        proxies=proxies,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def fetch_sod_license_history(app_id: str, private_key_pem: str,
                              start_date, end_date,
                              passphrase: str | None = None,
                              proxies: dict | None = None) -> list:
    """Fetch historical SoD (subscription-license) usage and reservation data.

    Calls ``GET /api/1.latest/metrics/history`` with:

    * ``names``: the three hardcoded SoD metric names
      (``subscription_license_reserved_space``,
      ``subscription_license_on_demand_space``,
      ``subscription_license_effective_used_space``)
    * ``resource_ids``: comma-separated list of **all** subscription-license
      IDs (retrieved first from ``/subscription-licenses``).  IDs are used
      instead of ``resource_names`` to avoid 400 errors caused by special
      characters (e.g. commas) inside license display names.
    * ``aggregation=max``, ``resolution=604800000`` (weekly)

    This matches the Pure1 API query confirmed by Pure Storage:

    .. code-block:: bash

        curl -G 'https://api.pure1.purestorage.com/api/1.latest/metrics/history' \\
          --data-urlencode "aggregation=max" \\
          --data-urlencode "names='subscription_license_reserved_space','subscription_license_on_demand_space','subscription_license_effective_used_space'" \\
          --data-urlencode "resource_ids='<id1>','<id2>'" \\
          --data-urlencode "resolution=604800000" \\
          --data-urlencode "start_time=<ms>" \\
          --data-urlencode "end_time=<ms>"

    Args:
        app_id: Pure1 application ID.
        private_key_pem: PEM-encoded RSA private key.
        start_date: :class:`datetime.date` – start of the history window (inclusive).
        end_date: :class:`datetime.date` – end of the history window (inclusive).
        passphrase: Optional passphrase for an encrypted private key.
        proxies: Optional requests-compatible proxy dict.

    Returns:
        List of dicts with keys ``date`` (:class:`datetime.date`),
        ``subscription_name``, ``license_name``, ``service_tier``,
        ``reserved_tb``, ``effective_used_tb``.

    Raises:
        requests.HTTPError: On non-2xx API responses.
    """
    import datetime as _dt

    token = get_pure1_access_token(app_id, private_key_pem,
                                   passphrase=passphrase, proxies=proxies)
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    # ── 1. Fetch all subscription licenses (paginated) ───────────────────────
    # We need the license IDs for resource_ids and the subscription /
    # service-tier metadata for the result records.
    licenses = []
    continuation = None
    while True:
        params = {"limit": 200}
        if continuation:
            params["continuation_token"] = continuation
        resp = requests.get(
            f"{PURE1_API_BASE}/subscription-licenses",
            headers=headers, params=params, timeout=30, proxies=proxies,
        )
        resp.raise_for_status()
        body = resp.json()
        licenses.extend(body.get("items", []))
        continuation = body.get("continuation_token")
        if not continuation:
            break

    if not licenses:
        return []

    # ── 2. Build license lookup map keyed by license ID ──────────────────────
    # Key: license id (str) → {"subscription_name": ..., "service_tier": ...,
    #                           "license_name": ...}
    # IDs are plain alphanumeric identifiers without special characters,
    # making them safe to use in query strings (avoids 400 errors caused by
    # commas or other special characters in display names).
    license_info: dict = {}
    for lic in licenses:
        lic_id = lic.get("id", "")
        if lic_id:
            license_info[lic_id] = {
                "subscription_name": (lic.get("subscription") or {}).get("name", ""),
                "service_tier": lic.get("service_tier") or None,
                "license_name": lic.get("name", ""),
            }

    # ── 3. Convert dates to Unix millisecond timestamps ──────────────────────
    start_ms = int(_dt.datetime.combine(start_date, _dt.time.min).timestamp() * 1000)
    end_ms = int(_dt.datetime.combine(
        end_date + _dt.timedelta(days=1), _dt.time.min
    ).timestamp() * 1000)

    # ── 4. Fetch metrics/history in batches ───────────────────────────────────
    # Pure1 API supports up to 32 timeseries (metric × resource combinations)
    # per request.  With 3 metrics we can fit floor(32 / 3) = 10 licenses per
    # batch.
    # Ref: Pure1 API spec – GET /api/1.latest/metrics/history description.
    MAX_TIMESERIES_PER_REQUEST = 32
    metric_names = [METRIC_RESERVED, METRIC_EFFECTIVE_USED, METRIC_ON_DEMAND]
    batch_size = max(1, MAX_TIMESERIES_PER_REQUEST // len(metric_names))
    names_qs = ",".join(f"'{n}'" for n in metric_names)

    lic_ids = list(license_info.keys())

    # key: (date, license_id) → {metric_name: value_bytes}
    data_map: dict = {}

    for i in range(0, len(lic_ids), batch_size):
        batch = lic_ids[i: i + batch_size]
        # Build query string without URL-encoding the single quotes.
        # The Pure1 API spec marks string-array parameters as "x-quoted: true",
        # meaning string values must be wrapped in single quotes in the raw query
        # string (e.g. names='metric1','metric2'). URL-encoding the quotes would
        # prevent correct server-side parsing.
        resource_ids_qs = ",".join(f"'{id_}'" for id_ in batch)
        qs = (
            f"names={names_qs}"
            f"&resource_ids={resource_ids_qs}"
            f"&start_time={start_ms}"
            f"&end_time={end_ms}"
            f"&resolution={WEEKLY_MS}"
            f"&aggregation=max"
        )
        resp = requests.get(
            f"{PURE1_API_BASE}/metrics/history?{qs}",
            headers=headers, timeout=60, proxies=proxies,
        )
        if resp.status_code == 404:
            logger.debug("metrics/history 404 for batch starting at index %d", i)
            continue
        resp.raise_for_status()

        for item in resp.json().get("items", []):
            m_name = item.get("name", "")
            resources = item.get("resources", [])
            if not resources:
                continue
            # resources[0].id is the subscription-license ID
            lic_id = resources[0].get("id", "")
            for point in item.get("data", []):
                if len(point) < 2 or point[1] is None:
                    continue
                ts_ms, value = point[0], point[1]
                rec_date = _dt.date.fromtimestamp(ts_ms / 1000)
                key = (rec_date, lic_id)
                if key not in data_map:
                    data_map[key] = {}
                data_map[key][m_name] = value

    # ── 5. Build result ───────────────────────────────────────────────────────
    result = []
    for (rec_date, lic_id), values in sorted(data_map.items()):
        info = license_info.get(lic_id)
        if not info:
            continue
        result.append({
            "date": rec_date,
            "subscription_name": info["subscription_name"],
            "license_name": info["license_name"],
            "service_tier": info["service_tier"],
            "reserved_tb": (values.get(METRIC_RESERVED) or 0) / 1024**4,
            "effective_used_tb": (values.get(METRIC_EFFECTIVE_USED) or 0) / 1024**4,
            "on_demand_tb": (values.get(METRIC_ON_DEMAND) or 0) / 1024**4,
        })
    return result


def fetch_subscription_licenses(app_id: str, private_key_pem: str,
                                 passphrase: str | None = None,
                                 proxies: dict | None = None) -> list:
    """Fetch all Pure1 subscription licenses and return the ``items`` list.

    Args:
        app_id: Pure1 application ID.
        private_key_pem: PEM-encoded RSA private key.
        passphrase: Optional passphrase for an encrypted private key.
        proxies: Optional requests-compatible proxy dict.

    Returns:
        List of subscription-license dicts as returned by the Pure1 API.

    Raises:
        requests.HTTPError: On non-2xx API responses.
    """
    token = get_pure1_access_token(app_id, private_key_pem,
                                   passphrase=passphrase, proxies=proxies)
    resp = requests.get(
        f"{PURE1_API_BASE}/subscription-licenses",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        timeout=30,
        proxies=proxies,
    )
    resp.raise_for_status()
    return resp.json().get("items", [])
