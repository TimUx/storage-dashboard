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
        json.dumps({"iss": app_id, "iat": now, "exp": now + expiry_seconds}, separators=(",", ":")).encode()
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
    resp = requests.post(
        PURE1_TOKEN_URL,
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt_token,
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

    Uses ``GET /api/1.latest/metrics/history`` with daily resolution to retrieve
    historical values for all subscription licenses.

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
        RuntimeError: If no subscription-license metrics are found.
        requests.HTTPError: On non-2xx API responses.
    """
    import datetime as _dt

    token = get_pure1_access_token(app_id, private_key_pem,
                                   passphrase=passphrase, proxies=proxies)
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    # ── 1. Fetch all subscription licenses (paginated) ───────────────────────
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

    # ── 2. Discover metrics available for subscription-licenses ──────────────
    resp = requests.get(
        f"{PURE1_API_BASE}/metrics",
        headers=headers,
        params={"resource_types": "subscription-licenses", "limit": 100},
        timeout=30, proxies=proxies,
    )
    resp.raise_for_status()
    catalog = resp.json().get("items", [])

    usage_metric = next(
        (m for m in catalog if "usage" in m.get("name", "").lower()),
        None,
    )
    reserved_metric = next(
        (m for m in catalog
         if "reserved" in m.get("name", "").lower()
         or "reservation" in m.get("name", "").lower()),
        None,
    )

    if not usage_metric and not reserved_metric:
        known = ", ".join(m.get("name", "") for m in catalog) or "(none)"
        raise RuntimeError(
            f"Keine Metrik für subscription-licenses in Pure1 gefunden. "
            f"Verfügbare Metriken: {known}"
        )

    metric_names = [m["name"] for m in [usage_metric, reserved_metric] if m]

    # ── 3. Determine best supported resolution (prefer daily) ────────────────
    DAILY_MS = 86_400_000
    resolution = DAILY_MS
    ref_metric = usage_metric or reserved_metric
    availabilities = ref_metric.get("availabilities", [])
    supported = [a["resolution"] for a in availabilities if "resolution" in a]
    if supported and DAILY_MS not in supported:
        # fall back to the coarsest available resolution ≤ daily
        candidates = [r for r in supported if r <= DAILY_MS]
        resolution = max(candidates) if candidates else min(supported)

    # ── 4. Convert dates to Unix millisecond timestamps ──────────────────────
    start_ms = int(_dt.datetime.combine(start_date, _dt.time.min).timestamp() * 1000)
    end_ms = int(_dt.datetime.combine(
        end_date + _dt.timedelta(days=1), _dt.time.min
    ).timestamp() * 1000)

    # ── 5. Build license lookup map ──────────────────────────────────────────
    license_info = {}
    for lic in licenses:
        license_info[lic["id"]] = {
            "name": lic.get("name", ""),
            "subscription_name": (lic.get("subscription") or {}).get("name", ""),
            "service_tier": lic.get("service_tier") or None,
        }

    # ── 6. Fetch metrics/history in batches (32 timeseries per call) ─────────
    # Pure1 API supports up to 32 timeseries (metric × resource combinations) per request.
    # Ref: Pure1 API spec – GET /api/1.latest/metrics/history description.
    MAX_TIMESERIES_PER_REQUEST = 32
    batch_size = max(1, MAX_TIMESERIES_PER_REQUEST // len(metric_names))
    lic_ids = list(license_info.keys())
    names_qs = ",".join(f"'{n}'" for n in metric_names)

    # Accumulate per (date, license_id) → { metric_name: value_bytes }
    data_map: dict = {}

    for i in range(0, len(lic_ids), batch_size):
        batch = lic_ids[i: i + batch_size]
        ids_qs = ",".join(f"'{lid}'" for lid in batch)
        # Build query string without URL-encoding the single quotes.
        # The Pure1 API spec marks string-array parameters as "x-quoted: true",
        # meaning string values must be wrapped in single quotes in the raw query
        # string (e.g. names='metric1','metric2'). URL-encoding the quotes would
        # prevent correct server-side parsing.
        qs = (
            f"names={names_qs}"
            f"&resource_ids={ids_qs}"
            f"&start_time={start_ms}"
            f"&end_time={end_ms}"
            f"&resolution={resolution}"
            f"&aggregation=avg"
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
            resource_id = resources[0].get("id", "")
            for point in item.get("data", []):
                if len(point) < 2 or point[1] is None:
                    continue
                ts_ms, value = point[0], point[1]
                rec_date = _dt.date.fromtimestamp(ts_ms / 1000)
                key = (rec_date, resource_id)
                if key not in data_map:
                    data_map[key] = {}
                data_map[key][m_name] = value

    # ── 7. Build result ───────────────────────────────────────────────────────
    usage_name = usage_metric["name"] if usage_metric else None
    reserved_name = reserved_metric["name"] if reserved_metric else None

    result = []
    for (rec_date, resource_id), values in sorted(data_map.items()):
        info = license_info.get(resource_id)
        if not info:
            continue
        usage_bytes = (values.get(usage_name) or 0) if usage_name else 0
        reserved_bytes = (values.get(reserved_name) or 0) if reserved_name else 0
        result.append({
            "date": rec_date,
            "subscription_name": info["subscription_name"],
            "license_name": info["name"],
            "service_tier": info["service_tier"],
            "reserved_tb": reserved_bytes / 1e12,
            "effective_used_tb": usage_bytes / 1e12,
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
