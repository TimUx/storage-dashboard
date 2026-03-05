"""Tests for the Pure1 REST API client (app/api/pure1_client.py).

All tests run without any network access; the ``requests.post`` call is
patched so we can assert the exact OAuth parameters sent to the token
endpoint without requiring real Pure1 credentials.
"""

import datetime
import json
import time
from unittest.mock import MagicMock, call, patch

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

    def test_jwt_payload_no_sub_claim(self):
        import base64
        from app.api.pure1_client import build_pure1_jwt
        app_id = "pure1:apikey:abc123"
        jwt = build_pure1_jwt(app_id, self.private_key_pem)
        payload_b64 = jwt.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
        assert "sub" not in payload, (
            "sub must not be present – Hosterman reference script uses only iss/iat/exp"
        )

    def test_jwt_payload_no_aud_claim(self):
        import base64
        from app.api.pure1_client import build_pure1_jwt
        jwt = build_pure1_jwt("pure1:apikey:test", self.private_key_pem)
        payload_b64 = jwt.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
        assert "aud" not in payload, (
            "aud must not be present – Pure1 token endpoint does not require aud in the JWT"
        )

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
        """grant_type must be 'urn:ietf:params:oauth:grant-type:token-exchange', not jwt-bearer."""
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

    def test_jwt_sent_as_subject_token_form_field(self):
        """JWT must be sent as subject_token form field, not as Authorization: Bearer header."""
        from app.api.pure1_client import get_pure1_access_token
        with patch("app.api.pure1_client.requests.post",
                   return_value=self._mock_response()) as mock_post:
            get_pure1_access_token("pure1:apikey:test", self.private_key_pem)
        _, kwargs = mock_post.call_args
        headers = kwargs.get("headers", {})
        form_data = kwargs.get("data", {})
        assert "subject_token" in form_data, "JWT must be sent as subject_token form field"
        assert "Authorization" not in headers, (
            "JWT must not be sent as Authorization Bearer header"
        )

    def test_subject_token_type_is_in_form_data(self):
        """subject_token_type must be present with the JWT token type URN."""
        from app.api.pure1_client import get_pure1_access_token
        with patch("app.api.pure1_client.requests.post",
                   return_value=self._mock_response()) as mock_post:
            get_pure1_access_token("pure1:apikey:test", self.private_key_pem)
        _, kwargs = mock_post.call_args
        form_data = kwargs.get("data", {})
        assert "subject_token_type" in form_data, "subject_token_type must be present"
        assert form_data["subject_token_type"] == "urn:ietf:params:oauth:token-type:jwt", (
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


# ---------------------------------------------------------------------------
# api_pure1_test step-logging logic
# ---------------------------------------------------------------------------

class TestApiPure1TestStepLogging:
    """Test the step-logging logic used by the /api/pure1-test route.

    We test the logic directly by importing ``build_pure1_jwt`` and simulating
    the three-step flow (JWT → token → API call) with mocked HTTP calls,
    verifying that the expected ``steps`` structure is produced.
    """

    def setup_method(self):
        self.private_key_pem = _generate_test_private_key_pem()
        self.app_id = "pure1:apikey:unittest"

    def _run_steps(self, mock_token_status=200, mock_token_body=None,
                   mock_api_status=200, mock_api_body=None):
        """Execute the three-step logic used in api_pure1_test() and return steps."""
        import base64 as _b64
        import datetime as _dt
        import json as _json
        import requests as req_lib
        from unittest.mock import MagicMock
        from app.api.pure1_client import build_pure1_jwt, PURE1_TOKEN_URL, PURE1_API_BASE

        if mock_token_body is None:
            mock_token_body = {"access_token": "fake-access-token-xyz"}
        if mock_api_body is None:
            mock_api_body = {"items": [{"name": "array-01"}], "total_item_count": 1}

        steps = []

        def _step(num, title, status, lines):
            return {'step': num, 'title': title, 'status': status, 'lines': lines}

        def _trunc(s, n=60):
            return s[:n] + '…' if len(s) > n else s

        # Step 1 – build JWT
        jwt_token = None
        step1_lines = []
        try:
            jwt_token = build_pure1_jwt(self.app_id, self.private_key_pem)
            hdr_b64, pay_b64, _ = jwt_token.split('.')
            hdr  = _json.loads(_b64.urlsafe_b64decode(hdr_b64  + '=='))
            pay  = _json.loads(_b64.urlsafe_b64decode(pay_b64  + '=='))
            iat_str = _dt.datetime.fromtimestamp(pay['iat'], tz=_dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            exp_str = _dt.datetime.fromtimestamp(pay['exp'], tz=_dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            step1_lines = [
                '# Header:',
                f'  {_json.dumps(hdr)}',
                '',
                '# Payload (Claims):',
                f'  iss : {pay["iss"]}',
                f'  iat : {pay["iat"]}  ({iat_str})',
                f'  exp : {pay["exp"]}  ({exp_str})',
                '',
                '# Signierung: RS256 (PKCS#1 v1.5 / SHA-256)',
                '',
                '# Kodiertes JWT (header.payload.signature):',
                f'  {_trunc(jwt_token, 80)}',
                f'  [{len(jwt_token)} Zeichen gesamt]',
                '',
                '# curl-Befehl für Token-Anfrage (zum manuellen Testen):',
                f"curl -X POST '{PURE1_TOKEN_URL}' \\",
                "  -H 'accept: application/json' \\",
                "  -H 'Content-Type: application/x-www-form-urlencoded' \\",
                f"  -d 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt&subject_token={jwt_token}'",
            ]
            steps.append(_step(1, 'JWT bauen (RS256)', 'success', step1_lines))
        except Exception as exc:
            step1_lines += ['', f'Fehler: {exc}']
            steps.append(_step(1, 'JWT bauen (RS256)', 'error', step1_lines))
            return False, steps

        # Step 2 – token request (mocked)
        step2_lines = [
            f'POST {PURE1_TOKEN_URL}',
            'Content-Type: application/x-www-form-urlencoded',
            '',
            'grant_type         = urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token_type = urn:ietf:params:oauth:token-type:jwt',
            f'subject_token      = {_trunc(jwt_token, 50)}',
        ]
        token_mock = MagicMock()
        token_mock.status_code = mock_token_status
        token_mock.reason = 'OK' if mock_token_status == 200 else 'Unauthorized'
        token_mock.json.return_value = mock_token_body
        if mock_token_status >= 400:
            from requests.exceptions import HTTPError
            http_err = HTTPError(response=token_mock)
            token_mock.raise_for_status.side_effect = http_err
        else:
            token_mock.raise_for_status.return_value = None

        access_token = None
        try:
            step2_lines += ['', f'→  HTTP {token_mock.status_code} {token_mock.reason}']
            token_mock.raise_for_status()
            resp_json = token_mock.json()
            access_token = resp_json.get('access_token', '')
            step2_lines += ['', '# Antwort:', f'  access_token  = {_trunc(access_token, 50)}']
            arrays_url_full = f'{PURE1_API_BASE}/arrays'
            step2_lines += [
                '',
                '# curl-Befehl für API-Anfrage (zum manuellen Testen):',
                f"curl -s '{arrays_url_full}?limit=1' \\",
                f"  -H 'Authorization: Bearer {access_token}'",
            ]
            steps.append(_step(2, 'Access Token abrufen', 'success', step2_lines))
        except Exception as exc:
            step2_lines += ['', f'Fehler: {exc}']
            steps.append(_step(2, 'Access Token abrufen', 'error', step2_lines))
            return False, steps

        # Step 3 – API call (mocked)
        step3_lines = [f'GET {PURE1_API_BASE}/arrays?limit=1']
        api_mock = MagicMock()
        api_mock.status_code = mock_api_status
        api_mock.reason = 'OK' if mock_api_status == 200 else 'Forbidden'
        api_mock.json.return_value = mock_api_body
        if mock_api_status >= 400:
            from requests.exceptions import HTTPError
            http_err = HTTPError(response=api_mock)
            api_mock.raise_for_status.side_effect = http_err
        else:
            api_mock.raise_for_status.return_value = None

        try:
            step3_lines += ['', f'→  HTTP {api_mock.status_code} {api_mock.reason}']
            api_mock.raise_for_status()
            api_data = api_mock.json()
            items = api_data.get('items', [])
            step3_lines += ['', '# Antwort:', f'  items (limit=1)  = {len(items)}']
            steps.append(_step(3, 'API-Test  GET /arrays?limit=1', 'success', step3_lines))
            return True, steps
        except Exception as exc:
            step3_lines += ['', f'Fehler: {exc}']
            steps.append(_step(3, 'API-Test  GET /arrays?limit=1', 'error', step3_lines))
            return False, steps

    # -- Tests ----------------------------------------------------------------

    def test_full_success_returns_three_steps(self):
        success, steps = self._run_steps()
        assert success is True
        assert len(steps) == 3

    def test_all_steps_have_required_keys(self):
        _, steps = self._run_steps()
        for s in steps:
            assert 'step'   in s
            assert 'title'  in s
            assert 'status' in s
            assert 'lines'  in s

    def test_step1_success_contains_jwt_claims(self):
        _, steps = self._run_steps()
        step1 = steps[0]
        assert step1['status'] == 'success'
        combined = '\n'.join(step1['lines'])
        assert 'iss' in combined
        assert 'RS256' in combined
        assert self.app_id in combined

    def test_step2_success_contains_token_endpoint_and_response(self):
        from app.api.pure1_client import PURE1_TOKEN_URL
        _, steps = self._run_steps()
        step2 = steps[1]
        assert step2['status'] == 'success'
        combined = '\n'.join(step2['lines'])
        assert PURE1_TOKEN_URL in combined
        assert 'token-exchange' in combined
        assert 'access_token' in combined

    def test_step3_success_contains_arrays_url_and_response(self):
        from app.api.pure1_client import PURE1_API_BASE
        _, steps = self._run_steps()
        step3 = steps[2]
        assert step3['status'] == 'success'
        combined = '\n'.join(step3['lines'])
        assert f'{PURE1_API_BASE}/arrays' in combined
        assert 'HTTP 200' in combined

    def test_token_failure_stops_at_step2_with_error(self):
        success, steps = self._run_steps(mock_token_status=401)
        assert success is False
        assert len(steps) == 2
        assert steps[1]['status'] == 'error'
        # Step 3 should not be present
        assert all(s['step'] != 3 for s in steps)

    def test_api_failure_stops_at_step3_with_error(self):
        success, steps = self._run_steps(mock_api_status=403)
        assert success is False
        assert len(steps) == 3
        assert steps[2]['status'] == 'error'
        assert steps[0]['status'] == 'success'
        assert steps[1]['status'] == 'success'

    def test_step1_success_contains_curl_command_for_token_endpoint(self):
        """Step 1 must include a full curl command for the token endpoint."""
        from app.api.pure1_client import PURE1_TOKEN_URL
        _, steps = self._run_steps()
        step1 = steps[0]
        assert step1['status'] == 'success'
        combined = '\n'.join(step1['lines'])
        assert 'curl' in combined
        assert PURE1_TOKEN_URL in combined
        assert 'grant_type' in combined
        assert 'token-exchange' in combined

    def test_step1_curl_command_contains_full_jwt_not_truncated(self):
        """The curl command in step 1 must embed the complete JWT, not a truncated version."""
        _, steps = self._run_steps()
        step1 = steps[0]
        subject_token_line = next(
            (l for l in step1['lines'] if 'subject_token=' in l),
            None,
        )
        assert subject_token_line is not None, "No subject_token found in step 1 curl command"
        assert '…' not in subject_token_line, "JWT must not be truncated in curl command"

    def test_step2_success_contains_curl_command_for_api_endpoint(self):
        """Step 2 must include a full curl command for the API endpoint."""
        from app.api.pure1_client import PURE1_API_BASE
        _, steps = self._run_steps()
        step2 = steps[1]
        assert step2['status'] == 'success'
        combined = '\n'.join(step2['lines'])
        assert 'curl' in combined
        assert f'{PURE1_API_BASE}/arrays' in combined

    def test_step2_curl_command_contains_full_access_token(self):
        """The curl command in step 2 must embed the complete access token."""
        _, steps = self._run_steps()
        step2 = steps[1]
        auth_line = next(
            (l for l in step2['lines'] if l.startswith("  -H 'Authorization: Bearer ")),
            None,
        )
        assert auth_line is not None, "No Authorization header found in step 2 curl command"
        assert '…' not in auth_line, "Access token must not be truncated in curl command"
        assert 'fake-access-token-xyz' in auth_line


# ---------------------------------------------------------------------------
# fetch_sod_license_history – resource_ids usage
# ---------------------------------------------------------------------------

class TestFetchSodLicenseHistoryResourceIds:
    """Verify that fetch_sod_license_history uses resource_ids (not resource_names)."""

    def setup_method(self):
        self.private_key_pem = _generate_test_private_key_pem()
        self.app_id = "pure1:apikey:test"

    def _make_licenses(self):
        """Return two fake subscription-license dicts with names containing special chars."""
        return [
            {
                "id": "lic-001",
                "name": "Equinix ExtHou Test, ERZ",
                "subscription": {"name": "Sub-A"},
                "service_tier": "//STaaS-Capacity",
            },
            {
                "id": "lic-002",
                "name": "eShelter Produktion",
                "subscription": {"name": "Sub-B"},
                "service_tier": "//STaaS-Performance",
            },
        ]

    def _make_history_items(self, lic_id, metric_name, ts_ms, value):
        return {
            "name": metric_name,
            "resources": [{"id": lic_id, "name": "ignored"}],
            "data": [[ts_ms, value]],
        }

    def _run_fetch(self, licenses, history_items):
        """Run fetch_sod_license_history with mocked HTTP calls."""
        from app.api.pure1_client import fetch_sod_license_history, PURE1_API_BASE

        token_resp = MagicMock()
        token_resp.json.return_value = {"access_token": "fake-token"}
        token_resp.raise_for_status.return_value = None

        licenses_resp = MagicMock()
        licenses_resp.json.return_value = {"items": licenses, "continuation_token": None}
        licenses_resp.raise_for_status.return_value = None

        history_resp = MagicMock()
        history_resp.status_code = 200
        history_resp.json.return_value = {"items": history_items}
        history_resp.raise_for_status.return_value = None

        captured_urls = []

        def fake_get(url, **kwargs):
            captured_urls.append(url)
            if "subscription-licenses" in url:
                return licenses_resp
            return history_resp

        with patch("app.api.pure1_client.requests.post", return_value=token_resp), \
             patch("app.api.pure1_client.requests.get", side_effect=fake_get):
            result = fetch_sod_license_history(
                self.app_id, self.private_key_pem,
                start_date=datetime.date(2025, 1, 1),
                end_date=datetime.date(2025, 1, 7),
            )
        return result, captured_urls

    def test_uses_resource_ids_not_resource_names(self):
        """The metrics/history request must contain resource_ids, not resource_names."""
        from app.api.pure1_client import fetch_sod_license_history, PURE1_API_BASE

        token_resp = MagicMock()
        token_resp.json.return_value = {"access_token": "fake-token"}
        token_resp.raise_for_status.return_value = None

        licenses_resp = MagicMock()
        licenses_resp.json.return_value = {
            "items": self._make_licenses(),
            "continuation_token": None,
        }
        licenses_resp.raise_for_status.return_value = None

        history_resp = MagicMock()
        history_resp.status_code = 200
        history_resp.json.return_value = {"items": []}
        history_resp.raise_for_status.return_value = None

        get_calls = []

        def fake_get(url, **kwargs):
            get_calls.append(url)
            if "subscription-licenses" in url:
                return licenses_resp
            return history_resp

        with patch("app.api.pure1_client.requests.post", return_value=token_resp), \
             patch("app.api.pure1_client.requests.get", side_effect=fake_get):
            fetch_sod_license_history(
                self.app_id, self.private_key_pem,
                start_date=datetime.date(2025, 1, 1),
                end_date=datetime.date(2025, 1, 7),
            )

        history_urls = [u for u in get_calls if "metrics/history" in u]
        assert history_urls, "metrics/history endpoint must be called"
        for url in history_urls:
            assert "resource_ids=" in url, (
                f"URL must use resource_ids, not resource_names. Got: {url}"
            )
            assert "resource_names=" not in url, (
                f"URL must not use resource_names. Got: {url}"
            )

    def test_license_ids_present_in_query(self):
        """License IDs must be present in the metrics/history query string."""
        from app.api.pure1_client import fetch_sod_license_history

        token_resp = MagicMock()
        token_resp.json.return_value = {"access_token": "fake-token"}
        token_resp.raise_for_status.return_value = None

        licenses_resp = MagicMock()
        licenses_resp.json.return_value = {
            "items": self._make_licenses(),
            "continuation_token": None,
        }
        licenses_resp.raise_for_status.return_value = None

        history_resp = MagicMock()
        history_resp.status_code = 200
        history_resp.json.return_value = {"items": []}
        history_resp.raise_for_status.return_value = None

        get_calls = []

        def fake_get(url, **kwargs):
            get_calls.append(url)
            if "subscription-licenses" in url:
                return licenses_resp
            return history_resp

        with patch("app.api.pure1_client.requests.post", return_value=token_resp), \
             patch("app.api.pure1_client.requests.get", side_effect=fake_get):
            fetch_sod_license_history(
                self.app_id, self.private_key_pem,
                start_date=datetime.date(2025, 1, 1),
                end_date=datetime.date(2025, 1, 7),
            )

        history_urls = [u for u in get_calls if "metrics/history" in u]
        assert history_urls
        combined = " ".join(history_urls)
        assert "lic-001" in combined
        assert "lic-002" in combined

    def test_result_contains_license_name_from_info_dict(self):
        """Result records must use the license display name (not the ID)."""
        ts_ms = int(datetime.datetime(2025, 1, 6).timestamp() * 1000)
        from app.api.pure1_client import METRIC_RESERVED
        history_items = [
            self._make_history_items("lic-001", METRIC_RESERVED, ts_ms, 10 * 1024**4),
        ]
        result, _ = self._run_fetch(self._make_licenses(), history_items)
        assert len(result) == 1
        assert result[0]["license_name"] == "Equinix ExtHou Test, ERZ"
        assert result[0]["subscription_name"] == "Sub-A"

    def test_result_reserved_tb_converted_correctly(self):
        """reserved_tb must be bytes / 1024^4 (tebibytes)."""
        ts_ms = int(datetime.datetime(2025, 1, 6).timestamp() * 1000)
        from app.api.pure1_client import METRIC_RESERVED
        history_items = [
            self._make_history_items("lic-002", METRIC_RESERVED, ts_ms, 2 * 1024**4),
        ]
        result, _ = self._run_fetch(self._make_licenses(), history_items)
        assert len(result) == 1
        assert result[0]["reserved_tb"] == pytest.approx(2.0)

    def test_empty_licenses_returns_empty_list(self):
        """No licenses → empty result without calling metrics/history."""
        result, urls = self._run_fetch([], [])
        assert result == []
        assert not any("metrics/history" in u for u in urls)

    def test_special_chars_in_names_do_not_appear_in_resource_ids_qs(self):
        """Commas and spaces inside license display names must not end up in the query string."""
        from app.api.pure1_client import fetch_sod_license_history

        token_resp = MagicMock()
        token_resp.json.return_value = {"access_token": "fake-token"}
        token_resp.raise_for_status.return_value = None

        licenses_resp = MagicMock()
        licenses_resp.json.return_value = {
            "items": self._make_licenses(),
            "continuation_token": None,
        }
        licenses_resp.raise_for_status.return_value = None

        history_resp = MagicMock()
        history_resp.status_code = 200
        history_resp.json.return_value = {"items": []}
        history_resp.raise_for_status.return_value = None

        get_calls = []

        def fake_get(url, **kwargs):
            get_calls.append(url)
            if "subscription-licenses" in url:
                return licenses_resp
            return history_resp

        with patch("app.api.pure1_client.requests.post", return_value=token_resp), \
             patch("app.api.pure1_client.requests.get", side_effect=fake_get):
            fetch_sod_license_history(
                self.app_id, self.private_key_pem,
                start_date=datetime.date(2025, 1, 1),
                end_date=datetime.date(2025, 1, 7),
            )

        history_urls = [u for u in get_calls if "metrics/history" in u]
        # The display name with comma must not appear – only clean IDs should be present
        for url in history_urls:
            assert "Equinix ExtHou Test" not in url, (
                "License display name with comma must not be in the resource_ids query string"
            )


# ---------------------------------------------------------------------------
# fetch_sod_license_history – UTC timestamps & time-window chunking
# ---------------------------------------------------------------------------

class TestFetchSodLicenseHistoryTimeHandling:
    """Verify that fetch_sod_license_history uses UTC timestamps and chunks large
    time ranges to avoid 400 errors from the Pure1 API."""

    def setup_method(self):
        self.private_key_pem = _generate_test_private_key_pem()
        self.app_id = "pure1:apikey:test"

    def _make_license(self, lic_id="lic-001"):
        return {
            "id": lic_id,
            "name": "Test License",
            "subscription": {"name": "Sub-X"},
            "service_tier": "//STaaS-Capacity",
        }

    def _run_fetch(self, start_date, end_date, licenses=None, fixed_now_ms=None):
        """Run fetch_sod_license_history with mocked HTTP and optionally freeze time."""
        from app.api.pure1_client import fetch_sod_license_history

        if licenses is None:
            licenses = [self._make_license()]

        token_resp = MagicMock()
        token_resp.json.return_value = {"access_token": "fake-token"}
        token_resp.raise_for_status.return_value = None

        licenses_resp = MagicMock()
        licenses_resp.json.return_value = {"items": licenses, "continuation_token": None}
        licenses_resp.raise_for_status.return_value = None

        history_resp = MagicMock()
        history_resp.status_code = 200
        history_resp.json.return_value = {"items": []}
        history_resp.raise_for_status.return_value = None

        captured_urls = []

        def fake_get(url, **kwargs):
            captured_urls.append(url)
            if "subscription-licenses" in url:
                return licenses_resp
            return history_resp

        post_patcher = patch("app.api.pure1_client.requests.post", return_value=token_resp)
        get_patcher  = patch("app.api.pure1_client.requests.get",  side_effect=fake_get)

        if fixed_now_ms is not None:
            # `time.time` is called through the module-level `import time` in
            # pure1_client; patch via that module's reference.
            time_patcher = patch("app.api.pure1_client.time.time", return_value=fixed_now_ms / 1000)
            with post_patcher, get_patcher, time_patcher:
                fetch_sod_license_history(
                    self.app_id, self.private_key_pem,
                    start_date=start_date,
                    end_date=end_date,
                )
        else:
            with post_patcher, get_patcher:
                fetch_sod_license_history(
                    self.app_id, self.private_key_pem,
                    start_date=start_date,
                    end_date=end_date,
                )

        history_urls = [u for u in captured_urls if "metrics/history" in u]
        return history_urls

    def _parse_qs_param(self, url, param):
        """Extract the integer value of a query-string parameter from a URL."""
        for part in url.split("&"):
            if part.startswith(f"{param}=") or f"?{param}=" in part:
                key, _, val = part.partition(f"{param}=")
                return int(val.split("&")[0])
        return None

    # ── UTC timestamp correctness ─────────────────────────────────────────────

    def test_start_time_uses_utc_midnight(self):
        """start_time must be midnight UTC of start_date (not local-timezone midnight)."""
        start_date = datetime.date(2025, 6, 1)
        end_date = datetime.date(2025, 6, 7)
        expected_start_ms = int(
            datetime.datetime(2025, 6, 1, 0, 0, 0, tzinfo=datetime.timezone.utc).timestamp() * 1000
        )
        urls = self._run_fetch(start_date, end_date)
        assert urls, "Expected at least one metrics/history call"
        start_ms_in_url = self._parse_qs_param(urls[0], "start_time")
        assert start_ms_in_url == expected_start_ms, (
            f"start_time should be UTC midnight {expected_start_ms}, got {start_ms_in_url}"
        )

    def test_end_time_is_not_in_the_future(self):
        """end_time must never exceed the current UTC timestamp (prevents Pure1 400 errors)."""
        start_date = datetime.date(2024, 1, 1)
        end_date = datetime.date.today()  # today → naive calculation would put end in future
        # Freeze "now" to a specific moment so the test is deterministic
        now_ms = int(
            datetime.datetime(2026, 3, 5, 11, 0, 0, tzinfo=datetime.timezone.utc).timestamp() * 1000
        )
        urls = self._run_fetch(start_date, end_date, fixed_now_ms=now_ms)
        for url in urls:
            end_ms_in_url = self._parse_qs_param(url, "end_time")
            if end_ms_in_url is not None:
                assert end_ms_in_url <= now_ms, (
                    f"end_time {end_ms_in_url} must not be in the future (now={now_ms})"
                )

    # ── Time-window chunking ──────────────────────────────────────────────────

    def test_two_year_range_produces_multiple_requests(self):
        """A 2-year date range must be split into multiple time-window chunks."""
        start_date = datetime.date(2024, 1, 1)
        end_date = datetime.date(2025, 12, 31)
        # Freeze "now" well beyond end_date so capping doesn't interfere
        now_ms = int(
            datetime.datetime(2026, 6, 1, 0, 0, 0, tzinfo=datetime.timezone.utc).timestamp() * 1000
        )
        urls = self._run_fetch(start_date, end_date, fixed_now_ms=now_ms)
        assert len(urls) > 1, (
            "A 2-year range should produce multiple chunked requests, not a single call"
        )

    def test_chunks_do_not_overlap(self):
        """Adjacent time chunks must not overlap: chunk_n+1 start_time == chunk_n end_time."""
        start_date = datetime.date(2024, 1, 1)
        end_date = datetime.date(2025, 12, 31)
        now_ms = int(
            datetime.datetime(2026, 6, 1, 0, 0, 0, tzinfo=datetime.timezone.utc).timestamp() * 1000
        )
        urls = self._run_fetch(start_date, end_date, fixed_now_ms=now_ms)
        starts = [self._parse_qs_param(u, "start_time") for u in urls]
        ends   = [self._parse_qs_param(u, "end_time")   for u in urls]
        for j in range(1, len(starts)):
            assert starts[j] == ends[j - 1], (
                f"Chunk {j} start_time {starts[j]} must equal previous chunk's "
                f"end_time {ends[j - 1]}"
            )

    def test_chunks_cover_full_range(self):
        """The union of all chunks must exactly cover [start_ms, end_ms]."""
        start_date = datetime.date(2024, 1, 1)
        end_date = datetime.date(2025, 12, 31)
        now_ms = int(
            datetime.datetime(2026, 6, 1, 0, 0, 0, tzinfo=datetime.timezone.utc).timestamp() * 1000
        )
        urls = self._run_fetch(start_date, end_date, fixed_now_ms=now_ms)
        starts = [self._parse_qs_param(u, "start_time") for u in urls]
        ends   = [self._parse_qs_param(u, "end_time")   for u in urls]
        expected_start_ms = int(
            datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc).timestamp() * 1000
        )
        assert min(starts) == expected_start_ms, "First chunk must start at the requested start_ms"
        # Last chunk end must be <= now_ms (capped) and covers through end_date+1 day
        assert max(ends) <= now_ms

    def test_short_range_produces_single_request(self):
        """A short date range (< chunk size) must produce exactly one metrics/history call."""
        start_date = datetime.date(2025, 1, 1)
        end_date = datetime.date(2025, 1, 31)  # ~1 month
        now_ms = int(
            datetime.datetime(2026, 6, 1, 0, 0, 0, tzinfo=datetime.timezone.utc).timestamp() * 1000
        )
        urls = self._run_fetch(start_date, end_date, fixed_now_ms=now_ms)
        assert len(urls) == 1, (
            f"A short (~1 month) range should produce exactly 1 request, got {len(urls)}"
        )

    def test_26_week_range_produces_multiple_requests(self):
        """A 26-week range must be split into multiple chunks.

        Regression test for the 400 Client Error caused by sending the full
        26-week range as a single request (30 timeseries × 26 data-points =
        780 total data-points, which exceeds the Pure1 API limit and returns
        400). With MAX_WEEKS_PER_CHUNK reduced to 13, the same range is split
        into at least 2 requests of ≤ 390 data-points each.
        """
        # Reproduce the exact dates from the reported 400 error:
        # start_time=1709596800000 (2024-03-05 UTC), end_time=1725321600000
        # (2024-09-03 UTC) → 26 weeks.
        start_date = datetime.date(2024, 3, 5)
        end_date = datetime.date(2024, 9, 2)  # end_ms = midnight of Sep 3
        now_ms = int(
            datetime.datetime(2026, 3, 5, 17, 0, 0, tzinfo=datetime.timezone.utc).timestamp() * 1000
        )
        urls = self._run_fetch(start_date, end_date, fixed_now_ms=now_ms)
        assert len(urls) > 1, (
            "A 26-week range must be split into multiple chunked requests to "
            "avoid the Pure1 400 error caused by too many data-points per call. "
            f"Got {len(urls)} request(s)."
        )


# ---------------------------------------------------------------------------
# fetch_subscription_asset_physical_used
# ---------------------------------------------------------------------------

class TestFetchSubscriptionAssetPhysicalUsed:
    """Unit-tests for fetch_subscription_asset_physical_used (no network access)."""

    def setup_method(self):
        self.private_key_pem = _generate_test_private_key_pem()
        self.app_id = "pure1:apikey:test"

    def _token_resp(self):
        r = MagicMock()
        r.json.return_value = {"access_token": "fake-token"}
        r.raise_for_status.return_value = None
        return r

    def _asset_resp(self, body):
        r = MagicMock()
        r.json.return_value = body
        r.raise_for_status.return_value = None
        return r

    def _run(self, asset_body):
        """Call the function with mocked HTTP and return the result."""
        from app.api.pure1_client import fetch_subscription_asset_physical_used
        with patch("app.api.pure1_client.requests.post", return_value=self._token_resp()):
            with patch("app.api.pure1_client.requests.get",
                       return_value=self._asset_resp(asset_body)) as mock_get:
                result = fetch_subscription_asset_physical_used(
                    self.app_id, self.private_key_pem, "pure07"
                )
        return result, mock_get

    def test_returns_physical_used_bytes(self):
        """Returns the float value from advanced_space.physical.total_used.data."""
        body = {
            "items": [{
                "name": "pure07",
                "array": {
                    "advanced_space": {
                        "physical": {
                            "total_used": {
                                "data": 416053195321762.94,
                                "unit": "B",
                            }
                        }
                    }
                }
            }]
        }
        result, _ = self._run(body)
        assert result == pytest.approx(416053195321762.94)

    def test_returns_none_when_items_empty(self):
        """Returns None when the API returns an empty items list (array not found)."""
        result, _ = self._run({"items": []})
        assert result is None

    def test_returns_none_when_advanced_space_missing(self):
        """Returns None when advanced_space key is absent (non-Evergreen array variant)."""
        body = {
            "items": [{
                "name": "pure07",
                "array": {}
            }]
        }
        result, _ = self._run(body)
        assert result is None

    def test_returns_none_when_total_used_data_is_null(self):
        """Returns None when total_used.data is explicitly null in the API response."""
        body = {
            "items": [{
                "name": "pure07",
                "array": {
                    "advanced_space": {
                        "physical": {
                            "total_used": {
                                "data": None,
                                "unit": "B",
                            }
                        }
                    }
                }
            }]
        }
        result, _ = self._run(body)
        assert result is None

    def test_url_contains_advanced_space_true(self):
        """The GET request URL must include advanced_space=true."""
        body = {"items": []}
        _, mock_get = self._run(body)
        url = mock_get.call_args[0][0]
        assert "advanced_space=true" in url, (
            "Request URL must contain advanced_space=true"
        )

    def test_url_contains_array_name_quoted(self):
        """The GET request URL must include the array name wrapped in single quotes."""
        body = {"items": []}
        _, mock_get = self._run(body)
        url = mock_get.call_args[0][0]
        assert "names='pure07'" in url, (
            "Request URL must contain names='pure07' (single-quoted, unencoded)"
        )

    def test_url_targets_subscription_assets_endpoint(self):
        """The GET request must target the /subscription-assets endpoint."""
        from app.api.pure1_client import PURE1_API_BASE
        body = {"items": []}
        _, mock_get = self._run(body)
        url = mock_get.call_args[0][0]
        assert url.startswith(f"{PURE1_API_BASE}/subscription-assets"), (
            f"URL must start with {PURE1_API_BASE}/subscription-assets, got {url}"
        )

    def test_authorization_header_is_bearer_token(self):
        """The GET request must carry an Authorization: Bearer <token> header."""
        body = {"items": []}
        _, mock_get = self._run(body)
        _, kwargs = mock_get.call_args
        headers = kwargs.get("headers", {})
        assert headers.get("Authorization") == "Bearer fake-token", (
            "Authorization header must be 'Bearer fake-token'"
        )

    def test_zero_bytes_returned_as_zero(self):
        """A physical_used value of 0 is valid and must be returned as 0.0."""
        body = {
            "items": [{
                "name": "pure07",
                "array": {
                    "advanced_space": {
                        "physical": {
                            "total_used": {"data": 0, "unit": "B"}
                        }
                    }
                }
            }]
        }
        result, _ = self._run(body)
        assert result == 0.0

    def test_proxies_forwarded_to_requests(self):
        """Proxy dict must be passed to requests.get."""
        from app.api.pure1_client import fetch_subscription_asset_physical_used
        body = {"items": []}
        asset_resp = self._asset_resp(body)
        proxies = {"https": "http://proxy.example.com:8080"}
        with patch("app.api.pure1_client.requests.post", return_value=self._token_resp()):
            with patch("app.api.pure1_client.requests.get",
                       return_value=asset_resp) as mock_get:
                fetch_subscription_asset_physical_used(
                    self.app_id, self.private_key_pem, "pure07", proxies=proxies
                )
        _, kwargs = mock_get.call_args
        assert kwargs.get("proxies") == proxies, (
            "proxies dict must be forwarded to requests.get"
        )
