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
            "aud must not be present – JWT is sent as Authorization: Bearer header "
            "where aud is not required by the Pure1 token endpoint"
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

    def test_jwt_sent_as_authorization_bearer_header(self):
        """JWT must be sent as Authorization: Bearer header, not as subject_token form field."""
        from app.api.pure1_client import get_pure1_access_token
        with patch("app.api.pure1_client.requests.post",
                   return_value=self._mock_response()) as mock_post:
            get_pure1_access_token("pure1:apikey:test", self.private_key_pem)
        _, kwargs = mock_post.call_args
        headers = kwargs.get("headers", {})
        form_data = kwargs.get("data", {})
        assert "Authorization" in headers, "JWT must be in Authorization header"
        assert headers["Authorization"].startswith("Bearer "), (
            "Authorization header must use Bearer scheme"
        )
        assert "subject_token" not in form_data, "'subject_token' form field must not be used"

    def test_no_subject_token_type_in_form_data(self):
        """subject_token_type must not be present – JWT goes in the Authorization header."""
        from app.api.pure1_client import get_pure1_access_token
        with patch("app.api.pure1_client.requests.post",
                   return_value=self._mock_response()) as mock_post:
            get_pure1_access_token("pure1:apikey:test", self.private_key_pem)
        _, kwargs = mock_post.call_args
        form_data = kwargs.get("data", {})
        assert "subject_token_type" not in form_data, (
            "subject_token_type must not be used – JWT is sent as Authorization Bearer header"
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
                f"curl -s -X POST '{PURE1_TOKEN_URL}' \\",
                f"  -H 'Authorization: Bearer {jwt_token}' \\",
                "  -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange'",
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
            f'Authorization: Bearer {_trunc(jwt_token, 50)}',
            '',
            'grant_type = urn:ietf:params:oauth:grant-type:token-exchange',
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
        assert 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' in combined

    def test_step1_curl_command_contains_full_jwt_not_truncated(self):
        """The curl command in step 1 must embed the complete JWT, not a truncated version."""
        _, steps = self._run_steps()
        step1 = steps[0]
        auth_line = next(
            (l for l in step1['lines'] if l.startswith("  -H 'Authorization: Bearer ")),
            None,
        )
        assert auth_line is not None, "No Authorization header found in step 1 curl command"
        assert '…' not in auth_line, "JWT must not be truncated in curl command"

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


