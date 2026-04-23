"""Admin JSON endpoint for Pure1 connectivity test."""
import base64 as _b64
import datetime as _dt
import json as _json

import requests as req_lib
from flask import jsonify
from flask_login import login_required

from app.api.pure1_client import PURE1_API_BASE, PURE1_TOKEN_URL, build_pure1_jwt
from app.models import AppSettings
from app.routes.admin import bp


@bp.route('/api/pure1-test', methods=['POST'])
@login_required
def api_pure1_test():
    """Test Pure1 API connection and return a verbose step-by-step log.

    Each entry in the ``steps`` list represents one stage of the flow
    (JWT build → token request → API call) and contains a ``lines`` list
    that mirrors what you would see in a shell session.

    Response schema::

        {
          "success": true | false,
          "steps": [
            {
              "step": 1,
              "title": "…",
              "status": "success" | "error",
              "lines": ["line1", "line2", …]
            },
            …
          ]
        }
    """

    def _step(num, title, status, lines):
        return {'step': num, 'title': title, 'status': status, 'lines': lines}

    def _trunc(s, n=60):
        return s[:n] + '…' if len(s) > n else s

    settings = AppSettings.query.first()
    if not settings or not settings.pure1_app_id or not settings.pure1_private_key:
        return jsonify({
            'success': False,
            'steps': [_step(1, 'Konfiguration prüfen', 'error', [
                'Pure1 API-Zugangsdaten nicht konfiguriert.',
                'Bitte App ID und Private Key in den Einstellungen hinterlegen.',
            ])],
        })

    steps = []

    # ── Schritt 1: JWT bauen ─────────────────────────────────────────────────
    jwt_token = None
    step1_lines = []
    try:
        jwt_token = build_pure1_jwt(
            settings.pure1_app_id,
            settings.pure1_private_key,
            passphrase=settings.pure1_private_key_passphrase,
        )

        # Decode the actual header + payload from the built JWT for display.
        hdr_b64, pay_b64, _sig_b64 = jwt_token.split('.')
        hdr = _json.loads(_b64.urlsafe_b64decode(hdr_b64 + '=='))
        pay = _json.loads(_b64.urlsafe_b64decode(pay_b64 + '=='))
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
        return jsonify({'success': False, 'steps': steps})

    # ── Schritt 2: JWT gegen Access Token tauschen ───────────────────────────
    access_token = None
    step2_lines = [
        f'POST {PURE1_TOKEN_URL}',
        'Content-Type: application/x-www-form-urlencoded',
        '',
        'grant_type         = urn:ietf:params:oauth:grant-type:token-exchange',
        'subject_token_type = urn:ietf:params:oauth:token-type:jwt',
        f'subject_token      = {_trunc(jwt_token, 50)}',
    ]
    try:
        token_resp = req_lib.post(
            PURE1_TOKEN_URL,
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token_type': 'urn:ietf:params:oauth:token-type:jwt',
                'subject_token': jwt_token,
            },
            timeout=15,
            proxies=settings.get_proxies() or None,
        )
        step2_lines += [
            '',
            f'→  HTTP {token_resp.status_code} {token_resp.reason}',
        ]
        token_resp.raise_for_status()
        resp_json = token_resp.json()
        access_token = resp_json.get('access_token', '')
        step2_lines += [
            '',
            '# Antwort:',
            f'  access_token  = {_trunc(access_token, 50)}',
            f'  [{len(access_token)} Zeichen]',
        ]
        for key in ('token_type', 'expires_in', 'issued_token_type'):
            if key in resp_json:
                step2_lines.append(f'  {key:<14}= {resp_json[key]}')
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
        if hasattr(exc, 'response') and exc.response is not None:
            step2_lines.append(f'Antwort: {exc.response.text[:400]}')
        steps.append(_step(2, 'Access Token abrufen', 'error', step2_lines))
        return jsonify({'success': False, 'steps': steps})

    # ── Schritt 3: API-Test  GET /arrays ─────────────────────────────────────
    arrays_url = f'{PURE1_API_BASE}/arrays'
    step3_lines = [
        f'GET {arrays_url}?limit=1',
        f'Authorization: Bearer {_trunc(access_token, 50)}',
    ]
    try:
        api_resp = req_lib.get(
            arrays_url,
            headers={'Authorization': f'Bearer {access_token}'},
            params={'limit': 1},
            timeout=15,
            proxies=settings.get_proxies() or None,
        )
        step3_lines += [
            '',
            f'→  HTTP {api_resp.status_code} {api_resp.reason}',
        ]
        api_resp.raise_for_status()
        api_data = api_resp.json()
        items = api_data.get('items', [])
        total = api_data.get('total_item_count', '?')
        step3_lines += [
            '',
            '# Antwort:',
            f'  total_item_count = {total}',
            f'  items (limit=1)  = {len(items)}',
        ]
        if items:
            step3_lines.append(f'  erstes Array     = {items[0].get("name", "?")}')
        steps.append(_step(3, 'API-Test  GET /arrays?limit=1', 'success', step3_lines))
        return jsonify({'success': True, 'steps': steps})

    except Exception as exc:
        step3_lines += ['', f'Fehler: {exc}']
        if hasattr(exc, 'response') and exc.response is not None:
            step3_lines.append(f'Antwort: {exc.response.text[:400]}')
        steps.append(_step(3, 'API-Test  GET /arrays?limit=1', 'error', step3_lines))
        return jsonify({'success': False, 'steps': steps})
