"""Admin JSON endpoint for SMTP connectivity / test mail."""
import logging

from flask import jsonify, request
from flask_login import login_required

from app.mail_sender import send_smtp_message
from app.models import AppSettings
from app.routes.admin import bp

logger = logging.getLogger(__name__)


def _step(num, title, status, lines):
    return {'step': num, 'title': title, 'status': status, 'lines': lines}


def _valid_recipient(addr: str) -> bool:
    if not addr or '@' not in addr:
        return False
    local, _, domain = addr.partition('@')
    return bool(local) and '.' in domain and len(domain) >= 3


@bp.route('/api/smtp-test', methods=['POST'])
@login_required
def api_smtp_test():
    """Send a test message using stored SMTP settings.

    JSON body: ``{"to": "user@example.com"}``

    Response matches the Pure1 test shape: ``success`` and ``steps``.
    """
    settings = AppSettings.query.first()
    payload = request.get_json(silent=True) or {}
    to_email = (payload.get('to') or '').strip()

    if not _valid_recipient(to_email):
        return jsonify({
            'success': False,
            'steps': [_step(1, 'Empfänger prüfen', 'error', [
                'Bitte eine gültige Empfänger-Adresse angeben (Feld „Test an“).',
            ])],
        })

    if not settings:
        return jsonify({
            'success': False,
            'steps': [_step(1, 'Konfiguration', 'error', ['Keine Anwendungseinstellungen gefunden.'])],
        })

    if not settings.smtp_enabled:
        return jsonify({
            'success': False,
            'steps': [_step(1, 'E-Mail-Versand', 'error', [
                'E-Mail-Versand ist deaktiviert. Aktivieren Sie die Option und speichern Sie die Einstellungen.',
            ])],
        })

    host = (settings.smtp_host or '').strip()
    if not host:
        return jsonify({
            'success': False,
            'steps': [_step(1, 'SMTP-Server', 'error', ['SMTP-Host ist nicht konfiguriert.'])],
        })

    port = settings.smtp_port or 587
    use_ssl = bool(settings.smtp_use_ssl)
    use_tls = bool(settings.smtp_use_tls)
    mode = (settings.smtp_auth_mode or 'none').lower()
    from_addr = (settings.smtp_from_address or '').strip()

    step1_lines = [
        f'# Ziel:        {to_email}',
        f'# SMTP:        {host}:{port}',
        f'# Verschlüsselung: {"SMTPS (SSL)" if use_ssl else "STARTTLS" if use_tls else "keine (Klartext)"}',
        f'# Authentifizierung: {mode}',
        f'# Absender:    {from_addr or "(nicht gesetzt)"}',
        '',
        '# Verbindung wird aufgebaut und Testmail wird gesendet …',
    ]

    try:
        subject = 'Storage Dashboard – SMTP-Test'
        body = (
            'Dies ist eine automatische Testnachricht aus den Admin-Einstellungen '
            '(E-Mail / SMTP). Wenn Sie diese Nachricht erhalten, ist der Versand '
            'erfolgreich konfiguriert.\n'
        )
        send_smtp_message(settings, [to_email], subject, body)
        step1_lines.append('')
        step1_lines.append('→ Testmail wurde akzeptiert und übergeben.')
        return jsonify({
            'success': True,
            'steps': [_step(1, 'SMTP-Testmail senden', 'success', step1_lines)],
        })
    except ValueError as exc:
        step1_lines.extend(['', f'Fehler: {exc}'])
        return jsonify({
            'success': False,
            'steps': [_step(1, 'SMTP-Testmail senden', 'error', step1_lines)],
        })
    except Exception as exc:
        logger.warning('SMTP test failed: %s', exc, exc_info=True)
        step1_lines.extend(['', f'Fehler: {exc}'])
        return jsonify({
            'success': False,
            'steps': [_step(1, 'SMTP-Testmail senden', 'error', step1_lines)],
        })
