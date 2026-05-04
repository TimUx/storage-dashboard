"""SMTP mail sending using application AppSettings (for reports, alerts, tests)."""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.settings import AppSettings

logger = logging.getLogger(__name__)


def _as_bool(val) -> bool:
    return bool(val) if val is not None else False


def send_smtp_message(
    settings: AppSettings,
    to_addrs: list[str],
    subject: str,
    body_text: str,
    *,
    timeout: int = 30,
) -> None:
    """Send one plain-text email using the configured SMTP settings.

    Raises ``ValueError`` for missing or inconsistent configuration, or
    ``smtplib.SMTPException`` / ``OSError`` on transport errors.
    """
    if not _as_bool(getattr(settings, 'smtp_enabled', None)):
        raise ValueError('E-Mail-Versand ist deaktiviert.')

    host = (getattr(settings, 'smtp_host', None) or '').strip()
    if not host:
        raise ValueError('SMTP-Server (Host) ist nicht konfiguriert.')

    port = getattr(settings, 'smtp_port', None) or 587
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise ValueError('SMTP-Port ist ungültig.') from None

    use_ssl = _as_bool(getattr(settings, 'smtp_use_ssl', None))
    use_tls = _as_bool(getattr(settings, 'smtp_use_tls', None))

    from_addr = (getattr(settings, 'smtp_from_address', None) or '').strip()
    if not from_addr:
        raise ValueError('Absender-E-Mail-Adresse (From) ist nicht konfiguriert.')

    from_name = (getattr(settings, 'smtp_from_name', None) or '').strip()
    auth_mode = (getattr(settings, 'smtp_auth_mode', None) or 'none').strip().lower()
    if auth_mode not in ('none', 'password'):
        auth_mode = 'none'

    username = (getattr(settings, 'smtp_username', None) or '').strip()
    password = getattr(settings, 'smtp_password', None) or ''

    if auth_mode == 'password' and not username:
        raise ValueError('SMTP-Benutzername fehlt (Authentifizierung: Passwort).')

    if auth_mode == 'password' and not password:
        raise ValueError('SMTP-Passwort fehlt (Authentifizierung: Passwort).')

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = formataddr((from_name, from_addr)) if from_name else from_addr
    msg['To'] = ', '.join(to_addrs)
    msg.set_content(body_text)

    context = ssl.create_default_context()

    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=timeout)

        try:
            server.ehlo()
            if use_tls and not use_ssl:
                server.starttls(context=context)
                server.ehlo()
            if auth_mode == 'password':
                server.login(username, password)
            server.send_message(msg)
        finally:
            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass
    except smtplib.SMTPException:
        logger.warning('SMTP send failed to %s (host=%s port=%s)', to_addrs, host, port, exc_info=True)
        raise
    except OSError:
        logger.warning('SMTP connection failed (host=%s port=%s)', host, port, exc_info=True)
        raise
