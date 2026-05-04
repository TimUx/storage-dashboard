"""Daily digest e-mail: snapshots whose TTL expires within the next 24 hours.

Sent at most once per calendar day in the configured app timezone, after 07:00,
when the snapshot collector wake cycle runs (typically every 15 minutes).
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta

import pytz

logger = logging.getLogger(__name__)

_RECIPIENT_SPLIT = re.compile(r'[\s,;]+')


def smtp_config_complete(settings) -> bool:
    """True when outbound SMTP is enabled and minimally configured (same rules as send)."""
    if not settings or not getattr(settings, 'smtp_enabled', None):
        return False
    if not (getattr(settings, 'smtp_host', None) or '').strip():
        return False
    if not (getattr(settings, 'smtp_from_address', None) or '').strip():
        return False
    auth = (getattr(settings, 'smtp_auth_mode', None) or 'none').strip().lower()
    if auth == 'password':
        if not (getattr(settings, 'smtp_username', None) or '').strip():
            return False
        if not getattr(settings, 'smtp_password', None):
            return False
    return True


def parse_recipient_list(raw: str | None) -> list[str]:
    """Split comma/semicolon/whitespace-separated addresses; basic de-dupe preserving order."""
    if not raw or not str(raw).strip():
        return []
    parts = [p for p in _RECIPIENT_SPLIT.split(str(raw).strip()) if p]
    seen: set[str] = set()
    out: list[str] = []
    for p in parts:
        key = p.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def _query_expiring_records(utc_now_naive, within_hours: int = 24):
    """Snapshots with TTL in (now, now + within_hours] (naive UTC, matches DB)."""
    from app.models import SnapshotRecord

    end = utc_now_naive + timedelta(hours=within_hours)
    return (
        SnapshotRecord.query.filter(
            SnapshotRecord.ttl.isnot(None),
            SnapshotRecord.ttl > utc_now_naive,
            SnapshotRecord.ttl <= end,
        )
        .order_by(SnapshotRecord.ttl.asc(), SnapshotRecord.sid.asc())
        .all()
    )


def _format_body(rows, tz_name: str) -> str:
    lines = [
        'Storage Dashboard – Snapshots mit TTL-Ablauf in den nächsten 24 Stunden',
        f'(Zeitbasis Datenbank: UTC; Anwendungszeitzone laut Einstellungen: {tz_name})',
        '',
    ]
    if not rows:
        lines.append('Keine Einträge in diesem Fenster.')
        return '\n'.join(lines)
    lines.append(f'Anzahl: {len(rows)}')
    lines.append('')
    for rec in rows:
        ttl_s = rec.ttl.strftime('%Y-%m-%d %H:%M:%S') if rec.ttl else '—'
        ct_s = (
            rec.creation_time.strftime('%Y-%m-%d %H:%M:%S') if rec.creation_time else '—'
        )
        lines.append(f'- SID {rec.sid}  |  Erstellung {ct_s} UTC  |  TTL {ttl_s} UTC')
        if rec.comment:
            lines.append(f'    Kommentar: {rec.comment}')
    lines.append('')
    lines.append('Hinweis: Nach Ablauf der TTL können Snapshots (je nach Konfiguration) automatisch')
    lines.append('auf dem Storage gelöscht werden; manuelle Löschungen nutzen eine 24h-Frist.')
    return '\n'.join(lines)


def maybe_send_snap_ttl_expiry_digest(app) -> None:
    """If enabled and due, send digest mail (no-op when SMTP incomplete or not past 07:00 local)."""
    from app import db
    from app.mail_sender import send_smtp_message
    from app.models import AppSettings

    with app.app_context():
        settings = AppSettings.query.first()
        if not settings or not getattr(settings, 'snap_ttl_expiry_email_enabled', None):
            return

        recipients = parse_recipient_list(getattr(settings, 'snap_ttl_expiry_recipients', None))
        if not recipients:
            logger.debug('Snapshot TTL digest: no recipients configured, skipping.')
            return

        if not smtp_config_complete(settings):
            logger.debug('Snapshot TTL digest: SMTP not fully configured, skipping send.')
            return

        tz_name = (settings.timezone or 'Europe/Berlin').strip() or 'Europe/Berlin'
        try:
            tz = pytz.timezone(tz_name)
        except Exception:
            logger.warning('Snapshot TTL digest: invalid timezone %r, using Europe/Berlin', tz_name)
            tz = pytz.timezone('Europe/Berlin')
            tz_name = 'Europe/Berlin'

        local_now = datetime.now(tz)
        if local_now.hour < 7:
            return

        today_key = local_now.date().isoformat()
        if getattr(settings, 'snap_ttl_expiry_email_last_sent', None) == today_key:
            return

        utc_now = datetime.utcnow()
        rows = _query_expiring_records(utc_now, within_hours=24)

        if not rows:
            settings.snap_ttl_expiry_email_last_sent = today_key
            db.session.commit()
            logger.debug('Snapshot TTL digest: no expiring snapshots, marking %s done.', today_key)
            return

        subject = (
            f'[{settings.company_name or "Storage"}] Snapshots: TTL in 24h ({len(rows)})'
        )
        body = _format_body(rows, tz_name)

        try:
            send_smtp_message(settings, recipients, subject, body)
        except Exception as exc:
            logger.warning('Snapshot TTL digest: send failed: %s', exc, exc_info=True)
            return

        settings.snap_ttl_expiry_email_last_sent = today_key
        db.session.commit()
        logger.info(
            'Snapshot TTL digest sent for %s to %d recipient(s), %d snapshot(s).',
            today_key,
            len(recipients),
            len(rows),
        )
