"""Tests for snapshot TTL digest e-mail helpers."""
from datetime import datetime, timedelta
from unittest.mock import patch

import pytz


def test_parse_recipient_list():
    from app.snap_ttl_email import parse_recipient_list

    assert parse_recipient_list('') == []
    assert parse_recipient_list('a@x.de') == ['a@x.de']
    assert parse_recipient_list('a@x.de, b@y.de') == ['a@x.de', 'b@y.de']
    assert parse_recipient_list('a@x.de\nb@y.de') == ['a@x.de', 'b@y.de']
    assert parse_recipient_list('a@x.de; a@x.de') == ['a@x.de']


def test_smtp_config_complete(dashboard_ctx, dashboard_db):
    from app import db
    from app.models import AppSettings
    from app.snap_ttl_email import smtp_config_complete

    s = AppSettings()
    db.session.add(s)
    db.session.commit()

    assert smtp_config_complete(s) is False

    s.smtp_enabled = 1
    s.smtp_host = 'mail.example.com'
    s.smtp_from_address = 'from@example.com'
    s.smtp_auth_mode = 'none'
    db.session.commit()
    assert smtp_config_complete(s) is True

    s.smtp_auth_mode = 'password'
    s.smtp_username = 'u'
    s.smtp_password = None
    db.session.commit()
    assert smtp_config_complete(s) is False

    s.smtp_password = 'secret'
    db.session.commit()
    assert smtp_config_complete(s) is True


def _ensure_settings(db):
    from app.models import AppSettings

    s = AppSettings.query.first()
    if not s:
        s = AppSettings()
        db.session.add(s)
    s.smtp_enabled = 1
    s.smtp_host = 'smtp.example.com'
    s.smtp_port = 587
    s.smtp_use_tls = 1
    s.smtp_use_ssl = 0
    s.smtp_auth_mode = 'none'
    s.smtp_from_address = 'noreply@example.com'
    s.timezone = 'Europe/Berlin'
    s.company_name = 'Co'
    s.snap_ttl_expiry_email_enabled = 1
    s.snap_ttl_expiry_recipients = 'ops@example.com'
    s.snap_ttl_expiry_email_last_sent = None
    db.session.commit()
    return s


def test_maybe_send_skips_before_7_local(dashboard_ctx, dashboard_db):
    from app import db
    from app.snap_ttl_email import maybe_send_snap_ttl_expiry_digest

    _ensure_settings(db)
    app = dashboard_ctx

    berlin = pytz.timezone('Europe/Berlin')
    with patch('app.snap_ttl_email.datetime') as m_dt:
        m_dt.utcnow.return_value = datetime(2026, 5, 4, 5, 0, 0)
        m_dt.now = lambda tz=None: berlin.localize(datetime(2026, 5, 4, 6, 30, 0))

        with patch('app.mail_sender.send_smtp_message') as send_m:
            maybe_send_snap_ttl_expiry_digest(app)
        send_m.assert_not_called()


def test_maybe_send_marks_day_when_no_rows(dashboard_ctx, dashboard_db):
    from app import db
    from app.models import AppSettings
    from app.snap_ttl_email import maybe_send_snap_ttl_expiry_digest

    _ensure_settings(db)
    app = dashboard_ctx

    berlin = pytz.timezone('Europe/Berlin')
    with patch('app.snap_ttl_email.datetime') as m_dt:
        m_dt.utcnow.return_value = datetime(2026, 5, 4, 6, 0, 0)
        m_dt.now = lambda tz=None: berlin.localize(datetime(2026, 5, 4, 8, 0, 0))

        with patch('app.mail_sender.send_smtp_message') as send_m:
            maybe_send_snap_ttl_expiry_digest(app)
        send_m.assert_not_called()

    s = AppSettings.query.first()
    assert s.snap_ttl_expiry_email_last_sent == '2026-05-04'


def test_maybe_send_sends_when_rows_in_window(dashboard_ctx, dashboard_db):
    from app import db
    from app.models import AppSettings, SnapshotRecord
    from app.snap_ttl_email import maybe_send_snap_ttl_expiry_digest

    _ensure_settings(db)
    utc = datetime(2026, 5, 4, 6, 0, 0)
    rec = SnapshotRecord(
        sid='ABC',
        creation_time=utc - timedelta(days=1),
        ttl=utc + timedelta(hours=6),
        flasharray_present=True,
        ontap_present=True,
        delete_marked=False,
        storage_locations='{}',
    )
    db.session.add(rec)
    db.session.commit()

    app = dashboard_ctx
    berlin = pytz.timezone('Europe/Berlin')
    with patch('app.snap_ttl_email.datetime') as m_dt:
        m_dt.utcnow.return_value = utc
        m_dt.now = lambda tz=None: berlin.localize(datetime(2026, 5, 4, 9, 0, 0))

        with patch('app.mail_sender.send_smtp_message') as send_m:
            maybe_send_snap_ttl_expiry_digest(app)
        send_m.assert_called_once()
        args, kwargs = send_m.call_args
        assert 'ops@example.com' in args[1]

    s = AppSettings.query.first()
    assert s.snap_ttl_expiry_email_last_sent == '2026-05-04'
