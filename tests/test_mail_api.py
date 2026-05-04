"""Tests for SMTP test API and mail sender validation."""
from unittest.mock import patch

import pytest


@pytest.fixture()
def app():
    import os
    os.environ.setdefault('SECRET_KEY', 'test-secret')
    os.environ['DATABASE_URL'] = 'sqlite://'
    os.environ['BACKGROUND_JOBS_ENABLED'] = '0'
    from app import create_app
    flask_app = create_app()
    flask_app.config['TESTING'] = True
    return flask_app


@pytest.fixture()
def app_ctx(app):
    with app.app_context():
        yield app


@pytest.fixture()
def db(app_ctx):
    from app import db as _db
    _db.create_all()
    yield _db
    _db.session.remove()


@pytest.fixture()
def logged_in_client(app, db):
    from app.models import AdminUser
    from werkzeug.security import generate_password_hash

    user = AdminUser(username='admin', password_hash=generate_password_hash('x'))
    db.session.add(user)
    db.session.commit()
    c = app.test_client()
    c.post('/admin/login', data={'username': 'admin', 'password': 'x'})
    return c


def test_smtp_test_rejects_invalid_email(logged_in_client):
    r = logged_in_client.post(
        '/admin/api/smtp-test',
        json={'to': 'not-an-email'},
        content_type='application/json',
    )
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is False


def test_smtp_test_disabled_without_config(logged_in_client):
    from app.models import AppSettings
    from app import db as _db

    s = AppSettings()
    _db.session.add(s)
    _db.session.commit()

    r = logged_in_client.post(
        '/admin/api/smtp-test',
        json={'to': 'a@b.example'},
        content_type='application/json',
    )
    data = r.get_json()
    assert data['success'] is False
    assert any('deaktiviert' in line for step in data['steps'] for line in step.get('lines', []))


def test_smtp_test_success_path(logged_in_client):
    from app.models import AppSettings
    from app import db as _db

    s = AppSettings()
    s.smtp_enabled = 1
    s.smtp_host = 'smtp.example.com'
    s.smtp_port = 587
    s.smtp_use_tls = 1
    s.smtp_use_ssl = 0
    s.smtp_auth_mode = 'none'
    s.smtp_from_address = 'from@example.com'
    _db.session.add(s)
    _db.session.commit()

    with patch('app.routes.admin.mail_api.send_smtp_message') as send:
        r = logged_in_client.post(
            '/admin/api/smtp-test',
            json={'to': 'to@example.com'},
            content_type='application/json',
        )
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is True
    send.assert_called_once()


def test_send_smtp_message_requires_from():
    from app.models import AppSettings
    from app.mail_sender import send_smtp_message

    s = AppSettings()
    s.smtp_enabled = 1
    s.smtp_host = 'h'
    s.smtp_port = 25
    s.smtp_from_address = None
    with pytest.raises(ValueError, match='Absender'):
        send_smtp_message(s, ['a@b.co'], 'S', 'B')
