"""Gemeinsame pytest-Fixtures für Storage Dashboard.

Viele ältere Testdateien definieren eigene ``app``-Fixtures; diese Datei
ergänzt optionale Fixtures für neue Integration-/E2E-Tests ohne bestehende
Tests zu überschreiben.
"""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest


def _patch_background_threads():
    """Verhindert Daemon-Threads beim create_app (deterministische Tests)."""

    def _noop(*_a, **_kw):
        return None

    return [
        patch('app.capacity_service.start_background_refresh', _noop),
        patch('app.sod_service.start_background_refresh', _noop),
        patch('app.status_service.start_background_refresh', _noop),
        patch('app.dr_service.start_background_refresh', _noop),
        patch('app.snap_service.start_background_refresh', _noop),
    ]


@pytest.fixture()
def dashboard_app():
    """Flask-App mit in-memory SQLite und ohne Hintergrund-Threads."""
    patches = _patch_background_threads()
    for p in patches:
        p.start()

    os.environ.setdefault('SECRET_KEY', 'pytest-secret-key-32bytes-min!!')
    os.environ['DATABASE_URL'] = 'sqlite://'
    os.environ.setdefault('SSL_VERIFY', 'false')

    from app import create_app

    app = create_app()
    app.config['TESTING'] = True

    for p in patches:
        p.stop()

    yield app


@pytest.fixture()
def dashboard_ctx(dashboard_app):
    with dashboard_app.app_context():
        yield dashboard_app


@pytest.fixture()
def dashboard_db(dashboard_ctx):
    from app import db as _db

    _db.create_all()
    yield _db
    _db.session.remove()
    _db.drop_all()


@pytest.fixture()
def dashboard_client(dashboard_app, dashboard_db):
    """Anonymer Testclient (nicht eingeloggt)."""
    return dashboard_app.test_client()


@pytest.fixture()
def admin_client(dashboard_app, dashboard_db):
    """Testclient nach Admin-Login."""
    from app.models import AdminUser
    from werkzeug.security import generate_password_hash

    user = AdminUser(
        username='pytest_admin',
        password_hash=generate_password_hash('pytest_admin_pw'),
        is_active=True,
    )
    dashboard_db.session.add(user)
    dashboard_db.session.commit()

    client = dashboard_app.test_client()
    resp = client.post(
        '/admin/login',
        data={'username': 'pytest_admin', 'password': 'pytest_admin_pw'},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303), 'Admin-Login muss umleiten'
    return client
