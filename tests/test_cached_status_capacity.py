"""Tests for the /api/cached-status endpoint capacity override.

These tests verify that capacity values returned by the cached-status
endpoint are taken from ``CapacitySnapshot`` (which contains Pure1
physical-used figures) rather than from ``StatusCache`` (which stores
raw vendor-API values).
"""

import json
from unittest.mock import patch

import pytest
from flask import Flask


# ---------------------------------------------------------------------------
# Helpers – create a lightweight test app that uses the real models/routes
# but does NOT start any background threads.
# ---------------------------------------------------------------------------

@pytest.fixture()
def app():
    """Return a test Flask application backed by an in-memory SQLite database.

    Background refresh threads are suppressed so the test stays fast and
    side-effect free.
    """
    # Patch start_background_refresh functions before create_app runs them.
    def no_op(*a, **kw):
        pass

    patches = [
        patch('app.capacity_service.start_background_refresh', no_op),
        patch('app.sod_service.start_background_refresh', no_op),
        patch('app.status_service.start_background_refresh', no_op),
    ]
    for p in patches:
        p.start()

    import os
    os.environ.setdefault('SECRET_KEY', 'test-secret')
    os.environ['DATABASE_URL'] = 'sqlite://'

    from app import create_app
    flask_app = create_app()
    flask_app.config['TESTING'] = True

    for p in patches:
        p.stop()

    yield flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def db_session(app):
    from app import db as _db
    with app.app_context():
        yield _db


# ---------------------------------------------------------------------------
# Helper – create minimal DB objects
# ---------------------------------------------------------------------------

def _make_system(db, name='pure05', vendor='pure'):
    from app.models import StorageSystem
    system = StorageSystem(
        name=name,
        vendor=vendor,
        ip_address='10.0.0.1',
        api_username='admin',
        api_password='password',
        enabled=True,
    )
    db.session.add(system)
    db.session.flush()
    return system


def _make_status_cache(db, system_id, used_tb, total_tb, percent):
    from app.models import StatusCache
    from datetime import datetime

    raw_status = {
        'status': 'online',
        'capacity_used_tb': used_tb,
        'capacity_total_tb': total_tb,
        'capacity_percent': percent,
    }
    cache = StatusCache(system_id=system_id)
    cache.set_status(raw_status)
    cache.fetched_at = datetime.utcnow()
    db.session.add(cache)
    db.session.flush()
    return cache


def _make_capacity_snapshot(db, system_id, used_tb, total_tb, percent_used):
    from app.models import CapacitySnapshot
    from datetime import datetime

    snap = CapacitySnapshot(
        system_id=system_id,
        total_tb=total_tb,
        used_tb=used_tb,
        free_tb=round(total_tb - used_tb, 2),
        percent_used=percent_used,
        percent_free=round(100.0 - percent_used, 1),
    )
    snap.fetched_at = datetime.utcnow()
    db.session.add(snap)
    db.session.flush()
    return snap


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCachedStatusCapacityOverride:
    """The /api/cached-status endpoint must return CapacitySnapshot values."""

    def test_capacity_used_comes_from_snapshot(self, client, db_session, app):
        """used_tb in the response should match CapacitySnapshot, not StatusCache."""
        with app.app_context():
            system = _make_system(db_session)
            # StatusCache has the wrong (local) value from the vendor API.
            _make_status_cache(db_session, system.id,
                               used_tb=281.8, total_tb=247.6, percent=113.8)
            # CapacitySnapshot has the correct Pure1 physical-used value.
            _make_capacity_snapshot(db_session, system.id,
                                    used_tb=195.86, total_tb=247.63, percent_used=79.1)
            db_session.session.commit()

        resp = client.get('/api/cached-status')
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1
        status = data[0]['status']
        assert abs(status['capacity_used_tb'] - 195.86) < 0.01
        assert abs(status['capacity_total_tb'] - 247.63) < 0.01
        assert abs(status['capacity_percent'] - 79.1) < 0.1

    def test_capacity_percent_comes_from_snapshot(self, client, db_session, app):
        """capacity_percent in the response should reflect the snapshot value."""
        with app.app_context():
            system = _make_system(db_session, name='pure07')
            _make_status_cache(db_session, system.id,
                               used_tb=603.9, total_tb=600.4, percent=100.6)
            _make_capacity_snapshot(db_session, system.id,
                                    used_tb=378.40, total_tb=600.38, percent_used=63.0)
            db_session.session.commit()

        resp = client.get('/api/cached-status')
        assert resp.status_code == 200
        data = resp.get_json()
        status = data[0]['status']
        assert abs(status['capacity_percent'] - 63.0) < 0.1

    def test_snapshot_with_zero_total_does_not_override(self, client, db_session, app):
        """A CapacitySnapshot with total_tb=0 must not override the cached values."""
        with app.app_context():
            system = _make_system(db_session, name='pure08')
            _make_status_cache(db_session, system.id,
                               used_tb=377.4, total_tb=600.4, percent=62.9)
            # Snapshot with 0 total_tb should be ignored.
            _make_capacity_snapshot(db_session, system.id,
                                    used_tb=0.0, total_tb=0.0, percent_used=0.0)
            db_session.session.commit()

        resp = client.get('/api/cached-status')
        assert resp.status_code == 200
        data = resp.get_json()
        status = data[0]['status']
        # Original StatusCache values should remain unchanged.
        assert abs(status['capacity_used_tb'] - 377.4) < 0.01
        assert abs(status['capacity_total_tb'] - 600.4) < 0.01

    def test_no_snapshot_falls_back_to_status_cache(self, client, db_session, app):
        """When no CapacitySnapshot exists, StatusCache values are returned as-is."""
        with app.app_context():
            system = _make_system(db_session, name='pure06')
            _make_status_cache(db_session, system.id,
                               used_tb=280.4, total_tb=247.6, percent=113.2)
            # No CapacitySnapshot created for this system.
            db_session.session.commit()

        resp = client.get('/api/cached-status')
        assert resp.status_code == 200
        data = resp.get_json()
        status = data[0]['status']
        assert abs(status['capacity_used_tb'] - 280.4) < 0.01
        assert abs(status['capacity_total_tb'] - 247.6) < 0.01

    def test_other_status_fields_are_preserved(self, client, db_session, app):
        """Non-capacity status fields must not be altered by the snapshot merge."""
        with app.app_context():
            system = _make_system(db_session, name='pure05b')
            _make_status_cache(db_session, system.id,
                               used_tb=281.8, total_tb=247.6, percent=113.8)
            _make_capacity_snapshot(db_session, system.id,
                                    used_tb=195.86, total_tb=247.63, percent_used=79.1)
            db_session.session.commit()

        resp = client.get('/api/cached-status')
        assert resp.status_code == 200
        data = resp.get_json()
        status = data[0]['status']
        # 'status' field from StatusCache must be preserved.
        assert status.get('status') == 'online'
