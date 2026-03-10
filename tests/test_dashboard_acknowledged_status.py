"""Tests for dashboard status adjustment based on acknowledged alerts.

Verifies that the /api/cached-status endpoint correctly adjusts
hardware_status, cluster_status, and alerts count when alerts have
been acknowledged via /api/alerts/state.
"""

import json
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Test application fixture (no background threads)
# ---------------------------------------------------------------------------

def _no_op(*a, **kw):
    pass


@pytest.fixture()
def app():
    patches = [
        patch('app.capacity_service.start_background_refresh', _no_op),
        patch('app.sod_service.start_background_refresh', _no_op),
        patch('app.status_service.start_background_refresh', _no_op),
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
# DB helpers
# ---------------------------------------------------------------------------

def _make_system(db, name, vendor='pure', ip='10.0.0.1'):
    from app.models import StorageSystem
    system = StorageSystem(
        name=name, vendor=vendor, ip_address=ip,
        api_username='admin', api_password='password', enabled=True,
    )
    db.session.add(system)
    db.session.flush()
    return system


def _make_cache(db, system, status_dict):
    from datetime import datetime, timezone
    from app.models import StatusCache
    cache = StatusCache(
        system_id=system.id,
        fetched_at=datetime.now(timezone.utc),
        status_json=json.dumps(status_dict),
    )
    db.session.add(cache)
    db.session.flush()
    return cache


def _alert_key(system_name, alert_id, title):
    from app.models import AlertState
    return AlertState.make_key(system_name, alert_id, title)


def _acknowledge(client, system_name, alert_id, title):
    key = _alert_key(system_name, alert_id, title)
    client.post('/api/alerts/state', json={'alert_keys': [key], 'acknowledged': True})
    return key


# ---------------------------------------------------------------------------
# Helper: fetch cached-status for a named system
# ---------------------------------------------------------------------------

def _get_status(client, system_name):
    data = client.get('/api/cached-status').get_json()
    for entry in data:
        if entry['system']['name'] == system_name:
            return entry['status']
    return None


# ---------------------------------------------------------------------------
# Test: alerts count reduction
# ---------------------------------------------------------------------------

class TestAlertsCountReduction:
    def test_unacknowledged_alerts_count_unchanged(self, client, db_session):
        """Alerts count stays the same when no alert has been acknowledged."""
        system = _make_system(db_session, 'sys-count-1')
        _make_cache(db_session, system, {
            'status': 'online',
            'hardware_status': 'error',
            'cluster_status': 'ok',
            'alerts': 2,
            'alert_details': [
                {'id': '1', 'title': 'A', 'severity': 'error', 'details': '-',
                 'error_code': '-', 'timestamp': '-', 'component': '-'},
                {'id': '2', 'title': 'B', 'severity': 'warning', 'details': '-',
                 'error_code': '-', 'timestamp': '-', 'component': '-'},
            ],
        })
        db_session.session.commit()
        status = _get_status(client, 'sys-count-1')
        assert status['alerts'] == 2

    def test_acknowledged_alert_reduces_count(self, client, db_session):
        """Acknowledging one of two alerts reduces the count by 1."""
        system = _make_system(db_session, 'sys-count-2')
        _make_cache(db_session, system, {
            'status': 'online',
            'hardware_status': 'error',
            'cluster_status': 'ok',
            'alerts': 2,
            'alert_details': [
                {'id': '10', 'title': 'AlertOne', 'severity': 'error', 'details': '-',
                 'error_code': '-', 'timestamp': '-', 'component': '-'},
                {'id': '11', 'title': 'AlertTwo', 'severity': 'warning', 'details': '-',
                 'error_code': '-', 'timestamp': '-', 'component': '-'},
            ],
        })
        db_session.session.commit()
        _acknowledge(client, 'sys-count-2', '10', 'AlertOne')
        status = _get_status(client, 'sys-count-2')
        assert status['alerts'] == 1

    def test_all_alerts_acknowledged_count_zero(self, client, db_session):
        """Acknowledging all alerts reduces the count to 0."""
        system = _make_system(db_session, 'sys-count-3')
        _make_cache(db_session, system, {
            'status': 'online',
            'hardware_status': 'warning',
            'cluster_status': 'ok',
            'alerts': 1,
            'alert_details': [
                {'id': '20', 'title': 'SingleAlert', 'severity': 'warning', 'details': '-',
                 'error_code': '-', 'timestamp': '-', 'component': '-'},
            ],
        })
        db_session.session.commit()
        _acknowledge(client, 'sys-count-3', '20', 'SingleAlert')
        status = _get_status(client, 'sys-count-3')
        assert status['alerts'] == 0


# ---------------------------------------------------------------------------
# Test: hardware_status cleared when all alerts acknowledged
# ---------------------------------------------------------------------------

class TestHardwareStatusCleared:
    def test_hardware_error_cleared_when_alert_acknowledged(self, client, db_session):
        """hardware_status 'error' → 'ok' when the single alert is acknowledged."""
        system = _make_system(db_session, 'hw-clear-1')
        _make_cache(db_session, system, {
            'status': 'online',
            'hardware_status': 'error',
            'cluster_status': 'ok',
            'alerts': 1,
            'alert_details': [
                {'id': '30', 'title': 'HwError', 'severity': 'critical', 'details': '-',
                 'error_code': '-', 'timestamp': '-', 'component': 'CT0'},
            ],
        })
        db_session.session.commit()
        _acknowledge(client, 'hw-clear-1', '30', 'HwError')
        status = _get_status(client, 'hw-clear-1')
        assert status['hardware_status'] == 'ok'
        assert status['alerts'] == 0

    def test_hardware_warning_cleared_when_alert_acknowledged(self, client, db_session):
        """hardware_status 'warning' → 'ok' when the single alert is acknowledged."""
        system = _make_system(db_session, 'hw-clear-2')
        _make_cache(db_session, system, {
            'status': 'online',
            'hardware_status': 'warning',
            'cluster_status': 'ok',
            'alerts': 1,
            'alert_details': [
                {'id': '31', 'title': 'HwWarn', 'severity': 'warning', 'details': '-',
                 'error_code': '-', 'timestamp': '-', 'component': 'CT1'},
            ],
        })
        db_session.session.commit()
        _acknowledge(client, 'hw-clear-2', '31', 'HwWarn')
        status = _get_status(client, 'hw-clear-2')
        assert status['hardware_status'] == 'ok'

    def test_hardware_error_kept_when_one_alert_remains(self, client, db_session):
        """hardware_status stays 'error' when at least one alert is unacknowledged."""
        system = _make_system(db_session, 'hw-keep-1')
        _make_cache(db_session, system, {
            'status': 'online',
            'hardware_status': 'error',
            'cluster_status': 'ok',
            'alerts': 2,
            'alert_details': [
                {'id': '40', 'title': 'Err1', 'severity': 'critical', 'details': '-',
                 'error_code': '-', 'timestamp': '-', 'component': 'CT0'},
                {'id': '41', 'title': 'Err2', 'severity': 'error', 'details': '-',
                 'error_code': '-', 'timestamp': '-', 'component': 'CT1'},
            ],
        })
        db_session.session.commit()
        # Acknowledge only the first alert – second remains open
        _acknowledge(client, 'hw-keep-1', '40', 'Err1')
        status = _get_status(client, 'hw-keep-1')
        assert status['hardware_status'] == 'error'
        assert status['alerts'] == 1

    def test_hardware_ok_unaffected_by_acknowledgment(self, client, db_session):
        """hardware_status 'ok' is not changed by alert acknowledgment."""
        system = _make_system(db_session, 'hw-ok-1')
        _make_cache(db_session, system, {
            'status': 'online',
            'hardware_status': 'ok',
            'cluster_status': 'ok',
            'alerts': 1,
            'alert_details': [
                {'id': '50', 'title': 'InfoAlert', 'severity': 'info', 'details': '-',
                 'error_code': '-', 'timestamp': '-', 'component': '-'},
            ],
        })
        db_session.session.commit()
        _acknowledge(client, 'hw-ok-1', '50', 'InfoAlert')
        status = _get_status(client, 'hw-ok-1')
        assert status['hardware_status'] == 'ok'


# ---------------------------------------------------------------------------
# Test: cluster_status cleared when all alerts acknowledged
# ---------------------------------------------------------------------------

class TestClusterStatusCleared:
    def test_cluster_error_cleared_when_all_alerts_acknowledged(self, client, db_session):
        """cluster_status 'error' → 'ok' when all alerts are acknowledged."""
        system = _make_system(db_session, 'cl-clear-1', vendor='netapp-storagegrid')
        _make_cache(db_session, system, {
            'status': 'online',
            'hardware_status': 'ok',
            'cluster_status': 'error',
            'alerts': 1,
            'alert_details': [
                {'id': '60', 'title': 'ClusterDown', 'severity': 'critical', 'details': '-',
                 'error_code': '-', 'timestamp': '-', 'component': 'site1'},
            ],
        })
        db_session.session.commit()
        _acknowledge(client, 'cl-clear-1', '60', 'ClusterDown')
        status = _get_status(client, 'cl-clear-1')
        assert status['cluster_status'] == 'ok'
        assert status['alerts'] == 0

    def test_cluster_status_kept_when_alert_unacknowledged(self, client, db_session):
        """cluster_status stays 'error' when an alert is unacknowledged."""
        system = _make_system(db_session, 'cl-keep-1', vendor='netapp-storagegrid')
        _make_cache(db_session, system, {
            'status': 'online',
            'hardware_status': 'ok',
            'cluster_status': 'error',
            'alerts': 1,
            'alert_details': [
                {'id': '70', 'title': 'ClusterErr', 'severity': 'critical', 'details': '-',
                 'error_code': '-', 'timestamp': '-', 'component': 'site1'},
            ],
        })
        db_session.session.commit()
        # Do NOT acknowledge
        status = _get_status(client, 'cl-keep-1')
        assert status['cluster_status'] == 'error'
        assert status['alerts'] == 1


# ---------------------------------------------------------------------------
# Test: DataDomain active_alerts
# ---------------------------------------------------------------------------

class TestDataDomainActiveAlerts:
    def test_dd_alert_count_reduced_when_acknowledged(self, client, db_session):
        """DataDomain active_alerts count is reduced when the alert is acknowledged."""
        system = _make_system(db_session, 'dd-ack-1', vendor='dell-datadomain')
        _make_cache(db_session, system, {
            'status': 'online',
            'hardware_status': 'warning',
            'cluster_status': 'ok',
            'alerts': 1,
            'active_alerts': [
                {'id': 'dd-99', 'name': 'FanFailure', 'severity': 'CRITICAL',
                 'category': 'HardwareFailure', 'message': 'Fan 2 failed',
                 'timestamp': '-'},
            ],
        })
        db_session.session.commit()
        # DataDomain uses 'name' as the title in the key
        _acknowledge(client, 'dd-ack-1', 'dd-99', 'FanFailure')
        status = _get_status(client, 'dd-ack-1')
        assert status['alerts'] == 0

    def test_dd_hardware_warning_cleared_when_alert_acknowledged(self, client, db_session):
        """DataDomain hardware_status 'warning' → 'ok' after acknowledging all alerts."""
        system = _make_system(db_session, 'dd-hw-1', vendor='dell-datadomain')
        _make_cache(db_session, system, {
            'status': 'online',
            'hardware_status': 'warning',
            'cluster_status': 'ok',
            'alerts': 1,
            'active_alerts': [
                {'id': 'dd-50', 'name': 'DiskPredictFailure', 'severity': 'major',
                 'category': 'StorageFailure', 'message': 'Disk predict fail',
                 'timestamp': '-'},
            ],
        })
        db_session.session.commit()
        _acknowledge(client, 'dd-hw-1', 'dd-50', 'DiskPredictFailure')
        status = _get_status(client, 'dd-hw-1')
        assert status['hardware_status'] == 'ok'


# ---------------------------------------------------------------------------
# Test: no alert_details → status unchanged
# ---------------------------------------------------------------------------

class TestNoAlertDetails:
    def test_status_unchanged_when_no_alert_details(self, client, db_session):
        """When there is no alert_details or active_alerts, the status is not modified."""
        system = _make_system(db_session, 'no-details-1')
        _make_cache(db_session, system, {
            'status': 'online',
            'hardware_status': 'error',
            'cluster_status': 'warning',
            'alerts': 3,
        })
        db_session.session.commit()
        status = _get_status(client, 'no-details-1')
        assert status['hardware_status'] == 'error'
        assert status['cluster_status'] == 'warning'
        assert status['alerts'] == 3

    def test_unacknowledge_restores_count(self, client, db_session):
        """Un-acknowledging an alert restores the full count."""
        system = _make_system(db_session, 'unack-1')
        _make_cache(db_session, system, {
            'status': 'online',
            'hardware_status': 'error',
            'cluster_status': 'ok',
            'alerts': 1,
            'alert_details': [
                {'id': '80', 'title': 'TempHigh', 'severity': 'error', 'details': '-',
                 'error_code': '-', 'timestamp': '-', 'component': 'CT0'},
            ],
        })
        db_session.session.commit()
        key = _acknowledge(client, 'unack-1', '80', 'TempHigh')

        # Confirm it's cleared
        assert _get_status(client, 'unack-1')['alerts'] == 0

        # Un-acknowledge
        client.post('/api/alerts/state', json={'alert_keys': [key], 'acknowledged': False})
        status = _get_status(client, 'unack-1')
        assert status['alerts'] == 1
        assert status['hardware_status'] == 'error'
