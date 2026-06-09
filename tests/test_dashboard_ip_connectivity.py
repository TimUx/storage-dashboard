"""Tests for dashboard status adjustment when management IPs are unreachable."""

import json
from unittest.mock import patch

import pytest


def _no_op(*a, **kw):
    pass


@pytest.fixture()
def app():
    patches = [
        patch('app.capacity_service.start_background_refresh', _no_op),
        patch('app.sod_service.start_background_refresh', _no_op),
        patch('app.status_service.start_background_refresh', _no_op),
        patch('app.dr_service.start_background_refresh', _no_op),
        patch('app.snap_service.start_background_refresh', _no_op),
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


def _make_system(db, name, vendor='dell-datadomain', ip='10.0.0.1', port=3009):
    from app.models import StorageSystem
    system = StorageSystem(
        name=name,
        vendor=vendor,
        ip_address=ip,
        port=port,
        api_username='admin',
        api_password='password',
        enabled=True,
        cluster_type='ha',
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


def _get_status(client, system_name):
    data = client.get('/api/cached-status').get_json()
    for entry in data:
        if entry['system']['name'] == system_name:
            return entry['status']
    return None


class TestDashboardIpConnectivityOverlay:
    def test_unreachable_ip_raises_alerts_and_downgrades_hardware(self, client, db_session):
        system = _make_system(db_session, 'ddq13')
        _make_cache(db_session, system, {
            'status': 'online',
            'hardware_status': 'ok',
            'cluster_status': 'ok',
            'alerts': 0,
            'ip_monitor': {
                'has_unreachable': True,
                'unreachable_ips': ['10.112.229.206'],
                'reachable_ips': ['10.112.228.75', '10.112.228.117'],
            },
        })
        db_session.session.commit()

        status = _get_status(client, 'ddq13')
        assert status['alerts'] == 1
        assert status['hardware_status'] == 'warning'
        assert status['cluster_status'] == 'warning'

    def test_all_ips_unreachable_sets_error_severity(self, client, db_session):
        system = _make_system(db_session, 'dd-down')
        _make_cache(db_session, system, {
            'status': 'online',
            'hardware_status': 'ok',
            'cluster_status': 'ok',
            'alerts': 0,
            'ip_monitor': {
                'has_unreachable': True,
                'unreachable_ips': ['10.0.0.1', '10.0.0.2'],
                'reachable_ips': [],
            },
        })
        db_session.session.commit()

        status = _get_status(client, 'dd-down')
        assert status['alerts'] == 2
        assert status['hardware_status'] == 'error'
        assert status['cluster_status'] == 'error'

    def test_acknowledged_ip_alert_does_not_affect_dashboard(self, client, db_session):
        from app.models import AlertState
        from app.routes.alerts import IP_CONNECTIVITY_ALERT_ID

        system = _make_system(db_session, 'dd-acked')
        ip = '10.112.229.206'
        title = f'Management-IP nicht erreichbar ({ip})'
        alert_id = f'{IP_CONNECTIVITY_ALERT_ID}:{ip}'
        db_session.session.add(AlertState(
            alert_key=AlertState.make_key(system.name, alert_id, title),
            acknowledged=True,
        ))
        _make_cache(db_session, system, {
            'status': 'online',
            'hardware_status': 'ok',
            'cluster_status': 'ok',
            'alerts': 0,
            'ip_monitor': {
                'has_unreachable': True,
                'unreachable_ips': [ip],
                'reachable_ips': ['10.112.228.75'],
            },
        })
        db_session.session.commit()

        status = _get_status(client, 'dd-acked')
        assert status['alerts'] == 0
        assert status['hardware_status'] == 'ok'
        assert status['cluster_status'] == 'ok'
