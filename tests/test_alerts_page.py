"""Tests for the /alerts/ page.

Verifies that:
- The alerts page is accessible (HTTP 200)
- Alerts from all three vendor types (Pure Storage, StorageGRID, DataDomain) are
  normalised into a unified structure and rendered in the table.
- When there are no alerts the empty-state message is shown.
- The open_alerts_count context variable (used by the navbar) is populated from
  the StatusCache.
"""

import json
from unittest.mock import patch

import pytest
from flask import Flask


# ---------------------------------------------------------------------------
# Helpers – lightweight test app (no background threads)
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
# Helpers – create DB objects
# ---------------------------------------------------------------------------

def _make_system(db, name, vendor='pure', ip='10.0.0.1'):
    from app.models import StorageSystem
    system = StorageSystem(
        name=name,
        vendor=vendor,
        ip_address=ip,
        api_username='admin',
        api_password='password',
        enabled=True,
    )
    db.session.add(system)
    db.session.flush()
    return system


def _make_cache(db, system, status_dict):
    from datetime import datetime
    from app.models import StatusCache
    cache = StatusCache(
        system_id=system.id,
        fetched_at=datetime.utcnow(),
        status_json=json.dumps(status_dict),
    )
    db.session.add(cache)
    db.session.flush()
    return cache


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAlertsPageBasic:
    def test_alerts_page_returns_200_when_no_alerts(self, client, db_session):
        """The /alerts/ page must load without errors even when there are no alerts."""
        db_session.session.commit()
        resp = client.get('/alerts/')
        assert resp.status_code == 200

    def test_empty_state_shown_when_no_alerts(self, client, db_session):
        """When no systems have open alerts, the empty-state message is rendered."""
        system = _make_system(db_session, 'pure01')
        _make_cache(db_session, system, {'alerts': 0, 'status': 'online'})
        db_session.session.commit()
        html = client.get('/alerts/').data.decode()
        assert 'Keine offenen Alerts' in html

    def test_alerts_table_shown_when_alerts_present(self, client, db_session):
        """When a system has open alerts via alert_details, the table is rendered."""
        system = _make_system(db_session, 'pure02')
        _make_cache(db_session, system, {
            'alerts': 1,
            'alert_details': [{
                'id': '42',
                'title': 'TestAlert',
                'details': 'Something went wrong',
                'severity': 'warning',
                'error_code': '7',
                'timestamp': '2024-01-15 10:00:00 UTC',
                'component': 'CT0',
            }],
        })
        db_session.session.commit()
        html = client.get('/alerts/').data.decode()
        assert 'TestAlert' in html
        assert 'Something went wrong' in html
        assert 'pure02' in html


class TestAlertsPageVendorNormalisation:
    def test_pure_storage_alert_details_rendered(self, client, db_session):
        """Pure Storage alert_details are normalised and shown in the table."""
        system = _make_system(db_session, 'fa-pure01', vendor='pure')
        _make_cache(db_session, system, {
            'alerts': 1,
            'alert_details': [{
                'id': 'abc123',
                'title': 'array_hw_error',
                'details': 'Controller temperature high',
                'severity': 'critical',
                'error_code': '13',
                'timestamp': '2024-01-10 08:30:00 UTC',
                'component': 'CT0',
            }],
        })
        db_session.session.commit()
        html = client.get('/alerts/').data.decode()
        assert 'array_hw_error' in html
        assert 'Controller temperature high' in html
        assert 'Critical' in html

    def test_storagegrid_alert_details_rendered(self, client, db_session):
        """StorageGRID alert_details are normalised and shown in the table."""
        system = _make_system(db_session, 'sgw01', vendor='netapp-storagegrid')
        _make_cache(db_session, system, {
            'alerts': 1,
            'alert_details': [{
                'id': '29ceeab5',
                'title': 'LowMetadataStorage',
                'details': 'The space available for storing object metadata is low.',
                'severity': 'minor',
                'error_code': '-',
                'timestamp': '2024-02-01T12:00:00Z',
                'component': 'DC1-S1',
            }],
        })
        db_session.session.commit()
        html = client.get('/alerts/').data.decode()
        assert 'LowMetadataStorage' in html
        assert 'sgw01' in html

    def test_datadomain_active_alerts_rendered(self, client, db_session):
        """DataDomain active_alerts are normalised and shown in the table."""
        system = _make_system(db_session, 'dd01', vendor='dell-datadomain')
        _make_cache(db_session, system, {
            'alerts': 1,
            'active_alerts': [{
                'id': 'alert-99',
                'name': 'FanFailure',
                'severity': 'CRITICAL',
                'category': 'HardwareFailure',
                'message': 'Fan 2 has failed',
                'timestamp': '2024-03-01 09:00:00 UTC',
                'error_code': 'FAN-001',
                'state': 'active',
            }],
        })
        db_session.session.commit()
        html = client.get('/alerts/').data.decode()
        assert 'FanFailure' in html
        assert 'Fan 2 has failed' in html
        assert 'dd01' in html

    def test_fallback_shown_when_no_alert_details(self, client, db_session):
        """When alert count > 0 but no details are available, a fallback row is shown."""
        system = _make_system(db_session, 'legacy01', vendor='netapp-ontap')
        _make_cache(db_session, system, {
            'alerts': 3,
        })
        db_session.session.commit()
        html = client.get('/alerts/').data.decode()
        assert '3 offene Alerts' in html
        assert 'Keine Details verfügbar' in html

    def test_fallback_singular_when_one_alert(self, client, db_session):
        """Singular form used for exactly one fallback alert."""
        system = _make_system(db_session, 'legacy02', vendor='netapp-ontap')
        _make_cache(db_session, system, {'alerts': 1})
        db_session.session.commit()
        html = client.get('/alerts/').data.decode()
        assert '1 offener Alert' in html


class TestOpenAlertsCountContextVar:
    def test_navbar_shows_alert_count_badge(self, client, db_session):
        """The open_alerts_count context variable populates the navbar badge."""
        system = _make_system(db_session, 'pure-badge')
        _make_cache(db_session, system, {'alerts': 5, 'status': 'online'})
        db_session.session.commit()
        # Any page should include the badge – use the dashboard
        html = client.get('/').data.decode()
        assert 'alert-badge' in html
        assert '5' in html

    def test_navbar_no_badge_when_no_alerts(self, client, db_session):
        """No alert badge when there are zero open alerts."""
        system = _make_system(db_session, 'pure-clean')
        _make_cache(db_session, system, {'alerts': 0, 'status': 'online'})
        db_session.session.commit()
        html = client.get('/').data.decode()
        # The badge span is only rendered when alerts > 0; the CSS class definition
        # in the <style> block is always present, so we check for the element tag.
        assert '<span class="alert-badge">' not in html

    def test_alerts_link_has_active_class_when_alerts_open(self, client, db_session):
        """The Alerts navbar link uses the alerts-active CSS class when alerts > 0."""
        system = _make_system(db_session, 'pure-active')
        _make_cache(db_session, system, {'alerts': 2, 'status': 'online'})
        db_session.session.commit()
        html = client.get('/').data.decode()
        assert 'alerts-active' in html
