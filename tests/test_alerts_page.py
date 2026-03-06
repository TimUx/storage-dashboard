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

    def test_ontap_ems_alert_details_rendered(self, client, db_session):
        """ONTAP EMS alert_details (from EMS events) are normalised and shown in the table."""
        system = _make_system(db_session, 'ontap-cl01', vendor='netapp-ontap')
        _make_cache(db_session, system, {
            'alerts': 1,
            'alert_details': [{
                'id': '42',
                'title': 'callhome.spares.low',
                'details': 'Spare capacity is critically low on node1',
                'severity': 'error',
                'error_code': 'callhome.spares.low',
                'timestamp': '2026-03-06T08:00:00+00:00',
                'component': 'node1',
            }],
        })
        db_session.session.commit()
        html = client.get('/alerts/').data.decode()
        assert 'callhome.spares.low' in html
        assert 'Spare capacity is critically low on node1' in html
        assert 'ontap-cl01' in html
        assert 'NetApp ONTAP' in html


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


# ---------------------------------------------------------------------------
# /api/alerts JSON endpoint tests
# ---------------------------------------------------------------------------

class TestApiAlertsEndpoint:
    """Tests for the /api/alerts JSON endpoint used by the auto-refresh loop."""

    def test_returns_200_and_json(self, client, db_session):
        """The /api/alerts endpoint must return HTTP 200 with a JSON body."""
        db_session.session.commit()
        resp = client.get('/api/alerts')
        assert resp.status_code == 200
        assert resp.content_type.startswith('application/json')

    def test_empty_when_no_alerts(self, client, db_session):
        """No open alerts → response has an empty 'alerts' list."""
        system = _make_system(db_session, 'api-clean')
        _make_cache(db_session, system, {'alerts': 0, 'status': 'online'})
        db_session.session.commit()
        data = client.get('/api/alerts').get_json()
        assert data['alerts'] == []

    def test_alerts_list_contains_normalised_fields(self, client, db_session):
        """Alert entries in the JSON response carry the expected normalised fields."""
        system = _make_system(db_session, 'api-pure', vendor='pure')
        _make_cache(db_session, system, {
            'alerts': 1,
            'alert_details': [{
                'id': '77',
                'title': 'hw_error',
                'details': 'Controller failure',
                'severity': 'critical',
                'error_code': '13',
                'timestamp': '2026-03-06T10:00:00+00:00',
                'component': 'CT0',
            }],
        })
        db_session.session.commit()
        data = client.get('/api/alerts').get_json()
        assert len(data['alerts']) == 1
        a = data['alerts'][0]
        assert a['system_name']  == 'api-pure'
        assert a['system_vendor'] == 'Pure Storage'
        assert a['alert_id']     == '77'
        assert a['title']        == 'hw_error'
        assert a['severity']     == 'critical'
        assert a['component']    == 'CT0'

    def test_response_includes_fetched_at(self, client, db_session):
        """The top-level 'fetched_at' key must be present (may be None when no cache)."""
        system = _make_system(db_session, 'api-ts')
        _make_cache(db_session, system, {
            'alerts': 1,
            'alert_details': [{
                'id': '1', 'title': 'T', 'details': 'D',
                'severity': 'error', 'error_code': '-',
                'timestamp': '-', 'component': '-',
            }],
        })
        db_session.session.commit()
        data = client.get('/api/alerts').get_json()
        assert 'fetched_at' in data

    def test_datadomain_alerts_returned_by_api(self, client, db_session):
        """DataDomain active_alerts are normalised and returned by /api/alerts."""
        system = _make_system(db_session, 'api-dd', vendor='dell-datadomain')
        _make_cache(db_session, system, {
            'alerts': 1,
            'active_alerts': [{
                'id': 'dd-42',
                'name': 'FanFailure',
                'severity': 'CRITICAL',
                'category': 'HardwareFailure',
                'message': 'Fan 3 has failed',
                'timestamp': '2026-03-06T09:00:00+00:00',
                'error_code': 'FAN-001',
            }],
        })
        db_session.session.commit()
        data = client.get('/api/alerts').get_json()
        assert len(data['alerts']) == 1
        assert data['alerts'][0]['title'] == 'FanFailure'

    def test_per_alert_fetched_at_present(self, client, db_session):
        """Each individual alert dict must carry a 'fetched_at' field."""
        system = _make_system(db_session, 'api-fa')
        _make_cache(db_session, system, {
            'alerts': 1,
            'alert_details': [{
                'id': '5', 'title': 'T', 'details': 'D',
                'severity': 'warning', 'error_code': '-',
                'timestamp': '-', 'component': '-',
            }],
        })
        db_session.session.commit()
        data = client.get('/api/alerts').get_json()
        assert 'fetched_at' in data['alerts'][0]


# ---------------------------------------------------------------------------
# Alert state & assignee history tests
# ---------------------------------------------------------------------------

class TestAlertStateEndpoints:
    """Tests for the POST /api/alerts/state, GET /api/alerts/assignees,
    and DELETE /api/alerts/assignees/<name> endpoints."""

    def _alert_key(self, system_name, alert_id, title):
        from app.models import AlertState
        return AlertState.make_key(system_name, alert_id, title)

    def test_acknowledge_alert(self, client, db_session):
        """POST /api/alerts/state can acknowledge an alert by key."""
        key = self._alert_key('sys1', '1', 'TestTitle')
        resp = client.post('/api/alerts/state', json={
            'alert_keys': [key],
            'acknowledged': True,
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['updated'] == 1

        from app.models import AlertState
        state = AlertState.query.filter_by(alert_key=key).first()
        assert state is not None
        assert state.acknowledged is True

    def test_unacknowledge_alert(self, client, db_session):
        """POST /api/alerts/state can un-acknowledge an already-acknowledged alert."""
        key = self._alert_key('sys1', '2', 'AnotherAlert')
        # First acknowledge
        client.post('/api/alerts/state', json={'alert_keys': [key], 'acknowledged': True})
        # Then un-acknowledge
        resp = client.post('/api/alerts/state', json={'alert_keys': [key], 'acknowledged': False})
        assert resp.status_code == 200

        from app.models import AlertState
        state = AlertState.query.filter_by(alert_key=key).first()
        assert state.acknowledged is False

    def test_set_assignee(self, client, db_session):
        """POST /api/alerts/state sets the assignee and records it in history."""
        key = self._alert_key('sys1', '3', 'AssignAlert')
        resp = client.post('/api/alerts/state', json={
            'alert_keys': [key],
            'assignee': 'Max Müller',
        })
        assert resp.status_code == 200

        from app.models import AlertState, AssigneeHistory
        state = AlertState.query.filter_by(alert_key=key).first()
        assert state.assignee == 'Max Müller'
        hist = AssigneeHistory.query.filter_by(name='Max Müller').first()
        assert hist is not None

    def test_set_comment(self, client, db_session):
        """POST /api/alerts/state sets the comment field."""
        key = self._alert_key('sys1', '4', 'CommentAlert')
        resp = client.post('/api/alerts/state', json={
            'alert_keys': [key],
            'comment': 'Wird untersucht',
        })
        assert resp.status_code == 200

        from app.models import AlertState
        state = AlertState.query.filter_by(alert_key=key).first()
        assert state.comment == 'Wird untersucht'

    def test_bulk_acknowledge(self, client, db_session):
        """POST /api/alerts/state can acknowledge multiple alerts at once."""
        keys = [
            self._alert_key('sys1', '10', 'A'),
            self._alert_key('sys1', '11', 'B'),
            self._alert_key('sys1', '12', 'C'),
        ]
        resp = client.post('/api/alerts/state', json={
            'alert_keys': keys,
            'acknowledged': True,
        })
        assert resp.status_code == 200
        assert resp.get_json()['updated'] == 3

        from app.models import AlertState
        for k in keys:
            state = AlertState.query.filter_by(alert_key=k).first()
            assert state is not None and state.acknowledged is True

    def test_missing_alert_keys_returns_400(self, client, db_session):
        """POST /api/alerts/state without alert_keys returns 400."""
        resp = client.post('/api/alerts/state', json={'acknowledged': True})
        assert resp.status_code == 400

    def test_get_assignees_empty(self, client, db_session):
        """GET /api/alerts/assignees returns empty list when no history."""
        db_session.session.commit()
        resp = client.get('/api/alerts/assignees')
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_get_assignees_returns_names(self, client, db_session):
        """GET /api/alerts/assignees returns previously stored names."""
        key = self._alert_key('sys2', '1', 'X')
        client.post('/api/alerts/state', json={'alert_keys': [key], 'assignee': 'Anna Schmidt'})
        resp = client.get('/api/alerts/assignees')
        assert 'Anna Schmidt' in resp.get_json()

    def test_delete_assignee(self, client, db_session):
        """DELETE /api/alerts/assignees/<name> removes from history."""
        key = self._alert_key('sys2', '2', 'Y')
        client.post('/api/alerts/state', json={'alert_keys': [key], 'assignee': 'Tom Berger'})
        del_resp = client.delete('/api/alerts/assignees/Tom Berger')
        assert del_resp.status_code == 200
        names = client.get('/api/alerts/assignees').get_json()
        assert 'Tom Berger' not in names

    def test_delete_nonexistent_assignee_is_ok(self, client, db_session):
        """DELETE on a non-existent name returns 200 (idempotent)."""
        resp = client.delete('/api/alerts/assignees/Nonexistent')
        assert resp.status_code == 200


class TestAlertStateInApiResponse:
    """Tests that collect_alerts() merges AlertState into each alert dict."""

    def test_acknowledged_field_in_api_response(self, client, db_session):
        """Each alert in /api/alerts carries acknowledged/assignee/comment fields."""
        system = _make_system(db_session, 'state-sys')
        _make_cache(db_session, system, {
            'alerts': 1,
            'alert_details': [{'id': '99', 'title': 'StateTest',
                                'details': 'D', 'severity': 'warning',
                                'error_code': '-', 'timestamp': '-', 'component': '-'}],
        })
        db_session.session.commit()

        data = client.get('/api/alerts').get_json()
        alert = data['alerts'][0]
        assert 'acknowledged' in alert
        assert 'assignee' in alert
        assert 'comment' in alert
        assert 'alert_key' in alert
        assert alert['acknowledged'] is False

    def test_acknowledged_alert_excluded_from_active_count(self, client, db_session):
        """The navbar count excludes acknowledged alerts."""
        system = _make_system(db_session, 'ack-count-sys')
        _make_cache(db_session, system, {
            'alerts': 2,
            'alert_details': [
                {'id': '1', 'title': 'Alert1', 'details': 'D1',
                 'severity': 'critical', 'error_code': '-', 'timestamp': '-', 'component': '-'},
                {'id': '2', 'title': 'Alert2', 'details': 'D2',
                 'severity': 'warning',  'error_code': '-', 'timestamp': '-', 'component': '-'},
            ],
        })
        db_session.session.commit()

        # Acknowledge the first alert
        from app.models import AlertState
        key1 = AlertState.make_key('ack-count-sys', '1', 'Alert1')
        client.post('/api/alerts/state', json={'alert_keys': [key1], 'acknowledged': True})

        # The navbar page should show count=1 (only the unacknowledged alert)
        html = client.get('/').data.decode()
        assert '<span class="alert-badge">1</span>' in html

