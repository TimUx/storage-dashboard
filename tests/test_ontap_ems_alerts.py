"""Tests for NetApp ONTAP EMS alert fetching in NetAppONTAPClient.

Uses unittest.mock to simulate ONTAP REST API responses so no real ONTAP
system is needed.  Verifies:
- EMS events with severity emergency/alert/error are collected and returned
  as alert_details in the response.
- alerts count reflects the number of EMS events returned.
- hardware_status is escalated to 'error' for emergency events, and to
  'warning' for alert/error events when hardware is otherwise OK.
- An empty EMS response leaves alerts=0 and alert_details absent.
- A 401/non-200 from the EMS endpoint is handled gracefully (no crash,
  alerts remain 0).
- EMS events carry the correct field mapping per the ems_event schema.
"""

import json
from unittest.mock import MagicMock, patch, call
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(status_code, body):
    """Create a mock requests.Response-like object."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    resp.text = json.dumps(body)
    return resp


def _cluster_ok():
    return _make_response(200, {
        'name': 'test-cluster',
        'version': {'full': 'NetApp Release 9.14.1', 'generation': 9},
    })


def _metrocluster_404():
    resp = _make_response(404, {'error': {'message': 'not found'}})
    return resp


def _nodes_response():
    return _make_response(200, {
        'records': [
            {'name': 'node1', 'controller': {'failed_power_supply': {'count': 0}, 'failed_fan': {'count': 0}, 'over_temperature': 'normal'}},
        ]
    })


def _capacity_response():
    # /api/storage/aggregates
    return _make_response(200, {
        'records': [
            {'space': {'block_storage': {'size': 10 * 1024**4, 'used': 5 * 1024**4}}}
        ]
    })


def _cluster_nodes_response():
    return _make_response(200, {
        'records': [
            {'name': 'node1', 'management_ip': {'address': '10.0.0.1'}, 'state': 'up', 'ha': {'partners': []}}
        ]
    })


def _peers_response():
    return _make_response(200, {'records': []})


def _ems_response(events):
    return _make_response(200, {'records': events, 'num_records': len(events)})


def _ems_401():
    return _make_response(401, {'error': {'message': 'Unauthorized'}})


def _ems_503():
    return _make_response(503, {'error': {'message': 'Service Unavailable'}})


# ---------------------------------------------------------------------------
# Build a full ONTAP client with all HTTP calls mocked
# ---------------------------------------------------------------------------

class _FakeSession:
    """Minimal mock for the module-level _local_session in storage_clients."""

    def __init__(self, route_map):
        # route_map: dict mapping URL substring -> mock response (or list of responses)
        self._map = route_map
        self._cursors = {}

    def get(self, url, **kwargs):
        for key, val in self._map.items():
            if key in url:
                if isinstance(val, list):
                    idx = self._cursors.get(key, 0)
                    self._cursors[key] = idx + 1
                    return val[idx] if idx < len(val) else val[-1]
                return val
        raise AssertionError(f"Unexpected GET: {url}")

    def post(self, url, **kwargs):
        # Not needed for GET-only tests
        return _make_response(200, {})


def _make_client():
    from app.api.storage_clients import NetAppONTAPClient
    client = NetAppONTAPClient.__new__(NetAppONTAPClient)
    client.ip_address = '10.0.0.1'
    client.port = 443
    client.username = 'admin'
    client.password = 'password'
    client.token = None
    client.resolved_address = '10.0.0.1'
    client.base_url = 'https://10.0.0.1:443'
    return client


def _default_route_map(ems_response):
    return {
        '/api/cluster/metrocluster': _metrocluster_404(),
        '/api/cluster/peers': _peers_response(),
        '/api/cluster/nodes': _nodes_response(),
        '/api/storage/aggregates': _capacity_response(),
        '/api/cluster': _cluster_ok(),
        '/api/support/ems/events': ems_response,
    }


def _run_client(ems_response):
    """Run NetAppONTAPClient.get_health_status() with mocked HTTP."""
    client = _make_client()
    fake_session = _FakeSession(_default_route_map(ems_response))
    # Also stub out /api/cluster/nodes for hardware AND cluster-nodes call
    # (same URL, return _nodes_response twice)
    fake_session._map['/api/cluster/nodes'] = [_nodes_response(), _nodes_response()]

    import app.api.storage_clients as sc
    with patch.object(sc, '_local_session', fake_session):
        with patch('app.ssl_utils.get_ssl_verify', return_value=False):
            return client.get_health_status()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestONTAPEmsAlertFetch:
    def test_no_ems_events_returns_alerts_zero(self):
        """An empty EMS response → alerts=0, no alert_details."""
        result = _run_client(_ems_response([]))
        assert result['alerts'] == 0
        assert 'alert_details' not in result or result.get('alert_details') is None

    def test_ems_events_set_alert_count(self):
        """EMS records → alerts count equals number of records."""
        events = [
            {'index': 1, 'message': {'name': 'callhome.spares.low', 'severity': 'error'},
             'log_message': 'Spare capacity low', 'time': '2026-03-06T08:00:00+00:00', 'node': {'name': 'node1'}},
            {'index': 2, 'message': {'name': 'raid.plex.offline', 'severity': 'alert'},
             'log_message': 'RAID plex went offline', 'time': '2026-03-06T08:01:00+00:00', 'node': {'name': 'node1'}},
        ]
        result = _run_client(_ems_response(events))
        assert result['alerts'] == 2

    def test_alert_details_fields_mapped_correctly(self):
        """alert_details entries carry the correct field mappings per ems_event schema."""
        events = [
            {'index': 42, 'message': {'name': 'callhome.spares.low', 'severity': 'error'},
             'log_message': 'Spare capacity is critically low on node1',
             'time': '2026-03-06T08:00:00+00:00',
             'node': {'name': 'node1'}},
        ]
        result = _run_client(_ems_response(events))
        assert result.get('alert_details'), "alert_details must be present"
        detail = result['alert_details'][0]
        assert detail['id'] == '42'
        assert detail['title'] == 'callhome.spares.low'
        assert detail['details'] == 'Spare capacity is critically low on node1'
        assert detail['severity'] == 'error'
        assert detail['error_code'] == 'callhome.spares.low'
        assert detail['timestamp'] == '2026-03-06T08:00:00+00:00'
        assert detail['component'] == 'node1'

    def test_emergency_severity_escalates_hardware_to_error(self):
        """An emergency EMS event must set hardware_status to 'error'."""
        events = [
            {'index': 1, 'message': {'name': 'callhome.emergency', 'severity': 'emergency'},
             'log_message': 'Critical system failure', 'time': '2026-03-06T08:00:00+00:00',
             'node': {'name': 'node1'}},
        ]
        result = _run_client(_ems_response(events))
        assert result['hardware_status'] == 'error'

    def test_alert_severity_sets_hardware_to_warning_when_hw_ok(self):
        """An 'alert'-severity EMS event sets hardware_status to 'warning' when HW is OK."""
        events = [
            {'index': 1, 'message': {'name': 'raid.plex.offline', 'severity': 'alert'},
             'log_message': 'RAID plex offline', 'time': '2026-03-06T08:00:00+00:00',
             'node': {'name': 'node1'}},
        ]
        result = _run_client(_ems_response(events))
        assert result['hardware_status'] in ('warning', 'error')

    def test_error_severity_sets_hardware_to_warning(self):
        """An 'error'-severity EMS event sets hardware_status to at least 'warning'."""
        events = [
            {'index': 1, 'message': {'name': 'callhome.spares.low', 'severity': 'error'},
             'log_message': 'Low spares', 'time': '2026-03-06T08:00:00+00:00',
             'node': {'name': 'node1'}},
        ]
        result = _run_client(_ems_response(events))
        assert result['hardware_status'] in ('warning', 'error')

    def test_401_ems_response_does_not_raise(self):
        """A 401 from the EMS endpoint must be handled gracefully."""
        result = _run_client(_ems_401())
        assert result['alerts'] == 0
        assert result['status'] == 'online'

    def test_non_200_ems_response_does_not_raise(self):
        """A non-200 (e.g. 503) from the EMS endpoint must not crash the client."""
        result = _run_client(_ems_503())
        assert result['alerts'] == 0
        assert result['status'] == 'online'

    def test_ems_missing_node_field_handled_gracefully(self):
        """EMS events without a 'node' field should not cause a KeyError."""
        events = [
            {'index': 5, 'message': {'name': 'some.event', 'severity': 'error'},
             'log_message': 'Something', 'time': '2026-03-06T08:00:00+00:00'},
        ]
        result = _run_client(_ems_response(events))
        assert result['alerts'] == 1
        assert result['alert_details'][0]['component'] == '-'

    def test_multiple_emergency_events_counted(self):
        """Multiple emergency events all contribute to the count."""
        events = [
            {'index': i, 'message': {'name': f'event.{i}', 'severity': 'emergency'},
             'log_message': f'Event {i}', 'time': '2026-03-06T08:00:00+00:00', 'node': {'name': 'node1'}}
            for i in range(1, 4)
        ]
        result = _run_client(_ems_response(events))
        assert result['alerts'] == 3
        assert len(result['alert_details']) == 3
        assert result['hardware_status'] == 'error'
