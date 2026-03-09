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
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch, call
import pytest


def _ago(hours):
    """Return an ISO-8601 timestamp for *hours* hours before now (UTC)."""
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


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


def _default_route_map(ems_response, recovery_response=None):
    if recovery_response is None:
        recovery_response = _ems_response([])
    return {
        '/api/cluster/metrocluster': _metrocluster_404(),
        '/api/cluster/peers': _peers_response(),
        '/api/cluster/nodes': _nodes_response(),
        '/api/storage/aggregates': _capacity_response(),
        '/api/cluster': _cluster_ok(),
        # Two sequential calls to the EMS endpoint:
        #   call 1 – severity-based problem events query
        #   call 2 – name-based recovery events query
        '/api/support/ems/events': [ems_response, recovery_response],
    }


def _run_client(ems_response, recovery_response=None):
    """Run NetAppONTAPClient.get_health_status() with mocked HTTP."""
    client = _make_client()
    fake_session = _FakeSession(_default_route_map(ems_response, recovery_response))
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
            {'index': 5, 'message': {'name': 'hm.something', 'severity': 'error'},
             'log_message': 'Something', 'time': _ago(1)},
        ]
        result = _run_client(_ems_response(events))
        assert result['alerts'] == 1
        assert result['alert_details'][0]['component'] == '-'

    def test_non_hw_event_missing_node_field_handled_gracefully(self):
        """Non-hardware events without a 'node' field should not cause a KeyError.

        The category filter passes emergency-level non-hardware events; a missing
        node field must not raise an exception regardless of event family.
        """
        events = [
            {'index': 6, 'message': {'name': 'some.unknown.event', 'severity': 'emergency'},
             'log_message': 'Unknown emergency', 'time': _ago(1)},
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


# ---------------------------------------------------------------------------
# Recovery-filtering tests
# Verify that already-resolved alerts are excluded from the result.
# ---------------------------------------------------------------------------

class TestONTAPEmsRecoveryFiltering:
    """Tests for the EMS active-alert state reconstruction logic.

    Each test supplies a ``problem_response`` (returned by the severity-based
    first query) and a ``recovery_response`` (returned by the name-based second
    query).  The implementation must apply ``_filter_active_ems_events`` before
    counting/building alert_details.
    """

    # ---- helper factories ------------------------------------------------
    # Default timestamps are relative to now so they always fall within the
    # 48-hour lookback window regardless of when the tests are executed.

    @staticmethod
    def _hm_raised(index, node, alert_id, time=None):
        return {
            'index': index,
            'message': {'name': 'hm.alert.raised', 'severity': 'alert'},
            'log_message': f'Health monitor alert {alert_id} raised on {node}',
            'time': time if time is not None else _ago(24),
            'node': {'name': node},
            'parameters': [{'name': 'alertId', 'value': alert_id}],
        }

    @staticmethod
    def _hm_cleared(index, node, alert_id, time=None):
        return {
            'index': index,
            'message': {'name': 'hm.alert.cleared', 'severity': 'informational'},
            'log_message': f'Health monitor alert {alert_id} cleared on {node}',
            'time': time if time is not None else _ago(12),
            'node': {'name': node},
            'parameters': [{'name': 'alertId', 'value': alert_id}],
        }

    @staticmethod
    def _cpeer_unavailable(index, node, peer, time=None):
        return {
            'index': index,
            'message': {'name': 'cpeer.unavailable', 'severity': 'error'},
            'log_message': f'Cluster peer {peer} unavailable',
            'time': time if time is not None else _ago(24),
            'node': {'name': node},
            'parameters': [{'name': 'peerName', 'value': peer}],
        }

    @staticmethod
    def _cpeer_available(index, node, peer, time=None):
        return {
            'index': index,
            'message': {'name': 'cpeer.available', 'severity': 'informational'},
            'log_message': f'Cluster peer {peer} available',
            'time': time if time is not None else _ago(12),
            'node': {'name': node},
            'parameters': [{'name': 'peerName', 'value': peer}],
        }

    @staticmethod
    def _cf_critical(index, node, time=None):
        return {
            'index': index,
            'message': {'name': 'cf.fsm.monitor.globalStatus.critical', 'severity': 'alert'},
            'log_message': f'Cluster failover critical on {node}',
            'time': time if time is not None else _ago(24),
            'node': {'name': node},
            'parameters': [],
        }

    @staticmethod
    def _cf_ok(index, node, time=None):
        return {
            'index': index,
            'message': {'name': 'cf.fsm.monitor.globalStatus.ok', 'severity': 'informational'},
            'log_message': f'Cluster failover ok on {node}',
            'time': time if time is not None else _ago(12),
            'node': {'name': node},
            'parameters': [],
        }

    # ---- hm.alert tests --------------------------------------------------

    def test_hm_alert_raised_without_cleared_is_active(self):
        """hm.alert.raised with no corresponding cleared event → alert is active."""
        problem = [self._hm_raised(1, 'node1', 'DiskFailure')]
        result = _run_client(_ems_response(problem), _ems_response([]))
        assert result['alerts'] == 1
        assert result['alert_details'][0]['title'] == 'hm.alert.raised'

    def test_hm_alert_raised_then_cleared_is_not_active(self):
        """hm.alert.raised followed by hm.alert.cleared → alert must not appear."""
        problem  = [self._hm_raised(1, 'node1', 'DiskFailure',  time=_ago(30))]
        recovery = [self._hm_cleared(2, 'node1', 'DiskFailure', time=_ago(6))]
        result = _run_client(_ems_response(problem), _ems_response(recovery))
        assert result['alerts'] == 0

    def test_hm_alert_cleared_then_raised_again_is_active(self):
        """Cleared then raised again (more recent raise) → alert must appear."""
        # problem_records contains only severity events, so the raise is there
        problem  = [self._hm_raised(3, 'node1', 'DiskFailure',  time=_ago(4))]
        # recovery query returns the older cleared event
        recovery = [self._hm_cleared(2, 'node1', 'DiskFailure', time=_ago(12))]
        result = _run_client(_ems_response(problem), _ems_response(recovery))
        assert result['alerts'] == 1
        assert result['alert_details'][0]['title'] == 'hm.alert.raised'

    def test_two_distinct_hm_alerts_one_cleared(self):
        """Two different hm.alert.raised events; only one is cleared → one active."""
        problem = [
            self._hm_raised(1, 'node1', 'DiskFailure', time=_ago(30)),
            self._hm_raised(2, 'node1', 'FanFailure',  time=_ago(20)),
        ]
        recovery = [self._hm_cleared(3, 'node1', 'DiskFailure', time=_ago(10))]
        result = _run_client(_ems_response(problem), _ems_response(recovery))
        assert result['alerts'] == 1
        active_ids = [d['error_code'] for d in result['alert_details']]
        assert 'hm.alert.raised' in active_ids  # FanFailure alert still active

    # ---- cpeer tests -----------------------------------------------------

    def test_cpeer_unavailable_without_available_is_active(self):
        """cpeer.unavailable with no cpeer.available → alert is active."""
        problem = [self._cpeer_unavailable(10, 'node1', 'cluster-b')]
        result = _run_client(_ems_response(problem), _ems_response([]))
        assert result['alerts'] == 1

    def test_cpeer_unavailable_then_available_is_not_active(self):
        """cpeer.unavailable followed by cpeer.available → cleared, not active."""
        problem  = [self._cpeer_unavailable(10, 'node1', 'cluster-b', time=_ago(30))]
        recovery = [self._cpeer_available(11, 'node1', 'cluster-b',   time=_ago(6))]
        result = _run_client(_ems_response(problem), _ems_response(recovery))
        assert result['alerts'] == 0

    # ---- cf.fsm.monitor tests --------------------------------------------

    def test_cf_critical_without_ok_is_active(self):
        """cf.fsm.monitor.globalStatus.critical with no ok event → active."""
        problem = [self._cf_critical(20, 'node1')]
        result = _run_client(_ems_response(problem), _ems_response([]))
        assert result['alerts'] == 1

    def test_cf_critical_then_ok_is_not_active(self):
        """cf.fsm.monitor.globalStatus.critical followed by ok → cleared."""
        problem  = [self._cf_critical(20, 'node1', time=_ago(30))]
        recovery = [self._cf_ok(21,       'node1', time=_ago(6))]
        result = _run_client(_ems_response(problem), _ems_response(recovery))
        assert result['alerts'] == 0

    # ---- mixed tests -----------------------------------------------------

    def test_tracked_cleared_plus_untracked_severity_event(self):
        """Cleared tracked alert + untracked severity event → only untracked appears."""
        problem = [
            self._hm_raised(1, 'node1', 'DiskFailure', time=_ago(30)),
            {'index': 5, 'message': {'name': 'callhome.spares.low', 'severity': 'error'},
             'log_message': 'Spare capacity low', 'time': _ago(20),
             'node': {'name': 'node1'}, 'parameters': []},
        ]
        recovery = [self._hm_cleared(2, 'node1', 'DiskFailure', time=_ago(10))]
        result = _run_client(_ems_response(problem), _ems_response(recovery))
        assert result['alerts'] == 1
        assert result['alert_details'][0]['error_code'] == 'callhome.spares.low'

    def test_recovery_query_failure_does_not_crash(self):
        """A failure fetching recovery events must be handled gracefully (no crash).

        When the recovery endpoint is unreachable we fall back to showing all
        severity-based events (conservative – no false negatives).
        """
        problem = [self._hm_raised(1, 'node1', 'DiskFailure')]
        # 503 on the recovery query
        result = _run_client(_ems_response(problem), _ems_503())
        # Should still show the problem event (no crash, no silent loss)
        assert result['alerts'] == 1
        assert result['status'] == 'online'


# ---------------------------------------------------------------------------
# Age and category filter tests (_filter_ems_by_age_and_category)
# ---------------------------------------------------------------------------

class TestEmsAgeAndCategoryFilter:
    """Unit tests for _filter_ems_by_age_and_category().

    These tests exercise the helper directly (no full client mock needed).
    """

    @staticmethod
    def _event(name, severity, hours_ago):
        """Build a minimal EMS event dict."""
        from datetime import datetime, timezone, timedelta
        ts = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
        return {
            'index': 1,
            'message': {'name': name, 'severity': severity},
            'log_message': f'{name} event',
            'time': ts,
            'node': {'name': 'node1'},
            'parameters': [],
        }

    def test_recent_hardware_error_is_kept(self):
        """A hardware 'error' event within 48 h must be included."""
        from app.api.storage_clients import _filter_ems_by_age_and_category
        events = [self._event('hm.alert.raised', 'error', hours_ago=1)]
        result = _filter_ems_by_age_and_category(events)
        assert len(result) == 1

    def test_recent_non_hw_error_is_dropped(self):
        """A non-hardware 'error' event (e.g. capacity) must be suppressed."""
        from app.api.storage_clients import _filter_ems_by_age_and_category
        events = [self._event('wafl.vol.autosize.done', 'error', hours_ago=1)]
        result = _filter_ems_by_age_and_category(events)
        assert len(result) == 0

    def test_recent_non_hw_alert_severity_is_kept(self):
        """A non-hardware 'alert'-severity event within 48 h must be kept."""
        from app.api.storage_clients import _filter_ems_by_age_and_category
        events = [self._event('wafl.vol.autosize.done', 'alert', hours_ago=1)]
        result = _filter_ems_by_age_and_category(events)
        assert len(result) == 1

    def test_recent_non_hw_emergency_is_kept(self):
        """A non-hardware 'emergency' event within 48 h must always be kept."""
        from app.api.storage_clients import _filter_ems_by_age_and_category
        events = [self._event('some.unknown.event', 'emergency', hours_ago=2)]
        result = _filter_ems_by_age_and_category(events)
        assert len(result) == 1

    def test_old_event_is_dropped_regardless_of_severity(self):
        """An event older than 96 h must be dropped even if severity is emergency."""
        from app.api.storage_clients import _filter_ems_by_age_and_category
        events = [self._event('hm.alert.raised', 'emergency', hours_ago=100)]
        result = _filter_ems_by_age_and_category(events)
        assert len(result) == 0

    def test_event_at_exactly_96h_boundary_is_dropped(self):
        """An event at exactly 96 h (or marginally older) must be dropped."""
        from app.api.storage_clients import _filter_ems_by_age_and_category
        events = [self._event('disk.write.failure', 'error', hours_ago=96.01)]
        result = _filter_ems_by_age_and_category(events)
        assert len(result) == 0

    def test_event_just_inside_window_is_kept(self):
        """An event raised 95.9 h ago must be kept."""
        from app.api.storage_clients import _filter_ems_by_age_and_category
        events = [self._event('disk.write.failure', 'error', hours_ago=95.9)]
        result = _filter_ems_by_age_and_category(events)
        assert len(result) == 1

    def test_unparseable_timestamp_is_kept_conservatively(self):
        """An event with an unparseable timestamp must be included (conservative)."""
        from app.api.storage_clients import _filter_ems_by_age_and_category
        event = {
            'index': 1,
            'message': {'name': 'hm.alert.raised', 'severity': 'error'},
            'log_message': 'bad ts',
            'time': 'not-a-timestamp',
            'node': {'name': 'node1'},
            'parameters': [],
        }
        result = _filter_ems_by_age_and_category([event])
        assert len(result) == 1

    def test_missing_timestamp_is_kept_conservatively(self):
        """An event with no 'time' field must be included (conservative)."""
        from app.api.storage_clients import _filter_ems_by_age_and_category
        event = {
            'index': 1,
            'message': {'name': 'hm.alert.raised', 'severity': 'error'},
            'log_message': 'no ts',
            'node': {'name': 'node1'},
            'parameters': [],
        }
        result = _filter_ems_by_age_and_category([event])
        assert len(result) == 1

    def test_hardware_prefixes_all_kept_at_error(self):
        """All hardware event prefixes must be treated as hardware at 'error' severity."""
        from app.api.storage_clients import _filter_ems_by_age_and_category, _EMS_HARDWARE_EVENT_PREFIXES
        hardware_names = [pfx + 'something' for pfx in _EMS_HARDWARE_EVENT_PREFIXES]
        events = [self._event(name, 'error', hours_ago=1) for name in hardware_names]
        result = _filter_ems_by_age_and_category(events)
        assert len(result) == len(hardware_names), (
            f"Expected all {len(hardware_names)} hardware events, got {len(result)}"
        )

    def test_mixed_events_filtered_correctly(self):
        """Mix of old, new, hw, non-hw events: only recent hw+alert-priority non-hw kept."""
        from app.api.storage_clients import _filter_ems_by_age_and_category
        events = [
            self._event('hm.alert.raised',       'error',     hours_ago=1),   # keep: hw, recent
            self._event('disk.write.failure',     'error',     hours_ago=1),   # keep: hw, recent
            self._event('callhome.spares.low',    'error',     hours_ago=100),  # drop: old
            self._event('wafl.vol.autosize.done', 'error',     hours_ago=1),   # drop: non-hw error
            self._event('wafl.vol.autosize.done', 'alert',     hours_ago=1),   # keep: non-hw alert
            self._event('some.unknown.event',     'emergency', hours_ago=1),   # keep: non-hw emergency
        ]
        result = _filter_ems_by_age_and_category(events)
        assert len(result) == 4
        names = [e['message']['name'] for e in result]
        assert 'hm.alert.raised' in names
        assert 'disk.write.failure' in names
        assert 'wafl.vol.autosize.done' in names
        assert 'some.unknown.event' in names

    def test_old_events_are_excluded_from_full_client(self):
        """Old EMS events are excluded from get_health_status() via the pre-filter."""
        from datetime import datetime, timezone, timedelta
        old_ts = (datetime.now(timezone.utc) - timedelta(hours=100)).isoformat()
        events = [
            {'index': 1, 'message': {'name': 'callhome.spares.low', 'severity': 'error'},
             'log_message': 'Old spare event', 'time': old_ts, 'node': {'name': 'node1'}},
        ]
        result = _run_client(_ems_response(events))
        assert result['alerts'] == 0

    def test_recent_non_hw_error_excluded_from_full_client(self):
        """Recent non-hardware 'error' events are excluded by the category filter."""
        from datetime import datetime, timezone, timedelta
        recent_ts = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        events = [
            {'index': 2, 'message': {'name': 'wafl.vol.autosize.done', 'severity': 'error'},
             'log_message': 'Volume autosize triggered', 'time': recent_ts,
             'node': {'name': 'node1'}, 'parameters': []},
        ]
        result = _run_client(_ems_response(events))
        assert result['alerts'] == 0

