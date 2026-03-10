"""Tests for Pure Storage FlashArray controller health-status detection.

Verifies that ``PureStorageClient.get_health_status()`` sets
``hardware_status = 'error'`` when any array controller reports a
non-ready status (e.g. ``not_ready`` during a software upgrade reboot).

Uses unittest.mock to simulate FlashArray REST API responses; no real
Pure Storage system is required.
"""

import json
from unittest.mock import patch
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(status_code, body):
    from unittest.mock import MagicMock
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    resp.text = json.dumps(body)
    return resp


def _ok(body):
    return _make_response(200, body)


def _404():
    return _make_response(404, {'error': {'message': 'not found'}})


# ---------------------------------------------------------------------------
# FakeSession – mirrors the pattern in test_ontap_rest_status_alerts.py
# ---------------------------------------------------------------------------

class _FakeSession:
    """Minimal mock for the module-level _local_session in storage_clients."""

    def __init__(self, route_map):
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
        return _ok({})


# ---------------------------------------------------------------------------
# Client factory
# ---------------------------------------------------------------------------

def _make_client():
    from app.api.storage_clients import PureStorageClient
    client = PureStorageClient.__new__(PureStorageClient)
    client.ip_address = '10.0.0.1'
    client.port = 443
    client.username = 'pureuser'
    client.password = 'password'
    client.token = 'test-api-token'
    client.resolved_address = '10.0.0.1'
    client.base_url = 'https://10.0.0.1:443'
    return client


# ---------------------------------------------------------------------------
# Minimal healthy responses for endpoints not under test
# ---------------------------------------------------------------------------

def _arrays_ok():
    return _ok({'items': [{'name': 'pure10', 'os': '6.9.3', 'id': 'abc-123'}]})


def _arrays_space_ok():
    return _ok({'items': [{'space': {'total_physical': 10 * 1024**4, 'total_capacity': 20 * 1024**4}}]})


def _controllers(items):
    """Return a /controllers response with the given list of controller dicts."""
    return _ok({'items': items})


def _network_ok():
    return _ok({'items': []})


def _hardware_ok():
    return _ok({'items': []})


def _drives_ok():
    return _ok({'items': []})


def _alerts_empty():
    return _ok({'items': []})


def _pods_ok():
    return _ok({'items': []})


def _array_connections_ok():
    return _ok({'items': []})


# ---------------------------------------------------------------------------
# Full route map for get_health_status() integration tests
# ---------------------------------------------------------------------------

def _full_route_map(ctrl_items=None, overrides=None):
    """Return a default route map where all endpoints return healthy/empty data.

    Pass ``ctrl_items`` to customise the /controllers response.
    Pass ``overrides`` dict to replace individual endpoints.
    """
    if ctrl_items is None:
        ctrl_items = [
            {'name': 'CT0', 'status': 'ready', 'mode': 'primary',
             'model': 'FA-X70R4', 'version': '6.9.3'},
            {'name': 'CT1', 'status': 'ready', 'mode': 'secondary',
             'model': 'FA-X70R4', 'version': '6.9.3'},
        ]
    base = {
        '/api/api_version':      _ok({'version': ['2.4', '2.10']}),
        '/api/2.10/login':       _ok({'username': 'pureuser'}),
        # /arrays/space must come BEFORE /arrays so the more-specific URL is
        # matched first by the substring check in _FakeSession.get().
        '/api/2.10/arrays/space': _arrays_space_ok(),
        '/api/2.10/arrays':      _arrays_ok(),
        '/api/2.10/controllers': _controllers(ctrl_items),
        '/api/2.10/network-interfaces': _network_ok(),
        '/api/2.10/hardware':    _hardware_ok(),
        '/api/2.10/drives':      _drives_ok(),
        '/api/2.10/alerts':      _alerts_empty(),
        '/api/2.10/pods':        _pods_ok(),
        '/api/2.10/array-connections': _array_connections_ok(),
        '/api/2.10/logout':      _ok({}),
    }
    if overrides:
        base.update(overrides)
    return base


def _run(ctrl_items=None, overrides=None):
    """Run get_health_status() with a controlled route map and return the result."""
    client = _make_client()
    fake_session = _FakeSession(_full_route_map(ctrl_items, overrides))
    import app.api.storage_clients as sc
    with patch.object(sc, '_local_session', fake_session):
        with patch('app.ssl_utils.get_ssl_verify', return_value=False):
            with patch('app.api.storage_clients.reverse_dns_lookup', return_value=[]):
                return client.get_health_status()


# ===========================================================================
# Tests
# ===========================================================================

class TestCtrlOkStates:
    """Verify the CTRL_OK_STATES constant contains the expected values."""

    def test_ready_is_ok(self):
        from app.api.storage_clients import PureStorageClient
        assert 'ready' in PureStorageClient.CTRL_OK_STATES

    def test_ok_is_ok(self):
        from app.api.storage_clients import PureStorageClient
        assert 'ok' in PureStorageClient.CTRL_OK_STATES

    def test_not_ready_is_not_in_ok_states(self):
        from app.api.storage_clients import PureStorageClient
        assert 'not_ready' not in PureStorageClient.CTRL_OK_STATES


class TestAllControllersReady:
    """Both controllers ready → hardware_status must remain 'ok'."""

    def test_hardware_status_ok(self):
        result = _run()
        assert result['hardware_status'] == 'ok'

    def test_status_online(self):
        result = _run()
        assert result['status'] == 'online'

    def test_controllers_returned(self):
        result = _run()
        assert len(result['controllers']) == 2


class TestOneControllerNotReady:
    """Secondary controller has status 'not_ready' (REST API style)."""

    def _result(self):
        items = [
            {'name': 'CT0', 'status': 'ready',     'mode': 'primary',
             'model': 'FA-X70R4', 'version': '6.9.3'},
            {'name': 'CT1', 'status': 'not_ready', 'mode': 'secondary',
             'model': 'FA-X70R4', 'version': '6.7.5'},
        ]
        return _run(ctrl_items=items)

    def test_hardware_status_is_error(self):
        assert self._result()['hardware_status'] == 'error'

    def test_overall_status_still_online(self):
        # The array is reachable; only hardware status reflects the bad controller
        assert self._result()['status'] == 'online'

    def test_controllers_preserved(self):
        result = self._result()
        statuses = {c['name']: c['status'] for c in result['controllers']}
        assert statuses['CT0'] == 'ready'
        assert statuses['CT1'] == 'not_ready'


class TestControllerStatusWithSpace:
    """'not ready' (with space, as shown in CLI output) must also trigger error."""

    def test_hardware_status_is_error(self):
        items = [
            {'name': 'CT0', 'status': 'ready',     'mode': 'primary',
             'model': 'FA-X70R4', 'version': '6.9.3'},
            {'name': 'CT1', 'status': 'not ready', 'mode': 'secondary',
             'model': 'FA-X70R4', 'version': '6.7.5'},
        ]
        result = _run(ctrl_items=items)
        assert result['hardware_status'] == 'error'


class TestControllerOffline:
    """A controller with 'offline' status must also trigger error."""

    def test_hardware_status_is_error(self):
        items = [
            {'name': 'CT0', 'status': 'ready',   'mode': 'primary',
             'model': 'FA-X70R4', 'version': '6.9.3'},
            {'name': 'CT1', 'status': 'offline', 'mode': 'secondary',
             'model': 'FA-X70R4', 'version': '6.9.3'},
        ]
        result = _run(ctrl_items=items)
        assert result['hardware_status'] == 'error'


class TestControllerStatusDoesNotDowngradeExistingError:
    """Hardware already in error state must stay 'error' regardless of controllers."""

    def test_remains_error_with_ready_controllers(self):
        # Inject a failed hardware component so hardware_status = 'error'
        hw_items = [{'name': 'CT0.FAN1', 'type': 'fan', 'status': 'failed'}]
        overrides = {'/api/2.10/hardware': _ok({'items': hw_items})}
        result = _run(overrides=overrides)
        assert result['hardware_status'] == 'error'


class TestShelfControllersIgnored:
    """Shelf controllers (.SC in name) must not trigger an error.

    Shelf controllers are filtered out during data collection (before the
    health check loop runs), so even a non-OK shelf controller status must
    not affect hardware_status.
    """

    def test_shelf_controller_skipped(self):
        # Include a shelf controller with a bad status alongside a healthy
        # main controller.  The shelf controller must be ignored because the
        # collection loop filters names containing '.SC'.
        items = [
            {'name': 'CT0',      'status': 'ready',     'mode': 'primary',
             'model': 'FA-X70R4', 'version': '6.9.3'},
            {'name': 'SH1.SC0',  'status': 'not_ready', 'mode': None,
             'model': 'FA-X70R4', 'version': '6.9.3'},
        ]
        result = _run(ctrl_items=items)
        assert result['hardware_status'] == 'ok'

    def test_only_main_controller_returned(self):
        """Shelf controller must not appear in the controllers list."""
        items = [
            {'name': 'CT0',     'status': 'ready',     'mode': 'primary',
             'model': 'FA-X70R4', 'version': '6.9.3'},
            {'name': 'SH1.SC0', 'status': 'not_ready', 'mode': None,
             'model': 'FA-X70R4', 'version': '6.9.3'},
        ]
        result = _run(ctrl_items=items)
        names = [c['name'] for c in result.get('controllers', [])]
        assert 'CT0' in names
        assert 'SH1.SC0' not in names


class TestNoControllers:
    """Empty controllers list must not crash and must keep hardware_status as-is."""

    def test_no_controllers_no_crash(self):
        result = _run(ctrl_items=[])
        assert result['hardware_status'] == 'ok'

    def test_controllers_list_empty(self):
        result = _run(ctrl_items=[])
        assert result.get('controllers', []) == []
