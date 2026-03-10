"""Tests for Pure FlashArray dual-method capacity collection in capacity_service._do_refresh.

Verifies that _do_refresh correctly uses one of two methods to query capacity
depending on whether the Standard or Evergreen/One Dashboard API is active:

  * Standard Dashboard API – ``space.total_physical`` is non-zero in the local
    FlashArray REST response.  The local API values are used directly.

  * Evergreen/One Dashboard API – ``space.total_physical`` is absent or 0.
    The Pure1 ``subscription-assets`` endpoint is the authoritative source; its
    ``used_bytes`` / ``capacity_bytes`` values are stored in CapacitySnapshot.

All network calls and background threads are patched; the tests run against an
in-memory SQLite database so they are fast and fully isolated.
"""

import logging
import os
from datetime import date, datetime
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Test application factory
# ---------------------------------------------------------------------------

def _no_op(*a, **kw):
    pass


@pytest.fixture()
def app():
    """Return a test Flask app with an in-memory SQLite database.

    Background threads are suppressed to keep the test suite fast.
    """
    patches = [
        patch('app.capacity_service.start_background_refresh', _no_op),
        patch('app.sod_service.start_background_refresh', _no_op),
        patch('app.status_service.start_background_refresh', _no_op),
    ]
    for p in patches:
        p.start()

    os.environ.setdefault('SECRET_KEY', 'test-secret-dual-method')
    os.environ['DATABASE_URL'] = 'sqlite://'

    from app import create_app
    flask_app = create_app()
    flask_app.config['TESTING'] = True

    for p in patches:
        p.stop()

    yield flask_app


@pytest.fixture()
def app_ctx(app):
    with app.app_context():
        yield app


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def _make_pure_system(db, name='pure-fa-01', ip='10.1.1.1', pure1_array_name=None):
    """Create and flush an enabled Pure FlashArray StorageSystem."""
    from app.models import StorageSystem
    system = StorageSystem(
        name=name,
        vendor='pure',
        ip_address=ip,
        api_token='test-token',
        enabled=True,
        pure1_array_name=pure1_array_name,
    )
    db.session.add(system)
    db.session.flush()
    return system


def _make_app_settings(db, pure1_app_id=None, pure1_private_key=None):
    """Create AppSettings with optional Pure1 credentials."""
    from app.models import AppSettings
    settings = AppSettings.query.first()
    if settings is None:
        settings = AppSettings()
        db.session.add(settings)
    if pure1_app_id is not None:
        settings.pure1_app_id = pure1_app_id
    if pure1_private_key is not None:
        settings.pure1_private_key = pure1_private_key
    db.session.flush()
    return settings


def _get_snapshot(db, system_id):
    """Return the CapacitySnapshot for the given system, or None."""
    from app.models import CapacitySnapshot
    return CapacitySnapshot.query.filter_by(system_id=system_id).first()


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

def _mock_standard_status(total_tb=100.0, used_tb=60.0):
    """Build a mock get_health_status() result for a Standard Dashboard array."""
    percent = round(used_tb / total_tb * 100, 1) if total_tb else 0.0
    return {
        'status': 'online',
        'hardware_status': 'ok',
        'cluster_status': 'ok',
        'alerts': 0,
        'capacity_total_tb': round(total_tb, 2),
        'capacity_used_tb': round(used_tb, 2),
        'capacity_percent': percent,
        'error': None,
        # evergreen_one_dashboard_active is absent → Standard Dashboard
    }


def _mock_evergreen_status(licensed_total_tb=500.0):
    """Build a mock get_health_status() result for an Evergreen/One Dashboard array.

    The local API returns the licensed capacity as ``capacity_total_tb`` and 0
    for ``capacity_used_tb`` (``space.total_physical`` == 0).
    """
    return {
        'status': 'online',
        'hardware_status': 'ok',
        'cluster_status': 'ok',
        'alerts': 0,
        'capacity_total_tb': round(licensed_total_tb, 2),
        'capacity_used_tb': 0.0,
        'capacity_percent': 0.0,
        'error': None,
        'evergreen_one_dashboard_active': True,
    }


def _mock_pure1_space(used_bytes, capacity_bytes):
    """Build a mock return value for fetch_subscription_asset_physical_used()."""
    return {
        'used_bytes': used_bytes,
        'capacity_bytes': capacity_bytes,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestStandardDashboardCapacity:
    """Standard Dashboard: capacity is taken from the local FlashArray REST API."""

    def test_local_values_stored_in_snapshot(self, app_ctx):
        """total_tb and used_tb from get_health_status() are written to CapacitySnapshot."""
        from app import db
        from app.capacity_service import _do_refresh

        with app_ctx.app_context():
            system = _make_pure_system(db)
            db.session.commit()

            mock_status = _mock_standard_status(total_tb=200.0, used_tb=80.0)
            mock_client = MagicMock()
            mock_client.get_health_status.return_value = mock_status

            with patch('app.api.get_client', return_value=mock_client), \
                 patch('app.api.pure1_client.fetch_subscription_asset_physical_used') as mock_pure1:

                _do_refresh(app_ctx)

                # Pure1 API must NOT be called for Standard Dashboard arrays
                mock_pure1.assert_not_called()

            snap = _get_snapshot(db, system.id)
            assert snap is not None
            assert abs(snap.total_tb - 200.0) < 0.01
            assert abs(snap.used_tb - 80.0) < 0.01

    def test_percent_computed_from_local_values(self, app_ctx):
        """capacity_percent is derived from the local API values."""
        from app import db
        from app.capacity_service import _do_refresh

        with app_ctx.app_context():
            system = _make_pure_system(db, name='pure-std-02')
            db.session.commit()

            mock_status = _mock_standard_status(total_tb=400.0, used_tb=100.0)
            mock_client = MagicMock()
            mock_client.get_health_status.return_value = mock_status

            with patch('app.api.get_client', return_value=mock_client):
                _do_refresh(app_ctx)

            snap = _get_snapshot(db, system.id)
            assert snap is not None
            assert abs(snap.percent_used - 25.0) < 0.5


class TestEvergreenOneDashboardCapacity:
    """Evergreen/One Dashboard: Pure1 API provides the authoritative capacity values."""

    def test_pure1_values_override_local_api(self, app_ctx):
        """When Evergreen/One is active and Pure1 is configured, Pure1 capacity is stored."""
        from app import db
        from app.capacity_service import _do_refresh

        with app_ctx.app_context():
            system = _make_pure_system(db, name='pure-eg1-01')
            _make_app_settings(db, pure1_app_id='pure1:apikey:abc', pure1_private_key='pem-data')
            db.session.commit()

            # Local API claims 500 TB licensed, 0 physical used (Evergreen/One)
            mock_status = _mock_evergreen_status(licensed_total_tb=500.0)
            mock_client = MagicMock()
            mock_client.get_health_status.return_value = mock_status

            # Pure1 reports real physical usage
            physical_used_bytes  = 247_000_000_000_000  # ~247 TB
            physical_capacity_bytes = 400_000_000_000_000  # ~400 TB
            mock_pure1_space = _mock_pure1_space(physical_used_bytes, physical_capacity_bytes)

            with patch('app.api.get_client', return_value=mock_client), \
                 patch('app.api.pure1_client.fetch_subscription_asset_physical_used',
                       return_value=mock_pure1_space):
                _do_refresh(app_ctx)

            snap = _get_snapshot(db, system.id)
            assert snap is not None

            expected_used_tb  = physical_used_bytes  / (1024 ** 4)
            expected_total_tb = physical_capacity_bytes / (1024 ** 4)

            assert abs(snap.used_tb  - expected_used_tb)  < 0.1, (
                f"used_tb should come from Pure1 ({expected_used_tb:.2f}), "
                f"not from local API (0.0); got {snap.used_tb}"
            )
            assert abs(snap.total_tb - expected_total_tb) < 0.1, (
                f"total_tb should come from Pure1 ({expected_total_tb:.2f}), "
                f"not from local API (500.0 licensed); got {snap.total_tb}"
            )

    def test_pure1_name_override_used_when_configured(self, app_ctx):
        """When pure1_array_name is set on the system, it is passed to the Pure1 API."""
        from app import db
        from app.capacity_service import _do_refresh

        with app_ctx.app_context():
            # Dashboard name differs from Pure1 name
            system = _make_pure_system(db, name='fa-dashboard-name', pure1_array_name='pure-fa-pure1')
            _make_app_settings(db, pure1_app_id='pure1:apikey:test', pure1_private_key='key-pem')
            db.session.commit()

            mock_status = _mock_evergreen_status(licensed_total_tb=300.0)
            mock_client = MagicMock()
            mock_client.get_health_status.return_value = mock_status

            captured_name = {}

            def _fake_pure1(app_id, key, array_name, **kwargs):
                captured_name['name'] = array_name
                return _mock_pure1_space(100_000_000_000_000, 300_000_000_000_000)

            with patch('app.api.get_client', return_value=mock_client), \
                 patch('app.api.pure1_client.fetch_subscription_asset_physical_used',
                       side_effect=_fake_pure1):
                _do_refresh(app_ctx)

            assert captured_name.get('name') == 'pure-fa-pure1', (
                "The pure1_array_name override must be used when calling the Pure1 API"
            )

    def test_system_name_used_when_no_pure1_name_override(self, app_ctx):
        """Without a pure1_array_name override the system name is used for the Pure1 call."""
        from app import db
        from app.capacity_service import _do_refresh

        with app_ctx.app_context():
            system = _make_pure_system(db, name='pure-fa-same-name', pure1_array_name=None)
            _make_app_settings(db, pure1_app_id='pure1:apikey:test', pure1_private_key='key-pem')
            db.session.commit()

            mock_status = _mock_evergreen_status(licensed_total_tb=200.0)
            mock_client = MagicMock()
            mock_client.get_health_status.return_value = mock_status

            captured_name = {}

            def _fake_pure1(app_id, key, array_name, **kwargs):
                captured_name['name'] = array_name
                return _mock_pure1_space(80_000_000_000_000, 200_000_000_000_000)

            with patch('app.api.get_client', return_value=mock_client), \
                 patch('app.api.pure1_client.fetch_subscription_asset_physical_used',
                       side_effect=_fake_pure1):
                _do_refresh(app_ctx)

            assert captured_name.get('name') == 'pure-fa-same-name'

    def test_percent_recalculated_from_pure1_values(self, app_ctx):
        """After the Pure1 override, percent_used is recalculated from the new figures."""
        from app import db
        from app.capacity_service import _do_refresh

        with app_ctx.app_context():
            system = _make_pure_system(db, name='pure-pct-01')
            _make_app_settings(db, pure1_app_id='pure1:apikey:x', pure1_private_key='k')
            db.session.commit()

            mock_status = _mock_evergreen_status(licensed_total_tb=1000.0)
            mock_client = MagicMock()
            mock_client.get_health_status.return_value = mock_status

            # 200 used out of 400 total = 50 %
            used_bytes  = 200 * (1024 ** 4)
            total_bytes = 400 * (1024 ** 4)

            with patch('app.api.get_client', return_value=mock_client), \
                 patch('app.api.pure1_client.fetch_subscription_asset_physical_used',
                       return_value=_mock_pure1_space(used_bytes, total_bytes)):
                _do_refresh(app_ctx)

            snap = _get_snapshot(db, system.id)
            assert snap is not None
            assert abs(snap.percent_used - 50.0) < 0.5, (
                f"percent_used should be ~50 %, got {snap.percent_used}"
            )


class TestEvergreenOneFallbackBehavior:
    """Fallback behaviour when Pure1 is unavailable or not configured."""

    def test_pure1_api_failure_falls_back_to_local_values(self, app_ctx):
        """A Pure1 API exception must not crash _do_refresh; local values are stored."""
        from app import db
        from app.capacity_service import _do_refresh

        with app_ctx.app_context():
            system = _make_pure_system(db, name='pure-fallback-01')
            _make_app_settings(db, pure1_app_id='pure1:apikey:x', pure1_private_key='k')
            db.session.commit()

            mock_status = _mock_evergreen_status(licensed_total_tb=600.0)
            mock_client = MagicMock()
            mock_client.get_health_status.return_value = mock_status

            with patch('app.api.get_client', return_value=mock_client), \
                 patch('app.api.pure1_client.fetch_subscription_asset_physical_used',
                       side_effect=Exception('Pure1 connection timeout')):
                # Must not raise
                _do_refresh(app_ctx)

            snap = _get_snapshot(db, system.id)
            assert snap is not None, "CapacitySnapshot must be written even when Pure1 fails"
            # Falls back to local API values: total = licensed capacity, used = 0
            assert abs(snap.total_tb - 600.0) < 0.1
            assert abs(snap.used_tb  - 0.0)   < 0.01

    def test_pure1_returns_none_falls_back_to_local_values(self, app_ctx):
        """When fetch_subscription_asset_physical_used returns None, local values are used."""
        from app import db
        from app.capacity_service import _do_refresh

        with app_ctx.app_context():
            system = _make_pure_system(db, name='pure-none-01')
            _make_app_settings(db, pure1_app_id='pure1:apikey:x', pure1_private_key='k')
            db.session.commit()

            mock_status = _mock_evergreen_status(licensed_total_tb=400.0)
            mock_client = MagicMock()
            mock_client.get_health_status.return_value = mock_status

            with patch('app.api.get_client', return_value=mock_client), \
                 patch('app.api.pure1_client.fetch_subscription_asset_physical_used',
                       return_value=None):
                _do_refresh(app_ctx)

            snap = _get_snapshot(db, system.id)
            assert snap is not None
            # Falls back to local values
            assert abs(snap.total_tb - 400.0) < 0.1
            assert abs(snap.used_tb  - 0.0)   < 0.01

    def test_pure1_not_configured_uses_local_values_with_warning(self, app_ctx, caplog):
        """No Pure1 credentials → local values stored; a warning is logged."""
        from app import db
        from app.capacity_service import _do_refresh

        with app_ctx.app_context():
            system = _make_pure_system(db, name='pure-nocred-01')
            # No Pure1 credentials configured
            _make_app_settings(db, pure1_app_id=None, pure1_private_key=None)
            db.session.commit()

            mock_status = _mock_evergreen_status(licensed_total_tb=300.0)
            mock_client = MagicMock()
            mock_client.get_health_status.return_value = mock_status

            with patch('app.api.get_client', return_value=mock_client), \
                 patch('app.api.pure1_client.fetch_subscription_asset_physical_used') as mock_pure1, \
                 caplog.at_level(logging.WARNING, logger='app.capacity_service'):
                _do_refresh(app_ctx)

                # Pure1 must NOT be called when credentials are absent
                mock_pure1.assert_not_called()

            snap = _get_snapshot(db, system.id)
            assert snap is not None
            # Local values are used (used = 0, total = licensed capacity)
            assert abs(snap.total_tb - 300.0) < 0.1
            assert abs(snap.used_tb  - 0.0)   < 0.01

            # A warning about missing Pure1 credentials must appear in the log
            warning_msgs = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
            assert any('Pure1' in msg or 'Evergreen' in msg for msg in warning_msgs), (
                f"Expected a warning about missing Pure1 credentials; got: {warning_msgs}"
            )


class TestCapacityHistoryDualMethod:
    """CapacityHistory entries written by _do_refresh must also reflect the correct source."""

    def test_history_entry_uses_pure1_values_for_evergreen(self, app_ctx):
        """For Evergreen/One arrays, CapacityHistory must store Pure1 values, not local API."""
        from app import db
        from app.models import CapacityHistory
        from app.capacity_service import _do_refresh

        with app_ctx.app_context():
            system = _make_pure_system(db, name='pure-hist-01')
            _make_app_settings(db, pure1_app_id='pure1:apikey:x', pure1_private_key='k')
            db.session.commit()

            mock_status = _mock_evergreen_status(licensed_total_tb=800.0)
            mock_client = MagicMock()
            mock_client.get_health_status.return_value = mock_status

            used_bytes  = 350 * (1024 ** 4)
            total_bytes = 700 * (1024 ** 4)

            with patch('app.api.get_client', return_value=mock_client), \
                 patch('app.api.pure1_client.fetch_subscription_asset_physical_used',
                       return_value=_mock_pure1_space(used_bytes, total_bytes)):
                _do_refresh(app_ctx)

            today = date.today()
            hist = CapacityHistory.query.filter_by(system_id=system.id, date=today).first()
            assert hist is not None, "CapacityHistory entry must be written for today"
            assert abs(hist.total_tb - 700.0) < 0.1, (
                f"CapacityHistory total_tb should be the Pure1 physical capacity (700 TB), "
                f"not the licensed capacity (800 TB); got {hist.total_tb}"
            )
            assert abs(hist.used_tb - 350.0) < 0.1

    def test_history_entry_uses_local_values_for_standard(self, app_ctx):
        """For Standard Dashboard arrays, CapacityHistory stores local API values."""
        from app import db
        from app.models import CapacityHistory
        from app.capacity_service import _do_refresh

        with app_ctx.app_context():
            system = _make_pure_system(db, name='pure-hist-std-01')
            db.session.commit()

            mock_status = _mock_standard_status(total_tb=250.0, used_tb=175.0)
            mock_client = MagicMock()
            mock_client.get_health_status.return_value = mock_status

            with patch('app.api.get_client', return_value=mock_client):
                _do_refresh(app_ctx)

            today = date.today()
            hist = CapacityHistory.query.filter_by(system_id=system.id, date=today).first()
            assert hist is not None
            assert abs(hist.total_tb - 250.0) < 0.1
            assert abs(hist.used_tb  - 175.0) < 0.1


# ---------------------------------------------------------------------------
# Detection tests – PureStorageClient.get_health_status()
# ---------------------------------------------------------------------------
# These tests verify that the FlashArray client correctly classifies an array
# as Standard or Evergreen/One Dashboard by inspecting the space API response.
# They use the same fake-session pattern as test_pure_controller_status.py.

def _make_response(status_code, body):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    return resp


def _ok_resp(body):
    return _make_response(200, body)


class _FakeSessionForDetection:
    """Minimal HTTP session mock for PureStorageClient integration tests."""

    def __init__(self, route_map):
        self._map = route_map

    def get(self, url, **kwargs):
        for key, val in self._map.items():
            if key in url:
                return val
        raise AssertionError(f"Unexpected GET: {url}")

    def post(self, url, **kwargs):
        return _ok_resp({})


def _detection_route_map(space_items):
    """Return a minimal route map; only the space endpoint varies between tests.

    Note: ``/api/2.10/arrays/space`` must be listed BEFORE ``/api/2.10/arrays``
    so that the more-specific URL is matched first by the substring check in
    _FakeSessionForDetection.get().
    """
    return {
        '/api/api_version':           _ok_resp({'version': ['2.4', '2.10']}),
        '/api/2.10/login':            _ok_resp({'username': 'pureuser'}),
        # /space BEFORE /arrays so the substring check matches the right response
        '/api/2.10/arrays/space':     _ok_resp({'items': space_items}),
        '/api/2.10/arrays':           _ok_resp({'items': [{'name': 'puredet01', 'version': '6.9.3'}]}),
        '/api/2.10/controllers':      _ok_resp({'items': [
            {'name': 'CT0', 'status': 'ready', 'mode': 'primary',
             'model': 'FA-X70R4', 'version': '6.9.3'},
        ]}),
        '/api/2.10/network-interfaces': _ok_resp({'items': []}),
        '/api/2.10/hardware':           _ok_resp({'items': []}),
        '/api/2.10/drives':             _ok_resp({'items': []}),
        '/api/2.10/alerts':             _ok_resp({'items': []}),
        '/api/2.10/pods':               _ok_resp({'items': []}),
        '/api/2.10/array-connections':  _ok_resp({'items': []}),
        '/api/2.10/logout':             _ok_resp({}),
    }


def _run_detection(space_items):
    """Run PureStorageClient.get_health_status() with controlled space API data."""
    from app.api.storage_clients import PureStorageClient
    import app.api.storage_clients as sc

    client = PureStorageClient.__new__(PureStorageClient)
    client.ip_address   = '10.9.9.1'
    client.port         = 443
    client.username     = 'pureuser'
    client.password     = 'secret'
    client.token        = 'test-api-token'
    client.resolved_address = '10.9.9.1'
    client.base_url     = 'https://10.9.9.1:443'

    fake_session = _FakeSessionForDetection(_detection_route_map(space_items))
    with patch.object(sc, '_local_session', fake_session), \
         patch('app.ssl_utils.get_ssl_verify', return_value=False), \
         patch('app.api.storage_clients.reverse_dns_lookup', return_value=[]):
        return client.get_health_status()


class TestEvergreenOneDetectionInGetHealthStatus:
    """PureStorageClient.get_health_status() must correctly detect Standard vs Evergreen/One."""

    def test_standard_dashboard_no_evergreen_flag(self):
        """Standard Dashboard: space.total_physical is non-zero → flag absent (or False)."""
        space_items = [{'capacity': 200 * (1024 ** 4),
                        'space': {'total_physical': 120 * (1024 ** 4)}}]
        result = _run_detection(space_items)
        assert not result.get('evergreen_one_dashboard_active'), (
            "Standard Dashboard arrays must NOT have evergreen_one_dashboard_active set"
        )

    def test_standard_dashboard_capacity_values_from_local_api(self):
        """Standard Dashboard: capacity values should reflect the local API response."""
        total_bytes = 200 * (1024 ** 4)
        used_bytes  = 120 * (1024 ** 4)
        space_items = [{'capacity': total_bytes,
                        'space': {'total_physical': used_bytes}}]
        result = _run_detection(space_items)
        expected_total = round(total_bytes / (1024 ** 4), 2)
        expected_used  = round(used_bytes  / (1024 ** 4), 2)
        assert abs(result['capacity_total_tb'] - expected_total) < 0.01
        assert abs(result['capacity_used_tb']  - expected_used)  < 0.01

    def test_evergreen_one_detected_when_total_physical_is_zero(self):
        """Evergreen/One Dashboard: space.total_physical == 0 → flag set to True."""
        space_items = [{'capacity': 500 * (1024 ** 4),
                        'space': {'total_physical': 0}}]
        result = _run_detection(space_items)
        assert result.get('evergreen_one_dashboard_active') is True, (
            "total_physical == 0 must trigger Evergreen/One detection"
        )

    def test_evergreen_one_detected_when_total_physical_absent(self):
        """Evergreen/One Dashboard: space.total_physical absent → flag set to True."""
        space_items = [{'capacity': 500 * (1024 ** 4),
                        'space': {}}]
        result = _run_detection(space_items)
        assert result.get('evergreen_one_dashboard_active') is True, (
            "Missing total_physical must trigger Evergreen/One detection"
        )

    def test_evergreen_one_used_tb_is_zero(self):
        """For Evergreen/One arrays, capacity_used_tb from local API must be 0."""
        space_items = [{'capacity': 600 * (1024 ** 4),
                        'space': {'total_physical': 0}}]
        result = _run_detection(space_items)
        assert result['capacity_used_tb'] == 0.0, (
            "Evergreen/One local API returns used = 0; Pure1 API is the authoritative source"
        )
