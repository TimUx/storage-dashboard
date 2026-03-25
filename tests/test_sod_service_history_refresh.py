"""Tests for the SoD history backfill / catch-up logic in app/sod_service.py.

Verifies that:
1. ``_refresh_sod_history`` fetches the initial year of history when no
   SodHistory rows exist.
2. When history is stale (last entry > 7 days ago), it backfills from the
   last known date to today.
3. When history is fresh (last entry ≤ 7 days ago), it only refreshes the
   current week's data point.
4. ``_is_sod_history_stale`` correctly identifies stale / fresh history.
5. ``_background_loop`` sleeps for the short catch-up interval when history
   is stale, and for the full weekly interval when history is fresh.
"""

import os
from datetime import date, timedelta
from unittest.mock import MagicMock, call, patch

import pytest


# ---------------------------------------------------------------------------
# Lightweight test-app fixture (no background threads)
# ---------------------------------------------------------------------------

@pytest.fixture()
def app():
    """Flask test app backed by an in-memory SQLite database."""

    def _no_op(*a, **kw):
        pass

    patches = [
        patch('app.capacity_service.start_background_refresh', _no_op),
        patch('app.sod_service.start_background_refresh', _no_op),
        patch('app.status_service.start_background_refresh', _no_op),
    ]
    for p in patches:
        p.start()

    os.environ.setdefault('SECRET_KEY', 'test-secret')
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
# Helpers
# ---------------------------------------------------------------------------

def _seed_sod_history(app_ctx, last_date: date):
    """Insert a single SodHistory row with the given date."""
    from app import db
    from app.models import SodHistory

    row = SodHistory(
        date=last_date,
        subscription_name="TEST-SUB",
        license_name="TEST-LIC",
        reserved_tb=10.0,
        effective_used_tb=5.0,
        on_demand_tb=0.0,
    )
    db.session.add(row)
    db.session.commit()


# ---------------------------------------------------------------------------
# _is_sod_history_stale
# ---------------------------------------------------------------------------

class TestIsSodHistoryStale:
    def test_stale_when_no_history(self, app_ctx):
        from app.sod_service import _is_sod_history_stale
        assert _is_sod_history_stale(app_ctx) is True

    def test_stale_when_last_entry_older_than_threshold(self, app_ctx):
        from app.sod_service import _is_sod_history_stale, SOD_STALE_THRESHOLD_DAYS

        old_date = date.today() - timedelta(days=SOD_STALE_THRESHOLD_DAYS + 1)
        _seed_sod_history(app_ctx, old_date)
        assert _is_sod_history_stale(app_ctx) is True

    def test_not_stale_when_last_entry_within_threshold(self, app_ctx):
        from app.sod_service import _is_sod_history_stale, SOD_STALE_THRESHOLD_DAYS

        recent_date = date.today() - timedelta(days=SOD_STALE_THRESHOLD_DAYS - 1)
        _seed_sod_history(app_ctx, recent_date)
        assert _is_sod_history_stale(app_ctx) is False

    def test_stale_when_last_entry_exactly_at_threshold(self, app_ctx):
        from app.sod_service import _is_sod_history_stale, SOD_STALE_THRESHOLD_DAYS

        # days == threshold: STALE (>= threshold), so the catch-up loop is triggered
        # rather than waiting another full normal interval before retrying.
        threshold_date = date.today() - timedelta(days=SOD_STALE_THRESHOLD_DAYS)
        _seed_sod_history(app_ctx, threshold_date)
        assert _is_sod_history_stale(app_ctx) is True


# ---------------------------------------------------------------------------
# _refresh_sod_history – start_date calculation
# ---------------------------------------------------------------------------

class TestRefreshSodHistoryStartDate:
    """_refresh_sod_history must derive the correct start_date for import."""

    def _run_refresh(self, app_ctx):
        """Call _refresh_sod_history inside the app context with patched import."""
        today = date.today()
        with patch('app.capacity_service.import_sod_history_from_pure1') as mock_import:
            mock_import.return_value = (0, 0, [])
            from app.sod_service import _refresh_sod_history
            _refresh_sod_history(app_ctx)
            return mock_import, today

    def test_no_history_uses_initial_weeks_lookback(self, app_ctx):
        from app.sod_service import SOD_HISTORY_INITIAL_WEEKS

        mock_import, today = self._run_refresh(app_ctx)
        mock_import.assert_called_once()
        called_start, called_end = mock_import.call_args[0]
        expected_start = today - timedelta(weeks=SOD_HISTORY_INITIAL_WEEKS)
        assert called_start == expected_start
        assert called_end == today

    def test_stale_history_backfills_from_last_entry(self, app_ctx):
        from app.sod_service import SOD_STALE_THRESHOLD_DAYS

        last_date = date.today() - timedelta(days=SOD_STALE_THRESHOLD_DAYS + 7)
        _seed_sod_history(app_ctx, last_date)

        mock_import, today = self._run_refresh(app_ctx)
        mock_import.assert_called_once()
        called_start, called_end = mock_import.call_args[0]
        assert called_start == last_date
        assert called_end == today

    def test_fresh_history_refreshes_from_last_entry(self, app_ctx):
        from app.sod_service import SOD_STALE_THRESHOLD_DAYS

        last_date = date.today() - timedelta(days=SOD_STALE_THRESHOLD_DAYS - 1)
        _seed_sod_history(app_ctx, last_date)

        mock_import, today = self._run_refresh(app_ctx)
        mock_import.assert_called_once()
        called_start, called_end = mock_import.call_args[0]
        # Fresh: start = last_entry.date (refresh current week)
        assert called_start == last_date
        assert called_end == today


# ---------------------------------------------------------------------------
# _background_loop – adaptive sleep interval
# ---------------------------------------------------------------------------

class TestBackgroundLoopSleepInterval:
    """The loop must sleep for the catch-up interval when history is stale."""

    def test_sleeps_catchup_interval_when_stale(self, app_ctx):
        from app.sod_service import SOD_CATCHUP_INTERVAL_SECONDS

        call_count = [0]

        def fake_do_refresh(app):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise SystemExit("stop loop")

        def fake_is_stale(app):
            return True

        sleep_calls = []

        with patch('app.sod_service._do_refresh', fake_do_refresh), \
             patch('app.sod_service._is_sod_history_stale', fake_is_stale), \
             patch('time.sleep', side_effect=lambda s: sleep_calls.append(s)):
            from app.sod_service import _background_loop
            try:
                _background_loop(app_ctx)
            except SystemExit:
                pass

        assert sleep_calls[0] == SOD_CATCHUP_INTERVAL_SECONDS

    def test_sleeps_weekly_interval_when_fresh(self, app_ctx):
        from app.sod_service import SOD_REFRESH_INTERVAL_SECONDS

        call_count = [0]

        def fake_do_refresh(app):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise SystemExit("stop loop")

        def fake_is_stale(app):
            return False

        sleep_calls = []

        with patch('app.sod_service._do_refresh', fake_do_refresh), \
             patch('app.sod_service._is_sod_history_stale', fake_is_stale), \
             patch('time.sleep', side_effect=lambda s: sleep_calls.append(s)):
            from app.sod_service import _background_loop
            try:
                _background_loop(app_ctx)
            except SystemExit:
                pass

        assert sleep_calls[0] == SOD_REFRESH_INTERVAL_SECONDS


# ---------------------------------------------------------------------------
# _do_refresh – history update is called
# ---------------------------------------------------------------------------

class TestDoRefreshCallsHistory:
    """_do_refresh must call _refresh_sod_history after updating the cache."""

    def test_refresh_sod_history_called_when_credentials_set(self, app_ctx):
        from app import db
        from app.models import AppSettings

        with app_ctx.app_context():
            settings = AppSettings(
                pure1_app_id="test-app-id",
                pure1_private_key="test-key",
            )
            db.session.add(settings)
            db.session.commit()

        with patch('app.api.pure1_client.fetch_subscription_licenses', return_value=[]), \
             patch('app.sod_service._refresh_sod_history') as mock_hist:
            from app.sod_service import _do_refresh
            _do_refresh(app_ctx)

        mock_hist.assert_called_once_with(app_ctx)

    def test_history_not_called_when_no_credentials(self, app_ctx):
        # No AppSettings row → credentials not configured
        with patch('app.sod_service._refresh_sod_history') as mock_hist:
            from app.sod_service import _do_refresh
            _do_refresh(app_ctx)

        mock_hist.assert_not_called()
