"""Background status refresh service – polls all enabled storage systems and caches results."""
import logging
import threading
import traceback
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# Default interval in seconds when no setting is configured
DEFAULT_INTERVAL_SECONDS = 5 * 60  # 5 minutes

# Module-level flag so that only one background thread is started per process
_background_thread_started = False
_thread_lock = threading.Lock()

# Event used to wake the background loop early (e.g. on manual trigger)
_refresh_now_event = threading.Event()


def _get_interval_seconds(app):
    """Return the configured refresh interval in seconds (reads from AppSettings)."""
    try:
        with app.app_context():
            from app.models import AppSettings
            settings = AppSettings.query.first()
            if settings and settings.dashboard_refresh_interval:
                return int(settings.dashboard_refresh_interval) * 60
    except Exception:
        pass
    return DEFAULT_INTERVAL_SECONDS


def _upsert_cache_entry(StatusCache, db, system_id, status, fetched_at):
    """Insert or update a StatusCache row for the given system."""
    cache = StatusCache.query.filter_by(system_id=system_id).first()
    if not cache:
        cache = StatusCache(system_id=system_id)
        db.session.add(cache)
    cache.fetched_at = fetched_at
    cache.set_status(status)
    cache.error = status.get('error')


def _run_parallel_fetch(systems, app):
    """Fetch status for *systems* in parallel and return a list of result dicts."""
    from app.routes.main import fetch_system_status

    max_workers = min(len(systems), 32)
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(fetch_system_status, system, app): system for system in systems}
        for future in as_completed(futures):
            system = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:
                logger.exception("Status refresh failed for %s", system.name)
                results.append({
                    'system': system.to_dict(),
                    'status': {'status': 'error', 'error': str(exc)},
                })
    return results


def _do_refresh(app):
    """Fetch health status for all enabled systems and persist results in StatusCache."""
    from app import db
    from app.models import StorageSystem, StatusCache

    with app.app_context():
        systems = StorageSystem.query.filter_by(enabled=True).all()
        if not systems:
            logger.info("Status refresh: no enabled systems found, skipping.")
            return

        results = _run_parallel_fetch(systems, app)
        now = datetime.utcnow()
        for result in results:
            _upsert_cache_entry(StatusCache, db, result['system']['id'], result['status'], now)

        try:
            db.session.commit()
            logger.info("Status cache refreshed for %d system(s).", len(results))
        except Exception as exc:
            logger.error("Failed to commit status cache: %s", exc)
            db.session.rollback()


def _background_loop(app):
    """Continuously refresh status, sleeping the configured interval between runs."""
    while True:
        try:
            _do_refresh(app)
        except Exception as exc:
            logger.error("Unhandled error in status background refresh: %s\n%s",
                         exc, traceback.format_exc())
        interval = _get_interval_seconds(app)
        # Wait for the interval, but allow early wake-up via _refresh_now_event
        _refresh_now_event.wait(timeout=interval)
        _refresh_now_event.clear()


def start_background_refresh(app):
    """Start the background status refresh thread (idempotent – safe to call multiple times)."""
    global _background_thread_started
    with _thread_lock:
        if _background_thread_started:
            return
        thread = threading.Thread(
            target=_background_loop,
            args=(app,),
            daemon=True,
            name="status-refresh",
        )
        thread.start()
        _background_thread_started = True
        logger.info("Status background refresh thread started (default interval=%ds).",
                    DEFAULT_INTERVAL_SECONDS)


def trigger_refresh(app):
    """Signal the background loop to run a refresh immediately (non-blocking).

    If the background thread has not been started yet, runs the refresh directly
    in a new daemon thread.
    """
    if _background_thread_started:
        _refresh_now_event.set()
    else:
        t = threading.Thread(
            target=_do_refresh,
            args=(app,),
            daemon=True,
            name="status-refresh-manual",
        )
        t.start()


def do_refresh_sync(app):
    """Run a full status refresh synchronously and return the results.

    Used by the manual-refresh API endpoint so callers receive fresh data
    in the same HTTP response.  The ``fetched_at`` timestamp recorded in the
    cache reflects the moment the DB was committed (not individual fetch times,
    which can vary by system), keeping the cache consistent.
    """
    from app.models import StorageSystem, StatusCache

    with app.app_context():
        systems = StorageSystem.query.filter_by(enabled=True).all()
        if not systems:
            return []

        results = _run_parallel_fetch(systems, app)

        from app import db
        now = datetime.utcnow()
        for result in results:
            _upsert_cache_entry(StatusCache, db, result['system']['id'], result['status'], now)

        try:
            db.session.commit()
        except Exception as exc:
            logger.error("Failed to commit status cache (sync refresh): %s", exc)
            db.session.rollback()

        # Also wake background thread so it resets its sleep timer
        _refresh_now_event.set()

        return [
            {
                'system': r['system'],
                'status': r['status'],
                'fetched_at': now.isoformat(),
            }
            for r in results
        ]
