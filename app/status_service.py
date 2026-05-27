"""Background status refresh service – polls all enabled storage systems and caches results."""
import logging
import socket
import threading
import time
import traceback
from datetime import datetime

logger = logging.getLogger(__name__)

# Default interval in seconds when no setting is configured
DEFAULT_INTERVAL_SECONDS = 5 * 60  # 5 minutes
IP_MONITOR_INTERVAL_SECONDS = 60 * 60  # 1 hour
IP_MONITOR_TIMEOUT_SECONDS = 2.0

# Module-level flag so that only one background thread is started per process
_background_thread_started = False
_thread_lock = threading.Lock()
_single_refresh_lock = threading.Lock()
_single_refresh_in_flight = set()

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


def _is_ip_reachable(ip, port):
    """Check whether *ip:port* is reachable via TCP connect."""
    try:
        with socket.create_connection((ip, int(port)), timeout=IP_MONITOR_TIMEOUT_SECONDS):
            return True
    except Exception:
        return False


def _attach_ip_monitoring(status, system, previous_status=None):
    """Attach hourly management-IP reachability data to the status payload."""
    if not isinstance(status, dict):
        return status

    monitor = {}
    if isinstance(previous_status, dict):
        monitor = dict(previous_status.get('ip_monitor') or {})

    checked_at = monitor.get('checked_at')
    if checked_at:
        try:
            age = max(0, int((datetime.utcnow() - datetime.fromisoformat(checked_at)).total_seconds()))
            if age < IP_MONITOR_INTERVAL_SECONDS:
                status['ip_monitor'] = monitor
                return status
        except Exception:
            pass

    all_ips = list(dict.fromkeys((system.get_all_ips() or []) + [system.ip_address]))
    reachable = []
    unreachable = []
    for ip in all_ips:
        if _is_ip_reachable(ip, system.port or 443):
            reachable.append(ip)
        else:
            unreachable.append(ip)

    status['ip_monitor'] = {
        'checked_at': datetime.utcnow().isoformat(),
        'interval_seconds': IP_MONITOR_INTERVAL_SECONDS,
        'reachable_ips': reachable,
        'unreachable_ips': unreachable,
        'has_unreachable': len(unreachable) > 0,
    }
    return status


def _run_parallel_fetch(systems, app):
    """Fetch status for *systems* in parallel and return a list of result dicts."""
    from app.parallel_system_status import fetch_system_status_parallel
    from app.services.system_status import fetch_system_status

    return fetch_system_status_parallel(
        systems, app, fetch_system_status, log_failures=True,
    )


def _do_refresh(app):
    """Fetch health status for all enabled systems and persist results in StatusCache."""
    from app import db
    from app.models import StatusCache, StorageSystem

    with app.app_context():
        systems = StorageSystem.query.filter_by(enabled=True).all()
        if not systems:
            logger.info("Status refresh: no enabled systems found, skipping.")
            return

        t0 = time.monotonic()
        results = _run_parallel_fetch(systems, app)
        elapsed = time.monotonic() - t0
        now = datetime.utcnow()
        for result in results:
            sys_id = result['system']['id']
            cache = StatusCache.query.filter_by(system_id=sys_id).first()
            prev_status = cache.get_status() if cache else {}
            system = next((s for s in systems if s.id == sys_id), None)
            if system:
                result['status'] = _attach_ip_monitoring(result['status'], system, prev_status)
            _upsert_cache_entry(StatusCache, db, sys_id, result['status'], now)

        try:
            db.session.commit()
            logger.info(
                "Status cache refreshed for %d system(s) in %.2fs.",
                len(results),
                elapsed,
            )
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


def _do_refresh_one_system(app, system_id):
    """Fetch status for one system and upsert its cache entry."""
    from app import db
    from app.models import StatusCache, StorageSystem
    from app.services.system_status import fetch_system_status

    with app.app_context():
        system = StorageSystem.query.filter_by(id=system_id, enabled=True).first()
        if not system:
            logger.debug("Single-system refresh skipped for unknown/disabled system_id=%s", system_id)
            return

        t0 = time.monotonic()
        result = fetch_system_status(system, app)
        now = datetime.utcnow()
        existing = StatusCache.query.filter_by(system_id=system_id).first()
        prev_status = existing.get_status() if existing else {}
        result['status'] = _attach_ip_monitoring(result['status'], system, prev_status)
        _upsert_cache_entry(StatusCache, db, result['system']['id'], result['status'], now)
        try:
            db.session.commit()
            logger.info(
                "Single-system status cache refreshed for %s (%s) in %.2fs.",
                system.name,
                system.ip_address,
                time.monotonic() - t0,
            )
        except Exception as exc:
            logger.error("Failed to commit single-system status cache refresh: %s", exc)
            db.session.rollback()


def trigger_system_refresh(app, system_id):
    """Trigger a non-blocking refresh for exactly one system.

    Returns ``True`` when a new refresh worker was started and ``False`` when
    the same system is already being refreshed.
    """
    with _single_refresh_lock:
        if system_id in _single_refresh_in_flight:
            return False
        _single_refresh_in_flight.add(system_id)

    def _worker():
        try:
            _do_refresh_one_system(app, system_id)
        except Exception as exc:
            logger.error("Unhandled error in single-system status refresh (%s): %s", system_id, exc)
        finally:
            with _single_refresh_lock:
                _single_refresh_in_flight.discard(system_id)

    threading.Thread(
        target=_worker,
        daemon=True,
        name=f"status-refresh-system-{system_id}",
    ).start()
    return True


def do_refresh_sync(app):
    """Run a full status refresh synchronously and return the results.

    Used by the manual-refresh API endpoint so callers receive fresh data
    in the same HTTP response.  The ``fetched_at`` timestamp recorded in the
    cache reflects the moment the DB was committed (not individual fetch times,
    which can vary by system), keeping the cache consistent.
    """
    from app.models import StatusCache, StorageSystem

    with app.app_context():
        systems = StorageSystem.query.filter_by(enabled=True).all()
        if not systems:
            return []

        results = _run_parallel_fetch(systems, app)

        from app import db
        now = datetime.utcnow()
        for result in results:
            sys_id = result['system']['id']
            cache = StatusCache.query.filter_by(system_id=sys_id).first()
            prev_status = cache.get_status() if cache else {}
            system = next((s for s in systems if s.id == sys_id), None)
            if system:
                result['status'] = _attach_ip_monitoring(result['status'], system, prev_status)
            _upsert_cache_entry(StatusCache, db, sys_id, result['status'], now)

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
