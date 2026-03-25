"""Storage on Demand – daily Pure1 subscription-licence background refresh.

Architecture mirrors ``capacity_service``:
- A single daemon thread runs ``_background_loop`` and calls ``_do_refresh``
  once on startup, then sleeps for ``SOD_REFRESH_INTERVAL_SECONDS``.
- The loop checks for new Pure1 data daily so that the latest weekly data
  point is picked up as soon as Pure1 publishes it.
- If the SodHistory trend data is stale (last entry 7 or more days old), the
  loop retries with a shorter ``SOD_CATCHUP_INTERVAL_SECONDS`` interval until
  the history is up to date again (automatic catch-up / backfill).
- ``trigger_refresh`` spawns a one-shot thread for on-demand refreshes.
- ``get_cached_data`` returns the latest persisted data (no live API call).
"""
import json
import logging
import threading
import traceback
from datetime import datetime, date, timedelta

logger = logging.getLogger(__name__)

# Daily automatic refresh – ensures the latest weekly Pure1 data point is
# picked up within 24 hours of it being published, keeping the SoD trend
# chart up to date without waiting a full week between checks.
SOD_REFRESH_INTERVAL_SECONDS = 24 * 60 * 60  # 24 hours

# Retry interval when SodHistory data is stale (> 7 days old)
SOD_CATCHUP_INTERVAL_SECONDS = 60 * 60  # 1 hour

# Maximum staleness before a backfill is considered necessary (in days)
SOD_STALE_THRESHOLD_DAYS = 7

# How many weeks back to look when there is no history at all (initial import)
SOD_HISTORY_INITIAL_WEEKS = 52

_background_thread_started = False
_thread_lock = threading.Lock()


def _refresh_sod_history(app):
    """Update SodHistory with the latest weekly data, backfilling any missed weeks.

    Determines the most recent date in SodHistory and fetches all data from
    that date through today.  When no history exists at all, the initial
    backfill covers ``SOD_HISTORY_INITIAL_WEEKS`` weeks.

    Must be called within an active Flask application context (e.g. inside a
    ``with app.app_context():`` block).
    """
    from app.capacity_service import import_sod_history_from_pure1
    from app.models import SodHistory

    today = date.today()
    last_entry = SodHistory.query.order_by(SodHistory.date.desc()).first()

    if last_entry is None:
        start_date = today - timedelta(weeks=SOD_HISTORY_INITIAL_WEEKS)
        logger.info(
            "No SoD history found. Backfilling from %s to %s.", start_date, today
        )
    else:
        days_since_last = (today - last_entry.date).days
        if days_since_last <= SOD_STALE_THRESHOLD_DAYS:
            # Already fresh – refresh the current week's data point only.
            start_date = last_entry.date
            logger.debug(
                "SoD history current (last entry: %s, %d day(s) ago). Refreshing current week.",
                last_entry.date, days_since_last,
            )
        else:
            # Stale – backfill from the last known date.
            start_date = last_entry.date
            logger.info(
                "SoD history stale (last entry: %s, %d day(s) ago). Backfilling to today.",
                last_entry.date, days_since_last,
            )

    try:
        imported, skipped, errors = import_sod_history_from_pure1(start_date, today)
        logger.info(
            "SoD history refresh: %d imported, %d skipped, %d error(s).",
            imported, skipped, len(errors),
        )
        if errors:
            logger.warning("SoD history import errors (first 5): %s", errors[:5])
    except Exception as exc:
        logger.error("SoD history refresh failed: %s", exc)


def _is_sod_history_stale(app) -> bool:
    """Return True when the most recent SodHistory entry is older than the stale threshold."""
    try:
        from app.models import SodHistory
        with app.app_context():
            last_entry = SodHistory.query.order_by(SodHistory.date.desc()).first()
            if last_entry is None:
                return True
            return (date.today() - last_entry.date).days >= SOD_STALE_THRESHOLD_DAYS
    except Exception:
        return False


def _do_refresh(app):
    """Fetch subscription licences from Pure1 and persist them in the cache table.

    Also updates the SodHistory trend table, with automatic backfill for any
    weeks that were missed (e.g. due to previous API or network errors).
    """
    from app import db
    from app.models import AppSettings, SubscriptionLicenseCache
    from app.api.pure1_client import fetch_subscription_licenses

    with app.app_context():
        settings = AppSettings.query.first()
        if not settings or not settings.pure1_app_id or not settings.pure1_private_key:
            logger.info("SoD refresh skipped – Pure1 credentials not configured.")
            return

        error_msg = None
        items = []
        try:
            items = fetch_subscription_licenses(
                settings.pure1_app_id,
                settings.pure1_private_key,
                passphrase=settings.pure1_private_key_passphrase,
                proxies=settings.get_proxies() or None,
            )
        except Exception as exc:
            logger.error("SoD refresh failed: %s", exc)
            error_msg = str(exc)

        cache = SubscriptionLicenseCache.query.first()
        if cache is None:
            cache = SubscriptionLicenseCache()
            db.session.add(cache)
        cache.fetched_at = datetime.utcnow()
        cache.data = json.dumps(items)
        cache.error = error_msg

        try:
            db.session.commit()
            logger.info("SoD cache updated: %d licence(s).", len(items))
        except Exception as exc:
            logger.error("Failed to commit SoD cache: %s", exc)
            db.session.rollback()

        # Update SodHistory (trend chart) – includes backfill for any missed weeks.
        _refresh_sod_history(app)


def _background_loop(app):
    import time
    while True:
        try:
            _do_refresh(app)
        except Exception as exc:
            logger.error(
                "Unhandled error in SoD background refresh: %s\n%s",
                exc,
                traceback.format_exc(),
            )

        # Use a shorter retry interval when SodHistory is still stale so that
        # missed weeks are caught up as quickly as possible.
        if _is_sod_history_stale(app):
            logger.info(
                "SoD history still stale after refresh – retrying in %ds.",
                SOD_CATCHUP_INTERVAL_SECONDS,
            )
            time.sleep(SOD_CATCHUP_INTERVAL_SECONDS)
        else:
            time.sleep(SOD_REFRESH_INTERVAL_SECONDS)


def start_background_refresh(app):
    """Start the daily SoD background-refresh thread (idempotent)."""
    global _background_thread_started
    with _thread_lock:
        if _background_thread_started:
            return
        thread = threading.Thread(
            target=_background_loop,
            args=(app,),
            daemon=True,
            name="sod-refresh",
        )
        thread.start()
        _background_thread_started = True
        logger.info(
            "SoD background refresh thread started (interval=%ds / daily).",
            SOD_REFRESH_INTERVAL_SECONDS,
        )


def trigger_refresh(app):
    """Trigger an immediate non-blocking SoD refresh in a one-shot thread."""
    t = threading.Thread(
        target=_do_refresh, args=(app,), daemon=True, name="sod-refresh-manual"
    )
    t.start()


def get_cached_data() -> dict:
    """Return the latest cached SoD data.

    Returns:
        dict with keys ``items`` (list), ``fetched_at`` (ISO string or None),
        ``error`` (string or None).
    """
    from app.models import SubscriptionLicenseCache

    cache = SubscriptionLicenseCache.query.first()
    if cache is None:
        return {"items": [], "fetched_at": None, "error": None}

    items = []
    if cache.data:
        try:
            items = json.loads(cache.data)
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    return {
        "items": items,
        "fetched_at": cache.fetched_at.isoformat() if cache.fetched_at else None,
        "error": cache.error,
    }
