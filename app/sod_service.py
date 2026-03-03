"""Storage on Demand – weekly Pure1 subscription-licence background refresh.

Architecture mirrors ``capacity_service``:
- A single daemon thread runs ``_background_loop`` and calls ``_do_refresh``
  once on startup, then sleeps for ``SOD_REFRESH_INTERVAL_SECONDS``.
- ``trigger_refresh`` spawns a one-shot thread for on-demand refreshes.
- ``get_cached_data`` returns the latest persisted data (no live API call).
"""
import json
import logging
import threading
import traceback
from datetime import datetime

logger = logging.getLogger(__name__)

# Weekly automatic refresh
SOD_REFRESH_INTERVAL_SECONDS = 7 * 24 * 60 * 60

_background_thread_started = False
_thread_lock = threading.Lock()


def _do_refresh(app):
    """Fetch subscription licences from Pure1 and persist them in the cache table."""
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
        time.sleep(SOD_REFRESH_INTERVAL_SECONDS)


def start_background_refresh(app):
    """Start the weekly SoD background-refresh thread (idempotent)."""
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
            "SoD background refresh thread started (interval=%ds).",
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
