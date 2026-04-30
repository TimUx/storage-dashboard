"""Kurzzeit-Cache für die Navbar-Alertanzahl (weniger DB/CPU pro Template-Render)."""
from __future__ import annotations

import threading
import time

_lock = threading.Lock()
_cached_value = 0
_cached_at = 0.0

_DEFAULT_TTL = 30.0


def invalidate_open_alerts_count_cache() -> None:
    """Navbar-Zähler nach Alert-State-Änderungen sofort neu berechnen."""
    global _cached_at
    with _lock:
        _cached_at = 0.0


def get_open_alerts_count_cached() -> int:
    """Liefert die Anzahl nicht bestätigter Alerts; Ergebnis bis zu *TTL* Sekunden gecacht."""
    ttl = _DEFAULT_TTL
    if ttl <= 0:
        return _compute_count()

    global _cached_value, _cached_at
    now = time.monotonic()
    with _lock:
        if now - _cached_at < ttl:
            return _cached_value
        _cached_value = _compute_count()
        _cached_at = now
        return _cached_value


def _compute_count() -> int:
    from app.routes.alerts import collect_alerts

    alerts = collect_alerts()
    return sum(1 for a in alerts if not a.get('acknowledged', False))
