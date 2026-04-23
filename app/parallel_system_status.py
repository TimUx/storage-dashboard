"""Parallel execution of per-system status fetches (shared by API and background service)."""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

MAX_PARALLEL_WORKERS = 32


def fetch_system_status_parallel(systems, app, fetch_system_status, *, log_failures=False):
    """Call ``fetch_system_status(system, app)`` for each storage system with a thread pool.

    Args:
        systems: Iterable of ``StorageSystem`` ORM instances.
        app: Flask application object to pass through to *fetch_system_status*.
        fetch_system_status: Callable ``(system, app) -> dict`` (same shape as route helper).
        log_failures: When true, log a full exception traceback for each failed system.

    Returns:
        List of result dicts (each containing ``system`` and ``status`` keys).
    """
    systems = list(systems)
    if not systems:
        return []

    max_workers = min(len(systems), MAX_PARALLEL_WORKERS)
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(fetch_system_status, system, app): system for system in systems}
        for future in as_completed(futures):
            system = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:
                if log_failures:
                    logger.exception("Status refresh failed for %s", system.name)
                results.append({
                    'system': system.to_dict(),
                    'status': {'status': 'error', 'error': str(exc)},
                })
    return results
