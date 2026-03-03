"""API routes for programmatic access"""
from flask import Blueprint, jsonify, current_app
from app.models import StorageSystem
from app.api import get_client
from app.routes.main import fetch_system_status
from concurrent.futures import ThreadPoolExecutor, as_completed

bp = Blueprint('api', __name__, url_prefix='/api')


@bp.route('/systems')
def list_systems():
    """List all storage systems"""
    systems = StorageSystem.query.all()
    return jsonify([system.to_dict() for system in systems])


@bp.route('/status')
def get_status():
    """Get status of all enabled systems (live – makes real-time API calls to storage systems)"""
    systems = StorageSystem.query.filter_by(enabled=True).all()
    
    # Get current app for passing to threads
    app = current_app._get_current_object()
    
    # Determine optimal number of workers based on system count
    # Support 16-32 systems in parallel as requested
    max_workers = min(len(systems), 32) if systems else 1
    
    # Fetch status for all systems in parallel
    systems_status = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(fetch_system_status, system, app): system for system in systems}
        for future in as_completed(futures):
            try:
                result = future.result()
                systems_status.append(result)
            except Exception as e:
                system = futures[future]
                systems_status.append({
                    'system': system.to_dict(),
                    'status': {
                        'status': 'error',
                        'error': str(e)
                    }
                })
    
    return jsonify(systems_status)


@bp.route('/systems/<int:system_id>/status')
def get_system_status(system_id):
    """Get status of a specific system"""
    system = StorageSystem.query.get_or_404(system_id)
    app = current_app._get_current_object()
    result = fetch_system_status(system, app)
    return jsonify(result)


@bp.route('/cached-status')
def get_cached_status():
    """Return the most recently cached health status for all enabled systems.

    Data is populated by the background refresh service (no live API calls).
    Each entry includes a ``fetched_at`` timestamp so the dashboard can show
    how recent the data is.
    """
    from app.models import StatusCache

    systems = StorageSystem.query.filter_by(enabled=True).all()
    result = []
    for system in systems:
        cache = StatusCache.query.filter_by(system_id=system.id).first()
        if cache:
            result.append({
                'system': system.to_dict(),
                'status': cache.get_status(),
                'fetched_at': cache.fetched_at.isoformat() if cache.fetched_at else None,
            })
        else:
            result.append({
                'system': system.to_dict(),
                'status': None,
                'fetched_at': None,
            })
    return jsonify(result)


@bp.route('/trigger-status-refresh', methods=['POST'])
def trigger_status_refresh():
    """Trigger an immediate status refresh (runs synchronously, returns fresh cached data).

    Useful for the manual-refresh button on the dashboard: the caller waits for
    the refresh to finish and receives up-to-date data in the response.
    """
    from app.status_service import do_refresh_sync
    app = current_app._get_current_object()
    results = do_refresh_sync(app)
    return jsonify(results)

