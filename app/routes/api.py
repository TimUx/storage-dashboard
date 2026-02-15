"""API routes for programmatic access"""
from flask import Blueprint, jsonify
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
    """Get status of all enabled systems"""
    systems = StorageSystem.query.filter_by(enabled=True).all()
    
    # Determine optimal number of workers based on system count
    max_workers = min(len(systems), 10) if systems else 1
    
    # Fetch status for all systems in parallel
    systems_status = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(fetch_system_status, system): system for system in systems}
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
    result = fetch_system_status(system)
    return jsonify(result)
