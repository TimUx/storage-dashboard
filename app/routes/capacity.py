"""Capacity Report routes – /capacity/"""
import logging
from flask import Blueprint, render_template, jsonify, request, current_app

bp = Blueprint('capacity', __name__, url_prefix='/capacity')
logger = logging.getLogger(__name__)


@bp.route('/')
def index():
    """Capacity report main page."""
    from app.models import AppSettings
    settings = AppSettings.query.first()
    pure1_configured = bool(settings and settings.pure1_app_id and settings.pure1_private_key)
    return render_template('capacity.html', pure1_configured=pure1_configured)


@bp.route('/api/data')
def api_data():
    """Return aggregated capacity data for all views as JSON."""
    from app.models import StorageSystem
    from app.capacity_service import (
        get_latest_snapshots,
        build_by_storage_art,
        build_by_environment,
        build_by_department,
        build_details,
    )

    systems = StorageSystem.query.filter_by(enabled=True).all()
    snapshots = get_latest_snapshots()

    # Determine staleness: is any snapshot older than 1 hour?
    from datetime import datetime, timedelta
    now = datetime.utcnow()
    stale = not snapshots or any(
        (now - s.fetched_at).total_seconds() > 3600
        for s in snapshots.values()
    )

    # Compute the most-recent fetched_at by comparing datetime objects, then ISO-format it
    last_dt = max((s.fetched_at for s in snapshots.values()), default=None) if snapshots else None

    return jsonify({
        'stale': stale,
        'last_updated': last_dt.isoformat() if last_dt else None,
        'by_storage_art': build_by_storage_art(systems, snapshots),
        'by_environment': build_by_environment(systems, snapshots),
        'by_department': build_by_department(systems, snapshots),
        'details': build_details(systems, snapshots),
    })


@bp.route('/api/history')
def api_history():
    """Return historical capacity data for chart rendering."""
    from app.capacity_service import get_history_data, compute_forecast

    range_param = request.args.get('range', 'all')
    days_map = {'3m': 90, '6m': 180, '1y': 365, '2y': 730}
    days = days_map.get(range_param)

    history = get_history_data(days=days)

    # Attach forecast to each storage art
    for art, art_data in history.items():
        fc = compute_forecast(art_data['labels'], art_data['used'], forecast_days=90)
        art_data['forecast_labels'] = fc['labels']
        art_data['forecast_values'] = fc['values']

    return jsonify(history)


@bp.route('/api/subscription-licenses')
def api_subscription_licenses():
    """Return Pure1 subscription-license data from the local cache (Storage on Demand)."""
    from app.models import AppSettings
    from app.sod_service import get_cached_data

    settings = AppSettings.query.first()
    configured = bool(settings and settings.pure1_app_id and settings.pure1_private_key)
    if not configured:
        return jsonify({
            'configured': False,
            'items': [],
            'fetched_at': None,
            'error': 'Pure1 API-Zugangsdaten nicht konfiguriert.',
        })

    data = get_cached_data()
    data['configured'] = True
    return jsonify(data)


@bp.route('/api/sod-refresh', methods=['POST'])
def api_sod_refresh():
    """Trigger an immediate non-blocking SoD data refresh."""
    from app.sod_service import trigger_refresh
    app = current_app._get_current_object()
    trigger_refresh(app)
    return jsonify({'status': 'refresh_triggered'})


@bp.route('/api/refresh', methods=['POST'])
def api_refresh():
    """Trigger an immediate (non-blocking) capacity data refresh."""
    from app.capacity_service import trigger_refresh
    app = current_app._get_current_object()
    trigger_refresh(app)
    return jsonify({'status': 'refresh_triggered'})
