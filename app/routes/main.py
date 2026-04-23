"""Main dashboard routes"""
import json as _json
import logging
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Blueprint, current_app, jsonify, render_template

from app.api import get_client
from app.models import CapacitySnapshot, StatusCache, StorageSystem, TagGroup
from app.services.system_status import fetch_system_status

bp = Blueprint('main', __name__)
logger = logging.getLogger(__name__)


@bp.route('/health')
def health_liveness():
    """Liveness für Load Balancer / Kubernetes (keine DB-Abfrage)."""
    return jsonify({'status': 'ok', 'service': 'storage-dashboard'})


@bp.route('/')
def root():
    """Redirect root URL to /dashboard."""
    from flask import redirect
    return redirect('/dashboard')


@bp.route('/dashboard')
def index():
    """Main dashboard view - returns HTML with empty dashboard for async loading"""
    from flask import request

    # Check if client-side async loading should be used (AJAX-based data fetching)
    # This is different from Python async/await - it controls whether the template
    # renders with data (sync) or loads data via JavaScript/AJAX (async)
    async_load = request.args.get('async', 'true').lower() == 'true'

    systems = StorageSystem.query.filter_by(enabled=True).all()
    tag_groups = TagGroup.query.order_by(TagGroup.name).all()

    vendor_names = {
        'pure': 'Pure Storage',
        'netapp-ontap': 'NetApp ONTAP',
        'netapp-storagegrid': 'NetApp StorageGRID',
        'dell-datadomain': 'Dell DataDomain'
    }

    # Define fixed vendor order
    vendor_order = ['pure', 'netapp-ontap', 'netapp-storagegrid', 'dell-datadomain']

    if async_load:
        # Return empty dashboard for async loading
        # Group systems by vendor for structure (but without status data)
        grouped_systems = {}
        for system in systems:
            vendor = system.vendor
            if vendor not in grouped_systems:
                grouped_systems[vendor] = []
            grouped_systems[vendor].append({
                'system': system.to_dict(),
                'status': None  # Will be loaded asynchronously
            })

        # Sort systems alphabetically within each vendor group
        for vendor in grouped_systems:
            grouped_systems[vendor].sort(key=lambda x: x['system']['name'].lower())

        return render_template('dashboard.html',
                             grouped_systems=grouped_systems,
                             vendor_names=vendor_names,
                             vendor_order=vendor_order,
                             tag_groups=tag_groups,
                             async_load=True)
    else:
        # Legacy synchronous mode - fetch all data before rendering
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
                    logger.error(f"Error in thread fetching status for {system.name} ({system.ip_address}): {e}")
                    logger.error(traceback.format_exc())
                    systems_status.append({
                        'system': system.to_dict(),
                        'status': {
                            'status': 'error',
                            'error': str(e)
                        }
                    })

        # Group by vendor
        grouped_systems = {}
        for item in systems_status:
            vendor = item['system']['vendor']
            if vendor not in grouped_systems:
                grouped_systems[vendor] = []
            grouped_systems[vendor].append(item)

        # Sort systems alphabetically within each vendor group
        for vendor in grouped_systems:
            grouped_systems[vendor].sort(key=lambda x: x['system']['name'].lower())

        return render_template('dashboard.html',
                             grouped_systems=grouped_systems,
                             vendor_names=vendor_names,
                             vendor_order=vendor_order,
                             tag_groups=tag_groups,
                             async_load=False)


@bp.route('/systems/<int:system_id>/details')
def system_details(system_id):
    """Detailed view for a single storage system"""
    system = StorageSystem.query.get_or_404(system_id)
    status_from_cache = False

    # Fetch current status via live API call
    try:
        client = get_client(
            vendor=system.vendor,
            ip_address=system.ip_address,
            port=system.port,
            username=system.api_username,
            password=system.api_password,
            token=system.api_token
        )
        status = client.get_health_status()
    except Exception as e:
        logger.error(f"Error getting health status for {system.name} ({system.ip_address}): {e}")
        logger.error(traceback.format_exc())
        status = {'status': 'error', 'hardware_status': 'unknown', 'cluster_status': 'unknown',
                  'alerts': 0, 'capacity_total_tb': 0, 'capacity_used_tb': 0,
                  'capacity_percent': 0, 'error': str(e)}

    # When the live call fails or returns an error, fall back to the cached status
    # so the page still shows meaningful information (capacity, last-known health, alerts).
    if status.get('status') == 'error' or status.get('error'):
        cache = StatusCache.query.filter_by(system_id=system.id).first()
        if cache and cache.status_json:
            try:
                cached = _json.loads(cache.status_json)
                if cached.get('status') == 'online':
                    # Preserve the original error so the warning banner is shown
                    live_error = status.get('error')
                    status = cached
                    status['_live_error'] = live_error
                    status_from_cache = True
                    logger.info(f"Using cached status for {system.name} ({system.ip_address})")
            except Exception as cache_err:
                logger.warning(f"Failed to parse cached status for {system.name}: {cache_err}")

    # Override capacity values with Pure1-corrected data from CapacitySnapshot
    # when available and when the status fetch succeeded.  The hourly capacity
    # refresh supplements local array values with Pure1 physical-used figures,
    # which is the authoritative source for Evergreen One arrays.
    snap = CapacitySnapshot.query.filter_by(system_id=system.id).first()
    if snap and snap.total_tb > 0:
        status['capacity_total_tb'] = snap.total_tb
        status['capacity_used_tb'] = snap.used_tb
        status['capacity_percent'] = snap.percent_used

    # Get partner cluster if exists
    partner_cluster = None
    if system.partner_cluster_id:
        partner_cluster = StorageSystem.query.get(system.partner_cluster_id)

    return render_template('details.html',
                           system=system,
                           status=status,
                           status_from_cache=status_from_cache,
                           partner_cluster=partner_cluster)

