"""Main dashboard routes"""
from flask import Blueprint, render_template, abort, current_app
from app.models import StorageSystem, db
from app.api import get_client
from concurrent.futures import ThreadPoolExecutor, as_completed

bp = Blueprint('main', __name__)


def fetch_system_status(system, app):
    """Fetch status for a single system
    
    Args:
        system: StorageSystem instance
        app: Flask application instance for context
    """
    with app.app_context():
        try:
            # Refresh the system object in this thread's context
            # Using load=False to prevent an unnecessary SELECT query since
            # we already have all the data we need from the original object
            system = db.session.merge(system, load=False)
            
            client = get_client(
                vendor=system.vendor,
                ip_address=system.ip_address,
                port=system.port,
                username=system.api_username,
                password=system.api_password,
                token=system.api_token
            )
            status = client.get_health_status()
            
            # Update OS version and API version if available in status
            if 'os_version' in status and status['os_version']:
                system.os_version = status['os_version']
            if 'api_version' in status and status['api_version']:
                system.api_version = status['api_version']
            
            # Update cluster type if MetroCluster is detected
            if status.get('is_metrocluster') and system.cluster_type != 'metrocluster':
                system.cluster_type = 'metrocluster'
            
            # Update MetroCluster information (for NetApp ONTAP)
            if 'metrocluster_info' in status and status['metrocluster_info']:
                system.set_metrocluster_info(status['metrocluster_info'])
            
            if 'metrocluster_dr_groups' in status and status['metrocluster_dr_groups']:
                system.set_metrocluster_dr_groups(status['metrocluster_dr_groups'])
            
            # Update node details from controllers data (for Pure Storage) or MetroCluster nodes (for NetApp)
            if 'controllers' in status and status['controllers']:
                system.set_node_details(status['controllers'])
                # Also extract all IPs from controllers
                all_ips = set()
                all_ips.add(system.ip_address)
                for ctrl in status['controllers']:
                    if 'ips' in ctrl:
                        all_ips.update(ctrl['ips'])
                system.set_all_ips(list(all_ips))
            
            # Update peer connections from array_connections data (for Pure Storage)
            if 'array_connections' in status and status['array_connections']:
                system.set_peer_connections(status['array_connections'])
            
            # Commit changes to database
            db.session.commit()
            
            return {
                'system': system.to_dict(),
                'status': status
            }
        except Exception as e:
            return {
                'system': system.to_dict(),
                'status': {
                    'status': 'error',
                    'hardware_status': 'unknown',
                    'cluster_status': 'unknown',
                    'alerts': 0,
                    'capacity_total_tb': 0,
                    'capacity_used_tb': 0,
                    'capacity_percent': 0,
                    'error': str(e)
                }
            }


@bp.route('/')
def index():
    """Main dashboard view"""
    systems = StorageSystem.query.filter_by(enabled=True).all()
    
    # Get current app for passing to threads
    app = current_app._get_current_object()
    
    # Determine optimal number of workers based on system count
    max_workers = min(len(systems), 10) if systems else 1
    
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
    
    # Group by vendor
    grouped_systems = {}
    for item in systems_status:
        vendor = item['system']['vendor']
        if vendor not in grouped_systems:
            grouped_systems[vendor] = []
        grouped_systems[vendor].append(item)
    
    vendor_names = {
        'pure': 'Pure Storage',
        'netapp-ontap': 'NetApp ONTAP',
        'netapp-storagegrid': 'NetApp StorageGRID',
        'dell-datadomain': 'Dell DataDomain'
    }
    
    return render_template('dashboard.html', 
                         grouped_systems=grouped_systems,
                         vendor_names=vendor_names)


@bp.route('/systems/<int:system_id>/details')
def system_details(system_id):
    """Detailed view for a single storage system"""
    system = StorageSystem.query.get_or_404(system_id)
    
    # Fetch current status
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
        status = {
            'status': 'error',
            'hardware_status': 'unknown',
            'cluster_status': 'unknown',
            'alerts': 0,
            'capacity_total_tb': 0,
            'capacity_used_tb': 0,
            'capacity_percent': 0,
            'error': str(e)
        }
    
    # Get partner cluster if exists
    partner_cluster = None
    if system.partner_cluster_id:
        partner_cluster = StorageSystem.query.get(system.partner_cluster_id)
    
    return render_template('details.html', 
                         system=system,
                         status=status,
                         partner_cluster=partner_cluster)

