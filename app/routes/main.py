"""Main dashboard routes"""
from flask import Blueprint, render_template
from app.models import StorageSystem
from app.api import get_client
from concurrent.futures import ThreadPoolExecutor, as_completed

bp = Blueprint('main', __name__)


def fetch_system_status(system):
    """Fetch status for a single system"""
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
