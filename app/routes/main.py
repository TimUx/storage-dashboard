"""Main dashboard routes"""
from flask import Blueprint, render_template, abort, current_app
from app.models import StorageSystem, db
from app.api import get_client
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import traceback

bp = Blueprint('main', __name__)
logger = logging.getLogger(__name__)


def extract_ips_from_mgmt_ips(all_mgmt_ips, system_name, system_ip):
    """Extract IP addresses from all_mgmt_ips data structure
    
    Handles both dict format with 'ip' and 'dns_names' keys and legacy string format.
    
    Args:
        all_mgmt_ips: List of management IP information (dicts or strings)
        system_name: System name for logging
        system_ip: System IP for logging
    
    Returns:
        Set of IP address strings
    """
    ips = set()
    
    if not isinstance(all_mgmt_ips, (list, tuple)):
        logger.warning(f"Unexpected type for all_mgmt_ips on {system_name} ({system_ip}): "
                     f"{type(all_mgmt_ips).__name__}, value: {str(all_mgmt_ips)[:100]}")
        return ips
    
    for mgmt_ip_info in all_mgmt_ips:
        if isinstance(mgmt_ip_info, dict) and 'ip' in mgmt_ip_info:
            ips.add(mgmt_ip_info['ip'])
        elif isinstance(mgmt_ip_info, str):
            # Fallback for backward compatibility if it's just a string
            ips.add(mgmt_ip_info)
        else:
            # Unexpected item type within the list
            logger.warning(f"Unexpected item type in all_mgmt_ips for {system_name} ({system_ip}): "
                         f"{type(mgmt_ip_info).__name__}, value: {str(mgmt_ip_info)[:100]}")
    
    return ips



def fetch_system_status(system, app):
    """Fetch status for a single system
    
    Args:
        system: StorageSystem instance
        app: Flask application instance for context
    """
    from app.system_logging import log_system_event
    
    with app.app_context():
        try:
            # Refresh the system object in this thread's context
            # Using load=False to prevent an unnecessary SELECT query since
            # we already have all the data we need from the original object
            system = db.session.merge(system, load=False)
            
            # Log connection attempt
            log_system_event(
                system_id=system.id,
                level='INFO',
                category='connection',
                message=f'Attempting to connect to {system.name} ({system.ip_address})'
            )
            
            client = get_client(
                vendor=system.vendor,
                ip_address=system.ip_address,
                port=system.port,
                username=system.api_username,
                password=system.api_password,
                token=system.api_token
            )
            status = client.get_health_status()
            
            # Check if there was an error
            if status.get('error'):
                log_system_event(
                    system_id=system.id,
                    level='ERROR' if status.get('status') == 'error' else 'WARNING',
                    category='api_call',
                    message=f'Error retrieving status: {status.get("error")}',
                    status_code=None
                )
            else:
                log_system_event(
                    system_id=system.id,
                    level='INFO',
                    category='data_query',
                    message=f'Successfully retrieved status for {system.name}'
                )
            
            
            # Update OS version and API version if available in status
            if 'os_version' in status and status['os_version']:
                system.os_version = status['os_version']
            if 'api_version' in status and status['api_version']:
                system.api_version = status['api_version']
            
            # Update API token if a new one was generated (for StorageGRID)
            if 'new_api_token' in status and status['new_api_token']:
                system.api_token = status['new_api_token']
                log_system_event(
                    system_id=system.id,
                    level='INFO',
                    category='authentication',
                    message=f'Auto-generated new API token for {system.name}'
                )
            
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
            
            # Update all management IPs if available (for Pure Storage)
            if 'all_mgmt_ips' in status and status['all_mgmt_ips']:
                # Merge with existing IPs
                all_ips = set(system.get_all_ips() or [])
                all_ips.add(system.ip_address)
                
                # Extract IP addresses using helper function
                mgmt_ips = extract_ips_from_mgmt_ips(
                    status['all_mgmt_ips'],
                    system.name,
                    system.ip_address
                )
                all_ips.update(mgmt_ips)
                
                # Save the merged IPs
                system.set_all_ips(list(all_ips))
            
            # Update site count if available
            if 'site_count' in status and status['site_count'] is not None:
                system.site_count = status['site_count']
                # For StorageGRID, update cluster type based on site count
                if system.vendor == 'netapp-storagegrid' and system.site_count > 0:
                    if system.site_count > 1:
                        system.cluster_type = 'multi-site'
                    else:  # site_count == 1 (since we validated site_count > 0)
                        system.cluster_type = 'single-site'
            
            # Update cluster type based on ActiveCluster detection (for Pure Storage)
            if status.get('is_active_cluster') and system.cluster_type != 'active-cluster':
                system.cluster_type = 'active-cluster'
            
            # Commit changes to database
            db.session.commit()
            
            return {
                'system': system.to_dict(),
                'status': status
            }
        except Exception as e:
            logger.error(f"Error fetching status for {system.name} ({system.ip_address}): {e}")
            logger.error(traceback.format_exc())
            
            # Log the error to database
            from app.system_logging import log_system_event
            log_system_event(
                system_id=system.id,
                level='ERROR',
                category='connection',
                message=f'Exception while fetching status: {str(e)}',
                details=traceback.format_exc()
            )
            
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
    
    vendor_names = {
        'pure': 'Pure Storage',
        'netapp-ontap': 'NetApp ONTAP',
        'netapp-storagegrid': 'NetApp StorageGRID',
        'dell-datadomain': 'Dell DataDomain'
    }
    
    # Define fixed vendor order
    vendor_order = ['pure', 'netapp-ontap', 'netapp-storagegrid', 'dell-datadomain']
    
    return render_template('dashboard.html', 
                         grouped_systems=grouped_systems,
                         vendor_names=vendor_names,
                         vendor_order=vendor_order)


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
        logger.error(f"Error getting health status for {system.name} ({system.ip_address}): {e}")
        logger.error(traceback.format_exc())
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

