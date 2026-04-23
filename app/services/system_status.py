"""Abruf und Aktualisierung des Speicher-Systemstatus (ehemals in routes.main)."""
import logging
import traceback

from app import db
from app.api import get_client

logger = logging.getLogger(__name__)


def extract_ips_from_mgmt_ips(all_mgmt_ips, system_name, system_ip):
    """IP-Adressen aus der ``all_mgmt_ips``-Struktur (Pure/DataDomain) extrahieren."""
    ips = set()

    if not isinstance(all_mgmt_ips, (list, tuple)):
        logger.warning(
            'Unexpected type for all_mgmt_ips on %s (%s): %s, value: %s',
            system_name,
            system_ip,
            type(all_mgmt_ips).__name__,
            str(all_mgmt_ips)[:100],
        )
        return ips

    for mgmt_ip_info in all_mgmt_ips:
        if isinstance(mgmt_ip_info, dict):
            ip = mgmt_ip_info.get('ip')
            if not ip:
                ip = mgmt_ip_info.get('ip_address')
            if ip:
                ips.add(ip)
        elif isinstance(mgmt_ip_info, str):
            ips.add(mgmt_ip_info)
        else:
            logger.warning(
                'Unexpected item type in all_mgmt_ips for %s (%s): %s, value: %s',
                system_name,
                system_ip,
                type(mgmt_ip_info).__name__,
                str(mgmt_ip_info)[:100],
            )

    return ips


def fetch_system_status(system, app):
    """Live-Status eines Systems abrufen, DB-Felder aktualisieren, Ergebnisdict liefern.

    Wird von der öffentlichen API, dem Status-Hintergrunddienst und dem
    synchronen Dashboard-Modus genutzt.
    """
    from app.system_logging import log_system_event

    with app.app_context():
        try:
            system = db.session.merge(system, load=False)

            log_system_event(
                system_id=system.id,
                level='INFO',
                category='connection',
                message=f'Attempting to connect to {system.name} ({system.ip_address})',
            )

            client = get_client(
                vendor=system.vendor,
                ip_address=system.ip_address,
                port=system.port,
                username=system.api_username,
                password=system.api_password,
                token=system.api_token,
            )
            status = client.get_health_status()

            if status.get('error'):
                log_system_event(
                    system_id=system.id,
                    level='ERROR' if status.get('status') == 'error' else 'WARNING',
                    category='api_call',
                    message=f'Error retrieving status: {status.get("error")}',
                    status_code=None,
                )
            else:
                log_system_event(
                    system_id=system.id,
                    level='INFO',
                    category='data_query',
                    message=f'Successfully retrieved status for {system.name}',
                )

            if 'os_version' in status and status['os_version']:
                system.os_version = status['os_version']
            if 'api_version' in status and status['api_version']:
                system.api_version = status['api_version']

            if 'new_api_token' in status and status['new_api_token']:
                system.api_token = status['new_api_token']
                log_system_event(
                    system_id=system.id,
                    level='INFO',
                    category='authentication',
                    message=f'Auto-generated new API token for {system.name}',
                )

            if status.get('is_metrocluster') and system.cluster_type != 'metrocluster':
                system.cluster_type = 'metrocluster'

            if 'metrocluster_info' in status and status['metrocluster_info']:
                system.set_metrocluster_info(status['metrocluster_info'])

            if 'metrocluster_dr_groups' in status and status['metrocluster_dr_groups']:
                system.set_metrocluster_dr_groups(status['metrocluster_dr_groups'])

            if 'ha_status' in status and status['ha_status']:
                system.set_ha_info(status['ha_status'])

            if 'controllers' in status and status['controllers']:
                system.set_node_details(status['controllers'])
                all_ips = {system.ip_address}
                for ctrl in status['controllers']:
                    if 'ips' in ctrl:
                        all_ips.update(ctrl['ips'])
                system.set_all_ips(list(all_ips))

            if 'array_connections' in status and status['array_connections']:
                system.set_peer_connections(status['array_connections'])

            if 'all_mgmt_ips' in status and status['all_mgmt_ips']:
                all_ips = set(system.get_all_ips() or [])
                all_ips.add(system.ip_address)
                mgmt_ips = extract_ips_from_mgmt_ips(
                    status['all_mgmt_ips'],
                    system.name,
                    system.ip_address,
                )
                all_ips.update(mgmt_ips)
                system.set_all_ips(list(all_ips))

            if 'site_count' in status and status['site_count'] is not None:
                system.site_count = status['site_count']
                if system.vendor == 'netapp-storagegrid' and system.site_count > 0:
                    if system.site_count > 1:
                        system.cluster_type = 'multi-site'
                    else:
                        system.cluster_type = 'single-site'

            if status.get('is_active_cluster') and system.cluster_type != 'active-cluster':
                system.cluster_type = 'active-cluster'

            db.session.commit()

            return {
                'system': system.to_dict(),
                'status': status,
            }
        except Exception as e:
            logger.error('Error fetching status for %s (%s): %s', system.name, system.ip_address, e)
            logger.error(traceback.format_exc())

            log_system_event(
                system_id=system.id,
                level='ERROR',
                category='connection',
                message=f'Exception while fetching status: {str(e)}',
                details=traceback.format_exc(),
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
                    'error': str(e),
                },
            }
