"""API clients for different storage vendors"""
from app.api.base_client import StorageClient
from app.discovery import reverse_dns_lookup
from app.ssl_utils import get_ssl_verify, is_ip_address
from app.constants import VENDOR_DEFAULT_PORTS
from flask import current_app
import requests
import warnings
import logging
import re
import traceback

logger = logging.getLogger(__name__)

# Maximum length of response text to log (to avoid flooding logs with large responses)
MAX_RESPONSE_LOG_LENGTH = 500

# StorageGRID API health state constants
# States that indicate a healthy grid/node
STORAGEGRID_HEALTHY_GRID_STATES = {'healthy', 'ok', 'normal'}

# Node states that indicate a healthy/connected node
STORAGEGRID_HEALTHY_NODE_STATES = {'connected', 'online', 'ok', 'healthy'}

# Alert states that are considered active/unresolved
# Based on StorageGRID API v4 alert states
STORAGEGRID_ACTIVE_ALERT_STATES = {'active', 'triggered', 'firing'}


# Suppress SSL warnings only when verification is disabled
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


def extract_field_with_fallbacks(data, field_names):
    """
    Helper function to extract a field value from data dictionary
    trying multiple possible field names.
    
    Args:
        data: Dictionary to search
        field_names: List of field names to try in order
    
    Returns:
        First non-None value found, or None if none found
    """
    if not data:
        return None
    
    for field_name in field_names:
        # Handle nested field names like 'version.full'
        if '.' in field_name:
            parts = field_name.split('.')
            value = data
            for part in parts:
                if value and isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = None
                    break
            if value:
                return value
        else:
            # Simple field name
            value = data.get(field_name)
            if value:
                return value
    
    return None


class PureStorageClient(StorageClient):
    """Pure Storage FlashArray client using REST API"""
    
    # FlashArray REST API version (will be detected dynamically)
    API_VERSION = '2.4'
    
    def detect_api_version(self):
        """Detect the API version supported by the FlashArray"""
        try:
            ssl_verify = get_ssl_verify(self.resolved_address)
            
            # Query api_version endpoint
            response = requests.get(
                f"{self.base_url}/api/api_version",
                verify=ssl_verify,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                # Get the latest supported version
                versions = data.get('version', [])
                if versions:
                    # Return the latest version (usually last in the list)
                    latest_version = versions[-1] if isinstance(versions, list) else versions
                    logger.info(f"Detected Pure Storage API version: {latest_version}")
                    return latest_version
        except Exception as e:
            logger.warning(f"Could not detect API version for {self.ip_address}: {e}")
        
        # Return default version if detection fails
        return self.API_VERSION
    
    def authenticate(self, api_version):
        """Authenticate and get session token for API 2.x
        
        For Pure Storage FlashArray API 2.x, authentication requires:
        1. POST to /api/2.x/login with api-token in request header
        2. Receive x-auth-token in response header
        3. Use x-auth-token for subsequent API calls
        4. POST to /api/2.x/logout when done (handled in get_health_status)
        
        Note: Session tokens are not cached as each client instance performs
        a complete login/query/logout cycle to minimize open sessions.
        
        Args:
            api_version: API version to use (e.g., '2.4', '2.26')
            
        Returns:
            Session token string or None if authentication fails
        """
        try:
            ssl_verify = get_ssl_verify(self.resolved_address)
            
            # For API 2.x, we need to login with the API token to get a session token
            # POST /api/2.x/login with api-token in the request header
            # This is the correct format for Pure Storage FlashArray API 2.x
            response = requests.post(
                f"{self.base_url}/api/{api_version}/login",
                headers={
                    'api-token': self.token
                },
                verify=ssl_verify,
                timeout=10
            )
            
            if response.status_code == 200:
                # Extract x-auth-token from response headers
                session_token = response.headers.get('x-auth-token')
                if session_token:
                    logger.info(f"Successfully authenticated to Pure Storage {self.ip_address}")
                    return session_token
                else:
                    logger.warning(f"No x-auth-token in login response for {self.ip_address}")
            elif response.status_code == 401:
                # Invalid API token
                logger.error(f"Authentication failed for {self.ip_address}: Invalid API token (401 Unauthorized)")
                return None
            elif response.status_code == 400:
                # Bad request - possibly malformed token
                logger.error(f"Authentication failed for {self.ip_address}: Bad request (400) - check API token format")
                return None
            else:
                logger.warning(f"Login failed for {self.ip_address}: HTTP {response.status_code}")
                
        except Exception as e:
            logger.warning(f"Authentication error for {self.ip_address}: {e}")
        
        return None
    
    def get_health_status(self):
        try:
            if not self.token:
                return self._format_response(status='error', hardware='error', cluster='error', error='Kein API-Token konfiguriert. Bitte API-Token in den System-Einstellungen eingeben.')
            
            ssl_verify = get_ssl_verify(self.resolved_address)
            
            # Detect API version dynamically
            api_version = self.detect_api_version()
            
            # Authenticate to get session token for API 2.x
            session_token = self.authenticate(api_version)
            
            if not session_token:
                return self._format_response(
                    status='error',
                    hardware='error',
                    cluster='error',
                    error=f'Authentifizierung fehlgeschlagen - Ungültiger API-Token oder Verbindungsfehler. API Version: {api_version}'
                )
            
            # FlashArray REST API v2 headers with session token
            headers = {
                'x-auth-token': session_token,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            # Get array info to verify connectivity and get OS version
            # REST API v2: GET /api/2.x/arrays
            response = requests.get(
                f"{self.base_url}/api/{api_version}/arrays",
                headers=headers,
                verify=ssl_verify,
                timeout=10
            )
            
            if response.status_code != 200:
                return self._format_response(status='error', hardware='error', cluster='error', error=f'API error: {response.status_code}')
            
            # Extract OS version from array info
            array_data = response.json()
            os_version = None
            array_name = None
            if 'items' in array_data and len(array_data['items']) > 0:
                item = array_data['items'][0]
                # Get version string - use 'version' field which contains the actual version number (e.g., "6.5.10")
                # The 'os' field contains "Purity//FA" which is not useful
                os_version = item.get('version')
                array_name = item.get('name')
            
            # Get space/capacity info
            # REST API v2: GET /api/2.x/arrays/space
            space_response = requests.get(
                f"{self.base_url}/api/{api_version}/arrays/space",
                headers=headers,
                verify=ssl_verify,
                timeout=10
            )
            
            total_bytes = 0
            used_bytes = 0
            
            if space_response.status_code == 200:
                space_data = space_response.json()
                
                # Parse space data from response
                # Response format: {"items": [{"capacity": ..., "space": {"total_physical": ...}}]}
                items = space_data.get('items', [])
                if items and len(items) > 0:
                    item = items[0]
                    
                    # Get capacity (total available capacity in bytes)
                    total_bytes = item.get('capacity', 0) or 0
                    
                    # Get used space (total_physical is the actual used space)
                    space_info = item.get('space', {})
                    used_bytes = space_info.get('total_physical', 0) or 0
            
            # Get controllers/nodes information
            # REST API v2: GET /api/2.x/controllers
            controllers = []
            try:
                controllers_response = requests.get(
                    f"{self.base_url}/api/{api_version}/controllers",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )
                
                if controllers_response.status_code == 200:
                    controllers_data = controllers_response.json()
                    items = controllers_data.get('items', [])
                    
                    for ctrl in items:
                        ctrl_name = ctrl.get('name', '')
                        
                        # Filter out shelf controllers (names containing .SC like SH9.SC0, SH9.SC1)
                        # These are not actual controller nodes
                        if '.SC' in ctrl_name:
                            logger.debug(f"Skipping shelf controller: {ctrl_name}")
                            continue
                        
                        controller_info = {
                            'name': ctrl_name,
                            'status': ctrl.get('status'),
                            'mode': ctrl.get('mode'),
                            'model': ctrl.get('model'),
                            'version': ctrl.get('version'),
                            'type': 'controller'
                        }
                        
                        # Collect all IPs from the controller
                        ips = []
                        if ctrl.get('ip'):
                            ips.append(ctrl.get('ip'))
                        if ctrl.get('mgmt_ip'):
                            ips.append(ctrl.get('mgmt_ip'))
                        if ctrl.get('replication_ip'):
                            ips.append(ctrl.get('replication_ip'))
                        
                        if ips:
                            controller_info['ips'] = ips
                        
                        controllers.append(controller_info)
                    
                    logger.info(f"Found {len(controllers)} controllers for {self.ip_address} (shelf controllers filtered out)")
            except Exception as ctrl_error:
                logger.warning(f"Could not get controllers for {self.ip_address}: {ctrl_error}")
            
            # Get all management network interfaces to collect all management IPs
            # REST API v2: GET /api/2.x/network-interfaces?filter=services='management'
            all_mgmt_ips = []
            try:
                network_response = requests.get(
                    f"{self.base_url}/api/{api_version}/network-interfaces",
                    headers=headers,
                    params={'filter': "services='management'"},
                    verify=ssl_verify,
                    timeout=10
                )
                
                if network_response.status_code == 200:
                    network_data = network_response.json()
                    items = network_data.get('items', [])
                    
                    for interface in items:
                        # Check if interface is enabled and has an IP address
                        if interface.get('enabled'):
                            eth_info = interface.get('eth', {})
                            ip_address = eth_info.get('address')
                            if ip_address:
                                all_mgmt_ips.append(ip_address)
                    
                    if all_mgmt_ips:
                        logger.info(f"Found {len(all_mgmt_ips)} management IPs for {self.ip_address}: {all_mgmt_ips}")
            except Exception as net_error:
                logger.warning(f"Could not get network interfaces for {self.ip_address}: {net_error}")
            
            # Perform DNS reverse lookups for all management IPs
            mgmt_ips_with_dns = []
            for mgmt_ip in all_mgmt_ips:
                dns_names = reverse_dns_lookup(mgmt_ip)
                mgmt_ips_with_dns.append({
                    'ip': mgmt_ip,
                    'dns_names': dns_names
                })
                if dns_names:
                    logger.info(f"DNS resolved for {mgmt_ip}: {dns_names}")
            
            # Get hardware status
            # REST API v2: GET /api/2.x/hardware
            hardware_status = 'ok'
            try:
                hardware_response = requests.get(
                    f"{self.base_url}/api/{api_version}/hardware",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )
                
                if hardware_response.status_code == 200:
                    hardware_data = hardware_response.json()
                    items = hardware_data.get('items', [])
                    
                    # Check if any hardware component is not OK
                    for hw in items:
                        status = hw.get('status', '').lower()
                        if status not in ['ok', 'healthy', 'normal', '']:
                            hardware_status = 'warning'
                            logger.warning(f"Hardware issue on {self.ip_address}: {hw.get('name')} is {status}")
                            break
            except Exception as hw_error:
                logger.warning(f"Could not get hardware status for {self.ip_address}: {hw_error}")
            
            # Get alerts
            # REST API v2: GET /api/2.x/alerts?filter=state='open'
            alerts_count = 0
            try:
                alerts_response = requests.get(
                    f"{self.base_url}/api/{api_version}/alerts",
                    headers=headers,
                    params={'filter': "state='open'"},
                    verify=ssl_verify,
                    timeout=10
                )
                
                if alerts_response.status_code == 200:
                    alerts_data = alerts_response.json()
                    items = alerts_data.get('items', [])
                    # API should return only open alerts, but filter as fallback
                    # in case the API doesn't support the filter parameter
                    alerts_count = sum(1 for a in items if a.get('state', '').lower() != 'closed')
                    
                    if alerts_count > 0:
                        logger.info(f"Found {alerts_count} open alerts for {self.ip_address}")
            except Exception as alerts_error:
                logger.warning(f"Could not get alerts for {self.ip_address}: {alerts_error}")
            
            # Get array connections (peers)
            # REST API v2: GET /api/2.x/array-connections
            array_connections = []
            try:
                connections_response = requests.get(
                    f"{self.base_url}/api/{api_version}/array-connections",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )
                
                if connections_response.status_code == 200:
                    connections_data = connections_response.json()
                    items = connections_data.get('items', [])
                    
                    for conn in items:
                        connection_info = {
                            'name': conn.get('name'),
                            'status': conn.get('status'),
                            'type': conn.get('type'),
                            'management_address': conn.get('management_address'),
                            'replication_address': conn.get('replication_address'),
                            'version': conn.get('version')
                        }
                        array_connections.append(connection_info)
                    
                    if array_connections:
                        logger.info(f"Found {len(array_connections)} array connections for {self.ip_address}")
            except Exception as conn_error:
                logger.warning(f"Could not get array connections for {self.ip_address}: {conn_error}")
            
            # Check for ActiveCluster configuration
            # REST API v2: GET /api/2.x/pods
            # An array is ActiveCluster if at least one pod has arrays.length > 1
            # Also check for sync-replication type in array connections
            is_active_cluster = False
            pods_info = []
            
            try:
                pods_response = requests.get(
                    f"{self.base_url}/api/{api_version}/pods",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )
                
                if pods_response.status_code == 200:
                    pods_data = pods_response.json()
                    items = pods_data.get('items', [])
                    
                    for pod in items:
                        # Get arrays for this pod
                        pod_arrays = pod.get('arrays', [])
                        
                        pod_info = {
                            'name': pod.get('name'),
                            'source': pod.get('source'),
                            'arrays': [arr.get('name') for arr in pod_arrays],
                            'array_count': pod.get('array_count', len(pod_arrays)),
                            'promotion_status': pod.get('promotion_status'),
                            'stretch': pod.get('stretch', False)
                        }
                        pods_info.append(pod_info)
                        
                        # ActiveCluster detection: pod must have more than 1 array
                        # Check both array_count field and arrays list length
                        array_count = pod.get('array_count', len(pod_arrays))
                        if array_count > 1 or len(pod_arrays) > 1:
                            is_active_cluster = True
                            logger.info(f"ActiveCluster detected: pod '{pod.get('name')}' has {array_count} arrays")
                    
                    if is_active_cluster:
                        logger.info(f"ActiveCluster confirmed for {self.ip_address} with {len(pods_info)} pods")
                    elif pods_info:
                        logger.debug(f"Pods exist for {self.ip_address} but no ActiveCluster (all pods have single array)")
            except Exception as pods_error:
                # Pods endpoint might not be available on all arrays
                logger.debug(f"Could not check pods for {self.ip_address}: {pods_error}")
            
            # Additional ActiveCluster detection via array connections
            # If there's a sync-replication type connection, it indicates ActiveCluster
            if not is_active_cluster and array_connections:
                for conn in array_connections:
                    if conn.get('type') == 'sync-replication':
                        is_active_cluster = True
                        logger.info(f"ActiveCluster detected via sync-replication connection to {conn.get('name')}")
                        break
            
            # Calculate site count based on peer connections
            # Each array connection represents a peer site, plus local site
            if array_connections:
                site_count = len(array_connections) + 1  # Local site + peer sites
                logger.info(f"Multi-site configuration detected: {site_count} sites (local + {len(array_connections)} peer(s))")
            else:
                site_count = 1  # Single site (no peer connections)
            
            # Logout to clean up the session
            try:
                requests.post(
                    f"{self.base_url}/api/{api_version}/logout",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=5
                )
                logger.debug(f"Logged out from Pure Storage {self.ip_address}")
            except Exception as logout_error:
                # Logout errors are not critical, but log for debugging
                logger.debug(f"Logout failed for {self.ip_address}: {logout_error}")
            
            return self._format_response(
                status='online',
                hardware=hardware_status,
                cluster='ok',
                alerts=alerts_count,
                total_tb=total_bytes / (1024**4),
                used_tb=used_bytes / (1024**4),
                os_version=os_version,
                api_version=api_version,
                controllers=controllers,
                array_connections=array_connections,
                is_active_cluster=is_active_cluster,
                site_count=site_count,
                pods_info=pods_info if pods_info else None,
                all_mgmt_ips=mgmt_ips_with_dns if mgmt_ips_with_dns else None
            )
                
        except Exception as e:
            logger.error(f"Error getting Pure Storage health status for {self.ip_address}: {e}")
            logger.error(traceback.format_exc())
            return self._format_response(status='error', hardware='error', cluster='error', error=str(e))


class NetAppONTAPClient(StorageClient):
    """NetApp ONTAP 9 client using REST API"""
    
    def get_health_status(self):
        try:
            if not self.username or not self.password:
                return self._format_response(status='error', hardware='error', cluster='error', error='No credentials configured')
            
            ssl_verify = get_ssl_verify(self.resolved_address)
            
            # ONTAP REST API uses basic authentication
            auth = (self.username, self.password)
            
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            # Get cluster info to verify connectivity
            # REST API: GET /api/cluster
            try:
                cluster_response = requests.get(
                    f"{self.base_url}/api/cluster",
                    auth=auth,
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )
                
                if cluster_response.status_code != 200:
                    return self._format_response(
                        status='error',
                        hardware='error',
                        cluster='error',
                        error=f'Failed to connect to cluster: HTTP {cluster_response.status_code}'
                    )
                
                cluster_data = cluster_response.json()
                cluster_name = cluster_data.get('name', 'unknown')
                
                # Extract OS version with null check
                version_data = cluster_data.get('version')
                os_version = None
                if version_data and isinstance(version_data, dict):
                    os_version = version_data.get('full') or version_data.get('generation')
                
            except Exception as cluster_error:
                return self._format_response(
                    status='error',
                    hardware='error',
                    cluster='error',
                    error=f'Failed to connect to cluster: {str(cluster_error)}'
                )
            
            # Check for MetroCluster configuration and get detailed information
            # Best practice: combine multiple endpoints for complete picture
            # 1. GET /api/cluster - local cluster info
            # 2. GET /api/cluster/metrocluster - MetroCluster state
            # 3. GET /api/cluster/peers - remote cluster info
            # 4. GET /api/cluster/metrocluster/nodes - all nodes (local + remote)
            # 5. GET /api/cluster/metrocluster/dr-groups - peer relationships
            is_metrocluster = False
            metrocluster_info = {}
            metrocluster_nodes = []
            metrocluster_dr_groups = []
            metrocluster_peers = []
            
            try:
                # Get MetroCluster configuration
                # REST API: GET /api/cluster/metrocluster
                metrocluster_response = requests.get(
                    f"{self.base_url}/api/cluster/metrocluster",
                    auth=auth,
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )
                
                if metrocluster_response.status_code == 200:
                    metrocluster_data = metrocluster_response.json()
                    
                    # Check if response contains error (no MetroCluster configured)
                    if 'error' in metrocluster_data:
                        logger.debug(f"No MetroCluster configured for {self.ip_address}: {metrocluster_data.get('error', {}).get('message')}")
                    # Check if records is empty (another way to indicate no MetroCluster)
                    elif 'records' in metrocluster_data and not metrocluster_data['records']:
                        logger.debug(f"No MetroCluster records for {self.ip_address}")
                    else:
                        # Check if MetroCluster is configured
                        # According to ONTAP API, check local.configuration_state
                        # Possible values: configured, not_configured, partial, degraded
                        local_config = metrocluster_data.get('local', {})
                        configuration_state = local_config.get('configuration_state')
                        
                        if configuration_state == 'configured':
                            is_metrocluster = True
                            logger.info(f"MetroCluster detected for {self.ip_address}: {configuration_state}")
                            
                            # Store MetroCluster configuration info
                            # configuration_type can be "ip_fabric" (MetroCluster IP) or "fabric" (MetroCluster FC)
                            local_cluster_from_mc = local_config.get('cluster', {}).get('name')
                            configuration_type = metrocluster_data.get('configuration_type')
                            
                            # Get partner cluster name from remote field
                            remote_cluster = metrocluster_data.get('remote', {}).get('cluster', {})
                            partner_cluster_name = remote_cluster.get('name')
                            
                            metrocluster_info = {
                                'configuration_state': configuration_state,
                                'mode': metrocluster_data.get('mode'),  # 'ip' or 'fc' (legacy field)
                                'configuration_type': configuration_type,  # 'ip_fabric' or 'fabric'
                                'uuid': metrocluster_data.get('uuid'),
                                'local_cluster_name': local_cluster_from_mc if local_cluster_from_mc is not None else cluster_name,
                                'partner_cluster_name': partner_cluster_name,
                            }
                            
                            # Extract nodes directly from metrocluster response if available
                            nodes_in_response = metrocluster_data.get('nodes', [])
                            if nodes_in_response:
                                logger.debug(f"Found {len(nodes_in_response)} nodes in MetroCluster response")
                            
                            # Extract DR groups directly from metrocluster response if available
                            dr_groups_in_response = metrocluster_data.get('dr_groups', [])
                            if dr_groups_in_response:
                                logger.debug(f"Found {len(dr_groups_in_response)} DR groups in MetroCluster response")
                            
                            # Get cluster peers to identify remote MetroCluster cluster
                            # REST API: GET /api/cluster/peers
                            try:
                                peers_response = requests.get(
                                    f"{self.base_url}/api/cluster/peers",
                                    auth=auth,
                                    headers=headers,
                                    verify=ssl_verify,
                                    timeout=10
                                )
                                
                                if peers_response.status_code == 200:
                                    peers_data = peers_response.json()
                                    records = peers_data.get('records', [])
                                    
                                    for peer in records:
                                        peer_info = {
                                            'name': peer.get('name'),
                                            'uuid': peer.get('uuid'),
                                            'location': peer.get('location'),
                                            'state': peer.get('state'),  # 'available' = active
                                            'health': peer.get('health'),  # 'healthy' = OK
                                            'ip_addresses': peer.get('remote', {}).get('ip_addresses', [])
                                        }
                                        metrocluster_peers.append(peer_info)
                                    
                                    if metrocluster_peers:
                                        logger.info(f"Found {len(metrocluster_peers)} MetroCluster peer cluster(s) for {self.ip_address}")
                                        # Update partner cluster name from peer info if not set
                                        if not metrocluster_info.get('partner_cluster_name') and metrocluster_peers:
                                            metrocluster_info['partner_cluster_name'] = metrocluster_peers[0]['name']
                            except Exception as peers_error:
                                logger.warning(f"Could not get cluster peers for {self.ip_address}: {peers_error}")
                            
                            # Get MetroCluster nodes information (includes both local and remote nodes)
                            # REST API: GET /api/cluster/metrocluster/nodes
                            try:
                                mc_nodes_response = requests.get(
                                    f"{self.base_url}/api/cluster/metrocluster/nodes",
                                    auth=auth,
                                    headers=headers,
                                    verify=ssl_verify,
                                    timeout=10
                                )
                                
                                if mc_nodes_response.status_code == 200:
                                    mc_nodes_data = mc_nodes_response.json()
                                    records = mc_nodes_data.get('records', [])
                                    
                                    for node in records:
                                        node_cluster = node.get('cluster', {}).get('name')
                                        node_details = node.get('node', {})
                                        node_info = {
                                            'name': node_details.get('name'),
                                            'uuid': node_details.get('uuid'),
                                            'cluster': node_cluster,
                                            'is_local': node_cluster == cluster_name,  # Distinguish local vs remote
                                            'dr_group_id': node.get('dr_group_id'),
                                            'dr_partner': node.get('dr_partner', {}).get('name'),
                                            'ha_partner': node.get('ha_partner', {}).get('name'),
                                            'configuration_state': node.get('configuration_state'),
                                            'type': 'metrocluster-node'
                                        }
                                        metrocluster_nodes.append(node_info)
                                    
                                    local_nodes = [n for n in metrocluster_nodes if n.get('is_local')]
                                    remote_nodes = [n for n in metrocluster_nodes if not n.get('is_local')]
                                    logger.info(f"Found {len(local_nodes)} local and {len(remote_nodes)} remote MetroCluster nodes for {self.ip_address}")
                            except Exception as mc_nodes_error:
                                logger.warning(f"Could not get MetroCluster nodes for {self.ip_address}: {mc_nodes_error}")
                            
                            # Get MetroCluster DR groups information (shows peer relationships)
                            # REST API: GET /api/cluster/metrocluster/dr-groups
                            try:
                                dr_groups_response = requests.get(
                                    f"{self.base_url}/api/cluster/metrocluster/dr-groups",
                                    auth=auth,
                                    headers=headers,
                                    verify=ssl_verify,
                                    timeout=10
                                )
                                
                                if dr_groups_response.status_code == 200:
                                    dr_groups_data = dr_groups_response.json()
                                    records = dr_groups_data.get('records', [])
                                    
                                    for dr_group in records:
                                        dr_group_info = {
                                            'id': dr_group.get('id'),
                                            'uuid': dr_group.get('uuid'),
                                            'local_nodes': [n.get('name') for n in dr_group.get('local', {}).get('nodes', [])],
                                            'partner_nodes': [n.get('name') for n in dr_group.get('partner', {}).get('nodes', [])],
                                        }
                                        metrocluster_dr_groups.append(dr_group_info)
                                    
                                    logger.info(f"Found {len(metrocluster_dr_groups)} MetroCluster DR groups for {self.ip_address}")
                            except Exception as dr_groups_error:
                                logger.warning(f"Could not get MetroCluster DR groups for {self.ip_address}: {dr_groups_error}")
                        elif configuration_state in ['not_configured', 'partial', 'degraded']:
                            logger.info(f"MetroCluster state for {self.ip_address}: {configuration_state}")
                        else:
                            logger.debug(f"Unknown MetroCluster state for {self.ip_address}: {configuration_state}")
            except Exception as mc_error:
                # MetroCluster endpoint might not be available if not configured
                logger.debug(f"Could not check MetroCluster status for {self.ip_address}: {mc_error}")
            
            # Get regular cluster nodes information (with model, serial number, etc.)
            # REST API: GET /api/cluster/nodes?fields=uuid,name,state,model,serial_number,version,metrocluster.type,ha.enabled,management_interfaces.ip.address
            cluster_nodes = []
            try:
                nodes_response = requests.get(
                    f"{self.base_url}/api/cluster/nodes",
                    auth=auth,
                    headers=headers,
                    params={'fields': 'uuid,name,state,model,serial_number,version,metrocluster.type,ha.enabled,management_interfaces.ip.address'},
                    verify=ssl_verify,
                    timeout=10
                )
                
                if nodes_response.status_code == 200:
                    nodes_data = nodes_response.json()
                    records = nodes_data.get('records', [])
                    
                    for node in records:
                        # Extract version info
                        version_info = node.get('version', {})
                        version_full = version_info.get('full', 'unknown') if isinstance(version_info, dict) else 'unknown'
                        
                        # Extract management IP addresses
                        mgmt_ips = []
                        mgmt_interfaces = node.get('management_interfaces', [])
                        if isinstance(mgmt_interfaces, list):
                            for iface in mgmt_interfaces:
                                ip_info = iface.get('ip', {})
                                if isinstance(ip_info, dict) and 'address' in ip_info:
                                    mgmt_ips.append(ip_info['address'])
                        
                        # Extract MetroCluster type
                        metrocluster_type = None
                        metrocluster_info_node = node.get('metrocluster', {})
                        if isinstance(metrocluster_info_node, dict):
                            metrocluster_type = metrocluster_info_node.get('type')
                        
                        # Extract HA enabled status
                        ha_enabled = None
                        ha_info = node.get('ha', {})
                        if isinstance(ha_info, dict):
                            ha_enabled = ha_info.get('enabled')
                        
                        node_info = {
                            'name': node.get('name', 'Unknown'),
                            'uuid': node.get('uuid'),
                            'status': node.get('state', 'unknown'),
                            'model': node.get('model', 'unknown'),
                            'serial': node.get('serial_number', 'unknown'),
                            'version': version_full,
                            'type': 'cluster-node',
                            'ips': mgmt_ips,
                            'metrocluster_type': metrocluster_type,
                            'ha_enabled': ha_enabled
                        }
                        cluster_nodes.append(node_info)
                    
                    logger.info(f"Found {len(cluster_nodes)} cluster nodes for {self.ip_address}")
            except Exception as nodes_error:
                logger.warning(f"Could not get cluster nodes for {self.ip_address}: {nodes_error}")
            
            # Merge cluster node info with MetroCluster node info if both exist
            # This enriches MetroCluster nodes with model/serial information
            if metrocluster_nodes and cluster_nodes:
                for mc_node in metrocluster_nodes:
                    # Find corresponding cluster node
                    for cluster_node in cluster_nodes:
                        if mc_node['name'] == cluster_node['name']:
                            # Merge the information
                            mc_node['model'] = cluster_node.get('model', 'unknown')
                            mc_node['serial'] = cluster_node.get('serial', 'unknown')
                            mc_node['version'] = cluster_node.get('version', 'unknown')
                            mc_node['status'] = cluster_node.get('status', 'unknown')
                            mc_node['ips'] = cluster_node.get('ips', [])
                            mc_node['metrocluster_type'] = cluster_node.get('metrocluster_type')
                            mc_node['ha_enabled'] = cluster_node.get('ha_enabled')
                            # Update UUID from cluster node if not already set
                            if not mc_node.get('uuid'):
                                mc_node['uuid'] = cluster_node.get('uuid')
                            break
            
            # Get aggregate space info
            # REST API: GET /api/storage/aggregates?fields=space
            total_bytes = 0
            used_bytes = 0
            
            try:
                aggregates_response = requests.get(
                    f"{self.base_url}/api/storage/aggregates",
                    auth=auth,
                    headers=headers,
                    params={'fields': 'space'},
                    verify=ssl_verify,
                    timeout=10
                )
                
                if aggregates_response.status_code == 200:
                    aggregates_data = aggregates_response.json()
                    
                    # Parse aggregates from response
                    # Response format: {"records": [{"space": {"block_storage": {"size": ..., "used": ...}}}]}
                    records = aggregates_data.get('records', [])
                    
                    for aggr in records:
                        space = aggr.get('space', {})
                        block_storage = space.get('block_storage', {})
                        
                        size = block_storage.get('size', 0) or 0
                        used = block_storage.get('used', 0) or 0
                        
                        total_bytes += size
                        used_bytes += used
            except Exception as aggr_error:
                # Log the error but continue with 0 capacity
                logger.warning(f"Could not get aggregate space info for {self.ip_address}: {aggr_error}")
            
            return self._format_response(
                status='online',
                hardware='ok',
                cluster='ok',
                alerts=0,
                total_tb=total_bytes / (1024**4),
                used_tb=used_bytes / (1024**4),
                os_version=os_version,
                is_metrocluster=is_metrocluster,
                metrocluster_info=metrocluster_info if metrocluster_info else None,
                metrocluster_nodes=metrocluster_nodes if metrocluster_nodes else None,
                metrocluster_dr_groups=metrocluster_dr_groups if metrocluster_dr_groups else None,
                metrocluster_peers=metrocluster_peers if metrocluster_peers else None,
                controllers=metrocluster_nodes if metrocluster_nodes else cluster_nodes  # Use MetroCluster nodes if available, otherwise regular cluster nodes
            )
        except Exception as e:
            logger.error(f"Error getting NetApp ONTAP health status for {self.ip_address}: {e}")
            logger.error(traceback.format_exc())
            return self._format_response(status='error', hardware='error', cluster='error', error=str(e))


class NetAppStorageGRIDClient(StorageClient):
    """NetApp StorageGRID client - API v4
    
    Based on: https://webscalegmi.netapp.com/grid/apidocs.html
    """
    
    def authenticate(self):
        """Authenticate with StorageGRID and obtain API token
        
        Uses username and password to authenticate and retrieve an API token.
        The token should be saved to the database for future use.
        
        Returns:
            str: API token if successful, None if authentication fails
        """
        if not self.username or not self.password:
            logger.error(f"Cannot authenticate to StorageGRID {self.ip_address}: username or password not configured")
            return None
        
        try:
            ssl_verify = get_ssl_verify(self.resolved_address)
            
            auth_data = {
                'username': self.username,
                'password': self.password,
                'cookie': True,
                'csrfToken': False
            }
            
            logger.debug(f"Authenticating to StorageGRID {self.ip_address}")
            
            response = requests.post(
                f"{self.base_url}/api/v4/authorize",
                json=auth_data,
                headers={'Content-Type': 'application/json'},
                verify=ssl_verify,
                timeout=10
            )
            
            if response.status_code == 200:
                auth_response = response.json()
                token = auth_response.get('data')
                
                if token:
                    logger.debug(f"Successfully obtained API token for StorageGRID {self.ip_address}")
                    return token
                else:
                    logger.error(f"Authentication response did not contain token data: {auth_response}")
                    return None
            else:
                logger.error(f"StorageGRID authentication failed for {self.ip_address}: HTTP {response.status_code}")
                try:
                    logger.error(f"Response: {response.text[:MAX_RESPONSE_LOG_LENGTH]}")
                except Exception:
                    pass
                return None
                
        except Exception as e:
            logger.error(f"Error authenticating to StorageGRID {self.ip_address}: {e}")
            logger.error(traceback.format_exc())
            return None
    
    def get_health_status(self):
        try:
            # StorageGRID REST API v4
            # If no token is configured, try to authenticate automatically
            new_token_generated = False
            if not self.token:
                logger.debug(f"Attempting automatic authentication for StorageGRID {self.ip_address}")
                self.token = self.authenticate()
                if self.token:
                    new_token_generated = True
                else:
                    return self._format_response(status='error', hardware='error', cluster='error', 
                                                error='Authentication failed. Please check credentials.')
            
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            ssl_verify = get_ssl_verify(self.resolved_address)
            
            # Get grid health to verify connectivity
            # API: GET /api/v4/grid/health
            # This endpoint returns counts of alarms, alerts, and nodes - no general health field exists
            hardware_status = 'ok'
            cluster_status = 'ok'
            try:
                health_response = requests.get(
                    f"{self.base_url}/api/v4/grid/health",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )
                
                if health_response.status_code == 200:
                    health_data = health_response.json()
                    data = health_data.get('data', {})
                    
                    # Parse grid health statistics for reference
                    # The actual health status will be determined from alerts and node health
                    alarms = data.get('alarms', {})
                    grid_alerts = data.get('alerts', {})
                    nodes = data.get('nodes', {})
                    
                    logger.debug(f"StorageGRID health stats for {self.ip_address}: "
                               f"Alarms(critical={alarms.get('critical', 0)}, major={alarms.get('major', 0)}), "
                               f"Alerts(critical={grid_alerts.get('critical', 0)}, major={grid_alerts.get('major', 0)}), "
                               f"Nodes(connected={nodes.get('connected', 0)}, unknown={nodes.get('unknown', 0)})")
            except Exception as health_error:
                logger.warning(f"Could not get StorageGRID health for {self.ip_address}: {health_error}")
            
            # Get grid topology to verify connectivity and get version info
            response = requests.get(
                f"{self.base_url}/api/v4/grid/health/topology",
                headers=headers,
                verify=ssl_verify,
                timeout=10
            )
            
            if response.status_code != 200:
                error_msg = f'API error: {response.status_code}'
                if response.status_code == 401:
                    # Token invalid - try to re-authenticate once
                    logger.debug(f"Re-authenticating to StorageGRID {self.ip_address}")
                    
                    new_token = self.authenticate()
                    if new_token:
                        self.token = new_token
                        new_token_generated = True
                        
                        # Retry the request with new token
                        headers['Authorization'] = f'Bearer {self.token}'
                        response = requests.get(
                            f"{self.base_url}/api/v4/grid/health/topology",
                            headers=headers,
                            verify=ssl_verify,
                            timeout=10
                        )
                        
                        if response.status_code != 200:
                            error_msg = f'API error: {response.status_code}'
                            logger.error(f"StorageGRID API error for {self.ip_address}: HTTP {response.status_code}")
                            return self._format_response(status='error', hardware='error', cluster='error', error=error_msg)
                    else:
                        error_msg = 'API error: 401 - Authentication failed. Please check credentials.'
                        logger.error(f"StorageGRID authentication failed for {self.ip_address}")
                        return self._format_response(status='error', hardware='error', cluster='error', error=error_msg)
                else:
                    logger.error(f"StorageGRID API error for {self.ip_address}: HTTP {response.status_code}")
                    try:
                        logger.error(f"Response text: {response.text[:MAX_RESPONSE_LOG_LENGTH]}")
                    except Exception:
                        logger.error("Response text unavailable")
                    return self._format_response(status='error', hardware='error', cluster='error', error=error_msg)
            
            # Get product version from grid config
            os_version = None
            try:
                version_response = requests.get(
                    f"{self.base_url}/api/v4/grid/config/product-version",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )
                
                if version_response.status_code == 200:
                    version_data = version_response.json()
                    os_version = extract_field_with_fallbacks(version_data, ['data.productVersion', 'productVersion'])
            except Exception as version_error:
                logger.warning(f"Could not get StorageGRID version for {self.ip_address}: {version_error}")
            
            # Get alerts count and severity
            # API: GET /api/v4/grid/alerts?include=active
            alerts_count = 0
            critical_alerts = 0
            major_alerts = 0
            minor_alerts = 0
            try:
                alerts_response = requests.get(
                    f"{self.base_url}/api/v4/grid/alerts",
                    headers=headers,
                    params={'include': 'active'},
                    verify=ssl_verify,
                    timeout=10
                )
                
                if alerts_response.status_code == 200:
                    alerts_data = alerts_response.json()
                    alerts_list = alerts_data.get('data', [])
                    # API returns only active alerts with include=active parameter
                    alerts_count = len(alerts_list)
                    
                    # Count alerts by severity to determine health status
                    for alert in alerts_list:
                        severity = alert.get('severity', '').lower()
                        if severity == 'critical':
                            critical_alerts += 1
                        elif severity == 'major':
                            major_alerts += 1
                        elif severity == 'minor':
                            minor_alerts += 1
                    
                    # Determine hardware status based on alert severity
                    if critical_alerts > 0:
                        hardware_status = 'error'
                        logger.warning(f"Found {critical_alerts} critical alerts for StorageGRID {self.ip_address}")
                    elif major_alerts > 0:
                        hardware_status = 'warning'
                        logger.warning(f"Found {major_alerts} major alerts for StorageGRID {self.ip_address}")
                    
                    # Log alert summary (always shown for visibility)
                    if alerts_count > 0:
                        logger.info(f"Total active alerts for StorageGRID {self.ip_address}: {alerts_count} "
                                  f"(critical={critical_alerts}, major={major_alerts}, minor={minor_alerts})")
            except Exception as alerts_error:
                logger.warning(f"Could not get StorageGRID alerts for {self.ip_address}: {alerts_error}")
            
            # Get node health information
            # API: GET /api/v4/grid/node-health
            nodes_info = []
            site_names = set()  # Track unique site names
            try:
                node_health_response = requests.get(
                    f"{self.base_url}/api/v4/grid/node-health",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )
                
                if node_health_response.status_code == 200:
                    node_health_data = node_health_response.json()
                    nodes_list = node_health_data.get('data', [])
                    
                    for node in nodes_list:
                        node_id = node.get('id', '')
                        node_name = node.get('name', 'Unknown')
                        node_state = node.get('state', 'unknown')
                        node_severity = node.get('severity', 'normal')
                        node_type = node.get('type', 'unknown')
                        site_name = node.get('siteName')
                        site_id = node.get('siteId')
                        
                        # Track unique site names for multi-site detection
                        if site_name:
                            site_names.add(site_name)
                        
                        node_info = {
                            'name': node_name,
                            'id': node_id,
                            'type': node_type,
                            'status': node_state,
                            'severity': node_severity
                        }
                        
                        # Add site information if available
                        if site_name:
                            node_info['site'] = site_name
                        if site_id:
                            node_info['site_id'] = site_id
                        
                        # Check node health based on state and severity
                        # State should be 'connected' and severity should be 'normal' for healthy nodes
                        if node_state and node_state.lower() not in STORAGEGRID_HEALTHY_NODE_STATES:
                            hardware_status = 'warning'
                            logger.warning(f"StorageGRID node {node_name} unhealthy state: {node_state}")
                        
                        # Check node severity - anything other than 'normal' indicates an issue
                        if node_severity and node_severity.lower() != 'normal':
                            severity_level = node_severity.lower()
                            if severity_level == 'critical':
                                hardware_status = 'error'
                                logger.warning(f"StorageGRID node {node_name} critical severity: {node_severity}")
                            elif severity_level in ['major', 'minor']:
                                # Only escalate to warning if not already error
                                if hardware_status != 'error':
                                    hardware_status = 'warning'
                                logger.warning(f"StorageGRID node {node_name} {severity_level} severity: {node_severity}")
                        
                        nodes_info.append(node_info)
                    
                    logger.info(f"Found {len(nodes_info)} nodes in StorageGRID {self.ip_address}")
            except Exception as node_health_error:
                logger.warning(f"Could not get StorageGRID node health for {self.ip_address}: {node_health_error}")
            
            # Determine site count from node siteNames
            # Note: /api/v4/grid/sites does not exist in StorageGRID API
            # Multi-site detection: if nodes have different siteNames, it's multi-site
            site_count = len(site_names) if site_names else 1
            sites_info = []
            
            if len(site_names) > 1:
                logger.info(f"Multi-site detected from node siteNames: {site_count} unique sites ({', '.join(site_names)})")
                # Create sites_info from unique site names
                for site_name in site_names:
                    sites_info.append({'name': site_name})
            elif len(site_names) == 1:
                logger.info(f"Single-site installation: {list(site_names)[0]}")
            else:
                logger.debug(f"No site information available from nodes")
            
            # Get capacity info using metric-query API
            # StorageGRID uses Prometheus-style metrics
            total_bytes = 0
            used_bytes = 0
            
            try:
                # Query total space metric
                # API: GET /api/v4/grid/metric-query?query=storagegrid_storage_utilization_total_space_bytes
                total_metric_response = requests.get(
                    f"{self.base_url}/api/v4/grid/metric-query",
                    headers=headers,
                    params={
                        'query': 'storagegrid_storage_utilization_total_space_bytes',
                        'timeout': '30s'
                    },
                    verify=ssl_verify,
                    timeout=35  # Allow enough time for the API-level timeout (30s) plus network overhead
                )
                
                if total_metric_response.status_code == 200:
                    total_metric_data = total_metric_response.json()
                    
                    # Parse metric query response
                    # Response format: {"data": {"resultType": "vector", "result": [{"metric": {...}, "value": [timestamp, "value"]}]}}
                    data = total_metric_data.get('data', {})
                    results = data.get('result', [])
                    
                    # Sum up total space from all storage nodes
                    for result in results:
                        value_array = result.get('value', [])
                        if len(value_array) >= 2:
                            # value is [timestamp, "bytes_value"]
                            try:
                                node_total = int(value_array[1])
                                total_bytes += node_total
                            except (ValueError, TypeError) as e:
                                # Include node identifier for easier debugging
                                metric_info = result.get('metric', {})
                                node_id = metric_info.get('instance', metric_info.get('node_id', 'unknown'))
                                logger.debug(f"Could not parse total space value for node {node_id}: {value_array[1]}, error: {e}")
                    
                    logger.info(f"StorageGRID total capacity from {len(results)} nodes: {total_bytes} bytes")
                
                # Query used data metric
                # API: GET /api/v4/grid/metric-query?query=storagegrid_storage_utilization_data_bytes
                used_metric_response = requests.get(
                    f"{self.base_url}/api/v4/grid/metric-query",
                    headers=headers,
                    params={
                        'query': 'storagegrid_storage_utilization_data_bytes',
                        'timeout': '30s'
                    },
                    verify=ssl_verify,
                    timeout=35  # Allow enough time for the API-level timeout (30s) plus network overhead
                )
                
                if used_metric_response.status_code == 200:
                    used_metric_data = used_metric_response.json()
                    
                    # Parse metric query response
                    data = used_metric_data.get('data', {})
                    results = data.get('result', [])
                    
                    # Sum up used space from all storage nodes
                    for result in results:
                        value_array = result.get('value', [])
                        if len(value_array) >= 2:
                            # value is [timestamp, "bytes_value"]
                            try:
                                node_used = int(value_array[1])
                                used_bytes += node_used
                            except (ValueError, TypeError) as e:
                                # Include node identifier for easier debugging
                                metric_info = result.get('metric', {})
                                node_id = metric_info.get('instance', metric_info.get('node_id', 'unknown'))
                                logger.debug(f"Could not parse used space value for node {node_id}: {value_array[1]}, error: {e}")
                    
                    logger.info(f"StorageGRID used capacity from {len(results)} nodes: {used_bytes} bytes")
                        
            except Exception as usage_error:
                # Log but don't fail if we can't get capacity
                logger.warning(f"Could not get StorageGRID storage metrics: {usage_error}")
            
            # Convert bytes to TB (1 TB = 1024^4 bytes)
            total_tb = total_bytes / (1024**4) if total_bytes > 0 else 0.0
            used_tb = used_bytes / (1024**4) if used_bytes > 0 else 0.0
            
            return self._format_response(
                status='online',
                hardware=hardware_status,
                cluster=cluster_status,
                alerts=alerts_count,
                total_tb=total_tb,
                used_tb=used_tb,
                os_version=os_version,
                controllers=nodes_info if nodes_info else None,
                site_count=site_count,
                sites_info=sites_info if sites_info else None,
                new_api_token=self.token if new_token_generated else None
            )
        except Exception as e:
            logger.error(f"Error getting StorageGRID health status for {self.ip_address}: {e}")
            logger.error(traceback.format_exc())
            return self._format_response(status='error', hardware='error', cluster='error', error=str(e))


class DellDataDomainClient(StorageClient):
    """Dell DataDomain client - REST API v1.0
    
    Uses token-based authentication.
    Authentication endpoint: POST /rest/v1.0/auth (port 3009)
    Returns X-DD-AUTH-TOKEN in response header
    """
    
    # Alert state constants for filtering active alerts
    ACTIVE_ALERT_STATES = ['active', 'new', 'unresolved']
    
    # Hardware component failure states
    FAILED_COMPONENT_STATES = ['failed', 'error', 'critical']
    
    # Critical alert severity levels
    CRITICAL_ALERT_SEVERITIES = ['critical', 'major']
    
    # Management network interfaces to check when bulk API fails
    MANAGEMENT_INTERFACES = ['ethMa', 'ethMb', 'ethMc', 'ethMd']
    
    def authenticate(self):
        """Authenticate with DataDomain and obtain session token
        
        Uses username and password to authenticate and retrieve a session token.
        The token should be saved to the database for future use.
        
        Returns:
            str: Session token if successful, None if authentication fails
        """
        if not self.username or not self.password:
            logger.error(f"Cannot authenticate to DataDomain {self.ip_address}: username or password not configured")
            return None
        
        try:
            ssl_verify = get_ssl_verify(self.resolved_address)
            
            auth_data = {
                'username': self.username,
                'password': self.password
            }
            
            logger.debug(f"Authenticating to DataDomain {self.ip_address} via {self.base_url}")
            
            response = requests.post(
                f"{self.base_url}/rest/v1.0/auth",
                json=auth_data,
                headers={'Content-Type': 'application/json'},
                verify=ssl_verify,
                timeout=10
            )
            
            if response.status_code == 201:
                # Token is in response header, not body
                token = response.headers.get('X-DD-AUTH-TOKEN')
                
                if token:
                    logger.debug(f"Successfully obtained session token for DataDomain {self.ip_address}")
                    return token
                else:
                    logger.error(f"Authentication response did not contain X-DD-AUTH-TOKEN header")
                    logger.error(f"Response headers: {dict(response.headers)}")
                    return None
            else:
                logger.error(f"DataDomain authentication failed for {self.ip_address}: HTTP {response.status_code}")
                try:
                    logger.error(f"Response: {response.text[:MAX_RESPONSE_LOG_LENGTH]}")
                except Exception:
                    pass
                return None
                
        except Exception as e:
            logger.error(f"Error authenticating to DataDomain {self.ip_address}: {e}")
            logger.error(traceback.format_exc())
            return None
    
    def _make_api_request(self, endpoint, method='GET', headers=None, ssl_verify=None, data=None):
        """Make an API request to DataDomain
        
        Args:
            endpoint: API endpoint path (e.g., '/rest/v1.0/dd-systems/0/ha')
            method: HTTP method (GET, POST, PUT, DELETE)
            headers: HTTP headers (will add auth token)
            ssl_verify: SSL verification setting
            data: Request body data (for POST/PUT)
            
        Returns:
            dict: Response JSON data or None on error
        """
        if headers is None:
            headers = {
                'X-DD-AUTH-TOKEN': self.token,
                'Accept': 'application/json'
            }
        if ssl_verify is None:
            ssl_verify = get_ssl_verify(self.resolved_address)
        
        try:
            url = f"{self.base_url}{endpoint}"
            
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, verify=ssl_verify, timeout=10)
            elif method.upper() == 'POST':
                response = requests.post(url, headers=headers, json=data, verify=ssl_verify, timeout=10)
            elif method.upper() == 'PUT':
                response = requests.put(url, headers=headers, json=data, verify=ssl_verify, timeout=10)
            elif method.upper() == 'DELETE':
                response = requests.delete(url, headers=headers, verify=ssl_verify, timeout=10)
            else:
                logger.error(f"Unsupported HTTP method: {method}")
                return None
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.debug(f"DataDomain API request to {endpoint} failed: HTTP {response.status_code}")
                return None
        except Exception as e:
            logger.debug(f"Error making DataDomain API request to {endpoint}: {e}")
            return None
    
    def _get_ha_status(self, headers, ssl_verify):
        """Get High Availability status and partner node information
        
        Returns:
            dict: HA status information or None
        """
        try:
            # Try both API v1 and REST v1.0 endpoints for HA information
            # API v1 provides more structured data with HaSysInfo schema
            data = self._make_api_request('/api/v1/dd-systems/0/ha', headers, ssl_verify)
            
            # If API v1 fails, fallback to REST v1.0
            if not data:
                data = self._make_api_request('/rest/v1.0/dd-systems/0/ha', headers, ssl_verify)
            
            if not data:
                return None
            
            # Extract haInfo section if present (API v1/v2.0 format with HaSysInfo wrapper)
            # If not present, use the entire data object (REST v1.0 format)
            ha_section = data.get('haInfo', data)
            
            ha_info = {
                'enabled': data.get('enabled', False),
                'state': ha_section.get('state', 'unknown'),
                'role': ha_section.get('role', 'unknown'),
                'mode': ha_section.get('mode'),
                'node_name': ha_section.get('nodeName'),  # Current node's name
                'origin_hostname': ha_section.get('originHostname'),
                'system_id': ha_section.get('systemId'),
                'partner_name': data.get('partner_name'),  # Will be populated from peer info if not present
                'partner_address': data.get('partner_address'),
                'partner_status': data.get('partner_status'),
                'failover_status': data.get('failover_status')
            }
            
            # Extract peer information if available
            peer_info = ha_section.get('peerInfo', {})
            if peer_info:
                ha_info['peer'] = {
                    'chassis_no': peer_info.get('chassisno'),
                    'serial_no': peer_info.get('serialno'),
                    'ip': peer_info.get('ip'),
                    'node_name': peer_info.get('nodeName'),
                    'state': peer_info.get('state'),
                    'origin_hostname': peer_info.get('originHostname')
                }
                # Use peer info to populate partner fields if not already set
                if not ha_info['partner_name'] and peer_info.get('nodeName'):
                    ha_info['partner_name'] = peer_info.get('nodeName')
                if not ha_info['partner_address'] and peer_info.get('ip'):
                    ha_info['partner_address'] = peer_info.get('ip')
                if not ha_info['partner_status'] and peer_info.get('state'):
                    ha_info['partner_status'] = peer_info.get('state')
            
            # Extract failover history if available
            failover_history = data.get('failoverHistory', [])
            if failover_history:
                ha_info['failover_history'] = failover_history
            
            logger.debug(f"DataDomain {self.ip_address} - HA Status: {ha_info.get('state')}, "
                        f"Role: {ha_info.get('role')}, Mode: {ha_info.get('mode')}, "
                        f"Node: {ha_info.get('node_name')}, Partner: {ha_info.get('partner_name')}")
            
            return ha_info
        except Exception as e:
            logger.debug(f"Could not get HA status for DataDomain {self.ip_address}: {e}")
            return None
    
    def _get_active_alerts(self, headers, ssl_verify):
        """Get active alerts from the system
        
        Returns:
            list: List of active alerts with severity, message, etc.
        """
        try:
            data = self._make_api_request('/rest/v1.0/dd-systems/0/alerts', headers, ssl_verify)
            if not data:
                return []
            
            # Extract alerts from response
            # DataDomain API may return alerts in different formats
            alerts = []
            alert_list = data.get('alerts', []) or data.get('alert', []) or []
            
            if isinstance(alert_list, list):
                for alert in alert_list:
                    # Only include active alerts (using class constant)
                    if alert.get('state', '').lower() in self.ACTIVE_ALERT_STATES:
                        alerts.append({
                            'id': alert.get('id'),
                            'severity': alert.get('severity', 'unknown'),
                            'category': alert.get('category', 'general'),
                            'message': alert.get('message', ''),
                            'timestamp': alert.get('timestamp', ''),
                            'state': alert.get('state', 'active')
                        })
            
            logger.debug(f"DataDomain {self.ip_address} - Found {len(alerts)} active alerts")
            return alerts
        except Exception as e:
            logger.debug(f"Could not get alerts for DataDomain {self.ip_address}: {e}")
            return []
    
    def _get_all_network_interfaces(self, headers, ssl_verify):
        """Get all network interface information
        
        Returns:
            list: List of network interfaces with IPs
        """
        try:
            data = self._make_api_request('/rest/v1.0/dd-systems/0/networks', headers, ssl_verify)
            if not data:
                return []
            
            interfaces = []
            # Try multiple possible field names for network list
            network_list = data.get('network')
            if network_list is None:
                network_list = data.get('networks', [])
            
            if isinstance(network_list, list):
                for iface in network_list:
                    ip_config = iface.get('ip_config', {})
                    ip_address = ip_config.get('ip_address')
                    
                    if ip_address:
                        interfaces.append({
                            'name': iface.get('name', iface.get('id', 'unknown')),
                            'ip_address': ip_address,
                            'enabled': iface.get('enabled', False),
                            'link_status': iface.get('link_status', 'unknown'),
                            'mtu': iface.get('mtu')
                        })
            
            logger.debug(f"DataDomain {self.ip_address} - Found {len(interfaces)} network interfaces")
            return interfaces
        except Exception as e:
            logger.debug(f"Could not get network interfaces for DataDomain {self.ip_address}: {e}")
            return []
    
    def _get_network_nics(self, headers, ssl_verify):
        """Get network NICs information from v2.0 API
        
        Returns:
            list: List of network NICs with detailed configuration
        """
        try:
            # Try v2.0 API first for NICs
            data = self._make_api_request('/rest/v2.0/dd-systems/0/networks/nics', headers, ssl_verify)
            if not data:
                # Fallback to v1.0 API
                return self._get_all_network_interfaces(headers, ssl_verify)
            
            nics = []
            # Try multiple possible field names for NIC list
            nic_list = data.get('nics')
            if nic_list is None:
                nic_list = data.get('nic', [])
            
            if isinstance(nic_list, list):
                for nic in nic_list:
                    nic_info = {
                        'name': nic.get('name', nic.get('id', 'unknown')),
                        'enabled': nic.get('enabled', False),
                        'link_status': nic.get('link_status', 'unknown'),
                        'mtu': nic.get('mtu')
                    }
                    
                    # Extract IP configuration
                    ip_config = nic.get('ip_config', {})
                    if ip_config:
                        nic_info['ip_address'] = ip_config.get('ip_address')
                        nic_info['netmask'] = ip_config.get('netmask')
                        nic_info['gateway'] = ip_config.get('gateway')
                    
                    # Only include NICs with IP addresses
                    if nic_info.get('ip_address'):
                        nics.append(nic_info)
                    
                    # If no IP was found but ID is available, try to fetch individual NIC details
                    elif nic.get('id'):
                        nic_id = nic.get('id')
                        nic_detail = self._make_api_request(f'/rest/v2.0/dd-systems/0/networks/nics/{nic_id}', headers, ssl_verify)
                        if nic_detail:
                            ip_config = nic_detail.get('ip_config', {})
                            if ip_config.get('ip_address'):
                                nic_info['ip_address'] = ip_config.get('ip_address')
                                nic_info['netmask'] = ip_config.get('netmask')
                                nic_info['gateway'] = ip_config.get('gateway')
                                nics.append(nic_info)
            
            # If we didn't get any NICs from the bulk API, try querying management interfaces individually
            if not nics:
                logger.debug(f"DataDomain {self.ip_address} - No NICs from bulk API, trying individual management interfaces")
                for iface_name in self.MANAGEMENT_INTERFACES:
                    try:
                        iface_data = self._make_api_request(f'/rest/v2.0/dd-systems/0/networks/nics/{iface_name}', headers, ssl_verify)
                        if iface_data:
                            ip_config = iface_data.get('ip_config', {})
                            if ip_config.get('ip_address'):
                                nics.append({
                                    'name': iface_name,
                                    'ip_address': ip_config.get('ip_address'),
                                    'netmask': ip_config.get('netmask'),
                                    'gateway': ip_config.get('gateway'),
                                    'enabled': iface_data.get('enabled', False),
                                    'link_status': iface_data.get('link_status', 'unknown'),
                                    'mtu': iface_data.get('mtu')
                                })
                    except Exception as e:
                        logger.debug(f"Could not get individual NIC {iface_name} for DataDomain {self.ip_address}: {e}")
            
            logger.debug(f"DataDomain {self.ip_address} - Found {len(nics)} NICs from v2.0 API")
            return nics
        except Exception as e:
            logger.debug(f"Could not get NICs from v2.0 API for DataDomain {self.ip_address}: {e}")
            # Fallback to v1.0 API
            return self._get_all_network_interfaces(headers, ssl_verify)
    
    def _get_replication_status(self, headers, ssl_verify):
        """Get replication context information
        
        Returns:
            dict: Replication status information
        """
        try:
            data = self._make_api_request('/rest/v1.0/dd-systems/0/replication/contexts', headers, ssl_verify)
            if not data:
                return None
            
            contexts = []
            context_list = data.get('context', []) or data.get('contexts', []) or []
            
            if isinstance(context_list, list):
                for ctx in context_list:
                    contexts.append({
                        'id': ctx.get('id'),
                        'name': ctx.get('name'),
                        'state': ctx.get('state', 'unknown'),
                        'direction': ctx.get('direction'),
                        'remote_host': ctx.get('remote_host'),
                        'remote_user': ctx.get('remote_user')
                    })
            
            repl_info = {
                'context_count': len(contexts),
                'contexts': contexts
            }
            
            logger.debug(f"DataDomain {self.ip_address} - Found {len(contexts)} replication contexts")
            return repl_info
        except Exception as e:
            logger.debug(f"Could not get replication status for DataDomain {self.ip_address}: {e}")
            return None
    
    def _get_hardware_status(self, headers, ssl_verify):
        """Get hardware component health status
        
        Returns:
            dict: Hardware health information
        """
        try:
            data = self._make_api_request('/rest/v1.0/dd-systems/0/hardware', headers, ssl_verify)
            if not data:
                return None
            
            hw_info = {
                'chassis_status': data.get('chassis', {}).get('status', 'unknown'),
                'controller_count': len(data.get('controllers', [])),
                'disk_count': len(data.get('disks', [])),
                'power_supply_count': len(data.get('power_supplies', [])),
                'fan_count': len(data.get('fans', [])),
                'overall_status': 'ok'  # Will be updated based on component status
            }
            
            # Check for failed components (using class constant)
            failed_components = []
            for component_type in ['power_supplies', 'fans', 'controllers']:
                components = data.get(component_type, [])
                if isinstance(components, list):
                    for comp in components:
                        if comp.get('status', '').lower() in self.FAILED_COMPONENT_STATES:
                            failed_components.append(f"{component_type}:{comp.get('id', 'unknown')}")
            
            if failed_components:
                hw_info['overall_status'] = 'warning'
                hw_info['failed_components'] = failed_components
            
            logger.debug(f"DataDomain {self.ip_address} - Hardware status: {hw_info.get('overall_status')}")
            return hw_info
        except Exception as e:
            logger.debug(f"Could not get hardware status for DataDomain {self.ip_address}: {e}")
            return None
    
    def _get_service_status(self, headers, ssl_verify):
        """Get system service status
        
        Returns:
            list: List of services with their status
        """
        try:
            data = self._make_api_request('/rest/v1.0/dd-systems/0/services', headers, ssl_verify)
            if not data:
                return []
            
            services = []
            service_list = data.get('service', []) or data.get('services', []) or []
            
            if isinstance(service_list, list):
                for svc in service_list:
                    services.append({
                        'name': svc.get('name', 'unknown'),
                        'status': svc.get('status', 'unknown'),
                        'enabled': svc.get('enabled', False)
                    })
            
            logger.debug(f"DataDomain {self.ip_address} - Found {len(services)} services")
            return services
        except Exception as e:
            logger.debug(f"Could not get service status for DataDomain {self.ip_address}: {e}")
            return []
    
    def get_health_status(self):
        try:
            # DataDomain REST API v1.0 with token authentication
            # If no token is configured, try to authenticate automatically
            new_token_generated = False
            if not self.token:
                logger.debug(f"Attempting automatic authentication for DataDomain {self.ip_address}")
                self.token = self.authenticate()
                if self.token:
                    new_token_generated = True
                else:
                    return self._format_response(status='error', hardware='error', cluster='error', 
                                                error='Authentication failed. Please check credentials.')
            
            headers = {
                'X-DD-AUTH-TOKEN': self.token,
                'Accept': 'application/json'
            }
            ssl_verify = get_ssl_verify(self.resolved_address)
            
            # Get system info from /rest/v1.0/system
            # This provides comprehensive system information including capacity, compression, etc.
            response = requests.get(
                f"{self.base_url}/rest/v1.0/system",
                headers=headers,
                verify=ssl_verify,
                timeout=10
            )
            
            if response.status_code != 200:
                error_msg = f'API error: {response.status_code}'
                if response.status_code == 401:
                    # Token invalid - try to re-authenticate once
                    logger.debug(f"Re-authenticating to DataDomain {self.ip_address}")
                    
                    new_token = self.authenticate()
                    if new_token:
                        self.token = new_token
                        new_token_generated = True
                        
                        # Retry the request with new token
                        headers['X-DD-AUTH-TOKEN'] = self.token
                        response = requests.get(
                            f"{self.base_url}/rest/v1.0/system",
                            headers=headers,
                            verify=ssl_verify,
                            timeout=10
                        )
                        
                        if response.status_code != 200:
                            error_msg = f'API error: {response.status_code}'
                            logger.error(f"DataDomain API error for {self.ip_address}: HTTP {response.status_code}")
                            return self._format_response(status='error', hardware='error', cluster='error', error=error_msg)
                    else:
                        error_msg = 'API error: 401 - Authentication failed. Please check credentials.'
                        logger.error(f"DataDomain authentication failed for {self.ip_address}")
                        return self._format_response(status='error', hardware='error', cluster='error', error=error_msg)
                else:
                    logger.error(f"DataDomain API error for {self.ip_address}: HTTP {response.status_code}")
                    try:
                        logger.error(f"Response text: {response.text[:MAX_RESPONSE_LOG_LENGTH]}")
                    except Exception:
                        logger.error("Response text unavailable")
                    return self._format_response(status='error', hardware='error', cluster='error', error=error_msg)
            
            data = response.json()
            
            # Extract system information
            os_version = data.get('version')
            system_name = data.get('name')
            model = data.get('model')
            
            # Extract capacity information from physical_capacity
            physical_capacity = data.get('physical_capacity', {})
            total_bytes = physical_capacity.get('total', 0)
            used_bytes = physical_capacity.get('used', 0)
            
            # Get logical capacity and compression factor for additional info
            logical_capacity = data.get('logical_capacity', {})
            compression_factor = data.get('compression_factor', 0) or 0
            
            logger.debug(f"DataDomain {self.ip_address} - System: {system_name}, Model: {model}, "
                        f"Version: {os_version}, Compression: {compression_factor:.2f}x")
            
            # Gather comprehensive system information using helper methods
            # Get HA status and partner node information
            ha_status = self._get_ha_status(headers, ssl_verify)
            
            # Get active alerts
            active_alerts = self._get_active_alerts(headers, ssl_verify)
            alert_count = len(active_alerts)
            
            # Get all network interfaces (includes management IPs)
            # Try v2.0 NICs API first, fallback to v1.0 networks API
            network_interfaces = self._get_network_nics(headers, ssl_verify)
            
            # If network interfaces API didn't work, try the legacy method for management IPs
            if not network_interfaces:
                for iface in self.MANAGEMENT_INTERFACES:
                    try:
                        iface_response = requests.get(
                            f"{self.base_url}/rest/v1.0/dd-systems/0/networks/{iface}",
                            headers=headers,
                            verify=ssl_verify,
                            timeout=10
                        )
                        
                        if iface_response.status_code == 200:
                            iface_data = iface_response.json()
                            ip_config = iface_data.get('ip_config', {})
                            ip_address = ip_config.get('ip_address')
                            if ip_address:
                                network_interfaces.append({
                                    'name': iface,
                                    'ip_address': ip_address,
                                    'enabled': iface_data.get('enabled', False)
                                })
                    except Exception as iface_error:
                        logger.debug(f"Could not get interface {iface} for DataDomain {self.ip_address}: {iface_error}")
            
            # Get replication status
            replication_status = self._get_replication_status(headers, ssl_verify)
            
            # Get hardware health status
            hardware_status = self._get_hardware_status(headers, ssl_verify)
            
            # Get service status
            service_status = self._get_service_status(headers, ssl_verify)
            
            # Determine overall hardware and cluster status based on gathered data
            hardware_health = 'ok'
            cluster_health = 'ok'
            
            # Check hardware status
            if hardware_status and hardware_status.get('overall_status') == 'warning':
                hardware_health = 'warning'
            
            # Check HA/cluster status
            if ha_status:
                ha_state = ha_status.get('state', '').lower()
                if ha_state in ['failed', 'error', 'critical']:
                    cluster_health = 'error'
                elif ha_state in ['degraded', 'warning']:
                    cluster_health = 'warning'
            
            # Check for critical alerts (using class constant)
            critical_alerts = [a for a in active_alerts 
                             if a.get('severity', '').lower() in self.CRITICAL_ALERT_SEVERITIES]
            if critical_alerts:
                if hardware_health == 'ok':
                    hardware_health = 'warning'
            
            # Build comprehensive response
            result = self._format_response(
                status='online',
                hardware=hardware_health,
                cluster=cluster_health,
                alerts=alert_count,
                total_tb=total_bytes / (1024**4),
                used_tb=used_bytes / (1024**4),
                os_version=os_version,
                all_mgmt_ips=network_interfaces if network_interfaces else None
            )
            
            # Add DataDomain-specific information to result
            if ha_status:
                result['ha_status'] = ha_status
            
            if active_alerts:
                result['active_alerts'] = active_alerts
            
            if replication_status:
                result['replication_status'] = replication_status
            
            if hardware_status:
                result['hardware_details'] = hardware_status
            
            if service_status:
                result['services'] = service_status
            
            # Add additional system details
            result['system_name'] = system_name
            result['model'] = model
            if compression_factor:
                result['compression_factor'] = compression_factor
            
            # Include new token if one was generated
            if new_token_generated:
                result['new_api_token'] = self.token
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting Dell DataDomain health status for {self.ip_address}: {e}")
            logger.error(traceback.format_exc())
            return self._format_response(status='error', hardware='error', cluster='error', error=str(e))


def get_client(vendor, ip_address, port=None, username=None, password=None, token=None):
    """Factory function to get appropriate storage client
    
    Args:
        vendor: Vendor type ('pure', 'netapp-ontap', 'netapp-storagegrid', 'dell-datadomain')
        ip_address: IP address or hostname of the storage system
        port: Port number (defaults to vendor-specific port if not specified)
        username: API username (for ONTAP and DataDomain)
        password: API password (for ONTAP and DataDomain)
        token: API token (for Pure Storage and StorageGRID)
    
    Returns:
        StorageClient: Appropriate storage client instance
    """
    clients = {
        'pure': PureStorageClient,
        'netapp-ontap': NetAppONTAPClient,
        'netapp-storagegrid': NetAppStorageGRIDClient,
        'dell-datadomain': DellDataDomainClient
    }
    
    client_class = clients.get(vendor)
    if not client_class:
        raise ValueError(f"Unknown vendor: {vendor}")
    
    # Use vendor-specific default port if not specified
    # VENDOR_DEFAULT_PORTS is imported from app.constants (single source of truth)
    if port is None:
        port = VENDOR_DEFAULT_PORTS.get(vendor, 443)
    
    return client_class(ip_address, port, username, password, token)
