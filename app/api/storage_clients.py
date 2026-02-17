"""API clients for different storage vendors"""
from app.api.base_client import StorageClient
from flask import current_app
import requests
import warnings
import logging
import ipaddress

logger = logging.getLogger(__name__)

# StorageGRID API health state constants
# States that indicate a healthy grid/node
STORAGEGRID_HEALTHY_GRID_STATES = {'healthy', 'ok', 'normal'}

# Node states that indicate a healthy/connected node
STORAGEGRID_HEALTHY_NODE_STATES = {'connected', 'online', 'ok', 'healthy'}

# Alert states that are considered active/unresolved
# Based on StorageGRID API v4 alert states
STORAGEGRID_ACTIVE_ALERT_STATES = {'active', 'triggered', 'firing'}


def is_ip_address(address):
    """Check if the given address is an IP address (IPv4 or IPv6)
    
    Args:
        address: String to check (IP address or hostname)
        
    Returns:
        bool: True if address is an IP address, False if it's a hostname/DNS name
    """
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def get_ssl_verify(target_address=None):
    """Get SSL verification setting from app config, with custom certificates if available
    
    Args:
        target_address: Optional IP address or hostname being connected to.
                       If provided and it's an IP address, SSL verification will be disabled
                       automatically (even if SSL_VERIFY=true) since IP addresses don't match
                       certificate common names.
    
    Returns:
        bool or str: False to disable SSL verification, True to use system defaults,
                    or path to custom CA bundle
    """
    try:
        # If connecting to an IP address, SSL verification must be disabled
        # because certificates are issued to DNS names, not IP addresses
        if target_address and is_ip_address(target_address):
            logger.debug(f"Disabling SSL verification for IP address: {target_address}")
            return False
        
        ssl_verify_enabled = current_app.config.get('SSL_VERIFY', False)
        
        if not ssl_verify_enabled:
            return False
        
        # Try to get custom certificates
        try:
            from app.ssl_utils import get_ssl_context
            return get_ssl_context()
        except Exception:
            # If custom certificates fail, use default
            return True
            
    except RuntimeError:
        # Outside application context, default to False for development
        return False

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
                # Get full version with Purity/FA prefix
                os_version = item.get('os') or item.get('version')
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
            # REST API v2: GET /api/2.x/alerts
            alerts_count = 0
            try:
                alerts_response = requests.get(
                    f"{self.base_url}/api/{api_version}/alerts",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )
                
                if alerts_response.status_code == 200:
                    alerts_data = alerts_response.json()
                    # Count open alerts (those that are not closed)
                    items = alerts_data.get('items', [])
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
                    
                    if items:
                        is_active_cluster = True
                        for pod in items:
                            pod_info = {
                                'name': pod.get('name'),
                                'source': pod.get('source'),
                                'arrays': []
                            }
                            pods_info.append(pod_info)
                        
                        logger.info(f"ActiveCluster detected for {self.ip_address} with {len(pods_info)} pods")
            except Exception as pods_error:
                # Pods endpoint might not be available on all arrays
                logger.debug(f"Could not check pods for {self.ip_address}: {pods_error}")
            
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
                pods_info=pods_info if pods_info else None
            )
                
        except Exception as e:
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
            is_metrocluster = False
            metrocluster_info = {}
            metrocluster_nodes = []
            metrocluster_dr_groups = []
            
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
                    # Check if MetroCluster is configured
                    configuration_state = metrocluster_data.get('configuration_state')
                    if configuration_state and configuration_state != 'not_configured':
                        is_metrocluster = True
                        logger.info(f"MetroCluster detected for {self.ip_address}: {configuration_state}")
                        
                        # Store MetroCluster configuration info
                        metrocluster_info = {
                            'configuration_state': configuration_state,
                            'mode': metrocluster_data.get('mode'),
                            'local_cluster_name': metrocluster_data.get('local', {}).get('cluster', {}).get('name'),
                            'partner_cluster_name': metrocluster_data.get('partner', {}).get('cluster', {}).get('name'),
                        }
                        
                        # Get MetroCluster nodes information
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
                                    node_info = {
                                        'name': node.get('name'),
                                        'cluster': node.get('cluster', {}).get('name'),
                                        'dr_group_id': node.get('dr_group_id'),
                                        'dr_partner': node.get('dr_partner', {}).get('name'),
                                        'ha_partner': node.get('ha_partner', {}).get('name'),
                                        'type': 'metrocluster-node'
                                    }
                                    metrocluster_nodes.append(node_info)
                                
                                logger.info(f"Found {len(metrocluster_nodes)} MetroCluster nodes for {self.ip_address}")
                        except Exception as mc_nodes_error:
                            logger.warning(f"Could not get MetroCluster nodes for {self.ip_address}: {mc_nodes_error}")
                        
                        # Get MetroCluster DR groups information
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
                                        'local_nodes': [n.get('name') for n in dr_group.get('local', {}).get('nodes', [])],
                                        'partner_nodes': [n.get('name') for n in dr_group.get('partner', {}).get('nodes', [])],
                                    }
                                    metrocluster_dr_groups.append(dr_group_info)
                                
                                logger.info(f"Found {len(metrocluster_dr_groups)} MetroCluster DR groups for {self.ip_address}")
                        except Exception as dr_groups_error:
                            logger.warning(f"Could not get MetroCluster DR groups for {self.ip_address}: {dr_groups_error}")
            except Exception as mc_error:
                # MetroCluster endpoint might not be available if not configured
                logger.debug(f"Could not check MetroCluster status for {self.ip_address}: {mc_error}")
            
            # Get regular cluster nodes information (with model, serial number, etc.)
            # REST API: GET /api/cluster/nodes?fields=name,state,model,serial_number,version
            cluster_nodes = []
            try:
                nodes_response = requests.get(
                    f"{self.base_url}/api/cluster/nodes",
                    auth=auth,
                    headers=headers,
                    params={'fields': 'name,state,model,serial_number,version'},
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
                        
                        node_info = {
                            'name': node.get('name', 'Unknown'),
                            'status': node.get('state', 'unknown'),
                            'model': node.get('model', 'unknown'),
                            'serial': node.get('serial_number', 'unknown'),
                            'version': version_full,
                            'type': 'cluster-node'
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
                controllers=metrocluster_nodes if metrocluster_nodes else cluster_nodes  # Use MC nodes if available, otherwise regular cluster nodes
            )
        except Exception as e:
            return self._format_response(status='error', hardware='error', cluster='error', error=str(e))


class NetAppStorageGRIDClient(StorageClient):
    """NetApp StorageGRID client - API v4
    
    Based on: https://webscalegmi.netapp.com/grid/apidocs.html
    """
    
    def get_health_status(self):
        try:
            # StorageGRID REST API v4
            if not self.token:
                return self._format_response(status='error', hardware='error', cluster='error', error='No API token configured')
            
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            ssl_verify = get_ssl_verify(self.resolved_address)
            
            # Get grid health to verify connectivity
            # API: GET /api/v4/grid/health
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
                    
                    # Check overall health status
                    health_state = data.get('health', 'unknown')
                    if health_state and health_state.lower() not in STORAGEGRID_HEALTHY_GRID_STATES:
                        hardware_status = 'warning'
                        logger.warning(f"StorageGRID health issue for {self.ip_address}: {health_state}")
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
                return self._format_response(status='error', hardware='error', cluster='error', error=f'API error: {response.status_code}')
            
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
            
            # Get alerts count
            # API: GET /api/v4/grid/alerts
            alerts_count = 0
            try:
                alerts_response = requests.get(
                    f"{self.base_url}/api/v4/grid/alerts",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )
                
                if alerts_response.status_code == 200:
                    alerts_data = alerts_response.json()
                    alerts_list = alerts_data.get('data', [])
                    # Count active/unresolved alerts
                    alerts_count = sum(1 for alert in alerts_list if alert.get('state', '').lower() in STORAGEGRID_ACTIVE_ALERT_STATES)
                    
                    if alerts_count > 0:
                        logger.info(f"Found {alerts_count} active alerts for StorageGRID {self.ip_address}")
                        hardware_status = 'warning'
            except Exception as alerts_error:
                logger.warning(f"Could not get StorageGRID alerts for {self.ip_address}: {alerts_error}")
            
            # Get node health information
            # API: GET /api/v4/grid/node-health
            nodes_info = []
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
                        node_type = node.get('type', 'unknown')
                        
                        node_info = {
                            'name': node_name,
                            'id': node_id,
                            'type': node_type,
                            'status': node_state
                        }
                        
                        # Check node health
                        if node_state and node_state.lower() not in STORAGEGRID_HEALTHY_NODE_STATES:
                            hardware_status = 'warning'
                            logger.warning(f"StorageGRID node {node_name} state: {node_state}")
                        
                        nodes_info.append(node_info)
                    
                    logger.info(f"Found {len(nodes_info)} nodes in StorageGRID {self.ip_address}")
            except Exception as node_health_error:
                logger.warning(f"Could not get StorageGRID node health for {self.ip_address}: {node_health_error}")
            
            # Get grid sites information to determine if multi-site
            # API: GET /api/v4/grid/sites
            site_count = 1
            sites_info = []
            try:
                sites_response = requests.get(
                    f"{self.base_url}/api/v4/grid/sites",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )
                
                if sites_response.status_code == 200:
                    sites_data = sites_response.json()
                    sites_list = sites_data.get('data', [])
                    
                    if sites_list:
                        site_count = len(sites_list)
                        for site in sites_list:
                            site_info = {
                                'id': site.get('id'),
                                'name': site.get('name', 'Unknown Site')
                            }
                            sites_info.append(site_info)
                        
                        logger.info(f"Found {site_count} sites in StorageGRID {self.ip_address}")
            except Exception as sites_error:
                logger.warning(f"Could not get StorageGRID sites for {self.ip_address}: {sites_error}")
            
            # Get capacity info from storage usage API
            total_bytes = 0
            used_bytes = 0
            
            try:
                # Try multiple endpoints for capacity information
                # First try: /api/v4/grid/storage-usage
                usage_response = requests.get(
                    f"{self.base_url}/api/v4/grid/storage-usage",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )
                
                if usage_response.status_code == 200:
                    usage_data = usage_response.json()
                    logger.info(f"StorageGRID usage response: {usage_data}")
                    
                    # Parse storage usage data using helper function
                    # StorageGRID API v4 returns data in 'data' object or at root level
                    data = usage_data.get('data', usage_data)
                    
                    # Try different possible field names for total capacity
                    total_bytes = extract_field_with_fallbacks(data, [
                        'storageTotalBytes', 
                        'totalCapacityBytes', 
                        'totalCapacity'
                    ]) or 0
                    
                    # Try different possible field names for used capacity
                    used_bytes = extract_field_with_fallbacks(data, [
                        'storageUsedBytes',
                        'usedCapacityBytes',
                        'objectDataUsedBytes',
                        'usedCapacity'
                    ]) or 0
                    
                    # If we still don't have capacity, try alternative approach
                    if total_bytes == 0:
                        # Try getting capacity from storage nodes
                        try:
                            nodes_response = requests.get(
                                f"{self.base_url}/api/v4/grid/storage-nodes",
                                headers=headers,
                                verify=ssl_verify,
                                timeout=10
                            )
                            
                            if nodes_response.status_code == 200:
                                nodes_data = nodes_response.json()
                                nodes = nodes_data.get('data', [])
                                
                                for node in nodes:
                                    # Sum up capacity from all storage nodes
                                    storage = node.get('storage', {})
                                    total_bytes += storage.get('totalCapacity', 0) or 0
                                    used_bytes += storage.get('usedCapacity', 0) or 0
                        except Exception as nodes_error:
                            logger.warning(f"Could not get StorageGRID nodes capacity: {nodes_error}")
                    
                    # Log for debugging
                    logger.info(f"StorageGRID capacity: total={total_bytes} bytes, used={used_bytes} bytes")
                        
            except Exception as usage_error:
                # Log but don't fail if we can't get capacity
                logger.warning(f"Could not get StorageGRID storage usage: {usage_error}")
            
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
                sites_info=sites_info if sites_info else None
            )
        except Exception as e:
            return self._format_response(status='error', hardware='error', cluster='error', error=str(e))


class DellDataDomainClient(StorageClient):
    """Dell DataDomain client"""
    
    def get_health_status(self):
        try:
            # DataDomain REST API
            auth = (self.username, self.password) if self.username and self.password else None
            if not auth:
                return self._format_response(status='error', hardware='error', cluster='error', error='No credentials configured')
            
            ssl_verify = get_ssl_verify(self.resolved_address)
            
            # Get system info
            response = requests.get(
                f"{self.base_url}/rest/v1.0/dd-systems",
                auth=auth,
                verify=ssl_verify,
                timeout=10
            )
            
            if response.status_code != 200:
                return self._format_response(status='error', hardware='error', cluster='error', error=f'API error: {response.status_code}')
            
            data = response.json()
            
            # Extract OS version from system info using helper function
            os_version = None
            if 'dd_systems' in data and len(data['dd_systems']) > 0:
                system = data['dd_systems'][0]
                os_version = extract_field_with_fallbacks(system, ['version', 'os_version'])
            
            # Get capacity info
            capacity_response = requests.get(
                f"{self.base_url}/rest/v1.0/dd-systems/0/file-systems",
                auth=auth,
                verify=ssl_verify,
                timeout=10
            )
            
            total_bytes = 0
            used_bytes = 0
            if capacity_response.status_code == 200:
                fs_data = capacity_response.json()
                filesystems = fs_data.get('file_system', [])
                for fs in filesystems:
                    total_bytes += fs.get('total_physical_capacity', {}).get('value', 0)
                    used_bytes += fs.get('used_physical_capacity', {}).get('value', 0)
            
            return self._format_response(
                status='online',
                hardware='ok',
                cluster='ok',
                alerts=0,
                total_tb=total_bytes / (1024**4),
                used_tb=used_bytes / (1024**4),
                os_version=os_version
            )
        except Exception as e:
            return self._format_response(status='error', hardware='error', cluster='error', error=str(e))


def get_client(vendor, ip_address, port=443, username=None, password=None, token=None):
    """Factory function to get appropriate storage client"""
    clients = {
        'pure': PureStorageClient,
        'netapp-ontap': NetAppONTAPClient,
        'netapp-storagegrid': NetAppStorageGRIDClient,
        'dell-datadomain': DellDataDomainClient
    }
    
    client_class = clients.get(vendor)
    if not client_class:
        raise ValueError(f"Unknown vendor: {vendor}")
    
    return client_class(ip_address, port, username, password, token)
