"""API clients for different storage vendors"""
from app.api.base_client import StorageClient
from flask import current_app
import requests
import warnings
import logging

logger = logging.getLogger(__name__)

def get_ssl_verify():
    """Get SSL verification setting from app config, with custom certificates if available"""
    try:
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
            ssl_verify = get_ssl_verify()
            
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
        1. POST to /api/2.x/login with api_token in JSON body
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
            ssl_verify = get_ssl_verify()
            
            # For API 2.x, we need to login with the API token to get a session token
            # POST /api/2.x/login with api_token in the body
            login_data = {
                'api_token': self.token
            }
            
            response = requests.post(
                f"{self.base_url}/api/{api_version}/login",
                json=login_data,
                headers={
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
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
                return self._format_response(status='error', error='Kein API-Token konfiguriert. Bitte API-Token in den System-Einstellungen eingeben.')
            
            ssl_verify = get_ssl_verify()
            
            # Detect API version dynamically
            api_version = self.detect_api_version()
            
            # Authenticate to get session token for API 2.x
            session_token = self.authenticate(api_version)
            
            if not session_token:
                return self._format_response(
                    status='error', 
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
                return self._format_response(status='error', error=f'API error: {response.status_code}')
            
            # Extract OS version from array info
            array_data = response.json()
            os_version = None
            if 'items' in array_data and len(array_data['items']) > 0:
                item = array_data['items'][0]
                os_version = item.get('os') or item.get('version')
            
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
                hardware='ok',
                cluster='ok',
                alerts=0,
                total_tb=total_bytes / (1024**4),
                used_tb=used_bytes / (1024**4),
                os_version=os_version,
                api_version=api_version
            )
                
        except Exception as e:
            return self._format_response(status='error', error=str(e))


class NetAppONTAPClient(StorageClient):
    """NetApp ONTAP 9 client using REST API"""
    
    def get_health_status(self):
        try:
            if not self.username or not self.password:
                return self._format_response(status='error', error='No credentials configured')
            
            ssl_verify = get_ssl_verify()
            
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
                    error=f'Failed to connect to cluster: {str(cluster_error)}'
                )
            
            # Check for MetroCluster configuration
            is_metrocluster = False
            try:
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
            except Exception as mc_error:
                # MetroCluster endpoint might not be available if not configured
                logger.debug(f"Could not check MetroCluster status for {self.ip_address}: {mc_error}")
            
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
                is_metrocluster=is_metrocluster
            )
        except Exception as e:
            return self._format_response(status='error', error=str(e))


class NetAppStorageGRIDClient(StorageClient):
    """NetApp StorageGRID client - API v4
    
    Based on: https://webscalegmi.netapp.com/grid/apidocs.html
    """
    
    def get_health_status(self):
        try:
            # StorageGRID REST API v4
            if not self.token:
                return self._format_response(status='error', error='No API token configured')
            
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            ssl_verify = get_ssl_verify()
            
            # Get grid health/topology to verify connectivity and get version info
            response = requests.get(
                f"{self.base_url}/api/v4/grid/health/topology",
                headers=headers,
                verify=ssl_verify,
                timeout=10
            )
            
            if response.status_code != 200:
                return self._format_response(status='error', error=f'API error: {response.status_code}')
            
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
                hardware='ok',
                cluster='ok',
                alerts=0,
                total_tb=total_tb,
                used_tb=used_tb,
                os_version=os_version
            )
        except Exception as e:
            return self._format_response(status='error', error=str(e))


class DellDataDomainClient(StorageClient):
    """Dell DataDomain client"""
    
    def get_health_status(self):
        try:
            # DataDomain REST API
            auth = (self.username, self.password) if self.username and self.password else None
            if not auth:
                return self._format_response(status='error', error='No credentials configured')
            
            ssl_verify = get_ssl_verify()
            
            # Get system info
            response = requests.get(
                f"{self.base_url}/rest/v1.0/dd-systems",
                auth=auth,
                verify=ssl_verify,
                timeout=10
            )
            
            if response.status_code != 200:
                return self._format_response(status='error', error=f'API error: {response.status_code}')
            
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
            return self._format_response(status='error', error=str(e))


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
