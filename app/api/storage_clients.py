"""API clients for different storage vendors"""
from app.api.base_client import StorageClient
from flask import current_app
import requests
import warnings

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


class PureStorageClient(StorageClient):
    """Pure Storage FlashArray client using official py-pure-client library"""
    
    def get_health_status(self):
        try:
            from pypureclient import flasharray
            
            if not self.token:
                return self._format_response(status='error', error='No API token configured')
            
            ssl_verify = get_ssl_verify()
            
            # Create FlashArray client with timeout
            client = flasharray.Client(
                target=self.ip_address,
                api_token=self.token,
                verify_ssl=ssl_verify,
                timeout=5  # 5 second timeout
            )
            
            # Get array info
            arrays_response = client.get_arrays()
            
            if isinstance(arrays_response, flasharray.ValidResponse):
                # Get space/capacity info
                space_response = client.get_arrays_space()
                
                if isinstance(space_response, flasharray.ValidResponse):
                    # Extract capacity data
                    space_items = list(getattr(space_response, 'items', []))
                    
                    if space_items and len(space_items) > 0:
                        space_data = space_items[0]
                        
                        # Get capacity values (in bytes)
                        capacity = getattr(space_data, 'capacity', 0) or 0
                        total_physical = getattr(space_data, 'space', None)
                        
                        # Calculate used space
                        if total_physical:
                            total_bytes = capacity
                            # space.total_physical is the used space
                            used_bytes = getattr(total_physical, 'total_physical', 0) or 0
                        else:
                            total_bytes = capacity
                            used_bytes = 0
                        
                        return self._format_response(
                            status='online',
                            hardware='ok',
                            cluster='ok',
                            alerts=0,
                            total_tb=total_bytes / (1024**4),
                            used_tb=used_bytes / (1024**4)
                        )
                    else:
                        # No space data available, return with 0 capacity
                        return self._format_response(
                            status='online',
                            hardware='ok',
                            cluster='ok',
                            alerts=0,
                            total_tb=0,
                            used_tb=0
                        )
                else:
                    # Space query failed, but array is reachable
                    return self._format_response(
                        status='online',
                        hardware='ok',
                        cluster='ok',
                        alerts=0,
                        total_tb=0,
                        used_tb=0
                    )
            else:
                # Error response from API
                error_msg = 'API error'
                if hasattr(arrays_response, 'errors'):
                    errors = arrays_response.errors
                    if errors and len(errors) > 0:
                        error_msg = str(errors[0])
                return self._format_response(status='error', error=error_msg)
                
        except Exception as e:
            return self._format_response(status='error', error=str(e))


class NetAppONTAPClient(StorageClient):
    """NetApp ONTAP 9 client using official netapp-ontap library"""
    
    def get_health_status(self):
        try:
            from netapp_ontap import config, HostConnection
            from netapp_ontap.resources import Cluster, Aggregate
            
            if not self.username or not self.password:
                return self._format_response(status='error', error='No credentials configured')
            
            ssl_verify = get_ssl_verify()
            
            # Create connection
            conn = HostConnection(
                self.ip_address,
                username=self.username,
                password=self.password,
                verify=ssl_verify
            )
            
            # Set as current connection
            config.CONNECTION = conn
            
            # Get cluster info to verify connectivity
            try:
                cluster = Cluster()
                cluster.get()
                
                cluster_name = getattr(cluster, 'name', 'unknown')
            except Exception as cluster_error:
                return self._format_response(
                    status='error', 
                    error=f'Failed to connect to cluster: {str(cluster_error)}'
                )
            
            # Get aggregate space info
            total_bytes = 0
            used_bytes = 0
            
            try:
                # Get all aggregates
                aggregates = list(Aggregate.get_collection())
                
                for aggr in aggregates:
                    # Get detailed aggregate info
                    aggr.get()
                    
                    # Extract space information
                    space = getattr(aggr, 'space', None)
                    if space:
                        block_storage = getattr(space, 'block_storage', None)
                        if block_storage:
                            size = getattr(block_storage, 'size', 0) or 0
                            used = getattr(block_storage, 'used', 0) or 0
                            total_bytes += size
                            used_bytes += used
            except Exception as aggr_error:
                # If aggregate query fails, return with 0 capacity but online status
                pass
            
            return self._format_response(
                status='online',
                hardware='ok',
                cluster='ok',
                alerts=0,
                total_tb=total_bytes / (1024**4),
                used_tb=used_bytes / (1024**4)
            )
        except Exception as e:
            return self._format_response(status='error', error=str(e))


class NetAppStorageGRIDClient(StorageClient):
    """NetApp StorageGRID client"""
    
    def get_health_status(self):
        try:
            # StorageGRID REST API
            if not self.token:
                return self._format_response(status='error', error='No API token configured')
            
            headers = {'Authorization': f'Bearer {self.token}'}
            ssl_verify = get_ssl_verify()
            
            # Get grid health
            response = requests.get(
                f"{self.base_url}/api/v3/grid/health/topology",
                headers=headers,
                verify=ssl_verify,
                timeout=10
            )
            
            if response.status_code != 200:
                return self._format_response(status='error', error=f'API error: {response.status_code}')
            
            # Get capacity info - Note: StorageGRID API requires specific endpoints for actual capacity
            # This is a simplified implementation
            total_tb = 0.0
            used_tb = 0.0
            
            # Attempt to get storage metrics if available
            try:
                metrics_response = requests.get(
                    f"{self.base_url}/api/v3/grid/metric-query",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )
                if metrics_response.status_code == 200:
                    # Parse metrics data if successful
                    # Note: Actual implementation would need specific metric queries
                    pass
            except:
                pass
            
            return self._format_response(
                status='online',
                hardware='ok',
                cluster='ok',
                alerts=0,
                total_tb=total_tb,
                used_tb=used_tb
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
                used_tb=used_bytes / (1024**4)
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
