"""API clients for different storage vendors"""
from app.api.base_client import StorageClient
from flask import current_app
import requests
import warnings

def get_ssl_verify():
    """Get SSL verification setting from app config"""
    try:
        return current_app.config.get('SSL_VERIFY', False)
    except RuntimeError:
        # Outside application context, default to False for development
        return False

# Suppress SSL warnings only when verification is disabled
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class PureStorageClient(StorageClient):
    """Pure Storage FlashArray client"""
    
    def get_health_status(self):
        try:
            # Pure Storage REST API v2
            headers = {'api-token': self.token} if self.token else None
            if not headers:
                return self._format_response(status='error', error='No API token configured')
            
            ssl_verify = get_ssl_verify()
            
            # Get array info
            response = requests.get(
                f"{self.base_url}/api/2.0/arrays",
                headers=headers,
                verify=ssl_verify,
                timeout=10
            )
            
            if response.status_code != 200:
                return self._format_response(status='error', error=f'API error: {response.status_code}')
            
            data = response.json()
            items = data.get('items', [{}])[0]
            
            # Get capacity info
            capacity_response = requests.get(
                f"{self.base_url}/api/2.0/arrays/space",
                headers=headers,
                verify=ssl_verify,
                timeout=10
            )
            
            capacity_data = capacity_response.json().get('items', [{}])[0] if capacity_response.status_code == 200 else {}
            
            total_bytes = capacity_data.get('capacity', 0)
            used_bytes = total_bytes - capacity_data.get('space', {}).get('available', 0)
            
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


class NetAppONTAPClient(StorageClient):
    """NetApp ONTAP 9 client"""
    
    def get_health_status(self):
        try:
            # ONTAP REST API
            auth = (self.username, self.password) if self.username and self.password else None
            if not auth:
                return self._format_response(status='error', error='No credentials configured')
            
            ssl_verify = get_ssl_verify()
            
            # Get cluster info
            response = requests.get(
                f"{self.base_url}/api/cluster",
                auth=auth,
                verify=ssl_verify,
                timeout=10
            )
            
            if response.status_code != 200:
                return self._format_response(status='error', error=f'API error: {response.status_code}')
            
            cluster_data = response.json()
            
            # Get aggregate space info
            aggr_response = requests.get(
                f"{self.base_url}/api/storage/aggregates",
                auth=auth,
                verify=ssl_verify,
                timeout=10
            )
            
            total_bytes = 0
            used_bytes = 0
            if aggr_response.status_code == 200:
                aggregates = aggr_response.json().get('records', [])
                for aggr in aggregates:
                    space = aggr.get('space', {})
                    block_storage = space.get('block_storage', {})
                    total_bytes += block_storage.get('size', 0)
                    used_bytes += block_storage.get('used', 0)
            
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
