"""Base storage client interface"""
from abc import ABC, abstractmethod

class StorageClient(ABC):
    """Abstract base class for storage system clients"""
    
    def __init__(self, ip_address, port=443, username=None, password=None, token=None):
        self.ip_address = ip_address
        self.port = port
        self.username = username
        self.password = password
        self.token = token
        self.base_url = f"https://{ip_address}:{port}"
    
    @abstractmethod
    def get_health_status(self):
        """Get health status of the storage system
        
        Returns:
            dict: {
                'hardware_status': 'ok|warning|error',
                'cluster_status': 'ok|warning|error',
                'alerts': int,
                'capacity_total_tb': float,
                'capacity_used_tb': float,
                'capacity_percent': float,
                'status': 'online|offline|error',
                'error': str (optional)
            }
        """
        pass
    
    def _format_response(self, status='ok', hardware='ok', cluster='ok', alerts=0, 
                        total_tb=0.0, used_tb=0.0, error=None, os_version=None, api_version=None, 
                        is_metrocluster=False):
        """Format standard response"""
        percent = (used_tb / total_tb * 100) if total_tb > 0 else 0
        response = {
            'status': status,
            'hardware_status': hardware,
            'cluster_status': cluster,
            'alerts': alerts,
            'capacity_total_tb': round(total_tb, 2),
            'capacity_used_tb': round(used_tb, 2),
            'capacity_percent': round(percent, 1),
            'error': error
        }
        if os_version:
            response['os_version'] = os_version
        if api_version:
            response['api_version'] = api_version
        if is_metrocluster:
            response['is_metrocluster'] = is_metrocluster
        return response
