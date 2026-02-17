"""Base storage client interface"""
from abc import ABC, abstractmethod
import socket
import logging

logger = logging.getLogger(__name__)

class StorageClient(ABC):
    """Abstract base class for storage system clients"""
    
    def __init__(self, ip_address, port=443, username=None, password=None, token=None):
        self.ip_address = ip_address  # Original configured address (may be IP or hostname)
        self.port = port
        self.username = username
        self.password = password
        self.token = token
        
        # Perform reverse DNS lookup if IP address is provided
        # If a DNS name is found, use it for API calls (enables SSL verification)
        self.resolved_address = self._resolve_address(ip_address)
        
        # Use resolved address for base_url (DNS name preferred over IP)
        self.base_url = f"https://{self.resolved_address}:{port}"
    
    def _resolve_address(self, address):
        """
        Resolve IP address to DNS name via reverse lookup.
        If address is already a hostname or reverse lookup fails, return original address.
        
        Args:
            address: IP address or hostname
            
        Returns:
            DNS name if reverse lookup succeeds, otherwise original address
        """
        from app.api.storage_clients import is_ip_address
        
        # If it's not an IP address, it's already a DNS name
        if not is_ip_address(address):
            logger.debug(f"Address {address} is already a DNS name")
            return address
        
        # Try reverse DNS lookup for IP addresses
        try:
            hostname, aliases, _ = socket.gethostbyaddr(address)
            if hostname:
                logger.info(f"Resolved IP {address} to DNS name: {hostname}")
                return hostname
        except socket.herror:
            logger.debug(f"No reverse DNS entry found for {address}")
        except Exception as e:
            logger.warning(f"Error during reverse DNS lookup for {address}: {e}")
        
        # Fall back to original IP address if resolution fails
        logger.debug(f"Using IP address {address} (no DNS name found)")
        return address
    
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
