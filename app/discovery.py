"""System discovery utilities for auto-detecting storage system details"""
import socket
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def reverse_dns_lookup(ip_address):
    """
    Perform reverse DNS lookup for an IP address
    
    Returns list of DNS names (PTR records, hostnames, aliases)
    """
    dns_names = []
    
    try:
        # Get hostname and aliases via gethostbyaddr
        hostname, aliases, _ = socket.gethostbyaddr(ip_address)
        
        if hostname:
            dns_names.append(hostname)
        
        if aliases:
            dns_names.extend(aliases)
            
    except socket.herror as e:
        logger.debug(f"Reverse DNS lookup failed for {ip_address}: {e}")
    except Exception as e:
        logger.warning(f"Error during reverse DNS lookup for {ip_address}: {e}")
    
    # Remove duplicates while preserving order
    seen = set()
    unique_names = []
    for name in dns_names:
        if name not in seen:
            seen.add(name)
            unique_names.append(name)
    
    return unique_names


def discover_pure_storage(ip_address, api_token, ssl_verify=False):
    """
    Discover Pure Storage FlashArray details via API
    
    Returns dict with cluster info, nodes, partner clusters, etc.
    """
    try:
        from pypureclient import flasharray
        
        client = flasharray.Client(
            target=ip_address,
            api_token=api_token,
            verify_ssl=ssl_verify,
            timeout=10
        )
        
        discovery_data = {
            'cluster_type': None,
            'node_count': 0,
            'site_count': 1,
            'dns_names': reverse_dns_lookup(ip_address),
            'all_ips': [ip_address],
            'node_details': [],
            'partner_info': None
        }
        
        # Get array info
        arrays_response = client.get_arrays()
        if isinstance(arrays_response, flasharray.ValidResponse):
            array_items = list(getattr(arrays_response, 'items', []))
            if array_items:
                array = array_items[0]
                
                # Detect cluster type (HA is default for Pure)
                discovery_data['cluster_type'] = 'ha'
        
        # Get controllers (nodes)
        try:
            controllers_response = client.get_controllers()
            if isinstance(controllers_response, flasharray.ValidResponse):
                controller_items = list(getattr(controllers_response, 'items', []))
                discovery_data['node_count'] = len(controller_items)
                
                for ctrl in controller_items:
                    node_info = {
                        'name': getattr(ctrl, 'name', 'Unknown'),
                        'status': getattr(ctrl, 'status', 'unknown'),
                        'mode': getattr(ctrl, 'mode', 'unknown'),
                        'model': getattr(ctrl, 'model', 'unknown'),
                        'version': getattr(ctrl, 'version', 'unknown')
                    }
                    discovery_data['node_details'].append(node_info)
        except Exception as e:
            logger.warning(f"Could not get controller info: {e}")
        
        # Try to detect ActiveCluster (requires additional API calls)
        try:
            # ActiveCluster pods would be detected here
            pods_response = client.get_pods()
            if isinstance(pods_response, flasharray.ValidResponse):
                pod_items = list(getattr(pods_response, 'items', []))
                if pod_items:
                    # If pods exist, might be ActiveCluster
                    discovery_data['cluster_type'] = 'active-cluster'
        except:
            pass  # Not all arrays support pods
        
        return discovery_data
        
    except Exception as e:
        logger.error(f"Pure Storage discovery error for {ip_address}: {e}")
        return {
            'error': str(e),
            'dns_names': reverse_dns_lookup(ip_address),
            'all_ips': [ip_address]
        }


def discover_netapp_ontap(ip_address, username, password, ssl_verify=False):
    """
    Discover NetApp ONTAP cluster details via API
    
    Returns dict with cluster info, nodes, MetroCluster partners, etc.
    """
    try:
        from netapp_ontap import config, HostConnection
        from netapp_ontap.resources import Cluster, Node, Aggregate
        
        config.CONNECTION = HostConnection(
            host=ip_address,
            username=username,
            password=password,
            verify=ssl_verify
        )
        
        discovery_data = {
            'cluster_type': 'local',
            'node_count': 0,
            'site_count': 1,
            'dns_names': reverse_dns_lookup(ip_address),
            'all_ips': [ip_address],
            'node_details': [],
            'partner_info': None
        }
        
        # Get cluster info
        try:
            cluster = Cluster()
            cluster.get()
            
            # Check for MetroCluster
            if hasattr(cluster, 'metrocluster') and cluster.metrocluster:
                discovery_data['cluster_type'] = 'metrocluster'
                discovery_data['site_count'] = 2
        except Exception as e:
            logger.warning(f"Could not get cluster info: {e}")
        
        # Get nodes
        try:
            nodes = Node.get_collection()
            node_list = list(nodes)
            discovery_data['node_count'] = len(node_list)
            
            for node in node_list:
                # Get management IPs
                node_ips = []
                if hasattr(node, 'management_interfaces'):
                    for intf in node.management_interfaces:
                        if hasattr(intf, 'ip') and hasattr(intf.ip, 'address'):
                            node_ips.append(intf.ip.address)
                            discovery_data['all_ips'].append(intf.ip.address)
                            
                            # DNS lookup for each IP
                            dns_names = reverse_dns_lookup(intf.ip.address)
                            discovery_data['dns_names'].extend(dns_names)
                
                node_info = {
                    'name': node.name if hasattr(node, 'name') else 'Unknown',
                    'uuid': node.uuid if hasattr(node, 'uuid') else None,
                    'state': getattr(node, 'state', 'unknown'),
                    'model': getattr(node, 'model', 'unknown'),
                    'serial_number': getattr(node, 'serial_number', 'unknown'),
                    'ips': node_ips
                }
                discovery_data['node_details'].append(node_info)
        except Exception as e:
            logger.warning(f"Could not get node info: {e}")
        
        # Deduplicate DNS names and IPs
        discovery_data['dns_names'] = list(set(discovery_data['dns_names']))
        discovery_data['all_ips'] = list(set(discovery_data['all_ips']))
        
        return discovery_data
        
    except Exception as e:
        logger.error(f"NetApp ONTAP discovery error for {ip_address}: {e}")
        return {
            'error': str(e),
            'dns_names': reverse_dns_lookup(ip_address),
            'all_ips': [ip_address]
        }


def discover_storagegrid(ip_address, api_token, ssl_verify=False):
    """
    Discover NetApp StorageGRID details via API
    
    Returns dict with grid info, sites, nodes, etc.
    """
    import requests
    
    try:
        discovery_data = {
            'cluster_type': 'single-site',
            'node_count': 0,
            'site_count': 1,
            'dns_names': reverse_dns_lookup(ip_address),
            'all_ips': [ip_address],
            'node_details': [],
            'partner_info': None
        }
        
        # StorageGRID uses a different API structure
        # Would need to authenticate and query grid topology
        # This is a simplified version
        
        base_url = f"https://{ip_address}"
        headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
        }
        
        # Get grid topology (requires proper authentication flow)
        # For now, return basic info
        logger.info(f"StorageGRID discovery not fully implemented for {ip_address}")
        
        return discovery_data
        
    except Exception as e:
        logger.error(f"StorageGRID discovery error for {ip_address}: {e}")
        return {
            'error': str(e),
            'dns_names': reverse_dns_lookup(ip_address),
            'all_ips': [ip_address]
        }


def discover_datadomain(ip_address, username, password, ssl_verify=False):
    """
    Discover Dell DataDomain details via API
    
    Returns dict with system info
    """
    import requests
    
    try:
        discovery_data = {
            'cluster_type': None,
            'node_count': 1,
            'site_count': 1,
            'dns_names': reverse_dns_lookup(ip_address),
            'all_ips': [ip_address],
            'node_details': [],
            'partner_info': None
        }
        
        # DataDomain REST API discovery
        # This would require proper authentication and API calls
        logger.info(f"DataDomain discovery not fully implemented for {ip_address}")
        
        return discovery_data
        
    except Exception as e:
        logger.error(f"DataDomain discovery error for {ip_address}: {e}")
        return {
            'error': str(e),
            'dns_names': reverse_dns_lookup(ip_address),
            'all_ips': [ip_address]
        }


def auto_discover_system(vendor, ip_address, username=None, password=None, api_token=None, ssl_verify=False):
    """
    Main auto-discovery function that routes to vendor-specific discovery
    
    Args:
        vendor: Storage vendor type
        ip_address: Primary management IP
        username: API username (if applicable)
        password: API password (if applicable)
        api_token: API token (if applicable)
        ssl_verify: Whether to verify SSL certificates
    
    Returns:
        Dictionary with discovered information
    """
    try:
        if vendor == 'pure':
            if not api_token:
                return {'error': 'API token required for Pure Storage'}
            return discover_pure_storage(ip_address, api_token, ssl_verify)
        
        elif vendor == 'netapp-ontap':
            if not (username and password):
                return {'error': 'Username and password required for NetApp ONTAP'}
            return discover_netapp_ontap(ip_address, username, password, ssl_verify)
        
        elif vendor == 'netapp-storagegrid':
            if not api_token:
                return {'error': 'API token required for StorageGRID'}
            return discover_storagegrid(ip_address, api_token, ssl_verify)
        
        elif vendor == 'dell-datadomain':
            if not (username and password):
                return {'error': 'Username and password required for DataDomain'}
            return discover_datadomain(ip_address, username, password, ssl_verify)
        
        else:
            return {'error': f'Unknown vendor: {vendor}'}
    
    except Exception as e:
        logger.error(f"Auto-discovery error for {vendor} at {ip_address}: {e}")
        return {
            'error': str(e),
            'dns_names': reverse_dns_lookup(ip_address),
            'all_ips': [ip_address]
        }
