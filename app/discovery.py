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
                
                # Filter out shelf controllers (names containing .SC)
                actual_nodes = [ctrl for ctrl in controller_items if '.SC' not in getattr(ctrl, 'name', '')]
                discovery_data['node_count'] = len(actual_nodes)
                
                for ctrl in actual_nodes:
                    ctrl_name = getattr(ctrl, 'name', 'Unknown')
                    node_info = {
                        'name': ctrl_name,
                        'status': getattr(ctrl, 'status', 'unknown'),
                        'mode': getattr(ctrl, 'mode', 'unknown'),
                        'model': getattr(ctrl, 'model', 'unknown'),
                        'version': getattr(ctrl, 'version', 'unknown'),
                        'ips': []
                    }
                    
                    # Try to get network interfaces for this controller
                    try:
                        network_interfaces_response = client.get_network_interfaces(
                            filter="services='management'"
                        )
                        if isinstance(network_interfaces_response, flasharray.ValidResponse):
                            interface_items = list(getattr(network_interfaces_response, 'items', []))
                            for intf in interface_items:
                                # Check if interface belongs to this controller
                                intf_name = getattr(intf, 'name', '')
                                if intf_name.startswith(ctrl_name):
                                    intf_address = getattr(intf, 'address', None)
                                    if intf_address:
                                        node_info['ips'].append(intf_address)
                                        # Add to all_ips list
                                        if intf_address not in discovery_data['all_ips']:
                                            discovery_data['all_ips'].append(intf_address)
                                        # Perform DNS lookup for node IP
                                        dns_names = reverse_dns_lookup(intf_address)
                                        discovery_data['dns_names'].extend(dns_names)
                    except Exception as net_error:
                        logger.debug(f"Could not get network interfaces for {ctrl_name}: {net_error}")
                    
                    discovery_data['node_details'].append(node_info)
        except Exception as e:
            logger.warning(f"Could not get controller info: {e}")
        
        # Try to detect ActiveCluster and get peer cluster info
        try:
            # ActiveCluster pods would be detected here
            pods_response = client.get_pods()
            if isinstance(pods_response, flasharray.ValidResponse):
                pod_items = list(getattr(pods_response, 'items', []))
                if pod_items:
                    # If pods exist, might be ActiveCluster
                    discovery_data['cluster_type'] = 'active-cluster'
                    
                    # Try to get pod array info to find peer cluster
                    for pod in pod_items:
                        try:
                            pod_arrays_response = client.get_pods_arrays(pod_names=[getattr(pod, 'name', '')])
                            if isinstance(pod_arrays_response, flasharray.ValidResponse):
                                pod_array_items = list(getattr(pod_arrays_response, 'items', []))
                                for pod_array in pod_array_items:
                                    array_name = getattr(pod_array, 'name', None)
                                    # Store partner array name for matching later
                                    if array_name and discovery_data['partner_info'] is None:
                                        discovery_data['partner_info'] = {
                                            'name': array_name,
                                            'status': getattr(pod_array, 'status', 'unknown')
                                        }
                                        break
                        except Exception as pod_error:
                            logger.debug(f"Could not get pod array info: {pod_error}")
                    
        except:
            pass  # Not all arrays support pods
        
        # Deduplicate DNS names
        discovery_data['dns_names'] = list(set(discovery_data['dns_names']))
        
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
            'cluster_type': None,  # Will be set based on HA and MetroCluster detection
            'node_count': 0,
            'site_count': 1,
            'dns_names': reverse_dns_lookup(ip_address),
            'all_ips': [ip_address],
            'node_details': [],
            'partner_info': None,
            'ha_enabled': False,
            'metrocluster_enabled': False
        }
        
        # Get cluster info and check for HA and MetroCluster
        try:
            cluster = Cluster()
            cluster.get()
            
            # Check for HA (High Availability) - typically 2+ nodes
            # HA is the default for ONTAP clusters with 2 or more nodes
            discovery_data['ha_enabled'] = True  # Will be confirmed after node count
            
            # Check for MetroCluster
            if hasattr(cluster, 'metrocluster') and cluster.metrocluster:
                discovery_data['metrocluster_enabled'] = True
                discovery_data['site_count'] = 2
                
                # Try to get MetroCluster partner info
                try:
                    if hasattr(cluster.metrocluster, 'configuration_state'):
                        mc_state = cluster.metrocluster.configuration_state
                    
                    # Try to get partner cluster information
                    # Note: This would require MetroCluster specific API calls
                    # For now, we mark that MetroCluster is enabled
                except Exception as mc_error:
                    logger.debug(f"Could not get MetroCluster details: {mc_error}")
        except Exception as e:
            logger.warning(f"Could not get cluster info: {e}")
        
        # Get nodes
        try:
            nodes = Node.get_collection()
            node_list = list(nodes)
            discovery_data['node_count'] = len(node_list)
            
            # Determine HA based on node count (2+ nodes = HA)
            if len(node_list) >= 2:
                discovery_data['ha_enabled'] = True
            else:
                discovery_data['ha_enabled'] = False
            
            for node in node_list:
                # Get full node details
                try:
                    node.get()
                except:
                    pass
                
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
                    'status': getattr(node, 'state', 'unknown'),
                    'model': getattr(node, 'model', 'unknown'),
                    'serial': getattr(node, 'serial_number', 'unknown'),
                    'version': getattr(node, 'version', {}).get('full', 'unknown') if hasattr(node, 'version') else 'unknown',
                    'ips': node_ips
                }
                discovery_data['node_details'].append(node_info)
        except Exception as e:
            logger.warning(f"Could not get node info: {e}")
        
        # Determine cluster_type based on HA and MetroCluster status
        if discovery_data['metrocluster_enabled'] and discovery_data['ha_enabled']:
            # Both MetroCluster and HA - this is the case described in the requirement
            discovery_data['cluster_type'] = 'metrocluster'  # MetroCluster takes precedence
        elif discovery_data['metrocluster_enabled']:
            discovery_data['cluster_type'] = 'metrocluster'
        elif discovery_data['ha_enabled']:
            discovery_data['cluster_type'] = 'ha'
        else:
            discovery_data['cluster_type'] = 'local'
        
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
