"""System discovery utilities for auto-detecting storage system details"""
import socket
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Pure Storage shelf controller pattern
# Shelf controllers have '.SC' in their names (e.g., SH9.SC0, SH9.SC1)
# These are not actual nodes and should be filtered out
SHELF_CONTROLLER_PATTERN = '.SC'

# API configuration constants
PURE_API_VERSION = '2.4'
API_TIMEOUT = 10  # seconds


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
    Discover Pure Storage FlashArray details via REST API
    
    Returns dict with cluster info, nodes, partner clusters, etc.
    """
    try:
        import requests
        
        # FlashArray REST API v2 headers
        headers = {
            'x-auth-token': api_token,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        base_url = f"https://{ip_address}"
        
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
        # REST API v2: GET /api/2.x/arrays
        arrays_response = requests.get(
            f"{base_url}/api/{PURE_API_VERSION}/arrays",
            headers=headers,
            verify=ssl_verify,
            timeout=API_TIMEOUT
        )
        
        if arrays_response.status_code == 200:
            # Detect cluster type (HA is default for Pure)
            discovery_data['cluster_type'] = 'ha'
        
        # Get controllers (nodes)
        # REST API v2: GET /api/2.x/controllers
        try:
            controllers_response = requests.get(
                f"{base_url}/api/{PURE_API_VERSION}/controllers",
                headers=headers,
                verify=ssl_verify,
                timeout=API_TIMEOUT
            )
            
            if controllers_response.status_code == 200:
                controllers_data = controllers_response.json()
                controller_items = controllers_data.get('items', [])
                
                # Filter out shelf controllers (names containing .SC)
                actual_nodes = [ctrl for ctrl in controller_items if SHELF_CONTROLLER_PATTERN not in ctrl.get('name', '')]
                discovery_data['node_count'] = len(actual_nodes)
                
                for ctrl in actual_nodes:
                    ctrl_name = ctrl.get('name', 'Unknown')
                    node_info = {
                        'name': ctrl_name,
                        'status': ctrl.get('status', 'unknown'),
                        'mode': ctrl.get('mode', 'unknown'),
                        'model': ctrl.get('model', 'unknown'),
                        'version': ctrl.get('version', 'unknown'),
                        'ips': []
                    }
                    
                    # Try to get network interfaces for this controller
                    # REST API v2: GET /api/2.x/network-interfaces?filter=services='management'
                    try:
                        network_interfaces_response = requests.get(
                            f"{base_url}/api/{PURE_API_VERSION}/network-interfaces",
                            headers=headers,
                            params={'filter': "services='management'"},
                            verify=ssl_verify,
                            timeout=API_TIMEOUT
                        )
                        
                        if network_interfaces_response.status_code == 200:
                            interfaces_data = network_interfaces_response.json()
                            interface_items = interfaces_data.get('items', [])
                            
                            for intf in interface_items:
                                # Check if interface belongs to this controller
                                intf_name = intf.get('name', '')
                                if intf_name.startswith(ctrl_name):
                                    intf_address = intf.get('address', None)
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
        # REST API v2: GET /api/2.x/pods
        # An array is ActiveCluster if at least one pod has arrays.length > 1
        try:
            pods_response = requests.get(
                f"{base_url}/api/{PURE_API_VERSION}/pods",
                headers=headers,
                verify=ssl_verify,
                timeout=API_TIMEOUT
            )
            
            if pods_response.status_code == 200:
                pods_data = pods_response.json()
                pod_items = pods_data.get('items', [])
                
                # Check if any pod has multiple arrays (ActiveCluster criteria)
                for pod in pod_items:
                    pod_arrays = pod.get('arrays', [])
                    
                    # ActiveCluster is detected when a pod has more than 1 array
                    if len(pod_arrays) > 1:
                        discovery_data['cluster_type'] = 'active-cluster'
                        logger.info(f"ActiveCluster detected: pod '{pod.get('name')}' has {len(pod_arrays)} arrays")
                        
                        # Store partner array information (first array found)
                        # Only one partner is stored for simplicity
                        for pod_array in pod_arrays:
                            array_name = pod_array.get('name', None)
                            if array_name and discovery_data['partner_info'] is None:
                                discovery_data['partner_info'] = {
                                    'name': array_name,
                                    # Status might be available in array object, fallback to 'connected'
                                    'status': pod_array.get('status', 'connected')
                                }
                                break  # Only store first partner array
                        break  # Exit pod loop after finding first ActiveCluster pod
        except Exception:
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
    Discover NetApp ONTAP cluster details via REST API
    
    Returns dict with cluster info, nodes, MetroCluster partners, etc.
    """
    try:
        import requests
        
        # ONTAP REST API uses basic authentication
        auth = (username, password)
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        base_url = f"https://{ip_address}"
        
        discovery_data = {
            'cluster_type': None,  # Will be set based on HA and MetroCluster detection
            'node_count': 0,
            'site_count': 1,
            'dns_names': reverse_dns_lookup(ip_address),
            'all_ips': [ip_address],
            'node_details': [],
            'partner_info': None,
            'ha_enabled': False,  # Will be set to True if 2+ nodes are found
            'metrocluster_enabled': False
        }
        
        # Get cluster info and check for HA and MetroCluster
        # REST API: GET /api/cluster
        try:
            cluster_response = requests.get(
                f"{base_url}/api/cluster",
                auth=auth,
                headers=headers,
                verify=ssl_verify,
                timeout=API_TIMEOUT
            )
            
            if cluster_response.status_code == 200:
                cluster_data = cluster_response.json()
                
                # Check for MetroCluster using dedicated endpoint
                # REST API: GET /api/cluster/metrocluster
                # Best practice: check configuration_state == "configured"
                try:
                    mc_response = requests.get(
                        f"{base_url}/api/cluster/metrocluster",
                        auth=auth,
                        headers=headers,
                        verify=ssl_verify,
                        timeout=API_TIMEOUT
                    )
                    
                    if mc_response.status_code == 200:
                        mc_data = mc_response.json()
                        
                        # Check if response contains error (no MetroCluster)
                        # or if records is empty (another indication of no MetroCluster)
                        if 'error' not in mc_data and ('records' not in mc_data or mc_data.get('records', [True])):
                            configuration_state = mc_data.get('configuration_state')
                            
                            # Only set MetroCluster enabled if state is "configured"
                            if configuration_state == 'configured':
                                discovery_data['metrocluster_enabled'] = True
                                discovery_data['site_count'] = 2
                                logger.info(f"MetroCluster detected: {configuration_state}, mode: {mc_data.get('mode')}")
                            else:
                                logger.debug(f"MetroCluster state: {configuration_state}")
                except Exception as mc_error:
                    logger.debug(f"Could not check MetroCluster: {mc_error}")
        except Exception as e:
            logger.warning(f"Could not get cluster info: {e}")
        
        # Get nodes
        # REST API: GET /api/cluster/nodes
        try:
            nodes_response = requests.get(
                f"{base_url}/api/cluster/nodes",
                auth=auth,
                headers=headers,
                verify=ssl_verify,
                timeout=API_TIMEOUT
            )
            
            if nodes_response.status_code == 200:
                nodes_data = nodes_response.json()
                node_list = nodes_data.get('records', [])
                discovery_data['node_count'] = len(node_list)
                
                # Determine HA based on node count (2+ nodes = HA)
                if len(node_list) >= 2:
                    discovery_data['ha_enabled'] = True
                else:
                    discovery_data['ha_enabled'] = False
                
                for node in node_list:
                    # Get full node details if we only have basic info
                    node_uuid = node.get('uuid', '')
                    
                    # Get management IPs
                    node_ips = []
                    
                    # Try to get detailed node info including management interfaces
                    try:
                        node_detail_response = requests.get(
                            f"{base_url}/api/cluster/nodes/{node_uuid}",
                            auth=auth,
                            headers=headers,
                            params={'fields': 'management_interfaces'},
                            verify=ssl_verify,
                            timeout=API_TIMEOUT
                        )
                        
                        if node_detail_response.status_code == 200:
                            node_detail = node_detail_response.json()
                            
                            management_interfaces = node_detail.get('management_interfaces', [])
                            for intf in management_interfaces:
                                ip_info = intf.get('ip', {})
                                address = ip_info.get('address', None)
                                if address:
                                    node_ips.append(address)
                                    discovery_data['all_ips'].append(address)
                                    
                                    # DNS lookup for each IP
                                    dns_names = reverse_dns_lookup(address)
                                    discovery_data['dns_names'].extend(dns_names)
                    except Exception as detail_error:
                        logger.debug(f"Could not get detailed node info: {detail_error}")
                    
                    # Extract version info
                    version_info = node.get('version', {})
                    version_full = version_info.get('full', 'unknown') if isinstance(version_info, dict) else 'unknown'
                    
                    node_info = {
                        'name': node.get('name', 'Unknown'),
                        'uuid': node_uuid,
                        'status': node.get('state', 'unknown'),  # 'status' key for consistency
                        'model': node.get('model', 'unknown'),
                        'serial': node.get('serial_number', 'unknown'),
                        'version': version_full,
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
    Discover NetApp StorageGRID details via API v4
    
    Returns dict with grid info, sites, nodes, etc.
    Based on: https://webscalegmi.netapp.com/grid/apidocs.html
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
        
        base_url = f"https://{ip_address}"
        headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        # Get grid sites first
        sites_count = 1
        try:
            sites_response = requests.get(
                f"{base_url}/api/v4/grid/sites",
                headers=headers,
                verify=ssl_verify,
                timeout=API_TIMEOUT
            )
            
            if sites_response.status_code == 200:
                sites_data = sites_response.json()
                # Response format: {"data": [{"id": "...", "name": "..."}, ...]}
                sites_list = sites_data.get('data', [])
                if sites_list:
                    sites_count = len(sites_list)
                    discovery_data['site_count'] = sites_count
                    
                    # Determine cluster type based on site count
                    if sites_count > 1:
                        discovery_data['cluster_type'] = 'multi-site'
                    else:
                        discovery_data['cluster_type'] = 'single-site'
                    
                    logger.info(f"StorageGRID: Found {sites_count} sites")
                    
        except Exception as sites_error:
            logger.warning(f"Could not get StorageGRID sites: {sites_error}")
        
        # Get grid nodes
        try:
            nodes_response = requests.get(
                f"{base_url}/api/v4/grid/nodes",
                headers=headers,
                verify=ssl_verify,
                timeout=API_TIMEOUT
            )
            
            if nodes_response.status_code == 200:
                nodes_data = nodes_response.json()
                # Response format: {"data": [{node_details}, ...]}
                nodes_list = nodes_data.get('data', [])
                
                # Also try to get service IDs to determine node types more accurately
                service_ids_map = {}
                try:
                    service_ids_response = requests.get(
                        f"{base_url}/api/v4/grid/service-ids",
                        headers=headers,
                        verify=ssl_verify,
                        timeout=API_TIMEOUT
                    )
                    
                    if service_ids_response.status_code == 200:
                        service_ids_data = service_ids_response.json()
                        services = service_ids_data.get('data', [])
                        
                        # Map node IDs to their primary service types
                        for service in services:
                            node_id = service.get('nodeId')
                            service_type = service.get('type', '')
                            
                            if node_id:
                                if node_id not in service_ids_map:
                                    service_ids_map[node_id] = []
                                service_ids_map[node_id].append(service_type)
                        
                        logger.info(f"StorageGRID: Collected service IDs for {len(service_ids_map)} nodes")
                except Exception as service_error:
                    logger.debug(f"Could not get StorageGRID service IDs: {service_error}")
                
                all_nodes = []
                for node in nodes_list:
                    node_name = node.get('name', 'Unknown')
                    node_id = node.get('id', '')
                    node_type = node.get('type', 'unknown')
                    node_state = node.get('state', 'unknown')
                    node_site = node.get('site', 'Unknown Site')
                    
                    # Try to determine node type from service IDs if type is unknown
                    if node_type == 'unknown' and node_id in service_ids_map:
                        services = service_ids_map[node_id]
                        # Determine type based on services running on the node
                        if 'ADC' in services or 'LDR' in services:
                            node_type = 'Storage Node'
                        elif 'CMN' in services or 'NMS' in services:
                            node_type = 'Admin Node'
                        elif 'CLB' in services or 'nginx' in services:
                            node_type = 'Gateway Node'
                        elif 'ARC' in services:
                            node_type = 'Archive Node'
                    
                    # Get node IPs if available
                    node_ips = []
                    if 'ips' in node:
                        node_ips = node.get('ips', [])
                    elif 'addresses' in node:
                        # Alternative field name
                        node_ips = node.get('addresses', [])
                    
                    node_info = {
                        'name': node_name,
                        'id': node_id,
                        'site': node_site,
                        'type': node_type,
                        'status': node_state,
                        'ips': node_ips
                    }
                    
                    all_nodes.append(node_info)
                    
                    # Add IPs to discovery data
                    for ip in node_ips:
                        if ip and ip not in discovery_data['all_ips']:
                            discovery_data['all_ips'].append(ip)
                            # Try DNS lookup for each IP
                            try:
                                dns_names = reverse_dns_lookup(ip)
                                discovery_data['dns_names'].extend(dns_names)
                            except:
                                pass
                
                discovery_data['node_count'] = len(all_nodes)
                discovery_data['node_details'] = all_nodes
                
                logger.info(f"StorageGRID: Found {len(all_nodes)} nodes")
                    
        except Exception as nodes_error:
            logger.warning(f"Could not get StorageGRID nodes: {nodes_error}")
        
        # Try to get topology as fallback if nodes endpoint didn't work
        if discovery_data['node_count'] == 0:
            # First try node-health endpoint
            try:
                node_health_response = requests.get(
                    f"{base_url}/api/v4/grid/node-health",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=API_TIMEOUT
                )
                
                if node_health_response.status_code == 200:
                    node_health_data = node_health_response.json()
                    nodes_list = node_health_data.get('data', [])
                    
                    all_nodes = []
                    for node in nodes_list:
                        node_name = node.get('name', 'Unknown')
                        node_id = node.get('id', '')
                        node_type = node.get('type', 'unknown')
                        node_state = node.get('state', 'unknown')
                        
                        node_info = {
                            'name': node_name,
                            'id': node_id,
                            'site': 'Unknown Site',
                            'type': node_type,
                            'status': node_state,
                            'ips': []
                        }
                        
                        all_nodes.append(node_info)
                    
                    if all_nodes:
                        discovery_data['node_count'] = len(all_nodes)
                        discovery_data['node_details'] = all_nodes
                        logger.info(f"StorageGRID: Found {len(all_nodes)} nodes from node-health endpoint")
            except Exception as node_health_error:
                logger.debug(f"Could not get StorageGRID node-health: {node_health_error}")
            
            # If still no nodes, try topology endpoint as final fallback
            if discovery_data['node_count'] == 0:
                try:
                    topology_response = requests.get(
                        f"{base_url}/api/v4/grid/health/topology",
                        headers=headers,
                        verify=ssl_verify,
                        timeout=API_TIMEOUT
                    )
                    
                    if topology_response.status_code == 200:
                        topology_data = topology_response.json()
                        
                        # Parse hierarchical topology structure
                        # Format: {"data": {"children": [sites], ...}}
                        data = topology_data.get('data', {})
                        sites = data.get('children', [])
                        
                        if sites and discovery_data['site_count'] == 1:
                            discovery_data['site_count'] = len(sites)
                            if len(sites) > 1:
                                discovery_data['cluster_type'] = 'multi-site'
                        
                        # Parse nodes from topology
                        all_nodes = []
                        for site in sites:
                            site_name = site.get('name', 'Unknown Site')
                            nodes = site.get('children', [])
                            
                            for node in nodes:
                                node_name = node.get('name', 'Unknown')
                                node_id = node.get('id', '')
                                node_state = node.get('state', 'unknown')
                                
                                node_info = {
                                    'name': node_name,
                                    'id': node_id,
                                    'site': site_name,
                                    'type': 'unknown',
                                    'status': node_state,
                                    'ips': []
                                }
                                
                                all_nodes.append(node_info)
                        
                        if all_nodes:
                            discovery_data['node_count'] = len(all_nodes)
                            discovery_data['node_details'] = all_nodes
                            
                except Exception as topo_error:
                    logger.debug(f"Could not get StorageGRID topology: {topo_error}")
        
        # Deduplicate DNS names and IPs
        discovery_data['dns_names'] = list(set(discovery_data['dns_names']))
        discovery_data['all_ips'] = list(set(discovery_data['all_ips']))
        
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
