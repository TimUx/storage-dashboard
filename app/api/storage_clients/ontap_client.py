"""NetApp ONTAP 9 REST API client."""
import logging
import re
import time
import traceback
from datetime import datetime, timezone

from app.api.base_client import StorageClient
from app.api.storage_clients.common import (
    _EMS_RECOVERY_FILTER,
    _filter_active_ems_events,
    _filter_ems_by_age_and_category,
    _make_rest_alert,
    _strip_version_date,
)
from app.api.storage_clients.runtime import local_session
from app.ssl_utils import get_ssl_verify

logger = logging.getLogger(__name__)

class NetAppONTAPClient(StorageClient):
    """NetApp ONTAP 9 client using REST API"""

    def _get_rest_status_alerts(self, cluster_name, auth, headers, ssl_verify):
        """Query REST status APIs and return a list of currently active alert dicts.

        Combines eight sources to detect problems that may not produce EMS events:

        1. Cluster health            – GET /api/cluster?fields=health
        2. Node state / health       – GET /api/cluster/nodes?fields=name,state,health,ha
        3. Cluster peer availability – GET /api/cluster/peers
        4. Network LIF state         – GET /api/network/ip/interfaces
        5. Ethernet port state       – GET /api/network/ethernet/ports
        6. Aggregate state           – GET /api/storage/aggregates?fields=name,state
        7. Disk health               – GET /api/storage/disks
        8. SnapMirror relationship   – GET /api/snapmirror/relationships

        Each detected problem is normalized with ``_make_rest_alert()`` into the
        common dashboard alert format (compatible with ``alert_details``).  Every
        alert also carries ``vendor``, ``platform``, ``category``, and ``source``
        fields for multi-vendor correlation in the UI.

        All sub-queries are individually wrapped in try/except so a failure in
        one check never blocks the others.

        Args:
            cluster_name: Cluster name string used as resource identifier.
            auth:         ``(user, password)`` tuple for basic auth.
            headers:      HTTP headers dict.
            ssl_verify:   SSL verification flag passed through to requests.

        Returns:
            list of alert dicts.
        """
        alerts = []
        now_ts = datetime.now(timezone.utc).isoformat()

        # 1 ── Cluster health ─────────────────────────────────────────────────
        try:
            resp = local_session().get(
                f"{self.base_url}/api/cluster",
                auth=auth, headers=headers,
                params={'fields': 'health'},
                verify=ssl_verify, timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                health = data.get('health', {})
                if isinstance(health, dict):
                    is_healthy = health.get('is_healthy', True)
                    status_val = health.get('status', 'ok')
                    if not is_healthy or str(status_val).lower() not in ('ok', ''):
                        alerts.append(_make_rest_alert(
                            category='cluster',
                            resource=cluster_name or self.ip_address,
                            severity='error',
                            message=(
                                'Cluster health is degraded'
                                + (f' (status: {status_val})' if status_val else '')
                            ),
                            source='/api/cluster',
                            timestamp=now_ts,
                        ))
        except Exception as e:
            logger.debug(f"Could not check cluster health for {self.ip_address}: {e}")

        # 2 ── Node state / health ────────────────────────────────────────────
        try:
            resp = local_session().get(
                f"{self.base_url}/api/cluster/nodes",
                auth=auth, headers=headers,
                params={'fields': 'name,state,health,ha'},
                verify=ssl_verify, timeout=10,
            )
            if resp.status_code == 200:
                for node in resp.json().get('records', []):
                    node_name = node.get('name', 'unknown')
                    state = node.get('state', 'up')
                    if state and state != 'up':
                        alerts.append(_make_rest_alert(
                            category='node',
                            resource=node_name,
                            severity='critical',
                            message=f'Node {node_name} is {state} (expected: up)',
                            source='/api/cluster/nodes',
                            timestamp=now_ts,
                        ))
                    # health.is_healthy (boolean) or health field may be absent
                    health = node.get('health', {})
                    if isinstance(health, dict):
                        is_healthy = health.get('is_healthy', True)
                        if not is_healthy:
                            alerts.append(_make_rest_alert(
                                category='node',
                                resource=f'{node_name}:health',
                                severity='error',
                                message=f'Node {node_name} health check failed',
                                source='/api/cluster/nodes',
                                timestamp=now_ts,
                            ))
                    # HA state checks
                    ha = node.get('ha', {})
                    if isinstance(ha, dict):
                        for ha_section in ('giveback', 'takeover'):
                            ha_state = ha.get(ha_section, {})
                            if isinstance(ha_state, dict):
                                state_val = ha_state.get('state', '')
                                if state_val and state_val not in (
                                    '', 'nothing_to_giveback', 'not_attempted', 'enabled', 'ready',
                                ):
                                    alerts.append(_make_rest_alert(
                                        category='node',
                                        resource=f'{node_name}:ha.{ha_section}',
                                        severity='warning',
                                        message=(
                                            f'Node {node_name} HA {ha_section} state is '
                                            f'{state_val!r} (not normal)'
                                        ),
                                        source='/api/cluster/nodes',
                                        timestamp=now_ts,
                                    ))
        except Exception as e:
            logger.debug(f"Could not check node health for {self.ip_address}: {e}")

        # 3 ── Cluster peer availability ──────────────────────────────────────
        try:
            resp = local_session().get(
                f"{self.base_url}/api/cluster/peers",
                auth=auth, headers=headers,
                params={'fields': 'name,availability'},
                verify=ssl_verify, timeout=10,
            )
            if resp.status_code == 200:
                for peer in resp.json().get('records', []):
                    peer_name    = peer.get('name', 'unknown')
                    availability = peer.get('availability', 'available')
                    if availability and availability != 'available':
                        alerts.append(_make_rest_alert(
                            category='cluster',
                            resource=f'peer:{peer_name}',
                            severity='error',
                            message=(
                                f'Cluster peer {peer_name!r} is not available '
                                f'(availability: {availability})'
                            ),
                            source='/api/cluster/peers',
                            timestamp=now_ts,
                        ))
        except Exception as e:
            logger.debug(f"Could not check cluster peers for {self.ip_address}: {e}")

        # 4 ── Network LIF state ──────────────────────────────────────────────
        try:
            resp = local_session().get(
                f"{self.base_url}/api/network/ip/interfaces",
                auth=auth, headers=headers,
                params={'fields': 'name,state,enabled,location,svm'},
                verify=ssl_verify, timeout=10,
            )
            if resp.status_code == 200:
                for lif in resp.json().get('records', []):
                    lif_name  = lif.get('name', 'unknown')
                    state     = lif.get('state', 'up')
                    enabled   = lif.get('enabled', True)
                    svm_name  = lif.get('svm', {}).get('name', '') if isinstance(lif.get('svm'), dict) else ''
                    resource  = f'{svm_name}:{lif_name}' if svm_name else lif_name
                    # Skip LIFs on MetroCluster destination vservers (name ends with
                    # "-mc"). These interfaces are intentionally down and only come
                    # online during a MetroCluster switchover.
                    if svm_name.endswith('-mc'):
                        continue
                    # Skip LIFs that are administratively disabled (enabled=false).
                    # An admin-down LIF is intentionally offline and should not alert.
                    if not enabled:
                        continue
                    if state and state != 'up':
                        alerts.append(_make_rest_alert(
                            category='network',
                            resource=resource,
                            severity='warning',
                            message=f'Network LIF {resource} is {state} (expected: up)',
                            source='/api/network/ip/interfaces',
                            timestamp=now_ts,
                        ))
        except Exception as e:
            logger.debug(f"Could not check network LIF state for {self.ip_address}: {e}")

        # 5 ── Ethernet port state ────────────────────────────────────────────
        try:
            resp = local_session().get(
                f"{self.base_url}/api/network/ethernet/ports",
                auth=auth, headers=headers,
                params={'fields': 'name,node,state,type,broadcast_domain,lag'},
                verify=ssl_verify, timeout=10,
            )
            if resp.status_code == 200:
                records = resp.json().get('records', [])

                # Build a set of (node_name, port_name) tuples that are members
                # of a LAG/ifgrp so we can detect configured physical members.
                lag_members: set[tuple[str, str]] = set()
                for _port in records:
                    if _port.get('type') == 'lag':
                        _node = _port.get('node', {})
                        _node_name = _node.get('name', '') if isinstance(_node, dict) else ''
                        for _member in _port.get('lag', {}).get('member_ports', []):
                            if isinstance(_member, dict):
                                _mname = _member.get('name', '')
                                if _mname:
                                    lag_members.add((_node_name, _mname))

                for port in records:
                    port_name = port.get('name', 'unknown')
                    node_info = port.get('node', {})
                    node_name = node_info.get('name', '') if isinstance(node_info, dict) else ''
                    state     = port.get('state', 'up')
                    port_type = port.get('type', '')
                    # Only alert on physical / lag ports; skip vlan/ifgroup internals
                    if port_type in ('vlan',):
                        continue
                    resource  = f'{node_name}:{port_name}' if node_name else port_name
                    if state and state != 'up':
                        # Suppress false-positive alerts for unconfigured physical
                        # ports: a port with no broadcast domain and no interface
                        # group membership has no active configuration and a down
                        # link is expected / harmless.
                        has_broadcast_domain = bool(port.get('broadcast_domain'))
                        is_lag_member = (node_name, port_name) in lag_members
                        if not has_broadcast_domain and not is_lag_member:
                            continue
                        alerts.append(_make_rest_alert(
                            category='network',
                            resource=resource,
                            severity='warning',
                            message=f'Ethernet port {resource} is {state} (expected: up)',
                            source='/api/network/ethernet/ports',
                            timestamp=now_ts,
                        ))
        except Exception as e:
            logger.debug(f"Could not check ethernet port state for {self.ip_address}: {e}")

        # 6 ── Aggregate state ────────────────────────────────────────────────
        try:
            resp = local_session().get(
                f"{self.base_url}/api/storage/aggregates",
                auth=auth, headers=headers,
                params={'fields': 'name,state'},
                verify=ssl_verify, timeout=10,
            )
            if resp.status_code == 200:
                for aggr in resp.json().get('records', []):
                    aggr_name = aggr.get('name', 'unknown')
                    state     = aggr.get('state', 'online')
                    if state and state != 'online':
                        alerts.append(_make_rest_alert(
                            category='storage',
                            resource=aggr_name,
                            severity='critical',
                            message=f'Aggregate {aggr_name!r} is {state} (expected: online)',
                            source='/api/storage/aggregates',
                            timestamp=now_ts,
                        ))
        except Exception as e:
            logger.debug(f"Could not check aggregate state for {self.ip_address}: {e}")

        # 7 ── Disk health ────────────────────────────────────────────────────
        try:
            resp = local_session().get(
                f"{self.base_url}/api/storage/disks",
                auth=auth, headers=headers,
                params={'fields': 'name,state,raid_state'},
                verify=ssl_verify, timeout=10,
            )
            if resp.status_code == 200:
                for disk in resp.json().get('records', []):
                    disk_name  = disk.get('name', 'unknown')
                    state      = disk.get('state', 'present')
                    raid_state = disk.get('raid_state', 'normal')
                    if state == 'broken' or raid_state == 'failed':
                        alerts.append(_make_rest_alert(
                            category='storage',
                            resource=disk_name,
                            severity='critical',
                            message=(
                                f'Disk {disk_name} is failed'
                                f' (state: {state}, raid_state: {raid_state})'
                            ),
                            source='/api/storage/disks',
                            timestamp=now_ts,
                        ))
        except Exception as e:
            logger.debug(f"Could not check disk health for {self.ip_address}: {e}")

        # 8 ── SnapMirror relationship health ─────────────────────────────────
        try:
            resp = local_session().get(
                f"{self.base_url}/api/snapmirror/relationships",
                auth=auth, headers=headers,
                params={'fields': 'healthy,unhealthy_reason,source,destination,state'},
                verify=ssl_verify, timeout=10,
            )
            if resp.status_code == 200:
                for rel in resp.json().get('records', []):
                    healthy  = rel.get('healthy', True)
                    if healthy:
                        continue
                    src = rel.get('source', {})
                    dst = rel.get('destination', {})
                    src_path = (
                        f"{src.get('svm', {}).get('name', '')}:{src.get('path', '')}"
                        if isinstance(src, dict) else str(src)
                    )
                    dst_path = (
                        f"{dst.get('svm', {}).get('name', '')}:{dst.get('path', '')}"
                        if isinstance(dst, dict) else str(dst)
                    )
                    reason_list = rel.get('unhealthy_reason', [])
                    reason_msg  = (
                        reason_list[0].get('message', '')
                        if reason_list and isinstance(reason_list[0], dict)
                        else str(reason_list)
                    )
                    resource = f'{src_path} → {dst_path}'
                    alerts.append(_make_rest_alert(
                        category='replication',
                        resource=resource,
                        severity='warning',
                        message=(
                            f'SnapMirror relationship unhealthy: {resource}'
                            + (f' – {reason_msg}' if reason_msg else '')
                        ),
                        source='/api/snapmirror/relationships',
                        timestamp=now_ts,
                    ))
        except Exception as e:
            logger.debug(f"Could not check SnapMirror relationships for {self.ip_address}: {e}")

        return alerts

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
                cluster_response = local_session().get(
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
                    os_version = _strip_version_date(version_data.get('full')) or version_data.get('generation')

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
                metrocluster_response = local_session().get(
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
                                peers_response = local_session().get(
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
                                mc_nodes_response = local_session().get(
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
                                dr_groups_response = local_session().get(
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
                nodes_response = local_session().get(
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
                        version_full = _strip_version_date(version_info.get('full', 'unknown')) if isinstance(version_info, dict) else 'unknown'

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
                aggregates_response = local_session().get(
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

            # Collect SnapMirror relationships for DR discovery
            # REST API: GET /api/snapmirror/relationships
            # Fields: source/destination endpoints, state, lag_time, healthy, policy type
            # Required to populate 'snapmirror_relationships' in health_data so that
            # ontap_snapmirror_logic.discover_relationships() can detect DR pairs.
            snapmirror_relationships = []
            try:
                sm_resp = local_session().get(
                    f"{self.base_url}/api/snapmirror/relationships",
                    auth=auth,
                    headers=headers,
                    params={
                        'fields': 'source,destination,state,lag_time,healthy,policy,transfer',
                        'max_records': 500,
                    },
                    verify=ssl_verify,
                    timeout=15,
                )
                if sm_resp.status_code == 200:
                    snapmirror_relationships = sm_resp.json().get('records', [])
                    logger.info(
                        f"Found {len(snapmirror_relationships)} SnapMirror relationships "
                        f"for {self.ip_address}"
                    )
            except Exception as sm_err:
                logger.debug(
                    f"Could not get SnapMirror relationships for {self.ip_address}: {sm_err}"
                )

            # Collect SVM peer relationships for cross-cluster SnapMirror mapping
            # REST API: GET /api/svm/peers
            # Identifies which local SVMs have peers on remote clusters, enabling
            # accurate secondary_cluster population in SnapMirror DR relationships.
            svm_peers = []
            try:
                svm_peers_resp = local_session().get(
                    f"{self.base_url}/api/svm/peers",
                    auth=auth,
                    headers=headers,
                    params={'fields': 'svm,peer.svm,peer.cluster,state'},
                    verify=ssl_verify,
                    timeout=10,
                )
                if svm_peers_resp.status_code == 200:
                    svm_peers = svm_peers_resp.json().get('records', [])
            except Exception as svm_peer_err:
                logger.debug(f"Could not get SVM peers for {self.ip_address}: {svm_peer_err}")

            # Collect MetroCluster interconnect status (only when MetroCluster is configured)
            # REST API: GET /api/cluster/metrocluster/interconnects
            # Provides per-port mirror and state info for the ISL links between sites.
            metrocluster_interconnects = []
            if is_metrocluster:
                try:
                    interconnects_resp = local_session().get(
                        f"{self.base_url}/api/cluster/metrocluster/interconnects",
                        auth=auth,
                        headers=headers,
                        params={'fields': 'node,partner_type,type,state,mirror'},
                        verify=ssl_verify,
                        timeout=10,
                    )
                    if interconnects_resp.status_code == 200:
                        metrocluster_interconnects = interconnects_resp.json().get('records', [])
                        logger.info(
                            f"Found {len(metrocluster_interconnects)} MetroCluster "
                            f"interconnects for {self.ip_address}"
                        )
                except Exception as ic_err:
                    logger.debug(
                        f"Could not get MetroCluster interconnects for {self.ip_address}: {ic_err}"
                    )

            # Get hardware status from node controller info
            # REST API: GET /api/cluster/nodes?fields=controller.failed_power_supply.count,controller.failed_fan.count,controller.over_temperature
            hardware_status = 'ok'
            hardware_details = []
            try:
                hw_nodes_response = local_session().get(
                    f"{self.base_url}/api/cluster/nodes",
                    auth=auth,
                    headers=headers,
                    params={'fields': 'name,controller.failed_power_supply.count,controller.failed_fan.count,controller.over_temperature'},
                    verify=ssl_verify,
                    timeout=10
                )

                if hw_nodes_response.status_code == 200:
                    hw_nodes_data = hw_nodes_response.json()
                    records = hw_nodes_data.get('records', [])

                    for node in records:
                        node_name = node.get('name', 'unknown')
                        controller = node.get('controller', {})
                        if not isinstance(controller, dict):
                            continue

                        failed_psu_info = controller.get('failed_power_supply', {})
                        failed_fan_info = controller.get('failed_fan', {})
                        failed_psus = failed_psu_info.get('count', 0) if isinstance(failed_psu_info, dict) else 0
                        failed_fans = failed_fan_info.get('count', 0) if isinstance(failed_fan_info, dict) else 0
                        over_temp = controller.get('over_temperature', 'normal') == 'over'

                        node_hw = {
                            'node': node_name,
                            'failed_power_supplies': failed_psus,
                            'failed_fans': failed_fans,
                            'over_temperature': over_temp,
                        }
                        hardware_details.append(node_hw)

                        if failed_psus > 0 or failed_fans > 0 or over_temp:
                            hardware_status = 'error'
                            logger.warning(
                                f"Hardware error on ONTAP node {node_name} ({self.ip_address}): "
                                f"failed_PSU={failed_psus}, failed_fans={failed_fans}, over_temp={over_temp}"
                            )
            except Exception as hw_error:
                logger.warning(f"Could not get hardware status for ONTAP {self.ip_address}: {hw_error}")

            # Get EMS (Event Management System) alerts
            # API schema reference: ontap_swagger.yaml – ems_event definition
            # Severity hierarchy: emergency > alert > error > notice > informational > debug
            # We only retrieve events that represent actionable problems (emergency/alert/error).
            # Fields per ems_event schema:
            #   index              – event ID (integer)
            #   message.name       – event name (e.g. "callhome.spares.low")
            #   message.severity   – enum: emergency, alert, error, notice, informational, debug
            #   log_message        – formatted human-readable description
            #   time               – ISO-8601 timestamp
            #   node.name          – node where the event originated
            #   parameters         – event-specific key/value pairs (e.g. alertId for hm.alert)
            #
            # Because ONTAP EMS is an event *log* (not a state database) resolved issues
            # remain in the log forever.  Many problems produce a paired recovery event
            # (e.g. hm.alert.raised / hm.alert.cleared).  We therefore:
            #   1. Fetch candidate problem events by severity (this query).
            #   2. Fetch recent recovery events for known event families (second query).
            #   3. Apply _filter_active_ems_events() to suppress already-resolved alerts.
            _EMS_FIELDS = 'index,message.name,message.severity,log_message,time,node.name,parameters'
            alerts_count = 0
            alert_details = []
            try:
                ems_response = local_session().get(
                    f"{self.base_url}/api/support/ems/events",
                    auth=auth,
                    headers=headers,
                    params={
                        'message.severity': 'emergency,alert,error',
                        'fields': _EMS_FIELDS,
                        'max_records': 500,
                        'order_by': 'time desc',
                    },
                    verify=ssl_verify,
                    timeout=15
                )

                if ems_response.status_code == 200:
                    ems_data = ems_response.json()
                    problem_records = ems_data.get('records', [])

                    # Pre-filter: drop events outside the 96-hour lookback window and
                    # suppress low-priority non-hardware "error"-class events before
                    # the more expensive state-reconstruction step.
                    problem_records = _filter_ems_by_age_and_category(problem_records)

                    # Second query: fetch recovery events for known event families so we
                    # can determine which problem events have already been resolved.
                    recovery_records = []
                    try:
                        recovery_response = local_session().get(
                            f"{self.base_url}/api/support/ems/events",
                            auth=auth,
                            headers=headers,
                            params={
                                'message.name': _EMS_RECOVERY_FILTER,
                                'fields': _EMS_FIELDS,
                                'max_records': 500,
                                'order_by': 'time desc',
                            },
                            verify=ssl_verify,
                            timeout=15
                        )
                        if recovery_response.status_code == 200:
                            recovery_records = recovery_response.json().get('records', [])
                    except Exception as rec_error:
                        logger.debug(
                            f"Could not fetch EMS recovery events for ONTAP {self.ip_address}: {rec_error}"
                        )

                    # Apply state-reconstruction filter: keep only active alerts
                    records = _filter_active_ems_events(problem_records, recovery_records)
                    alerts_count = len(records)

                    for event in records:
                        msg = event.get('message', {})
                        severity_raw = msg.get('severity', 'error')
                        node_info = event.get('node', {})
                        alert_details.append({
                            'id': str(event.get('index', '-')),
                            'title': msg.get('name', '-'),
                            'details': event.get('log_message', '-'),
                            'severity': severity_raw,
                            'error_code': msg.get('name', '-'),
                            'timestamp': event.get('time', '-'),
                            'component': node_info.get('name', '-') if isinstance(node_info, dict) else '-',
                        })

                    # Escalate hardware_status when critical EMS events are present
                    emergency_count = sum(
                        1 for e in alert_details if e['severity'] == 'emergency'
                    )
                    if emergency_count > 0 and hardware_status != 'error':
                        hardware_status = 'error'
                    elif alerts_count > 0 and hardware_status == 'ok':
                        hardware_status = 'warning'

                    if alerts_count > 0:
                        logger.warning(
                            f"Found {alerts_count} active EMS events (emergency/alert/error) "
                            f"for ONTAP {self.ip_address}"
                        )
                elif ems_response.status_code == 401:
                    logger.warning(
                        f"Not authorised to read EMS events for ONTAP {self.ip_address} "
                        f"(user may lack permissions)"
                    )
                else:
                    logger.debug(
                        f"EMS events endpoint returned HTTP {ems_response.status_code} "
                        f"for ONTAP {self.ip_address}"
                    )
            except Exception as ems_error:
                logger.warning(f"Could not get EMS events for ONTAP {self.ip_address}: {ems_error}")

            # Collect REST status-based alerts (node/peer/LIF/port/aggregate/disk/SnapMirror)
            # These detect problems that may not generate EMS events.  Each sub-check is
            # independently fault-tolerant; failures are logged at DEBUG level only.
            try:
                rest_alerts = self._get_rest_status_alerts(cluster_name, auth, headers, ssl_verify)
                if rest_alerts:
                    # Deduplicate: skip REST alerts whose resource is already covered by an
                    # EMS alert (identified by a matching 'component' value).
                    ems_components = {d.get('component', '') for d in alert_details}
                    for ra in rest_alerts:
                        if ra.get('component', '') not in ems_components:
                            alert_details.append(ra)

                    alerts_count = len(alert_details)

                    # Escalate hardware_status based on REST alert severity
                    for ra in rest_alerts:
                        sev = ra.get('severity', '')
                        if sev == 'critical' and hardware_status != 'error':
                            hardware_status = 'error'
                        elif sev in ('error', 'warning') and hardware_status == 'ok':
                            hardware_status = 'warning'

                    if rest_alerts:
                        logger.warning(
                            f"Found {len(rest_alerts)} REST status alert(s) for ONTAP {self.ip_address}"
                        )
            except Exception as rest_err:
                logger.warning(f"Could not collect REST status alerts for {self.ip_address}: {rest_err}")

            result = self._format_response(
                status='online',
                hardware=hardware_status,
                cluster='ok',
                alerts=alerts_count,
                total_tb=total_bytes / (1024**4),
                used_tb=used_bytes / (1024**4),
                os_version=os_version,
                is_metrocluster=is_metrocluster,
                metrocluster_info=metrocluster_info if metrocluster_info else None,
                metrocluster_nodes=metrocluster_nodes if metrocluster_nodes else None,
                metrocluster_dr_groups=metrocluster_dr_groups if metrocluster_dr_groups else None,
                metrocluster_peers=metrocluster_peers if metrocluster_peers else None,
                controllers=metrocluster_nodes if metrocluster_nodes else cluster_nodes,
                hardware_details=hardware_details if hardware_details else None,
                alert_details=alert_details if alert_details else None
            )
            # Attach DR-discovery data that goes beyond the standard _format_response params
            if snapmirror_relationships:
                result['snapmirror_relationships'] = snapmirror_relationships
            if svm_peers:
                result['svm_peers'] = svm_peers
            if metrocluster_interconnects:
                result['metrocluster_interconnects'] = metrocluster_interconnects
            return result
        except Exception as e:
            logger.error(f"Error getting NetApp ONTAP health status for {self.ip_address}: {e}")
            logger.error(traceback.format_exc())
            return self._format_response(status='error', hardware='error', cluster='error', error=str(e))

    # ------------------------------------------------------------------
    # Volume-snapshot management (used by /snaps/ live execution)
    # ------------------------------------------------------------------

    def _resolve_snapshot_uuid(self, vol_uuid: str, snap_name: str,
                               auth, headers, ssl_verify,
                               timeout_seconds: int = 30) -> tuple[str | None, dict]:
        """Look up the ONTAP snapshot UUID for ``snap_name`` on ``vol_uuid``.

        Returns ``(snap_uuid, raw_response_json)``.  ``snap_uuid`` is None if
        the snapshot cannot be found.  The raw response is returned for
        diagnostic logging by callers.
        """
        resp = local_session().get(
            f"{self.base_url}/api/storage/volumes/{vol_uuid}/snapshots",
            auth=auth, headers=headers, verify=ssl_verify, timeout=timeout_seconds,
            params={'name': snap_name, 'fields': 'name,uuid,expiry_time'},
        )
        body = {}
        try:
            body = resp.json() if resp.status_code == 200 else {}
        except Exception:
            body = {}
        if resp.status_code != 200:
            return None, {'status_code': resp.status_code, 'text': resp.text[:300]}
        records = body.get('records', [])
        if not records:
            return None, body
        return records[0].get('uuid'), body

    def _resolve_volume_uuid(self, svm: str, volume_name: str,
                             auth, headers, ssl_verify) -> str | None:
        """Look up the ONTAP volume UUID by SVM and volume name."""
        params = {'name': volume_name, 'fields': 'name,uuid,svm'}
        if svm:
            params['svm.name'] = svm
        resp = local_session().get(
            f"{self.base_url}/api/storage/volumes",
            auth=auth, headers=headers, verify=ssl_verify, timeout=30,
            params=params,
        )
        if resp.status_code != 200:
            return None
        try:
            records = resp.json().get('records', [])
        except Exception:
            return None
        if not records:
            return None
        return records[0].get('uuid')

    def _snapshot_ops_session(self):
        """Return ``(auth, headers, ssl_verify)`` for snapshot REST operations."""
        if not self.username or not self.password:
            raise RuntimeError("No credentials configured for ONTAP")
        ssl_verify = get_ssl_verify(self.resolved_address)
        auth = (self.username, self.password)
        headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        return auth, headers, ssl_verify

    def _wait_for_job_completion(self, job_uuid: str, auth, headers, ssl_verify,
                                 timeout_seconds: int = 45) -> tuple[bool, dict]:
        """Poll an ONTAP async job until it finishes."""
        deadline = time.time() + timeout_seconds
        last_payload: dict = {}
        while time.time() < deadline:
            resp = local_session().get(
                f"{self.base_url}/api/cluster/jobs/{job_uuid}",
                auth=auth, headers=headers, verify=ssl_verify, timeout=15,
            )
            if resp.status_code != 200:
                return False, {'status_code': resp.status_code, 'text': resp.text[:300]}
            try:
                payload = resp.json()
            except Exception:
                payload = {}
            last_payload = payload if isinstance(payload, dict) else {}
            state = str(last_payload.get('state', '')).lower()
            if state in ('success', 'completed'):
                return True, last_payload
            if state in ('failure', 'failed', 'error'):
                message = ''
                if isinstance(last_payload.get('message'), str):
                    message = last_payload.get('message', '')
                elif isinstance(last_payload.get('description'), str):
                    message = last_payload.get('description', '')
                return False, {
                    'error': (
                        f'ONTAP async job failed (state={state})'
                        + (f': {message}' if message else '')
                    ),
                    'job': last_payload,
                }
            time.sleep(1.0)
        return False, {'error': 'ONTAP async job timeout', 'job': last_payload}

    def _wait_for_snapshot_name(self, vol_uuid: str, snap_name: str,
                                auth, headers, ssl_verify,
                                timeout_seconds: int = 60) -> tuple[bool, dict]:
        """Wait until a snapshot is resolvable by name on a volume."""
        deadline = time.time() + timeout_seconds
        last_lookup: dict = {}
        while time.time() < deadline:
            snap_uuid, lookup = self._resolve_snapshot_uuid(
                vol_uuid, snap_name, auth, headers, ssl_verify, timeout_seconds=5
            )
            last_lookup = lookup if isinstance(lookup, dict) else {}
            if snap_uuid:
                return True, {'snap_uuid': snap_uuid, 'lookup': last_lookup}
            time.sleep(1.0)
        return False, {
            'error': f'Snapshot {snap_name} not visible after rename wait window',
            'lookup': last_lookup,
        }

    @staticmethod
    def _extract_job_uuid_from_response(resp) -> str | None:
        """Extract ONTAP async job UUID from JSON body or HTTP headers."""
        job_uuid = None
        try:
            job_uuid = (resp.json() or {}).get('job', {}).get('uuid')
        except Exception:
            job_uuid = None
        if job_uuid:
            return job_uuid

        # Some ONTAP versions return async job links in headers only.
        for hdr in ('Location', 'location', 'Content-Location', 'content-location'):
            link = resp.headers.get(hdr)
            if not link:
                continue
            m = re.search(r'/api/cluster/jobs/([0-9a-fA-F-]+)', str(link))
            if m:
                return m.group(1)
        return None

    def update_snapshot_expiry(self, svm: str, volume_name: str,
                               snap_name: str, expiry_iso: str | None) -> tuple[bool, dict]:
        """Set ``expiry_time`` on an ONTAP volume snapshot.

        ``expiry_iso`` may be ``None``/empty to clear the expiry.  ONTAP
        refuses snapshot deletion while ``expiry_time`` is still in the future
        (errors 1638555 / 53412007); callers about to delete a snapshot should
        first push the expiry into the past via this method.

        Returns ``(success, info_dict)`` – info contains ``status_code`` and
        ``text`` for diagnostic display.
        """
        try:
            auth, headers, ssl_verify = self._snapshot_ops_session()
            vol_uuid = self._resolve_volume_uuid(svm, volume_name, auth, headers, ssl_verify)
            if not vol_uuid:
                return False, {'error': f'Volume {volume_name} not found on SVM {svm}'}
            snap_uuid, lookup = self._resolve_snapshot_uuid(
                vol_uuid, snap_name, auth, headers, ssl_verify
            )
            if not snap_uuid:
                return False, {'error': f'Snapshot {snap_name} not found on volume {volume_name}',
                               'lookup': lookup}
            body = {'expiry_time': expiry_iso} if expiry_iso else {'expiry_time': ''}
            resp = local_session().patch(
                f"{self.base_url}/api/storage/volumes/{vol_uuid}/snapshots/{snap_uuid}",
                auth=auth, headers=headers, verify=ssl_verify, timeout=30,
                json=body,
                params={'return_timeout': 30},
            )
            ok = resp.status_code in (200, 202)
            info = {'status_code': resp.status_code, 'text': resp.text[:500],
                    'volume_uuid': vol_uuid, 'snap_uuid': snap_uuid}
            info['resolved_endpoint'] = (
                f"/api/storage/volumes/{vol_uuid}/snapshots/{snap_uuid}"
            )
            # ONTAP often replies 202 (Accepted) and processes the change
            # asynchronously via /api/cluster/jobs. Without polling that
            # job we cannot tell whether the expiry was actually updated –
            # a silently-failed job would let the caller think the
            # snapshot is now deletable, while it still has its old
            # expiry. Poll until the job reaches success/failure.
            if ok and resp.status_code == 202:
                job_uuid = self._extract_job_uuid_from_response(resp)
                if job_uuid:
                    job_ok, job_info = self._wait_for_job_completion(
                        job_uuid, auth, headers, ssl_verify, timeout_seconds=45
                    )
                    info['job_uuid'] = job_uuid
                    info['job'] = job_info
                    ok = job_ok
                else:
                    info['job'] = {
                        'state': 'unknown',
                        'message': (
                            'HTTP 202 received, but no job UUID returned in body/headers'
                        ),
                    }
            if ok:
                logger.info("ONTAP %s: set expiry_time on %s/%s (uuid=%s) → %s",
                            self.ip_address, volume_name, snap_name, snap_uuid, expiry_iso)
            else:
                logger.warning("ONTAP %s: set expiry_time on %s/%s failed (HTTP %d, job=%s): %s",
                               self.ip_address, volume_name, snap_name,
                               resp.status_code, info.get('job'), resp.text[:200])
            return ok, info
        except Exception as exc:
            logger.warning("ONTAP update_snapshot_expiry error %s/%s: %s",
                           self.ip_address, volume_name, exc)
            return False, {'error': str(exc)}

    def delete_volume_snapshot(self, svm: str, volume_name: str,
                               snap_name: str) -> tuple[bool, dict]:
        """Delete an ONTAP volume snapshot via the REST API.

        Workflow performed by this method:
            1. Resolve volume UUID via ``GET /api/storage/volumes``.
            2. Resolve snapshot UUID via
               ``GET /api/storage/volumes/{vol_uuid}/snapshots?name=...``.
            3. ``DELETE /api/storage/volumes/{vol_uuid}/snapshots/{snap_uuid}``.

        Note: callers that need to remove the protection imposed by a future
        ``expiry_time`` must first call :py:meth:`update_snapshot_expiry`
        with an expiry in the past – this method does NOT adjust the expiry
        automatically because the caller (live-execution flow) needs to log
        the adjustment as its own step.

        Returns ``(success, info_dict)``.
        """
        try:
            auth, headers, ssl_verify = self._snapshot_ops_session()
            vol_uuid = self._resolve_volume_uuid(svm, volume_name, auth, headers, ssl_verify)
            if not vol_uuid:
                return False, {'error': f'Volume {volume_name} not found on SVM {svm}'}
            snap_uuid, lookup = self._resolve_snapshot_uuid(
                vol_uuid, snap_name, auth, headers, ssl_verify
            )
            if not snap_uuid:
                return False, {'error': f'Snapshot {snap_name} not found on volume {volume_name}',
                               'lookup': lookup}
            resp = local_session().delete(
                f"{self.base_url}/api/storage/volumes/{vol_uuid}/snapshots/{snap_uuid}",
                auth=auth, headers=headers, verify=ssl_verify, timeout=60,
                params={'return_timeout': 30},
            )
            ok = resp.status_code in (200, 202)
            info = {'status_code': resp.status_code, 'text': resp.text[:500],
                    'volume_uuid': vol_uuid, 'snap_uuid': snap_uuid}
            # ONTAP usually returns 202 + job UUID and processes the
            # delete asynchronously. Without polling /api/cluster/jobs we
            # would report "success" even when the job fails (e.g. because
            # expiry_time was still in the future, or a SnapMirror lock is
            # active). That false positive previously caused the dashboard
            # to remove the DB record while the snapshot kept living on
            # the array.
            if ok and resp.status_code == 202:
                job_uuid = self._extract_job_uuid_from_response(resp)
                if job_uuid:
                    job_ok, job_info = self._wait_for_job_completion(
                        job_uuid, auth, headers, ssl_verify, timeout_seconds=60
                    )
                    info['job_uuid'] = job_uuid
                    info['job'] = job_info
                    ok = job_ok
                else:
                    info['job'] = {
                        'state': 'unknown',
                        'message': (
                            'HTTP 202 received, but no job UUID returned in body/headers'
                        ),
                    }
            if ok:
                logger.info("ONTAP %s: deleted snapshot %s/%s (uuid=%s)",
                            self.ip_address, volume_name, snap_name, snap_uuid)
            else:
                logger.warning("ONTAP %s: delete snapshot %s/%s failed (HTTP %d, job=%s): %s",
                               self.ip_address, volume_name, snap_name,
                               resp.status_code, info.get('job'), resp.text[:200])
            return ok, info
        except Exception as exc:
            logger.warning("ONTAP delete_volume_snapshot error %s/%s: %s",
                           self.ip_address, volume_name, exc)
            return False, {'error': str(exc)}

    def rename_volume_snapshot(self, svm: str, volume_name: str,
                               snap_name: str, new_name: str,
                               new_expiry_iso: str | None = None) -> tuple[bool, dict]:
        """Rename an ONTAP volume snapshot, optionally updating ``expiry_time``.

        Used by the TTL-update flow: the snapshot is renamed to embed the new
        timestamp in the suffix and ``expiry_time`` is set to the same point
        in time.

        Returns ``(success, info_dict)``.
        """
        try:
            auth, headers, ssl_verify = self._snapshot_ops_session()
            vol_uuid = self._resolve_volume_uuid(svm, volume_name, auth, headers, ssl_verify)
            if not vol_uuid:
                return False, {'error': f'Volume {volume_name} not found on SVM {svm}'}
            snap_uuid, lookup = self._resolve_snapshot_uuid(
                vol_uuid, snap_name, auth, headers, ssl_verify
            )
            if not snap_uuid:
                return False, {'error': f'Snapshot {snap_name} not found on volume {volume_name}',
                               'lookup': lookup}
            body: dict = {'name': new_name}
            if new_expiry_iso:
                body['expiry_time'] = new_expiry_iso
            resp = local_session().patch(
                f"{self.base_url}/api/storage/volumes/{vol_uuid}/snapshots/{snap_uuid}",
                auth=auth, headers=headers, verify=ssl_verify, timeout=30,
                json=body,
            )
            ok = resp.status_code in (200, 202)
            info = {'status_code': resp.status_code, 'text': resp.text[:500],
                    'volume_uuid': vol_uuid, 'snap_uuid': snap_uuid}
            job_ok = True
            if ok and resp.status_code == 202:
                job_uuid = self._extract_job_uuid_from_response(resp)
                if job_uuid:
                    job_ok, job_info = self._wait_for_job_completion(
                        job_uuid, auth, headers, ssl_verify, timeout_seconds=30
                    )
                    info['job_uuid'] = job_uuid
                    info['job'] = job_info
                else:
                    info['job'] = {
                        'state': 'unknown',
                        'message': (
                            'HTTP 202 received, but no job UUID returned in body/headers; '
                            'falling back to name-visibility wait.'
                        ),
                    }
                # Do not fail immediately on job polling issues; the decisive
                # condition is whether the renamed snapshot becomes visible.
                ok = True
            if ok:
                logger.info("ONTAP %s: renamed snapshot %s/%s → %s",
                            self.ip_address, volume_name, snap_name, new_name)
            else:
                logger.warning("ONTAP %s: rename snapshot %s/%s failed (HTTP %d): %s",
                               self.ip_address, volume_name, snap_name,
                               resp.status_code, resp.text[:200])
                return False, info

            # Post-condition check: ensure the new name becomes resolvable.
            visibility_wait = 60 if info.get('job_uuid') else 20
            visible, vis_info = self._wait_for_snapshot_name(
                vol_uuid, new_name, auth, headers, ssl_verify,
                timeout_seconds=visibility_wait
            )
            if not visible:
                # Additional diagnostic: check whether the old snapshot name is
                # still present to better explain why visibility failed.
                old_visible, old_info = self._wait_for_snapshot_name(
                    vol_uuid, snap_name, auth, headers, ssl_verify, timeout_seconds=2
                )
                return False, {
                    'error': (
                        f'Rename reported success but snapshot {new_name} not found'
                        + (f'; old snapshot {snap_name} still exists' if old_visible else '')
                    ),
                    'status_code': resp.status_code,
                    'volume_uuid': vol_uuid,
                    'snap_uuid': snap_uuid,
                    'old_snap_uuid': snap_uuid,
                    'lookup': vis_info.get('lookup'),
                    'old_lookup': old_info.get('lookup') if isinstance(old_info, dict) else None,
                    'job': info.get('job'),
                }
            if not job_ok:
                logger.warning(
                    "ONTAP %s: rename visibility confirmed, but job polling reported problem for %s/%s",
                    self.ip_address, volume_name, snap_name,
                )
            info['renamed_snap_uuid'] = vis_info.get('snap_uuid')
            return ok, info
        except Exception as exc:
            logger.warning("ONTAP rename_volume_snapshot error %s/%s: %s",
                           self.ip_address, volume_name, exc)
            return False, {'error': str(exc)}

    def get_volume_snapshots(self):
        """Return ONTAP volume snapshots via REST API.

        Queries GET /api/storage/volumes/*/snapshots (using the bulk snapshots
        endpoint if available, otherwise iterates volumes).  Returns a list of
        dicts with keys: name, create_time, volume, svm, cluster.
        """
        try:
            ssl_verify = get_ssl_verify(self.resolved_address)
            auth = (self.username, self.password) if self.username else None
            headers = {'Accept': 'application/json'}

            # Resolve cluster name for context
            cluster_name = self.ip_address
            try:
                cl_resp = local_session().get(
                    f"{self.base_url}/api/cluster",
                    auth=auth, headers=headers, verify=ssl_verify, timeout=10,
                )
                if cl_resp.status_code == 200:
                    cluster_name = cl_resp.json().get('name', self.ip_address)
            except Exception:
                pass

            results = []
            # Collect all volumes first
            vol_resp = local_session().get(
                f"{self.base_url}/api/storage/volumes",
                auth=auth, headers=headers, verify=ssl_verify, timeout=30,
                params={'fields': 'name,uuid,svm', 'max_records': 1000},
            )
            if vol_resp.status_code != 200:
                return []

            volumes = vol_resp.json().get('records', [])
            for vol in volumes:
                vol_uuid = vol.get('uuid')
                vol_name = vol.get('name', '')
                svm_name = (vol.get('svm') or {}).get('name', '')
                if not vol_uuid:
                    continue
                snap_resp = local_session().get(
                    f"{self.base_url}/api/storage/volumes/{vol_uuid}/snapshots",
                    auth=auth, headers=headers, verify=ssl_verify, timeout=30,
                    params={'fields': 'name,create_time', 'max_records': 500},
                )
                if snap_resp.status_code != 200:
                    continue
                for snap in snap_resp.json().get('records', []):
                    results.append({
                        'name': snap.get('name', ''),
                        'create_time': snap.get('create_time'),
                        'volume': vol_name,
                        'svm': svm_name,
                        'cluster': cluster_name,
                    })
            return results
        except Exception as exc:
            logger.warning("ONTAP get_volume_snapshots error for %s: %s", self.ip_address, exc)
            return []
