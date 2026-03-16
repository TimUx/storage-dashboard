"""NetApp ONTAP MetroCluster DR logic.

Provides generation rules and command templates for ONTAP MetroCluster
(synchronous site-level replication) environments.

Supported failover directions
------------------------------
planned_failover
    Negotiated switchover initiated from the healthy primary site.
    All nodes are up.  Uses ``metrocluster switchover`` (no extra flags).

failback
    Return operations to the primary site after it has been restored.
    Uses ``metrocluster switchback``.

disaster_recovery
    Forced switchover initiated from the surviving secondary site after
    the primary site is down.  Uses
    ``metrocluster switchover -forced-on-disaster true``.

    Per NetApp documentation the full disaster recovery procedure is:
    https://docs.netapp.com/us-en/ontap-metrocluster/disaster-recovery/
    task_perform_a_forced_switchover_after_a_disaster.html

    The 8-phase workflow is:
    1. Disaster detection
    2. Pre-checks on surviving site
    3. Forced switchover
    4. Switchover verification
    5. Aggregate healing (data aggregates)
    6. Root aggregate healing
    7. Switchback (when failed site returns)
    8. Final verification
"""

# ---------------------------------------------------------------------------
# DR relationship discovery
# ---------------------------------------------------------------------------

def discover_relationships(system_name, health_data):
    """Analyse health_data and return normalised MetroCluster DR relationship dicts.

    Uses ``is_metrocluster``, ``metrocluster_info``, and ``metrocluster_peers``
    keys as returned by NetAppONTAPClient.get_health_status().  The data matches
    the ONTAP REST API (GET /api/cluster/metrocluster) defined in ontap_swagger.yaml.
    """
    relationships = []

    # The health_data returned by NetAppONTAPClient.get_health_status() stores
    # MetroCluster state as is_metrocluster (bool) and configuration details as
    # metrocluster_info (dict) with local_cluster_name, partner_cluster_name,
    # configuration_state, configuration_type.  metrocluster_peers is a list of
    # peer cluster dicts from GET /api/cluster/peers.
    is_metrocluster = health_data.get('is_metrocluster')
    if not is_metrocluster:
        return relationships

    mc_info = health_data.get('metrocluster_info') or {}
    mc_peers = health_data.get('metrocluster_peers') or []
    mc_nodes = health_data.get('metrocluster_nodes') or []

    configuration_state = mc_info.get('configuration_state', 'unknown')
    replication_state = 'healthy' if configuration_state in ('configured', 'healthy') else 'degraded'

    local_cluster = mc_info.get('local_cluster_name') or system_name
    # Partner cluster from metrocluster_info; fall back to first peer entry
    partner_cluster = mc_info.get('partner_cluster_name')
    if not partner_cluster and mc_peers:
        partner_cluster = mc_peers[0].get('name', '')
    partner_cluster = partner_cluster or ''

    # Derive site names from cluster names
    site_a = local_cluster
    site_b = partner_cluster or 'Site B'

    configuration_type = mc_info.get('configuration_type', '')
    mc_type_label = 'MetroCluster FC'
    if configuration_type and 'ip' in configuration_type.lower():
        mc_type_label = 'MetroCluster IP'

    relationships.append({
        'system_name': system_name,
        'vendor': 'netapp-ontap',
        'replication_type': 'metrocluster',
        'primary_site': site_a,
        'secondary_site': site_b,
        'primary_cluster': local_cluster,
        'secondary_cluster': partner_cluster,
        'replication_state': replication_state,
        'relationship_data': {
            'metrocluster': {
                'configuration_state': configuration_state,
                'configuration_type': mc_type_label,
                'local_cluster': local_cluster,
                'partner_cluster': partner_cluster,
                'peers': mc_peers,
                'nodes': mc_nodes,
            }
        },
    })

    return relationships


# ---------------------------------------------------------------------------
# Topology building
# ---------------------------------------------------------------------------

def build_topology(relationship):
    """Return a topology dict for the given MetroCluster DR relationship."""
    site_a = relationship.get('primary_site', 'Datacenter A')
    site_b = relationship.get('secondary_site', 'Datacenter B')
    primary = relationship.get('primary_cluster') or 'Cluster-A'
    secondary = relationship.get('secondary_cluster') or 'Cluster-B'
    rd = relationship.get('relationship_data', {})
    mc = rd.get('metrocluster', {}) if isinstance(rd.get('metrocluster'), dict) else {}
    api_nodes = mc.get('nodes', []) if isinstance(mc, dict) else []

    topo_nodes = []
    vips = []

    # Build per-site node lists from API data if available, else use defaults
    for node in api_nodes:
        if not isinstance(node, dict):
            continue
        name = node.get('name', 'node')
        # Assign to site based on available DR home info
        site = node.get('dr_home_port', {}).get('node', {}).get('name', site_a) if isinstance(node.get('dr_home_port'), dict) else site_a
        topo_nodes.append({'name': name, 'type': 'ontap-node', 'site': site})

    if not topo_nodes:
        # Default: 2 nodes per cluster
        for prefix, site in [(primary, site_a), (secondary, site_b)]:
            topo_nodes.append({'name': f'{prefix}-01', 'type': 'ontap-node', 'site': site})
            topo_nodes.append({'name': f'{prefix}-02', 'type': 'ontap-node', 'site': site})

    # Add cluster management VIPs
    vips.append({'name': f'{primary}-ClusterMgmtVIP', 'type': 'cluster-mgmt', 'cluster': primary})
    vips.append({'name': f'{secondary}-ClusterMgmtVIP', 'type': 'cluster-mgmt', 'cluster': secondary})

    # Add ISL switches as special nodes
    topo_nodes.append({'name': 'ISL-Switch-A', 'type': 'fc-switch', 'site': site_a})
    topo_nodes.append({'name': 'ISL-Switch-B', 'type': 'fc-switch', 'site': site_b})

    return {
        'sites': [
            {'name': site_a, 'role': 'primary'},
            {'name': site_b, 'role': 'secondary'},
        ],
        'nodes': topo_nodes,
        'links': [
            {
                'source': site_a,
                'target': site_b,
                'type': 'synchronous-replication',
                'label': 'MetroCluster ISL',
            }
        ],
        'vips': vips,
    }


# ---------------------------------------------------------------------------
# Workflow generation
# ---------------------------------------------------------------------------

_WORKFLOW_STEPS = {
    'planned_failover': [
        {'phase': 'pre-failover', 'step': 1, 'title': 'MetroCluster Status prüfen',
         'description': 'Run metrocluster check run and review the output for any errors.'},
        {'phase': 'pre-failover', 'step': 2, 'title': 'Replikationsstatus prüfen',
         'description': 'Confirm metrocluster show reports "configured" and all nodes are reachable.'},
        {'phase': 'pre-failover', 'step': 3, 'title': 'Client I/O stoppen',
         'description': 'Suspend application I/O to all volumes on the primary site SVMs.'},
        {'phase': 'failover', 'step': 4, 'title': 'MetroCluster Switchover starten',
         'description': 'Execute a negotiated switchover from the primary to the secondary site.'},
        {'phase': 'failover', 'step': 5, 'title': 'Erfolgreichen Switchover prüfen',
         'description': 'Run metrocluster show to confirm operational state is "switchover".'},
        {'phase': 'post-failover', 'step': 6, 'title': 'SVMs auf dem Zielcluster starten',
         'description': 'Verify that all migrated SVMs are running on the secondary cluster.'},
        {'phase': 'post-failover', 'step': 7, 'title': 'Client Verbindungen aktualisieren',
         'description': 'Redirect NFS/CIFS/iSCSI clients to the secondary site LIFs.'},
        {'phase': 'post-failover', 'step': 8, 'title': 'Datenintegrität prüfen',
         'description': 'Run volume status checks and application smoke tests.'},
    ],
    'failback': [
        {'phase': 'pre-failback', 'step': 1, 'title': 'Primären Standort wiederherstellen',
         'description': 'Confirm all primary site hardware is operational.'},
        {'phase': 'pre-failback', 'step': 2, 'title': 'MetroCluster Switchback-Bereitschaft prüfen',
         'description': 'Run metrocluster switchback -simulate to check for blockers.'},
        {'phase': 'failback', 'step': 3, 'title': 'Switchback durchführen',
         'description': 'Perform metrocluster switchback to return operations to the primary site.'},
        {'phase': 'failback', 'step': 4, 'title': 'Switchback prüfen',
         'description': 'Confirm metrocluster show shows "normal" operational state.'},
        {'phase': 'post-failback', 'step': 5, 'title': 'Clients mit primärem Standort verbinden',
         'description': 'Update client connections back to the primary site LIFs.'},
        {'phase': 'post-failback', 'step': 6, 'title': 'MetroCluster Status validieren',
         'description': 'Run metrocluster check run and confirm all checks pass.'},
    ],
    # Disaster recovery: forced switchover from the surviving site after a
    # site-level disaster.  Per NetApp documentation:
    # https://docs.netapp.com/us-en/ontap-metrocluster/disaster-recovery/
    # task_perform_a_forced_switchover_after_a_disaster.html
    'disaster_recovery': [
        {'phase': 'detection', 'step': 1, 'title': 'Katastrophe erkannt',
         'description': (
             'Confirm the primary site is down and the surviving secondary site nodes are '
             'healthy.  Check connectivity and console output to rule out a partial failure.'
         )},
        {'phase': 'pre-checks', 'step': 2, 'title': 'MetroCluster Vorabprüfungen durchführen',
         'description': (
             'On the surviving site run metrocluster show, metrocluster node show, '
             'metrocluster check run, and metrocluster check show to assess cluster '
             'health and confirm the disaster switchover is required.'
         )},
        {'phase': 'forced-switchover', 'step': 3, 'title': 'Erzwungener Switchover',
         'description': (
             'Execute the forced disaster switchover to bring all data aggregates online '
             'on the surviving site: '
             'metrocluster switchover -forced-on-disaster true'
         )},
        {'phase': 'verification', 'step': 4, 'title': 'Erfolgreichen Switchover prüfen',
         'description': (
             'Confirm the switchover completed successfully by checking '
             'metrocluster operation show and metrocluster show.'
         )},
        {'phase': 'aggregate-healing', 'step': 5, 'title': 'Aggregat-Heilung (Daten-Aggregate)',
         'description': (
             'Heal the data (non-root) aggregates to make them fully available: '
             'metrocluster heal -phase aggregates'
         )},
        {'phase': 'aggregate-healing', 'step': 6, 'title': 'Root-Aggregat-Heilung',
         'description': (
             'Heal the root aggregates to complete recovery: '
             'metrocluster heal -phase root-aggregates'
         )},
        {'phase': 'switchback', 'step': 7, 'title': 'Switchback (nach Wiederherstellung)',
         'description': (
             'When the failed site is restored and hardware is confirmed healthy, '
             'perform switchback to return operations to the primary site: '
             'metrocluster switchback'
         )},
        {'phase': 'final-verification', 'step': 8, 'title': 'Abschlussüberprüfung',
         'description': (
             'After switchback, run metrocluster node show and metrocluster show to '
             'confirm normal operational state.  All aggregates should be online on '
             'their original sites.'
         )},
    ],
}


def generate_workflow(relationship, failover_direction='planned_failover'):
    """Return workflow steps for the given failover direction.

    Supported directions: ``planned_failover``, ``failback``,
    ``disaster_recovery``.  Unknown directions fall back to
    ``planned_failover``.
    """
    return list(_WORKFLOW_STEPS.get(failover_direction, _WORKFLOW_STEPS['planned_failover']))


# ---------------------------------------------------------------------------
# Command generation
# ---------------------------------------------------------------------------

def generate_commands(relationship, failover_direction='planned_failover'):
    """Return CLI command objects for the given failover direction.

    Commands are built dynamically from the discovered topology stored in
    *relationship*.  This ensures that cluster names and node names in the
    generated commands reflect the actual discovered environment.

    Supported directions: ``planned_failover``, ``failback``,
    ``disaster_recovery``.
    """
    primary = relationship.get('primary_cluster') or 'cluster1'
    secondary = relationship.get('secondary_cluster') or 'cluster2'

    # For disaster recovery the commands are issued from the surviving
    # (secondary) site because the primary site is down.
    surviving = secondary if failover_direction == 'disaster_recovery' else primary

    commands = {
        'planned_failover': [
            {'phase': 'pre-failover', 'description': 'Check MetroCluster configuration',
             'cli': 'metrocluster show', 'target': primary},
            {'phase': 'pre-failover', 'description': 'Check MetroCluster node status',
             'cli': 'metrocluster node show', 'target': primary},
            {'phase': 'pre-failover', 'description': 'Run MetroCluster health check',
             'cli': 'metrocluster check run', 'target': primary},
            {'phase': 'pre-failover', 'description': 'Show check results',
             'cli': 'metrocluster check show', 'target': primary},
            {'phase': 'pre-failover', 'description': 'Show SVM state',
             'cli': 'vserver show -state running', 'target': primary},
            {'phase': 'failover', 'description': 'Simulate switchover (dry run)',
             'cli': 'metrocluster switchover -simulate', 'target': primary},
            {'phase': 'failover', 'description': 'Execute negotiated switchover',
             'cli': 'metrocluster switchover', 'target': primary},
            {'phase': 'failover', 'description': 'Verify switchover operation',
             'cli': 'metrocluster operation show', 'target': primary},
            {'phase': 'failover', 'description': 'Verify switchover state',
             'cli': 'metrocluster show', 'target': primary},
            {'phase': 'post-failover', 'description': 'Verify node state post-switchover',
             'cli': 'metrocluster node show', 'target': primary},
            {'phase': 'post-failover', 'description': 'Show SVMs on secondary',
             'cli': 'vserver show', 'target': primary},
            {'phase': 'post-failover', 'description': 'Show LIF status on secondary',
             'cli': 'network interface show', 'target': primary},
        ],
        'failback': [
            {'phase': 'pre-failback', 'description': 'Check MetroCluster configuration',
             'cli': 'metrocluster show', 'target': surviving},
            {'phase': 'pre-failback', 'description': 'Check MetroCluster node status',
             'cli': 'metrocluster node show', 'target': surviving},
            {'phase': 'pre-failback', 'description': 'Simulate switchback (dry run)',
             'cli': 'metrocluster switchback -simulate', 'target': surviving},
            {'phase': 'failback', 'description': 'Execute switchback',
             'cli': 'metrocluster switchback', 'target': surviving},
            {'phase': 'failback', 'description': 'Verify switchback operation',
             'cli': 'metrocluster operation show', 'target': surviving},
            {'phase': 'failback', 'description': 'Verify normal state',
             'cli': 'metrocluster show', 'target': surviving},
            {'phase': 'post-failback', 'description': 'Run health check post-switchback',
             'cli': 'metrocluster check run', 'target': surviving},
            {'phase': 'post-failback', 'description': 'Review check results',
             'cli': 'metrocluster check show', 'target': surviving},
            {'phase': 'post-failback', 'description': 'Verify node state post-switchback',
             'cli': 'metrocluster node show', 'target': surviving},
        ],
        # Disaster recovery commands executed on the *surviving* (secondary) site.
        # Reference: https://docs.netapp.com/us-en/ontap-metrocluster/disaster-recovery/
        #   task_perform_a_forced_switchover_after_a_disaster.html
        'disaster_recovery': [
            # Phase: pre-checks (on surviving site)
            {'phase': 'pre-checks', 'description': 'Check MetroCluster configuration on surviving site',
             'cli': 'metrocluster show', 'target': surviving},
            {'phase': 'pre-checks', 'description': 'Check MetroCluster node status on surviving site',
             'cli': 'metrocluster node show', 'target': surviving},
            {'phase': 'pre-checks', 'description': 'Run MetroCluster health check',
             'cli': 'metrocluster check run', 'target': surviving},
            {'phase': 'pre-checks', 'description': 'Show MetroCluster check results',
             'cli': 'metrocluster check show', 'target': surviving},
            # Phase: forced-switchover
            {'phase': 'forced-switchover', 'description': 'Execute forced disaster switchover',
             'cli': 'metrocluster switchover -forced-on-disaster true', 'target': surviving},
            # Phase: verification
            {'phase': 'verification', 'description': 'Verify switchover operation completed',
             'cli': 'metrocluster operation show', 'target': surviving},
            {'phase': 'verification', 'description': 'Verify MetroCluster state after switchover',
             'cli': 'metrocluster show', 'target': surviving},
            {'phase': 'verification', 'description': 'Verify node state after switchover',
             'cli': 'metrocluster node show', 'target': surviving},
            # Phase: aggregate-healing (data aggregates, then root aggregates)
            {'phase': 'aggregate-healing', 'description': 'Heal data aggregates',
             'cli': 'metrocluster heal -phase aggregates', 'target': surviving},
            {'phase': 'aggregate-healing', 'description': 'Heal root aggregates',
             'cli': 'metrocluster heal -phase root-aggregates', 'target': surviving},
            # Phase: switchback (when failed site returns)
            {'phase': 'switchback', 'description': 'Verify switchback readiness',
             'cli': 'metrocluster switchback -simulate', 'target': surviving},
            {'phase': 'switchback', 'description': 'Execute switchback to primary site',
             'cli': 'metrocluster switchback', 'target': surviving},
            # Phase: final-verification
            {'phase': 'final-verification', 'description': 'Verify node state after switchback',
             'cli': 'metrocluster node show', 'target': surviving},
            {'phase': 'final-verification', 'description': 'Verify normal MetroCluster state',
             'cli': 'metrocluster show', 'target': surviving},
        ],
    }

    return commands.get(failover_direction, commands['planned_failover'])


# ---------------------------------------------------------------------------
# Mermaid diagram generation
# ---------------------------------------------------------------------------

def generate_topology_diagram(relationship):
    """Return a Mermaid diagram string showing the MetroCluster topology.

    Includes Datacenter A & B, ONTAP clusters, nodes, FC/IP switches (ISL),
    SVMs, and cluster management VIPs.
    """
    site_a = relationship.get('primary_site', 'Datacenter A')
    site_b = relationship.get('secondary_site', 'Datacenter B')
    primary = relationship.get('primary_cluster') or 'Cluster-A'
    secondary = relationship.get('secondary_cluster') or 'Cluster-B'
    rd = relationship.get('relationship_data', {})
    mc = rd.get('metrocluster', {})
    nodes = mc.get('nodes', []) if isinstance(mc, dict) else []

    a_id = _safe_id(primary)
    b_id = _safe_id(secondary)

    # Build node lines for each site.
    # Primary strategy: use the 'cluster' field set by storage_clients.py API
    # collection, which directly contains the cluster name.  This correctly
    # handles names like FASMC1C/FASMC2C that share the letters of 'FASMC'
    # (e.g. the letter 'A') and would be misclassified by a simple letter-based
    # heuristic.  Fall back to dr_home_port.node.name for legacy data formats.
    def _node_cluster(node):
        if not isinstance(node, dict):
            return ''
        # Direct cluster name as stored by storage_clients.py
        if node.get('cluster'):
            return node['cluster']
        # Legacy: dr_home_port.node.name from older data structures
        if isinstance(node.get('dr_home_port'), dict):
            return node['dr_home_port'].get('node', {}).get('name', '')
        return node.get('site', '')

    a_nodes = [n for n in nodes if isinstance(n, dict) and _node_cluster(n) == primary]
    b_nodes = [n for n in nodes if isinstance(n, dict) and _node_cluster(n) == secondary]
    # Fallback: letter-based heuristic for classic A/B naming conventions
    if not a_nodes and not b_nodes and nodes:
        a_nodes = [n for n in nodes if isinstance(n, dict) and 'A' in n.get('name', '').upper()]
        b_nodes = [n for n in nodes if isinstance(n, dict) and 'B' in n.get('name', '').upper()]
    # Last resort: split by position
    if not a_nodes and not b_nodes and nodes:
        mid = max(1, len(nodes) // 2)
        a_nodes, b_nodes = nodes[:mid], nodes[mid:]

    def _node_lines(cluster_nodes, prefix):
        """Generate Mermaid subgraph lines for a set of ONTAP nodes."""
        result = []
        for i, node in enumerate(cluster_nodes[:4]):  # cap at 4 nodes
            nname = node.get('name', f'node{i+1}') if isinstance(node, dict) else f'node{i+1}'
            nid = f'{prefix}_n{i}'
            result.append(f'      {nid}[["Node: {nname}"]]')
        return result

    # ISL switches are contained nodes inside their site subgraphs – there are
    # no explicit within-site edges between the cluster subgraph and the ISL
    # switch.  This matches the StorageGRID/SnapMirror pattern where nodes are
    # just grouped inside their site box and the single cross-site link between
    # ISL_A and ISL_B is the only explicit connection that bridges the two
    # datacenters.
    lines = [
        'graph LR',
        f'  subgraph {_safe_id(site_a)}["{site_a}"]',
        f'    subgraph {a_id}_cluster["{primary} (Primary)"]',
    ]
    if a_nodes:
        lines += _node_lines(a_nodes, a_id)
    else:
        lines += [
            f'      {a_id}_n0[["Node-01\\n(Controller)"]]',
            f'      {a_id}_n1[["Node-02\\n(Controller)"]]',
        ]
    lines += [
        f'      {a_id}_vip(["Cluster Mgmt VIP"])',
        f'      {a_id}_svm[("{primary}-SVM")]',
        '    end',
        f'    ISL_A(["FC/IP Switch\\nSite A"])',
        '  end',
        f'  subgraph {_safe_id(site_b)}["{site_b}"]',
        f'    subgraph {b_id}_cluster["{secondary} (Secondary)"]',
    ]
    if b_nodes:
        lines += _node_lines(b_nodes, b_id)
    else:
        lines += [
            f'      {b_id}_n0[["Node-01\\n(Controller)"]]',
            f'      {b_id}_n1[["Node-02\\n(Controller)"]]',
        ]
    lines += [
        f'      {b_id}_vip(["Cluster Mgmt VIP"])',
        f'      {b_id}_svm[("{secondary}-SVM")]',
        '    end',
        f'    ISL_B(["FC/IP Switch\\nSite B"])',
        '  end',
        '  ISL_A <-->|"MetroCluster\\nSynchronous\\n(ISL)"| ISL_B',
    ]
    return '\n'.join(lines)


def generate_workflow_diagram(relationship, failover_direction='planned_failover'):
    """Return a Mermaid flowchart for the MetroCluster DR workflow.

    The diagram is generated dynamically from the workflow steps so that any
    change to the step list is automatically reflected in the diagram.
    """
    steps = generate_workflow(relationship, failover_direction)
    lines = ['flowchart TD']
    prev_id = None
    for s in steps:
        node_id = f"S{s['step']}"
        label = s['title'].replace('"', "'")
        lines.append(f'  {node_id}["{s["step"]}. {label}"]')
        if prev_id:
            lines.append(f'  {prev_id} --> {node_id}')
        prev_id = node_id
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Runbook generation
# ---------------------------------------------------------------------------

def generate_runbook(relationship, failover_direction='planned_failover'):
    """Return structured runbook sections for the given failover direction."""
    steps = generate_workflow(relationship, failover_direction)
    commands = generate_commands(relationship, failover_direction)
    sections = {}
    for step in steps:
        sections.setdefault(step['phase'], []).append(step)
    cmd_by_phase = {}
    for cmd in commands:
        cmd_by_phase.setdefault(cmd['phase'], []).append(cmd)
    result = []
    for phase, phase_steps in sections.items():
        result.append({'phase': phase, 'steps': phase_steps, 'commands': cmd_by_phase.get(phase, [])})
    return result


def _safe_id(name):
    return name.replace(' ', '_').replace('-', '_').replace('/', '_')

