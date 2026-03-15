"""Pure Storage FlashArray ActiveCluster DR logic.

Provides generation rules and command templates for Pure FlashArray
ActiveCluster (synchronous replication) environments.
"""

# ---------------------------------------------------------------------------
# DR relationship discovery
# ---------------------------------------------------------------------------

def discover_relationships(system_name, health_data):
    """Analyse health_data returned by PureStorageClient.get_health_status()
    and return a list of normalised DR relationship dicts.

    Each dict contains:
        system_name, vendor, replication_type,
        primary_site, secondary_site, primary_cluster, secondary_cluster,
        replication_state, relationship_data
    """
    relationships = []
    ac_info = health_data.get('activecluster') or health_data.get('active_cluster')
    if not ac_info:
        return relationships

    mediators = ac_info.get('mediator_status') if isinstance(ac_info, dict) else None
    pods = health_data.get('pods', []) or []

    for pod in pods:
        if not isinstance(pod, dict):
            continue
        arrays = pod.get('arrays', [])
        if len(arrays) < 2:
            continue

        primary = arrays[0]
        secondary = arrays[1]
        state = 'healthy'
        if pod.get('status') not in (None, 'online', 'healthy'):
            state = 'degraded'

        rel = {
            'system_name': system_name,
            'vendor': 'pure',
            'replication_type': 'activecluster',
            'primary_site': primary.get('name', 'Site A'),
            'secondary_site': secondary.get('name', 'Site B'),
            'primary_cluster': primary.get('name', system_name),
            'secondary_cluster': secondary.get('name', ''),
            'replication_state': state,
            'relationship_data': {
                'pod_name': pod.get('name'),
                'pod_status': pod.get('status'),
                'arrays': arrays,
                'mediator': mediators,
            },
        }
        relationships.append(rel)

    if not relationships and isinstance(ac_info, dict):
        # Minimal entry when ActiveCluster is detected but no pod detail
        relationships.append({
            'system_name': system_name,
            'vendor': 'pure',
            'replication_type': 'activecluster',
            'primary_site': 'Site A',
            'secondary_site': 'Site B',
            'primary_cluster': system_name,
            'secondary_cluster': '',
            'replication_state': 'unknown',
            'relationship_data': {'activecluster': ac_info},
        })

    return relationships


# ---------------------------------------------------------------------------
# Topology building
# ---------------------------------------------------------------------------

def build_topology(relationship):
    """Return a topology dict for the given DR relationship."""
    rd = relationship.get('relationship_data', {})
    arrays = rd.get('arrays', [])

    site_a_name = relationship.get('primary_site', 'Datacenter A')
    site_b_name = relationship.get('secondary_site', 'Datacenter B')

    nodes = []
    vips = []
    for arr in arrays:
        arr_name = arr.get('name', 'array') if isinstance(arr, dict) else str(arr)
        # Add the array cluster node
        nodes.append({
            'name': arr_name,
            'type': 'flasharray-cluster',
            'site': arr_name,
        })
        # Add controllers for each array
        nodes.append({'name': f'{arr_name}-CT0', 'type': 'controller', 'site': arr_name})
        nodes.append({'name': f'{arr_name}-CT1', 'type': 'controller', 'site': arr_name})
        # Add management VIP
        vips.append({'name': f'{arr_name}-MgmtVIP', 'type': 'management', 'array': arr_name})

    return {
        'sites': [
            {'name': site_a_name, 'role': 'primary'},
            {'name': site_b_name, 'role': 'secondary'},
        ],
        'nodes': nodes,
        'links': [
            {
                'source': site_a_name,
                'target': site_b_name,
                'type': 'synchronous-replication',
                'label': 'ActiveCluster Pod',
            }
        ],
        'vips': vips,
    }


# ---------------------------------------------------------------------------
# Workflow generation
# ---------------------------------------------------------------------------

_WORKFLOW_STEPS = {
    'planned_failover': [
        {'phase': 'pre-failover', 'step': 1, 'title': 'Verify replication health',
         'description': 'Confirm all ActiveCluster pods are online and healthy before proceeding.'},
        {'phase': 'pre-failover', 'step': 2, 'title': 'Notify stakeholders',
         'description': 'Inform application owners and IT operations of the planned failover window.'},
        {'phase': 'pre-failover', 'step': 3, 'title': 'Suspend workloads',
         'description': 'Gracefully stop or migrate workloads using volumes in the target pod.'},
        {'phase': 'failover', 'step': 4, 'title': 'Detach pod from primary array',
         'description': 'Remove the primary array from the ActiveCluster pod so the secondary becomes the sole owner.'},
        {'phase': 'failover', 'step': 5, 'title': 'Verify secondary array owns pod',
         'description': 'Confirm the pod status is "online" on the secondary array.'},
        {'phase': 'post-failover', 'step': 6, 'title': 'Restart workloads on secondary',
         'description': 'Re-connect hosts to volumes on the secondary array and restart applications.'},
        {'phase': 'post-failover', 'step': 7, 'title': 'Validate application health',
         'description': 'Run smoke tests and monitoring checks to confirm all services are operational.'},
        {'phase': 'post-failover', 'step': 8, 'title': 'Update DNS / load-balancer entries',
         'description': 'Point DNS records and load-balancers to the secondary site.'},
    ],
    'failback': [
        {'phase': 'pre-failback', 'step': 1, 'title': 'Restore primary array connectivity',
         'description': 'Confirm the primary array is online and reachable from the secondary.'},
        {'phase': 'pre-failback', 'step': 2, 'title': 'Re-join primary to pod',
         'description': 'Add the primary array back to the ActiveCluster pod to begin resync.'},
        {'phase': 'failback', 'step': 3, 'title': 'Wait for full resync',
         'description': 'Monitor pod resync progress until replication lag is zero.'},
        {'phase': 'failback', 'step': 4, 'title': 'Detach secondary from pod',
         'description': 'Remove the secondary array from the pod to make the primary the sole owner.'},
        {'phase': 'post-failback', 'step': 5, 'title': 'Restart workloads on primary',
         'description': 'Reconnect hosts to primary volumes and restart applications.'},
        {'phase': 'post-failback', 'step': 6, 'title': 'Re-add secondary to pod',
         'description': 'Restore the full ActiveCluster configuration for continued protection.'},
    ],
}


def generate_workflow(relationship, failover_direction='planned_failover'):
    """Return workflow steps for the given failover direction."""
    steps = _WORKFLOW_STEPS.get(failover_direction, _WORKFLOW_STEPS['planned_failover'])
    return list(steps)


# ---------------------------------------------------------------------------
# Command generation
# ---------------------------------------------------------------------------

def generate_commands(relationship, failover_direction='planned_failover'):
    """Return CLI command objects for the given failover direction."""
    rd = relationship.get('relationship_data', {})
    pod_name = rd.get('pod_name') or 'pod1'
    primary = relationship.get('primary_cluster') or 'array1'
    secondary = relationship.get('secondary_cluster') or 'array2'

    commands = {
        'planned_failover': [
            {
                'phase': 'pre-failover',
                'description': 'Check pod health',
                'cli': f'purepod list {pod_name}',
                'target': primary,
            },
            {
                'phase': 'pre-failover',
                'description': 'List pod members',
                'cli': f'purepod list --array {pod_name}',
                'target': primary,
            },
            {
                'phase': 'failover',
                'description': 'Detach primary array from pod',
                'cli': f'purepod remove --array {primary} {pod_name}',
                'target': primary,
            },
            {
                'phase': 'failover',
                'description': 'Verify pod on secondary',
                'cli': f'purepod list {pod_name}',
                'target': secondary,
            },
            {
                'phase': 'post-failover',
                'description': 'Verify volumes on secondary',
                'cli': f'purevol list --pod {pod_name}',
                'target': secondary,
            },
        ],
        'failback': [
            {
                'phase': 'pre-failback',
                'description': 'Check pod status on secondary',
                'cli': f'purepod list {pod_name}',
                'target': secondary,
            },
            {
                'phase': 'pre-failback',
                'description': 'Re-add primary array to pod',
                'cli': f'purepod add --array {primary} {pod_name}',
                'target': secondary,
            },
            {
                'phase': 'failback',
                'description': 'Monitor resync progress',
                'cli': f'purepod list {pod_name}',
                'target': secondary,
            },
            {
                'phase': 'failback',
                'description': 'Detach secondary from pod',
                'cli': f'purepod remove --array {secondary} {pod_name}',
                'target': secondary,
            },
        ],
    }

    return commands.get(failover_direction, commands['planned_failover'])


# ---------------------------------------------------------------------------
# Mermaid diagram generation
# ---------------------------------------------------------------------------

def generate_topology_diagram(relationship):
    """Return a Mermaid diagram string showing the ActiveCluster topology.

    Includes Datacenter A & B, FlashArray clusters, controllers (CT0/CT1),
    management VIPs, replication link, and mediator.
    """
    site_a = relationship.get('primary_site', 'Datacenter A')
    site_b = relationship.get('secondary_site', 'Datacenter B')
    primary = relationship.get('primary_cluster') or 'Array-A'
    secondary = relationship.get('secondary_cluster') or 'Array-B'
    rd = relationship.get('relationship_data', {})
    pod_name = rd.get('pod_name') or 'pod'
    # Derive safe node IDs
    a_id = _safe_id(primary)
    b_id = _safe_id(secondary)

    lines = [
        'graph LR',
        f'  subgraph {_safe_id(site_a)}["{site_a}"]',
        f'    subgraph {a_id}_cluster["{primary}"]',
        f'      {a_id}_ct0[["CT0\\n(Controller)"]]',
        f'      {a_id}_ct1[["CT1\\n(Controller)"]]',
        f'      {a_id}_vip(["Mgmt VIP"])',
        f'    end',
        '  end',
        f'  subgraph {_safe_id(site_b)}["{site_b}"]',
        f'    subgraph {b_id}_cluster["{secondary}"]',
        f'      {b_id}_ct0[["CT0\\n(Controller)"]]',
        f'      {b_id}_ct1[["CT1\\n(Controller)"]]',
        f'      {b_id}_vip(["Mgmt VIP"])',
        f'    end',
        '  end',
        f'  M(["Mediator"])',
        f'  {a_id}_cluster <-->|"ActiveCluster\\n{pod_name}\\n(Synchronous)"| {b_id}_cluster',
        f'  {a_id}_cluster -.->|"Heartbeat"| M',
        f'  {b_id}_cluster -.->|"Heartbeat"| M',
    ]
    return '\n'.join(lines)


def generate_workflow_diagram(relationship, failover_direction='planned_failover'):
    """Return a Mermaid flowchart for the DR workflow."""
    site_a = relationship.get('primary_site', 'Site A')
    site_b = relationship.get('secondary_site', 'Site B')
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
    site_a = relationship.get('primary_site', 'Site A')
    site_b = relationship.get('secondary_site', 'Site B')
    steps = generate_workflow(relationship, failover_direction)
    commands = generate_commands(relationship, failover_direction)

    # Group steps by phase
    sections = {}
    for step in steps:
        phase = step['phase']
        sections.setdefault(phase, []).append(step)

    cmd_by_phase = {}
    for cmd in commands:
        cmd_by_phase.setdefault(cmd['phase'], []).append(cmd)

    result = []
    for phase, phase_steps in sections.items():
        result.append({
            'phase': phase,
            'steps': phase_steps,
            'commands': cmd_by_phase.get(phase, []),
        })

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_id(name):
    """Convert a name to a Mermaid-safe node ID."""
    return name.replace(' ', '_').replace('-', '_').replace('/', '_')
