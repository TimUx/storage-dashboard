"""NetApp ONTAP MetroCluster DR logic.

Provides generation rules and command templates for ONTAP MetroCluster
(synchronous site-level replication) environments.
"""

# ---------------------------------------------------------------------------
# DR relationship discovery
# ---------------------------------------------------------------------------

def discover_relationships(system_name, health_data):
    """Analyse health_data and return normalised MetroCluster DR relationship dicts."""
    relationships = []
    mc_info = health_data.get('metrocluster') or health_data.get('metro_cluster')
    if not mc_info:
        return relationships

    if isinstance(mc_info, dict):
        sites = mc_info.get('sites', [])
        site_a = sites[0].get('name', 'Site A') if len(sites) > 0 else 'Site A'
        site_b = sites[1].get('name', 'Site B') if len(sites) > 1 else 'Site B'
        state = mc_info.get('configuration_state', 'unknown')
    else:
        site_a, site_b = 'Site A', 'Site B'
        state = 'unknown'

    replication_state = 'healthy' if state in ('configured', 'healthy') else 'degraded'

    relationships.append({
        'system_name': system_name,
        'vendor': 'netapp-ontap',
        'replication_type': 'metrocluster',
        'primary_site': site_a,
        'secondary_site': site_b,
        'primary_cluster': system_name,
        'secondary_cluster': '',
        'replication_state': replication_state,
        'relationship_data': {'metrocluster': mc_info if isinstance(mc_info, dict) else {}},
    })

    return relationships


# ---------------------------------------------------------------------------
# Topology building
# ---------------------------------------------------------------------------

def build_topology(relationship):
    """Return a topology dict for the given MetroCluster DR relationship."""
    site_a = relationship.get('primary_site', 'Site A')
    site_b = relationship.get('secondary_site', 'Site B')
    rd = relationship.get('relationship_data', {})
    mc = rd.get('metrocluster', {})
    nodes = mc.get('nodes', [])

    topo_nodes = []
    for node in nodes:
        topo_nodes.append({
            'name': node.get('name', 'node'),
            'type': 'ontap-node',
            'site': node.get('dr_home_port', {}).get('node', {}).get('name', site_a),
        })

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
        'vips': [],
    }


# ---------------------------------------------------------------------------
# Workflow generation
# ---------------------------------------------------------------------------

_WORKFLOW_STEPS = {
    'planned_failover': [
        {'phase': 'pre-failover', 'step': 1, 'title': 'Verify MetroCluster health',
         'description': 'Run metrocluster check run and review the output for any errors.'},
        {'phase': 'pre-failover', 'step': 2, 'title': 'Check replication state',
         'description': 'Confirm metrocluster show reports "configured" and all nodes are reachable.'},
        {'phase': 'pre-failover', 'step': 3, 'title': 'Stop client I/O',
         'description': 'Suspend application I/O to all volumes on the primary site SVMs.'},
        {'phase': 'failover', 'step': 4, 'title': 'Initiate MetroCluster switchover',
         'description': 'Execute a negotiated switchover from the primary to the secondary site.'},
        {'phase': 'failover', 'step': 5, 'title': 'Verify switchover completion',
         'description': 'Run metrocluster show to confirm operational state is "switchover".'},
        {'phase': 'post-failover', 'step': 6, 'title': 'Bring SVMs online on secondary',
         'description': 'Verify that all migrated SVMs are running on the secondary cluster.'},
        {'phase': 'post-failover', 'step': 7, 'title': 'Update client connections',
         'description': 'Redirect NFS/CIFS/iSCSI clients to the secondary site LIFs.'},
        {'phase': 'post-failover', 'step': 8, 'title': 'Validate data integrity',
         'description': 'Run volume status checks and application smoke tests.'},
    ],
    'failback': [
        {'phase': 'pre-failback', 'step': 1, 'title': 'Restore primary site',
         'description': 'Confirm all primary site hardware is operational.'},
        {'phase': 'pre-failback', 'step': 2, 'title': 'Verify MetroCluster switchback readiness',
         'description': 'Run metrocluster switchback -simulate to check for blockers.'},
        {'phase': 'failback', 'step': 3, 'title': 'Execute switchback',
         'description': 'Perform metrocluster switchback to return operations to the primary site.'},
        {'phase': 'failback', 'step': 4, 'title': 'Verify switchback',
         'description': 'Confirm metrocluster show shows "normal" operational state.'},
        {'phase': 'post-failback', 'step': 5, 'title': 'Reconnect clients to primary',
         'description': 'Update client connections back to the primary site LIFs.'},
        {'phase': 'post-failback', 'step': 6, 'title': 'Validate MetroCluster health',
         'description': 'Run metrocluster check run and confirm all checks pass.'},
    ],
}


def generate_workflow(relationship, failover_direction='planned_failover'):
    """Return workflow steps for the given failover direction."""
    return list(_WORKFLOW_STEPS.get(failover_direction, _WORKFLOW_STEPS['planned_failover']))


# ---------------------------------------------------------------------------
# Command generation
# ---------------------------------------------------------------------------

def generate_commands(relationship, failover_direction='planned_failover'):
    """Return CLI command objects for the given failover direction."""
    primary = relationship.get('primary_cluster') or 'cluster1'

    commands = {
        'planned_failover': [
            {'phase': 'pre-failover', 'description': 'Check MetroCluster configuration',
             'cli': 'metrocluster show', 'target': primary},
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
            {'phase': 'failover', 'description': 'Verify switchover state',
             'cli': 'metrocluster show', 'target': primary},
            {'phase': 'post-failover', 'description': 'Show SVMs on secondary',
             'cli': 'vserver show', 'target': primary},
            {'phase': 'post-failover', 'description': 'Show LIF status on secondary',
             'cli': 'network interface show', 'target': primary},
        ],
        'failback': [
            {'phase': 'pre-failback', 'description': 'Simulate switchback (dry run)',
             'cli': 'metrocluster switchback -simulate', 'target': primary},
            {'phase': 'failback', 'description': 'Execute switchback',
             'cli': 'metrocluster switchback', 'target': primary},
            {'phase': 'failback', 'description': 'Verify normal state',
             'cli': 'metrocluster show', 'target': primary},
            {'phase': 'post-failback', 'description': 'Run health check post-switchback',
             'cli': 'metrocluster check run', 'target': primary},
            {'phase': 'post-failback', 'description': 'Review check results',
             'cli': 'metrocluster check show', 'target': primary},
        ],
    }

    return commands.get(failover_direction, commands['planned_failover'])


# ---------------------------------------------------------------------------
# Mermaid diagram generation
# ---------------------------------------------------------------------------

def generate_topology_diagram(relationship):
    """Return a Mermaid diagram string showing the MetroCluster topology."""
    site_a = relationship.get('primary_site', 'Site A')
    site_b = relationship.get('secondary_site', 'Site B')
    primary = relationship.get('primary_cluster') or 'Cluster A'

    lines = [
        'graph LR',
        f'  subgraph {_safe_id(site_a)}["{site_a}"]',
        f'    MC_A["{primary}\\nONTAP MetroCluster\\n(Primary)"]',
        '  end',
        f'  subgraph {_safe_id(site_b)}["{site_b}"]',
        f'    MC_B["Cluster B\\nONTAP MetroCluster\\n(Secondary)"]',
        '  end',
        '  ISL["ISL / FC Switch"]',
        '  MC_A <-->|"Synchronous\\nReplication"| ISL',
        '  ISL <-->|"MetroCluster\\nISL"| MC_B',
    ]
    return '\n'.join(lines)


def generate_workflow_diagram(relationship, failover_direction='planned_failover'):
    """Return a Mermaid flowchart for the MetroCluster DR workflow."""
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
