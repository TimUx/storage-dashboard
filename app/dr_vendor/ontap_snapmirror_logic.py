"""NetApp ONTAP SnapMirror DR logic.

Provides generation rules and command templates for ONTAP SnapMirror
asynchronous replication environments.
"""

# ---------------------------------------------------------------------------
# DR relationship discovery
# ---------------------------------------------------------------------------

def discover_relationships(system_name, health_data):
    """Analyse health_data and return normalised SnapMirror DR relationship dicts."""
    relationships = []
    sm_list = health_data.get('snapmirror_relationships') or health_data.get('snapmirror', [])
    if not sm_list:
        return relationships

    if not isinstance(sm_list, list):
        sm_list = [sm_list]

    for sm in sm_list:
        if not isinstance(sm, dict):
            continue
        state = sm.get('state', 'unknown')
        replication_state = 'healthy' if state in ('snapmirrored', 'in_sync') else 'degraded'
        src_svm = sm.get('source', {}).get('svm', {}).get('name', '') if isinstance(sm.get('source'), dict) else ''
        dst_svm = sm.get('destination', {}).get('svm', {}).get('name', '') if isinstance(sm.get('destination'), dict) else ''

        relationships.append({
            'system_name': system_name,
            'vendor': 'netapp-ontap',
            'replication_type': 'snapmirror',
            'primary_site': src_svm or 'Primary Site',
            'secondary_site': dst_svm or 'Secondary Site',
            'primary_cluster': system_name,
            'secondary_cluster': sm.get('destination', {}).get('cluster', {}).get('name', '') if isinstance(sm.get('destination'), dict) else '',
            'replication_state': replication_state,
            'relationship_data': sm,
        })

    return relationships


# ---------------------------------------------------------------------------
# Topology building
# ---------------------------------------------------------------------------

def build_topology(relationship):
    site_a = relationship.get('primary_site', 'Site A')
    site_b = relationship.get('secondary_site', 'Site B')
    return {
        'sites': [
            {'name': site_a, 'role': 'primary'},
            {'name': site_b, 'role': 'secondary'},
        ],
        'nodes': [
            {'name': relationship.get('primary_cluster') or site_a, 'type': 'ontap-cluster', 'site': site_a},
            {'name': relationship.get('secondary_cluster') or site_b, 'type': 'ontap-cluster', 'site': site_b},
        ],
        'links': [
            {'source': site_a, 'target': site_b, 'type': 'async-replication', 'label': 'SnapMirror'}
        ],
        'vips': [],
    }


# ---------------------------------------------------------------------------
# Workflow generation
# ---------------------------------------------------------------------------

_WORKFLOW_STEPS = {
    'planned_failover': [
        {'phase': 'pre-failover', 'step': 1, 'title': 'Verify SnapMirror health',
         'description': 'Run snapmirror show to confirm all relationships are in "snapmirrored" state.'},
        {'phase': 'pre-failover', 'step': 2, 'title': 'Perform final SnapMirror update',
         'description': 'Trigger a manual update to minimise data loss before failover.'},
        {'phase': 'pre-failover', 'step': 3, 'title': 'Quiesce SnapMirror relationships',
         'description': 'Quiesce the SnapMirror relationships to prevent further updates during failover.'},
        {'phase': 'failover', 'step': 4, 'title': 'Break SnapMirror relationships',
         'description': 'Break the SnapMirror relationships to make the destination volumes read/write.'},
        {'phase': 'failover', 'step': 5, 'title': 'Bring up destination SVM',
         'description': 'Start the destination SVM and configure network interfaces.'},
        {'phase': 'post-failover', 'step': 6, 'title': 'Mount destination volumes',
         'description': 'Mount volumes and verify exports/shares on the destination SVM.'},
        {'phase': 'post-failover', 'step': 7, 'title': 'Redirect client connections',
         'description': 'Update DNS or mount points so clients connect to the destination SVM.'},
        {'phase': 'post-failover', 'step': 8, 'title': 'Validate data access',
         'description': 'Test application access to confirm data is readable and writeable.'},
    ],
    'failback': [
        {'phase': 'pre-failback', 'step': 1, 'title': 'Re-establish SnapMirror from destination to source',
         'description': 'Reverse the SnapMirror relationship so changes made at destination are replicated back.'},
        {'phase': 'failback', 'step': 2, 'title': 'Resync source volumes',
         'description': 'Run snapmirror resync to initialise the reverse relationship.'},
        {'phase': 'failback', 'step': 3, 'title': 'Quiesce and break reverse relationship',
         'description': 'Once synced, quiesce and break the reverse relationship to return to normal direction.'},
        {'phase': 'failback', 'step': 4, 'title': 'Restore original SnapMirror direction',
         'description': 'Resync the original relationship to bring source volumes up to date.'},
        {'phase': 'post-failback', 'step': 5, 'title': 'Redirect clients back to source',
         'description': 'Update client connections to the original SVM on the primary site.'},
        {'phase': 'post-failback', 'step': 6, 'title': 'Verify SnapMirror health',
         'description': 'Confirm all relationships are in "snapmirrored" state with no lag.'},
    ],
}


def generate_workflow(relationship, failover_direction='planned_failover'):
    return list(_WORKFLOW_STEPS.get(failover_direction, _WORKFLOW_STEPS['planned_failover']))


# ---------------------------------------------------------------------------
# Command generation
# ---------------------------------------------------------------------------

def generate_commands(relationship, failover_direction='planned_failover'):
    rd = relationship.get('relationship_data', {})
    src_vol = ''
    dst_vol = ''
    if isinstance(rd.get('source'), dict):
        src_vol = rd['source'].get('path', '*')
    if isinstance(rd.get('destination'), dict):
        dst_vol = rd['destination'].get('path', '*')

    primary = relationship.get('primary_cluster') or 'cluster1'

    commands = {
        'planned_failover': [
            {'phase': 'pre-failover', 'description': 'Show SnapMirror relationships',
             'cli': f'snapmirror show -destination-path {dst_vol}', 'target': primary},
            {'phase': 'pre-failover', 'description': 'Trigger manual update',
             'cli': f'snapmirror update -destination-path {dst_vol}', 'target': primary},
            {'phase': 'pre-failover', 'description': 'Quiesce relationship',
             'cli': f'snapmirror quiesce -destination-path {dst_vol}', 'target': primary},
            {'phase': 'failover', 'description': 'Break SnapMirror relationship',
             'cli': f'snapmirror break -destination-path {dst_vol}', 'target': primary},
            {'phase': 'failover', 'description': 'Start destination SVM',
             'cli': f'vserver start -vserver {relationship.get("secondary_site", "*")}', 'target': primary},
            {'phase': 'post-failover', 'description': 'Verify volume state on destination',
             'cli': f'volume show -vserver {relationship.get("secondary_site", "*")}', 'target': primary},
        ],
        'failback': [
            {'phase': 'pre-failback', 'description': 'Resync SnapMirror (reverse)',
             'cli': f'snapmirror resync -source-path {dst_vol} -destination-path {src_vol}', 'target': primary},
            {'phase': 'failback', 'description': 'Quiesce reverse relationship',
             'cli': f'snapmirror quiesce -destination-path {src_vol}', 'target': primary},
            {'phase': 'failback', 'description': 'Break reverse relationship',
             'cli': f'snapmirror break -destination-path {src_vol}', 'target': primary},
            {'phase': 'failback', 'description': 'Resync original direction',
             'cli': f'snapmirror resync -destination-path {dst_vol}', 'target': primary},
            {'phase': 'post-failback', 'description': 'Verify SnapMirror health',
             'cli': f'snapmirror show -destination-path {dst_vol}', 'target': primary},
        ],
    }

    return commands.get(failover_direction, commands['planned_failover'])


# ---------------------------------------------------------------------------
# Mermaid diagram generation
# ---------------------------------------------------------------------------

def generate_topology_diagram(relationship):
    """Return a Mermaid diagram string showing the SnapMirror topology.

    Includes Datacenter A & B, ONTAP clusters, nodes, SVMs, cluster VIPs,
    and the async SnapMirror replication link.
    """
    site_a = relationship.get('primary_site', 'Datacenter A')
    site_b = relationship.get('secondary_site', 'Datacenter B')
    primary = relationship.get('primary_cluster') or 'Cluster-Source'
    secondary = relationship.get('secondary_cluster') or 'Cluster-Dest'
    rd = relationship.get('relationship_data', {})
    src_svm = ''
    dst_svm = ''
    if isinstance(rd.get('source'), dict):
        src_svm = rd['source'].get('svm', {}).get('name', '') if isinstance(rd['source'].get('svm'), dict) else ''
    if isinstance(rd.get('destination'), dict):
        dst_svm = rd['destination'].get('svm', {}).get('name', '') if isinstance(rd['destination'].get('svm'), dict) else ''

    a_id = _safe_id(primary)
    b_id = _safe_id(secondary)

    lines = [
        'graph LR',
        f'  subgraph {_safe_id(site_a)}["{site_a}"]',
        f'    subgraph {a_id}_cluster["{primary} (Source)"]',
        f'      {a_id}_n0[["Node-01\\n(Controller)"]]',
        f'      {a_id}_n1[["Node-02\\n(Controller)"]]',
        f'      {a_id}_vip(["Cluster Mgmt VIP"])',
        f'      {a_id}_svm[("{src_svm or primary + "-SVM"}")]',
        '    end',
        '  end',
        f'  subgraph {_safe_id(site_b)}["{site_b}"]',
        f'    subgraph {b_id}_cluster["{secondary} (Destination)"]',
        f'      {b_id}_n0[["Node-01\\n(Controller)"]]',
        f'      {b_id}_n1[["Node-02\\n(Controller)"]]',
        f'      {b_id}_vip(["Cluster Mgmt VIP"])',
        f'      {b_id}_svm[("{dst_svm or secondary + "-SVM"}")]',
        '    end',
        '  end',
        f'  {a_id}_svm -->|"SnapMirror\\n(Asynchronous)"| {b_id}_svm',
    ]
    return '\n'.join(lines)


def generate_workflow_diagram(relationship, failover_direction='planned_failover'):
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
