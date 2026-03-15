"""Dell DataDomain replication DR logic.

Provides generation rules and command templates for DataDomain
MTree replication environments.
"""

# ---------------------------------------------------------------------------
# DR relationship discovery
# ---------------------------------------------------------------------------

def discover_relationships(system_name, health_data):
    """Analyse health_data and return normalised DataDomain DR relationship dicts."""
    relationships = []
    replication = health_data.get('replication') or health_data.get('dd_replication', [])
    if not replication:
        return relationships

    if not isinstance(replication, list):
        replication = [replication]

    for rep in replication:
        if not isinstance(rep, dict):
            continue
        state = rep.get('state', 'unknown')
        replication_state = 'healthy' if state in ('replicating', 'active', 'idle') else 'degraded'

        relationships.append({
            'system_name': system_name,
            'vendor': 'dell-datadomain',
            'replication_type': 'datadomain-replication',
            'primary_site': rep.get('source', {}).get('host', system_name) if isinstance(rep.get('source'), dict) else system_name,
            'secondary_site': rep.get('destination', {}).get('host', 'Secondary') if isinstance(rep.get('destination'), dict) else 'Secondary',
            'primary_cluster': system_name,
            'secondary_cluster': rep.get('destination', {}).get('host', '') if isinstance(rep.get('destination'), dict) else '',
            'replication_state': replication_state,
            'relationship_data': rep,
        })

    return relationships


# ---------------------------------------------------------------------------
# Topology building
# ---------------------------------------------------------------------------

def build_topology(relationship):
    site_a = relationship.get('primary_site', 'Primary')
    site_b = relationship.get('secondary_site', 'Secondary')
    primary = relationship.get('primary_cluster') or site_a
    secondary = relationship.get('secondary_cluster') or site_b

    return {
        'sites': [
            {'name': site_a, 'role': 'primary'},
            {'name': site_b, 'role': 'secondary'},
        ],
        'nodes': [
            {'name': primary, 'type': 'datadomain', 'site': site_a},
            {'name': secondary, 'type': 'datadomain', 'site': site_b},
        ],
        'links': [
            {'source': site_a, 'target': site_b, 'type': 'mtree-replication', 'label': 'DD MTree Replication'}
        ],
        'vips': [],
    }


# ---------------------------------------------------------------------------
# Workflow generation
# ---------------------------------------------------------------------------

_WORKFLOW_STEPS = {
    'planned_failover': [
        {'phase': 'pre-failover', 'step': 1, 'title': 'Verify DataDomain replication health',
         'description': 'Check replication status and ensure all MTree replications are in sync.'},
        {'phase': 'pre-failover', 'step': 2, 'title': 'Force final replication sync',
         'description': 'Trigger a manual sync for all MTrees to minimise data loss.'},
        {'phase': 'pre-failover', 'step': 3, 'title': 'Stop backup jobs',
         'description': 'Suspend backup jobs targeting the primary DataDomain.'},
        {'phase': 'failover', 'step': 4, 'title': 'Break replication on destination',
         'description': 'On the destination DataDomain, break the replication context and promote MTree as read/write.'},
        {'phase': 'failover', 'step': 5, 'title': 'Configure backup server to use destination',
         'description': 'Reconfigure the backup server (NetBackup / Veeam / Commvault) to use the destination DataDomain.'},
        {'phase': 'post-failover', 'step': 6, 'title': 'Resume backup jobs',
         'description': 'Resume backup jobs now targeting the destination DataDomain.'},
        {'phase': 'post-failover', 'step': 7, 'title': 'Validate data access',
         'description': 'Verify that backup catalogs and restore points are accessible on the destination.'},
    ],
    'failback': [
        {'phase': 'pre-failback', 'step': 1, 'title': 'Restore primary DataDomain',
         'description': 'Confirm the primary DataDomain is online and reachable.'},
        {'phase': 'pre-failback', 'step': 2, 'title': 'Re-establish replication to primary',
         'description': 'Configure replication from the destination back to the primary DataDomain.'},
        {'phase': 'failback', 'step': 3, 'title': 'Sync data back to primary',
         'description': 'Allow all MTrees to replicate back to the primary site.'},
        {'phase': 'failback', 'step': 4, 'title': 'Redirect backup server to primary',
         'description': 'Reconfigure the backup server to use the primary DataDomain.'},
        {'phase': 'post-failback', 'step': 5, 'title': 'Restore original replication direction',
         'description': 'Re-establish original replication from primary to secondary.'},
        {'phase': 'post-failback', 'step': 6, 'title': 'Verify replication health',
         'description': 'Confirm all MTree replications are healthy and in sync.'},
    ],
}


def generate_workflow(relationship, failover_direction='planned_failover'):
    return list(_WORKFLOW_STEPS.get(failover_direction, _WORKFLOW_STEPS['planned_failover']))


# ---------------------------------------------------------------------------
# Command generation
# ---------------------------------------------------------------------------

def generate_commands(relationship, failover_direction='planned_failover'):
    rd = relationship.get('relationship_data', {})
    mtree = ''
    if isinstance(rd.get('source'), dict):
        mtree = rd['source'].get('mtree', '/data/col1/backup')
    else:
        mtree = '/data/col1/backup'

    primary = relationship.get('primary_cluster') or 'dd1'
    secondary = relationship.get('secondary_cluster') or 'dd2'

    commands = {
        'planned_failover': [
            {'phase': 'pre-failover', 'description': 'Check replication status',
             'cli': 'replication show', 'target': primary},
            {'phase': 'pre-failover', 'description': 'Sync replication',
             'cli': f'replication sync ctx://remote/{mtree}', 'target': primary},
            {'phase': 'failover', 'description': 'Break replication context on destination',
             'cli': f'replication break ctx://remote/{mtree}', 'target': secondary},
            {'phase': 'failover', 'description': 'Show MTree status on destination',
             'cli': f'mtree show {mtree}', 'target': secondary},
            {'phase': 'post-failover', 'description': 'Verify data availability',
             'cli': f'filesys show space {mtree}', 'target': secondary},
        ],
        'failback': [
            {'phase': 'pre-failback', 'description': 'Check primary DataDomain health',
             'cli': 'system show', 'target': primary},
            {'phase': 'failback', 'description': 'Re-establish replication to primary',
             'cli': f'replication add source mtree://localhost{mtree} destination mtree://{primary}{mtree}',
             'target': secondary},
            {'phase': 'failback', 'description': 'Sync data back to primary',
             'cli': f'replication sync ctx://remote/{mtree}', 'target': secondary},
            {'phase': 'post-failback', 'description': 'Verify replication health',
             'cli': 'replication show', 'target': primary},
        ],
    }

    return commands.get(failover_direction, commands['planned_failover'])


# ---------------------------------------------------------------------------
# Mermaid diagram generation
# ---------------------------------------------------------------------------

def generate_topology_diagram(relationship):
    site_a = relationship.get('primary_site', 'Primary')
    site_b = relationship.get('secondary_site', 'Secondary')
    primary = relationship.get('primary_cluster') or 'DD Primary'
    secondary = relationship.get('secondary_cluster') or 'DD Secondary'

    lines = [
        'graph LR',
        f'  subgraph {_safe_id(site_a)}["{site_a}"]',
        f'    DD_PRI["{primary}\\nDataDomain\\n(Source)"]',
        f'    BCK["Backup\\nServer"]',
        '  end',
        f'  subgraph {_safe_id(site_b)}["{site_b}"]',
        f'    DD_SEC["{secondary}\\nDataDomain\\n(Destination)"]',
        '  end',
        '  BCK -->|"Backup"| DD_PRI',
        '  DD_PRI -->|"MTree\\nReplication"| DD_SEC',
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
