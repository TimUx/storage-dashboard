"""NetApp StorageGRID multi-site DR logic.

Provides generation rules and command templates for StorageGRID
multi-site grid environments.
"""

# ---------------------------------------------------------------------------
# DR relationship discovery
# ---------------------------------------------------------------------------

def discover_relationships(system_name, health_data):
    """Analyse health_data and return normalised StorageGRID DR relationship dicts.

    Uses ``sites_info`` and ``site_count`` keys as returned by
    NetAppStorageGRIDClient.get_health_status().

    ``sites_info`` is populated in priority order:
    1. Explicit site list from GET /api/v4/grid/expansion/sites (authoritative,
       lists all sites even if their nodes are offline).
    2. Unique siteNames derived from GET /api/v4/grid/node-health (fallback when
       the expansion/sites endpoint is unavailable).
    """
    relationships = []

    # The health_data returned by NetAppStorageGRIDClient.get_health_status()
    # stores multi-site info as sites_info (list of {name: ...}) built from the
    # unique siteNames of all nodes returned by /api/v4/grid/node-health.
    sites = health_data.get('sites_info') or []
    if not isinstance(sites, list) or len(sites) < 2:
        return relationships

    site_a = sites[0].get('name', 'Site A') if isinstance(sites[0], dict) else str(sites[0])
    site_b = sites[1].get('name', 'Site B') if isinstance(sites[1], dict) else str(sites[1])

    grid_name = health_data.get('grid_name') or system_name
    replication_state = 'unknown'

    relationships.append({
        'system_name': system_name,
        'vendor': 'netapp-storagegrid',
        'replication_type': 'storagegrid-multisite',
        'primary_site': site_a,
        'secondary_site': site_b,
        'primary_cluster': grid_name,
        'secondary_cluster': grid_name,
        'replication_state': replication_state,
        'relationship_data': {
            'grid_name': grid_name,
            'sites': sites,
            'node_count': health_data.get('node_count'),
        },
    })

    return relationships


# ---------------------------------------------------------------------------
# Topology building
# ---------------------------------------------------------------------------

def build_topology(relationship):
    site_a = relationship.get('primary_site', 'Site A')
    site_b = relationship.get('secondary_site', 'Site B')
    rd = relationship.get('relationship_data', {})
    sites = rd.get('sites', [])

    nodes = []
    for site in sites:
        if isinstance(site, dict):
            site_name = site.get('name', 'site')
            for node in site.get('nodes', []):
                if isinstance(node, dict):
                    nodes.append({
                        'name': node.get('name', 'node'),
                        'type': node.get('type', 'storage-node'),
                        'site': site_name,
                    })

    return {
        'sites': [
            {'name': site_a, 'role': 'primary'},
            {'name': site_b, 'role': 'secondary'},
        ],
        'nodes': nodes,
        'links': [
            {'source': site_a, 'target': site_b, 'type': 'object-replication', 'label': 'ILM Replication'}
        ],
        'vips': [],
    }


# ---------------------------------------------------------------------------
# Workflow generation
# ---------------------------------------------------------------------------

_WORKFLOW_STEPS = {
    'planned_failover': [
        {'phase': 'pre-failover', 'step': 1, 'title': 'Grid-Status prüfen',
         'description': 'Check Grid Manager dashboard for any active alerts on the primary site nodes.'},
        {'phase': 'pre-failover', 'step': 2, 'title': 'ILM-Policy prüfen',
         'description': 'Confirm the ILM policy protects all critical buckets with copies on the secondary site.'},
        {'phase': 'pre-failover', 'step': 3, 'title': 'Replikationswarteschlange prüfen',
         'description': 'Verify no large pending replication queue exists before isolating the primary site.'},
        {'phase': 'failover', 'step': 4, 'title': 'Primären Standort isolieren',
         'description': 'Shut down or network-isolate the primary site admin and storage nodes.'},
        {'phase': 'failover', 'step': 5, 'title': 'Sekundären Admin-Node aktivieren',
         'description': 'Use Grid Manager on the secondary site to take over grid operations.'},
        {'phase': 'post-failover', 'step': 6, 'title': 'Objektzugriff am sekundären Standort prüfen',
         'description': 'Confirm S3/Swift clients can connect to the secondary site load balancer endpoints.'},
        {'phase': 'post-failover', 'step': 7, 'title': 'DNS-Endpunkte aktualisieren',
         'description': 'Point S3/Swift DNS entries to the secondary site load balancer VIPs.'},
        {'phase': 'post-failover', 'step': 8, 'title': 'ILM am sekundären Standort validieren',
         'description': 'Review Grid Manager to confirm ILM is running and objects are protected.'},
    ],
    'failback': [
        {'phase': 'pre-failback', 'step': 1, 'title': 'Primäre Standort-Nodes wiederherstellen',
         'description': 'Bring primary site admin and storage nodes back online.'},
        {'phase': 'pre-failback', 'step': 2, 'title': 'Primären Standort mit Grid verbinden',
         'description': 'Verify primary site nodes appear in Grid Manager.'},
        {'phase': 'failback', 'step': 3, 'title': 'Datenresynchronisierung abwarten',
         'description': 'Allow ILM to replicate objects back to the primary site as configured.'},
        {'phase': 'post-failback', 'step': 4, 'title': 'Clients zurück zum primären Standort umleiten',
         'description': 'Update DNS to point S3/Swift endpoints back to the primary site.'},
        {'phase': 'post-failback', 'step': 5, 'title': 'Grid-Status prüfen',
         'description': 'Confirm all nodes in Grid Manager report Connected status.'},
    ],
}


def generate_workflow(relationship, failover_direction='planned_failover'):
    return list(_WORKFLOW_STEPS.get(failover_direction, _WORKFLOW_STEPS['planned_failover']))


# ---------------------------------------------------------------------------
# Command generation
# ---------------------------------------------------------------------------

def generate_commands(relationship, failover_direction='planned_failover'):
    primary = relationship.get('primary_cluster') or 'sgadmin1'

    commands = {
        'planned_failover': [
            {'phase': 'pre-failover', 'description': 'Check grid node status via API',
             'cli': 'curl -s -k "https://{admin_node}/api/v4/grid/node-health" -H "Authorization: Bearer $TOKEN"',
             'target': primary},
            {'phase': 'pre-failover', 'description': 'Check ILM evaluation queue',
             'cli': 'curl -s -k "https://{admin_node}/api/v4/grid/ilm/metrics" -H "Authorization: Bearer $TOKEN"',
             'target': primary},
            {'phase': 'failover', 'description': 'Verify secondary site admin node readiness',
             'cli': 'curl -s -k "https://{secondary_admin_node}/api/v4/grid/health" -H "Authorization: Bearer $TOKEN"',
             'target': primary},
            {'phase': 'post-failover', 'description': 'Verify S3 endpoint on secondary',
             'cli': 'curl -s -k "https://{secondary_lb}/health"',
             'target': primary},
        ],
        'failback': [
            {'phase': 'pre-failback', 'description': 'Check primary node status',
             'cli': 'curl -s -k "https://{admin_node}/api/v4/grid/node-health" -H "Authorization: Bearer $TOKEN"',
             'target': primary},
            {'phase': 'post-failback', 'description': 'Verify grid health after failback',
             'cli': 'curl -s -k "https://{admin_node}/api/v4/grid/health" -H "Authorization: Bearer $TOKEN"',
             'target': primary},
        ],
    }

    return commands.get(failover_direction, commands['planned_failover'])


# ---------------------------------------------------------------------------
# Mermaid diagram generation
# ---------------------------------------------------------------------------

def generate_topology_diagram(relationship):
    site_a = relationship.get('primary_site', 'Site A')
    site_b = relationship.get('secondary_site', 'Site B')
    grid = relationship.get('primary_cluster') or 'Grid'

    lines = [
        'graph TD',
        f'  subgraph {_safe_id(site_a)}["{site_a}"]',
        f'    direction LR',
        f'    SGADM_A["Admin Node A\\n{grid}"]',
        f'    SGSN_A["Storage Nodes\\n{site_a}"]',
        f'    SGLB_A["Load Balancer\\n{site_a}"]',
        '  end',
        f'  subgraph {_safe_id(site_b)}["{site_b}"]',
        f'    direction LR',
        f'    SGADM_B["Admin Node B\\n{grid}"]',
        f'    SGSN_B["Storage Nodes\\n{site_b}"]',
        f'    SGLB_B["Load Balancer\\n{site_b}"]',
        '  end',
        '  SGSN_A <-->|"ILM\\nReplication"| SGSN_B',
        '  SGADM_A <-->|"Grid\\nManagement"| SGADM_B',
        '  S3_CLIENT["S3/Swift Clients"] --> SGLB_A',
        '  S3_CLIENT --> SGLB_B',
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
