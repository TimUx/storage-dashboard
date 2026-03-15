"""Dell DataDomain replication DR logic.

Provides generation rules and command templates for DataDomain
MTree replication environments.

Supported failover directions
------------------------------
planned_failover
    Negotiated failover when both sites are up.  Performs a final sync
    before breaking replication to minimise data loss.

failback
    Return operations to the primary site after it has been restored.
    Re-establishes replication from the DR site back to primary, syncs
    data, then restores original replication direction.

disaster_recovery
    Unplanned failover from the surviving DR site after the primary
    DataDomain system is unreachable.  Skips the sync step (primary is
    down) and proceeds directly to break → promote → validate → switch.

    Per Dell documentation the full MTree disaster recovery procedure is:
    https://www.dell.com/support/kbdoc/en-us/000317549/
    data-domain-best-practices-for-data-migration-on-powerprotect-
    data-domain-systems-using-mtree-replication

    The 7-phase workflow is:
    1. Disaster detection
    2. Replication validation (on surviving DR system)
    3. Break replication context
    4. Promote DR MTree to read/write
    5. Validate filesystem state
    6. Switch backup infrastructure to DR system
    7. Recreate replication after primary recovery
"""

# ---------------------------------------------------------------------------
# DR relationship discovery
# ---------------------------------------------------------------------------

def discover_relationships(system_name, health_data):
    """Analyse health_data and return normalised DataDomain DR relationship dicts.

    Uses ``mtree_replications`` (preferred) from the schema-defined endpoint
    GET /api/v1/dd-systems/0/mtree-replications (per dd_api.json), falling back
    to ``replication_status.contexts`` from the legacy REST v1.0 endpoint.

    Each MtreeReplicationDetail entry provides source_host, destination_host,
    source_mtree, destination_mtree, mode (SOURCE/TARGET), state and connected.
    """
    relationships = []

    # Prefer the structured MTree replication list collected via the API schema
    # endpoint.  Fall back to the legacy replication context list.
    mtree_repls = health_data.get('mtree_replications') or []
    if not mtree_repls:
        repl_status = health_data.get('replication_status') or {}
        legacy_contexts = repl_status.get('contexts') or []
        for ctx in legacy_contexts:
            if not isinstance(ctx, dict):
                continue
            remote = ctx.get('remote_host', '')
            direction = (ctx.get('direction') or '').upper()
            is_outbound = direction == 'OUTBOUND'
            mtree_repls.append({
                'mode': 'SOURCE' if is_outbound else 'TARGET',
                'state': ctx.get('state', 'unknown'),
                'connected': True,
                'source_host': system_name if is_outbound else remote,
                'destination_host': remote if is_outbound else system_name,
                'source_mtree': None,
                'destination_mtree': None,
            })

    if not mtree_repls:
        return relationships

    for repl in mtree_repls:
        if not isinstance(repl, dict):
            continue

        state = (repl.get('state') or 'unknown').upper()
        connected = repl.get('connected', False)
        replication_state = 'healthy' if state in ('NORMAL', 'RESYNCING') and connected else 'degraded'

        mode = (repl.get('mode') or 'SOURCE').upper()
        source_host = repl.get('source_host') or system_name
        dest_host = repl.get('destination_host') or 'Secondary'

        # The source is always the primary and the destination the secondary,
        # regardless of whether the local system is the SOURCE or TARGET.
        primary_site = source_host
        secondary_site = dest_host
        primary_cluster = source_host
        secondary_cluster = dest_host

        relationships.append({
            'system_name': system_name,
            'vendor': 'dell-datadomain',
            'replication_type': 'datadomain-replication',
            'primary_site': primary_site,
            'secondary_site': secondary_site,
            'primary_cluster': primary_cluster,
            'secondary_cluster': secondary_cluster,
            'replication_state': replication_state,
            'relationship_data': {
                'source': {'host': source_host, 'mtree': repl.get('source_mtree')},
                'destination': {'host': dest_host, 'mtree': repl.get('destination_mtree')},
                'state': repl.get('state'),
                'connected': connected,
                'mode': mode,
            },
        })

    return relationships


# ---------------------------------------------------------------------------
# Topology building
# ---------------------------------------------------------------------------

def build_topology(relationship):
    """Return an enhanced topology dict for the given DataDomain DR relationship.

    Includes both sites, HA controller nodes (Node-A/Node-B) per appliance,
    management VIPs, Backup Server, and MTree replication link.
    """
    site_a = relationship.get('primary_site', 'Datacenter A')
    site_b = relationship.get('secondary_site', 'Datacenter B')
    primary = relationship.get('primary_cluster') or site_a
    secondary = relationship.get('secondary_cluster') or site_b
    rd = relationship.get('relationship_data', {})
    mtree = ''
    if isinstance(rd.get('source'), dict):
        mtree = rd['source'].get('mtree', '/data/col1/backup')

    nodes = [
        # Primary appliance HA nodes
        {'name': f'{primary}-Node-A', 'type': 'dd-node', 'site': site_a},
        {'name': f'{primary}-Node-B', 'type': 'dd-node', 'site': site_a},
        # Backup server at primary site
        {'name': 'Backup-Server', 'type': 'backup-server', 'site': site_a},
        # Secondary appliance HA nodes
        {'name': f'{secondary}-Node-A', 'type': 'dd-node', 'site': site_b},
        {'name': f'{secondary}-Node-B', 'type': 'dd-node', 'site': site_b},
    ]

    vips = [
        {'name': f'{primary}-MgmtVIP', 'type': 'management', 'appliance': primary},
        {'name': f'{secondary}-MgmtVIP', 'type': 'management', 'appliance': secondary},
    ]

    return {
        'sites': [
            {'name': site_a, 'role': 'primary'},
            {'name': site_b, 'role': 'secondary'},
        ],
        'nodes': nodes,
        'links': [
            {
                'source': site_a,
                'target': site_b,
                'type': 'mtree-replication',
                'label': f'DD MTree Replication{(" – " + mtree) if mtree else ""}',
            }
        ],
        'vips': vips,
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
    # Disaster recovery: unplanned failover from the surviving DR site after the
    # primary DataDomain system is unreachable.  No sync step because the source
    # is down — proceed directly to break → promote → validate → switch.
    # Reference: https://www.dell.com/support/kbdoc/en-us/000317549/
    #   data-domain-best-practices-for-data-migration-on-powerprotect-
    #   data-domain-systems-using-mtree-replication
    'disaster_recovery': [
        {'phase': 'detection', 'step': 1, 'title': 'Disaster detected',
         'description': (
             'Confirm the primary DataDomain system is unreachable.  Verify that the '
             'source system and its replication contexts cannot be reached before '
             'proceeding with the unplanned failover.'
         )},
        {'phase': 'validation', 'step': 2, 'title': 'Validate replication state on DR system',
         'description': (
             'On the DR (destination) DataDomain run replication status, '
             'replication show config, filesys status, and alerts show to assess '
             'the last known replication state, filesystem health, and any active alerts.'
         )},
        {'phase': 'break-replication', 'step': 3, 'title': 'Break replication context',
         'description': (
             'Break the MTree replication context on the DR DataDomain to sever the '
             'relationship and allow the destination MTree to become read/write.  '
             'Because the source is down, no sync step is performed first: '
             'replication break ctx://remote/<mtree>'
         )},
        {'phase': 'promote-mtree', 'step': 4, 'title': 'Promote DR MTree to read/write',
         'description': (
             'Verify that the destination MTree is now writable.  Confirm with '
             'mtree show and filesys show space that the data is intact and the '
             'MTree is in a healthy state.'
         )},
        {'phase': 'validate-filesystem', 'step': 5, 'title': 'Validate filesystem state',
         'description': (
             'Check the DataDomain filesystem status to confirm it is fully operational.  '
             'Review active alerts and confirm no filesystem errors are present.'
         )},
        {'phase': 'switch-backup', 'step': 6, 'title': 'Switch backup infrastructure to DR system',
         'description': (
             'Reconfigure the backup server (NetBackup, Veeam, Commvault) to target '
             'the DR DataDomain.  Update device paths and re-import backup catalogs '
             'from the promoted MTree.  Resume backup and restore operations.'
         )},
        {'phase': 'recreate-replication', 'step': 7, 'title': 'Recreate replication after primary recovery',
         'description': (
             'When the primary DataDomain returns, re-establish MTree replication in the '
             'original direction to resync data accumulated at the DR site: '
             'replication add source mtree://localhost<mtree> destination mtree://<primary><mtree>'
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
    *relationship*.  This ensures that MTree paths and system names reflect
    the actual discovered environment.

    Supported directions: ``planned_failover``, ``failback``,
    ``disaster_recovery``.
    """
    rd = relationship.get('relationship_data', {})
    mtree = ''
    if isinstance(rd.get('source'), dict):
        mtree = rd['source'].get('mtree', '/data/col1/backup')
    else:
        mtree = '/data/col1/backup'

    primary = relationship.get('primary_cluster') or 'dd1'
    secondary = relationship.get('secondary_cluster') or 'dd2'

    # For disaster recovery, commands run on the surviving (DR/destination) system
    # because the primary is down.
    dr_target = secondary

    commands = {
        'planned_failover': [
            {'phase': 'pre-failover', 'description': 'Check replication status',
             'cli': 'replication status', 'target': primary},
            {'phase': 'pre-failover', 'description': 'Show replication configuration',
             'cli': 'replication show config', 'target': primary},
            {'phase': 'pre-failover', 'description': 'Check filesystem status',
             'cli': 'filesys status', 'target': primary},
            {'phase': 'pre-failover', 'description': 'Show active alerts',
             'cli': 'alerts show', 'target': primary},
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
        # Disaster recovery commands executed on the *surviving* (DR/destination) system.
        # Reference: https://www.dell.com/support/kbdoc/en-us/000317549/
        #   data-domain-best-practices-for-data-migration-on-powerprotect-
        #   data-domain-systems-using-mtree-replication
        'disaster_recovery': [
            # Phase: validation (assess last known replication state on DR system)
            {'phase': 'validation', 'description': 'Check replication status on DR system',
             'cli': 'replication status', 'target': dr_target},
            {'phase': 'validation', 'description': 'Show replication configuration on DR system',
             'cli': 'replication show config', 'target': dr_target},
            {'phase': 'validation', 'description': 'Check filesystem status on DR system',
             'cli': 'filesys status', 'target': dr_target},
            {'phase': 'validation', 'description': 'Show active alerts on DR system',
             'cli': 'alerts show', 'target': dr_target},
            # Phase: break-replication (no sync — source is down)
            {'phase': 'break-replication', 'description': 'Break replication context on DR system',
             'cli': f'replication break ctx://remote/{mtree}', 'target': dr_target},
            # Phase: promote-mtree
            {'phase': 'promote-mtree', 'description': 'Show MTree status after break',
             'cli': f'mtree show {mtree}', 'target': dr_target},
            {'phase': 'promote-mtree', 'description': 'Verify MTree space on DR system',
             'cli': f'filesys show space {mtree}', 'target': dr_target},
            # Phase: validate-filesystem
            {'phase': 'validate-filesystem', 'description': 'Validate filesystem health',
             'cli': 'filesys status', 'target': dr_target},
            {'phase': 'validate-filesystem', 'description': 'Confirm no critical alerts',
             'cli': 'alerts show current', 'target': dr_target},
            # Phase: recreate-replication (after primary recovery)
            {'phase': 'recreate-replication',
             'description': 'Re-establish MTree replication from DR back to primary',
             'cli': (
                 f'replication add source mtree://localhost{mtree} '
                 f'destination mtree://{primary}{mtree}'
             ),
             'target': dr_target},
            {'phase': 'recreate-replication', 'description': 'Verify recreated replication context',
             'cli': 'replication show config', 'target': dr_target},
        ],
    }

    return commands.get(failover_direction, commands['planned_failover'])


# ---------------------------------------------------------------------------
# Mermaid diagram generation
# ---------------------------------------------------------------------------

def generate_topology_diagram(relationship):
    """Return an enhanced Mermaid diagram showing the DataDomain replication topology.

    Includes Datacenter A & B subgraphs, DataDomain appliances with HA nodes
    (Node-A/Node-B), management VIPs, MTree path, Backup Server connection,
    and the async MTree replication link.
    """
    site_a = relationship.get('primary_site', 'Datacenter A')
    site_b = relationship.get('secondary_site', 'Datacenter B')
    primary = relationship.get('primary_cluster') or 'DD-Primary'
    secondary = relationship.get('secondary_cluster') or 'DD-Secondary'
    rd = relationship.get('relationship_data', {})
    mtree = ''
    if isinstance(rd.get('source'), dict):
        mtree = rd['source'].get('mtree', '')

    a_id = _safe_id(primary)
    b_id = _safe_id(secondary)
    mtree_label = f'MTree Replication\\n{mtree}' if mtree else 'MTree Replication'

    lines = [
        'graph LR',
        f'  subgraph {_safe_id(site_a)}["{site_a}"]',
        f'    subgraph {a_id}_appliance["{primary} (Source)"]',
        f'      {a_id}_na[["Node-A\\n(Controller)"]]',
        f'      {a_id}_nb[["Node-B\\n(Controller)"]]',
        f'      {a_id}_vip(["Mgmt VIP"])',
        f'      {a_id}_mt[["{mtree or "/data/col1"}\\n(MTree)"]]]',
        '    end',
        f'    BCK_A[("Backup Server")]',
        f'    BCK_A -->|"Backup"| {a_id}_appliance',
        '  end',
        f'  subgraph {_safe_id(site_b)}["{site_b}"]',
        f'    subgraph {b_id}_appliance["{secondary} (Destination)"]',
        f'      {b_id}_na[["Node-A\\n(Controller)"]]',
        f'      {b_id}_nb[["Node-B\\n(Controller)"]]',
        f'      {b_id}_vip(["Mgmt VIP"])',
        f'      {b_id}_mt[["{mtree or "/data/col1"}\\n(MTree Replica)"]]]',
        '    end',
        '  end',
        f'  {a_id}_mt -->|"{mtree_label}\\n(Asynchronous)"| {b_id}_mt',
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
