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

    # Fallback 3: derive relationships from replication_targets / replication_sources
    # when neither mtree_replications nor replication_status.contexts are available.
    # This covers DataDomain appliances where the MTree-level endpoint is unsupported
    # but the targets/sources endpoints work.
    if not mtree_repls:
        for t in (health_data.get('replication_targets') or []):
            if not isinstance(t, dict):
                continue
            dest = t.get('host')
            if not dest:
                continue
            state_str = (t.get('state') or 'unknown').upper()
            connected = state_str in ('REPLICATING', 'NORMAL', 'OK', 'ENABLED')
            mtree_repls.append({
                'mode': 'SOURCE',
                'state': t.get('state', 'unknown'),
                'connected': connected,
                'source_host': system_name,
                'destination_host': dest,
                'source_mtree': None,
                'destination_mtree': None,
            })
        for s in (health_data.get('replication_sources') or []):
            if not isinstance(s, dict):
                continue
            src = s.get('host')
            if not src:
                continue
            state_str = (s.get('state') or 'unknown').upper()
            connected = state_str in ('REPLICATING', 'NORMAL', 'OK', 'ENABLED')
            mtree_repls.append({
                'mode': 'TARGET',
                'state': s.get('state', 'unknown'),
                'connected': connected,
                'source_host': src,
                'destination_host': system_name,
                'source_mtree': None,
                'destination_mtree': None,
            })

    if not mtree_repls:
        return relationships

    # Aggregate multiple MTree contexts by (source_host, destination_host) pair
    # so each unique replication pair produces exactly one DR relationship entry.
    # All individual MTree contexts are collected inside relationship_data.contexts
    # for display in the detail view.
    pair_map: dict = {}
    for repl in mtree_repls:
        if not isinstance(repl, dict):
            continue

        state = (repl.get('state') or 'unknown').upper()
        connected = repl.get('connected', False)
        replication_state = 'healthy' if state in ('NORMAL', 'RESYNCING') and connected else 'degraded'

        mode = (repl.get('mode') or 'SOURCE').upper()
        source_host = repl.get('source_host') or system_name
        dest_host = repl.get('destination_host') or 'Secondary'

        pair_key = (source_host, dest_host)
        ctx_entry = {
            'source_mtree': repl.get('source_mtree'),
            'destination_mtree': repl.get('destination_mtree'),
            'state': repl.get('state'),
            'connected': connected,
            'mode': mode,
        }

        if pair_key not in pair_map:
            pair_map[pair_key] = {
                'system_name': system_name,
                'vendor': 'dell-datadomain',
                'replication_type': 'datadomain-replication',
                'primary_site': source_host,
                'secondary_site': dest_host,
                'primary_cluster': source_host,
                'secondary_cluster': dest_host,
                'replication_state': replication_state,
                'relationship_data': {
                    # source/destination carry the first-seen MTree path for
                    # backward compatibility (generate_commands, test assertions).
                    'source': {
                        'host': source_host,
                        'mtree': repl.get('source_mtree'),
                    },
                    'destination': {
                        'host': dest_host,
                        'mtree': repl.get('destination_mtree'),
                    },
                    'mode': mode,
                    # contexts: list of individual MTree replication entries
                    'contexts': [],
                },
            }
        else:
            # Promote to the worst observed state across all contexts.
            existing = pair_map[pair_key]
            state_rank = {'healthy': 0, 'degraded': 1, 'broken': 2, 'unknown': -1}
            current_rank = state_rank.get(existing['replication_state'], -1)
            new_rank = state_rank.get(replication_state, -1)
            if new_rank > current_rank:
                existing['replication_state'] = replication_state

        if repl.get('source_mtree') or repl.get('destination_mtree'):
            pair_map[pair_key]['relationship_data']['contexts'].append(ctx_entry)

    relationships = list(pair_map.values())
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
        {'phase': 'pre-failover', 'step': 1, 'title': 'DataDomain Replikationsstatus prüfen',
         'description': 'Check replication status and ensure all MTree replications are in sync.'},
        {'phase': 'pre-failover', 'step': 2, 'title': 'Abschließende Replikationssynchronisierung erzwingen',
         'description': 'Trigger a manual sync for all MTrees to minimise data loss.'},
        {'phase': 'pre-failover', 'step': 3, 'title': 'Backup-Jobs stoppen',
         'description': 'Suspend backup jobs targeting the primary DataDomain.'},
        {'phase': 'failover', 'step': 4, 'title': 'Replikation am Ziel trennen',
         'description': 'On the destination DataDomain, break the replication context and promote MTree as read/write.'},
        {'phase': 'failover', 'step': 5, 'title': 'Backup-Server auf Ziel umstellen',
         'description': 'Reconfigure the backup server (NetBackup / Veeam / Commvault) to use the destination DataDomain.'},
        {'phase': 'post-failover', 'step': 6, 'title': 'Backup-Jobs fortsetzen',
         'description': 'Resume backup jobs now targeting the destination DataDomain.'},
        {'phase': 'post-failover', 'step': 7, 'title': 'Datenzugriff prüfen',
         'description': 'Verify that backup catalogs and restore points are accessible on the destination.'},
    ],
    'failback': [
        {'phase': 'pre-failback', 'step': 1, 'title': 'Primäres DataDomain wiederherstellen',
         'description': 'Confirm the primary DataDomain is online and reachable.'},
        {'phase': 'pre-failback', 'step': 2, 'title': 'Replikation zur Primäranlage wiederherstellen',
         'description': 'Configure replication from the destination back to the primary DataDomain.'},
        {'phase': 'failback', 'step': 3, 'title': 'Daten zurück zu Primär synchronisieren',
         'description': 'Allow all MTrees to replicate back to the primary site.'},
        {'phase': 'failback', 'step': 4, 'title': 'Backup-Server auf Primär umstellen',
         'description': 'Reconfigure the backup server to use the primary DataDomain.'},
        {'phase': 'post-failback', 'step': 5, 'title': 'Ursprüngliche Replikationsrichtung wiederherstellen',
         'description': 'Re-establish original replication from primary to secondary.'},
        {'phase': 'post-failback', 'step': 6, 'title': 'Replikationsstatus prüfen',
         'description': 'Confirm all MTree replications are healthy and in sync.'},
    ],
    # Disaster recovery: unplanned failover from the surviving DR site after the
    # primary DataDomain system is unreachable.  No sync step because the source
    # is down — proceed directly to break → promote → validate → switch.
    # Reference: https://www.dell.com/support/kbdoc/en-us/000317549/
    #   data-domain-best-practices-for-data-migration-on-powerprotect-
    #   data-domain-systems-using-mtree-replication
    'disaster_recovery': [
        {'phase': 'detection', 'step': 1, 'title': 'Katastrophe erkannt',
         'description': (
             'Confirm the primary DataDomain system is unreachable.  Verify that the '
             'source system and its replication contexts cannot be reached before '
             'proceeding with the unplanned failover.'
         )},
        {'phase': 'validation', 'step': 2, 'title': 'Replikationsstatus auf DR-System prüfen',
         'description': (
             'On the DR (destination) DataDomain run replication status, '
             'replication show config, filesys status, and alerts show to assess '
             'the last known replication state, filesystem health, and any active alerts.'
         )},
        {'phase': 'break-replication', 'step': 3, 'title': 'Replikationskontext trennen',
         'description': (
             'Break the MTree replication context on the DR DataDomain to sever the '
             'relationship and allow the destination MTree to become read/write.  '
             'Because the source is down, no sync step is performed first: '
             'replication break ctx://remote/<mtree>'
         )},
        {'phase': 'promote-mtree', 'step': 4, 'title': 'DR-MTree auf Lesen/Schreiben umstellen',
         'description': (
             'Verify that the destination MTree is now writable.  Confirm with '
             'mtree show and filesys show space that the data is intact and the '
             'MTree is in a healthy state.'
         )},
        {'phase': 'validate-filesystem', 'step': 5, 'title': 'Dateisystemzustand prüfen',
         'description': (
             'Check the DataDomain filesystem status to confirm it is fully operational.  '
             'Review active alerts and confirm no filesystem errors are present.'
         )},
        {'phase': 'switch-backup', 'step': 6, 'title': 'Backup-Infrastruktur auf DR-System umschalten',
         'description': (
             'Reconfigure the backup server (NetBackup, Veeam, Commvault) to target '
             'the DR DataDomain.  Update device paths and re-import backup catalogs '
             'from the promoted MTree.  Resume backup and restore operations.'
         )},
        {'phase': 'recreate-replication', 'step': 7, 'title': 'Replikation nach Wiederherstellung neu einrichten',
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

    When multiple MTree contexts are present (relationship_data.contexts),
    per-MTree commands (sync, break, mtree show, filesys show space,
    replication add) are generated for **every** MTree path.  System-level
    commands (replication status, replication show config, filesys status,
    alerts show) are emitted only once per phase.

    Supported directions: ``planned_failover``, ``failback``,
    ``disaster_recovery``.
    """
    rd = relationship.get('relationship_data', {})

    # Collect all MTree paths from contexts; fall back to the single mtree
    # stored in relationship_data.source for backward compatibility.
    contexts = rd.get('contexts') or []
    mtrees = [ctx.get('source_mtree') for ctx in contexts if ctx.get('source_mtree')]
    if not mtrees:
        if isinstance(rd.get('source'), dict):
            fallback = rd['source'].get('mtree', '/data/col1/backup')
        else:
            fallback = '/data/col1/backup'
        mtrees = [fallback]

    primary = relationship.get('primary_cluster') or 'dd1'
    secondary = relationship.get('secondary_cluster') or 'dd2'

    # For disaster recovery, commands run on the surviving (DR/destination) system
    # because the primary is down.
    dr_target = secondary

    # Build per-MTree command blocks for each failover direction.
    def build_planned_failover():
        cmds = [
            {'phase': 'pre-failover', 'description': 'Check replication status',
             'cli': 'replication status', 'target': primary},
            {'phase': 'pre-failover', 'description': 'Show replication configuration',
             'cli': 'replication show config', 'target': primary},
            {'phase': 'pre-failover', 'description': 'Check filesystem status',
             'cli': 'filesys status', 'target': primary},
            {'phase': 'pre-failover', 'description': 'Show active alerts',
             'cli': 'alerts show', 'target': primary},
        ]
        for mt in mtrees:
            cmds.append({'phase': 'pre-failover', 'description': f'Sync replication ({mt})',
                         'cli': f'replication sync ctx://remote/{mt}', 'target': primary})
        for mt in mtrees:
            cmds.append({'phase': 'failover',
                         'description': f'Break replication context on destination ({mt})',
                         'cli': f'replication break ctx://remote/{mt}', 'target': secondary})
            cmds.append({'phase': 'failover', 'description': f'Show MTree status on destination ({mt})',
                         'cli': f'mtree show {mt}', 'target': secondary})
        for mt in mtrees:
            cmds.append({'phase': 'post-failover', 'description': f'Verify data availability ({mt})',
                         'cli': f'filesys show space {mt}', 'target': secondary})
        return cmds

    def build_failback():
        cmds = [
            {'phase': 'pre-failback', 'description': 'Check primary DataDomain health',
             'cli': 'system show', 'target': primary},
        ]
        for mt in mtrees:
            cmds.append({'phase': 'failback',
                         'description': f'Re-establish replication to primary ({mt})',
                         'cli': f'replication add source mtree://localhost{mt} destination mtree://{primary}{mt}',
                         'target': secondary})
            cmds.append({'phase': 'failback', 'description': f'Sync data back to primary ({mt})',
                         'cli': f'replication sync ctx://remote/{mt}', 'target': secondary})
        cmds.append({'phase': 'post-failback', 'description': 'Verify replication health',
                     'cli': 'replication show', 'target': primary})
        return cmds

    def build_disaster_recovery():
        # Reference: https://www.dell.com/support/kbdoc/en-us/000317549/
        #   data-domain-best-practices-for-data-migration-on-powerprotect-
        #   data-domain-systems-using-mtree-replication
        cmds = [
            # Phase: validation (assess last known replication state on DR system)
            {'phase': 'validation', 'description': 'Check replication status on DR system',
             'cli': 'replication status', 'target': dr_target},
            {'phase': 'validation', 'description': 'Show replication configuration on DR system',
             'cli': 'replication show config', 'target': dr_target},
            {'phase': 'validation', 'description': 'Check filesystem status on DR system',
             'cli': 'filesys status', 'target': dr_target},
            {'phase': 'validation', 'description': 'Show active alerts on DR system',
             'cli': 'alerts show', 'target': dr_target},
        ]
        # Phase: break-replication (no sync — source is down)
        for mt in mtrees:
            cmds.append({'phase': 'break-replication',
                         'description': f'Break replication context on DR system ({mt})',
                         'cli': f'replication break ctx://remote/{mt}', 'target': dr_target})
        # Phase: promote-mtree
        for mt in mtrees:
            cmds.append({'phase': 'promote-mtree', 'description': f'Show MTree status after break ({mt})',
                         'cli': f'mtree show {mt}', 'target': dr_target})
            cmds.append({'phase': 'promote-mtree', 'description': f'Verify MTree space on DR system ({mt})',
                         'cli': f'filesys show space {mt}', 'target': dr_target})
        cmds += [
            # Phase: validate-filesystem
            {'phase': 'validate-filesystem', 'description': 'Validate filesystem health',
             'cli': 'filesys status', 'target': dr_target},
            {'phase': 'validate-filesystem', 'description': 'Confirm no critical alerts',
             'cli': 'alerts show current', 'target': dr_target},
        ]
        # Phase: recreate-replication (after primary recovery)
        for mt in mtrees:
            cmds.append({'phase': 'recreate-replication',
                         'description': f'Re-establish MTree replication from DR back to primary ({mt})',
                         'cli': (
                             f'replication add source mtree://localhost{mt} '
                             f'destination mtree://{primary}{mt}'
                         ),
                         'target': dr_target})
        cmds.append({'phase': 'recreate-replication', 'description': 'Verify recreated replication context',
                     'cli': 'replication show config', 'target': dr_target})
        return cmds

    builders = {
        'planned_failover': build_planned_failover,
        'failback': build_failback,
        'disaster_recovery': build_disaster_recovery,
    }
    builder = builders.get(failover_direction, builders['planned_failover'])
    return builder()


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
        'graph TD',
        f'  subgraph {_safe_id(site_a)}["{site_a}"]',
        f'    direction LR',
        f'    subgraph {a_id}_appliance["{primary} (Source)"]',
        f'      direction LR',
        f'      {a_id}_na[["Node-A\\n(Controller)"]]',
        f'      {a_id}_nb[["Node-B\\n(Controller)"]]',
        f'      {a_id}_vip(["Mgmt VIP"])',
        f'      {a_id}_mt[["{mtree or "/data/col1"}\\n(MTree)"]]',
        '    end',
        f'    BCK_A[("Backup Server")]',
        f'    BCK_A -->|"Backup"| {a_id}_appliance',
        '  end',
        f'  subgraph {_safe_id(site_b)}["{site_b}"]',
        f'    direction LR',
        f'    subgraph {b_id}_appliance["{secondary} (Destination)"]',
        f'      direction LR',
        f'      {b_id}_na[["Node-A\\n(Controller)"]]',
        f'      {b_id}_nb[["Node-B\\n(Controller)"]]',
        f'      {b_id}_vip(["Mgmt VIP"])',
        f'      {b_id}_mt[["{mtree or "/data/col1"}\\n(MTree Replica)"]]',
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
    return (
        name
        .replace(' ', '_')
        .replace('-', '_')
        .replace('/', '_')
        .replace('.', '_')
        .replace('[', '_')
        .replace(']', '_')
    )
