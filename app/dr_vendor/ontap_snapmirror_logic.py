"""NetApp ONTAP SnapMirror DR logic.

Provides generation rules and command templates for ONTAP SnapMirror
asynchronous replication environments.

Supported failover directions
------------------------------
planned_failover
    Negotiated failover when both sites are up.  Quiesces and drains
    replication before breaking the relationship.

failback
    Return operations to the primary site after it has been restored.
    Reverses replication direction, resyncs, then restores original
    direction.

disaster_recovery
    Unplanned failover from the surviving DR site after the primary site
    is unreachable.  Skips quiesce (source is down) and proceeds directly
    to break → SVM activation → client redirection → reprotect.

    Per NetApp documentation the full disaster recovery procedure is:
    https://docs.netapp.com/us-en/ontap/data-protection/
    svm-disaster-recovery-workflow-concept.html
    https://docs.netapp.com/us-en/ontap/data-protection/
    make-destination-volume-writeable-task.html

    The 8-phase workflow is:
    1. Disaster detection
    2. Pre-checks (SnapMirror state on DR cluster)
    3. SnapMirror break (make destination read/write)
    4. Activate DR SVM or volumes
    5. Verify storage availability
    6. Verify network access
    7. Serve clients from DR site
    8. Reprotect replication after primary recovery

SnapMirror relationship types
-------------------------------
svm_dr
    Whole-SVM replication (destination path ends with ``:``, no volume).
    Use-case: SVM Disaster Recovery.

volume
    Single-volume replication (destination path is ``<svm>:<vol>``).
    Use-case: volume-level DR / SnapVault.
"""

# ---------------------------------------------------------------------------
# DR relationship discovery
# ---------------------------------------------------------------------------

def _detect_sm_type(sm):
    """Return ``'svm_dr'`` or ``'volume'`` based on the SnapMirror record.

    SVM DR relationships have a destination path of the form ``<svm>:``
    (trailing colon, no volume component).  Volume SnapMirror relationships
    have a path of the form ``<svm>:<volume>``.  Path-based detection takes
    precedence; policy type is used only when no path is available.
    """
    dst = sm.get('destination', {}) if isinstance(sm.get('destination'), dict) else {}
    path = dst.get('path', '')
    if path:
        return 'svm_dr' if path.endswith(':') else 'volume'
    # Fall back to policy type when no path is present
    policy = sm.get('policy', {}) if isinstance(sm.get('policy'), dict) else {}
    policy_type = policy.get('type', '').lower()
    if policy_type in ('sync_mirror', 'strict_sync_mirror', 'sync'):
        return 'volume'
    return 'svm_dr'


def discover_relationships(system_name, health_data):
    """Analyse health_data and return normalised SnapMirror DR relationship dicts.

    Uses ``snapmirror_relationships`` populated by
    NetAppONTAPClient.get_health_status() from
    GET /api/snapmirror/relationships (per ontap_swagger.yaml).

    For DR purposes only inter-cluster relationships are relevant (i.e. where
    the destination cluster differs from the local cluster).  Intra-cluster
    SnapMirror relationships (no ``destination.cluster.name``) are skipped.

    ``svm_peers`` (from GET /api/svm/peers) is used to enrich the secondary
    cluster name when the SnapMirror response itself does not carry it.

    Each returned relationship includes a ``sm_type`` key (``'svm_dr'`` or
    ``'volume'``) derived from the destination path format.
    """
    relationships = []
    sm_list = health_data.get('snapmirror_relationships') or health_data.get('snapmirror', [])
    if not sm_list:
        return relationships

    if not isinstance(sm_list, list):
        sm_list = [sm_list]

    # Build an SVM → cluster lookup from svm_peers for enrichment
    svm_peer_cluster = {}
    for peer in (health_data.get('svm_peers') or []):
        if not isinstance(peer, dict):
            continue
        peer_cluster = (
            peer.get('peer', {}).get('cluster', {}).get('name', '')
            if isinstance(peer.get('peer'), dict)
            else ''
        )
        peer_svm = (
            peer.get('peer', {}).get('svm', {}).get('name', '')
            if isinstance(peer.get('peer'), dict)
            else ''
        )
        if peer_svm and peer_cluster:
            svm_peer_cluster[peer_svm] = peer_cluster

    for sm in sm_list:
        if not isinstance(sm, dict):
            continue

        # Determine destination cluster
        dst_cluster_name = ''
        dst = sm.get('destination', {}) if isinstance(sm.get('destination'), dict) else {}
        if isinstance(dst.get('cluster'), dict):
            dst_cluster_name = dst['cluster'].get('name', '')
        dst_svm_name = dst.get('svm', {}).get('name', '') if isinstance(dst.get('svm'), dict) else ''
        dst_path = dst.get('path', '')

        # Enrich from svm_peers when cluster name is missing from SM record
        if not dst_cluster_name and dst_svm_name:
            dst_cluster_name = svm_peer_cluster.get(dst_svm_name, '')

        # Skip intra-cluster relationships (no remote cluster = not a DR pair)
        if not dst_cluster_name or dst_cluster_name == system_name:
            continue

        state = sm.get('state', 'unknown')
        replication_state = 'healthy' if state in ('snapmirrored', 'in_sync') else 'degraded'
        src = sm.get('source', {}) if isinstance(sm.get('source'), dict) else {}
        src_svm = src.get('svm', {}).get('name', '') if isinstance(src.get('svm'), dict) else ''
        src_path = src.get('path', '')

        sm_type = _detect_sm_type(sm)

        # Store enriched SnapMirror record with sm_type for command generation
        rel_data = dict(sm)
        rel_data['sm_type'] = sm_type

        relationships.append({
            'system_name': system_name,
            'vendor': 'netapp-ontap',
            'replication_type': 'snapmirror',
            'primary_site': src_svm or system_name,
            'secondary_site': dst_svm_name or dst_cluster_name,
            'primary_cluster': system_name,
            'secondary_cluster': dst_cluster_name,
            'replication_state': replication_state,
            'relationship_data': rel_data,
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
        {'phase': 'pre-failover', 'step': 1, 'title': 'SnapMirror Status prüfen',
         'description': 'Run snapmirror show to confirm all relationships are in "snapmirrored" state.'},
        {'phase': 'pre-failover', 'step': 2, 'title': 'Letztes SnapMirror Update durchführen',
         'description': 'Trigger a manual update to minimise data loss before failover.'},
        {'phase': 'pre-failover', 'step': 3, 'title': 'SnapMirror Beziehungen pausieren',
         'description': 'Quiesce the SnapMirror relationships to prevent further updates during failover.'},
        {'phase': 'failover', 'step': 4, 'title': 'SnapMirror Beziehungen trennen',
         'description': 'Break the SnapMirror relationships to make the destination volumes read/write.'},
        {'phase': 'failover', 'step': 5, 'title': 'Ziel-SVM starten',
         'description': 'Start the destination SVM and configure network interfaces.'},
        {'phase': 'post-failover', 'step': 6, 'title': 'Ziel-Volumes einhängen',
         'description': 'Mount volumes and verify exports/shares on the destination SVM.'},
        {'phase': 'post-failover', 'step': 7, 'title': 'Client Verbindungen umleiten',
         'description': 'Update DNS or mount points so clients connect to the destination SVM.'},
        {'phase': 'post-failover', 'step': 8, 'title': 'Datenzugriff prüfen',
         'description': 'Test application access to confirm data is readable and writeable.'},
    ],
    'failback': [
        {'phase': 'pre-failback', 'step': 1, 'title': 'SnapMirror vom Ziel zur Quelle wiederherstellen',
         'description': 'Reverse the SnapMirror relationship so changes made at destination are replicated back.'},
        {'phase': 'failback', 'step': 2, 'title': 'Quell-Volumes resynchronisieren',
         'description': 'Run snapmirror resync to initialise the reverse relationship.'},
        {'phase': 'failback', 'step': 3, 'title': 'Umgekehrte Beziehung pausieren und trennen',
         'description': 'Once synced, quiesce and break the reverse relationship to return to normal direction.'},
        {'phase': 'failback', 'step': 4, 'title': 'Ursprüngliche SnapMirror-Richtung wiederherstellen',
         'description': 'Resync the original relationship to bring source volumes up to date.'},
        {'phase': 'post-failback', 'step': 5, 'title': 'Clients zurück zur Quelle umleiten',
         'description': 'Update client connections to the original SVM on the primary site.'},
        {'phase': 'post-failback', 'step': 6, 'title': 'SnapMirror Status prüfen',
         'description': 'Confirm all relationships are in "snapmirrored" state with no lag.'},
    ],
    # Disaster recovery: unplanned failover from the surviving DR site after the
    # primary site is unreachable.  Source cannot be quiesced so we proceed
    # directly to break → SVM activation.
    # Reference:
    # https://docs.netapp.com/us-en/ontap/data-protection/
    #   svm-disaster-recovery-workflow-concept.html
    # https://docs.netapp.com/us-en/ontap/data-protection/
    #   make-destination-volume-writeable-task.html
    'disaster_recovery': [
        {'phase': 'detection', 'step': 1, 'title': 'Katastrophe erkannt',
         'description': (
             'Confirm the primary site is unreachable.  Verify that the source cluster '
             'and its SVMs are not accessible before proceeding with the unplanned failover.'
         )},
        {'phase': 'pre-checks', 'step': 2, 'title': 'SnapMirror Replikationsstatus prüfen',
         'description': (
             'On the DR cluster run snapmirror show and '
             'snapmirror show -fields status,health,lag-time to assess the replication '
             'state and lag of all relationships.  Note the last successful transfer time.'
         )},
        {'phase': 'snapmirror-break', 'step': 3, 'title': 'SnapMirror Beziehungen trennen',
         'description': (
             'Break the SnapMirror relationship(s) to make the destination volumes '
             'read/write.  Because the source is down, no quiesce step is possible: '
             'snapmirror break -destination-path <path>'
         )},
        {'phase': 'activate-dr', 'step': 4, 'title': 'DR-SVM oder Volumes aktivieren',
         'description': (
             'For SVM DR: start the destination SVM with vserver start.  '
             'For volume SnapMirror: mount the destination volumes and set them online.  '
             'Verify all LIFs are up and serving data.'
         )},
        {'phase': 'verify-storage', 'step': 5, 'title': 'Speicherverfügbarkeit prüfen',
         'description': (
             'Confirm that all volumes are online and data is accessible.  '
             'Check aggregates, volumes, and LUNs on the DR cluster.'
         )},
        {'phase': 'verify-network', 'step': 6, 'title': 'Netzwerkzugang prüfen',
         'description': (
             'Confirm that all required data LIFs are up and reachable from clients.  '
             'Verify DNS resolution and NFS/CIFS exports are correct.'
         )},
        {'phase': 'serve-clients', 'step': 7, 'title': 'Clients vom DR-Standort versorgen',
         'description': (
             'Redirect client connections (DNS, mount points, iSCSI targets) to the '
             'DR site.  Validate that applications can read and write data successfully.'
         )},
        {'phase': 'reprotect', 'step': 8, 'title': 'Nach Wiederherstellung erneut schützen',
         'description': (
             'When the primary site returns, re-establish SnapMirror replication in the '
             'original direction to re-sync changes made at the DR site: '
             'snapmirror resync -destination-path <original-dst-path>'
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
    *relationship*.  This ensures that paths, SVM names, and cluster targets
    reflect the actual discovered environment.

    Supported directions: ``planned_failover``, ``failback``,
    ``disaster_recovery``.
    """
    rd = relationship.get('relationship_data', {})
    src_vol = ''
    dst_vol = ''
    if isinstance(rd.get('source'), dict):
        src_vol = rd['source'].get('path', '*')
    if isinstance(rd.get('destination'), dict):
        dst_vol = rd['destination'].get('path', '*')

    primary = relationship.get('primary_cluster') or 'cluster1'
    secondary = relationship.get('secondary_cluster') or 'cluster2'
    dst_svm = relationship.get('secondary_site') or secondary

    # For disaster recovery, commands run on the surviving (DR/destination) cluster
    # because the source cluster is down.
    dr_target = secondary

    sm_type = rd.get('sm_type', 'volume')

    commands = {
        'planned_failover': [
            {'phase': 'pre-failover', 'description': 'Show all SnapMirror relationships',
             'cli': 'snapmirror show', 'target': primary},
            {'phase': 'pre-failover', 'description': 'Show replication status and lag',
             'cli': 'snapmirror show -fields status,health,lag-time', 'target': primary},
            {'phase': 'pre-failover', 'description': 'Show destination relationship detail',
             'cli': f'snapmirror show -destination-path {dst_vol}', 'target': primary},
            {'phase': 'pre-failover', 'description': 'Trigger manual update',
             'cli': f'snapmirror update -destination-path {dst_vol}', 'target': primary},
            {'phase': 'pre-failover', 'description': 'Quiesce relationship',
             'cli': f'snapmirror quiesce -destination-path {dst_vol}', 'target': primary},
            {'phase': 'failover', 'description': 'Break SnapMirror relationship',
             'cli': f'snapmirror break -destination-path {dst_vol}', 'target': primary},
            {'phase': 'failover', 'description': 'Start destination SVM',
             'cli': f'vserver start -vserver {dst_svm}', 'target': primary},
            {'phase': 'post-failover', 'description': 'Verify volume state on destination',
             'cli': f'volume show -vserver {dst_svm}', 'target': primary},
            {'phase': 'post-failover', 'description': 'Verify LIF availability on destination',
             'cli': f'network interface show -vserver {dst_svm}', 'target': primary},
        ],
        'failback': [
            {'phase': 'pre-failback', 'description': 'Show SnapMirror status before failback',
             'cli': 'snapmirror show -fields status,health,lag-time', 'target': secondary},
            {'phase': 'pre-failback', 'description': 'Resync SnapMirror (reverse)',
             'cli': f'snapmirror resync -source-path {dst_vol} -destination-path {src_vol}', 'target': secondary},
            {'phase': 'failback', 'description': 'Quiesce reverse relationship',
             'cli': f'snapmirror quiesce -destination-path {src_vol}', 'target': secondary},
            {'phase': 'failback', 'description': 'Break reverse relationship',
             'cli': f'snapmirror break -destination-path {src_vol}', 'target': secondary},
            {'phase': 'failback', 'description': 'Resync original direction',
             'cli': f'snapmirror resync -destination-path {dst_vol}', 'target': secondary},
            {'phase': 'post-failback', 'description': 'Verify SnapMirror health',
             'cli': f'snapmirror show -destination-path {dst_vol}', 'target': secondary},
        ],
        # Disaster recovery commands executed on the *surviving* (DR/destination) cluster.
        # Reference: https://docs.netapp.com/us-en/ontap/data-protection/
        #   svm-disaster-recovery-workflow-concept.html
        # Reference: https://docs.netapp.com/us-en/ontap/data-protection/
        #   make-destination-volume-writeable-task.html
        'disaster_recovery': [
            # Phase: pre-checks (validate replication state on DR cluster)
            {'phase': 'pre-checks', 'description': 'Show all SnapMirror relationships on DR cluster',
             'cli': 'snapmirror show', 'target': dr_target},
            {'phase': 'pre-checks', 'description': 'Show replication status and lag on DR cluster',
             'cli': 'snapmirror show -fields status,health,lag-time', 'target': dr_target},
            {'phase': 'pre-checks', 'description': 'Show destination relationship detail',
             'cli': f'snapmirror show -destination-path {dst_vol}', 'target': dr_target},
            # Phase: snapmirror-break (no quiesce — source is down)
            {'phase': 'snapmirror-break', 'description': 'Break SnapMirror to make destination read/write',
             'cli': f'snapmirror break -destination-path {dst_vol}', 'target': dr_target},
            # Phase: activate-dr
            {'phase': 'activate-dr', 'description': 'Start destination SVM',
             'cli': f'vserver start -vserver {dst_svm}', 'target': dr_target},
            {'phase': 'activate-dr', 'description': 'Verify SVM state',
             'cli': f'vserver show -vserver {dst_svm}', 'target': dr_target},
            # Phase: verify-storage
            {'phase': 'verify-storage', 'description': 'Verify volumes on DR cluster',
             'cli': f'volume show -vserver {dst_svm}', 'target': dr_target},
            {'phase': 'verify-storage', 'description': 'Verify aggregate state on DR cluster',
             'cli': 'storage aggregate show', 'target': dr_target},
            # Phase: verify-network
            {'phase': 'verify-network', 'description': 'Verify LIFs on DR cluster',
             'cli': f'network interface show -vserver {dst_svm}', 'target': dr_target},
            # Phase: reprotect (after primary recovery)
            {'phase': 'reprotect', 'description': 'Re-establish SnapMirror from DR to primary (reverse)',
             'cli': f'snapmirror resync -source-path {dst_vol} -destination-path {src_vol}', 'target': dr_target},
            {'phase': 'reprotect', 'description': 'Verify reprotect relationship is syncing',
             'cli': f'snapmirror show -destination-path {src_vol}', 'target': dr_target},
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
