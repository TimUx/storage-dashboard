"""Disaster Recovery (DR) routes – /dr/"""
import logging
from datetime import datetime, timedelta
from flask import Blueprint, render_template, jsonify, request, current_app

bp = Blueprint('dr', __name__, url_prefix='/dr')
logger = logging.getLogger(__name__)

# Age threshold after which the UI shows a "may be outdated" warning
DR_STALE_THRESHOLD_SECONDS = 7 * 24 * 60 * 60  # 1 week (matches default build interval)

# Mapping from internal replication_type to human-readable storage technology tab label
_REPLICATION_TYPE_LABELS = {
    'activecluster': 'FlashArray ActiveCluster',
    'metrocluster': 'ONTAP MetroCluster',
    'snapmirror': 'ONTAP SnapMirror',
    'storagegrid-multisite': 'StorageGRID',
    'datadomain-replication': 'DataDomain',
}

# State priority for aggregation (lower = worse)
_STATE_PRIORITY = {'broken': 0, 'degraded': 1, 'unknown': 2, 'healthy': 3}


@bp.route('/')
def index():
    """DR Operations page."""
    return render_template('dr.html')


# ---------------------------------------------------------------------------
# DR topology overview
# ---------------------------------------------------------------------------

@bp.route('/api/topology')
def api_topology():
    """Return DR topology overview (all discovered relationships in latest build)."""
    from app.dr_service import get_latest_build, get_dr_relationships

    build = get_latest_build()
    if not build:
        return jsonify({'build': None, 'relationships': [], 'stale': False})

    relationships = get_dr_relationships(build_id=build.id)
    stale = _is_stale(build)

    return jsonify({
        'build': build.to_dict(),
        'relationships': [r.to_dict() for r in relationships],
        'stale': stale,
    })


# ---------------------------------------------------------------------------
# System-centric DR overview (new: one entry per system, grouped by type)
# ---------------------------------------------------------------------------

@bp.route('/api/systems')
def api_systems():
    """Return DR systems grouped by storage technology, with relationships aggregated.

    Query parameters:
        environment: all | production | test  (default: all)
    """
    from app.dr_service import get_latest_build, get_dr_relationships
    from app.models import StorageSystem

    build = get_latest_build()
    if not build:
        return jsonify({'build': None, 'groups': {}, 'systems': [], 'sites': [], 'stale': False})

    env_filter = request.args.get('environment', 'all').lower()
    relationships = get_dr_relationships(build_id=build.id)
    stale = _is_stale(build)

    # Collect environment classification from StorageSystem tags (Landschaft group),
    # DataCenter tags for site names, and build a set of systems excluded from DR failover.
    sys_env_map: dict[str, str] = {}
    sys_dc_map: dict[str, str] = {}
    excluded_systems: set[str] = set()
    try:
        from app.dr_service import _is_dr_excluded
        for ss in StorageSystem.query.all():
            sys_env_map[ss.name] = 'unknown'
            for tag in (ss.tags or []):
                group_name = (tag.group.name if tag.group else '').strip()
                tag_name = tag.name.strip()
                if group_name == 'Landschaft':
                    if tag_name == 'Produktion':
                        sys_env_map[ss.name] = 'production'
                    elif tag_name == 'Test/Dev':
                        sys_env_map[ss.name] = 'test'
                elif group_name == 'DataCenter':
                    sys_dc_map[ss.name] = tag_name
            if _is_dr_excluded(ss):
                excluded_systems.add(ss.name)
    except Exception as exc:
        logger.warning("Could not load system tags: %s", exc)

    # Aggregate relationships per system_name
    systems_map: dict[str, dict] = {}
    for rel in relationships:
        rel_dict = rel.to_dict()
        sname = rel_dict['system_name']
        if sname not in systems_map:
            # Resolve DataCenter tags for primary and secondary sites.
            # Primary site = DataCenter tag of this system.
            # Secondary site = DataCenter tag of the secondary cluster system (if found),
            # falling back to the raw secondary_site value from the relationship.
            primary_dc = sys_dc_map.get(sname) or rel_dict.get('primary_site') or ''
            sec_cluster = rel_dict.get('secondary_cluster') or ''
            secondary_dc = (sys_dc_map.get(sec_cluster) if sec_cluster else '') \
                or rel_dict.get('secondary_site') or ''
            systems_map[sname] = {
                'system_name': sname,
                'vendor': rel_dict['vendor'],
                'replication_type': rel_dict['replication_type'],
                'primary_site': primary_dc,
                'secondary_site': secondary_dc,
                'status': rel_dict.get('replication_state') or 'unknown',
                'environment': sys_env_map.get(sname, 'unknown'),
                'relationships': [],
            }
        systems_map[sname]['relationships'].append(rel_dict)
        # Promote status to worst observed state
        cur_pri = _STATE_PRIORITY.get(systems_map[sname]['status'], 2)
        new_pri = _STATE_PRIORITY.get(rel_dict.get('replication_state') or 'unknown', 2)
        if new_pri < cur_pri:
            systems_map[sname]['status'] = rel_dict.get('replication_state') or 'unknown'

    # Remove systems that are outside the DR scope (Landschaft=File, Storage Art=Backup)
    if excluded_systems:
        systems_map = {k: v for k, v in systems_map.items() if k not in excluded_systems}

    # Apply environment filter
    if env_filter in ('production', 'test'):
        systems_map = {k: v for k, v in systems_map.items() if v['environment'] == env_filter}

    # Group by storage technology tab; sort each group alphabetically by system name
    groups: dict[str, list] = {}
    for sys_dict in systems_map.values():
        rep_type = sys_dict['replication_type']
        group_label = _REPLICATION_TYPE_LABELS.get(rep_type, rep_type)
        groups.setdefault(group_label, []).append(sys_dict)

    for label in groups:
        groups[label].sort(key=lambda s: s['system_name'].lower())

    # Collect unique site pairs (primary → secondary) for the direction selector.
    # Pairs are expressed as "DC1 → DC2" strings so the filter can match both ends.
    seen_pairs: set[tuple] = set()
    site_pairs: list[str] = []
    for sys_dict in systems_map.values():
        p = sys_dict['primary_site']
        s = sys_dict['secondary_site']
        if p and s:
            pair = (p, s)
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                site_pairs.append(f"{p} \u2192 {s}")

    return jsonify({
        'build': build.to_dict(),
        'groups': groups,
        'systems': list(systems_map.values()),
        'sites': sorted(site_pairs),
        'stale': stale,
    })


# ---------------------------------------------------------------------------
# DR system details
# ---------------------------------------------------------------------------

@bp.route('/api/system/<path:system_name>')
def api_system(system_name):
    """Return all DR artifacts for a specific system from the latest build.

    Returns all relationships for the system plus the topology, workflow,
    runbook, command set and diagrams for the requested failover direction.
    Multiple replication relationship rows for the same system (e.g. a system
    with both MetroCluster and SnapMirror configurations) are returned in the
    ``relationships`` list so the UI can show them in the details pane.
    """
    from app.dr_service import (
        get_latest_build, get_topology, get_workflow,
        get_runbook, get_command_set, get_diagram,
    )
    from app.models import DRRelationship

    build = get_latest_build()
    if not build:
        return jsonify({'error': 'No DR build available'}), 404

    direction = request.args.get('direction', 'planned_failover')

    # Fetch ALL relationships for this system (may be > 1 for SnapMirror/DD)
    all_rels = DRRelationship.query.filter_by(
        build_id=build.id, system_name=system_name
    ).all()

    topology = get_topology(system_name, build_id=build.id)
    workflow = get_workflow(system_name, direction, build_id=build.id)
    runbook = get_runbook(system_name, direction, build_id=build.id)
    command_set = get_command_set(system_name, direction, build_id=build.id)
    topo_diagram = get_diagram(system_name, 'topology', build_id=build.id)
    wf_diagram = get_diagram(system_name, f'workflow_{direction}', build_id=build.id)

    # For backwards compatibility keep the single ``relationship`` key as well
    first_rel = all_rels[0] if all_rels else None

    return jsonify({
        'build': build.to_dict(),
        'system_name': system_name,
        'direction': direction,
        'relationship': first_rel.to_dict() if first_rel else None,
        'relationships': [r.to_dict() for r in all_rels],
        'topology': topology.to_dict() if topology else None,
        'workflow': workflow.to_dict() if workflow else None,
        'runbook': runbook.to_dict() if runbook else None,
        'command_set': command_set.to_dict() if command_set else None,
        'topology_diagram': topo_diagram.to_dict() if topo_diagram else None,
        'workflow_diagram': wf_diagram.to_dict() if wf_diagram else None,
    })


# ---------------------------------------------------------------------------
# DR architecture data
# ---------------------------------------------------------------------------

@bp.route('/api/architecture/<path:system_name>')
def api_architecture(system_name):
    """Return DR topology model for a specific system."""
    from app.dr_service import get_latest_build, get_topology

    build = get_latest_build()
    if not build:
        return jsonify({'error': 'No DR build available'}), 404

    topology = get_topology(system_name, build_id=build.id)
    if not topology:
        return jsonify({'error': f'No topology found for {system_name}'}), 404

    topo_diagram = None
    from app.dr_service import get_diagram
    diag = get_diagram(system_name, 'topology', build_id=build.id)

    return jsonify({
        'build_id': build.id,
        'system_name': system_name,
        'topology': topology.to_dict(),
        'diagram': diag.to_dict() if diag else None,
    })


# ---------------------------------------------------------------------------
# DR workflow definitions
# ---------------------------------------------------------------------------

@bp.route('/api/workflow/<path:system_name>')
def api_workflow(system_name):
    """Return DR workflow steps for a specific system."""
    from app.dr_service import get_latest_build, get_workflow

    build = get_latest_build()
    if not build:
        return jsonify({'error': 'No DR build available'}), 404

    direction = request.args.get('direction', 'planned_failover')
    workflow = get_workflow(system_name, direction, build_id=build.id)
    if not workflow:
        return jsonify({'error': f'No workflow found for {system_name}'}), 404

    from app.dr_service import get_diagram
    wf_diagram = get_diagram(system_name, f'workflow_{direction}', build_id=build.id)

    return jsonify({
        'build_id': build.id,
        'system_name': system_name,
        'direction': direction,
        'workflow': workflow.to_dict(),
        'diagram': wf_diagram.to_dict() if wf_diagram else None,
    })


# ---------------------------------------------------------------------------
# DR runbook data
# ---------------------------------------------------------------------------

@bp.route('/api/runbook/<path:system_name>')
def api_runbook(system_name):
    """Return DR runbook for a specific system."""
    from app.dr_service import get_latest_build, get_runbook

    build = get_latest_build()
    if not build:
        return jsonify({'error': 'No DR build available'}), 404

    direction = request.args.get('direction', 'planned_failover')
    runbook = get_runbook(system_name, direction, build_id=build.id)
    if not runbook:
        return jsonify({'error': f'No runbook found for {system_name}'}), 404

    return jsonify({
        'build_id': build.id,
        'system_name': system_name,
        'direction': direction,
        'runbook': runbook.to_dict(),
    })


# ---------------------------------------------------------------------------
# DR CLI command sets
# ---------------------------------------------------------------------------

@bp.route('/api/commands/<path:system_name>')
def api_commands(system_name):
    """Return DR CLI command set for a specific system."""
    from app.dr_service import get_latest_build, get_command_set

    build = get_latest_build()
    if not build:
        return jsonify({'error': 'No DR build available'}), 404

    direction = request.args.get('direction', 'planned_failover')
    command_set = get_command_set(system_name, direction, build_id=build.id)
    if not command_set:
        return jsonify({'error': f'No command set found for {system_name}'}), 404

    return jsonify({
        'build_id': build.id,
        'system_name': system_name,
        'direction': direction,
        'command_set': command_set.to_dict(),
    })


# ---------------------------------------------------------------------------
# DR build status
# ---------------------------------------------------------------------------

@bp.route('/api/build-status')
def api_build_status():
    """Return metadata about the most recent DR build."""
    from app.dr_service import get_latest_build, DR_BUILD_INTERVAL_SECONDS
    from app.models import DRBuildMetadata

    build = get_latest_build()
    stale = _is_stale(build)

    next_build = None
    if build and build.build_timestamp:
        next_build_dt = build.build_timestamp + timedelta(seconds=DR_BUILD_INTERVAL_SECONDS)
        next_build = next_build_dt.isoformat()

    # Count of all builds
    total_builds = DRBuildMetadata.query.count()

    return jsonify({
        'build': build.to_dict() if build else None,
        'stale': stale,
        'next_scheduled_build': next_build,
        'total_builds': total_builds,
        'build_interval_seconds': DR_BUILD_INTERVAL_SECONDS,
    })


# ---------------------------------------------------------------------------
# DR rebuild trigger
# ---------------------------------------------------------------------------

@bp.route('/api/rebuild', methods=['POST'])
def api_rebuild():
    """Manually trigger a DR information rebuild."""
    try:
        from app.dr_service import trigger_rebuild
        trigger_rebuild(current_app._get_current_object())
        return jsonify({'status': 'triggered', 'message': 'DR rebuild has been triggered.'})
    except Exception as exc:
        logger.error("Failed to trigger DR rebuild: %s", exc)
        return jsonify({'error': str(exc)}), 500


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_stale(build):
    """Return True if the build is older than DR_STALE_THRESHOLD_SECONDS."""
    if not build or not build.build_timestamp:
        return False
    age = (datetime.utcnow() - build.build_timestamp).total_seconds()
    return age > DR_STALE_THRESHOLD_SECONDS
