"""Disaster Recovery (DR) routes – /dr/"""
import logging
from datetime import datetime, timedelta
from flask import Blueprint, render_template, jsonify, request, current_app

bp = Blueprint('dr', __name__, url_prefix='/dr')
logger = logging.getLogger(__name__)

# Age threshold after which the UI shows a "may be outdated" warning
DR_STALE_THRESHOLD_SECONDS = 7 * 24 * 60 * 60  # 1 week (matches default build interval)


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
# DR system details
# ---------------------------------------------------------------------------

@bp.route('/api/system/<path:system_name>')
def api_system(system_name):
    """Return all DR artifacts for a specific system from the latest build."""
    from app.dr_service import (
        get_latest_build, get_topology, get_workflow,
        get_runbook, get_command_set, get_diagram,
    )
    from app.models import DRRelationship

    build = get_latest_build()
    if not build:
        return jsonify({'error': 'No DR build available'}), 404

    direction = request.args.get('direction', 'planned_failover')

    # Fetch relationship
    rel = DRRelationship.query.filter_by(
        build_id=build.id, system_name=system_name
    ).first()

    topology = get_topology(system_name, build_id=build.id)
    workflow = get_workflow(system_name, direction, build_id=build.id)
    runbook = get_runbook(system_name, direction, build_id=build.id)
    command_set = get_command_set(system_name, direction, build_id=build.id)
    topo_diagram = get_diagram(system_name, 'topology', build_id=build.id)
    wf_diagram = get_diagram(system_name, f'workflow_{direction}', build_id=build.id)

    return jsonify({
        'build': build.to_dict(),
        'system_name': system_name,
        'direction': direction,
        'relationship': rel.to_dict() if rel else None,
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
