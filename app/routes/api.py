"""API routes for programmatic access"""
import os

from flask import Blueprint, current_app, jsonify, request

from app.models import StorageSystem
from app.parallel_system_status import fetch_system_status_parallel
from app.services.system_status import fetch_system_status

bp = Blueprint('api', __name__, url_prefix='/api')


@bp.before_request
def _require_api_access_token():
    """Optional: ``API_ACCESS_TOKEN`` setzen, dann Header ``Authorization: Bearer …`` oder ``X-API-Key``."""
    token = (os.environ.get('API_ACCESS_TOKEN') or '').strip()
    if not token:
        return None
    if request.endpoint == 'api.api_health':
        return None
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer ') and auth[7:].strip() == token:
        return None
    if request.headers.get('X-API-Key', '').strip() == token:
        return None
    return jsonify({'error': 'Unauthorized', 'hint': 'Send Authorization: Bearer <token> or X-API-Key'}), 401


@bp.route('/health')
def api_health():
    """API-Liveness (von Auth ausgenommen)."""
    return jsonify({'status': 'ok', 'service': 'storage-dashboard-api'})


@bp.route('/systems')
def list_systems():
    """List all storage systems"""
    systems = StorageSystem.query.all()
    return jsonify([system.to_dict() for system in systems])


@bp.route('/status')
def get_status():
    """Get status of all enabled systems (live – makes real-time API calls to storage systems)"""
    systems = StorageSystem.query.filter_by(enabled=True).all()

    # Get current app for passing to threads
    app = current_app._get_current_object()

    systems_status = fetch_system_status_parallel(systems, app, fetch_system_status)
    return jsonify(systems_status)


@bp.route('/systems/<int:system_id>/status')
def get_system_status(system_id):
    """Get status of a specific system"""
    system = StorageSystem.query.get_or_404(system_id)
    app = current_app._get_current_object()
    result = fetch_system_status(system, app)
    return jsonify(result)


@bp.route('/cached-status')
def get_cached_status():
    """Return the most recently cached health status for all enabled systems.

    Data is populated by the background refresh service (no live API calls).
    Each entry includes a ``fetched_at`` timestamp so the dashboard can show
    how recent the data is.

    Capacity values (used, total, percent) are overridden with data from
    ``CapacitySnapshot`` when available, as those values include the
    Pure1 physical-used supplement which provides accurate figures for
    Evergreen One arrays.

    ``hardware_status``, ``cluster_status``, and the ``alerts`` count are
    adjusted to reflect acknowledged alert states so that the dashboard
    correctly shows OK once an operator has acknowledged the corresponding
    alert(s) in the Alerts view.
    """
    from app.models import CapacitySnapshot, StatusCache

    systems = StorageSystem.query.filter_by(enabled=True).all()
    result = []
    for system in systems:
        cache = StatusCache.query.filter_by(system_id=system.id).first()
        if cache:
            status = cache.get_status()
            # Override capacity values with Pure1-corrected data from
            # CapacitySnapshot (populated by the hourly capacity refresh which
            # supplements local values with Pure1 physical-used figures).
            snap = CapacitySnapshot.query.filter_by(system_id=system.id).first()
            if snap and snap.total_tb > 0:
                status['capacity_total_tb'] = snap.total_tb
                status['capacity_used_tb'] = snap.used_tb
                status['capacity_percent'] = snap.percent_used
            # Overlay acknowledged alert states so the dashboard reflects
            # operator acknowledgments without requiring a live API refresh.
            _apply_acknowledged_states(status, system.name)
            result.append({
                'system': system.to_dict(),
                'status': status,
                'fetched_at': cache.fetched_at.isoformat() if cache.fetched_at else None,
            })
        else:
            result.append({
                'system': system.to_dict(),
                'status': None,
                'fetched_at': None,
            })
    return jsonify(result)


def _apply_acknowledged_states(status, system_name):
    """Adjust *status* in-place to reflect acknowledged alert states.

    For each alert stored in ``alert_details`` (Pure Storage / ONTAP /
    StorageGRID) or ``active_alerts`` (DataDomain) the :class:`AlertState`
    table is consulted.  Acknowledged alerts are excluded from the ``alerts``
    count.  When **all** alerts for a system have been acknowledged both
    ``hardware_status`` and ``cluster_status`` are set to ``'ok'`` (provided
    they were non-ok before), matching the expectation that the dashboard
    reflects operator acknowledgment.

    If neither ``alert_details`` nor ``active_alerts`` is present in *status*
    (e.g. ONTAP without EMS data) the function returns without modification so
    that raw vendor-API status values are preserved.

    Args:
        status:      The mutable status dict from :class:`StatusCache`.
        system_name: The human-readable name of the storage system, used as
                     part of the composite alert key.
    """
    from app.models import AlertState

    # Determine which alert list to use and how to extract key fields.
    # DataDomain uses 'active_alerts' with 'id'/'name' fields;
    # all other vendors use 'alert_details' with 'id'/'title' fields.
    is_active_alerts = bool(status.get('active_alerts'))
    alert_list = status.get('active_alerts') if is_active_alerts else status.get('alert_details')

    if not alert_list:
        return  # No per-alert detail → cannot determine acknowledged state

    # Build composite keys for every alert in the list.
    def _make_key(alert):
        alert_id = str(alert.get('id', '-'))
        if is_active_alerts:
            title = alert.get('name', alert.get('category', '-'))
        else:
            title = alert.get('title', '-')
        return AlertState.make_key(system_name, alert_id, title)

    alert_keys = [_make_key(a) for a in alert_list]

    # Single batch query – O(1) DB round-trips regardless of alert count.
    acknowledged_keys = {
        s.alert_key
        for s in AlertState.query.filter(
            AlertState.alert_key.in_(alert_keys),
            AlertState.acknowledged,
        ).all()
    }

    unacknowledged_count = sum(1 for k in alert_keys if k not in acknowledged_keys)

    # Update the alert counter shown in the dashboard card.
    status['alerts'] = unacknowledged_count

    # When every alert for this system has been acknowledged, promote both
    # hardware and cluster status back to 'ok' so the dashboard card turns
    # green.  A single remaining unacknowledged alert keeps the original
    # severity, ensuring a second error is never silently hidden.
    if unacknowledged_count == 0:
        if status.get('hardware_status') not in ('ok', None):
            status['hardware_status'] = 'ok'
        if status.get('cluster_status') not in ('ok', None):
            status['cluster_status'] = 'ok'


@bp.route('/trigger-status-refresh', methods=['POST'])
def trigger_status_refresh():
    """Trigger an immediate status refresh (runs synchronously, returns fresh cached data).

    Useful for the manual-refresh button on the dashboard: the caller waits for
    the refresh to finish and receives up-to-date data in the response.
    """
    from app.status_service import do_refresh_sync
    app = current_app._get_current_object()
    results = do_refresh_sync(app)
    return jsonify(results)


@bp.route('/alerts')
def get_alerts():
    """Return the current open alerts from the StatusCache as JSON.

    Used by the alerts page for live auto-refresh: the JavaScript polling loop
    calls this endpoint periodically and updates the table to reflect the latest
    cached state.  Resolved alerts that are no longer present in the cache are
    automatically absent from the response, so the table cleans itself up
    without requiring a full page reload.

    Response shape::

        {
            "alerts": [ { ...alert fields... }, ... ],
            "fetched_at": "<ISO-8601 timestamp of the most recent cache entry>"
        }
    """
    from app.routes.alerts import collect_alerts
    alerts = collect_alerts()
    # Determine the most recent fetched_at across all alerts so the UI can
    # show a single "last updated" timestamp.
    fetched_at = None
    for a in alerts:
        fa = a.get('fetched_at')
        if fa and (fetched_at is None or fa > fetched_at):
            fetched_at = fa
    return jsonify({'alerts': alerts, 'fetched_at': fetched_at})


@bp.route('/alerts/state', methods=['POST'])
def update_alert_state():
    """Update the user-managed state for one or more alerts (bulk-capable).

    Request body (JSON)::

        {
            "alert_keys": ["system|id|title", ...],
            "acknowledged": true,          // optional – omit to leave unchanged
            "assignee":     "Max Müller",  // optional – null clears the field
            "comment":      "Wird untersucht"  // optional – null clears the field
        }

    Returns the number of affected alert keys.
    """
    from datetime import datetime

    from app import db
    from app.models import AlertState, AssigneeHistory

    data = request.get_json(silent=True) or {}
    alert_keys = data.get('alert_keys')
    if not alert_keys or not isinstance(alert_keys, list):
        return jsonify({'error': 'alert_keys list required'}), 400

    acknowledged = data.get('acknowledged')        # None means "don't change"
    assignee     = data.get('assignee', _MISSING)  # _MISSING means "don't change"
    comment      = data.get('comment',  _MISSING)

    updated = 0
    for key in alert_keys:
        if not isinstance(key, str) or not key:
            continue
        state = AlertState.query.filter_by(alert_key=key).first()
        if state is None:
            state = AlertState(alert_key=key)
            db.session.add(state)
        if acknowledged is not None:
            state.acknowledged = bool(acknowledged)
        if assignee is not _MISSING:
            state.assignee = assignee or None
        if comment is not _MISSING:
            state.comment = comment or None
        state.updated_at = datetime.utcnow()
        updated += 1

    # Persist a new assignee name into the history table for autocomplete
    assignee_name = data.get('assignee')
    if assignee_name and isinstance(assignee_name, str):
        existing = AssigneeHistory.query.filter_by(name=assignee_name).first()
        if existing:
            existing.used_at = datetime.utcnow()
        else:
            db.session.add(AssigneeHistory(name=assignee_name))

    db.session.commit()
    from app.alert_count_cache import invalidate_open_alerts_count_cache
    invalidate_open_alerts_count_cache()
    return jsonify({'updated': updated})


# Sentinel to distinguish "key absent" from "key present with None value"
_MISSING = object()


@bp.route('/alerts/assignees', methods=['GET'])
def get_assignees():
    """Return all assignee names stored in history, ordered by most recently used."""
    from app.models import AssigneeHistory
    history = AssigneeHistory.query.order_by(AssigneeHistory.used_at.desc()).all()
    return jsonify([h.name for h in history])


@bp.route('/alerts/assignees/<path:name>', methods=['DELETE'])
def delete_assignee(name):
    """Remove an assignee name from the autocomplete history."""
    from app import db
    from app.models import AssigneeHistory
    entry = AssigneeHistory.query.filter_by(name=name).first()
    if entry:
        db.session.delete(entry)
        db.session.commit()
    return jsonify({'deleted': name})

