"""Alerts page route – shows all open alerts across all storage systems"""
from flask import Blueprint, render_template
from app.models import StorageSystem, StatusCache, AlertState

bp = Blueprint('alerts', __name__)

VENDOR_NAMES = {
    'pure': 'Pure Storage',
    'netapp-ontap': 'NetApp ONTAP',
    'netapp-storagegrid': 'NetApp StorageGRID',
    'dell-datadomain': 'Dell DataDomain',
}


def _normalize_dd_alert(alert, system):
    """Normalise a DataDomain active_alerts entry to the common schema.
    
    Field mapping based on dd_api.json alertDetail schema:
      alert_id / id → alert_id
      severity      → severity
      class         → stored as 'category' in active_alerts dict
      msg           → stored as 'message' in active_alerts dict
      partError     → stored as 'error_code' in active_alerts dict
    """
    return {
        'system_name': system.name,
        'system_vendor': VENDOR_NAMES.get(system.vendor, system.vendor),
        'alert_id': str(alert.get('id', '-')),
        'title': alert.get('name', alert.get('category', '-')),
        'details': alert.get('message', '-'),
        'severity': alert.get('severity', 'unknown'),
        'error_code': str(alert.get('error_code', alert.get('id', '-'))),
        'timestamp': alert.get('timestamp', '-'),
        'component': alert.get('category', '-'),
    }


def _normalize_alert_detail(alert, system):
    """Normalise a generic alert_details entry (Pure Storage / StorageGRID)."""
    return {
        'system_name': system.name,
        'system_vendor': VENDOR_NAMES.get(system.vendor, system.vendor),
        'alert_id': str(alert.get('id', '-')),
        'title': alert.get('title', '-'),
        'details': alert.get('details', '-'),
        'severity': alert.get('severity', 'unknown'),
        'error_code': str(alert.get('error_code', '-')),
        'timestamp': alert.get('timestamp', '-'),
        'component': alert.get('component', '-'),
    }


def _merge_alert_states(all_alerts):
    """Attach persisted state (acknowledged, assignee, comment, alert_key) to each alert dict.

    Performs a single batch DB query so that merging is O(1) per alert rather
    than O(n) queries.
    """
    if not all_alerts:
        return

    # Build composite keys for all alerts
    for a in all_alerts:
        a['alert_key'] = AlertState.make_key(
            a.get('system_name', ''),
            a.get('alert_id', ''),
            a.get('title', ''),
        )

    keys = [a['alert_key'] for a in all_alerts]
    states_by_key = {
        s.alert_key: s
        for s in AlertState.query.filter(AlertState.alert_key.in_(keys)).all()
    }

    for a in all_alerts:
        state = states_by_key.get(a['alert_key'])
        a['acknowledged'] = state.acknowledged if state else False
        a['assignee'] = state.assignee if state else None
        a['comment'] = state.comment if state else None


def collect_alerts():
    """Build the normalised list of open alerts from the current StatusCache.

    Returns a list of alert dicts in the common schema.  Each dict also carries
    a ``fetched_at`` key (ISO-8601 string or ``None``) indicating how fresh the
    underlying cache entry is, as well as ``alert_key``, ``acknowledged``,
    ``assignee``, and ``comment`` fields from :class:`AlertState`.

    This function is used by both the HTML route and the JSON API endpoint so
    that both views always reflect the same data.
    """
    systems = StorageSystem.query.filter_by(enabled=True).order_by(StorageSystem.name).all()

    all_alerts = []
    for system in systems:
        cache = StatusCache.query.filter_by(system_id=system.id).first()
        if not cache:
            continue
        status = cache.get_status()
        if not status:
            continue

        fetched_at = cache.fetched_at.isoformat() if cache.fetched_at else None

        def _tag(alert_dict):
            alert_dict['fetched_at'] = fetched_at
            return alert_dict

        # DataDomain stores alert details under 'active_alerts'
        if status.get('active_alerts'):
            for alert in status['active_alerts']:
                all_alerts.append(_tag(_normalize_dd_alert(alert, system)))
            continue

        # Pure Storage / StorageGRID store alert details under 'alert_details'
        if status.get('alert_details'):
            for alert in status['alert_details']:
                all_alerts.append(_tag(_normalize_alert_detail(alert, system)))
            continue

        # Fallback: no details available but alerts count > 0
        alert_count = status.get('alerts', 0)
        if alert_count:
            all_alerts.append({
                'system_name': system.name,
                'system_vendor': VENDOR_NAMES.get(system.vendor, system.vendor),
                'alert_id': '-',
                'title': f'{alert_count} offene{"r" if alert_count == 1 else ""} Alert{"" if alert_count == 1 else "s"}',
                'details': 'Keine Details verfügbar',
                'severity': 'unknown',
                'error_code': '-',
                'timestamp': '-',
                'component': '-',
                'fetched_at': fetched_at,
            })

    _merge_alert_states(all_alerts)
    return all_alerts


@bp.route('/alerts/')
def alerts():
    """Alerts page – aggregates open alerts from all cached system statuses."""
    all_alerts = collect_alerts()
    return render_template('alerts.html', all_alerts=all_alerts)
