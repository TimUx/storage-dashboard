"""Alerts page route – shows all open alerts across all storage systems"""
from datetime import datetime

from flask import Blueprint, render_template
from app.models import StorageSystem, StatusCache, AlertState

bp = Blueprint('alerts', __name__)

VENDOR_NAMES = {
    'pure': 'Pure Storage',
    'netapp-ontap': 'NetApp ONTAP',
    'netapp-storagegrid': 'NetApp StorageGRID',
    'dell-datadomain': 'Dell DataDomain',
}

# Synthetic alert when the dashboard cannot reach a system (stable id/title for AlertState).
CONNECTIVITY_ALERT_ID = 'dashboard.connectivity'
CONNECTIVITY_ALERT_TITLE = 'System nicht erreichbar'
IP_CONNECTIVITY_ALERT_ID = 'dashboard.ip-connectivity'
SNAP_COLLECTOR_ALERT_ID = 'dashboard.snap-collector'
SNAP_COLLECTOR_ALERT_TITLE = 'Snapshot-Aktualisierung fehlgeschlagen'
SNAP_COLLECTOR_STALE_ALERT_ID = 'dashboard.snap-collector.stale'
SNAP_COLLECTOR_STALE_ALERT_TITLE = 'Snapshot-Aktualisierung überfällig'


def _status_indicates_unreachable(status):
    """True if cached status means the storage API was not successfully queried."""
    if not status or not isinstance(status, dict):
        return False
    st = (status.get('status') or '').lower()
    if st in ('error', 'offline'):
        return True
    if status.get('error') and st != 'online':
        return True
    return False


def _synthetic_connectivity_alert(system, status, fetched_at):
    """Build a normalised alert row for an unreachable / errored system."""
    msg = status.get('error') if isinstance(status, dict) else None
    details = (msg or '').strip() or (
        'Das Speichersystem antwortet nicht oder die Anmeldung ist fehlgeschlagen.'
    )
    return {
        'system_name': system.name,
        'system_vendor': VENDOR_NAMES.get(system.vendor, system.vendor),
        'alert_id': CONNECTIVITY_ALERT_ID,
        'title': CONNECTIVITY_ALERT_TITLE,
        'details': details,
        'severity': 'error',
        'error_code': 'CONNECTIVITY',
        'timestamp': fetched_at or '-',
        'component': system.ip_address,
        'fetched_at': fetched_at,
    }


def _synthetic_ip_alerts(system, status, fetched_at):
    """Build one synthetic alert per unreachable management IP."""
    ip_monitor = status.get('ip_monitor') if isinstance(status, dict) else {}
    if not isinstance(ip_monitor, dict):
        return []
    alerts = []
    for ip in ip_monitor.get('unreachable_ips') or []:
        alerts.append({
            'system_name': system.name,
            'system_vendor': VENDOR_NAMES.get(system.vendor, system.vendor),
            'alert_id': f'{IP_CONNECTIVITY_ALERT_ID}:{ip}',
            'title': f'Management-IP nicht erreichbar ({ip})',
            'details': f'Die Management-IP {ip} ist per TCP-Port {system.port or 443} nicht erreichbar.',
            'severity': 'error',
            'error_code': 'IP_CONNECTIVITY',
            'timestamp': fetched_at or '-',
            'component': ip,
            'fetched_at': fetched_at,
        })
    return alerts


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

        # Vendor-specific alert rows (may coexist with a synthetic connectivity alert).
        if status.get('active_alerts'):
            for alert in status['active_alerts']:
                all_alerts.append(_tag(_normalize_dd_alert(alert, system)))
        elif status.get('alert_details'):
            for alert in status['alert_details']:
                all_alerts.append(_tag(_normalize_alert_detail(alert, system)))
        else:
            alert_count = status.get('alerts', 0)
            if alert_count:
                all_alerts.append(_tag({
                    'system_name': system.name,
                    'system_vendor': VENDOR_NAMES.get(system.vendor, system.vendor),
                    'alert_id': '-',
                    'title': f'{alert_count} offene{"r" if alert_count == 1 else ""} Alert{"" if alert_count == 1 else "s"}',
                    'details': 'Keine Details verfügbar',
                    'severity': 'unknown',
                    'error_code': '-',
                    'timestamp': '-',
                    'component': '-',
                }))

        if _status_indicates_unreachable(status):
            all_alerts.append(_tag(_synthetic_connectivity_alert(system, status, fetched_at)))
        for ip_alert in _synthetic_ip_alerts(system, status, fetched_at):
            all_alerts.append(_tag(ip_alert))

    # Add synthetic app-health alerts for snapshot collector failures/staleness.
    try:
        from app.models import SnapshotCollectorMetadata
        try:
            from app.snap_service import SNAP_COLLECT_INTERVAL_SECONDS
        except Exception:
            SNAP_COLLECT_INTERVAL_SECONDS = 15 * 60

        stale_threshold_seconds = max(int(SNAP_COLLECT_INTERVAL_SECONDS) * 2, 20 * 60)
        latest_snap_run = SnapshotCollectorMetadata.query.order_by(
            SnapshotCollectorMetadata.run_at.desc()
        ).first()
        latest_snap_error = SnapshotCollectorMetadata.query.filter(
            SnapshotCollectorMetadata.status == 'error'
        ).order_by(SnapshotCollectorMetadata.run_at.desc()).first()

        if latest_snap_run and latest_snap_run.run_at:
            now = datetime.utcnow()
            age_seconds = max(0, int((now - latest_snap_run.run_at).total_seconds()))
        else:
            age_seconds = None

        if latest_snap_run and (latest_snap_run.status or '').lower() == 'error':
            run_at = latest_snap_run.run_at.isoformat() if latest_snap_run.run_at else None
            details = (latest_snap_run.error_message or '').strip() or (
                'Die letzte Snapshot-Sammelroutine ist fehlgeschlagen.'
            )
            all_alerts.append({
                'system_name': 'Snapshot Collector',
                'system_vendor': 'Storage Dashboard',
                'alert_id': SNAP_COLLECTOR_ALERT_ID,
                'title': SNAP_COLLECTOR_ALERT_TITLE,
                'details': details,
                'severity': 'error',
                'error_code': 'SNAP_COLLECTOR',
                'timestamp': run_at or '-',
                'component': 'Background-Thread',
                'fetched_at': run_at,
            })
        elif (
            latest_snap_run
            and latest_snap_run.run_at
            and age_seconds is not None
            and age_seconds > stale_threshold_seconds
        ):
            run_at = latest_snap_run.run_at.isoformat()
            last_status = (latest_snap_run.status or 'unknown').lower()
            systems_queried = latest_snap_run.systems_queried or 0
            duration = latest_snap_run.duration_seconds
            duration_text = (
                f'{duration:.1f}s'
                if isinstance(duration, (int, float))
                else 'unbekannt'
            )

            reason_hint = (
                'Seit dem letzten erfolgreichen Lauf wurde kein neuer Lauf abgeschlossen. '
                'Mögliche Ursachen: Background-Thread gestoppt/hängend, '
                'Scheduler blockiert oder Prozess-Neustart ohne aktive Jobs.'
                if last_status == 'success' else
                'Der letzte bekannte Lauf war nicht erfolgreich. '
                'Die Aktualisierung bleibt daher auf einem alten Stand.'
            )

            last_error_hint = ''
            if latest_snap_error and latest_snap_error.run_at:
                err_run_at = latest_snap_error.run_at.isoformat()
                err_msg = (latest_snap_error.error_message or '').strip()
                if err_msg:
                    err_msg = err_msg.replace('\n', ' ').strip()
                    last_error_hint = (
                        f' Letzter Fehlerlauf ({err_run_at}): {err_msg}'
                    )
                else:
                    last_error_hint = (
                        f' Letzter Fehlerlauf ({err_run_at}) ohne Fehlermeldungstext.'
                    )

            all_alerts.append({
                'system_name': 'Snapshot Collector',
                'system_vendor': 'Storage Dashboard',
                'alert_id': SNAP_COLLECTOR_STALE_ALERT_ID,
                'title': SNAP_COLLECTOR_STALE_ALERT_TITLE,
                'details': (
                    f'Die letzte erfolgreiche Snapshot-Sammelroutine liegt '
                    f'seit {age_seconds // 60} Minuten zurück. '
                    f'Letzter Laufstatus: {last_status.upper()}, '
                    f'Dauer: {duration_text}, abgefragte Systeme: {systems_queried}. '
                    f'{reason_hint}{last_error_hint}'
                ),
                'severity': 'warning',
                'error_code': 'SNAP_COLLECTOR_STALE',
                'timestamp': run_at,
                'component': 'Background-Thread',
                'fetched_at': run_at,
            })
    except Exception:
        # Keep alerts rendering resilient even if optional snapshot metadata lookup fails.
        pass

    _merge_alert_states(all_alerts)
    return all_alerts


@bp.route('/alerts/')
def alerts():
    """Alerts page – aggregates open alerts from all cached system statuses."""
    all_alerts = collect_alerts()
    return render_template('alerts.html', all_alerts=all_alerts)
