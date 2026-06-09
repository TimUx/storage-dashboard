"""Dashboard display adjustments derived from management-IP monitoring."""
from __future__ import annotations

from app.routes.alerts import IP_CONNECTIVITY_ALERT_ID


def _ip_alert_title(ip: str) -> str:
    return f'Management-IP nicht erreichbar ({ip})'


def collect_ip_connectivity_alert_keys(status, system_name):
    """Return :class:`AlertState` composite keys for unreachable management IPs."""
    from app.models import AlertState

    ip_monitor = status.get('ip_monitor') if isinstance(status, dict) else {}
    if not isinstance(ip_monitor, dict):
        return []

    keys = []
    for ip in ip_monitor.get('unreachable_ips') or []:
        alert_id = f'{IP_CONNECTIVITY_ALERT_ID}:{ip}'
        keys.append(AlertState.make_key(system_name, alert_id, _ip_alert_title(ip)))
    return keys


def apply_ip_connectivity_dashboard_status(status, system_name, *, acknowledged_keys=None):
    """Reflect unacknowledged unreachable management IPs in dashboard status fields.

    Mutates *status* in place: increments ``alerts`` and downgrades ``hardware_status``
    / ``cluster_status`` when at least one unreachable IP is not acknowledged.
    """
    if not isinstance(status, dict):
        return

    ip_monitor = status.get('ip_monitor') or {}
    unreachable = ip_monitor.get('unreachable_ips') or []
    if not unreachable:
        return

    keys = collect_ip_connectivity_alert_keys(status, system_name)
    if not keys:
        return

    if acknowledged_keys is None:
        from app.models import AlertState

        acknowledged_keys = {
            s.alert_key
            for s in AlertState.query.filter(
                AlertState.alert_key.in_(keys),
                AlertState.acknowledged,
            ).all()
        }

    unacknowledged = sum(1 for key in keys if key not in acknowledged_keys)
    if unacknowledged == 0:
        return

    status['alerts'] = (status.get('alerts') or 0) + unacknowledged

    reachable = ip_monitor.get('reachable_ips') or []
    severity = 'error' if not reachable else 'warning'

    hw = status.get('hardware_status')
    if hw in (None, 'ok'):
        status['hardware_status'] = severity
    elif severity == 'error' and hw == 'warning':
        status['hardware_status'] = 'error'

    cluster = status.get('cluster_status')
    if cluster in (None, 'ok'):
        status['cluster_status'] = severity
    elif severity == 'error' and cluster == 'warning':
        status['cluster_status'] = 'error'


def prepare_dashboard_status(status, system_name, *, snap=None, acknowledged_keys=None):
    """Apply capacity override and vendor-ack / IP-monitor overlays for UI display."""
    from app.routes.api import _apply_acknowledged_states, _get_acknowledged_keys
    from app.routes.api import _collect_alert_keys as collect_vendor_alert_keys

    if snap and snap.total_tb > 0:
        status['capacity_total_tb'] = snap.total_tb
        status['capacity_used_tb'] = snap.used_tb
        status['capacity_percent'] = snap.percent_used

    if acknowledged_keys is None:
        keys = collect_vendor_alert_keys(status, system_name)
        keys.extend(collect_ip_connectivity_alert_keys(status, system_name))
        acknowledged_keys = _get_acknowledged_keys(keys)

    _apply_acknowledged_states(status, system_name, acknowledged_keys=acknowledged_keys)
    apply_ip_connectivity_dashboard_status(
        status, system_name, acknowledged_keys=acknowledged_keys,
    )
