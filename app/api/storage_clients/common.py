"""Shared helpers and ONTAP EMS logic for storage API clients."""
import logging
import re
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)
_EPOCH_TS_FORMAT = '%Y-%m-%d %H:%M:%S UTC'


def _strip_version_date(version_str):
    """Return only the release identifier from a NetApp version string.

    ONTAP returns version strings like
    "NetApp Release 9.16.1P11: Thu Jan 15 11:21:38 UTC 2026".
    Only the part before the first colon is relevant for display.
    """
    if version_str and isinstance(version_str, str):
        return version_str.split(':')[0].strip()
    return version_str


def _epoch_ms_to_str(epoch_ms):
    """Convert a Unix timestamp in milliseconds to a human-readable UTC string."""
    try:
        return datetime.fromtimestamp(int(epoch_ms) / 1000, tz=timezone.utc).strftime(_EPOCH_TS_FORMAT)
    except Exception:
        return str(epoch_ms)


def _epoch_s_to_str(epoch_s):
    """Convert a Unix timestamp in seconds to a human-readable UTC string."""
    try:
        return datetime.fromtimestamp(int(epoch_s), tz=timezone.utc).strftime(_EPOCH_TS_FORMAT)
    except Exception:
        return str(epoch_s)

# Maximum length of response text to log (to avoid flooding logs with large responses)
MAX_RESPONSE_LOG_LENGTH = 500

# StorageGRID API health state constants
# States that indicate a healthy grid/node
STORAGEGRID_HEALTHY_GRID_STATES = {'healthy', 'ok', 'normal'}

# Node states that indicate a healthy/connected node
STORAGEGRID_HEALTHY_NODE_STATES = {'connected', 'online', 'ok', 'healthy'}

# Alert states that are considered active/unresolved
# Based on StorageGRID API v4 alert states
STORAGEGRID_ACTIVE_ALERT_STATES = {'active', 'triggered', 'firing'}

# ---------------------------------------------------------------------------
# ONTAP EMS active-alert filtering
# ---------------------------------------------------------------------------
# ONTAP EMS is an event log, not a state database.  Many problems generate two
# events: a "problem" event when the issue occurs and a "recovery" event when
# it is resolved.  Historical events for already-resolved issues remain in the
# log forever, so we must reconstruct the current state by checking the most
# recent event per affected resource.
#
# Map: problem event name  →  its corresponding recovery event name
_EMS_PROBLEM_RECOVERY_PAIRS = {
    'hm.alert.raised':                        'hm.alert.cleared',
    'cpeer.unavailable':                      'cpeer.available',
    'cf.fsm.monitor.globalStatus.critical':   'cf.fsm.monitor.globalStatus.ok',
}

_EMS_RECOVERY_EVENT_NAMES = set(_EMS_PROBLEM_RECOVERY_PAIRS.values())
_EMS_PROBLEM_EVENT_NAMES  = set(_EMS_PROBLEM_RECOVERY_PAIRS.keys())
_EMS_TRACKED_EVENT_NAMES  = _EMS_PROBLEM_EVENT_NAMES | _EMS_RECOVERY_EVENT_NAMES

# ONTAP REST API filter string for all recovery events (used in the second query)
_EMS_RECOVERY_FILTER = ','.join(sorted(_EMS_RECOVERY_EVENT_NAMES))

# ---------------------------------------------------------------------------
# EMS age and category filtering
# ---------------------------------------------------------------------------
# Two additional filters are applied on top of the state-reconstruction filter:
#
# 1. Age filter – events older than _EMS_LOOKBACK_HOURS are discarded.
#    ONTAP EMS keeps every event forever; old entries that were never paired
#    with a recovery event (untracked families) would otherwise accumulate and
#    flood the dashboard with stale noise.
#
# 2. Category filter – not all "error"-severity events are equally actionable.
#    Hardware-related events (drive failures, cluster HA, environmental …) are
#    shown from severity "error" upwards (unchanged from the API query).
#    Non-hardware events (capacity thresholds, filesystem notices, …) require
#    at least severity "alert" so that low-priority "error"-class capacity
#    warnings are suppressed unless they escalate to truly critical.
#
# Hours of EMS history to show.  Events raised before this window are skipped
# regardless of whether they have been recovered.
_EMS_LOOKBACK_HOURS = 96

# ONTAP EMS event-name prefixes that identify hardware-related events.
# These events are retained at all fetched severity levels (emergency/alert/error).
# Events whose names do NOT start with any of these prefixes require at least
# severity "alert" (i.e. "error"-only capacity/software events are suppressed).
_EMS_HARDWARE_EVENT_PREFIXES = (
    'hm.',        # Health Monitor – hardware fault alerts
    'disk.',      # Disk / drive hardware
    'raid.',      # RAID / plex failures
    'nvme.',      # NVMe hardware
    'nvmf.',      # NVMe-oF hardware
    'env.',       # Environmental: fans, PSUs, temperature
    'cf.',        # Cluster failover / HA
    'node.',      # Node-level hardware events
    'sas.',       # SAS interconnect hardware
    'fc.',        # Fibre Channel hardware
    'callhome.',  # System call-home (triggered by hardware failures)
    'cpeer.',     # Cluster peer connectivity
)

# Minimum severities required for non-hardware EMS events to be shown.
# "error"-class non-hardware events (e.g. capacity thresholds) are excluded.
_EMS_NON_HW_MIN_SEVERITIES = frozenset({'emergency', 'alert'})


def _parse_ems_timestamp(time_str):
    """Parse an ONTAP EMS ISO-8601 timestamp string to a timezone-aware datetime.

    Handles both ``+00:00`` offset notation and the ``Z`` suffix.
    Returns ``None`` when the string cannot be parsed so callers can apply a
    conservative fallback (include the event rather than silently drop it).
    """
    if not time_str:
        return None
    try:
        s = str(time_str)
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError, AttributeError):
        return None


def _filter_ems_by_age_and_category(events):
    """Apply age and category-based severity filters to EMS problem events.

    Removes:
    * Events older than ``_EMS_LOOKBACK_HOURS`` hours – stale log entries
      that should have been cleared but were not (e.g. untracked event
      families without a recovery counterpart).
    * Non-hardware events whose severity is only ``error`` – capacity
      threshold breaches, filesystem notices, etc. require at least
      severity ``alert`` to appear in the dashboard.

    Hardware events (names starting with ``_EMS_HARDWARE_EVENT_PREFIXES``)
    are kept at every fetched severity level (emergency / alert / error).

    Events with an unparseable timestamp or missing message name are included
    conservatively so that unknown events are never silently dropped.

    Args:
        events: list of EMS event dicts (from the severity-based API query).

    Returns:
        Filtered list containing only relevant, recent EMS events.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=_EMS_LOOKBACK_HOURS)
    result = []
    for event in events:
        # --- Age filter ---------------------------------------------------
        event_time = _parse_ems_timestamp(event.get('time', ''))
        if event_time is not None and event_time < cutoff:
            continue  # Too old – skip

        # --- Category-based severity filter --------------------------------
        msg      = event.get('message', {})
        msg_name = msg.get('name', '')
        severity = msg.get('severity', '')

        is_hardware = any(msg_name.startswith(pfx) for pfx in _EMS_HARDWARE_EVENT_PREFIXES)
        if not is_hardware and severity not in _EMS_NON_HW_MIN_SEVERITIES:
            continue  # Low-priority non-hardware event – skip

        result.append(event)
    return result


def _get_ems_resource_key(event):
    """Return a hashable key that uniquely identifies the resource affected by an EMS event.

    The key is used to group problem and recovery events for the same resource
    so that the most-recent event wins.

    For health-monitor alerts the ONTAP EMS parameters include an ``alertId``
    that distinguishes individual alerts on the same node.  For cluster-peer and
    cluster-failover events the node name (or peer name from parameters) is
    sufficient.
    """
    msg_name  = event.get('message', {}).get('name', '')
    node_info = event.get('node', {})
    node_name = node_info.get('name', '') if isinstance(node_info, dict) else ''

    # Parse event-specific parameters (array of {name, value} objects)
    params = {}
    for p in event.get('parameters', []):
        if isinstance(p, dict):
            params[p.get('name', '')] = p.get('value', '')

    if msg_name in ('hm.alert.raised', 'hm.alert.cleared'):
        alert_id = params.get('alertId', params.get('alert_id', ''))
        return ('hm.alert', node_name, alert_id)
    elif msg_name in ('cpeer.unavailable', 'cpeer.available'):
        peer = params.get('peerName', params.get('peer_name', params.get('peer', '')))
        return ('cpeer', peer)
    elif 'cf.fsm.monitor.globalStatus' in msg_name:
        return ('cf.fsm.monitor.globalStatus', node_name)
    # Fallback: not a tracked event family
    return None


def _filter_active_ems_events(problem_records, recovery_records):
    """Return only the EMS problem events that are still active.

    For each event in *problem_records* that belongs to a known problem/recovery
    pair family (see ``_EMS_PROBLEM_RECOVERY_PAIRS``), this function checks
    whether a more recent recovery event exists in *recovery_records* for the
    same resource.  If one is found the problem is considered resolved and is
    excluded from the result.

    Events that do not belong to a tracked family (e.g. generic severity-based
    events like ``callhome.spares.low``) are always included unchanged.

    Args:
        problem_records: list of EMS event dicts from the severity-based query.
        recovery_records: list of EMS event dicts from the recovery-name query.

    Returns:
        A filtered list containing only currently active alert dicts.
    """
    # Build a map: resource_key → latest recovery event time
    recovery_latest = {}
    for event in recovery_records:
        key = _get_ems_resource_key(event)
        if key is None:
            continue
        event_time = event.get('time', '')
        if key not in recovery_latest or event_time > recovery_latest[key]:
            recovery_latest[key] = event_time

    active = []
    for event in problem_records:
        msg_name = event.get('message', {}).get('name', '')
        if msg_name not in _EMS_PROBLEM_EVENT_NAMES:
            # Not a tracked problem event – include as-is
            active.append(event)
            continue

        resource_key = _get_ems_resource_key(event)
        if resource_key is None:
            # Cannot determine resource key – include conservatively
            active.append(event)
            continue

        problem_time         = event.get('time', '')
        latest_recovery_time = recovery_latest.get(resource_key)

        if latest_recovery_time is None or problem_time > latest_recovery_time:
            # No recovery found, or problem is newer than any recovery → still active
            active.append(event)
        # else: a more recent recovery event exists → alert is cleared, skip

    return active


# ---------------------------------------------------------------------------
# REST status alert helpers
# ---------------------------------------------------------------------------

_REST_ALERT_VENDOR   = 'netapp'
_REST_ALERT_PLATFORM = 'ontap'


def _make_rest_alert(category, resource, severity, message, source, timestamp=None):
    """Create an alert dict in the common dashboard format from an ONTAP REST status check.

    The returned dict is compatible with the existing ``alert_details`` schema
    consumed by ``_normalize_alert_detail()`` in *routes/alerts.py* and also
    carries the additional normalized fields described in the multi-vendor alert
    specification (vendor / platform / category / source).

    Args:
        category:  One of 'cluster', 'node', 'network', 'storage', 'replication'.
        resource:  Human-readable identifier of the affected object,
                   e.g. "node1", "node1:e0c", "svm1:lif1".
        severity:  'critical', 'error', or 'warning'.
        message:   Human-readable description of the problem.
        source:    REST API path used to detect the problem, e.g. '/api/cluster'.
        timestamp: ISO-8601 string; defaults to current UTC time when omitted.
    """
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    safe_id = re.sub(r'[^a-z0-9_:-]', '-', resource.lower())
    return {
        # Fields used by _normalize_alert_detail() in routes/alerts.py
        'id':         f'rest-{category}-{safe_id}',
        'title':      f'{category.title()} issue: {resource}',
        'details':    message,
        'severity':   severity,
        'error_code': f'{category}.status',
        'timestamp':  ts,
        'component':  resource,
        # Normalized multi-vendor format fields
        'vendor':     _REST_ALERT_VENDOR,
        'platform':   _REST_ALERT_PLATFORM,
        'category':   category,
        'source':     source,
    }


def extract_field_with_fallbacks(data, field_names):
    """
    Helper function to extract a field value from data dictionary
    trying multiple possible field names.

    Args:
        data: Dictionary to search
        field_names: List of field names to try in order

    Returns:
        First non-None value found, or None if none found
    """
    if not data:
        return None

    for field_name in field_names:
        # Handle nested field names like 'version.full'
        if '.' in field_name:
            parts = field_name.split('.')
            value = data
            for part in parts:
                if value and isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = None
                    break
            if value:
                return value
        else:
            # Simple field name
            value = data.get(field_name)
            if value:
                return value

    return None
