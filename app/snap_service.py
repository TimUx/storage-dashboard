"""Snapshot collection service – background collector for Pure FlashArray and ONTAP snapshots.

Architecture mirrors ``capacity_service`` and ``dr_service``:
- A single daemon thread runs ``_background_loop`` and calls ``_do_collect``
  once on startup, then sleeps for SNAP_COLLECT_INTERVAL_SECONDS (15 min).
- Each storage system is queried in a separate worker thread using a
  ThreadPoolExecutor with 16–32 workers.
- Collected snapshot data is normalised, deduplicated, grouped by SID and
  stored in PostgreSQL (snapshot_records table).

FlashArray vs. ONTAP snapshot identification
--------------------------------------------
The two platforms use fundamentally different naming conventions; the filtering
rules are platform-specific and must NOT be mixed:

Pure FlashArray
    Snapshots are identified by their suffix / name patterns:
    - HANA databases: suffix contains ``HDBSNAP``, volumes end in ``_data``
      or ``_log``.  Pod-hosted volumes carry a ``pod-name::`` prefix that is
      stripped before matching.
      Examples (after pod-prefix strip):
          IEP_1_data.HDBSNAP-2026-03-18-002003  →  SID = IEP  (HANA data LUN)
          IEP_1_log.HDBSNAP-2026-03-18-002003   →  SID = IEP  (HANA log LUN)
    - Oracle databases: LUN names start with ``vg<SID>``; suffix is a plain
      timestamp with no ``HDBSNAP`` token.
      Examples (after pod-prefix strip):
          vgIQP_1.2026-03-19-124002              →  SID = IQP  (Oracle LUN)
    Volume prefix filtering (``HANA_`` / ``ORA_``) is NOT applied to Pure.

ONTAP
    Only snapshots on volumes whose names start with ``HANA_`` or ``ORA_``
    (see ``_ONTAP_INCLUDE_VOLUME_PREFIXES``) are collected; all other volumes
    are ignored.  The ``HANA_``/``ORA_`` prefix tokens are skipped during SID
    extraction so that the real SID is obtained correctly.

Pod prefix stripping (Pure FlashArray)
---------------------------------------
Pod-local volumes are reported with the pod name prepended using the
``pod-name::volume-name`` format, e.g. ``pod-x86-0102::IEP_1_data``.
``_strip_pod_prefix`` removes this prefix before filter matching and SID
extraction while the original full name is preserved for storage and API calls.

SID extraction
--------------
SIDs are 3–5 uppercase alphanumeric characters embedded at the start of a
snapshot or volume name (after any pod prefix is stripped) before the first
underscore or dot.

Examples (FlashArray, pod prefix already stripped)
    IEP_1_data.HDBSNAP-2026-03-18-002003  →  SID = IEP
    IEP_1_log.HDBSNAP-2026-03-18-002003   →  SID = IEP
    vgIQP_1.2026-03-19-124002             →  SID = IQP
    ACP_1_data_hpa2012.HDBSNAP-2026-03-18-024722  →  SID = ACP

Examples (ONTAP, app-type prefix skipped by extract_sid)
    HANA_ABP_data  →  SID = ABP
    ORA_WQ4        →  SID = WQ4

TTL extraction
--------------
The expiration timestamp is embedded in the snapshot suffix.

Examples
    HDBSNAP-2026-03-18-024722  →  TTL = 2026-03-18 02:47:22
    2026-03-19-124002          →  TTL = 2026-03-19 12:40:02
    vgAQP_1.2026-03-19-123749  →  TTL = 2026-03-19 12:37:49

Multi-LUN aggregation
---------------------
A single logical database snapshot spans multiple LUNs (e.g. ``_data`` and
``_log`` for HANA).  All LUNs sharing the same SID and creation-time minute
are merged into one ``SnapshotRecord`` by ``_group_by_sid_and_time``.  Each
LUN snapshot name is listed individually in ``storage_locations``.

ActiveCluster / cluster-pair deduplication
-------------------------------------------
Pure ActiveCluster pairs (e.g. fa01/fa02) both report identical snapshots.
``_group_by_sid_and_time`` deduplicates by ``(sid, snapshot_name, ttl, array)``
so that the same snapshot name from the same array is never counted twice.
Both arrays are recorded in ``storage_locations`` so that the detail view shows
all systems on which the snapshot resides; the list view shows only one entry
per SID + creation-time.
"""
import json
import logging
import os
import re
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# How often (seconds) the collector runs.  Override via env var.
SNAP_COLLECT_INTERVAL_SECONDS = int(
    os.getenv('SNAP_COLLECT_INTERVAL_SECONDS', str(15 * 60))  # 15 minutes
)

# Thread-pool size for parallel system queries.
_MAX_SNAP_WORKERS = 32

# Minimum thread-pool size (used when few systems are registered).
_MIN_SNAP_WORKERS = 16

# ONTAP snapshot prefixes to ignore (automatic/scheduled snapshots).
_ONTAP_IGNORE_PREFIXES = ('daily.', 'weekly.', 'monthly.', 'hourly.', '12-hourly.')

# Allow-list of ONTAP volume name prefixes that qualify for snapshot collection.
# Only snapshots on volumes whose names start with one of these prefixes represent
# application database backups (SAP HANA, Oracle) and belong in the dashboard.
# Every other volume – NFS root/infrastructure volumes, Kubernetes/Trident PVCs
# (trident_pvc_*, old_trident_pvc_*, …), monitoring volumes, etc. – is excluded.
_ONTAP_INCLUDE_VOLUME_PREFIXES = ('HANA_', 'ORA_')

# Known application-type prefix tokens that appear before the actual SID in some
# volume and snapshot naming conventions:
#   HANA_ABP        → app prefix HANA, SID ABP
#   ORA_WQ4         → app prefix ORA,  SID WQ4
#   HANA_ABP_data   → app prefix HANA, SID ABP (info after second underscore ignored)
# These tokens are NOT SAP/Oracle SIDs themselves; the real SID follows the first
# underscore.  They must match _ONTAP_INCLUDE_VOLUME_PREFIXES (without trailing _).
_SID_APP_PREFIXES = frozenset(('HANA', 'ORA'))

# Regex to extract a 3–5 character SID from the beginning of a snapshot or volume
# name.  Handles "ACP_…", "vgACP_…", and bare-SID strings ("WQ4" at end of input).
# The `$` alternative allows matching a SID that is not followed by `_` or `.`
# (e.g. when matching the remainder after stripping an app-type prefix).
_SID_RE = re.compile(r'(?:vg)?([A-Z0-9]{3,5})(?:_|\.|$)', re.IGNORECASE)

# Regex to extract timestamp from snapshot name (YYYY-MM-DD-HHMMSS).
_TS_RE = re.compile(r'(\d{4}-\d{2}-\d{2}-\d{6})')

# Module-level singleton guard
_background_thread_started = False
_thread_lock = threading.Lock()
_collect_event = threading.Event()


# ---------------------------------------------------------------------------
# Snapshot name helpers
# ---------------------------------------------------------------------------

def extract_sid(name: str) -> str | None:
    """Extract a 3–5 character SID from a snapshot or volume name.

    Returns the SID string (upper-cased) or None if not found.

    Naming conventions handled:

    * ``ACP_1_data.HDBSNAP-…``   → SID ``ACP``  (plain SID prefix)
    * ``vgAQP_1.2026-…``         → SID ``AQP``  (vg-prefixed LVM volume)
    * ``HANA_ABP``               → SID ``ABP``  (app prefix HANA skipped)
    * ``HANA_ABP_data``          → SID ``ABP``  (app prefix HANA skipped)
    * ``ORA_WQ4``                → SID ``WQ4``  (app prefix ORA skipped)
    * ``ORA_WQ4_archivelog``     → SID ``WQ4``  (app prefix ORA skipped)

    If the first matched token is a known application-type prefix (see
    ``_SID_APP_PREFIXES``), the function skips it and extracts the SID from
    the remainder of the string.
    """
    m = _SID_RE.match(name.strip())
    if not m:
        return None
    candidate = m.group(1).upper()
    if candidate in _SID_APP_PREFIXES:
        # Skip the app-type prefix and extract the actual SID from the rest.
        rest = name[m.end():]
        m2 = _SID_RE.match(rest)
        return m2.group(1).upper() if m2 else None
    return candidate


def extract_ttl(name: str) -> datetime | None:
    """Extract the expiration timestamp embedded in a snapshot name.

    Recognises the pattern YYYY-MM-DD-HHMMSS anywhere in the string.
    Returns a naive UTC datetime or None if not found / not parseable.
    """
    m = _TS_RE.search(name)
    if not m:
        return None
    ts_str = m.group(1)  # e.g. "2026-03-18-024722"
    try:
        return datetime.strptime(ts_str, '%Y-%m-%d-%H%M%S')
    except ValueError:
        return None


def _strip_pod_prefix(name: str) -> str:
    """Strip a Pure Storage pod prefix from a volume or snapshot name.

    Pod-local volumes are reported with the pod name prepended using the
    ``pod-name::volume-name`` format, e.g. ``pod-x86-0102::IEP_1_data`` or
    ``pod-x86-0102::IEP_1_data.HDBSNAP-2026-03-18-002003``.

    Stripping the prefix exposes the bare volume/snapshot name so that
    SID extraction and filter matching work correctly.  The original full
    name (with pod prefix) is kept in the result dict for API calls and
    display purposes.

    Returns the unchanged string if no ``::`` separator is present.
    """
    if '::' in name:
        return name.split('::', 1)[1]
    return name


# ---------------------------------------------------------------------------
# Per-system collectors (called in worker threads)
# ---------------------------------------------------------------------------

def _collect_flasharray_snapshots(system):
    """Query Pure FlashArray volume-snapshots and return a list of normalised dicts.

    Each dict has keys: sid, snapshot_name, creation_time, ttl, array_name.

    ActiveCluster arrays report the same snapshots on both controllers.
    Both arrays are recorded in the result so that ``_group_by_sid_and_time``
    can show all systems in the detail view while keeping one list entry per
    SID + creation-time.

    Snapshot identification (Pure-specific, NOT ONTAP-style prefix filtering)
    --------------------------------------------------------------------------
    - HANA:   suffix contains ``HDBSNAP``; volumes end in ``_data`` / ``_log``
    - Oracle: LUN name starts with ``vg<SID>``; suffix is a plain timestamp

    Pod prefix stripping
    --------------------
    Pod-local volumes carry a ``pod-name::`` prefix in both ``name`` and
    ``source.name``.  This prefix is stripped before filter matching and SID
    extraction; the original full name is stored in the result for API calls.

    Pure Storage API response fields used here (api/pure_swagger.json):
        name        – full snapshot name, e.g. ``pod-x86-0102::IEP_1_data.HDBSNAP-2026-03-18-002003``
        created     – ISO-8601 UTC string (epoch_ms already converted by the client)
        suffix      – snapshot suffix only, e.g. ``HDBSNAP-2026-03-18-002003``
                      Primary source for TTL extraction.
        source_name – parent volume name, e.g. ``pod-x86-0102::IEP_1_data``
                      Used as SID-extraction fallback when the snapshot name
                      does not directly expose the SID.
    """
    from app.api import get_client

    try:
        client = get_client(
            vendor=system.vendor,
            ip_address=system.ip_address,
            port=system.port,
            username=system.api_username,
            password=system.api_password,
            token=system.api_token,
        )
        raw = client.get_volume_snapshots()
        if not raw:
            return []

        results = []
        for snap in raw:
            name = snap.get('name', '') or ''
            suffix = snap.get('suffix', '') or ''
            source_name = snap.get('source_name', '') or ''

            # Strip pod prefix (e.g. "pod-x86-0102::") so that filter matching
            # and SID extraction work on the bare volume/snapshot name.
            # The original ``name`` is kept intact for storage and API calls.
            name_local = _strip_pod_prefix(name)
            source_local = _strip_pod_prefix(source_name)

            # Skip non-database snapshots (Pure-specific identification):
            # – HANA: suffix / name contains "HDBSNAP"
            # – Oracle: bare name starts with "vg<SID>_…" (matches _SID_RE)
            # Volume prefix filtering (HANA_ / ORA_) is ONTAP-only and must
            # NOT be applied here.
            hdbsnap_present = 'HDBSNAP' in suffix.upper() or 'HDBSNAP' in name.upper()
            if not hdbsnap_present and not _SID_RE.match(name_local):
                continue

            # Extract SID from the pod-stripped snapshot name first, then fall
            # back to the pod-stripped source volume name
            # (e.g. "IEP_1_data" → SID "IEP", "vgIQP_1" → SID "IQP").
            sid = extract_sid(name_local)
            if not sid and source_local:
                sid = extract_sid(source_local)
            if not sid:
                continue

            # creation_time: 'created' is already an ISO-8601 string (converted
            # from epoch_ms by PureStorageClient.get_volume_snapshots).
            created_raw = snap.get('created') or ''
            creation_time: datetime | None = None
            if isinstance(created_raw, str) and created_raw:
                for fmt in ('%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S'):
                    try:
                        dt = datetime.strptime(created_raw.replace('Z', '+00:00'), fmt)
                        if dt.tzinfo is not None:
                            dt = dt.astimezone(timezone.utc)
                        creation_time = dt.replace(tzinfo=None)
                        break
                    except ValueError:
                        pass

            # TTL: prefer the suffix field (direct, unambiguous TTL source),
            # fall back to the full snapshot name.
            ttl = extract_ttl(suffix) if suffix else None
            if ttl is None:
                ttl = extract_ttl(name)

            results.append({
                'sid': sid,
                'snapshot_name': name,
                'creation_time': creation_time,
                'ttl': ttl,
                'array_name': system.name,
            })

        return results

    except Exception as exc:
        logger.warning("FlashArray snapshot query failed for %s: %s", system.name, exc)
        return []


def _collect_ontap_snapshots(system):
    """Query ONTAP volume snapshots and return a list of normalised dicts.

    Each dict has keys: sid, snapshot_name, creation_time, ttl,
    cluster_name, svm_name, volume_name.

    Automatic/scheduled snapshots (daily.*, weekly.*, etc.) are ignored.

    Only snapshots on volumes whose names start with a prefix listed in
    ``_ONTAP_INCLUDE_VOLUME_PREFIXES`` (``HANA_``, ``ORA_``) are collected.
    All other volumes – NFS root/infrastructure volumes, Kubernetes Trident
    PVCs (``trident_pvc_*``), renamed PVCs (``old_trident_pvc_*``), monitoring
    volumes, etc. – are excluded because they are not application database
    backups.
    """
    from app.api import get_client

    try:
        client = get_client(
            vendor=system.vendor,
            ip_address=system.ip_address,
            port=system.port,
            username=system.api_username,
            password=system.api_password,
            token=system.api_token,
        )
        raw = client.get_volume_snapshots()
        if not raw:
            return []

        results = []
        for snap in raw:
            snap_name = snap.get('name', '') or ''
            volume_name = snap.get('volume', '') or snap.get('volume_name', '') or ''

            # Allow-list: only process volumes with a known application prefix.
            # This excludes NFS root/infrastructure volumes, Kubernetes/Trident
            # PVCs (trident_pvc_*, old_trident_pvc_*, …) and any other volume
            # that is not a HANA or Oracle database volume.
            if not any(volume_name.upper().startswith(p.upper())
                       for p in _ONTAP_INCLUDE_VOLUME_PREFIXES):
                continue

            # Ignore automatic snapshots
            if any(snap_name.lower().startswith(p) for p in _ONTAP_IGNORE_PREFIXES):
                continue

            sid = extract_sid(snap_name)
            if not sid:
                # Also try extracting SID from the volume name
                sid = extract_sid(volume_name) if volume_name else None
            if not sid:
                continue

            created_raw = snap.get('create_time') or snap.get('creation_time') or ''
            creation_time: datetime | None = None
            if created_raw:
                for fmt in ('%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S'):
                    try:
                        dt = datetime.strptime(created_raw.replace('Z', '+00:00'), fmt)
                        if dt.tzinfo is not None:
                            dt = dt.astimezone(timezone.utc)
                        creation_time = dt.replace(tzinfo=None)
                        break
                    except ValueError:
                        pass

            ttl = extract_ttl(snap_name)

            results.append({
                'sid': sid,
                'snapshot_name': snap_name,
                'creation_time': creation_time,
                'ttl': ttl,
                'cluster_name': snap.get('cluster') or system.name,
                'svm_name': snap.get('svm') or snap.get('svm_name') or '',
                'volume_name': volume_name,
            })

        return results

    except Exception as exc:
        logger.warning("ONTAP snapshot query failed for %s: %s", system.name, exc)
        return []


def _collect_system_snapshots(system):
    """Dispatch snapshot collection to the appropriate vendor collector.

    Returns a dict with keys:
        system_id, system_name, vendor, flasharray_snaps, ontap_snaps
    """
    vendor = (system.vendor or '').lower()
    flasharray_snaps = []
    ontap_snaps = []

    if vendor == 'pure':
        flasharray_snaps = _collect_flasharray_snapshots(system)
    elif vendor in ('netapp-ontap', 'netapp_ontap', 'ontap'):
        ontap_snaps = _collect_ontap_snapshots(system)

    return {
        'system_id': system.id,
        'system_name': system.name,
        'vendor': vendor,
        'flasharray_snaps': flasharray_snaps,
        'ontap_snaps': ontap_snaps,
    }


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------

def _group_by_sid_and_time(all_fa_snaps, all_ontap_snaps):
    """Group collected snapshots into logical snapshot records.

    FlashArray snapshots are keyed by (sid, creation_time_minute) – multiple
    LUN snapshots sharing the same SID and timestamp belong to one logical
    snapshot (e.g. HANA ``_data`` + ``_log`` LUNs, or multiple Oracle LUNs).

    Multi-LUN aggregation
    ---------------------
    All snapshot names for the same SID + creation-minute are accumulated in
    ``storage_locations`` under their respective array name.  The list view
    therefore shows one entry per database snapshot regardless of how many
    LUNs were snapped; the detail view lists every individual LUN name.

    ActiveCluster / cluster-pair deduplication
    -------------------------------------------
    Both arrays in an ActiveCluster pair (e.g. fa01/fa02) report the same
    snapshots.  The dedup key ``(sid, snap_name, ttl, array_name)`` ensures
    the same snapshot from the same array is never counted twice, while still
    allowing both fa01 and fa02 to appear in ``storage_locations`` so the
    detail view shows all systems that hold the snapshot.

    Returns a list of dicts suitable for upsert into snapshot_records.
    """
    # Key: (sid, creation_minute_str)  Value: aggregated record dict
    records: dict[tuple, dict] = {}

    # Deduplicate: same snapshot name from the same array must not be added
    # twice (guards against API pagination artifacts or dual collection runs).
    # Using array_name in the key intentionally allows the same snapshot name
    # reported by a different array (ActiveCluster partner) to be recorded,
    # so that the detail view can show all arrays holding the snapshot.
    seen_fa: set[tuple] = set()

    for snap in all_fa_snaps:
        sid = snap['sid']
        ts: datetime | None = snap.get('creation_time')
        snap_name = snap.get('snapshot_name', '')
        ttl = snap.get('ttl')
        arr = snap.get('array_name', '')

        # Dedup key includes array_name so the same snap from a partner array
        # (ActiveCluster) is still processed and added to that array's entry.
        ttl_str = ttl.strftime('%Y-%m-%d-%H%M%S') if ttl else ''
        dedup_key = (sid, snap_name, ttl_str, arr)
        if dedup_key in seen_fa:
            continue
        seen_fa.add(dedup_key)

        # Use TTL as creation key if creation_time is missing (common for FlashArray)
        effective_time = ts or ttl
        if not effective_time:
            continue

        # Normalise to minute-level to group LUN snapshots of the same DB snap
        time_key = effective_time.replace(second=0, microsecond=0)
        record_key = (sid, time_key)

        if record_key not in records:
            records[record_key] = {
                'sid': sid,
                'creation_time': effective_time,
                'ttl': ttl,
                'flasharray_present': True,
                'ontap_present': False,
                'fa_systems': {},   # array_name → [snapshot_names]
                'ontap_clusters': {},
            }
        rec = records[record_key]
        rec['flasharray_present'] = True
        # Accumulate LUN snapshot names per array (arr already extracted above)
        if arr:
            rec['fa_systems'].setdefault(arr, [])
            if snap_name not in rec['fa_systems'][arr]:
                rec['fa_systems'][arr].append(snap_name)
        # Keep earliest creation_time and latest TTL per group
        if ts and ts < rec['creation_time']:
            rec['creation_time'] = ts
        if ttl and (rec['ttl'] is None or ttl > rec['ttl']):
            rec['ttl'] = ttl

    # Build a secondary index: (sid, ttl_minute) → record_key so that ONTAP
    # snaps can be matched to FA records by TTL even when the FA record was
    # keyed by creation_time (Oracle case: TTL is the expiry date, days after
    # the snapshot was taken, so ttl_minute ≠ creation_time_minute).
    ttl_index: dict[tuple, tuple] = {}
    for rec_key, rec in records.items():
        rec_ttl = rec.get('ttl')
        if rec_ttl:
            ttl_min = rec_ttl.replace(second=0, microsecond=0)
            idx_key = (rec['sid'], ttl_min)
            if idx_key not in ttl_index:
                ttl_index[idx_key] = rec_key

    # Match ONTAP snapshots to existing FA records (or create standalone ones)
    for snap in all_ontap_snaps:
        sid = snap['sid']
        ts: datetime | None = snap.get('creation_time')
        ttl = snap.get('ttl')

        # Try to match by TTL timestamp (primary link between FA and ONTAP snaps).
        # FA records are keyed by (sid, creation_time_minute).  For HANA snaps,
        # TTL ≈ creation_time (same minute), so a direct key lookup works.
        # For Oracle snaps, TTL is the expiry date (days later), so the direct
        # lookup fails – fall back to the secondary TTL index built above.
        matched = False
        matched_key = None
        if ttl:
            ttl_minute = ttl.replace(second=0, microsecond=0)
            ttl_key = (sid, ttl_minute)
            if ttl_key in records:
                matched_key = ttl_key
                matched = True
            elif ttl_key in ttl_index:
                matched_key = ttl_index[ttl_key]
                matched = True

        if matched and matched_key is not None:
            records[matched_key]['ontap_present'] = True
            cluster = snap.get('cluster_name', '')
            svm = snap.get('svm_name', '')
            vol = snap.get('volume_name', '')
            snap_name = snap.get('snapshot_name', '')
            cluster_key = cluster
            records[matched_key]['ontap_clusters'].setdefault(
                cluster_key, {'cluster': cluster, 'svm': svm, 'volumes': []}
            )
            entry = {'volume': vol, 'snap': snap_name}
            if vol and entry not in records[matched_key]['ontap_clusters'][cluster_key]['volumes']:
                records[matched_key]['ontap_clusters'][cluster_key]['volumes'].append(entry)

        if not matched:
            # Standalone ONTAP snapshot (no matching FA snap)
            effective_time = ts or ttl
            if not effective_time:
                continue
            time_key = effective_time.replace(second=0, microsecond=0)
            record_key = (sid, time_key)
            if record_key not in records:
                records[record_key] = {
                    'sid': sid,
                    'creation_time': effective_time,
                    'ttl': ttl,
                    'flasharray_present': False,
                    'ontap_present': True,
                    'fa_systems': {},
                    'ontap_clusters': {},
                }
            rec = records[record_key]
            rec['ontap_present'] = True
            cluster = snap.get('cluster_name', '')
            svm = snap.get('svm_name', '')
            vol = snap.get('volume_name', '')
            snap_name = snap.get('snapshot_name', '')
            rec['ontap_clusters'].setdefault(
                cluster, {'cluster': cluster, 'svm': svm, 'volumes': []}
            )
            entry = {'volume': vol, 'snap': snap_name}
            if vol and entry not in rec['ontap_clusters'][cluster]['volumes']:
                rec['ontap_clusters'][cluster]['volumes'].append(entry)

    # Flatten to list and build storage_locations JSON
    result = []
    for rec in records.values():
        fa_list = [
            {'name': arr, 'snapshot_names': names}
            for arr, names in rec['fa_systems'].items()
        ]
        ontap_list = list(rec['ontap_clusters'].values())
        storage_locations = {'flasharray_systems': fa_list, 'ontap_clusters': ontap_list}

        result.append({
            'sid': rec['sid'],
            'creation_time': rec['creation_time'],
            'ttl': rec['ttl'],
            'flasharray_present': rec['flasharray_present'],
            'ontap_present': rec['ontap_present'],
            'storage_locations': json.dumps(storage_locations),
        })

    return result


# ---------------------------------------------------------------------------
# Database upsert
# ---------------------------------------------------------------------------

def _upsert_snapshot_records(app, aggregated, systems_queried):
    """Persist aggregated snapshot records to PostgreSQL and reconcile stale entries.

    Reconciliation logic
    --------------------
    Every record updated during this run has its ``last_seen`` timestamp set to
    ``run_start``.  After all upserts are complete, any record whose
    ``last_seen`` is *older* than ``run_start`` was NOT seen in this collection
    cycle, which means the snapshot was deleted or renamed on the storage
    system since the previous run.

    Stale records are removed from the database with one exception: records
    that carry a user comment are set to ``flasharray_present=False`` /
    ``ontap_present=False`` instead of being deleted so that the operator's
    annotation is preserved until they explicitly delete the row.

    Fields controlled by the user (comment, delete_marked, delete_deadline)
    are never overwritten by the collector.
    """
    from app import db
    from app.models import SnapshotRecord, SnapshotCollectorMetadata, SnapshotAuditLog

    with app.app_context():
        run_start = datetime.utcnow()
        stored = 0
        try:
            for rec_data in aggregated:
                sid = rec_data['sid']
                ct: datetime = rec_data['creation_time']
                # Normalise to second-level precision for DB storage
                ct = ct.replace(microsecond=0)

                existing = SnapshotRecord.query.filter_by(sid=sid, creation_time=ct).first()
                if existing:
                    # Update collector-owned fields only
                    existing.flasharray_present = rec_data['flasharray_present']
                    existing.ontap_present = rec_data['ontap_present']
                    existing.storage_locations = rec_data['storage_locations']
                    existing.last_seen = run_start
                    # Only update TTL if not already user-modified (no audit log entries mean it's still original)
                    if rec_data.get('ttl') and not SnapshotAuditLog.query.filter_by(snapshot_id=existing.id).first():
                        existing.ttl = rec_data['ttl']
                else:
                    new_rec = SnapshotRecord(
                        sid=sid,
                        creation_time=ct,
                        ttl=rec_data.get('ttl'),
                        flasharray_present=rec_data['flasharray_present'],
                        ontap_present=rec_data['ontap_present'],
                        storage_locations=rec_data['storage_locations'],
                        last_seen=run_start,
                    )
                    db.session.add(new_rec)
                    stored += 1

            # ------------------------------------------------------------------
            # Reconciliation: remove (or mark absent) records that were not seen
            # in this collection cycle.
            # ------------------------------------------------------------------
            stale = SnapshotRecord.query.filter(
                SnapshotRecord.last_seen < run_start,
            ).all()
            removed = 0
            marked_absent = 0
            for rec in stale:
                if rec.comment:
                    # Preserve operator annotations – just clear presence flags
                    rec.flasharray_present = False
                    rec.ontap_present = False
                    rec.storage_locations = None
                    rec.last_seen = run_start  # reset so it isn't stale next run
                    marked_absent += 1
                else:
                    # Keep the run resilient: a single delete failure (e.g. legacy
                    # FK constraints in older DB schemas) must not roll back the
                    # whole collection run.
                    try:
                        with db.session.begin_nested():
                            db.session.delete(rec)
                            db.session.flush()
                        removed += 1
                    except Exception as delete_exc:
                        logger.warning(
                            "Snapshot collector: could not delete stale record %s "
                            "(sid=%s), marking absent instead: %s",
                            rec.id, rec.sid, delete_exc,
                        )
                        rec.flasharray_present = False
                        rec.ontap_present = False
                        rec.storage_locations = None
                        rec.last_seen = run_start
                        marked_absent += 1

            if removed or marked_absent:
                logger.info(
                    "Snapshot collector: reconciliation removed %d stale records, "
                    "marked %d absent (had comments)",
                    removed, marked_absent,
                )

            # Write collector run metadata
            meta = SnapshotCollectorMetadata(
                run_at=run_start,
                duration_seconds=(datetime.utcnow() - run_start).total_seconds(),
                systems_queried=systems_queried,
                snapshots_stored=stored,
                status='success',
            )
            db.session.add(meta)
            db.session.commit()
            logger.info(
                "Snapshot collector: stored %d new records (%d systems queried)",
                stored, systems_queried,
            )
        except Exception as exc:
            db.session.rollback()
            # Write error metadata
            try:
                meta = SnapshotCollectorMetadata(
                    run_at=run_start,
                    duration_seconds=(datetime.utcnow() - run_start).total_seconds(),
                    systems_queried=systems_queried,
                    snapshots_stored=0,
                    status='error',
                    error_message=str(exc),
                )
                db.session.add(meta)
                db.session.commit()
            except Exception:
                pass
            logger.error("Snapshot collector DB upsert failed: %s", exc)
            logger.debug(traceback.format_exc())


# ---------------------------------------------------------------------------
# Delete worker – executes expired deletions
# ---------------------------------------------------------------------------

def _process_expired_deletions(app):
    """Delete snapshot records whose delete_deadline has passed.

    This function is called after each collection run.  Actual storage-system
    snapshot deletion is intentionally omitted (simulation mode per spec) –
    only the database record is removed.
    """
    from app import db
    from app.models import SnapshotRecord

    with app.app_context():
        try:
            now = datetime.utcnow()
            expired = SnapshotRecord.query.filter(
                SnapshotRecord.delete_marked,
                SnapshotRecord.delete_deadline <= now,
            ).all()
            if expired:
                for rec in expired:
                    logger.info(
                        "Snapshot collector: deleting expired record %s sid=%s ct=%s",
                        rec.id, rec.sid, rec.creation_time,
                    )
                    db.session.delete(rec)
                db.session.commit()
                logger.info("Snapshot collector: deleted %d expired snapshot records", len(expired))
        except Exception as exc:
            db.session.rollback()
            logger.error("Snapshot collector delete worker error: %s", exc)


# ---------------------------------------------------------------------------
# Main collection pipeline
# ---------------------------------------------------------------------------

def _do_collect(app):
    """Run one full snapshot collection cycle."""
    from app.models import StorageSystem

    with app.app_context():
        systems = StorageSystem.query.filter(
            StorageSystem.enabled == True,  # noqa: E712
            or_(StorageSystem.snaps_enabled == True, StorageSystem.snaps_enabled == None),  # noqa: E712,E711
        ).all()

    if not systems:
        logger.info("Snapshot collector: no systems with snap collection enabled found, skipping.")
        return

    # Determine how many workers to use (16 minimum, up to 32)
    num_workers = max(_MIN_SNAP_WORKERS, min(_MAX_SNAP_WORKERS, len(systems)))

    all_fa_snaps: list[dict] = []
    all_ontap_snaps: list[dict] = []
    systems_queried = 0

    with ThreadPoolExecutor(max_workers=num_workers, thread_name_prefix='snap-worker') as pool:
        futures = {pool.submit(_collect_system_snapshots, system): system for system in systems}
        for future in as_completed(futures):
            system = futures[future]
            try:
                result = future.result()
                all_fa_snaps.extend(result['flasharray_snaps'])
                all_ontap_snaps.extend(result['ontap_snaps'])
                systems_queried += 1
            except Exception as exc:
                logger.warning(
                    "Snapshot collector: error collecting from %s: %s",
                    system.name, exc,
                )

    aggregated = _group_by_sid_and_time(all_fa_snaps, all_ontap_snaps)
    _upsert_snapshot_records(app, aggregated, systems_queried)
    _process_expired_deletions(app)


# ---------------------------------------------------------------------------
# Background thread
# ---------------------------------------------------------------------------

def _background_loop(app):
    """Run _do_collect on startup and then every SNAP_COLLECT_INTERVAL_SECONDS."""
    while True:
        try:
            _do_collect(app)
        except Exception as exc:
            logger.error("Snapshot collector background loop error: %s", exc)
            logger.debug(traceback.format_exc())
        _collect_event.wait(timeout=SNAP_COLLECT_INTERVAL_SECONDS)
        _collect_event.clear()


def start_background_refresh(app):
    """Start the snapshot background collector daemon thread (idempotent)."""
    global _background_thread_started
    with _thread_lock:
        if not _background_thread_started:
            thread = threading.Thread(
                target=_background_loop,
                args=(app,),
                daemon=True,
                name='snap-collector',
            )
            thread.start()
            _background_thread_started = True
            logger.info(
                "Snapshot background collector started (interval=%ds, workers=%d–%d)",
                SNAP_COLLECT_INTERVAL_SECONDS, _MIN_SNAP_WORKERS, _MAX_SNAP_WORKERS,
            )


def trigger_refresh(app):
    """Trigger an immediate snapshot collection outside the normal schedule."""
    if _background_thread_started:
        _collect_event.set()
    else:
        t = threading.Thread(
            target=_do_collect,
            args=(app,),
            daemon=True,
            name='snap-collector-manual',
        )
        t.start()
