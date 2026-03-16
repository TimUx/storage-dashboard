"""Snapshot collection service – background collector for Pure FlashArray and ONTAP snapshots.

Architecture mirrors ``capacity_service`` and ``dr_service``:
- A single daemon thread runs ``_background_loop`` and calls ``_do_collect``
  once on startup, then sleeps for SNAP_COLLECT_INTERVAL_SECONDS (15 min).
- Each storage system is queried in a separate worker thread using a
  ThreadPoolExecutor with 16–32 workers.
- Collected snapshot data is normalised, deduplicated, grouped by SID and
  stored in PostgreSQL (snapshot_records table).

SID extraction
--------------
SIDs are 3–5 uppercase alphanumeric characters embedded at the start of a
snapshot name before the first underscore or dot.

Examples
    ACP_1_data_hpa2012.HDBSNAP-2026-03-18-024722  →  SID = ACP
    vgAQP_1.2026-03-19-123749                       →  SID = AQP

TTL extraction
--------------
The expiration timestamp is embedded in the snapshot suffix.

Examples
    ...HDBSNAP-2026-03-18-024722  →  TTL = 2026-03-18 02:47:22
    vgAQP_1.2026-03-19-123749      →  TTL = 2026-03-19 12:37:49
"""
import json
import logging
import os
import re
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

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

# Regex to extract a 3–5 character SID from the beginning of a snapshot name.
# Handles both "ACP_..." and "vgACP_..." style names.
_SID_RE = re.compile(r'(?:vg)?([A-Z0-9]{3,5})(?:_|\.)', re.IGNORECASE)

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
    """
    m = _SID_RE.match(name.strip())
    if m:
        return m.group(1).upper()
    return None


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


# ---------------------------------------------------------------------------
# Per-system collectors (called in worker threads)
# ---------------------------------------------------------------------------

def _collect_flasharray_snapshots(system):
    """Query Pure FlashArray volume-snapshots and return a list of normalised dicts.

    Each dict has keys: sid, snapshot_name, creation_time, ttl, array_name.

    ActiveCluster arrays report the same snapshots on both controllers.
    Deduplication is handled downstream (keyed on sid + creation_time +
    snapshot_name).
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
            # Skip empty or non-database snapshot names
            if 'HDBSNAP' not in name.upper() and not _SID_RE.match(name):
                continue

            sid = extract_sid(name)
            if not sid:
                continue

            # creation_time: prefer 'created' field; parse ISO string
            created_raw = snap.get('created') or snap.get('creation_time') or ''
            creation_time: datetime | None = None
            if created_raw:
                for fmt in ('%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S'):
                    try:
                        creation_time = datetime.strptime(
                            created_raw.replace('Z', '+00:00'), fmt
                        ).replace(tzinfo=None)
                        break
                    except ValueError:
                        pass

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
            # Ignore automatic snapshots
            if any(snap_name.lower().startswith(p) for p in _ONTAP_IGNORE_PREFIXES):
                continue

            sid = extract_sid(snap_name)
            if not sid:
                # Also try extracting SID from the volume name
                volume_name = snap.get('volume', '') or ''
                sid = extract_sid(volume_name) if volume_name else None
            if not sid:
                continue

            created_raw = snap.get('create_time') or snap.get('creation_time') or ''
            creation_time: datetime | None = None
            if created_raw:
                for fmt in ('%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S'):
                    try:
                        creation_time = datetime.strptime(
                            created_raw.replace('Z', '+00:00'), fmt
                        ).replace(tzinfo=None)
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
                'volume_name': snap.get('volume') or snap.get('volume_name') or '',
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
    snapshot.  ActiveCluster duplicates are removed by tracking unique
    (sid, ttl_str, snapshot_name) tuples.

    Returns a list of dicts suitable for upsert into snapshot_records.
    """
    # Key: (sid, creation_minute_str)  Value: aggregated record dict
    records: dict[tuple, dict] = {}

    # Deduplicate FlashArray snaps across ActiveCluster arrays
    seen_fa: set[tuple] = set()

    for snap in all_fa_snaps:
        sid = snap['sid']
        ts: datetime | None = snap.get('creation_time')
        snap_name = snap.get('snapshot_name', '')
        ttl = snap.get('ttl')

        # Build dedup key using SID + snapshot name + ttl string
        ttl_str = ttl.strftime('%Y-%m-%d-%H%M%S') if ttl else ''
        dedup_key = (sid, snap_name, ttl_str)
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
        # Accumulate LUN snapshot names per array
        arr = snap.get('array_name', '')
        if arr:
            rec['fa_systems'].setdefault(arr, [])
            if snap_name not in rec['fa_systems'][arr]:
                rec['fa_systems'][arr].append(snap_name)
        # Keep earliest creation_time and latest TTL per group
        if ts and ts < rec['creation_time']:
            rec['creation_time'] = ts
        if ttl and (rec['ttl'] is None or ttl > rec['ttl']):
            rec['ttl'] = ttl

    # Match ONTAP snapshots to existing FA records (or create standalone ones)
    for snap in all_ontap_snaps:
        sid = snap['sid']
        ts: datetime | None = snap.get('creation_time')
        ttl = snap.get('ttl')

        # Try to match by TTL timestamp (primary link between FA and ONTAP snaps)
        matched = False
        if ttl:
            ttl_minute = ttl.replace(second=0, microsecond=0)
            record_key = (sid, ttl_minute)
            if record_key in records:
                records[record_key]['ontap_present'] = True
                cluster = snap.get('cluster_name', '')
                svm = snap.get('svm_name', '')
                vol = snap.get('volume_name', '')
                cluster_key = cluster
                records[record_key]['ontap_clusters'].setdefault(
                    cluster_key, {'cluster': cluster, 'svm': svm, 'volumes': []}
                )
                if vol and vol not in records[record_key]['ontap_clusters'][cluster_key]['volumes']:
                    records[record_key]['ontap_clusters'][cluster_key]['volumes'].append(vol)
                matched = True

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
            rec['ontap_clusters'].setdefault(
                cluster, {'cluster': cluster, 'svm': svm, 'volumes': []}
            )
            if vol and vol not in rec['ontap_clusters'][cluster]['volumes']:
                rec['ontap_clusters'][cluster]['volumes'].append(vol)

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
    """Persist aggregated snapshot records to PostgreSQL.

    Uses an upsert pattern: existing records (matched by sid + creation_time)
    are updated for presence flags, TTL and storage_locations.  Fields
    controlled by the user (comment, db_override, nfs_override, delete_marked,
    delete_deadline) are never overwritten by the collector.
    """
    from app import db
    from app.models import SnapshotRecord, SnapshotCollectorMetadata, SnapshotAuditLog

    with app.app_context():
        start = datetime.utcnow()
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
                    existing.last_seen = datetime.utcnow()
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
                        last_seen=datetime.utcnow(),
                    )
                    db.session.add(new_rec)
                    stored += 1

            # Write collector run metadata
            meta = SnapshotCollectorMetadata(
                run_at=datetime.utcnow(),
                duration_seconds=(datetime.utcnow() - start).total_seconds(),
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
                    run_at=datetime.utcnow(),
                    duration_seconds=(datetime.utcnow() - start).total_seconds(),
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
        systems = StorageSystem.query.filter_by(enabled=True).all()

    if not systems:
        logger.info("Snapshot collector: no enabled storage systems found, skipping.")
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
