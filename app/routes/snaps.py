"""Snapshot management routes – /snaps/

Live-execution streaming
------------------------
The *TTL update* endpoint (``/snaps/api/update-ttl``) executes the underlying
storage operations **for real** and streams its progress as newline-delimited
JSON (``application/x-ndjson``) so the front-end can render a step-by-step
status modal with a collapsible "terminal" view.

Deferred deletion
-----------------
The *delete* endpoint (``/snaps/api/delete``) does **not** execute the
delete operation immediately.  Instead it schedules the deletion 24 hours
in the future by setting ``delete_marked=True`` and
``delete_deadline = now + 24h`` on the :class:`SnapshotRecord`.  The
front-end shows a countdown of the remaining hours and exposes a
"↩ Rückgängig" button that calls ``/snaps/api/undo-delete`` to clear the
marker.

The actual storage-level deletion is performed by the background snapshot
collector once the deadline has elapsed (see
``app.snap_service._process_expired_deletions``).  The execution uses the
same plan / streaming machinery as the live TTL update; for scheduled
deletions the events are recorded only in the application log because no
HTTP client is connected at that point.

Stream events (TTL update)
~~~~~~~~~~~~~~~~~~~~~~~~~~
Each line is one JSON object with an ``event`` field.  The following event
types are emitted:

- ``run_start``    – overall run starts; payload: ``title``, ``snap_id``,
                     ``total_steps``.
- ``step_start``   – a new step begins; payload: ``step_id`` (1-based index),
                     ``label``, ``target`` (storage system display name),
                     ``command`` (curl-equivalent description for the
                     terminal view).
- ``step_log``     – additional log output for the current step; payload:
                     ``step_id``, ``message``.
- ``step_done``    – step finished; payload: ``step_id``, ``status``
                     (``ok`` or ``error``), optional ``message``.
- ``run_done``     – overall run finished; payload: ``status``,
                     ``message`` and optional updated ``snapshot`` dict for
                     the front-end to refresh its local state.
"""
import json
import logging
from datetime import datetime, timedelta

from flask import Blueprint, current_app, jsonify, render_template, request
from sqlalchemy import and_, or_

bp = Blueprint('snaps', __name__, url_prefix='/snaps')
logger = logging.getLogger(__name__)

# How far in the future a delete request schedules the actual deletion.
# Operators can cancel the deletion at any time during this window.
_DELETE_DELAY_HOURS = 24


# ---------------------------------------------------------------------------
# UI route
# ---------------------------------------------------------------------------

@bp.route('/')
@bp.route('')
def index():
    """Snapshot management page."""
    return render_template('snaps.html')


# ---------------------------------------------------------------------------
# API – list snapshots
# ---------------------------------------------------------------------------

@bp.route('/api/list')
def api_list():
    """Return all snapshot records with statistics.

    Query parameters (all optional):
        sid          – filter by exact SID (case-insensitive)
        ttl_before   – ISO-8601 date; only return snapshots with TTL before this date
        ttl_after    – ISO-8601 date; only return snapshots with TTL after this date
        created_before – ISO-8601 date filter on creation_time
        created_after  – ISO-8601 date filter on creation_time
    """
    from app.models import SnapshotCollectorMetadata, SnapshotRecord

    sid_filter = request.args.get('sid', '').strip().upper()

    query = SnapshotRecord.query.filter(
        or_(
            SnapshotRecord.flasharray_present.is_(True),
            SnapshotRecord.ontap_present.is_(True),
            SnapshotRecord.delete_marked.is_(True),
            and_(
                SnapshotRecord.comment.isnot(None),
                SnapshotRecord.comment != '',
            ),
        )
    )

    if sid_filter:
        query = query.filter(SnapshotRecord.sid == sid_filter)

    ttl_before = _parse_dt(request.args.get('ttl_before', ''))
    ttl_after = _parse_dt(request.args.get('ttl_after', ''))
    created_before = _parse_dt(request.args.get('created_before', ''))
    created_after = _parse_dt(request.args.get('created_after', ''))

    if ttl_before:
        query = query.filter(SnapshotRecord.ttl <= ttl_before)
    if ttl_after:
        query = query.filter(SnapshotRecord.ttl >= ttl_after)
    if created_before:
        query = query.filter(SnapshotRecord.creation_time <= created_before)
    if created_after:
        query = query.filter(SnapshotRecord.creation_time >= created_after)

    records = query.order_by(
        SnapshotRecord.sid.asc(),
        SnapshotRecord.creation_time.desc(),
    ).all()

    now = datetime.utcnow()
    total = len(records)
    older_5 = sum(1 for r in records if r.creation_time and (now - r.creation_time).days >= 5)
    older_10 = sum(1 for r in records if r.creation_time and (now - r.creation_time).days >= 10)

    last_run = SnapshotCollectorMetadata.query.order_by(
        SnapshotCollectorMetadata.run_at.desc()
    ).first()

    return jsonify({
        'snapshots': [r.to_dict() for r in records],
        'stats': {
            'total': total,
            'older_5_days': older_5,
            'older_10_days': older_10,
            'last_update': (last_run.run_at.isoformat() + 'Z') if last_run else None,
            'last_update_status': last_run.status if last_run else None,
        },
    })


# ---------------------------------------------------------------------------
# Live execution – update TTL (rename snapshot)
# ---------------------------------------------------------------------------

@bp.route('/api/update-ttl', methods=['POST'])
def api_update_ttl():
    """Execute a TTL change live and stream the per-step progress.

    Request JSON:
        id       (int)  – snapshot record ID
        new_ttl  (str)  – new TTL in ISO-8601 or DD.MM.YYYY HH:MM:SS format
        user     (str)  – operator name (optional)

    Response: streamed ``application/x-ndjson`` progress events (see module
    docstring for the event schema).  HTTP errors before streaming begins
    are returned as a plain JSON error body with the appropriate status.
    """
    from app.models import SnapshotRecord

    data = request.get_json(force=True) or {}
    snap_id = data.get('id')
    new_ttl_str = data.get('new_ttl', '')
    user = data.get('user', request.remote_addr or 'unknown')

    if not snap_id:
        return jsonify({'error': 'id required'}), 400

    rec = SnapshotRecord.query.get(snap_id)
    if not rec:
        return jsonify({'error': 'Snapshot not found'}), 404

    new_ttl = _parse_dt(new_ttl_str)
    if not new_ttl:
        return jsonify({'error': f'Cannot parse new_ttl: {new_ttl_str!r}'}), 400

    locs = rec.get_storage_locations()
    plan = _build_update_ttl_plan(rec, locs, new_ttl)
    if not plan:
        return jsonify({'error': 'No storage locations to update'}), 400

    app = current_app._get_current_object()

    def generator():
        yield from _stream_run(
            app=app,
            title=f'TTL ändern – SID {rec.sid} ({rec.creation_time:%d.%m.%Y %H:%M:%S})',
            snap_id=rec.id,
            steps=plan,
            on_success=lambda: _persist_ttl_update(app, rec.id, new_ttl, user),
        )

    return current_app.response_class(generator(), mimetype='application/x-ndjson')


# ---------------------------------------------------------------------------
# Schedule deletion (24h delay)
# ---------------------------------------------------------------------------

@bp.route('/api/delete', methods=['POST'])
def api_delete():
    """Schedule the deletion of a snapshot 24 hours in the future.

    The operation is **not** executed immediately on the storage systems.
    Instead the snapshot record is marked with ``delete_marked=True`` and
    ``delete_deadline = now + 24h``.  Within the 24-hour window the
    operator can cancel the deletion via :func:`api_undo_delete`; the
    front-end shows a live countdown of the remaining hours.

    Once the deadline has elapsed, the snapshot collector background worker
    (:func:`app.snap_service._process_expired_deletions`) executes the
    actual delete plan against the storage systems.

    Request JSON:
        id (int) – snapshot record ID

    Response JSON:
        success (bool)             – ``True`` if the deletion was scheduled.
        delete_deadline (str)      – ISO-8601 UTC timestamp when the
                                     deletion will be executed.
        delete_planned (bool)      – False if no storage locations would
                                     produce any plan steps.  In that case
                                     the record is removed from the DB
                                     immediately because nothing is left
                                     to delete on a storage system.
    """
    from app import db
    from app.models import SnapshotRecord

    data = request.get_json(force=True) or {}
    snap_id = data.get('id')
    if not snap_id:
        return jsonify({'error': 'id required'}), 400

    rec = SnapshotRecord.query.get(snap_id)
    if not rec:
        return jsonify({'error': 'Snapshot not found'}), 404

    # Determine whether anything would actually be sent to a storage system
    # so the UI can distinguish between scheduled-delete and "stale-only"
    # records (which we drop right away).
    plan = _build_delete_plan(rec, rec.get_storage_locations())
    if not plan:
        db.session.delete(rec)
        db.session.commit()
        return jsonify({
            'success': True,
            'delete_planned': False,
            'message': ('Keine Storage-Operationen nötig – '
                        'Datensatz wurde direkt entfernt.'),
        })

    rec.delete_marked = True
    rec.delete_deadline = datetime.utcnow() + timedelta(hours=_DELETE_DELAY_HOURS)
    db.session.commit()

    return jsonify({
        'success': True,
        'delete_planned': True,
        'delete_deadline': rec.delete_deadline.isoformat(),
        'snapshot': rec.to_dict(),
    })


# ---------------------------------------------------------------------------
# API – cancel pending deletion
# ---------------------------------------------------------------------------

@bp.route('/api/undo-delete', methods=['POST'])
def api_undo_delete():
    """Cancel a pending deletion so the storage delete plan is **not** run.

    Only effective while ``delete_deadline`` is still in the future.  Once
    the worker has started executing the plan, the deletion can no longer
    be cancelled (the worker clears ``delete_marked`` only after a
    successful run).
    """
    from app import db
    from app.models import SnapshotRecord

    data = request.get_json(force=True) or {}
    snap_id = data.get('id')
    if not snap_id:
        return jsonify({'error': 'id required'}), 400

    rec = SnapshotRecord.query.get(snap_id)
    if not rec:
        return jsonify({'error': 'Snapshot not found'}), 404

    rec.delete_marked = False
    rec.delete_deadline = None
    db.session.commit()

    return jsonify({'success': True, 'snapshot': rec.to_dict()})


# ---------------------------------------------------------------------------
# API – save comment
# ---------------------------------------------------------------------------

@bp.route('/api/comment', methods=['POST'])
def api_comment():
    """Save a free-text comment for a snapshot record.

    Request JSON:
        id      (int)  – snapshot record ID
        comment (str)  – new comment text
    """
    from app import db
    from app.models import SnapshotRecord

    data = request.get_json(force=True) or {}
    snap_id = data.get('id')
    if not snap_id:
        return jsonify({'error': 'id required'}), 400

    rec = SnapshotRecord.query.get(snap_id)
    if not rec:
        return jsonify({'error': 'Snapshot not found'}), 404

    rec.comment = data.get('comment', '')
    db.session.commit()

    return jsonify({'success': True})


# ---------------------------------------------------------------------------
# API – trigger manual collection
# ---------------------------------------------------------------------------

@bp.route('/api/trigger-collect', methods=['POST'])
def api_trigger_collect():
    """Trigger an immediate snapshot collection cycle."""
    from app.snap_service import trigger_refresh
    trigger_refresh(current_app._get_current_object())
    return jsonify({'success': True, 'message': 'Snapshot collection triggered'})


# ---------------------------------------------------------------------------
# Helpers – datetime parsing
# ---------------------------------------------------------------------------

def _parse_dt(s: str) -> datetime | None:
    """Parse a datetime string in several common formats.  Returns None on failure."""
    if not s:
        return None
    for fmt in (
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M',
        '%Y-%m-%d',
        '%d.%m.%Y %H:%M:%S',
        '%d.%m.%Y %H:%M',
        '%d.%m.%Y',
    ):
        try:
            return datetime.strptime(s.strip(), fmt)
        except ValueError:
            pass
    return None


# ---------------------------------------------------------------------------
# Plan builders – translate a SnapshotRecord into ordered execution steps
# ---------------------------------------------------------------------------

def _build_update_ttl_plan(rec, locs: dict, new_ttl: datetime) -> list[dict]:
    """Build the ordered execution plan for a TTL change.

    Each plan entry is a dict with keys:

        ``label``      – human-readable step title (German UI)
        ``platform``   – ``'FlashArray'`` or ``'ONTAP'``
        ``target``     – display name shown in the modal header line for the
                         step (e.g. array or ``cluster / svm – volume``)
        ``command``    – curl-equivalent string shown in the terminal view
        ``execute``    – callable ``() -> tuple[bool, dict]`` performing the
                         actual REST call.  The ``dict`` is rendered as the
                         command response in the terminal view.
    """
    import re

    new_ts_str = new_ttl.strftime('%Y-%m-%d-%H%M%S')
    new_iso = new_ttl.strftime('%Y-%m-%dT%H:%M:%SZ')
    plan: list[dict] = []

    seen_fa_snap_sets: set[tuple] = set()
    for fa in locs.get('flasharray_systems', []):
        array_name = fa.get('name', '')
        snap_names = list(fa.get('snapshot_names', []))
        snap_key = tuple(sorted(snap_names))
        if snap_key in seen_fa_snap_sets:
            continue  # ActiveCluster partner shares the same snapshot set
        seen_fa_snap_sets.add(snap_key)

        for snap_name in snap_names:
            current_suffix = snap_name.split('.')[-1]
            new_suffix = re.sub(
                r'(HDBSNAP-)?\d{4}-\d{2}-\d{2}-\d{6}',
                lambda m: (m.group(1) or '') + new_ts_str,
                current_suffix,
            )
            dot_idx = snap_name.rfind('.')
            new_full_name = (snap_name[:dot_idx + 1] + new_suffix) if dot_idx != -1 else snap_name

            command = (
                f"curl -X PATCH 'https://{array_name}/api/<ver>/volume-snapshots"
                f"?names={snap_name}' "
                f"-H 'x-auth-token: <session>' "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"name\":\"{new_full_name}\"}}'"
            )
            plan.append({
                'label': f'FlashArray Rename: {snap_name} → {new_full_name}',
                'platform': 'FlashArray',
                'target': array_name,
                'command': command,
                'execute': _make_fa_rename_executor(array_name, snap_name, new_full_name),
            })

    for oc in locs.get('ontap_clusters', []):
        cluster = oc.get('cluster', '')
        svm = oc.get('svm', '')
        for vol_entry in (oc.get('volumes') or []):
            if isinstance(vol_entry, dict):
                vol_name = vol_entry.get('volume', '')
                snap_name = vol_entry.get('snap', '')
            else:
                vol_name = vol_entry
                snap_name = ''
            if not snap_name:
                # Fall back to a SID-derived name (older records)
                old_ts = rec.ttl.strftime('%Y-%m-%d-%H%M%S') if rec.ttl else ''
                snap_name = f'{rec.sid}_HDBSNAP-{old_ts}' if old_ts else f'{rec.sid}_HDBSNAP'

            new_snap_name = re.sub(
                r'(HDBSNAP-)?\d{4}-\d{2}-\d{2}-\d{6}',
                lambda m: (m.group(1) or '') + new_ts_str,
                snap_name,
            )
            if new_snap_name == snap_name:
                # No timestamp pattern found – append the new timestamp.
                new_snap_name = f'{rec.sid}_HDBSNAP-{new_ts_str}'

            command = (
                f"curl -X PATCH 'https://{cluster}/api/storage/volumes/{{vol_uuid}}"
                f"/snapshots/{{snap_uuid}}' "
                f"-u <user>:<password> "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"name\":\"{new_snap_name}\",\"expiry_time\":\"{new_iso}\"}}'"
            )
            plan.append({
                'label': f'ONTAP Rename: {vol_name}/{snap_name} → {new_snap_name}',
                'platform': 'ONTAP',
                'target': f'{cluster} / {svm} – {vol_name}',
                'command': command,
                'execute': _make_ontap_rename_executor(
                    cluster, svm, vol_name, snap_name, new_snap_name, new_iso,
                ),
            })

    return plan


def _build_delete_plan(rec, locs: dict) -> list[dict]:
    """Build the ordered execution plan for a snapshot deletion.

    Pure FlashArray: a single ``destroyed=true`` step per snapshot LUN; the
    array auto-eradicates after its configured eradication delay (default
    24 h).  No rename / expiration adjustment is necessary on Pure.

    ONTAP: two steps per volume – first reset ``expiry_time`` to "now"
    (ONTAP refuses deletion while the expiry is in the future, errors
    1638555 / 53412007), then DELETE.
    """
    plan: list[dict] = []

    seen_fa_snap_sets: set[tuple] = set()
    for fa in locs.get('flasharray_systems', []):
        array_name = fa.get('name', '')
        snap_names = list(fa.get('snapshot_names', []))
        snap_key = tuple(sorted(snap_names))
        if snap_key in seen_fa_snap_sets:
            continue
        seen_fa_snap_sets.add(snap_key)

        for snap_name in snap_names:
            command = (
                f"curl -X PATCH 'https://{array_name}/api/<ver>/volume-snapshots"
                f"?names={snap_name}' "
                f"-H 'x-auth-token: <session>' "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"destroyed\":true}}'"
            )
            plan.append({
                'label': f'FlashArray Destroy: {snap_name}',
                'platform': 'FlashArray',
                'target': array_name,
                'command': command,
                'execute': _make_fa_destroy_executor(array_name, snap_name),
            })

    now_dt = datetime.utcnow()
    now_iso = now_dt.strftime('%Y-%m-%dT%H:%M:%SZ')

    for oc in locs.get('ontap_clusters', []):
        cluster = oc.get('cluster', '')
        svm = oc.get('svm', '')
        for vol_entry in (oc.get('volumes') or []):
            if isinstance(vol_entry, dict):
                vol_name = vol_entry.get('volume', '')
                snap_name = vol_entry.get('snap', '')
            else:
                vol_name = vol_entry
                snap_name = ''
            if not vol_name or not snap_name:
                continue

            target = f'{cluster} / {svm} – {vol_name}'
            cmd_expiry = (
                f"curl -X PATCH 'https://{cluster}/api/storage/volumes/{{vol_uuid}}"
                f"/snapshots/{{snap_uuid}}' "
                f"-u <user>:<password> "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"expiry_time\":\"{now_iso}\"}}'"
            )
            cmd_delete = (
                f"curl -X DELETE 'https://{cluster}/api/storage/volumes/{{vol_uuid}}"
                f"/snapshots/{{snap_uuid}}' "
                f"-u <user>:<password>"
            )
            plan.append({
                'label': f'ONTAP expiry_time = jetzt: {vol_name}/{snap_name}',
                'platform': 'ONTAP',
                'target': target,
                'command': cmd_expiry,
                'execute': _make_ontap_set_expiry_executor(
                    cluster, svm, vol_name, snap_name, now_iso,
                ),
            })
            plan.append({
                'label': f'ONTAP Delete: {vol_name}/{snap_name}',
                'platform': 'ONTAP',
                'target': target,
                'command': cmd_delete,
                'execute': _make_ontap_delete_executor(
                    cluster, svm, vol_name, snap_name,
                ),
            })

    return plan


# ---------------------------------------------------------------------------
# Executor factories – return ``() -> (ok, info)`` callables
# ---------------------------------------------------------------------------

def _resolve_system(name: str, vendor: str | None = None):
    """Look up an enabled :class:`StorageSystem` row by its display name.

    Returns ``None`` if the system is missing or disabled.  When ``vendor``
    is given the result is also filtered by vendor (so a Pure ``pure01``
    cannot be confused with an ONTAP ``pure01`` in unusual setups).
    """
    from app.models import StorageSystem
    q = StorageSystem.query.filter(StorageSystem.name == name,
                                   StorageSystem.enabled.is_(True))
    if vendor:
        q = q.filter(StorageSystem.vendor == vendor)
    return q.first()


def _get_pure_client(array_name: str):
    from app.api import get_client
    sys = _resolve_system(array_name, vendor='pure')
    if not sys:
        return None, f'FlashArray "{array_name}" not found / disabled'
    client = get_client(
        vendor=sys.vendor,
        ip_address=sys.ip_address,
        port=sys.port,
        username=sys.api_username,
        password=sys.api_password,
        token=sys.api_token,
    )
    return client, None


def _get_ontap_client(cluster_name: str):
    from app.api import get_client
    sys = _resolve_system(cluster_name, vendor='netapp-ontap')
    if not sys:
        return None, f'ONTAP cluster "{cluster_name}" not found / disabled'
    client = get_client(
        vendor=sys.vendor,
        ip_address=sys.ip_address,
        port=sys.port,
        username=sys.api_username,
        password=sys.api_password,
        token=sys.api_token,
    )
    return client, None


def _make_fa_rename_executor(array_name: str, old_name: str, new_full_name: str):
    def _exec():
        client, err = _get_pure_client(array_name)
        if err:
            return False, {'error': err}
        return client.rename_volume_snapshot(old_name, new_full_name)
    return _exec


def _make_fa_destroy_executor(array_name: str, snap_name: str):
    def _exec():
        client, err = _get_pure_client(array_name)
        if err:
            return False, {'error': err}
        return client.destroy_volume_snapshot(snap_name)
    return _exec


def _make_ontap_rename_executor(cluster: str, svm: str, volume: str,
                                snap_name: str, new_snap_name: str,
                                new_expiry_iso: str):
    def _exec():
        client, err = _get_ontap_client(cluster)
        if err:
            return False, {'error': err}
        return client.rename_volume_snapshot(svm, volume, snap_name,
                                             new_snap_name, new_expiry_iso)
    return _exec


def _make_ontap_set_expiry_executor(cluster: str, svm: str, volume: str,
                                    snap_name: str, expiry_iso: str):
    def _exec():
        client, err = _get_ontap_client(cluster)
        if err:
            return False, {'error': err}
        return client.update_snapshot_expiry(svm, volume, snap_name, expiry_iso)
    return _exec


def _make_ontap_delete_executor(cluster: str, svm: str, volume: str,
                                snap_name: str):
    def _exec():
        client, err = _get_ontap_client(cluster)
        if err:
            return False, {'error': err}
        return client.delete_volume_snapshot(svm, volume, snap_name)
    return _exec


# ---------------------------------------------------------------------------
# Streaming runner – yields ndjson event lines
# ---------------------------------------------------------------------------

def _ndjson_line(event: str, **kwargs) -> str:
    payload = {'event': event, **kwargs}
    return json.dumps(payload, default=str) + '\n'


def _stream_run(app, *, title: str, snap_id: int, steps: list[dict],
                on_success):
    """Run ``steps`` sequentially and yield ndjson progress events.

    Stops at the first failing step (subsequent steps are still emitted as
    ``step_done`` with status ``skipped``).  When all steps succeed,
    ``on_success`` is invoked inside the Flask app context to perform the
    accompanying database update.

    Args:
        app:        Flask app object (needed for app_context inside generator).
        title:      Human-readable run title shown in the modal header.
        snap_id:    Snapshot record ID, echoed back to the client.
        steps:      Plan returned by :func:`_build_delete_plan` /
                    :func:`_build_update_ttl_plan`.
        on_success: Zero-argument callable executed in the app context after
                    every step succeeded.  May return a snapshot dict that
                    will be embedded in ``run_done`` for client refresh.
    """
    yield _ndjson_line('run_start', title=title, snap_id=snap_id,
                       total_steps=len(steps))
    failed = False
    for idx, step in enumerate(steps, start=1):
        yield _ndjson_line(
            'step_start',
            step_id=idx,
            label=step['label'],
            platform=step.get('platform', ''),
            target=step.get('target', ''),
            command=step.get('command', ''),
        )
        if failed:
            yield _ndjson_line('step_done', step_id=idx,
                               status='skipped',
                               message='Übersprungen wegen vorherigem Fehler')
            continue

        try:
            with app.app_context():
                ok, info = step['execute']()
        except Exception as exc:
            ok, info = False, {'error': str(exc)}
            logger.exception("Snap step %d (%s) crashed", idx, step['label'])

        info_str = _format_response_info(info)
        if info_str:
            yield _ndjson_line('step_log', step_id=idx, message=info_str)

        if ok:
            yield _ndjson_line('step_done', step_id=idx, status='ok')
        else:
            failed = True
            err_msg = info.get('error') if isinstance(info, dict) else str(info)
            yield _ndjson_line('step_done', step_id=idx, status='error',
                               message=err_msg or 'Aufruf fehlgeschlagen')

    snapshot_payload = None
    if not failed:
        try:
            with app.app_context():
                snapshot_payload = on_success() or None
        except Exception as exc:
            logger.exception("Snap finalization callback failed: %s", exc)
            failed = True
            yield _ndjson_line('step_log', step_id=0,
                               message=f'Datenbank-Update fehlgeschlagen: {exc}')

    yield _ndjson_line(
        'run_done',
        status='ok' if not failed else 'error',
        message=('Alle Schritte erfolgreich.' if not failed
                 else 'Mindestens ein Schritt fehlgeschlagen.'),
        snapshot=snapshot_payload,
    )


def _format_response_info(info) -> str:
    """Render the executor's info dict as a single human-readable line.

    The output is shown in the collapsible terminal view of the modal so the
    operator can see the actual REST status code and response body excerpt.
    """
    if not info:
        return ''
    if not isinstance(info, dict):
        return str(info)
    if 'error' in info and 'status_code' not in info:
        return f"Fehler: {info['error']}"
    parts = []
    if 'status_code' in info:
        parts.append(f"HTTP {info['status_code']}")
    if info.get('text'):
        text = info['text'].strip()
        if text:
            parts.append(text)
    if info.get('volume_uuid'):
        parts.append(f"vol_uuid={info['volume_uuid']}")
    if info.get('snap_uuid'):
        parts.append(f"snap_uuid={info['snap_uuid']}")
    return ' | '.join(parts) if parts else json.dumps(info, default=str)


# ---------------------------------------------------------------------------
# Post-success database mutations
# ---------------------------------------------------------------------------

def _persist_ttl_update(app, snap_id: int, new_ttl: datetime, user: str) -> dict | None:
    from app import db
    from app.models import SnapshotAuditLog, SnapshotRecord

    rec = SnapshotRecord.query.get(snap_id)
    if not rec:
        return None
    old_ttl = rec.ttl
    rec.ttl = new_ttl
    audit = SnapshotAuditLog(
        snapshot_id=rec.id,
        old_ttl=old_ttl,
        new_ttl=new_ttl,
        changed_by=user,
        changed_at=datetime.utcnow(),
    )
    db.session.add(audit)
    db.session.commit()
    return rec.to_dict()


def _finalize_delete(app, snap_id: int) -> dict | None:
    """After a successful delete run, drop the SnapshotRecord row.

    Storage no longer reports the snapshot, so the dashboard's collector
    would also remove it on its next pass – we just speed that up.  We
    return ``None`` so the front-end refreshes its view.
    """
    from app import db
    from app.models import SnapshotRecord

    rec = SnapshotRecord.query.get(snap_id)
    if not rec:
        return None
    db.session.delete(rec)
    db.session.commit()
    return None
