"""Snapshot management routes – /snaps/"""
import json
import logging
from datetime import datetime, timedelta

from flask import Blueprint, render_template, jsonify, request, current_app

bp = Blueprint('snaps', __name__, url_prefix='/snaps')
logger = logging.getLogger(__name__)

# Offset added to deletion timestamp (24 hours)
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
    from app.models import SnapshotRecord, SnapshotCollectorMetadata

    sid_filter = request.args.get('sid', '').strip().upper()

    query = SnapshotRecord.query

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

    # Last collector run
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
# API – update TTL
# ---------------------------------------------------------------------------

@bp.route('/api/update-ttl', methods=['POST'])
def api_update_ttl():
    """Update the TTL of a snapshot record and return the CURL simulation preview.

    Request JSON:
        id       (int)  – snapshot record ID
        new_ttl  (str)  – new TTL in ISO-8601 or DD.MM.YYYY HH:MM:SS format
        user     (str)  – operator name (optional)
    """
    from app import db
    from app.models import SnapshotRecord, SnapshotAuditLog

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

    old_ttl = rec.ttl
    new_ts_str = new_ttl.strftime('%Y-%m-%d-%H%M%S')

    # Build CURL simulation commands
    locs = rec.get_storage_locations()
    curl_commands = _build_rename_curl_commands(rec, locs, new_ts_str)

    # Persist TTL change
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

    return jsonify({
        'success': True,
        'old_ttl': old_ttl.isoformat() if old_ttl else None,
        'new_ttl': new_ttl.isoformat(),
        'curl_commands': curl_commands,
    })


# ---------------------------------------------------------------------------
# API – mark/unmark deletion
# ---------------------------------------------------------------------------

@bp.route('/api/delete', methods=['POST'])
def api_delete():
    """Mark a snapshot record for deletion (sets 24h deadline).

    Request JSON:
        id (int) – snapshot record ID
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

    rec.delete_marked = True
    rec.delete_deadline = datetime.utcnow() + timedelta(hours=_DELETE_DELAY_HOURS)
    db.session.commit()

    return jsonify({
        'success': True,
        'delete_deadline': rec.delete_deadline.isoformat(),
    })


@bp.route('/api/delete-preview', methods=['POST'])
def api_delete_preview():
    """Return the CURL commands that *would* delete a snapshot, without any DB change.

    This endpoint is used by the frontend to show operators the exact API calls
    that will be executed when a snapshot is eventually deleted.
    No storage API calls are made; no database state is modified.

    Request JSON:
        id (int) – snapshot record ID

    Response JSON:
        curl_commands (list) – list of command dicts (platform, command, …)
    """
    from app.models import SnapshotRecord

    data = request.get_json(force=True) or {}
    snap_id = data.get('id')
    if not snap_id:
        return jsonify({'error': 'id required'}), 400

    rec = SnapshotRecord.query.get(snap_id)
    if not rec:
        return jsonify({'error': 'Snapshot not found'}), 404

    locs = rec.get_storage_locations()
    curl_commands = _build_delete_curl_commands(rec, locs)

    return jsonify({'success': True, 'curl_commands': curl_commands})


@bp.route('/api/undo-delete', methods=['POST'])
def api_undo_delete():
    """Cancel a pending deletion.

    Request JSON:
        id (int) – snapshot record ID
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

    return jsonify({'success': True})


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
# Helpers
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


def _build_rename_curl_commands(rec, locs: dict, new_ts_str: str) -> list[dict]:
    """Build simulated CURL rename commands for a TTL change.

    Returns a list of dicts with keys: platform, command.
    No actual API calls are made.

    FlashArray rename (Pure Storage REST API 2.x, api/pure_swagger.json):
        PATCH /api/<ver>/volume-snapshots?names=<full_snap_name>
        Body: {"name": "<new_suffix>"}   ← suffix only, NOT the full name
        The full snapshot name is ``{source_volume}.{suffix}``; the API renames
        by setting the suffix portion via the ``name`` field in the request body.
        ActiveCluster arrays share pod volumes – renaming on one array propagates
        automatically, so only the first array per unique snapshot set is included.

    ONTAP rename (ONTAP REST API, api/ontap_swagger.yaml) – one command per volume:
        Step 1 – Find snapshot UUID:
            GET  /api/storage/volumes/{vol_uuid}/snapshots?name=<exact_snap_name>
        Step 2 – Rename and update expiry_time:
            PATCH /api/storage/volumes/{vol_uuid}/snapshots/{snap_uuid}
            Body: {"name": "<new_snap_name>", "expiry_time": "<ISO>"}
    """
    import re
    commands = []

    # FlashArray rename commands.
    # Deduplicate ActiveCluster partner arrays: arrays with identical snapshot sets
    # share pod volumes, so only one array needs to receive the rename command.
    seen_fa_snap_sets: set[tuple] = set()
    for fa in locs.get('flasharray_systems', []):
        array_name = fa.get('name', 'fa-unknown')
        snap_names = fa.get('snapshot_names', [])
        snap_key = tuple(sorted(snap_names))
        if snap_key in seen_fa_snap_sets:
            continue  # already emitted for an ActiveCluster partner with same snapshots
        seen_fa_snap_sets.add(snap_key)

        for snap_name in snap_names:
            # Build the new suffix (only the part after the last '.')
            # The suffix is the HDBSNAP-YYYY-MM-DD-HHMMSS portion.
            # PATCH body must contain only the NEW SUFFIX, not the full name.
            new_suffix = re.sub(
                r'(HDBSNAP-)\d{4}-\d{2}-\d{2}-\d{6}',
                r'\g<1>' + new_ts_str,
                snap_name.split('.')[-1],   # extract current suffix from full name
            )
            # Build the new full name for display (source_vol.new_suffix)
            dot_idx = snap_name.rfind('.')
            new_full_name = (snap_name[:dot_idx + 1] + new_suffix) if dot_idx != -1 else snap_name
            commands.append({
                'platform': 'FlashArray',
                'array': array_name,
                # Correct API call per Pure Storage REST API 2.x schema:
                #   PATCH /api/<ver>/volume-snapshots?names=<full_old_name>
                #   Body: {"name": "<new_suffix>"}  (suffix only, not full name)
                'command': (
                    f"curl -X PATCH 'https://{array_name}/api/2.26/volume-snapshots"
                    f"?names={snap_name}'"
                    f" -H 'x-auth-token: <token>'"
                    f" -H 'Content-Type: application/json'"
                    f" -d '{{\"name\":\"{new_suffix}\"}}'"
                ),
                'old_name': snap_name,
                'new_name': new_full_name,
            })

    # ONTAP rename commands – one entry per volume so the operator can see exactly
    # which volumes are affected and copy the correct command for each.
    for oc in locs.get('ontap_clusters', []):
        cluster = oc.get('cluster', 'ontap-unknown')
        svm = oc.get('svm', '')
        volumes = oc.get('volumes', [])

        # Convert YYYY-MM-DD-HHMMSS → ISO-8601 for expiry_time field
        try:
            expiry_dt = datetime.strptime(new_ts_str, '%Y-%m-%d-%H%M%S')
            expiry_iso = expiry_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        except Exception:
            expiry_iso = new_ts_str

        for vol_entry in (volumes or []):
            # volumes entries are dicts {'volume': <vol_name>, 'snap': <snap_name>}
            if isinstance(vol_entry, dict):
                vol_name = vol_entry.get('volume', '')
                old_snap_name = vol_entry.get('snap', '')
            else:
                vol_name = vol_entry
                old_snap_name = ''

            # Derive new snap name: replace old timestamp in snap name with new one.
            # Fall back to SID-based convention if snap name is not available.
            if old_snap_name:
                new_snap_name = re.sub(
                    r'(HDBSNAP-)\d{4}-\d{2}-\d{2}-\d{6}',
                    r'\g<1>' + new_ts_str,
                    old_snap_name,
                )
                # If the pattern was not found, fall back to SID-based convention
                if new_snap_name == old_snap_name:
                    new_snap_name = f"{rec.sid}_HDBSNAP-{new_ts_str}"
                search_name = old_snap_name
            else:
                old_ts_str = rec.ttl.strftime('%Y-%m-%d-%H%M%S') if rec.ttl else '<alter-ttl-ts>'
                new_snap_name = f"{rec.sid}_HDBSNAP-{new_ts_str}"
                search_name = f"*HDBSNAP-{old_ts_str}*"

            commands.append({
                'platform': 'ONTAP',
                'cluster': cluster,
                'svm': svm,
                'volume': vol_name,
                'command': (
                    f"# Schritt 1: Snapshot-UUID ermitteln (Volume: {vol_name}, SVM: {svm})\n"
                    f"curl 'https://{cluster}/api/storage/volumes/{{vol_uuid}}"
                    f"/snapshots?name={search_name}'"
                    f" -u admin:<password>\n\n"
                    f"# Schritt 2: Snapshot umbenennen und TTL setzen\n"
                    f"curl -X PATCH 'https://{cluster}/api/storage/volumes/{{vol_uuid}}"
                    f"/snapshots/{{snap_uuid}}'"
                    f" -u admin:<password>"
                    f" -H 'Content-Type: application/json'"
                    f" -d '{{\"name\":\"{new_snap_name}\",\"expiry_time\":\"{expiry_iso}\"}}'"
                ),
                'new_snap_name': new_snap_name,
                'expiry_time': expiry_iso,
            })

    return commands


def _build_delete_curl_commands(rec, locs: dict) -> list[dict]:
    """Build simulated CURL delete commands for a snapshot record.

    Returns a list of dicts with keys: platform, command, …
    No actual API calls are made.

    FlashArray deletion is a **two-step** process
    (api/pure_swagger.json, PATCH + DELETE /api/2.26/volume-snapshots):

        Step 1 – Destroy (moves to eradication-pending state):
            PATCH /api/<ver>/volume-snapshots?names=<full_snap_name>
            Body: {"destroyed": true}

        Step 2 – Eradicate (permanent deletion, cannot be recovered):
            DELETE /api/<ver>/volume-snapshots?names=<full_snap_name>

        ActiveCluster arrays share pod volumes – only one array needs the command.

    ONTAP deletion (ONTAP REST API) – one command per volume:
        Step 1 – Find snapshot UUID:
            GET  /api/storage/volumes/{vol_uuid}/snapshots?name=<snap_name>
        Step 2 – Delete snapshot:
            DELETE /api/storage/volumes/{vol_uuid}/snapshots/{snap_uuid}
    """
    commands = []

    # FlashArray two-step delete commands (one per snapshot LUN).
    # Deduplicate ActiveCluster partner arrays: arrays with identical snapshot sets
    # share pod volumes, so only one array needs to receive the delete command.
    seen_fa_snap_sets: set[tuple] = set()
    for fa in locs.get('flasharray_systems', []):
        array_name = fa.get('name', 'fa-unknown')
        snap_names = fa.get('snapshot_names', [])
        snap_key = tuple(sorted(snap_names))
        if snap_key in seen_fa_snap_sets:
            continue  # already emitted for an ActiveCluster partner with same snapshots
        seen_fa_snap_sets.add(snap_key)

        for snap_name in snap_names:
            commands.append({
                'platform': 'FlashArray',
                'array': array_name,
                'snap_name': snap_name,
                'command': (
                    f"# Schritt 1: Snapshot als gelöscht markieren (Eradication-Pending)\n"
                    f"curl -X PATCH 'https://{array_name}/api/2.26/volume-snapshots"
                    f"?names={snap_name}'"
                    f" -H 'x-auth-token: <token>'"
                    f" -H 'Content-Type: application/json'"
                    f" -d '{{\"destroyed\":true}}'\n\n"
                    f"# Schritt 2: Snapshot endgültig löschen (Eradication)\n"
                    f"curl -X DELETE 'https://{array_name}/api/2.26/volume-snapshots"
                    f"?names={snap_name}'"
                    f" -H 'x-auth-token: <token>'"
                    f" -H 'Content-Type: application/json'"
                ),
            })

    # ONTAP delete commands – one entry per volume
    ttl_ts_str = rec.ttl.strftime('%Y-%m-%d-%H%M%S') if rec.ttl else '<ttl-ts>'

    for oc in locs.get('ontap_clusters', []):
        cluster = oc.get('cluster', 'ontap-unknown')
        svm = oc.get('svm', '')
        volumes = oc.get('volumes', [])

        for vol_entry in (volumes or []):
            # volumes entries are dicts {'volume': <vol_name>, 'snap': <snap_name>}
            if isinstance(vol_entry, dict):
                vol_name = vol_entry.get('volume', '')
                snap_name_str = vol_entry.get('snap', '')
            else:
                vol_name = vol_entry
                snap_name_str = ''

            search_name = snap_name_str if snap_name_str else f"*HDBSNAP-{ttl_ts_str}*"

            commands.append({
                'platform': 'ONTAP',
                'cluster': cluster,
                'svm': svm,
                'volume': vol_name,
                'command': (
                    f"# Schritt 1: Snapshot-UUID ermitteln (Volume: {vol_name}, SVM: {svm})\n"
                    f"curl 'https://{cluster}/api/storage/volumes/{{vol_uuid}}"
                    f"/snapshots?name={search_name}'"
                    f" -u admin:<password>\n\n"
                    f"# Schritt 2: Snapshot löschen\n"
                    f"curl -X DELETE 'https://{cluster}/api/storage/volumes/{{vol_uuid}}"
                    f"/snapshots/{{snap_uuid}}'"
                    f" -u admin:<password>"
                    f" -H 'Content-Type: application/json'"
                ),
            })

    return commands
