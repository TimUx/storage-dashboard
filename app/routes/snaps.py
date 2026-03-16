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
            'last_update': last_run.run_at.isoformat() if last_run else None,
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
    """
    commands = []

    # FlashArray rename commands
    for fa in locs.get('flasharray_systems', []):
        array_name = fa.get('name', 'fa-unknown')
        for snap_name in fa.get('snapshot_names', []):
            # Replace timestamp suffix: find HDBSNAP-YYYY-MM-DD-HHMMSS pattern
            import re
            new_name = re.sub(
                r'(HDBSNAP-)\d{4}-\d{2}-\d{2}-\d{6}',
                r'\g<1>' + new_ts_str,
                snap_name,
            )
            if new_name == snap_name:
                # Also try generic timestamp replacement
                new_name = re.sub(
                    r'\d{4}-\d{2}-\d{2}-\d{6}$',
                    new_ts_str,
                    snap_name,
                )
            commands.append({
                'platform': 'FlashArray',
                'array': array_name,
                'command': (
                    f"curl -X PATCH https://{array_name}/api/volume-snapshots/{{id}}"
                    f" -H 'x-auth-token: <token>'"
                    f" -d '{{\"name\":\"{new_name}\"}}'"
                ),
                'old_name': snap_name,
                'new_name': new_name,
            })

    # ONTAP rename commands
    for oc in locs.get('ontap_clusters', []):
        cluster = oc.get('cluster', 'ontap-unknown')
        svm = oc.get('svm', '')
        new_expiry = new_ts_str.replace('-', '').replace('T', '')
        # Convert YYYYMMDDHHMMSS → ISO
        try:
            expiry_dt = datetime.strptime(new_ts_str, '%Y-%m-%d-%H%M%S')
            expiry_iso = expiry_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        except Exception:
            expiry_iso = new_ts_str

        # Build ONTAP snapshot name for this SID
        ontap_snap_name = f"{rec.sid}_HDBSNAP-{new_ts_str}"
        commands.append({
            'platform': 'ONTAP',
            'cluster': cluster,
            'svm': svm,
            'command': (
                f"curl -X PATCH https://{cluster}/api/storage/volumes/{{uuid}}/snapshots/{{snap_uuid}}"
                f" -u admin:<password>"
                f" -d '{{\"name\":\"{ontap_snap_name}\",\"expiry_time\":\"{expiry_iso}\"}}'"
            ),
            'new_snap_name': ontap_snap_name,
            'expiry_time': expiry_iso,
        })

    return commands
