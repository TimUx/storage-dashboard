"""Admin API: preview which snapshots match TTL auto-delete exclusion rules."""
import logging

from flask import jsonify, request
from flask_login import login_required

from app.models import SnapshotRecord
from app.routes.admin import bp
from app.snap_ttl_auto_delete_exclusions import preview_excluded_snapshots

logger = logging.getLogger(__name__)


@bp.route('/api/snap-ttl-exclusions-preview', methods=['POST'])
@login_required
def api_snap_ttl_exclusions_preview():
    """Return matching snapshots for unsaved JSON (body: ``{"raw_json": "..."}``)."""
    payload = request.get_json(silent=True) or {}
    raw = payload.get('raw_json')
    if raw is not None and not isinstance(raw, str):
        return jsonify({'error': 'raw_json muss ein String sein'}), 400
    try:
        recs = SnapshotRecord.query.order_by(
            SnapshotRecord.sid.asc(),
            SnapshotRecord.creation_time.desc(),
        ).all()
        rows, err, total = preview_excluded_snapshots(recs, raw, limit=500)
        return jsonify({
            'rows': rows,
            'parse_error': err,
            'total': total,
        })
    except Exception as exc:
        logger.error('snap-ttl-exclusions-preview failed: %s', exc, exc_info=True)
        return jsonify({'error': str(exc)}), 500
