"""Tests for the /snaps module.

Covers:
1. SID extraction (extract_sid)
2. TTL extraction (extract_ttl)
3. Snapshot grouping / deduplication (_group_by_sid_and_time)
4. API endpoints: list, comment, delete, undo-delete, update-ttl, update-presence
5. Statistics calculation
"""

import json
import os
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _no_op(*a, **kw):
    pass


@pytest.fixture()
def app():
    """Flask test app backed by in-memory SQLite (no background threads)."""
    patches = [
        patch('app.capacity_service.start_background_refresh', _no_op),
        patch('app.sod_service.start_background_refresh', _no_op),
        patch('app.status_service.start_background_refresh', _no_op),
        patch('app.dr_service.start_background_refresh', _no_op),
        patch('app.snap_service.start_background_refresh', _no_op),
    ]
    for p in patches:
        p.start()

    os.environ.setdefault('SECRET_KEY', 'test-secret')
    os.environ['DATABASE_URL'] = 'sqlite://'

    from app import create_app
    flask_app = create_app()
    flask_app.config['TESTING'] = True

    for p in patches:
        p.stop()

    yield flask_app


@pytest.fixture()
def client(app):
    with app.app_context():
        yield app.test_client()


@pytest.fixture()
def ctx(app):
    with app.app_context():
        yield app


# ---------------------------------------------------------------------------
# Unit tests for snap_service helpers
# ---------------------------------------------------------------------------

def test_extract_sid_standard():
    from app.snap_service import extract_sid
    assert extract_sid('ACP_1_data_hpa2012.HDBSNAP-2026-03-18-024722') == 'ACP'


def test_extract_sid_vg_prefix():
    from app.snap_service import extract_sid
    assert extract_sid('vgAQP_1.2026-03-19-123749') == 'AQP'


def test_extract_sid_5char():
    from app.snap_service import extract_sid
    assert extract_sid('ABCDE_1_data.snap') == 'ABCDE'


def test_extract_sid_no_match():
    from app.snap_service import extract_sid
    assert extract_sid('') is None
    # A name with no underscore or dot separator cannot be matched
    assert extract_sid('no-separator-name') is None


def test_extract_ttl_hdbsnap():
    from app.snap_service import extract_ttl
    dt = extract_ttl('ACP_1_data_hpa2012.HDBSNAP-2026-03-18-024722')
    assert dt is not None
    assert dt.year == 2026
    assert dt.month == 3
    assert dt.day == 18
    assert dt.hour == 2
    assert dt.minute == 47
    assert dt.second == 22


def test_extract_ttl_vg_style():
    from app.snap_service import extract_ttl
    dt = extract_ttl('vgAQP_1.2026-03-19-123749')
    assert dt is not None
    assert dt.year == 2026
    assert dt.month == 3
    assert dt.day == 19
    assert dt.hour == 12
    assert dt.minute == 37
    assert dt.second == 49


def test_extract_ttl_no_match():
    from app.snap_service import extract_ttl
    assert extract_ttl('no-timestamp-here') is None


def test_group_by_sid_deduplicates_activecluster():
    """Two FA snaps with identical SID, name, TTL (ActiveCluster pair) → one record."""
    from app.snap_service import _group_by_sid_and_time

    ts = datetime(2026, 3, 18, 2, 47, 0)
    snap = {
        'sid': 'ACP',
        'snapshot_name': 'ACP_1_data_hpa2012.HDBSNAP-2026-03-18-024722',
        'creation_time': ts,
        'ttl': datetime(2026, 3, 18, 2, 47, 22),
        'array_name': 'fa01',
    }
    snap_dup = dict(snap)
    snap_dup['array_name'] = 'fa02'  # Same snap reported by partner controller

    result = _group_by_sid_and_time([snap, snap_dup], [])
    assert len(result) == 1
    assert result[0]['sid'] == 'ACP'
    assert result[0]['flasharray_present'] is True


def test_group_by_sid_groups_multiple_luns():
    """Multiple LUN snaps with same SID and same TTL minute → one record."""
    from app.snap_service import _group_by_sid_and_time

    ts = datetime(2026, 3, 18, 2, 47, 22)
    common = {'sid': 'ACP', 'creation_time': ts, 'ttl': ts, 'array_name': 'fa01'}
    snaps = [
        {**common, 'snapshot_name': 'ACP_1_data.HDBSNAP-2026-03-18-024722'},
        {**common, 'snapshot_name': 'ACP_1_log.HDBSNAP-2026-03-18-024722'},
        {**common, 'snapshot_name': 'ACP_2_data.HDBSNAP-2026-03-18-024722'},
    ]
    result = _group_by_sid_and_time(snaps, [])
    assert len(result) == 1
    locs = json.loads(result[0]['storage_locations'])
    assert len(locs['flasharray_systems'][0]['snapshot_names']) == 3


def test_group_by_sid_matches_ontap():
    """ONTAP snap matching same SID+TTL minute as FA snap → ontap_present=True."""
    from app.snap_service import _group_by_sid_and_time

    ts = datetime(2026, 3, 18, 2, 47, 22)
    fa_snap = {'sid': 'ACP', 'snapshot_name': 'ACP_1.HDBSNAP-2026-03-18-024722',
               'creation_time': ts, 'ttl': ts, 'array_name': 'fa01'}
    ontap_snap = {'sid': 'ACP', 'snapshot_name': 'ACP_HDBSNAP-2026-03-18-024722',
                  'creation_time': ts, 'ttl': ts,
                  'cluster_name': 'ontap01', 'svm_name': 'svm1', 'volume_name': 'HANA_ACP'}

    result = _group_by_sid_and_time([fa_snap], [ontap_snap])
    assert len(result) == 1
    assert result[0]['ontap_present'] is True
    assert result[0]['flasharray_present'] is True


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------

def _seed_snapshot(ctx, sid='ACP', days_ago=2):
    """Helper to insert a SnapshotRecord."""
    from app import db
    from app.models import SnapshotRecord
    ct = datetime.utcnow() - timedelta(days=days_ago)
    ttl = ct + timedelta(days=3)
    locs = json.dumps({'flasharray_systems': [{'name': 'fa01', 'snapshot_names': ['ACP_1.HDBSNAP']}],
                       'ontap_clusters': []})
    rec = SnapshotRecord(
        sid=sid,
        creation_time=ct,
        ttl=ttl,
        flasharray_present=True,
        ontap_present=False,
        storage_locations=locs,
    )
    with ctx.app_context():
        db.session.add(rec)
        db.session.commit()
        return rec.id


def test_api_list_empty(client):
    resp = client.get('/snaps/api/list')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['snapshots'] == []
    assert data['stats']['total'] == 0


def test_api_list_returns_snapshots(app, client):
    snap_id = _seed_snapshot(app)
    resp = client.get('/snaps/api/list')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['stats']['total'] == 1
    assert data['snapshots'][0]['sid'] == 'ACP'


def test_api_list_sid_filter(app, client):
    _seed_snapshot(app, sid='ACP')
    _seed_snapshot(app, sid='YZ4')
    resp = client.get('/snaps/api/list?sid=ACP')
    assert resp.status_code == 200
    data = resp.get_json()
    assert all(s['sid'] == 'ACP' for s in data['snapshots'])


def test_api_comment(app, client):
    snap_id = _seed_snapshot(app)
    resp = client.post('/snaps/api/comment',
                       json={'id': snap_id, 'comment': 'Test comment'},
                       content_type='application/json')
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True

    resp2 = client.get('/snaps/api/list')
    snap = next(s for s in resp2.get_json()['snapshots'] if s['id'] == snap_id)
    assert snap['comment'] == 'Test comment'


def test_api_delete_and_undo(app, client):
    snap_id = _seed_snapshot(app)

    # Mark for deletion
    resp = client.post('/snaps/api/delete',
                       json={'id': snap_id},
                       content_type='application/json')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert 'delete_deadline' in data

    # Confirm marked in list
    list_data = client.get('/snaps/api/list').get_json()
    snap = next(s for s in list_data['snapshots'] if s['id'] == snap_id)
    assert snap['delete_marked'] is True

    # Undo
    resp2 = client.post('/snaps/api/undo-delete',
                        json={'id': snap_id},
                        content_type='application/json')
    assert resp2.status_code == 200
    assert resp2.get_json()['success'] is True

    # Confirm cancelled
    list_data2 = client.get('/snaps/api/list').get_json()
    snap2 = next(s for s in list_data2['snapshots'] if s['id'] == snap_id)
    assert snap2['delete_marked'] is False
    assert snap2['delete_deadline'] is None


def test_api_update_ttl(app, client):
    snap_id = _seed_snapshot(app)
    resp = client.post('/snaps/api/update-ttl',
                       json={'id': snap_id, 'new_ttl': '2026-04-01 12:00:00'},
                       content_type='application/json')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert '2026-04-01' in data['new_ttl']

    # curl_commands is a list (may be empty if no storage locations with HDBSNAP)
    assert isinstance(data['curl_commands'], list)


def test_api_update_ttl_bad_format(app, client):
    snap_id = _seed_snapshot(app)
    resp = client.post('/snaps/api/update-ttl',
                       json={'id': snap_id, 'new_ttl': 'not-a-date'},
                       content_type='application/json')
    assert resp.status_code == 400


def test_api_update_ttl_missing_id(app, client):
    resp = client.post('/snaps/api/update-ttl',
                       json={'new_ttl': '2026-04-01 12:00:00'},
                       content_type='application/json')
    assert resp.status_code == 400


def test_update_presence_endpoint_removed(app, client):
    """The /api/update-presence endpoint was removed – DB/NFS columns are auto-only."""
    snap_id = _seed_snapshot(app)
    resp = client.post('/snaps/api/update-presence',
                       json={'id': snap_id, 'db_override': 'Manual'},
                       content_type='application/json')
    # Endpoint was removed: any non-2xx response (404 or auth redirect) is acceptable
    assert resp.status_code not in (200, 201)


def test_api_stats_older_than_5_days(app, client):
    _seed_snapshot(app, sid='OLD', days_ago=7)
    _seed_snapshot(app, sid='NEW', days_ago=1)
    resp = client.get('/snaps/api/list')
    data = resp.get_json()
    assert data['stats']['older_5_days'] >= 1


def test_snap_page_renders(client):
    resp = client.get('/snaps/')
    assert resp.status_code == 200
    assert b'Snapshot' in resp.data


def test_audit_log_created_on_ttl_change(app, client):
    """Updating TTL should write an audit log entry."""
    snap_id = _seed_snapshot(app)
    client.post('/snaps/api/update-ttl',
                json={'id': snap_id, 'new_ttl': '2026-05-01 00:00:00', 'user': 'operator1'},
                content_type='application/json')

    with app.app_context():
        from app.models import SnapshotAuditLog
        logs = SnapshotAuditLog.query.filter_by(snapshot_id=snap_id).all()
        assert len(logs) == 1
        assert logs[0].changed_by == 'operator1'
        assert logs[0].new_ttl.year == 2026


def test_reconciliation_removes_stale_records(app):
    """Stale records (not seen in last collection run) must be removed from DB."""
    from app.snap_service import _upsert_snapshot_records, _group_by_sid_and_time
    from datetime import datetime, timedelta

    # Seed an old record directly (simulates a snapshot already in DB)
    old_ct = datetime(2026, 1, 1, 0, 0, 0)
    with app.app_context():
        from app import db
        from app.models import SnapshotRecord
        old_rec = SnapshotRecord(
            sid='GONE',
            creation_time=old_ct,
            ttl=old_ct + timedelta(days=3),
            flasharray_present=True,
            ontap_present=False,
            last_seen=datetime(2026, 1, 1, 0, 0, 0),  # very old last_seen
        )
        db.session.add(old_rec)
        db.session.commit()
        old_id = old_rec.id

    # Run the collector with a DIFFERENT snapshot (ACP); GONE is not included
    ts = datetime(2026, 3, 18, 2, 47, 0)
    fa_snap = {'sid': 'ACP', 'snapshot_name': 'ACP_1.HDBSNAP-2026-03-18-024722',
               'creation_time': ts, 'ttl': ts, 'array_name': 'fa01'}
    aggregated = _group_by_sid_and_time([fa_snap], [])
    _upsert_snapshot_records(app, aggregated, systems_queried=1)

    # GONE record should be deleted because it wasn't seen this run
    with app.app_context():
        from app.models import SnapshotRecord
        assert SnapshotRecord.query.get(old_id) is None
        assert SnapshotRecord.query.filter_by(sid='ACP').count() == 1


def test_reconciliation_keeps_stale_with_comment(app):
    """Stale records that have a user comment are kept but flagged as absent."""
    from app.snap_service import _upsert_snapshot_records, _group_by_sid_and_time
    from datetime import datetime, timedelta

    old_ct = datetime(2026, 2, 1, 0, 0, 0)
    with app.app_context():
        from app import db
        from app.models import SnapshotRecord
        rec = SnapshotRecord(
            sid='ANNOT',
            creation_time=old_ct,
            ttl=old_ct + timedelta(days=3),
            flasharray_present=True,
            ontap_present=False,
            comment='Wichtiger Hinweis',
            last_seen=datetime(2026, 2, 1, 0, 0, 0),  # old
        )
        db.session.add(rec)
        db.session.commit()
        rec_id = rec.id

    # Run with no matching snapshot
    aggregated = _group_by_sid_and_time([], [])
    _upsert_snapshot_records(app, aggregated, systems_queried=1)

    with app.app_context():
        from app.models import SnapshotRecord
        kept = SnapshotRecord.query.get(rec_id)
        assert kept is not None, "Record with comment should be kept"
        assert kept.flasharray_present is False
        assert kept.ontap_present is False
        assert kept.comment == 'Wichtiger Hinweis'
