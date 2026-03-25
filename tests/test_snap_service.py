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
    # Names that don't start with 3+ consecutive alphanumeric chars return None
    assert extract_sid('no-separator-name') is None


def test_extract_sid_ora_prefix():
    """ORA_ prefix is skipped; the actual SID is the token after the underscore."""
    from app.snap_service import extract_sid
    assert extract_sid('ORA_WQ4') == 'WQ4'
    assert extract_sid('ORA_WQ1') == 'WQ1'
    assert extract_sid('ORA_WQ2') == 'WQ2'
    assert extract_sid('ORA_WQ4_archivelog') == 'WQ4'


def test_extract_sid_hana_prefix():
    """HANA_ prefix is skipped; the actual SID is the token after the underscore."""
    from app.snap_service import extract_sid
    assert extract_sid('HANA_ABP') == 'ABP'
    assert extract_sid('HANA_AFT') == 'AFT'
    assert extract_sid('HANA_ABP_data.HDBSNAP-2026-03-13-073434') == 'ABP'


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


# ---------------------------------------------------------------------------
# _strip_pod_prefix tests
# ---------------------------------------------------------------------------

def test_strip_pod_prefix_hana_name():
    from app.snap_service import _strip_pod_prefix
    assert _strip_pod_prefix(
        'pod-x86-0102::IEP_1_data.HDBSNAP-2026-03-18-002003'
    ) == 'IEP_1_data.HDBSNAP-2026-03-18-002003'


def test_strip_pod_prefix_oracle_name():
    from app.snap_service import _strip_pod_prefix
    assert _strip_pod_prefix('pod-aix-0102::vgIQP_1.2026-03-19-124002') == 'vgIQP_1.2026-03-19-124002'


def test_strip_pod_prefix_source_name():
    from app.snap_service import _strip_pod_prefix
    assert _strip_pod_prefix('pod-x86-0102::IEP_1_data') == 'IEP_1_data'
    assert _strip_pod_prefix('pod-aix-0102::vgIQP_1') == 'vgIQP_1'


def test_strip_pod_prefix_no_pod():
    """Names without '::' are returned unchanged."""
    from app.snap_service import _strip_pod_prefix
    assert _strip_pod_prefix('ACP_1_data.HDBSNAP-2026-03-18-024722') == 'ACP_1_data.HDBSNAP-2026-03-18-024722'
    assert _strip_pod_prefix('vgAQP_1.2026-03-19-123749') == 'vgAQP_1.2026-03-19-123749'
    assert _strip_pod_prefix('') == ''


# ---------------------------------------------------------------------------
# extract_sid tests for pod-stripped names
# ---------------------------------------------------------------------------

def test_extract_sid_pod_hana_stripped():
    """SID extracted from pod-stripped HANA volume names."""
    from app.snap_service import extract_sid, _strip_pod_prefix
    assert extract_sid(_strip_pod_prefix('pod-x86-0102::IEP_1_data')) == 'IEP'
    assert extract_sid(_strip_pod_prefix('pod-x86-0102::IEP_1_log')) == 'IEP'
    assert extract_sid(_strip_pod_prefix(
        'pod-x86-0102::IEP_1_data.HDBSNAP-2026-03-18-002003'
    )) == 'IEP'


def test_extract_sid_pod_oracle_stripped():
    """SID extracted from pod-stripped Oracle vg-prefixed volume names."""
    from app.snap_service import extract_sid, _strip_pod_prefix
    assert extract_sid(_strip_pod_prefix('pod-aix-0102::vgIQP_1')) == 'IQP'
    assert extract_sid(_strip_pod_prefix('pod-aix-0102::vgIQP_1.2026-03-19-124002')) == 'IQP'


# ---------------------------------------------------------------------------
# _collect_flasharray_snapshots: pod-based snapshot integration tests
# ---------------------------------------------------------------------------

def _make_mock_system(name='fa01'):
    from unittest.mock import MagicMock
    sys = MagicMock()
    sys.name = name
    sys.vendor = 'pure'
    sys.ip_address = '1.2.3.4'
    sys.port = None
    sys.api_username = 'admin'
    sys.api_password = 'secret'
    sys.api_token = 'token'
    return sys


def test_collect_flasharray_pod_hana_snaps():
    """Pod-prefixed HANA snapshots (data + log LUN) yield SID = IEP, TTL from suffix."""
    from app.snap_service import _collect_flasharray_snapshots
    from unittest.mock import patch, MagicMock

    api_snaps = [
        {
            'name': 'pod-x86-0102::IEP_1_data.HDBSNAP-2026-03-18-002003',
            'suffix': 'HDBSNAP-2026-03-18-002003',
            'source_name': 'pod-x86-0102::IEP_1_data',
            'created': '2026-03-18T00:21:06Z',
        },
        {
            'name': 'pod-x86-0102::IEP_1_log.HDBSNAP-2026-03-18-002003',
            'suffix': 'HDBSNAP-2026-03-18-002003',
            'source_name': 'pod-x86-0102::IEP_1_log',
            'created': '2026-03-18T00:21:06Z',
        },
    ]
    mock_client = MagicMock()
    mock_client.get_volume_snapshots.return_value = api_snaps

    with patch('app.api.get_client', return_value=mock_client):
        result = _collect_flasharray_snapshots(_make_mock_system())

    assert len(result) == 2
    assert all(r['sid'] == 'IEP' for r in result)
    # Full name (with pod prefix) preserved for API calls / display
    names = {r['snapshot_name'] for r in result}
    assert 'pod-x86-0102::IEP_1_data.HDBSNAP-2026-03-18-002003' in names
    assert 'pod-x86-0102::IEP_1_log.HDBSNAP-2026-03-18-002003' in names
    # TTL extracted from suffix
    assert all(r['ttl'] is not None for r in result)
    assert result[0]['ttl'].strftime('%Y-%m-%d-%H%M%S') == '2026-03-18-002003'


def test_collect_flasharray_pod_oracle_snaps():
    """Pod-prefixed Oracle snapshots (vg-prefix, no HDBSNAP) yield SID = IQP."""
    from app.snap_service import _collect_flasharray_snapshots
    from unittest.mock import patch, MagicMock

    api_snaps = [
        {
            'name': 'pod-aix-0102::vgIQP_1.2026-03-19-124002',
            'suffix': '2026-03-19-124002',
            'source_name': 'pod-aix-0102::vgIQP_1',
            'created': '2026-03-19T12:40:12Z',
        },
    ]
    mock_client = MagicMock()
    mock_client.get_volume_snapshots.return_value = api_snaps

    with patch('app.api.get_client', return_value=mock_client):
        result = _collect_flasharray_snapshots(_make_mock_system())

    assert len(result) == 1
    assert result[0]['sid'] == 'IQP'
    assert result[0]['snapshot_name'] == 'pod-aix-0102::vgIQP_1.2026-03-19-124002'
    assert result[0]['ttl'] is not None
    assert result[0]['ttl'].strftime('%Y-%m-%d-%H%M%S') == '2026-03-19-124002'


def test_collect_flasharray_skips_non_db_snaps():
    """Snapshots with no HDBSNAP and no recognisable SID pattern are skipped."""
    from app.snap_service import _collect_flasharray_snapshots
    from unittest.mock import patch, MagicMock

    api_snaps = [
        {
            'name': 'backup-infra-vol.snapshot-2026-03-18',
            'suffix': 'snapshot-2026-03-18',
            'source_name': 'backup-infra-vol',
            'created': '2026-03-18T00:00:00Z',
        },
    ]
    mock_client = MagicMock()
    mock_client.get_volume_snapshots.return_value = api_snaps

    with patch('app.api.get_client', return_value=mock_client):
        result = _collect_flasharray_snapshots(_make_mock_system())

    assert result == []


# ---------------------------------------------------------------------------
# _group_by_sid_and_time: ActiveCluster + multi-LUN tests
# ---------------------------------------------------------------------------

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


def test_group_by_sid_activecluster_both_arrays_in_locations():
    """ActiveCluster partner arrays both appear in storage_locations detail."""
    from app.snap_service import _group_by_sid_and_time

    ts = datetime(2026, 3, 18, 0, 20, 6)
    ttl = datetime(2026, 3, 18, 0, 20, 3)
    common = {'sid': 'IEP', 'creation_time': ts, 'ttl': ttl}

    # Both fa01 and fa02 (ActiveCluster pair) report data + log LUNs
    snaps = [
        {**common, 'snapshot_name': 'pod-x86-0102::IEP_1_data.HDBSNAP-2026-03-18-002003', 'array_name': 'fa01'},
        {**common, 'snapshot_name': 'pod-x86-0102::IEP_1_log.HDBSNAP-2026-03-18-002003',  'array_name': 'fa01'},
        {**common, 'snapshot_name': 'pod-x86-0102::IEP_1_data.HDBSNAP-2026-03-18-002003', 'array_name': 'fa02'},
        {**common, 'snapshot_name': 'pod-x86-0102::IEP_1_log.HDBSNAP-2026-03-18-002003',  'array_name': 'fa02'},
    ]

    result = _group_by_sid_and_time(snaps, [])
    # One list entry for the logical snapshot
    assert len(result) == 1
    assert result[0]['sid'] == 'IEP'

    locs = json.loads(result[0]['storage_locations'])
    fa_systems = {s['name']: s['snapshot_names'] for s in locs['flasharray_systems']}

    # Both ActiveCluster members appear in the detail
    assert 'fa01' in fa_systems
    assert 'fa02' in fa_systems
    # Both LUNs listed under each array
    assert len(fa_systems['fa01']) == 2
    assert len(fa_systems['fa02']) == 2


def test_group_by_sid_pod_hana_multi_lun_one_record():
    """HANA pod snaps: data + log LUNs with same SID+minute → one record, two snap names."""
    from app.snap_service import _group_by_sid_and_time

    ts = datetime(2026, 3, 18, 0, 20, 6)
    ttl = datetime(2026, 3, 18, 0, 20, 3)
    snaps = [
        {
            'sid': 'IEP',
            'snapshot_name': 'pod-x86-0102::IEP_1_data.HDBSNAP-2026-03-18-002003',
            'creation_time': ts, 'ttl': ttl, 'array_name': 'fa01',
        },
        {
            'sid': 'IEP',
            'snapshot_name': 'pod-x86-0102::IEP_1_log.HDBSNAP-2026-03-18-002003',
            'creation_time': ts, 'ttl': ttl, 'array_name': 'fa01',
        },
    ]

    result = _group_by_sid_and_time(snaps, [])
    assert len(result) == 1

    locs = json.loads(result[0]['storage_locations'])
    snap_names = locs['flasharray_systems'][0]['snapshot_names']
    assert len(snap_names) == 2
    assert 'pod-x86-0102::IEP_1_data.HDBSNAP-2026-03-18-002003' in snap_names
    assert 'pod-x86-0102::IEP_1_log.HDBSNAP-2026-03-18-002003' in snap_names


def test_group_by_sid_pod_oracle_one_record():
    """Oracle pod snap: single LUN per snapshot, correct SID and TTL."""
    from app.snap_service import _group_by_sid_and_time

    ts = datetime(2026, 3, 19, 12, 40, 12)
    ttl = datetime(2026, 3, 19, 12, 40, 2)
    snap = {
        'sid': 'IQP',
        'snapshot_name': 'pod-aix-0102::vgIQP_1.2026-03-19-124002',
        'creation_time': ts, 'ttl': ttl, 'array_name': 'fa01',
    }

    result = _group_by_sid_and_time([snap], [])
    assert len(result) == 1
    assert result[0]['sid'] == 'IQP'
    locs = json.loads(result[0]['storage_locations'])
    assert locs['flasharray_systems'][0]['snapshot_names'] == ['pod-aix-0102::vgIQP_1.2026-03-19-124002']



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


def test_group_by_sid_oracle_ttl_index_match():
    """Oracle FA+ONTAP snaps with same TTL but different creation_time → one record.

    Oracle snapshots embed the expiry date (TTL) in the snapshot name, not the
    creation time.  As a result, the FA record is keyed by creation_time_minute
    while the ONTAP snap carries the same TTL but a different (potentially
    timezone-shifted) creation_time.  The secondary TTL index must bridge this
    gap and yield a single merged record.
    """
    from app.snap_service import _group_by_sid_and_time

    ttl = datetime(2026, 3, 20, 17, 15, 51)  # expiry date – same for both
    fa_creation = datetime(2026, 3, 16, 16, 15, 58)   # UTC creation time on FA
    # ONTAP creation_time is 1 hour later (CET already normalised to UTC here;
    # the raw CET offset is corrected in _collect_ontap_snapshots before this
    # function is called – so both values are already UTC-naive).
    ontap_creation = datetime(2026, 3, 16, 16, 16, 3)

    fa_snap = {
        'sid': 'A4P',
        'snapshot_name': 'pod-x86-1112::vgA4P_1.2026-03-20-171551',
        'creation_time': fa_creation,
        'ttl': ttl,
        'array_name': 'pure12',
    }
    ontap_snap = {
        'sid': 'A4P',
        'snapshot_name': 'A4P.2026-03-20-171551',
        'creation_time': ontap_creation,
        'ttl': ttl,
        'cluster_name': 'FASMC1',
        'svm_name': 'nfs01',
        'volume_name': 'ORA_A4P',
    }

    result = _group_by_sid_and_time([fa_snap], [ontap_snap])
    # Must produce exactly ONE merged record, not two separate ones
    assert len(result) == 1, (
        f"Expected 1 merged record, got {len(result)}: {result}"
    )
    rec = result[0]
    assert rec['sid'] == 'A4P'
    assert rec['flasharray_present'] is True
    assert rec['ontap_present'] is True
    assert rec['ttl'] == ttl

    locs = json.loads(rec['storage_locations'])
    assert len(locs['flasharray_systems']) == 1
    assert locs['flasharray_systems'][0]['name'] == 'pure12'
    assert len(locs['ontap_clusters']) == 1
    assert locs['ontap_clusters'][0]['cluster'] == 'FASMC1'


def test_group_by_sid_oracle_two_fa_arrays_and_ontap():
    """Oracle: ActiveCluster (two FA arrays) + ONTAP → one merged record."""
    from app.snap_service import _group_by_sid_and_time

    ttl = datetime(2026, 3, 20, 17, 15, 51)
    fa_creation = datetime(2026, 3, 16, 16, 15, 58)
    ontap_creation = datetime(2026, 3, 16, 16, 16, 3)

    common_fa = {
        'sid': 'A4P',
        'snapshot_name': 'pod-x86-1112::vgA4P_1.2026-03-20-171551',
        'creation_time': fa_creation,
        'ttl': ttl,
    }
    fa_snaps = [
        {**common_fa, 'array_name': 'pure11'},
        {**common_fa, 'array_name': 'pure12'},
    ]
    ontap_snap = {
        'sid': 'A4P',
        'snapshot_name': 'A4P.2026-03-20-171551',
        'creation_time': ontap_creation,
        'ttl': ttl,
        'cluster_name': 'FASMC1',
        'svm_name': 'nfs01',
        'volume_name': 'ORA_A4P',
    }

    result = _group_by_sid_and_time(fa_snaps, [ontap_snap])
    assert len(result) == 1, f"Expected 1 record, got {len(result)}"
    rec = result[0]
    assert rec['flasharray_present'] is True
    assert rec['ontap_present'] is True

    locs = json.loads(rec['storage_locations'])
    fa_names = {s['name'] for s in locs['flasharray_systems']}
    assert fa_names == {'pure11', 'pure12'}
    assert len(locs['ontap_clusters']) == 1


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


def test_do_collect_skips_snaps_disabled_systems(app):
    """_do_collect must not query systems where snaps_enabled=False."""
    from app import db
    from app.models import StorageSystem
    from unittest.mock import patch

    with app.app_context():
        sys_on = StorageSystem(
            name='sys-snaps-on', vendor='pure', ip_address='1.2.3.4',
            enabled=True, snaps_enabled=True,
        )
        sys_off = StorageSystem(
            name='sys-snaps-off', vendor='pure', ip_address='1.2.3.5',
            enabled=True, snaps_enabled=False,
        )
        db.session.add_all([sys_on, sys_off])
        db.session.commit()

    queried_names = []

    def mock_collect(system):
        queried_names.append(system.name)
        return {'system_id': system.id, 'system_name': system.name,
                'vendor': system.vendor, 'flasharray_snaps': [], 'ontap_snaps': []}

    with patch('app.snap_service._collect_system_snapshots', side_effect=mock_collect):
        from app.snap_service import _do_collect
        _do_collect(app)

    assert 'sys-snaps-on' in queried_names
    assert 'sys-snaps-off' not in queried_names


def test_do_collect_includes_snaps_enabled_null_systems(app):
    """_do_collect must query systems where snaps_enabled IS NULL (legacy rows).

    When the snaps_enabled column is added via ALTER TABLE to an existing
    database, rows that pre-date the column receive NULL.  These systems should
    behave as if snaps_enabled=True (the model-level default), so the collector
    must not skip them.
    """
    from app import db
    from app.models import StorageSystem
    from unittest.mock import patch
    import sqlalchemy as sa

    with app.app_context():
        sys_null = StorageSystem(
            name='sys-snaps-null', vendor='pure', ip_address='1.2.3.6',
            enabled=True, snaps_enabled=True,
        )
        db.session.add(sys_null)
        db.session.commit()
        # Force snaps_enabled to NULL at the SQL level to simulate a migrated row
        db.session.execute(
            sa.text("UPDATE storage_systems SET snaps_enabled = NULL WHERE name = 'sys-snaps-null'")
        )
        db.session.commit()

    queried_names = []

    def mock_collect(system):
        queried_names.append(system.name)
        return {'system_id': system.id, 'system_name': system.name,
                'vendor': system.vendor, 'flasharray_snaps': [], 'ontap_snaps': []}

    with patch('app.snap_service._collect_system_snapshots', side_effect=mock_collect):
        from app.snap_service import _do_collect
        _do_collect(app)

    assert 'sys-snaps-null' in queried_names, (
        "Systems with snaps_enabled=NULL must be included in snapshot collection"
    )


# ---------------------------------------------------------------------------
# Bug fix: FlashArray epoch-ms timestamp handling
# ---------------------------------------------------------------------------

def test_collect_fa_snaps_epoch_ms_created():
    """_collect_flasharray_snapshots must handle integer epoch-ms 'created' field.

    The Pure Storage REST API returns ``created`` as an int64 millisecond
    timestamp.  Before the fix, calling ``.replace()`` on the integer caused
    an AttributeError which silently returned [].
    """
    from unittest.mock import MagicMock, patch
    from app.snap_service import _collect_flasharray_snapshots

    # Simulate what PureStorageClient.get_volume_snapshots() now returns after
    # the epoch-ms → ISO conversion fix.
    mock_raw = [
        {
            'name': 'ABP_data.HDBSNAP-2026-03-13-073434',
            'created': '2026-03-13T07:34:34Z',   # already converted to ISO string
            'suffix': 'HDBSNAP-2026-03-13-073434',
            'source_name': 'ABP_data',
        },
    ]

    system = MagicMock()
    system.vendor = 'pure'
    system.name = 'fa01'

    with patch('app.api.get_client') as mock_get_client:
        mock_client = MagicMock()
        mock_client.get_volume_snapshots.return_value = mock_raw
        mock_get_client.return_value = mock_client

        result = _collect_flasharray_snapshots(system)

    assert len(result) == 1
    snap = result[0]
    assert snap['sid'] == 'ABP'
    assert snap['ttl'] is not None
    assert snap['ttl'].year == 2026
    assert snap['ttl'].month == 3
    assert snap['ttl'].day == 13
    assert snap['creation_time'] is not None
    assert snap['array_name'] == 'fa01'


def test_collect_fa_snaps_sid_from_source_name():
    """SID is extracted from source_name when snapshot name alone gives no SID.

    If the Pure Storage API returns only the bare suffix as the snapshot name
    (e.g. ``HDBSNAP-2026-03-13-073434`` without a volume prefix), the SID
    regex finds no match.  The fallback to ``source_name`` (e.g. ``ABP_data``)
    must then yield the correct SID "ABP".
    """
    from unittest.mock import MagicMock, patch
    from app.snap_service import _collect_flasharray_snapshots

    mock_raw = [
        {
            # Bare suffix as name: _SID_RE won't match because there is no
            # 3-5 uppercase char block followed by '_' or '.' at the start.
            'name': 'HDBSNAP-2026-03-13-073434',
            'created': '2026-03-13T07:34:34Z',
            'suffix': 'HDBSNAP-2026-03-13-073434',
            'source_name': 'ABP_data',   # SID extracted here as fallback
        },
    ]

    system = MagicMock()
    system.vendor = 'pure'
    system.name = 'fa01'

    with patch('app.api.get_client') as mock_get_client:
        mock_client = MagicMock()
        mock_client.get_volume_snapshots.return_value = mock_raw
        mock_get_client.return_value = mock_client

        result = _collect_flasharray_snapshots(system)

    assert len(result) == 1
    assert result[0]['sid'] == 'ABP'


def test_collect_fa_snaps_ttl_from_suffix():
    """TTL is extracted from the 'suffix' field (primary source)."""
    from unittest.mock import MagicMock, patch
    from app.snap_service import _collect_flasharray_snapshots

    mock_raw = [
        {
            'name': 'ABP_data.HDBSNAP-2026-04-01-120000',
            'created': '2026-03-01T00:00:00Z',
            'suffix': 'HDBSNAP-2026-04-01-120000',
            'source_name': 'ABP_data',
        },
    ]

    system = MagicMock()
    system.vendor = 'pure'
    system.name = 'fa01'

    with patch('app.api.get_client') as mock_get_client:
        mock_client = MagicMock()
        mock_client.get_volume_snapshots.return_value = mock_raw
        mock_get_client.return_value = mock_client

        result = _collect_flasharray_snapshots(system)

    assert len(result) == 1
    ttl = result[0]['ttl']
    assert ttl.year == 2026 and ttl.month == 4 and ttl.day == 1
    assert ttl.hour == 12 and ttl.minute == 0


# ---------------------------------------------------------------------------
# ONTAP volume allow-list filtering
# ---------------------------------------------------------------------------

def test_collect_ontap_snaps_only_hana_ora_volumes():
    """_collect_ontap_snapshots must only process HANA_ and ORA_ volumes.

    Covers the full matrix of volumes that must be excluded:
      - nfs03_root           → NFS root volume, SID would be "NFS03"
      - old_trident_pvc_*    → renamed Trident PVCs, SID would be "OLD"
      - trident_pvc_*        → active Trident PVCs, SID would be "CLONE" etc.
      - infrastr_vol01       → infrastructure volume, no relevant SID

    And the volumes that must be included:
      - HANA_ABP             → SID ABP
      - ORA_WQ4              → SID WQ4
    """
    from unittest.mock import MagicMock, patch
    from app.snap_service import _collect_ontap_snapshots

    mock_raw = [
        # Must be included
        {'name': 'ABP_HDBSNAP-2026-03-13-193449', 'create_time': '2026-03-13T19:34:49Z',
         'volume': 'HANA_ABP', 'svm': 'svm1', 'cluster': 'FASMC1'},
        {'name': 'ORA_WQ4_snap1', 'create_time': '2026-03-16T11:13:12Z',
         'volume': 'ORA_WQ4', 'svm': 'svm1', 'cluster': 'FASMC1'},
        # Must be excluded – NFS root volume
        {'name': 'nfs03_root_snap', 'create_time': '2026-03-16T00:25:04Z',
         'volume': 'nfs03_root', 'svm': 'svm1', 'cluster': 'FASMC1'},
        # Must be excluded – renamed old Trident PVCs
        {'name': 'snap1', 'create_time': '2025-02-18T20:18:13Z',
         'volume': 'old_trident_pvc_influxdb', 'svm': 'svm1', 'cluster': 'FASMC1'},
        {'name': 'snap2', 'create_time': '2025-02-18T20:18:13Z',
         'volume': 'old_trident_pvc_old', 'svm': 'svm1', 'cluster': 'FASMC1'},
        {'name': 'snap3', 'create_time': '2025-02-18T20:18:13Z',
         'volume': 'old_trident_pvc_navida', 'svm': 'svm1', 'cluster': 'FASMC1'},
        # Must be excluded – active Trident PVCs
        {'name': 'CLONE_20250218201813', 'create_time': '2025-02-18T20:18:13Z',
         'volume': 'trident_pvc_ca7f7c70_d4d5_4fdb_8a84_b14d0e3f4be6',
         'svm': 'svm1', 'cluster': 'FASMC1'},
        # Must be excluded – unrelated infrastructure volume
        {'name': 'infra_snap', 'create_time': '2026-03-16T00:00:00Z',
         'volume': 'infrastr_vol01', 'svm': 'svm1', 'cluster': 'FASMC1'},
    ]

    system = MagicMock()
    system.vendor = 'netapp-ontap'
    system.name = 'FASMC1'

    with patch('app.api.get_client') as mock_get_client:
        mock_client = MagicMock()
        mock_client.get_volume_snapshots.return_value = mock_raw
        mock_get_client.return_value = mock_client
        result = _collect_ontap_snapshots(system)

    sids = [r['sid'] for r in result]
    volumes = [r['volume_name'] for r in result]

    # Correct snapshots present
    assert 'ABP' in sids, "HANA_ABP snapshot must be included"
    assert 'WQ4' in sids, "ORA_WQ4 snapshot must be included"

    # Bad SIDs must not appear
    for bad in ('NFS03', 'OLD', 'CLONE'):
        assert bad not in sids, f"Volume producing spurious SID '{bad}' must be excluded"

    # Exact count: only the two DB volumes
    assert len(result) == 2

    # Correct SID extracted from ORA_ prefix
    ora_result = next(r for r in result if r['volume_name'] == 'ORA_WQ4')
    assert ora_result['sid'] == 'WQ4', "SID must be WQ4, not ORA"


def test_collect_ontap_snaps_excludes_trident_volumes():
    """_collect_ontap_snapshots excludes trident_pvc_* volumes (superseded by allow-list).

    Kept for regression: Trident PVC volumes are not in the HANA_/ORA_ allow-list
    so they are excluded automatically.
    """
    from unittest.mock import MagicMock, patch
    from app.snap_service import _collect_ontap_snapshots

    mock_raw = [
        {'name': 'ABP_HDBSNAP-2026-03-13-193449', 'create_time': '2026-03-13T19:34:49Z',
         'volume': 'HANA_ABP', 'svm': 'svm1', 'cluster': 'FASMC1'},
        {'name': 'CLONE_20250218201813', 'create_time': '2025-02-18T20:18:13Z',
         'volume': 'trident_pvc_ca7f7c70_d4d5_4fdb_8a84_b14d0e3f4be6',
         'svm': 'svm1', 'cluster': 'FASMC1'},
        {'name': 'CLONE_20250218201813', 'create_time': '2025-02-18T20:18:13Z',
         'volume': 'trident_pvc_bc348446_2d9e_4fb5_96f4_e8027bd023a3_2810',
         'svm': 'svm1', 'cluster': 'FASMC1'},
    ]

    system = MagicMock()
    system.vendor = 'netapp-ontap'
    system.name = 'FASMC1'

    with patch('app.api.get_client') as mock_get_client:
        mock_client = MagicMock()
        mock_client.get_volume_snapshots.return_value = mock_raw
        mock_get_client.return_value = mock_client
        result = _collect_ontap_snapshots(system)

    sids = [r['sid'] for r in result]
    assert 'CLONE' not in sids, "Trident PVC clone snapshot must be excluded"
    assert 'ABP' in sids, "Legitimate HANA snapshot must be included"
    assert len(result) == 1


def test_collect_ontap_snaps_creation_time_utc_normalisation():
    """ONTAP create_time with a non-UTC offset is normalised to UTC.

    The ONTAP REST API returns timestamps with the local timezone offset
    (e.g. +01:00 for CET).  The collector must convert to UTC before storing,
    so that creation_time is comparable with FlashArray timestamps (which are
    always UTC).

    CET = UTC+1: 2026-03-16T17:16:03+01:00 → 2026-03-16T16:16:03 UTC
    """
    from unittest.mock import MagicMock, patch
    from app.snap_service import _collect_ontap_snapshots

    mock_raw = [
        {
            'name': 'A4P.2026-03-20-171551',
            'create_time': '2026-03-16T17:16:03+01:00',   # CET timestamp
            'volume': 'ORA_A4P',
            'svm': 'nfs01',
            'cluster': 'FASMC1',
        },
    ]

    system = MagicMock()
    system.vendor = 'netapp-ontap'
    system.name = 'FASMC1'

    with patch('app.api.get_client') as mock_get_client:
        mock_client = MagicMock()
        mock_client.get_volume_snapshots.return_value = mock_raw
        mock_get_client.return_value = mock_client
        result = _collect_ontap_snapshots(system)

    assert len(result) == 1
    ct = result[0]['creation_time']
    assert ct is not None
    # After UTC normalisation, the hour must be 16, not 17
    assert ct.hour == 16, (
        f"creation_time {ct} should be UTC 16:16:03, not CET 17:16:03"
    )
    assert ct.minute == 16


def test_get_volume_snapshots_converts_epoch_ms():
    """PureStorageClient.get_volume_snapshots must convert epoch-ms to ISO string."""
    from app.api.storage_clients import PureStorageClient
    from unittest.mock import MagicMock, patch

    client = PureStorageClient('fa01', 443, None, None, 'fake-token')

    # epoch_ms for 2026-03-13T07:34:34Z
    epoch_ms = 1773387274000

    api_response = {
        'items': [
            {
                'name': 'ABP_data.HDBSNAP-2026-03-13-073434',
                'created': epoch_ms,
                'suffix': 'HDBSNAP-2026-03-13-073434',
                'source': {'id': 'abc', 'name': 'ABP_data'},
            }
        ],
        'continuation_token': None,
    }

    with patch.object(client, 'detect_api_version', return_value='2.26'), \
         patch.object(client, 'authenticate', return_value='session-token'):

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = api_response

        mock_resp2 = MagicMock()
        mock_resp2.status_code = 200
        mock_resp2.json.return_value = {'items': [], 'continuation_token': None}

        mock_logout = MagicMock()
        mock_logout.status_code = 200

        with patch('app.api.storage_clients._local_session') as mock_session:
            mock_session.get.side_effect = [mock_resp, mock_resp2]
            mock_session.post.return_value = mock_logout

            results = client.get_volume_snapshots()

    assert len(results) == 1
    snap = results[0]
    # created must be an ISO string, not an integer
    assert isinstance(snap['created'], str), "created must be an ISO string"
    assert '2026-03-13' in snap['created']
    assert snap['suffix'] == 'HDBSNAP-2026-03-13-073434'
    assert snap['source_name'] == 'ABP_data'


def test_get_volume_snapshots_filters_destroyed():
    """PureStorageClient.get_volume_snapshots must request destroyed=false."""
    from app.api.storage_clients import PureStorageClient
    from unittest.mock import MagicMock, patch

    client = PureStorageClient('fa01', 443, None, None, 'fake-token')

    with patch.object(client, 'detect_api_version', return_value='2.26'), \
         patch.object(client, 'authenticate', return_value='session-token'):

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'items': [], 'continuation_token': None}

        mock_logout = MagicMock()
        mock_logout.status_code = 200

        with patch('app.api.storage_clients._local_session') as mock_session:
            mock_session.get.return_value = mock_resp
            mock_session.post.return_value = mock_logout

            client.get_volume_snapshots()

        params = mock_session.get.call_args.kwargs.get('params', {})
        assert params.get('destroyed') == 'false', \
            "API call must include destroyed=false to exclude pending-eradication snapshots"


def test_build_rename_curl_uses_correct_patch_format():
    """_build_rename_curl_commands must use the correct Pure Storage PATCH format.

    Per api/pure_swagger.json:
      PATCH /api/<ver>/volume-snapshots?names=<full_name>
      Body: {"name": "<new_suffix>"}  ← suffix only, not the full VOL.SUFFIX name
    """
    from app.routes.snaps import _build_rename_curl_commands
    from unittest.mock import MagicMock

    rec = MagicMock()
    rec.sid = 'ABP'

    locs = {
        'flasharray_systems': [
            {
                'name': 'fa01',
                'snapshot_names': ['ABP_data.HDBSNAP-2026-03-13-073434'],
            }
        ],
        'ontap_clusters': [],
    }

    new_ts = '2026-04-01-120000'
    commands = _build_rename_curl_commands(rec, locs, new_ts)

    assert len(commands) == 1
    cmd = commands[0]
    assert cmd['platform'] == 'FlashArray'
    # Must include authentication step (Step 0)
    assert '/login' in cmd['command'], "Command must include login/auth step"
    assert 'api-token' in cmd['command'], "Login step must reference api-token"
    assert 'x-auth-token' in cmd['command'], "Command must use x-auth-token header"
    # URL must use ?names= query parameter, not /id path segment
    assert '?names=' in cmd['command'], "PATCH must use ?names= query param"
    # Body must contain only the new suffix (not the full VOL.SUFFIX name)
    assert '"HDBSNAP-2026-04-01-120000"' in cmd['command'], \
        "PATCH body must set the new suffix"
    # The suffix must NOT be prefixed with 'ABP_data.' in the body
    assert '"ABP_data.HDBSNAP' not in cmd['command'], \
        "PATCH body must contain suffix only, not full snapshot name"
    # Old name should be in the URL query parameter
    assert 'HDBSNAP-2026-03-13-073434' in cmd['command'], \
        "Old snapshot name must appear in the ?names= parameter"


def test_build_rename_curl_oracle_plain_timestamp():
    """_build_rename_curl_commands handles Oracle VG snapshots (plain timestamp suffix).

    Oracle FlashArray snapshots use a plain YYYY-MM-DD-HHmmss suffix without the
    HDBSNAP- prefix, e.g. ``pod-x86-0304::vgA4T_1.2026-03-22-073617``.
    The PATCH body must contain the NEW plain timestamp as the suffix,
    NOT the old timestamp (which would be a no-op rename).
    """
    from app.routes.snaps import _build_rename_curl_commands
    from unittest.mock import MagicMock

    rec = MagicMock()
    rec.sid = 'A4T'

    locs = {
        'flasharray_systems': [
            {
                'name': 'pure04',
                'snapshot_names': ['pod-x86-0304::vgA4T_1.2026-03-22-073617'],
            }
        ],
        'ontap_clusters': [],
    }

    new_ts = '2026-04-15-120000'
    commands = _build_rename_curl_commands(rec, locs, new_ts)

    assert len(commands) == 1
    cmd = commands[0]
    assert cmd['platform'] == 'FlashArray'
    assert cmd['array'] == 'pure04'

    # Must include authentication step
    assert '/login' in cmd['command'], "Command must include login/auth step"
    assert 'api-token' in cmd['command'], "Login step must reference api-token"
    assert 'x-auth-token' in cmd['command'], "Command must use x-auth-token header"

    # Old snapshot name must appear in the ?names= URL parameter
    assert 'pod-x86-0304::vgA4T_1.2026-03-22-073617' in cmd['command'], \
        "Old snapshot name must appear in the ?names= parameter"

    # PATCH body must set the NEW plain timestamp (no HDBSNAP- prefix)
    assert '"2026-04-15-120000"' in cmd['command'], \
        "PATCH body must contain the new plain timestamp suffix"

    # Body must NOT still contain the old timestamp (that would be a no-op)
    assert '"2026-03-22-073617"' not in cmd['command'], \
        "PATCH body must not contain the old timestamp (rename would be a no-op)"

    # Body must NOT gain a spurious HDBSNAP- prefix
    assert '"HDBSNAP-2026-04-15-120000"' not in cmd['command'], \
        "PATCH body must not add HDBSNAP- prefix for Oracle snapshots"

    # new_name field must also reflect the updated name
    assert cmd['new_name'] == 'pod-x86-0304::vgA4T_1.2026-04-15-120000'


    """_build_rename_curl_commands emits one ONTAP command per volume.

    The popup must show a command for every affected ONTAP volume so the
    operator can copy the correct curl call.  Each command must:
      - show the volume name in the platform label (returned as 'volume' key)
      - include both a GET (find snapshot UUID) and a PATCH (rename) step
      - set the new snapshot name and expiry_time
    """
    from app.routes.snaps import _build_rename_curl_commands
    from unittest.mock import MagicMock
    from datetime import datetime

    rec = MagicMock()
    rec.sid = 'ABP'
    rec.ttl = datetime(2026, 3, 13, 19, 3, 49)   # old TTL → 2026-03-13-190349

    locs = {
        'flasharray_systems': [],
        'ontap_clusters': [
            {
                'cluster': 'FASMC1',
                'svm': 'nfs01',
                'volumes': ['HANA_ABP', 'HANA_ABP_log', 'HANA_ABP_data'],
            }
        ],
    }

    new_ts = '2026-04-01-190349'
    commands = _build_rename_curl_commands(rec, locs, new_ts)

    # Must produce one command per volume
    assert len(commands) == 3
    vols = [c['volume'] for c in commands]
    assert vols == ['HANA_ABP', 'HANA_ABP_log', 'HANA_ABP_data']

    for cmd in commands:
        assert cmd['platform'] == 'ONTAP'
        assert cmd['cluster'] == 'FASMC1'
        assert cmd['svm'] == 'nfs01'
        # Must contain find step (GET)
        assert 'HDBSNAP-2026-03-13-190349' in cmd['command'], \
            "Command must reference the old TTL pattern to find the snapshot UUID"
        # Must contain rename step (PATCH) with new name and expiry_time
        assert 'ABP_HDBSNAP-2026-04-01-190349' in cmd['command'], \
            "Command must set the new snapshot name"
        assert '2026-04-01T19:03:49Z' in cmd['command'], \
            "Command must set expiry_time in ISO format"


def test_build_delete_curl_ontap_per_volume():
    """_build_delete_curl_commands emits one ONTAP command per volume.

    The popup must show delete commands for every affected ONTAP volume.
    """
    from app.routes.snaps import _build_delete_curl_commands
    from unittest.mock import MagicMock
    from datetime import datetime

    rec = MagicMock()
    rec.sid = 'ABP'
    rec.ttl = datetime(2026, 3, 17, 19, 1, 19)   # TTL → 2026-03-17-190119

    locs = {
        'flasharray_systems': [],
        'ontap_clusters': [
            {
                'cluster': 'FASMC1',
                'svm': 'nfs01',
                'volumes': ['HANA_ABP', 'HANA_ABP_log'],
            }
        ],
    }

    commands = _build_delete_curl_commands(rec, locs)

    assert len(commands) == 2
    vols = [c['volume'] for c in commands]
    assert vols == ['HANA_ABP', 'HANA_ABP_log']

    for cmd in commands:
        assert cmd['platform'] == 'ONTAP'
        # Must contain find step referencing current TTL
        assert 'HDBSNAP-2026-03-17-190119' in cmd['command'], \
            "Delete command must search by current TTL pattern"
        # Must contain DELETE step
        assert 'DELETE' in cmd['command']


def test_delete_preview_endpoint(app, client):
    """GET /snaps/api/delete-preview returns CURL commands without modifying the DB."""
    from app import db
    from app.models import SnapshotRecord
    import json
    from datetime import datetime

    with app.app_context():
        rec = SnapshotRecord(
            sid='ABP',
            creation_time=datetime(2026, 3, 13, 19, 3, 49),
            ttl=datetime(2026, 3, 17, 19, 1, 19),
            flasharray_present=True,
            ontap_present=True,
            storage_locations=json.dumps({
                'flasharray_systems': [
                    {'name': 'fa01', 'snapshot_names': ['ABP_data.HDBSNAP-2026-03-17-190119']}
                ],
                'ontap_clusters': [
                    {'cluster': 'FASMC1', 'svm': 'nfs01', 'volumes': ['HANA_ABP']}
                ],
            }),
        )
        db.session.add(rec)
        db.session.commit()
        snap_id = rec.id

    resp = client.post('/snaps/api/delete-preview',
                       data=json.dumps({'id': snap_id}),
                       content_type='application/json')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True

    cmds = data['curl_commands']
    platforms = [c['platform'] for c in cmds]

    # Both platforms present
    assert 'FlashArray' in platforms, "FlashArray delete command must be present"
    assert 'ONTAP' in platforms, "ONTAP delete command must be present"

    # FlashArray command has authentication step + destroy + eradicate steps
    fa_cmd = next(c for c in cmds if c['platform'] == 'FlashArray')
    assert '/login' in fa_cmd['command'], "FlashArray must include login/auth step"
    assert 'api-token' in fa_cmd['command'], "FlashArray login step must reference api-token"
    assert 'x-auth-token' in fa_cmd['command'], "FlashArray must include x-auth-token header"
    assert 'destroyed' in fa_cmd['command'], "FlashArray must include destroy step"
    assert 'DELETE' in fa_cmd['command'], "FlashArray must include eradicate step"

    # ONTAP command references volume name
    ontap_cmd = next(c for c in cmds if c['platform'] == 'ONTAP')
    assert ontap_cmd.get('volume') == 'HANA_ABP'
    assert 'DELETE' in ontap_cmd['command']

    # DB must NOT be modified
    with app.app_context():
        unchanged = SnapshotRecord.query.get(snap_id)
        assert unchanged.delete_marked is False
        assert unchanged.delete_deadline is None


def test_update_ttl_endpoint_includes_auth_step(app, client):
    """POST /snaps/api/update-ttl returns FlashArray curl commands with auth step.

    The FlashArray rename command must include:
      - Step 0: POST /login to obtain x-auth-token
      - Step 1: PATCH with x-auth-token header (not bare <token>)
    """
    from app import db
    from app.models import SnapshotRecord
    import json
    from datetime import datetime

    with app.app_context():
        rec = SnapshotRecord(
            sid='ABP',
            creation_time=datetime(2026, 3, 13, 19, 3, 49),
            ttl=datetime(2026, 3, 17, 19, 1, 19),
            flasharray_present=True,
            ontap_present=False,
            storage_locations=json.dumps({
                'flasharray_systems': [
                    {'name': 'pure04', 'snapshot_names': ['ABP_data.HDBSNAP-2026-03-17-190119']}
                ],
                'ontap_clusters': [],
            }),
        )
        db.session.add(rec)
        db.session.commit()
        snap_id = rec.id

    resp = client.post('/snaps/api/update-ttl',
                       data=json.dumps({'id': snap_id, 'new_ttl': '2026-04-01 19:01:19'}),
                       content_type='application/json')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True

    cmds = data['curl_commands']
    assert len(cmds) >= 1

    fa_cmd = next((c for c in cmds if c['platform'] == 'FlashArray'), None)
    assert fa_cmd is not None, "FlashArray rename command must be present"

    # Must include the login / auth step
    assert '/login' in fa_cmd['command'], "Command must include POST /login auth step"
    assert 'api-token' in fa_cmd['command'], "Login step must reference api-token"
    assert 'x-auth-token' in fa_cmd['command'], "PATCH step must use x-auth-token header"

    # PATCH rename step must reference the old snapshot name in the URL
    assert 'HDBSNAP-2026-03-17-190119' in fa_cmd['command'], \
        "Old snapshot name must appear in the PATCH ?names= parameter"
    # and the new timestamp in the body
    assert 'HDBSNAP-2026-04-01-190119' in fa_cmd['command'], \
        "New timestamp must appear in the PATCH body"

    # TTL must be updated in the DB
    with app.app_context():
        updated = SnapshotRecord.query.get(snap_id)
        assert updated.ttl == datetime(2026, 4, 1, 19, 1, 19)
