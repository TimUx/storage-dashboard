"""Tests for the /snaps module.

Covers:
1. SID extraction (extract_sid)
2. TTL extraction (extract_ttl)
3. Snapshot grouping / deduplication (_group_by_sid_and_time)
4. API endpoints: list, comment, delete (live), undo-delete, update-ttl (live)
5. Statistics calculation
6. Live execution streaming (delete & rename)
"""

import json
import os
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest


def _consume_ndjson(resp) -> list[dict]:
    """Decode an ndjson streaming response into a list of event dicts."""
    out = []
    for line in resp.get_data(as_text=True).splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


class _OkPureClient:
    """Stub Pure client whose snapshot operations succeed."""
    def rename_volume_snapshot(self, *a, **kw):
        return True, {'status_code': 200, 'text': '{"items":[]}'}

    def destroy_volume_snapshot(self, *a, **kw):
        return True, {'status_code': 200, 'text': '{"items":[]}'}


class _OkOntapClient:
    """Stub ONTAP client whose snapshot operations succeed."""
    def rename_volume_snapshot(self, *a, **kw):
        return True, {'status_code': 200, 'text': '', 'volume_uuid': 'vol-uuid', 'snap_uuid': 'snap-uuid'}

    def update_snapshot_expiry(self, *a, **kw):
        return True, {'status_code': 200, 'text': '', 'volume_uuid': 'vol-uuid', 'snap_uuid': 'snap-uuid'}

    def delete_volume_snapshot(self, *a, **kw):
        return True, {'status_code': 200, 'text': '', 'volume_uuid': 'vol-uuid', 'snap_uuid': 'snap-uuid'}


def _patch_storage_clients(monkey_pure=None, monkey_ontap=None):
    """Return patch context managers that swap the snaps route's client lookups.

    ``monkey_pure``/``monkey_ontap`` may be a client instance or ``None`` to
    use the default success stub.
    """
    pure_client = monkey_pure if monkey_pure is not None else _OkPureClient()
    ontap_client = monkey_ontap if monkey_ontap is not None else _OkOntapClient()
    return [
        patch('app.routes.snaps._get_pure_client',
              lambda name: (pure_client, None)),
        patch('app.routes.snaps._get_ontap_client',
              lambda name: (ontap_client, None)),
    ]


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
    """Helper to insert a SnapshotRecord.

    The TTL is placed far enough in the future that the 25-hour action-lock
    introduced by the snaps route does not kick in for the seeded record.
    Tests that explicitly want a "locked" snapshot use
    :func:`_seed_snapshot_with_ttl` instead.
    """
    from app import db
    from app.models import SnapshotRecord
    ct = datetime.utcnow() - timedelta(days=days_ago)
    # Keep the TTL ≥ 26h in the future so the action-lock (≤ 25h) does not
    # apply to records that the test does not specifically lock.
    ttl = datetime.utcnow() + timedelta(days=5)
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


def test_api_list_hides_absent_snapshots_without_comment(app, client):
    from app import db
    from app.models import SnapshotRecord

    rec = SnapshotRecord(
        sid='GONE',
        creation_time=datetime.utcnow() - timedelta(days=10),
        ttl=datetime.utcnow() - timedelta(days=1),
        flasharray_present=False,
        ontap_present=False,
        storage_locations=None,
    )
    with app.app_context():
        db.session.add(rec)
        db.session.commit()

    resp = client.get('/snaps/api/list')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['stats']['total'] == 0
    assert data['snapshots'] == []


def test_api_list_keeps_absent_snapshots_with_comment(app, client):
    from app import db
    from app.models import SnapshotRecord

    rec = SnapshotRecord(
        sid='NOTE',
        creation_time=datetime.utcnow() - timedelta(days=10),
        ttl=datetime.utcnow() - timedelta(days=1),
        flasharray_present=False,
        ontap_present=False,
        comment='Operator comment',
        storage_locations=None,
    )
    with app.app_context():
        db.session.add(rec)
        db.session.commit()

    resp = client.get('/snaps/api/list')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['stats']['total'] == 1
    assert len(data['snapshots']) == 1
    assert data['snapshots'][0]['sid'] == 'NOTE'


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


def _seed_snapshot_with_ttl(ctx, ttl: datetime, sid='LCK', days_ago=2):
    """Seed a SnapshotRecord with an explicit TTL value."""
    from app import db
    from app.models import SnapshotRecord
    ct = datetime.utcnow() - timedelta(days=days_ago)
    locs = json.dumps({
        'flasharray_systems': [{'name': 'fa01', 'snapshot_names': [f'{sid}_1.HDBSNAP']}],
        'ontap_clusters': [],
    })
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


def test_actions_lock_flag_in_list_for_short_ttl(app, client):
    """Snapshots with TTL ≤ 25h until expiry expose actions_locked=True."""
    snap_id = _seed_snapshot_with_ttl(
        app, datetime.utcnow() + timedelta(hours=10), sid='SOON',
    )
    data = client.get('/snaps/api/list').get_json()
    snap = next(s for s in data['snapshots'] if s['id'] == snap_id)
    assert snap['actions_locked'] is True
    assert snap['actions_lock_reason']
    assert data['stats']['actions_lock_hours'] == 25


def test_actions_lock_flag_false_for_long_ttl(app, client):
    """Snapshots with TTL well in the future are NOT locked."""
    snap_id = _seed_snapshot_with_ttl(
        app, datetime.utcnow() + timedelta(hours=72), sid='FREE',
    )
    data = client.get('/snaps/api/list').get_json()
    snap = next(s for s in data['snapshots'] if s['id'] == snap_id)
    assert snap['actions_locked'] is False
    assert snap['actions_lock_reason'] is None


def test_actions_lock_flag_true_for_already_expired_ttl(app, client):
    """An already-expired TTL also locks the row."""
    snap_id = _seed_snapshot_with_ttl(
        app, datetime.utcnow() - timedelta(hours=1), sid='EXP',
    )
    data = client.get('/snaps/api/list').get_json()
    snap = next(s for s in data['snapshots'] if s['id'] == snap_id)
    assert snap['actions_locked'] is True


def test_api_update_ttl_blocked_when_actions_locked(app, client):
    """update-ttl rejects a locked snapshot with HTTP 409."""
    snap_id = _seed_snapshot_with_ttl(
        app, datetime.utcnow() + timedelta(hours=10), sid='LOCK',
    )
    resp = client.post('/snaps/api/update-ttl',
                       json={'id': snap_id, 'new_ttl': '2099-12-31 00:00:00'},
                       content_type='application/json')
    assert resp.status_code == 409
    body = resp.get_json()
    assert body.get('actions_locked') is True
    assert 'gesperrt' in body['error'].lower()


def test_api_delete_blocked_when_actions_locked(app, client):
    """delete rejects a locked snapshot with HTTP 409 and does NOT mark it."""
    from app.models import SnapshotRecord

    snap_id = _seed_snapshot_with_ttl(
        app, datetime.utcnow() + timedelta(hours=10), sid='DLCK',
    )
    resp = client.post('/snaps/api/delete',
                       json={'id': snap_id},
                       content_type='application/json')
    assert resp.status_code == 409
    body = resp.get_json()
    assert body.get('actions_locked') is True

    with app.app_context():
        rec = SnapshotRecord.query.get(snap_id)
        assert rec is not None
        assert rec.delete_marked is False
        assert rec.delete_deadline is None


def test_api_delete_schedules_with_24h_deadline(app, client):
    """POST /snaps/api/delete schedules the deletion 24h ahead, no live execution."""
    snap_id = _seed_snapshot(app)

    before = datetime.utcnow()
    resp = client.post('/snaps/api/delete',
                       json={'id': snap_id},
                       content_type='application/json')
    after = datetime.utcnow()

    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert data['delete_planned'] is True
    assert 'delete_deadline' in data and data['delete_deadline']

    deadline = datetime.fromisoformat(data['delete_deadline'])
    # Allow a small tolerance so the test does not flake on slow runners.
    assert deadline >= before + timedelta(hours=24) - timedelta(seconds=2)
    assert deadline <= after + timedelta(hours=24) + timedelta(seconds=2)

    # Snapshot must still be present and marked for deletion.
    list_data = client.get('/snaps/api/list').get_json()
    snap = next(s for s in list_data['snapshots'] if s['id'] == snap_id)
    assert snap['delete_marked'] is True
    assert snap['delete_deadline']


def test_api_delete_drops_record_when_no_storage_steps(app, client):
    """A record with no storage locations is removed immediately on delete."""
    from app import db
    from app.models import SnapshotRecord

    with app.app_context():
        rec = SnapshotRecord(
            sid='ORPH',
            creation_time=datetime.utcnow() - timedelta(days=1),
            # TTL well outside the 25h action-lock window so the lock check
            # does not interfere with this scenario.
            ttl=datetime.utcnow() + timedelta(days=5),
            flasharray_present=False,
            ontap_present=False,
            comment='Stale row',
            storage_locations=json.dumps({'flasharray_systems': [], 'ontap_clusters': []}),
        )
        db.session.add(rec)
        db.session.commit()
        snap_id = rec.id

    resp = client.post('/snaps/api/delete',
                       json={'id': snap_id},
                       content_type='application/json')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert data['delete_planned'] is False

    with app.app_context():
        assert SnapshotRecord.query.get(snap_id) is None


def test_api_undo_delete_cancels_pending_deletion(app, client):
    """/api/undo-delete clears delete_marked and delete_deadline."""
    snap_id = _seed_snapshot(app)
    # Schedule first
    sched = client.post('/snaps/api/delete',
                        json={'id': snap_id},
                        content_type='application/json').get_json()
    assert sched['delete_planned'] is True

    resp = client.post('/snaps/api/undo-delete',
                       json={'id': snap_id},
                       content_type='application/json')
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True

    list_data = client.get('/snaps/api/list').get_json()
    snap = next(s for s in list_data['snapshots'] if s['id'] == snap_id)
    assert snap['delete_marked'] is False
    assert snap['delete_deadline'] is None


def test_process_expired_deletions_runs_storage_plan_when_due(app):
    """The collector worker executes the storage delete plan once the deadline expires."""
    from app import db
    from app.models import SnapshotRecord
    from app.snap_service import _process_expired_deletions

    snap_id = _seed_snapshot(app)
    with app.app_context():
        rec = SnapshotRecord.query.get(snap_id)
        rec.delete_marked = True
        rec.delete_deadline = datetime.utcnow() - timedelta(minutes=1)  # already due
        db.session.commit()

    pure = MagicMock()
    pure.destroy_volume_snapshot.return_value = (True, {'status_code': 200, 'text': ''})

    patches = _patch_storage_clients(monkey_pure=pure)
    for p in patches:
        p.start()
    try:
        _process_expired_deletions(app)
    finally:
        for p in patches:
            p.stop()

    # destroy_volume_snapshot must have been called for the seeded LUN.
    pure.destroy_volume_snapshot.assert_called()
    # Record must be removed from the DB.
    with app.app_context():
        assert SnapshotRecord.query.get(snap_id) is None


def test_process_expired_deletions_keeps_record_on_failure(app):
    """If a storage step fails the record is preserved for the next retry."""
    from app import db
    from app.models import SnapshotRecord
    from app.snap_service import _process_expired_deletions

    snap_id = _seed_snapshot(app)
    with app.app_context():
        rec = SnapshotRecord.query.get(snap_id)
        rec.delete_marked = True
        rec.delete_deadline = datetime.utcnow() - timedelta(minutes=1)
        db.session.commit()

    pure = MagicMock()
    pure.destroy_volume_snapshot.return_value = (
        False, {'status_code': 500, 'text': 'boom'}
    )
    patches = _patch_storage_clients(monkey_pure=pure)
    for p in patches:
        p.start()
    try:
        _process_expired_deletions(app)
    finally:
        for p in patches:
            p.stop()

    # Record must still be in the DB and still marked for deletion so the
    # next collection cycle retries.
    with app.app_context():
        rec = SnapshotRecord.query.get(snap_id)
        assert rec is not None
        assert rec.delete_marked is True


def test_process_expired_deletions_skips_records_not_yet_due(app):
    """Records whose deadline lies in the future must be left untouched."""
    from app import db
    from app.models import SnapshotRecord
    from app.snap_service import _process_expired_deletions

    snap_id = _seed_snapshot(app)
    with app.app_context():
        rec = SnapshotRecord.query.get(snap_id)
        rec.delete_marked = True
        rec.delete_deadline = datetime.utcnow() + timedelta(hours=1)  # not yet due
        db.session.commit()

    pure = MagicMock()
    pure.destroy_volume_snapshot.return_value = (True, {'status_code': 200, 'text': ''})
    patches = _patch_storage_clients(monkey_pure=pure)
    for p in patches:
        p.start()
    try:
        _process_expired_deletions(app)
    finally:
        for p in patches:
            p.stop()

    pure.destroy_volume_snapshot.assert_not_called()
    with app.app_context():
        assert SnapshotRecord.query.get(snap_id) is not None


def test_api_update_ttl_streams_and_persists(app, client):
    """POST /snaps/api/update-ttl streams progress and updates ttl on success."""
    snap_id = _seed_snapshot(app)
    # Seeded TTL is now+5d; pick a target ≥ 24h after that to satisfy the
    # "min 24h increase" rule enforced by the route.
    new_ttl_dt = datetime.utcnow() + timedelta(days=8)
    new_ttl_str = new_ttl_dt.strftime('%Y-%m-%d %H:%M:%S')
    patches = _patch_storage_clients()
    for p in patches:
        p.start()
    try:
        resp = client.post('/snaps/api/update-ttl',
                           json={'id': snap_id, 'new_ttl': new_ttl_str},
                           content_type='application/json')
        assert resp.status_code == 200
        events = _consume_ndjson(resp)
    finally:
        for p in patches:
            p.stop()

    assert events[0]['event'] == 'run_start'
    assert events[-1]['event'] == 'run_done'
    assert events[-1]['status'] == 'ok'

    # Persisted TTL on the record
    list_data = client.get('/snaps/api/list').get_json()
    snap = next(s for s in list_data['snapshots'] if s['id'] == snap_id)
    assert new_ttl_dt.strftime('%Y-%m-%d') in snap['ttl']


def test_resolve_system_matches_case_insensitive(app):
    """Storage-system resolution tolerates upper/lower-case mismatches."""
    from app import db
    from app.models import StorageSystem
    from app.routes.snaps import _resolve_system

    with app.app_context():
        sys = StorageSystem(
            name='fasmc1',
            vendor='netapp-ontap',
            ip_address='10.112.228.55',
            port=443,
            enabled=True,
        )
        db.session.add(sys)
        db.session.commit()

        resolved = _resolve_system('FASMC1', vendor='netapp-ontap')
        assert resolved is not None
        assert resolved.id == sys.id


def test_resolve_system_matches_shortname_to_fqdn(app):
    """Storage-system resolution maps short cluster name to FQDN entry."""
    from app import db
    from app.models import StorageSystem
    from app.routes.snaps import _resolve_system

    with app.app_context():
        sys = StorageSystem(
            name='fasmc1.itscare.prod.dom',
            vendor='netapp-ontap',
            ip_address='10.112.228.55',
            port=443,
            enabled=True,
        )
        db.session.add(sys)
        db.session.commit()

        resolved = _resolve_system('FASMC1', vendor='netapp-ontap')
        assert resolved is not None
        assert resolved.id == sys.id


def test_api_update_ttl_does_not_persist_on_failure(app, client):
    """If the storage rename fails, the TTL must NOT be updated in the DB."""
    snap_id = _seed_snapshot(app)
    failing_pure = MagicMock()
    failing_pure.rename_volume_snapshot.return_value = (
        False, {'status_code': 400, 'text': 'Bad request'}
    )
    new_ttl_dt = datetime.utcnow() + timedelta(days=8)
    new_ttl_str = new_ttl_dt.strftime('%Y-%m-%d %H:%M:%S')
    patches = _patch_storage_clients(monkey_pure=failing_pure)
    for p in patches:
        p.start()
    try:
        resp = client.post('/snaps/api/update-ttl',
                           json={'id': snap_id, 'new_ttl': new_ttl_str},
                           content_type='application/json')
        events = _consume_ndjson(resp)
    finally:
        for p in patches:
            p.stop()

    assert events[-1]['status'] == 'error'

    list_data = client.get('/snaps/api/list').get_json()
    snap = next(s for s in list_data['snapshots'] if s['id'] == snap_id)
    # The seeded ttl is creation_time + 5 days, not the requested target.
    assert snap['ttl'] is None or new_ttl_dt.strftime('%Y-%m-%d') not in snap['ttl']


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


def test_api_update_ttl_allows_reduction_if_still_24h_in_future(app, client):
    """Reducing TTL is allowed when the new TTL is still >= now + 24h."""
    snap_id = _seed_snapshot(app)  # seeded TTL = now + 5 days
    reduced_but_valid = datetime.utcnow() + timedelta(days=2)
    new_ttl_str = reduced_but_valid.strftime('%Y-%m-%d %H:%M:%S')

    patches = _patch_storage_clients()
    for p in patches:
        p.start()
    try:
        resp = client.post('/snaps/api/update-ttl',
                           json={'id': snap_id, 'new_ttl': new_ttl_str},
                           content_type='application/json')
        assert resp.status_code == 200
        events = _consume_ndjson(resp)
    finally:
        for p in patches:
            p.stop()

    assert events[-1]['status'] == 'ok'


def test_api_update_ttl_rejects_value_below_now_plus_24h(app, client):
    """A new TTL earlier than now + 24 h must be rejected."""
    snap_id = _seed_snapshot(app)
    too_close = (datetime.utcnow() + timedelta(hours=12)).strftime('%Y-%m-%d %H:%M:%S')
    resp = client.post('/snaps/api/update-ttl',
                       json={'id': snap_id, 'new_ttl': too_close},
                       content_type='application/json')
    assert resp.status_code == 400
    body = resp.get_json()
    assert body.get('min_new_ttl')


def test_api_list_exposes_ttl_min_increase(app, client):
    """The list endpoint advertises the configured min-increase window."""
    _seed_snapshot(app)
    data = client.get('/snaps/api/list').get_json()
    assert data['stats'].get('ttl_min_increase_hours') == 24


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


def test_persist_ttl_update_updates_storage_locations_snapshot_names(app):
    """After a successful TTL update, details must use updated snapshot names.

    The UI details render snapshot *names* from ``storage_locations``.
    If only ``rec.ttl`` is updated, the table TTL and the expanded
    snapshot-name details diverge.
    """
    from app.models import SnapshotRecord
    from app.routes.snaps import _persist_ttl_update

    old_ttl = datetime(2026, 5, 7, 16, 14, 37)
    new_ttl = datetime(2026, 5, 7, 18, 14, 37)
    old_ts_str = old_ttl.strftime('%Y-%m-%d-%H%M%S')
    new_ts_str = new_ttl.strftime('%Y-%m-%d-%H%M%S')

    old_storage_locations = {
        'flasharray_systems': [
            {'name': 'pure04', 'snapshot_names': [f'pod-x86-0304::vgIZT_1.{old_ts_str}']},
        ],
        'ontap_clusters': [
            {
                'cluster': 'FASMC1',
                'svm': 'nfs01',
                'volumes': [
                    {'volume': 'ORA_IZT', 'snap': f'IZT_{old_ts_str}'},
                ],
            },
        ],
    }

    rec = SnapshotRecord(
        sid='IZT',
        creation_time=datetime(2026, 4, 28, 16, 14, 51),
        ttl=old_ttl,
        flasharray_present=True,
        ontap_present=True,
        storage_locations=json.dumps(old_storage_locations),
    )

    with app.app_context():
        db.session.add(rec)
        db.session.commit()

        _persist_ttl_update(app, rec.id, new_ttl, user='operator1')

        updated = SnapshotRecord.query.get(rec.id)
        assert updated is not None
        assert updated.ttl == new_ttl

        locs = updated.get_storage_locations()

        fa_names = locs.get('flasharray_systems', [])[0].get('snapshot_names', [])
        assert any(new_ts_str in n for n in fa_names)
        assert not any(old_ts_str in n for n in fa_names)

        vols = locs.get('ontap_clusters', [])[0].get('volumes', [])
        snap_names = [v.get('snap') for v in vols if isinstance(v, dict)]
        assert any(isinstance(n, str) and new_ts_str in n for n in snap_names)
        assert not any(isinstance(n, str) and old_ts_str in n for n in snap_names)


def test_snap_page_renders(client):
    resp = client.get('/snaps/')
    assert resp.status_code == 200
    assert b'Snapshot' in resp.data


def test_audit_log_created_on_ttl_change(app, client):
    """A successful live TTL change writes exactly one audit log entry."""
    snap_id = _seed_snapshot(app)
    new_ttl_dt = datetime.utcnow() + timedelta(days=8)
    new_ttl_str = new_ttl_dt.strftime('%Y-%m-%d %H:%M:%S')
    patches = _patch_storage_clients()
    for p in patches:
        p.start()
    try:
        resp = client.post('/snaps/api/update-ttl',
                           json={'id': snap_id, 'new_ttl': new_ttl_str,
                                 'user': 'operator1'},
                           content_type='application/json')
        assert resp.status_code == 200
        # Drain the stream so the on_success callback runs
        events = _consume_ndjson(resp)
        assert events[-1]['status'] == 'ok'
    finally:
        for p in patches:
            p.stop()

    with app.app_context():
        from app.models import SnapshotAuditLog
        logs = SnapshotAuditLog.query.filter_by(snapshot_id=snap_id).all()
        assert len(logs) == 1
        assert logs[0].changed_by == 'operator1'
        assert logs[0].new_ttl.year == new_ttl_dt.year
        assert logs[0].new_ttl.month == new_ttl_dt.month
        assert logs[0].new_ttl.day == new_ttl_dt.day


def test_audit_log_not_created_on_ttl_failure(app, client):
    """Failed live TTL change must NOT write an audit log entry."""
    snap_id = _seed_snapshot(app)
    failing_pure = MagicMock()
    failing_pure.rename_volume_snapshot.return_value = (
        False, {'status_code': 500, 'text': 'boom'}
    )
    new_ttl_str = (datetime.utcnow() + timedelta(days=8)).strftime('%Y-%m-%d %H:%M:%S')
    patches = _patch_storage_clients(monkey_pure=failing_pure)
    for p in patches:
        p.start()
    try:
        client.post('/snaps/api/update-ttl',
                    json={'id': snap_id, 'new_ttl': new_ttl_str,
                          'user': 'operator1'},
                    content_type='application/json')
    finally:
        for p in patches:
            p.stop()

    with app.app_context():
        from app.models import SnapshotAuditLog
        logs = SnapshotAuditLog.query.filter_by(snapshot_id=snap_id).all()
        assert logs == []


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


def test_reconciliation_delete_failure_does_not_rollback_new_records(app):
    """A stale-delete error must not roll back inserts/updates from the same run."""
    from app.snap_service import _upsert_snapshot_records, _group_by_sid_and_time
    from datetime import datetime, timedelta
    from unittest.mock import patch

    with app.app_context():
        from app import db
        from app.models import SnapshotRecord
        old_ct = datetime(2026, 1, 1, 0, 0, 0)
        stale = SnapshotRecord(
            sid='GONE',
            creation_time=old_ct,
            ttl=old_ct + timedelta(days=2),
            flasharray_present=True,
            ontap_present=True,
            last_seen=datetime(2026, 1, 1, 0, 0, 0),
        )
        db.session.add(stale)
        db.session.commit()
        stale_id = stale.id

    ts = datetime(2026, 3, 18, 2, 47, 0)
    fa_snap = {
        'sid': 'ACP',
        'snapshot_name': 'ACP_1.HDBSNAP-2026-03-18-024722',
        'creation_time': ts,
        'ttl': ts,
        'array_name': 'fa01',
    }
    aggregated = _group_by_sid_and_time([fa_snap], [])

    with app.app_context():
        from app import db
        original_delete = db.session.delete

        def fail_stale_delete(obj):
            if getattr(obj, 'id', None) == stale_id:
                raise RuntimeError('simulated FK delete failure')
            return original_delete(obj)

        with patch.object(db.session, 'delete', side_effect=fail_stale_delete):
            _upsert_snapshot_records(app, aggregated, systems_queried=1)

    with app.app_context():
        from app.models import SnapshotRecord
        # New records from this run are still committed.
        assert SnapshotRecord.query.filter_by(sid='ACP').count() == 1

        # Failed stale delete falls back to "absent" state instead of rollback.
        kept = SnapshotRecord.query.get(stale_id)
        assert kept is not None
        assert kept.flasharray_present is False
        assert kept.ontap_present is False
        assert kept.storage_locations is None


def test_reconciliation_deletes_audit_logs_before_snapshot_delete(app):
    """Stale snapshot deletion must remove audit rows first (no NULL snapshot_id updates)."""
    from app import db
    from app.models import SnapshotAuditLog, SnapshotRecord
    from app.snap_service import _upsert_snapshot_records, _group_by_sid_and_time

    old_ct = datetime(2026, 1, 1, 0, 0, 0)
    with app.app_context():
        stale = SnapshotRecord(
            sid='STALE',
            creation_time=old_ct,
            ttl=old_ct + timedelta(days=1),
            flasharray_present=True,
            ontap_present=False,
            last_seen=datetime(2026, 1, 1, 0, 0, 0),
        )
        db.session.add(stale)
        db.session.commit()
        stale_id = stale.id

        db.session.add(SnapshotAuditLog(
            snapshot_id=stale_id,
            old_ttl=old_ct + timedelta(days=1),
            new_ttl=old_ct + timedelta(days=2),
            changed_by='operator1',
        ))
        db.session.commit()

    # Collector run with a different snapshot => stale row should be removed.
    ts = datetime(2026, 3, 18, 2, 47, 0)
    fa_snap = {
        'sid': 'ACP',
        'snapshot_name': 'ACP_1.HDBSNAP-2026-03-18-024722',
        'creation_time': ts,
        'ttl': ts,
        'array_name': 'fa01',
    }
    aggregated = _group_by_sid_and_time([fa_snap], [])
    _upsert_snapshot_records(app, aggregated, systems_queried=1)

    with app.app_context():
        assert SnapshotRecord.query.get(stale_id) is None
        assert SnapshotAuditLog.query.filter_by(snapshot_id=stale_id).count() == 0


def test_upsert_refreshes_ttl_from_storage_even_with_audit_log(app):
    """Collector must refresh TTL from storage regardless of audit history."""
    from app import db
    from app.models import SnapshotAuditLog, SnapshotRecord
    from app.snap_service import _upsert_snapshot_records

    ct = datetime(2026, 4, 28, 14, 14, 51)
    old_ttl = datetime(2026, 5, 14, 16, 14, 37)
    new_ttl = datetime(2026, 5, 7, 16, 14, 37)

    with app.app_context():
        rec = SnapshotRecord(
            sid='IZT',
            creation_time=ct,
            ttl=old_ttl,
            flasharray_present=True,
            ontap_present=True,
            storage_locations=json.dumps({'flasharray_systems': [], 'ontap_clusters': []}),
            last_seen=datetime(2026, 4, 28, 14, 20, 0),
        )
        db.session.add(rec)
        db.session.commit()
        rec_id = rec.id

        # Simulate prior user-triggered TTL update history.
        db.session.add(SnapshotAuditLog(
            snapshot_id=rec_id,
            old_ttl=old_ttl,
            new_ttl=datetime(2026, 5, 21, 16, 14, 37),
            changed_by='operator1',
        ))
        db.session.commit()

    aggregated = [{
        'sid': 'IZT',
        'creation_time': ct,
        'ttl': new_ttl,
        'flasharray_present': True,
        'ontap_present': True,
        'storage_locations': json.dumps({'flasharray_systems': [], 'ontap_clusters': []}),
    }]
    _upsert_snapshot_records(app, aggregated, systems_queried=1)

    with app.app_context():
        refreshed = SnapshotRecord.query.get(rec_id)
        assert refreshed is not None
        assert refreshed.ttl == new_ttl


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


def test_build_update_ttl_plan_flasharray_full_rename():
    """``_build_update_ttl_plan`` produces a FlashArray rename step with the
    correct *full* new snapshot name (VOL.SUFFIX, including pod prefix).
    """
    from app.routes.snaps import _build_update_ttl_plan
    from unittest.mock import MagicMock

    rec = MagicMock()
    rec.sid = 'A4T'
    rec.ttl = datetime(2026, 3, 22, 7, 36, 17)

    locs = {
        'flasharray_systems': [
            {
                'name': 'pure04',
                'snapshot_names': ['pod-x86-0304::vgA4T_1.2026-03-22-073617'],
            }
        ],
        'ontap_clusters': [],
    }

    plan = _build_update_ttl_plan(rec, locs, datetime(2026, 4, 15, 12, 0, 0))
    assert len(plan) == 1
    step = plan[0]
    assert step['platform'] == 'FlashArray'
    assert step['target'] == 'pure04'
    # Command shown to the user must reference both the old name (in ?names=)
    # and the new full name (in the JSON body).
    assert 'pod-x86-0304::vgA4T_1.2026-03-22-073617' in step['command']
    assert '"pod-x86-0304::vgA4T_1.2026-04-15-120000"' in step['command']


def test_build_update_ttl_plan_ontap_two_steps_per_volume():
    """ONTAP TTL plan emits rename + expiry update per volume."""
    from app.routes.snaps import _build_update_ttl_plan
    from unittest.mock import MagicMock

    rec = MagicMock()
    rec.sid = 'ABP'
    rec.ttl = datetime(2026, 3, 13, 19, 3, 49)

    locs = {
        'flasharray_systems': [],
        'ontap_clusters': [
            {
                'cluster': 'FASMC1',
                'svm': 'nfs01',
                'volumes': [
                    {'volume': 'HANA_ABP', 'snap': 'ABP_HDBSNAP-2026-03-13-190349'},
                    {'volume': 'HANA_ABP_log',
                     'snap': 'ABP_HDBSNAP-2026-03-13-190349'},
                ],
            }
        ],
    }
    plan = _build_update_ttl_plan(rec, locs, datetime(2026, 4, 1, 19, 3, 49))
    ontap_steps = [s for s in plan if s['platform'] == 'ONTAP']
    # Two volumes × (rename + expiry update) = 4 ONTAP steps
    assert len(ontap_steps) == 4
    rename_steps = [s for s in ontap_steps if '"name":"ABP_HDBSNAP-2026-04-01-190349"' in s['command']]
    expiry_steps = [s for s in ontap_steps if '"expiry_time":"2026-04-01T19:03:49Z"' in s['command']]
    assert len(rename_steps) == 2
    assert len(expiry_steps) == 2


def test_build_delete_plan_flasharray_destroy_only():
    """FlashArray delete plan: a single destroy step per snapshot LUN, no rename, no DELETE."""
    from app.routes.snaps import _build_delete_plan
    from unittest.mock import MagicMock

    rec = MagicMock()
    rec.sid = 'Z8T'
    rec.ttl = datetime(2026, 4, 28, 23, 0, 36)

    locs = {
        'flasharray_systems': [
            {
                'name': 'pure03',
                'snapshot_names': [
                    'pod-x86-0304::Z8T_1_data_htz315.HDBSNAP-2026-04-28-230036',
                    'pod-x86-0304::Z8T_1_log_htz315.HDBSNAP-2026-04-28-230036',
                ],
            }
        ],
        'ontap_clusters': [],
    }

    plan = _build_delete_plan(rec, locs)
    assert len(plan) == 2
    for step in plan:
        assert step['platform'] == 'FlashArray'
        body = step['command']
        assert 'PATCH' in body
        assert '"destroyed":true' in body
        # No rename, no eradication DELETE on FlashArray.
        assert '"name"' not in body
        assert 'curl -X DELETE' not in body


def test_build_delete_plan_ontap_two_steps_per_volume():
    """ONTAP delete plan: expiry_time adjustment followed by DELETE per volume."""
    from app.routes.snaps import _build_delete_plan
    from unittest.mock import MagicMock

    rec = MagicMock()
    rec.sid = 'ABP'
    rec.ttl = datetime(2026, 3, 17, 19, 1, 19)

    locs = {
        'flasharray_systems': [],
        'ontap_clusters': [
            {
                'cluster': 'FASMC1',
                'svm': 'nfs01',
                'volumes': [
                    {'volume': 'HANA_ABP', 'snap': 'ABP_HDBSNAP-2026-03-17-190119'},
                    {'volume': 'HANA_ABP_log',
                     'snap': 'ABP_HDBSNAP-2026-03-17-190119'},
                ],
            }
        ],
    }

    plan = _build_delete_plan(rec, locs)
    # Two volumes × (expiry + delete) = 4 steps
    assert len(plan) == 4
    vol_names = sorted({s['target'] for s in plan})
    assert any('HANA_ABP' in name for name in vol_names)

    expiry_steps = [s for s in plan if 'expiry_time' in s['command']]
    delete_steps = [s for s in plan if 'curl -X DELETE' in s['command']]
    assert len(expiry_steps) == 2
    assert len(delete_steps) == 2

    # Order matters: each (expiry, delete) pair appears in that sequence.
    for i in range(0, len(plan), 2):
        assert 'expiry_time' in plan[i]['command']
        assert 'curl -X DELETE' in plan[i + 1]['command']


def test_format_response_info_renders_nested_ontap_job_error():
    """When an ONTAP async job fails, the terminal view must show state/message/code."""
    from app.routes.snaps import _format_response_info

    # Mirrors the wrapper shape returned by NetAppONTAPClient._wait_for_job_completion
    # on failure: {'error': ..., 'job': <job_payload>}.
    info = {
        'status_code': 202,
        'job_uuid': '67dedff3-439e-11f1-ac22-d039ea53066a',
        'job': {
            'error': 'ONTAP async job failed (state=failure): not authorized for that command',
            'job': {
                'uuid': '67dedff3-439e-11f1-ac22-d039ea53066a',
                'description': 'PATCH /api/storage/volumes/…/snapshots/…',
                'state': 'failure',
                'message': 'not authorized for that command',
                'code': 6,
            },
        },
    }

    s = _format_response_info(info)
    assert 'job_state=failure' in s
    assert 'not authorized for that command' in s
    assert 'job_code=6' in s
