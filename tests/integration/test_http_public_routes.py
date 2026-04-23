"""Integration: öffentliche HTML- und JSON-Routen (ohne Storage-Live-Calls)."""
import json

import pytest

from tests.support.factories import (
    ontap_system_kwargs,
    status_cache_payload_online,
    storage_system_kwargs,
)


@pytest.mark.integration
def test_dashboard_loads(dashboard_client):
    r = dashboard_client.get('/dashboard', follow_redirects=True)
    assert r.status_code == 200
    body = r.data.decode('utf-8', errors='replace')
    assert 'Storage' in body or 'Dashboard' in body or 'dashboard' in body.lower()


@pytest.mark.integration
def test_public_pages_load(dashboard_client):
    for path in ('/capacity/', '/snaps/', '/dr/', '/alerts/'):
        r = dashboard_client.get(path, follow_redirects=True)
        assert r.status_code == 200, path


@pytest.mark.integration
def test_api_systems_empty_db(dashboard_client):
    r = dashboard_client.get('/api/systems')
    assert r.status_code == 200
    assert r.get_json() == []


@pytest.mark.integration
def test_api_cached_status_empty(dashboard_client):
    r = dashboard_client.get('/api/cached-status')
    assert r.status_code == 200
    assert r.get_json() == []


@pytest.mark.integration
def test_api_alerts_empty(dashboard_client):
    r = dashboard_client.get('/api/alerts')
    assert r.status_code == 200
    data = r.get_json()
    assert data['alerts'] == []


@pytest.mark.integration
def test_capacity_api_data_structure(dashboard_client):
    r = dashboard_client.get('/capacity/api/data')
    assert r.status_code == 200
    data = r.get_json()
    for key in ('stale', 'last_updated', 'by_storage_art', 'by_environment', 'by_department', 'details'):
        assert key in data


@pytest.mark.integration
def test_snaps_api_list_empty(dashboard_client):
    r = dashboard_client.get('/snaps/api/list')
    assert r.status_code == 200
    data = r.get_json()
    assert data.get('snapshots') == []
    assert 'stats' in data


@pytest.mark.integration
def test_dr_topology_json_empty_build(dashboard_client):
    r = dashboard_client.get('/dr/api/topology')
    assert r.status_code == 200
    data = r.get_json()
    assert data.get('build') is None
    assert data.get('relationships') == []


@pytest.mark.integration
def test_api_systems_with_seeded_system(dashboard_app, dashboard_db, dashboard_client):
    from app.models import StorageSystem

    s = StorageSystem(**storage_system_kwargs(name='SEED-FA-01'))
    dashboard_db.session.add(s)
    dashboard_db.session.commit()

    r = dashboard_client.get('/api/systems')
    assert r.status_code == 200
    rows = r.get_json()
    assert len(rows) == 1
    assert rows[0]['name'] == 'SEED-FA-01'
    assert rows[0]['vendor'] == 'pure'


@pytest.mark.integration
def test_cached_status_reflects_seed_cache(dashboard_app, dashboard_db, dashboard_client):
    from datetime import datetime

    from app.models import StatusCache, StorageSystem

    s = StorageSystem(**ontap_system_kwargs(name='SEED-ONTAP'))
    dashboard_db.session.add(s)
    dashboard_db.session.flush()
    cache = StatusCache(
        system_id=s.id,
        fetched_at=datetime.utcnow(),
        status_json=json.dumps(status_cache_payload_online()),
    )
    dashboard_db.session.add(cache)
    dashboard_db.session.commit()

    r = dashboard_client.get('/api/cached-status')
    assert r.status_code == 200
    rows = r.get_json()
    assert len(rows) == 1
    assert rows[0]['system']['name'] == 'SEED-ONTAP'
    assert rows[0]['status']['status'] == 'online'
