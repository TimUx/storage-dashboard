"""Integration: Health-Endpunkte und optionale API-Authentifizierung."""
import pytest


@pytest.mark.integration
def test_health_liveness(dashboard_client):
    r = dashboard_client.get('/health')
    assert r.status_code == 200
    assert r.get_json().get('status') == 'ok'


@pytest.mark.integration
def test_api_health_public(dashboard_client):
    r = dashboard_client.get('/api/health')
    assert r.status_code == 200
    assert r.get_json().get('status') == 'ok'


@pytest.mark.integration
def test_api_systems_requires_bearer_when_token_set(dashboard_client, monkeypatch):
    """Wenn ``API_ACCESS_TOKEN`` gesetzt ist, schützen alle /api/*-Routen (außer /api/health)."""
    monkeypatch.setenv('API_ACCESS_TOKEN', 'only-for-test')
    try:
        assert dashboard_client.get('/api/systems').status_code == 401
        ok = dashboard_client.get(
            '/api/systems',
            headers={'Authorization': 'Bearer only-for-test'},
        )
        assert ok.status_code == 200
        assert dashboard_client.get('/api/health').status_code == 200
    finally:
        monkeypatch.delenv('API_ACCESS_TOKEN', raising=False)

    assert dashboard_client.get('/api/systems').status_code == 200
