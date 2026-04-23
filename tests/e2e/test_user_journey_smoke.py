"""E2E-artige Flows über den Flask-Testclient (ohne Browser).

Diese Tests simulieren typische Operator-Schritte in einer realistischen
Reihenfolge. Für echtes Browser-E2E siehe TESTING.md (Playwright, optional).
"""
import json

import pytest

from tests.support.factories import status_cache_payload_online, storage_system_kwargs


@pytest.mark.e2e
def test_journey_anonymous_dashboard_and_public_apis(dashboard_client):
    """Anonym: Dashboard öffnen, Systemliste und Alerts-JSON abrufen."""
    dash = dashboard_client.get('/dashboard', follow_redirects=True)
    assert dash.status_code == 200

    systems = dashboard_client.get('/api/systems')
    assert systems.status_code == 200
    assert systems.get_json() == []

    alerts = dashboard_client.get('/api/alerts')
    assert alerts.status_code == 200
    assert alerts.get_json()['alerts'] == []


@pytest.mark.e2e
def test_journey_login_admin_home_and_settings(admin_client):
    """Eingeloggt: Admin-Startseite und Einstellungen erreichen."""
    home = admin_client.get('/admin/')
    assert home.status_code == 200
    assert b'Admin - Storage' in home.data or b'Admin' in home.data

    settings = admin_client.get('/admin/settings')
    assert settings.status_code == 200


@pytest.mark.e2e
def test_journey_system_seed_alerts_and_cached_status(dashboard_app, dashboard_db, dashboard_client):
    """Mit gespeichertem System und Cache: Alerts-Liste und Cached-Status."""
    from datetime import datetime

    from app.models import StatusCache, StorageSystem

    sys = StorageSystem(**storage_system_kwargs(name='E2E-FA-99'))
    dashboard_db.session.add(sys)
    dashboard_db.session.flush()
    dashboard_db.session.add(
        StatusCache(
            system_id=sys.id,
            fetched_at=datetime.utcnow(),
            status_json=json.dumps(
                status_cache_payload_online(
                    alerts=1,
                    alert_details=[
                        {
                            'id': 'e2e-1',
                            'title': 'E2E Test Alert',
                            'details': 'Synthetic alert for journey test',
                            'severity': 'warning',
                            'error_code': '-',
                            'timestamp': '2026-01-01T00:00:00+00:00',
                            'component': 'TEST',
                        },
                    ],
                )
            ),
        )
    )
    dashboard_db.session.commit()

    r_alerts = dashboard_client.get('/api/alerts')
    assert r_alerts.status_code == 200
    items = r_alerts.get_json()['alerts']
    assert len(items) >= 1
    assert any(a.get('title') == 'E2E Test Alert' for a in items)

    r_cache = dashboard_client.get('/api/cached-status')
    assert r_cache.status_code == 200
    assert len(r_cache.get_json()) == 1
