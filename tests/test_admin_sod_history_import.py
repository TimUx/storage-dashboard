"""Admin endpoint POST /admin/api/sod-history-import-pure1."""
from __future__ import annotations

from unittest.mock import patch

from app.models import AppSettings


def test_sod_history_import_400_without_pure1(admin_client, dashboard_db):
    s = AppSettings()
    s.company_name = 'pytest'
    dashboard_db.session.add(s)
    dashboard_db.session.commit()

    r = admin_client.post('/admin/api/sod-history-import-pure1')
    assert r.status_code == 400
    data = r.get_json()
    assert 'error' in data


def test_sod_history_import_ok_with_pure1(admin_client, dashboard_db):
    s = AppSettings()
    s.company_name = 'pytest'
    s.pure1_app_id = 'pure1:apikey:test'
    s.pure1_private_key = '-----BEGIN RSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY-----'
    dashboard_db.session.add(s)
    dashboard_db.session.commit()

    with patch(
        'app.capacity_service.import_sod_history_from_pure1',
        return_value=(42, 2, ['note']),
    ):
        r = admin_client.post('/admin/api/sod-history-import-pure1')

    assert r.status_code == 200
    data = r.get_json()
    assert data['imported'] == 42
    assert data['skipped'] == 2
    assert data['errors'] == ['note']
    assert 'start_date' in data and 'end_date' in data


def test_sod_history_import_requires_login(dashboard_client, dashboard_db):
    s = AppSettings()
    s.company_name = 'pytest'
    s.pure1_app_id = 'pure1:apikey:test'
    s.pure1_private_key = 'k'
    dashboard_db.session.add(s)
    dashboard_db.session.commit()

    r = dashboard_client.post('/admin/api/sod-history-import-pure1')
    assert r.status_code == 302
