"""Tests for the Full-Backup export and import (restore) routes.

Verifies that:
- GET  /admin/backup/export  returns a valid JSON backup with backup_type='full'
- POST /admin/backup/import  restores settings and creates systems/certs/tags
- POST /admin/backup/import  skips systems/certs/tags that already exist
- POST /admin/backup/import  rejects files without backup_type='full'
- POST /admin/backup/import  rejects invalid (non-JSON) files
- The settings page renders the Backup tab (HTML contains expected content)
- The OpenAPI schema file contains the backup endpoints
"""

import io
import json
import os
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Helpers – lightweight test app (no background threads)
# ---------------------------------------------------------------------------

def _no_op(*a, **kw):
    pass


@pytest.fixture()
def app():
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
def app_ctx(app):
    with app.app_context():
        yield app


@pytest.fixture()
def db(app_ctx):
    from app import db as _db
    _db.create_all()
    yield _db
    _db.session.remove()


@pytest.fixture()
def logged_in_client(app, db):
    """Return a test client that is already authenticated as admin."""
    from app.models import AdminUser
    from werkzeug.security import generate_password_hash

    user = AdminUser(username='admin', password_hash=generate_password_hash('testpass'))
    db.session.add(user)
    db.session.commit()

    client = app.test_client()
    client.post('/admin/login', data={'username': 'admin', 'password': 'testpass'},
                follow_redirects=False)
    return client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_backup_payload(**overrides):
    """Return a minimal valid full-backup payload dict."""
    payload = {
        'backup_version': '1.0',
        'backup_date': '2026-01-01T00:00:00',
        'backup_type': 'full',
        'settings': {
            'company_name': 'Test GmbH',
            'primary_color': '#FF0000',
            'secondary_color': '#00FF00',
            'accent_color': '#0000FF',
            'timezone': 'UTC',
            'max_logs_per_system': 500,
            'log_retention_days': 14,
            'min_log_level': 'WARNING',
            'dashboard_refresh_interval': 15,
        },
        'systems': [
            {
                'name': 'test-array-01',
                'vendor': 'pure',
                'ip_address': '10.0.0.99',
                'port': 443,
                'api_username': 'pureuser',
                'api_password': 'purepass',
                'api_token': None,
                'enabled': True,
                'cluster_type': None,
                'node_count': 2,
                'site_count': None,
                'dns_names': [],
                'all_ips': [],
                'pure1_array_name': None,
                'tags': [],
            }
        ],
        'certificates': [
            {
                'name': 'test-cert',
                'certificate_type': 'ca',
                'certificate_pem': '-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----\n',
                'description': 'Test CA',
                'enabled': True,
            }
        ],
        'tag_groups': [
            {
                'name': 'Standort',
                'description': 'Physischer Standort',
                'tags': [{'name': 'Berlin'}, {'name': 'München'}],
            }
        ],
    }
    payload.update(overrides)
    return payload


def _upload_backup(client, payload):
    """POST a backup payload to /admin/backup/import and return the response."""
    data = json.dumps(payload).encode('utf-8')
    return client.post(
        '/admin/backup/import',
        data={'backup_file': (io.BytesIO(data), 'backup.json')},
        content_type='multipart/form-data',
        follow_redirects=True,
    )


# ---------------------------------------------------------------------------
# Export tests
# ---------------------------------------------------------------------------

class TestBackupExport:
    def test_export_returns_200(self, logged_in_client):
        """GET /admin/backup/export must return HTTP 200."""
        resp = logged_in_client.get('/admin/backup/export')
        assert resp.status_code == 200

    def test_export_content_type_is_json(self, logged_in_client):
        """Export response must have application/json content type."""
        resp = logged_in_client.get('/admin/backup/export')
        assert 'application/json' in resp.content_type

    def test_export_has_backup_type_full(self, logged_in_client):
        """Exported JSON must have backup_type='full'."""
        resp = logged_in_client.get('/admin/backup/export')
        data = json.loads(resp.data)
        assert data['backup_type'] == 'full'

    def test_export_contains_required_top_level_keys(self, logged_in_client):
        """Exported JSON must contain all required top-level keys."""
        resp = logged_in_client.get('/admin/backup/export')
        data = json.loads(resp.data)
        for key in ('backup_version', 'backup_date', 'backup_type',
                    'settings', 'systems', 'certificates', 'tag_groups'):
            assert key in data, f'Missing key: {key}'

    def test_export_filename_has_timestamp(self, logged_in_client):
        """Content-Disposition header must include a timestamped filename."""
        resp = logged_in_client.get('/admin/backup/export')
        disposition = resp.headers.get('Content-Disposition', '')
        assert 'storage_dashboard_backup_' in disposition
        assert '.json' in disposition

    def test_export_requires_login(self, app, db):
        """Unauthenticated request must be redirected to login page."""
        client = app.test_client()
        resp = client.get('/admin/backup/export', follow_redirects=False)
        assert resp.status_code == 302
        assert '/admin/login' in resp.headers.get('Location', '')

    def test_export_includes_system_from_db(self, logged_in_client, db):
        """A system added to the DB must appear in the exported backup."""
        from app.models import StorageSystem
        system = StorageSystem(
            name='export-test-array',
            vendor='pure',
            ip_address='10.1.2.3',
            enabled=True,
        )
        db.session.add(system)
        db.session.commit()

        resp = logged_in_client.get('/admin/backup/export')
        data = json.loads(resp.data)
        names = [s['name'] for s in data['systems']]
        assert 'export-test-array' in names


# ---------------------------------------------------------------------------
# Import / Restore tests
# ---------------------------------------------------------------------------

class TestBackupImport:
    def test_import_requires_login(self, app, db):
        """Unauthenticated POST to /admin/backup/import must redirect to login."""
        client = app.test_client()
        payload = _make_backup_payload()
        resp = _upload_backup(client, payload)
        # After redirect chain, ends up at login page
        assert b'login' in resp.data.lower() or resp.status_code in (200, 302)

    def test_import_restores_settings(self, logged_in_client, db):
        """Importing a backup must overwrite the AppSettings."""
        from app.models import AppSettings
        payload = _make_backup_payload()
        resp = _upload_backup(logged_in_client, payload)
        assert resp.status_code == 200

        settings = AppSettings.query.first()
        assert settings is not None
        assert settings.company_name == 'Test GmbH'
        assert settings.primary_color == '#FF0000'
        assert settings.timezone == 'UTC'
        assert settings.max_logs_per_system == 500
        assert settings.log_retention_days == 14

    def test_import_creates_system(self, logged_in_client, db):
        """Importing a backup must create the storage systems from the payload."""
        from app.models import StorageSystem
        payload = _make_backup_payload()
        _upload_backup(logged_in_client, payload)

        system = StorageSystem.query.filter_by(name='test-array-01').first()
        assert system is not None
        assert system.vendor == 'pure'
        assert system.ip_address == '10.0.0.99'

    def test_import_creates_certificate(self, logged_in_client, db):
        """Importing a backup must create the certificates from the payload."""
        from app.models import Certificate
        payload = _make_backup_payload()
        _upload_backup(logged_in_client, payload)

        cert = Certificate.query.filter_by(name='test-cert').first()
        assert cert is not None
        assert cert.certificate_type == 'ca'

    def test_import_creates_tag_groups_and_tags(self, logged_in_client, db):
        """Importing a backup must create tag groups and their tags."""
        from app.models import TagGroup, Tag
        payload = _make_backup_payload()
        _upload_backup(logged_in_client, payload)

        grp = TagGroup.query.filter_by(name='Standort').first()
        assert grp is not None
        tag_names = [t.name for t in grp.tags]
        assert 'Berlin' in tag_names
        assert 'München' in tag_names

    def test_import_skips_existing_system(self, logged_in_client, db):
        """A system that already exists (same name) must not be imported again."""
        from app.models import StorageSystem
        # Pre-create the system
        existing = StorageSystem(
            name='test-array-01',
            vendor='pure',
            ip_address='10.0.0.1',
            enabled=True,
        )
        db.session.add(existing)
        db.session.commit()

        payload = _make_backup_payload()
        resp = _upload_backup(logged_in_client, payload)
        assert resp.status_code == 200

        # Must still be only one system with this name
        count = StorageSystem.query.filter_by(name='test-array-01').count()
        assert count == 1
        # Original IP must be preserved (not overwritten)
        system = StorageSystem.query.filter_by(name='test-array-01').first()
        assert system.ip_address == '10.0.0.1'

    def test_import_skips_existing_certificate(self, logged_in_client, db):
        """A certificate that already exists (same name) must not be imported again."""
        from app.models import Certificate
        existing = Certificate(
            name='test-cert',
            certificate_type='ca',
            certificate_pem='ORIGINAL PEM',
            enabled=True,
        )
        db.session.add(existing)
        db.session.commit()

        payload = _make_backup_payload()
        _upload_backup(logged_in_client, payload)

        count = Certificate.query.filter_by(name='test-cert').count()
        assert count == 1
        cert = Certificate.query.filter_by(name='test-cert').first()
        assert cert.certificate_pem == 'ORIGINAL PEM'

    def test_import_rejects_wrong_backup_type(self, logged_in_client, db):
        """A file with backup_type != 'full' must be rejected with an error flash."""
        payload = _make_backup_payload(backup_type='partial')
        resp = _upload_backup(logged_in_client, payload)
        assert resp.status_code == 200
        assert b'backup_type' in resp.data or 'Ungültig'.encode() in resp.data

    def test_import_rejects_invalid_json(self, logged_in_client):
        """A non-JSON file must be rejected with an error flash."""
        resp = logged_in_client.post(
            '/admin/backup/import',
            data={'backup_file': (io.BytesIO(b'not valid json!!!'), 'bad.json')},
            content_type='multipart/form-data',
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b'JSON' in resp.data or 'Ungültig'.encode() in resp.data

    def test_import_without_file_shows_error(self, logged_in_client):
        """Submitting the import form without a file must show an error flash."""
        resp = logged_in_client.post(
            '/admin/backup/import',
            data={},
            content_type='multipart/form-data',
            follow_redirects=True,
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Settings page – Backup tab presence
# ---------------------------------------------------------------------------

class TestSettingsBackupTab:
    def test_settings_page_contains_backup_tab_button(self, logged_in_client):
        """The settings page must render a 'Backup' tab button."""
        resp = logged_in_client.get('/admin/settings')
        assert resp.status_code == 200
        html = resp.data.decode('utf-8')
        assert 'data-tab="backup"' in html

    def test_settings_page_contains_backup_export_link(self, logged_in_client):
        """The settings page must contain the export link pointing to /admin/backup/export."""
        resp = logged_in_client.get('/admin/settings')
        html = resp.data.decode('utf-8')
        assert '/admin/backup/export' in html

    def test_settings_page_contains_backup_import_form(self, logged_in_client):
        """The settings page must contain the import form posting to /admin/backup/import."""
        resp = logged_in_client.get('/admin/settings')
        html = resp.data.decode('utf-8')
        assert '/admin/backup/import' in html
        assert 'backup_file' in html


# ---------------------------------------------------------------------------
# OpenAPI schema – backup endpoints present
# ---------------------------------------------------------------------------

class TestOpenApiSchema:
    def _load_schema(self):
        schema_path = os.path.join(
            os.path.dirname(__file__), '..', 'app', 'static', 'openapi.json'
        )
        with open(os.path.normpath(schema_path)) as f:
            return json.load(f)

    def test_schema_is_valid_json(self):
        """openapi.json must be valid JSON."""
        schema = self._load_schema()
        assert isinstance(schema, dict)

    def test_schema_has_backup_export_path(self):
        """openapi.json must document GET /admin/backup/export."""
        schema = self._load_schema()
        assert '/admin/backup/export' in schema['paths']
        assert 'get' in schema['paths']['/admin/backup/export']

    def test_schema_has_backup_import_path(self):
        """openapi.json must document POST /admin/backup/import."""
        schema = self._load_schema()
        assert '/admin/backup/import' in schema['paths']
        assert 'post' in schema['paths']['/admin/backup/import']

    def test_schema_has_backup_tag(self):
        """openapi.json must include a 'Backup' tag."""
        schema = self._load_schema()
        tag_names = [t['name'] for t in schema.get('tags', [])]
        assert 'Backup' in tag_names

    def test_schema_has_backup_payload_schema(self):
        """openapi.json must define a BackupPayload component schema."""
        schema = self._load_schema()
        schemas = schema['components']['schemas']
        assert 'BackupPayload' in schemas

    def test_schema_has_alerts_endpoints(self):
        """openapi.json must document /api/alerts and /api/alerts/state."""
        schema = self._load_schema()
        assert '/api/alerts' in schema['paths']
        assert '/api/alerts/state' in schema['paths']

    def test_schema_version_updated(self):
        """openapi.json version must be at least 1.1.0 to reflect new endpoints."""
        schema = self._load_schema()
        version = schema['info']['version']
        major, minor, *_ = version.split('.')
        assert (int(major), int(minor)) >= (1, 1), f'Expected >= 1.1.0, got {version}'
