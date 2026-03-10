"""Tests for database migration utilities (app/migrations.py).

These tests use an in-memory SQLite database so they require no external
services and run quickly.  Each test creates a minimal schema that mimics
an *older* installation (missing the columns that migrations are supposed to
add), runs the relevant migration function, and asserts that the column is
now present.
"""

import pytest
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# ---------------------------------------------------------------------------
# Minimal Flask/SQLAlchemy fixture – avoids importing the full app (which
# tries to start background threads, etc.)
# ---------------------------------------------------------------------------

@pytest.fixture()
def minimal_app():
    """Return a bare-bones Flask app backed by an in-memory SQLite database."""
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['TESTING'] = True
    return app


@pytest.fixture()
def db(minimal_app):
    """Initialise SQLAlchemy on *minimal_app* and yield the db object."""
    from flask_sqlalchemy import SQLAlchemy as _SQLAlchemy
    _db = _SQLAlchemy()
    _db.init_app(minimal_app)
    with minimal_app.app_context():
        yield _db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_minimal_table(db, table_name, extra_ddl=''):
    """Create a minimal version of *table_name* with only an ``id`` column."""
    with db.engine.connect() as conn:
        conn.execute(db.text(
            f"CREATE TABLE IF NOT EXISTS {table_name} (id INTEGER PRIMARY KEY {extra_ddl})"
        ))
        conn.commit()


def _column_exists(db, table_name, column_name):
    inspector = db.inspect(db.engine)
    cols = [c['name'] for c in inspector.get_columns(table_name)]
    return column_name in cols


# ---------------------------------------------------------------------------
# Unit tests – validate_identifier
# ---------------------------------------------------------------------------

class TestValidateIdentifier:
    def test_valid_identifiers(self):
        import app.migrations as mig
        assert mig.validate_identifier('storage_systems') == 'storage_systems'
        assert mig.validate_identifier('app_settings') == 'app_settings'
        assert mig.validate_identifier('os_version') == 'os_version'

    def test_invalid_identifier_raises(self):
        import app.migrations as mig
        with pytest.raises(ValueError):
            mig.validate_identifier('bad-name')
        with pytest.raises(ValueError):
            mig.validate_identifier('1bad')
        with pytest.raises(ValueError):
            mig.validate_identifier('bad name')
        with pytest.raises(ValueError):
            mig.validate_identifier("'; DROP TABLE foo; --")


# ---------------------------------------------------------------------------
# Unit tests – ALLOWED_COLUMNS completeness
# ---------------------------------------------------------------------------

class TestAllowedColumnsCompleteness:
    """Ensure every column referenced in migration functions is whitelisted."""

    STORAGE_SYSTEMS_COLUMNS = [
        'cluster_type', 'node_count', 'site_count', 'dns_names', 'all_ips',
        'node_details', 'partner_cluster_id', 'last_discovery', 'discovery_error',
        'os_version', 'api_version', 'peer_connections', 'metrocluster_info',
        'metrocluster_dr_groups', 'ha_info',
    ]

    APP_SETTINGS_COLUMNS = [
        'primary_color', 'secondary_color', 'accent_color', 'logo_filename',
        'logo_data', 'company_name', 'timezone', 'max_logs_per_system',
        'log_retention_days', 'min_log_level', 'pure1_display_name',
        'pure1_app_id', 'pure1_private_key', 'pure1_private_key_passphrase',
        'pure1_public_key', 'proxy_http', 'proxy_https', 'proxy_no_proxy',
        'dashboard_refresh_interval',
    ]

    SOD_HISTORY_COLUMNS = ['on_demand_tb']

    def test_storage_systems_columns_whitelisted(self):
        from app.migrations import ALLOWED_COLUMNS
        for col in self.STORAGE_SYSTEMS_COLUMNS:
            assert col in ALLOWED_COLUMNS, f"'{col}' missing from ALLOWED_COLUMNS"

    def test_app_settings_columns_whitelisted(self):
        from app.migrations import ALLOWED_COLUMNS
        for col in self.APP_SETTINGS_COLUMNS:
            assert col in ALLOWED_COLUMNS, f"'{col}' missing from ALLOWED_COLUMNS"

    def test_sod_history_columns_whitelisted(self):
        from app.migrations import ALLOWED_COLUMNS
        for col in self.SOD_HISTORY_COLUMNS:
            assert col in ALLOWED_COLUMNS, f"'{col}' missing from ALLOWED_COLUMNS"


# ---------------------------------------------------------------------------
# Unit tests – _get_column_type dialect handling
# ---------------------------------------------------------------------------

class TestGetColumnType:
    """_get_column_type should return dialect-adjusted SQL type strings."""

    def test_sqlite_last_discovery_is_datetime(self, minimal_app):
        import app.migrations as mig
        original_db = mig.db
        with minimal_app.app_context():
            from flask_sqlalchemy import SQLAlchemy as _SA
            _db = _SA()
            _db.init_app(minimal_app)
            mig.db = _db
            try:
                result = mig._get_column_type('last_discovery')
                assert result == 'DATETIME'
            finally:
                mig.db = original_db

    def test_sqlite_logo_data_is_blob(self, minimal_app):
        import app.migrations as mig
        original_db = mig.db
        with minimal_app.app_context():
            from flask_sqlalchemy import SQLAlchemy as _SA
            _db = _SA()
            _db.init_app(minimal_app)
            mig.db = _db
            try:
                result = mig._get_column_type('logo_data')
                assert result == 'BLOB'
            finally:
                mig.db = original_db

    def test_non_overridden_column_returns_base_type(self, minimal_app):
        import app.migrations as mig
        original_db = mig.db
        with minimal_app.app_context():
            from flask_sqlalchemy import SQLAlchemy as _SA
            _db = _SA()
            _db.init_app(minimal_app)
            mig.db = _db
            try:
                assert mig._get_column_type('os_version') == 'VARCHAR(100)'
                assert mig._get_column_type('on_demand_tb') == 'FLOAT'
            finally:
                mig.db = original_db


# ---------------------------------------------------------------------------
# Integration tests – add_column_if_not_exists
# ---------------------------------------------------------------------------

class TestAddColumnIfNotExists:

    def test_adds_missing_column(self, minimal_app, db):
        import app.migrations as mig
        original_db = mig.db
        mig.db = db
        try:
            _create_minimal_table(db, 'storage_systems')
            assert not _column_exists(db, 'storage_systems', 'os_version')
            result = mig.add_column_if_not_exists('storage_systems', 'os_version', 'VARCHAR(100)')
            assert result is True
            assert _column_exists(db, 'storage_systems', 'os_version')
        finally:
            mig.db = original_db

    def test_skips_existing_column(self, minimal_app, db):
        import app.migrations as mig
        original_db = mig.db
        mig.db = db
        try:
            _create_minimal_table(db, 'storage_systems')
            # Add once – should succeed
            mig.add_column_if_not_exists('storage_systems', 'os_version', 'VARCHAR(100)')
            # Add again – should be a no-op
            result = mig.add_column_if_not_exists('storage_systems', 'os_version', 'VARCHAR(100)')
            assert result is False
        finally:
            mig.db = original_db

    def test_rejects_unknown_column(self, minimal_app, db):
        import app.migrations as mig
        original_db = mig.db
        mig.db = db
        try:
            _create_minimal_table(db, 'storage_systems')
            with pytest.raises(ValueError, match="not in allowed migration list"):
                mig.add_column_if_not_exists('storage_systems', 'evil_column', 'TEXT')
        finally:
            mig.db = original_db

    def test_rejects_invalid_table_name(self, minimal_app, db):
        import app.migrations as mig
        original_db = mig.db
        mig.db = db
        try:
            with pytest.raises(ValueError, match="Invalid SQL identifier"):
                mig.add_column_if_not_exists('bad-table', 'os_version', 'VARCHAR(100)')
        finally:
            mig.db = original_db

    def test_rejects_invalid_column_name(self, minimal_app, db):
        import app.migrations as mig
        original_db = mig.db
        mig.db = db
        try:
            with pytest.raises(ValueError, match="Invalid SQL identifier"):
                mig.add_column_if_not_exists('storage_systems', '1bad', 'TEXT')
        finally:
            mig.db = original_db


# ---------------------------------------------------------------------------
# Integration tests – migrate_storage_systems_table
# ---------------------------------------------------------------------------

class TestMigrateStorageSystemsTable:

    def test_adds_all_missing_columns(self, minimal_app, db):
        import app.migrations as mig
        original_db = mig.db
        mig.db = db
        try:
            _create_minimal_table(db, 'storage_systems')
            applied = mig.migrate_storage_systems_table()
            expected = [
                'cluster_type', 'node_count', 'site_count', 'dns_names', 'all_ips',
                'node_details', 'partner_cluster_id', 'last_discovery', 'discovery_error',
                'os_version', 'api_version', 'peer_connections', 'metrocluster_info',
                'metrocluster_dr_groups', 'ha_info', 'pure1_array_name',
            ]
            assert set(applied) == set(expected)
            for col in expected:
                assert _column_exists(db, 'storage_systems', col), f"Column '{col}' not found"
        finally:
            mig.db = original_db

    def test_idempotent_when_columns_exist(self, minimal_app, db):
        import app.migrations as mig
        original_db = mig.db
        mig.db = db
        try:
            _create_minimal_table(db, 'storage_systems')
            mig.migrate_storage_systems_table()
            # Second run should apply nothing
            applied = mig.migrate_storage_systems_table()
            assert applied == []
        finally:
            mig.db = original_db


# ---------------------------------------------------------------------------
# Integration tests – migrate_app_settings_table
# ---------------------------------------------------------------------------

class TestMigrateAppSettingsTable:

    def test_adds_all_missing_columns(self, minimal_app, db):
        import app.migrations as mig
        original_db = mig.db
        mig.db = db
        try:
            _create_minimal_table(db, 'app_settings')
            applied = mig.migrate_app_settings_table()
            expected = [
                'primary_color', 'secondary_color', 'accent_color', 'logo_filename',
                'logo_data', 'company_name', 'timezone', 'max_logs_per_system',
                'log_retention_days', 'min_log_level', 'pure1_display_name',
                'pure1_app_id', 'pure1_private_key', 'pure1_private_key_passphrase',
                'pure1_public_key', 'proxy_http', 'proxy_https', 'proxy_no_proxy',
                'dashboard_refresh_interval',
            ]
            assert set(applied) == set(expected)
            for col in expected:
                assert _column_exists(db, 'app_settings', col), f"Column '{col}' not found"
        finally:
            mig.db = original_db

    def test_idempotent_when_columns_exist(self, minimal_app, db):
        import app.migrations as mig
        original_db = mig.db
        mig.db = db
        try:
            _create_minimal_table(db, 'app_settings')
            mig.migrate_app_settings_table()
            applied = mig.migrate_app_settings_table()
            assert applied == []
        finally:
            mig.db = original_db


# ---------------------------------------------------------------------------
# Integration tests – migrate_sod_history_table
# ---------------------------------------------------------------------------

class TestMigrateSodHistoryTable:

    def test_adds_on_demand_tb(self, minimal_app, db):
        import app.migrations as mig
        original_db = mig.db
        mig.db = db
        try:
            _create_minimal_table(db, 'sod_history')
            applied = mig.migrate_sod_history_table()
            assert 'on_demand_tb' in applied
            assert _column_exists(db, 'sod_history', 'on_demand_tb')
        finally:
            mig.db = original_db

    def test_idempotent(self, minimal_app, db):
        import app.migrations as mig
        original_db = mig.db
        mig.db = db
        try:
            _create_minimal_table(db, 'sod_history')
            mig.migrate_sod_history_table()
            applied = mig.migrate_sod_history_table()
            assert applied == []
        finally:
            mig.db = original_db


# ---------------------------------------------------------------------------
# Integration tests – run_all_migrations (smoke test with empty schema)
# ---------------------------------------------------------------------------

class TestRunAllMigrations:

    def test_run_on_fresh_db_returns_empty_list(self, minimal_app, db):
        """If no tables exist yet (brand-new DB), run_all_migrations returns []."""
        import app.migrations as mig
        original_db = mig.db
        mig.db = db
        try:
            result = mig.run_all_migrations()
            assert isinstance(result, list)
            assert result == []
        finally:
            mig.db = original_db

    def test_run_on_partial_schema_applies_migrations(self, minimal_app, db):
        """Minimal tables → migrations are applied and list is non-empty."""
        import app.migrations as mig
        original_db = mig.db
        mig.db = db
        try:
            _create_minimal_table(db, 'storage_systems')
            _create_minimal_table(db, 'app_settings')
            _create_minimal_table(db, 'sod_history')
            result = mig.run_all_migrations()
            assert isinstance(result, list)
            assert len(result) > 0
        finally:
            mig.db = original_db

    def test_run_all_idempotent(self, minimal_app, db):
        """Running twice in a row: second call applies nothing."""
        import app.migrations as mig
        original_db = mig.db
        mig.db = db
        try:
            _create_minimal_table(db, 'storage_systems')
            _create_minimal_table(db, 'app_settings')
            _create_minimal_table(db, 'sod_history')
            mig.run_all_migrations()
            result = mig.run_all_migrations()
            # Only datadomain_port migration may run (returns 0 updated systems → not appended)
            assert result == []
        finally:
            mig.db = original_db
