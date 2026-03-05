"""Database migration utilities for Storage Dashboard"""
import sqlite3
import logging
from app import db
from app.constants import VENDOR_DELL_DATADOMAIN, VENDOR_DEFAULT_PORTS
import re

logger = logging.getLogger(__name__)

# Allowed column names and types for validation (whitelist approach).
# Values are the default SQL type string; dialect-specific overrides are
# handled by _get_column_type() below (e.g. DATETIME vs TIMESTAMP, BLOB vs BYTEA).
ALLOWED_COLUMNS = {
    # storage_systems – originally present columns that may be absent in older installs
    'cluster_type': 'VARCHAR(50)',
    'node_count': 'INTEGER',
    'site_count': 'INTEGER',
    'dns_names': 'TEXT',
    'all_ips': 'TEXT',
    'node_details': 'TEXT',
    'partner_cluster_id': 'INTEGER',
    'last_discovery': 'DATETIME',   # overridden to TIMESTAMP on PostgreSQL
    'discovery_error': 'TEXT',
    # storage_systems – columns added via previous migrations
    'os_version': 'VARCHAR(100)',
    'api_version': 'VARCHAR(50)',
    'peer_connections': 'TEXT',
    'metrocluster_info': 'TEXT',
    'metrocluster_dr_groups': 'TEXT',
    'ha_info': 'TEXT',
    # storage_systems – Pure1 array name override for Evergreen One physical capacity
    'pure1_array_name': 'VARCHAR(100)',
    # app_settings – originally present columns that may be absent in older installs
    'primary_color': 'VARCHAR(7)',
    'secondary_color': 'VARCHAR(7)',
    'accent_color': 'VARCHAR(7)',
    'logo_filename': 'VARCHAR(255)',
    'logo_data': 'BLOB',            # overridden to BYTEA on PostgreSQL
    'company_name': 'VARCHAR(100)',
    # app_settings – columns added via previous migrations
    'timezone': 'VARCHAR(50)',
    'max_logs_per_system': 'INTEGER',
    'log_retention_days': 'INTEGER',
    'min_log_level': 'VARCHAR(20)',
    'pure1_display_name': 'TEXT',
    'pure1_app_id': 'TEXT',
    'pure1_private_key': 'TEXT',
    'pure1_private_key_passphrase': 'TEXT',
    'pure1_public_key': 'TEXT',
    'proxy_http': 'TEXT',
    'proxy_https': 'TEXT',
    'proxy_no_proxy': 'TEXT',
    'dashboard_refresh_interval': 'INTEGER',
    # sod_history
    'on_demand_tb': 'FLOAT',
}

# Dialect-specific type overrides: {column_name: {dialect_name: sql_type}}
_DIALECT_TYPE_OVERRIDES = {
    'last_discovery': {'postgresql': 'TIMESTAMP'},
    'logo_data':      {'postgresql': 'BYTEA'},
}


def _get_column_type(column_name):
    """Return the SQL type string for *column_name*, adjusted for the active DB dialect."""
    base_type = ALLOWED_COLUMNS[column_name]
    dialect = db.engine.dialect.name
    overrides = _DIALECT_TYPE_OVERRIDES.get(column_name, {})
    return overrides.get(dialect, base_type)


def validate_identifier(identifier, allowed_pattern=r'^[a-zA-Z_][a-zA-Z0-9_]*$'):
    """Validate SQL identifier to prevent SQL injection"""
    if not re.match(allowed_pattern, identifier):
        raise ValueError(f"Invalid SQL identifier: {identifier}")
    return identifier


def get_column_names(table_name):
    """Get existing column names for a table"""
    validate_identifier(table_name)
    inspector = db.inspect(db.engine)
    columns = inspector.get_columns(table_name)
    return [col['name'] for col in columns]


def add_column_if_not_exists(table_name, column_name, column_type, default=None):
    """Add a column to a table if it doesn't exist
    
    Args:
        table_name: Table name (validated against SQL injection)
        column_name: Column name (validated against SQL injection)
        column_type: Column type (validated against whitelist; ignored in favour of
                     the whitelisted type to prevent injection)
        default: Default value (not currently used to avoid injection risk)
    """
    # Validate table and column names
    validate_identifier(table_name)
    validate_identifier(column_name)
    
    # Check if column is in allowed list
    if column_name not in ALLOWED_COLUMNS:
        raise ValueError(f"Column {column_name} not in allowed migration list")
    
    # Always use the whitelisted type (dialect-adjusted) to prevent injection
    base_type = ALLOWED_COLUMNS[column_name]
    column_type = _get_column_type(column_name)
    if base_type != column_type:
        logger.debug(f"Using dialect-specific type for {column_name}: {column_type}")
    
    existing_columns = get_column_names(table_name)
    
    if column_name in existing_columns:
        logger.info(f"Column {table_name}.{column_name} already exists, skipping.")
        return False
    
    # Build ALTER TABLE statement using validated identifiers
    # Note: SQLite doesn't support parameterized ALTER TABLE, so we use validated string formatting
    alter_stmt = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"
    
    logger.info(f"Adding column {table_name}.{column_name} ({column_type})")
    
    try:
        with db.engine.connect() as conn:
            conn.execute(db.text(alter_stmt))
            conn.commit()
        logger.info(f"Successfully added column {table_name}.{column_name}")
        return True
    except Exception as e:
        # Handle race condition where another worker already added the column
        # SQLAlchemy wraps sqlite3 errors in sqlalchemy.exc.OperationalError
        from sqlalchemy.exc import OperationalError
        if isinstance(e, OperationalError):
            error_msg = str(e).lower()
            if 'duplicate column' in error_msg or 'already exists' in error_msg:
                logger.info(f"Column {table_name}.{column_name} already exists (added by another worker)")
                return False
        # For all other errors, log and re-raise
        logger.error(f"Error adding column {table_name}.{column_name}: {e}")
        raise


def migrate_storage_systems_table():
    """Migrate storage_systems table to add missing columns"""
    migrations_applied = []

    # Columns that may be absent in older installations (nullable, no default needed)
    nullable_columns = [
        ('cluster_type',        ALLOWED_COLUMNS['cluster_type']),
        ('node_count',          ALLOWED_COLUMNS['node_count']),
        ('site_count',          ALLOWED_COLUMNS['site_count']),
        ('dns_names',           ALLOWED_COLUMNS['dns_names']),
        ('all_ips',             ALLOWED_COLUMNS['all_ips']),
        ('node_details',        ALLOWED_COLUMNS['node_details']),
        ('partner_cluster_id',  ALLOWED_COLUMNS['partner_cluster_id']),
        ('last_discovery',      ALLOWED_COLUMNS['last_discovery']),
        ('discovery_error',     ALLOWED_COLUMNS['discovery_error']),
        ('os_version',          ALLOWED_COLUMNS['os_version']),
        ('api_version',         ALLOWED_COLUMNS['api_version']),
        ('peer_connections',    ALLOWED_COLUMNS['peer_connections']),
        ('metrocluster_info',   ALLOWED_COLUMNS['metrocluster_info']),
        ('metrocluster_dr_groups', ALLOWED_COLUMNS['metrocluster_dr_groups']),
        ('ha_info',             ALLOWED_COLUMNS['ha_info']),
        ('pure1_array_name',    ALLOWED_COLUMNS['pure1_array_name']),
    ]
    for col_name, col_type in nullable_columns:
        if add_column_if_not_exists('storage_systems', col_name, col_type):
            migrations_applied.append(col_name)
    
    return migrations_applied


def migrate_app_settings_table():
    """Migrate app_settings table to add missing columns"""
    migrations_applied = []

    # Columns that may be absent in older installations
    columns = [
        # Branding / UI columns (may predate log/Pure1/proxy columns in some installs)
        ('primary_color',   ALLOWED_COLUMNS['primary_color']),
        ('secondary_color', ALLOWED_COLUMNS['secondary_color']),
        ('accent_color',    ALLOWED_COLUMNS['accent_color']),
        ('logo_filename',   ALLOWED_COLUMNS['logo_filename']),
        ('logo_data',       ALLOWED_COLUMNS['logo_data']),
        ('company_name',    ALLOWED_COLUMNS['company_name']),
        # Log retention settings
        ('timezone',            ALLOWED_COLUMNS['timezone']),
        ('max_logs_per_system', ALLOWED_COLUMNS['max_logs_per_system']),
        ('log_retention_days',  ALLOWED_COLUMNS['log_retention_days']),
        ('min_log_level',       ALLOWED_COLUMNS['min_log_level']),
        # Pure1 API credential columns
        ('pure1_display_name',          ALLOWED_COLUMNS['pure1_display_name']),
        ('pure1_app_id',                ALLOWED_COLUMNS['pure1_app_id']),
        ('pure1_private_key',           ALLOWED_COLUMNS['pure1_private_key']),
        ('pure1_private_key_passphrase', ALLOWED_COLUMNS['pure1_private_key_passphrase']),
        ('pure1_public_key',            ALLOWED_COLUMNS['pure1_public_key']),
        # Proxy settings
        ('proxy_http',     ALLOWED_COLUMNS['proxy_http']),
        ('proxy_https',    ALLOWED_COLUMNS['proxy_https']),
        ('proxy_no_proxy', ALLOWED_COLUMNS['proxy_no_proxy']),
        # Dashboard refresh interval
        ('dashboard_refresh_interval', ALLOWED_COLUMNS['dashboard_refresh_interval']),
    ]
    for col_name, col_type in columns:
        if add_column_if_not_exists('app_settings', col_name, col_type):
            migrations_applied.append(col_name)

    return migrations_applied


def migrate_datadomain_port():
    """Update existing DataDomain systems to use port 3009 if they're using the default port 443
    
    Uses constants from app.constants to ensure consistency with the rest of the application.
    """
    try:
        from app.models import StorageSystem
        
        # Get the correct DataDomain port from constants
        correct_port = VENDOR_DEFAULT_PORTS[VENDOR_DELL_DATADOMAIN]
        
        # Find all DataDomain systems using port 443 (incorrect default)
        # Note: We check for 443 specifically as that was the old default
        datadomain_systems = StorageSystem.query.filter_by(vendor=VENDOR_DELL_DATADOMAIN, port=443).all()
        
        if not datadomain_systems:
            logger.info(f"No {VENDOR_DELL_DATADOMAIN} systems found with port 443, skipping port migration.")
            return 0
        
        count = 0
        for system in datadomain_systems:
            logger.info(f"Updating Dell DataDomain system '{system.name}' ({system.ip_address}) from port 443 to {correct_port}")
            system.port = correct_port
            count += 1
        
        db.session.commit()
        logger.info(f"Successfully updated {count} Dell DataDomain system(s) to use port {correct_port}")
        return count
        
    except Exception as e:
        logger.error(f"Error migrating DataDomain ports: {e}")
        db.session.rollback()
        raise


def seed_initial_tags():
    """Seed initial tag groups and tags if they don't exist yet"""
    from app.models import TagGroup, Tag

    initial_data = [
        {
            'name': 'Storage Art',
            'description': 'Art des Storage Systems',
            'tags': ['Block', 'File', 'Object', 'Archiv', 'Backup'],
        },
        {
            'name': 'Landschaft',
            'description': 'Betriebsumgebung',
            'tags': ['Produktion', 'Test/Dev'],
        },
        {
            'name': 'Themenzugehörigkeit',
            'description': 'Thematische Zuordnung',
            'tags': ['ERZ', 'EGK', 'OGS', 'EH', 'KNG', 'ITS', 'TSY'],
        },
    ]

    seeded = []
    for group_data in initial_data:
        group = TagGroup.query.filter_by(name=group_data['name']).first()
        if not group:
            group = TagGroup(name=group_data['name'], description=group_data['description'])
            db.session.add(group)
            db.session.flush()  # get the id
            logger.info(f"Created tag group: {group_data['name']}")
            seeded.append(group_data['name'])

        for tag_name in group_data['tags']:
            existing_tag = Tag.query.filter_by(name=tag_name, group_id=group.id).first()
            if not existing_tag:
                db.session.add(Tag(name=tag_name, group_id=group.id))
                logger.info(f"Created tag: {tag_name} in group {group_data['name']}")

    if seeded:
        db.session.commit()
        logger.info(f"Seeded {len(seeded)} tag group(s)")
    return seeded


def migrate_sod_history_table():
    """Migrate sod_history table to add missing columns."""
    migrations_applied = []
    if add_column_if_not_exists('sod_history', 'on_demand_tb', ALLOWED_COLUMNS['on_demand_tb']):
        migrations_applied.append('on_demand_tb')
    return migrations_applied


def run_all_migrations():
    """Run all pending database migrations"""
    logger.info("Starting database migrations...")
    all_migrations = []
    
    try:
        # Check if storage_systems table exists
        inspector = db.inspect(db.engine)
        if 'storage_systems' in inspector.get_table_names():
            migrations = migrate_storage_systems_table()
            all_migrations.extend(migrations)
            
            # Run DataDomain port migration
            try:
                updated_count = migrate_datadomain_port()
                if updated_count > 0:
                    all_migrations.append(f'datadomain_port_3009 ({updated_count} systems)')
            except Exception as e:
                logger.warning(f"DataDomain port migration failed (non-critical): {e}")
        
        # Check if app_settings table exists and run migrations
        if 'app_settings' in inspector.get_table_names():
            migrations = migrate_app_settings_table()
            all_migrations.extend(migrations)

        # Migrate sod_history table
        if 'sod_history' in inspector.get_table_names():
            migrations = migrate_sod_history_table()
            all_migrations.extend(migrations)
        
        # Seed initial tags if tag_groups table exists
        if 'tag_groups' in inspector.get_table_names():
            try:
                seeded = seed_initial_tags()
                if seeded:
                    all_migrations.extend([f'seed_tag_group:{g}' for g in seeded])
            except Exception as e:
                logger.warning(f"Tag seeding failed (non-critical): {e}")
        
        if all_migrations:
            logger.info(f"Applied {len(all_migrations)} migrations: {', '.join(all_migrations)}")
        else:
            logger.info("No migrations needed, database schema is up to date.")
        
        return all_migrations
    except Exception as e:
        logger.error(f"Error running migrations: {e}")
        raise
