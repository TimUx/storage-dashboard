"""Database migration utilities for Storage Dashboard"""
import sqlite3
import logging
from app import db
from app.constants import VENDOR_DELL_DATADOMAIN, VENDOR_DEFAULT_PORTS
import re

logger = logging.getLogger(__name__)

# Allowed column names and types for validation (whitelist approach)
ALLOWED_COLUMNS = {
    'os_version': 'VARCHAR(100)',
    'api_version': 'VARCHAR(50)',
    'peer_connections': 'TEXT',
    'metrocluster_info': 'TEXT',
    'metrocluster_dr_groups': 'TEXT',
    'ha_info': 'TEXT',
}


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
        column_type: Column type (validated against whitelist)
        default: Default value (not currently used to avoid injection risk)
    """
    # Validate table and column names
    validate_identifier(table_name)
    validate_identifier(column_name)
    
    # Check if column is in allowed list
    if column_name not in ALLOWED_COLUMNS:
        raise ValueError(f"Column {column_name} not in allowed migration list")
    
    # Use whitelisted column type
    if ALLOWED_COLUMNS[column_name] != column_type:
        logger.warning(f"Column type mismatch for {column_name}: expected {ALLOWED_COLUMNS[column_name]}, got {column_type}")
        column_type = ALLOWED_COLUMNS[column_name]
    
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
    
    # Add os_version column if missing
    if add_column_if_not_exists('storage_systems', 'os_version', 'VARCHAR(100)'):
        migrations_applied.append('os_version')
    
    # Add api_version column if missing
    if add_column_if_not_exists('storage_systems', 'api_version', 'VARCHAR(50)'):
        migrations_applied.append('api_version')
    
    # Add peer_connections column if missing
    if add_column_if_not_exists('storage_systems', 'peer_connections', 'TEXT'):
        migrations_applied.append('peer_connections')
    
    # Add metrocluster_info column if missing
    if add_column_if_not_exists('storage_systems', 'metrocluster_info', 'TEXT'):
        migrations_applied.append('metrocluster_info')
    
    # Add metrocluster_dr_groups column if missing
    if add_column_if_not_exists('storage_systems', 'metrocluster_dr_groups', 'TEXT'):
        migrations_applied.append('metrocluster_dr_groups')
    
    # Add ha_info column if missing (for DataDomain HA clusters)
    if add_column_if_not_exists('storage_systems', 'ha_info', 'TEXT'):
        migrations_applied.append('ha_info')
    
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
        
        if all_migrations:
            logger.info(f"Applied {len(all_migrations)} migrations: {', '.join(all_migrations)}")
        else:
            logger.info("No migrations needed, database schema is up to date.")
        
        return all_migrations
    except Exception as e:
        logger.error(f"Error running migrations: {e}")
        raise
