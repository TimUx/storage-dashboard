"""Database migration utilities for Storage Dashboard"""
import sqlite3
import logging
from app import db

logger = logging.getLogger(__name__)


def get_column_names(table_name):
    """Get existing column names for a table"""
    inspector = db.inspect(db.engine)
    columns = inspector.get_columns(table_name)
    return [col['name'] for col in columns]


def add_column_if_not_exists(table_name, column_name, column_type, default=None):
    """Add a column to a table if it doesn't exist"""
    existing_columns = get_column_names(table_name)
    
    if column_name in existing_columns:
        logger.info(f"Column {table_name}.{column_name} already exists, skipping.")
        return False
    
    # Build ALTER TABLE statement
    alter_stmt = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"
    if default is not None:
        alter_stmt += f" DEFAULT {default}"
    
    logger.info(f"Adding column {table_name}.{column_name} ({column_type})")
    
    try:
        with db.engine.connect() as conn:
            conn.execute(db.text(alter_stmt))
            conn.commit()
        logger.info(f"Successfully added column {table_name}.{column_name}")
        return True
    except Exception as e:
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
        
        if all_migrations:
            logger.info(f"Applied {len(all_migrations)} migrations: {', '.join(all_migrations)}")
        else:
            logger.info("No migrations needed, database schema is up to date.")
        
        return all_migrations
    except Exception as e:
        logger.error(f"Error running migrations: {e}")
        raise
