"""Logging utility for system events"""
from app.models import SystemLog, db, AppSettings
from datetime import datetime, timedelta
from sqlalchemy.exc import OperationalError, SQLAlchemyError
import logging
import time

logger = logging.getLogger(__name__)

# Configuration constants
CLEANUP_FREQUENCY_DIVISOR = 10  # Cleanup runs for 1 in every N log events (10 = 10%)
MAX_LOG_RETRIES = 3  # Maximum retry attempts for log operations
CLEANUP_RETRIES = 2  # Maximum retry attempts for cleanup operations
RETRY_BASE_DELAY = 0.1  # Base delay in seconds for retry backoff


def get_log_settings():
    """Get log settings from AppSettings, with fallback to defaults"""
    settings = AppSettings.query.first()
    if settings:
        return {
            'max_logs_per_system': settings.max_logs_per_system or 1000,
            'log_retention_days': settings.log_retention_days or 30,
            'min_log_level': settings.min_log_level or 'INFO'
        }
    return {
        'max_logs_per_system': 1000,
        'log_retention_days': 30,
        'min_log_level': 'INFO'
    }


# Log level priority for filtering
LOG_LEVELS = {
    'DEBUG': 10,
    'INFO': 20,
    'WARNING': 30,
    'ERROR': 40,
    'CRITICAL': 50
}


def should_log(level):
    """Check if a log level should be recorded based on settings"""
    settings = get_log_settings()
    min_level = settings['min_log_level']
    
    return LOG_LEVELS.get(level.upper(), 0) >= LOG_LEVELS.get(min_level, 20)


def log_system_event(system_id, level, category, message, details=None, status_code=None, api_endpoint=None):
    """
    Log a system event to the database
    
    Args:
        system_id: ID of the storage system
        level: Log level (INFO, WARNING, ERROR, CRITICAL)
        category: Event category (connection, authentication, api_call, data_query)
        message: Short message describing the event
        details: Optional detailed information (e.g., stack trace)
        status_code: Optional HTTP status code
        api_endpoint: Optional API endpoint that was called
    """
    # Check if this log level should be recorded
    if not should_log(level):
        return
    
    # Retry logic for database locking issues
    for attempt in range(MAX_LOG_RETRIES):
        try:
            log_entry = SystemLog(
                system_id=system_id,
                level=level.upper(),
                category=category,
                message=message,
                details=details,
                status_code=status_code,
                api_endpoint=api_endpoint
            )
            db.session.add(log_entry)
            db.session.commit()
            
            # Clean up old logs to prevent database growth
            # Only cleanup periodically to reduce database load
            # Use system_id as a simple hash to distribute cleanup across different calls
            if isinstance(system_id, int) and system_id % CLEANUP_FREQUENCY_DIVISOR == 0:
                cleanup_old_logs(system_id)
            
            return  # Success, exit the retry loop
            
        except OperationalError as e:
            # Handle database locking errors with retry
            error_msg = str(e).lower()
            if 'database is locked' in error_msg or 'locked' in error_msg:
                db.session.rollback()
                if attempt < MAX_LOG_RETRIES - 1:
                    # Exponential backoff: 0.1s, 0.2s, 0.4s
                    sleep_time = RETRY_BASE_DELAY * (2 ** attempt)
                    time.sleep(sleep_time)
                    continue
                else:
                    logger.warning(f"Failed to log system event after {MAX_LOG_RETRIES} attempts (database locked): {message}")
            else:
                # Different operational error, don't retry
                logger.error(f"Failed to log system event: {e}")
                db.session.rollback()
            return
            
        except SQLAlchemyError as e:
            logger.error(f"Failed to log system event: {e}")
            try:
                db.session.rollback()
            except Exception:
                pass
            return
            
        except Exception as e:
            logger.error(f"Unexpected error logging system event: {e}")
            try:
                db.session.rollback()
            except Exception:
                pass
            return


def cleanup_old_logs(system_id, max_logs=None):
    """
    Remove old log entries to prevent database growth
    Keeps only the most recent max_logs entries per system
    Also removes logs older than retention_days
    
    Args:
        system_id: ID of the storage system
        max_logs: Maximum number of logs to keep (if None, uses settings)
    """
    for attempt in range(CLEANUP_RETRIES):
        try:
            settings = get_log_settings()
            if max_logs is None:
                max_logs = settings['max_logs_per_system']
            
            retention_days = settings['log_retention_days']
            
            # Delete logs older than retention period using bulk delete
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            deleted_old = SystemLog.query.filter(
                SystemLog.system_id == system_id,
                SystemLog.timestamp < cutoff_date
            ).delete(synchronize_session=False)
            
            # Count total logs for this system after date cleanup
            total_logs = SystemLog.query.filter_by(system_id=system_id).count()
            
            deleted_excess = 0
            if total_logs > max_logs:
                # Get IDs of logs to delete (keep only the newest max_logs)
                logs_to_delete_result = db.session.query(SystemLog.id).filter_by(system_id=system_id)\
                    .order_by(SystemLog.timestamp.desc())\
                    .offset(max_logs)\
                    .all()
                
                if logs_to_delete_result:
                    # Extract IDs from the query result tuples and bulk delete
                    ids_list = [log_id[0] for log_id in logs_to_delete_result]
                    deleted_excess = SystemLog.query.filter(SystemLog.id.in_(ids_list)).delete(synchronize_session=False)
            
            if deleted_old > 0 or deleted_excess > 0:
                db.session.commit()
                total_deleted = deleted_old + deleted_excess
                logger.debug(f"Cleaned up {total_deleted} old log entries for system {system_id}")
            
            return  # Success, exit retry loop
            
        except OperationalError as e:
            # Handle database locking errors with retry
            error_msg = str(e).lower()
            if 'database is locked' in error_msg or 'locked' in error_msg:
                db.session.rollback()
                if attempt < CLEANUP_RETRIES - 1:
                    sleep_time = RETRY_BASE_DELAY * (2 ** attempt)
                    time.sleep(sleep_time)
                    continue
                else:
                    logger.debug(f"Skipped cleanup for system {system_id} (database locked)")
            else:
                logger.error(f"Failed to cleanup old logs: {e}")
                db.session.rollback()
            return
            
        except SQLAlchemyError as e:
            logger.error(f"Failed to cleanup old logs: {e}")
            try:
                db.session.rollback()
            except Exception:
                pass
            return
            
        except Exception as e:
            logger.error(f"Unexpected error during log cleanup: {e}")
            try:
                db.session.rollback()
            except Exception:
                pass
            return


def get_system_logs(system_id=None, level=None, category=None, limit=100, offset=0):
    """
    Retrieve system logs with optional filtering
    
    Args:
        system_id: Optional system ID to filter by
        level: Optional log level to filter by
        category: Optional category to filter by
        limit: Maximum number of logs to return
        offset: Number of logs to skip (for pagination)
    
    Returns:
        List of SystemLog objects
    """
    query = SystemLog.query
    
    if system_id:
        query = query.filter_by(system_id=system_id)
    if level:
        query = query.filter_by(level=level.upper())
    if category:
        query = query.filter_by(category=category)
    
    return query.order_by(SystemLog.timestamp.desc()).limit(limit).offset(offset).all()


def get_recent_errors(system_id=None, hours=24, limit=50):
    """
    Get recent error logs
    
    Args:
        system_id: Optional system ID to filter by
        hours: Number of hours to look back
        limit: Maximum number of errors to return
    
    Returns:
        List of SystemLog objects with level ERROR or CRITICAL
    """
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    query = SystemLog.query.filter(
        SystemLog.timestamp >= cutoff_time,
        SystemLog.level.in_(['ERROR', 'CRITICAL'])
    )
    
    if system_id:
        query = query.filter_by(system_id=system_id)
    
    return query.order_by(SystemLog.timestamp.desc()).limit(limit).all()
