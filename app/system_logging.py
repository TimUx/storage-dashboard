"""Logging utility for system events"""
from app.models import SystemLog, db
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

# Maximum number of log entries to keep per system
MAX_LOGS_PER_SYSTEM = 1000


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
        cleanup_old_logs(system_id)
        
    except Exception as e:
        logger.error(f"Failed to log system event: {e}")
        # Don't raise - logging failures shouldn't break the application
        try:
            db.session.rollback()
        except:
            pass


def cleanup_old_logs(system_id, max_logs=MAX_LOGS_PER_SYSTEM):
    """
    Remove old log entries to prevent database growth
    Keeps only the most recent max_logs entries per system
    
    Args:
        system_id: ID of the storage system
        max_logs: Maximum number of logs to keep
    """
    try:
        # Count total logs for this system
        total_logs = SystemLog.query.filter_by(system_id=system_id).count()
        
        if total_logs > max_logs:
            # Get IDs of logs to delete (keep only the newest max_logs)
            logs_to_delete = SystemLog.query.filter_by(system_id=system_id)\
                .order_by(SystemLog.timestamp.desc())\
                .offset(max_logs)\
                .all()
            
            for log in logs_to_delete:
                db.session.delete(log)
            
            db.session.commit()
            logger.debug(f"Cleaned up {len(logs_to_delete)} old log entries for system {system_id}")
            
    except Exception as e:
        logger.error(f"Failed to cleanup old logs: {e}")
        try:
            db.session.rollback()
        except:
            pass


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
