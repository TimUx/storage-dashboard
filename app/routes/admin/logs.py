"""Admin system log views."""
import logging

from flask import flash, redirect, render_template, request, url_for
from flask_login import login_required

from app import db
from app.models import StorageSystem
from app.routes.admin import bp

logger = logging.getLogger(__name__)


@bp.route('/logs')
@login_required
def logs():
    """System logs view"""
    # Get filter parameters
    system_id = request.args.get('system_id', type=int)
    level = request.args.get('level')
    category = request.args.get('category')
    page = request.args.get('page', 1, type=int)
    per_page = 100

    # Import here to avoid circular imports
    from app.models import SystemLog

    # Build query
    query = SystemLog.query

    if system_id:
        query = query.filter_by(system_id=system_id)
    if level:
        query = query.filter_by(level=level.upper())
    if category:
        query = query.filter_by(category=category)

    # Get paginated results
    pagination = query.order_by(SystemLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    logs_list = pagination.items

    # Get all systems for the filter dropdown
    systems = StorageSystem.query.order_by(StorageSystem.name).all()

    # Get available levels and categories for filters
    available_levels = ['INFO', 'WARNING', 'ERROR', 'CRITICAL']
    available_categories = ['connection', 'authentication', 'api_call', 'data_query']

    return render_template(
        'admin/logs.html',
        logs=logs_list,
        systems=systems,
        pagination=pagination,
        selected_system_id=system_id,
        selected_level=level,
        selected_category=category,
        available_levels=available_levels,
        available_categories=available_categories,
    )


@bp.route('/logs/<int:log_id>')
@login_required
def log_detail(log_id):
    """View detailed information for a specific log entry"""
    from app.models import SystemLog
    log = SystemLog.query.get_or_404(log_id)
    return render_template('admin/log_detail.html', log=log)


@bp.route('/logs/clear', methods=['POST'])
@login_required
def clear_logs():
    """Clear logs for a specific system or all systems"""
    system_id = request.form.get('system_id', type=int)

    from app.models import SystemLog

    try:
        if system_id:
            # Clear logs for specific system
            SystemLog.query.filter_by(system_id=system_id).delete()
            system = StorageSystem.query.get(system_id)
            flash(f'Logs für System "{system.name}" wurden gelöscht', 'success')
        else:
            # Clear all logs
            SystemLog.query.delete()
            flash('Alle System-Logs wurden gelöscht', 'success')

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f'Fehler beim Löschen der Logs: {str(e)}', 'error')
        logger.error(f"Error clearing logs: {e}")

    return redirect(url_for('admin.logs'))
