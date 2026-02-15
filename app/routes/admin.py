"""Admin routes for managing storage systems"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from app import db
from app.models import StorageSystem
from app.discovery import auto_discover_system
from datetime import datetime
import logging

bp = Blueprint('admin', __name__, url_prefix='/admin')
logger = logging.getLogger(__name__)


@bp.route('/')
def index():
    """Admin dashboard"""
    systems = StorageSystem.query.all()
    return render_template('admin/index.html', systems=systems)


@bp.route('/systems/new', methods=['GET', 'POST'])
def new_system():
    """Create new storage system with auto-discovery"""
    if request.method == 'POST':
        try:
            # Create system with basic info
            system = StorageSystem(
                name=request.form['name'],
                vendor=request.form['vendor'],
                ip_address=request.form['ip_address'],
                port=int(request.form.get('port', 443)),
                api_username=request.form.get('api_username', '').strip() or None,
                api_password=request.form.get('api_password', '').strip() or None,
                api_token=request.form.get('api_token', '').strip() or None,
                enabled=request.form.get('enabled') == 'on'
            )
            
            # Auto-discover system details
            discovery_result = auto_discover_system(
                vendor=system.vendor,
                ip_address=system.ip_address,
                username=system.api_username,
                password=system.api_password,
                api_token=system.api_token,
                ssl_verify=False  # Could be made configurable
            )
            
            # Update system with discovered info
            if 'error' not in discovery_result:
                system.cluster_type = discovery_result.get('cluster_type')
                system.node_count = discovery_result.get('node_count')
                system.site_count = discovery_result.get('site_count')
                system.set_dns_names(discovery_result.get('dns_names', []))
                system.set_all_ips(discovery_result.get('all_ips', []))
                system.set_node_details(discovery_result.get('node_details', []))
                system.last_discovery = datetime.utcnow()
                
                flash(f'System added and discovered successfully! Found {system.node_count or 0} nodes.', 'success')
            else:
                system.discovery_error = discovery_result.get('error')
                system.set_dns_names(discovery_result.get('dns_names', []))
                system.set_all_ips(discovery_result.get('all_ips', []))
                flash(f'System added but discovery had issues: {discovery_result.get("error")}', 'warning')
            
            db.session.add(system)
            db.session.commit()
            return redirect(url_for('admin.index'))
            
        except Exception as e:
            logger.error(f'Error adding system: {e}', exc_info=True)
            flash(f'Error adding system: {str(e)}', 'error')
    
    return render_template('admin/form.html', system=None, action='Create')


@bp.route('/systems/<int:system_id>/edit', methods=['GET', 'POST'])
def edit_system(system_id):
    """Edit storage system"""
    system = StorageSystem.query.get_or_404(system_id)
    
    if request.method == 'POST':
        try:
            system.name = request.form['name']
            system.vendor = request.form['vendor']
            system.ip_address = request.form['ip_address']
            system.port = int(request.form.get('port', 443))
            system.api_username = request.form.get('api_username', '').strip() or None
            system.api_password = request.form.get('api_password', '').strip() or None
            system.api_token = request.form.get('api_token', '').strip() or None
            system.enabled = request.form.get('enabled') == 'on'
            
            db.session.commit()
            flash('Storage system updated successfully', 'success')
            return redirect(url_for('admin.index'))
        except Exception as e:
            flash(f'Error updating system: {str(e)}', 'error')
    
    return render_template('admin/form.html', system=system, action='Edit')


@bp.route('/systems/<int:system_id>/rediscover', methods=['POST'])
def rediscover_system(system_id):
    """Re-run discovery for a system"""
    system = StorageSystem.query.get_or_404(system_id)
    
    try:
        discovery_result = auto_discover_system(
            vendor=system.vendor,
            ip_address=system.ip_address,
            username=system.api_username,
            password=system.api_password,
            api_token=system.api_token,
            ssl_verify=False
        )
        
        if 'error' not in discovery_result:
            system.cluster_type = discovery_result.get('cluster_type')
            system.node_count = discovery_result.get('node_count')
            system.site_count = discovery_result.get('site_count')
            system.set_dns_names(discovery_result.get('dns_names', []))
            system.set_all_ips(discovery_result.get('all_ips', []))
            system.set_node_details(discovery_result.get('node_details', []))
            system.last_discovery = datetime.utcnow()
            system.discovery_error = None
            
            db.session.commit()
            flash(f'System re-discovered successfully! Found {system.node_count or 0} nodes.', 'success')
        else:
            system.discovery_error = discovery_result.get('error')
            system.last_discovery = datetime.utcnow()
            db.session.commit()
            flash(f'Discovery had issues: {discovery_result.get("error")}', 'warning')
            
    except Exception as e:
        logger.error(f'Error re-discovering system: {e}', exc_info=True)
        flash(f'Error re-discovering system: {str(e)}', 'error')
    
    return redirect(url_for('admin.index'))


@bp.route('/systems/<int:system_id>/delete', methods=['POST'])
def delete_system(system_id):
    """Delete storage system"""
    try:
        system = StorageSystem.query.get_or_404(system_id)
        db.session.delete(system)
        db.session.commit()
        flash('Storage system deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting system: {str(e)}', 'error')
    
    return redirect(url_for('admin.index'))


@bp.route('/docs')
def docs():
    """API setup documentation"""
    return render_template('admin/docs.html')
