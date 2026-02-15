"""Admin routes for managing storage systems"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from app import db
from app.models import StorageSystem

bp = Blueprint('admin', __name__, url_prefix='/admin')


@bp.route('/')
def index():
    """Admin dashboard"""
    systems = StorageSystem.query.all()
    return render_template('admin/index.html', systems=systems)


@bp.route('/systems/new', methods=['GET', 'POST'])
def new_system():
    """Create new storage system"""
    if request.method == 'POST':
        try:
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
            db.session.add(system)
            db.session.commit()
            flash('Storage system added successfully', 'success')
            return redirect(url_for('admin.index'))
        except Exception as e:
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
