"""Admin routes for managing storage systems"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file
from app import db
from app.models import StorageSystem, Certificate
from app.discovery import auto_discover_system
from datetime import datetime
import logging
import io

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


# Certificate Management Routes

@bp.route('/certificates')
def certificates():
    """List all certificates"""
    certs = Certificate.query.all()
    return render_template('admin/certificates.html', certificates=certs)


@bp.route('/certificates/new', methods=['GET', 'POST'])
def new_certificate():
    """Upload new certificate"""
    if request.method == 'POST':
        try:
            name = request.form['name']
            cert_type = request.form['certificate_type']
            description = request.form.get('description', '')
            
            # Read uploaded file
            if 'certificate_file' not in request.files:
                flash('Keine Zertifikatsdatei hochgeladen', 'error')
                return redirect(url_for('admin.new_certificate'))
            
            cert_file = request.files['certificate_file']
            if cert_file.filename == '':
                flash('Keine Datei ausgewählt', 'error')
                return redirect(url_for('admin.new_certificate'))
            
            # Read certificate content
            cert_pem = cert_file.read().decode('utf-8')
            
            # Basic validation
            if '-----BEGIN CERTIFICATE-----' not in cert_pem:
                flash('Ungültiges Zertifikatsformat. Nur PEM-Format wird unterstützt.', 'error')
                return redirect(url_for('admin.new_certificate'))
            
            # Create certificate
            certificate = Certificate(
                name=name,
                certificate_type=cert_type,
                certificate_pem=cert_pem,
                description=description,
                enabled=request.form.get('enabled') == 'on'
            )
            
            db.session.add(certificate)
            db.session.commit()
            
            flash(f'Zertifikat "{name}" erfolgreich hochgeladen', 'success')
            return redirect(url_for('admin.certificates'))
            
        except Exception as e:
            logger.error(f'Error uploading certificate: {e}', exc_info=True)
            flash(f'Fehler beim Hochladen: {str(e)}', 'error')
    
    return render_template('admin/certificate_form.html', certificate=None, action='Create')


@bp.route('/certificates/<int:cert_id>/edit', methods=['GET', 'POST'])
def edit_certificate(cert_id):
    """Edit certificate"""
    certificate = Certificate.query.get_or_404(cert_id)
    
    if request.method == 'POST':
        try:
            certificate.name = request.form['name']
            certificate.certificate_type = request.form['certificate_type']
            certificate.description = request.form.get('description', '')
            certificate.enabled = request.form.get('enabled') == 'on'
            
            # Optionally update certificate file
            if 'certificate_file' in request.files:
                cert_file = request.files['certificate_file']
                if cert_file.filename != '':
                    cert_pem = cert_file.read().decode('utf-8')
                    if '-----BEGIN CERTIFICATE-----' in cert_pem:
                        certificate.certificate_pem = cert_pem
                    else:
                        flash('Ungültiges Zertifikatsformat', 'warning')
            
            db.session.commit()
            flash('Zertifikat aktualisiert', 'success')
            return redirect(url_for('admin.certificates'))
            
        except Exception as e:
            logger.error(f'Error updating certificate: {e}', exc_info=True)
            flash(f'Fehler beim Aktualisieren: {str(e)}', 'error')
    
    return render_template('admin/certificate_form.html', certificate=certificate, action='Edit')


@bp.route('/certificates/<int:cert_id>/toggle', methods=['POST'])
def toggle_certificate(cert_id):
    """Toggle certificate enabled status"""
    try:
        certificate = Certificate.query.get_or_404(cert_id)
        certificate.enabled = not certificate.enabled
        db.session.commit()
        
        status = 'aktiviert' if certificate.enabled else 'deaktiviert'
        flash(f'Zertifikat "{certificate.name}" {status}', 'success')
    except Exception as e:
        logger.error(f'Error toggling certificate: {e}', exc_info=True)
        flash(f'Fehler: {str(e)}', 'error')
    
    return redirect(url_for('admin.certificates'))


@bp.route('/certificates/<int:cert_id>/download')
def download_certificate(cert_id):
    """Download certificate as PEM file"""
    try:
        certificate = Certificate.query.get_or_404(cert_id)
        
        # Create file-like object from certificate PEM
        cert_bytes = certificate.certificate_pem.encode('utf-8')
        cert_io = io.BytesIO(cert_bytes)
        
        filename = f"{certificate.name.replace(' ', '_')}.pem"
        
        return send_file(
            cert_io,
            mimetype='application/x-pem-file',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        logger.error(f'Error downloading certificate: {e}', exc_info=True)
        flash(f'Fehler beim Download: {str(e)}', 'error')
        return redirect(url_for('admin.certificates'))


@bp.route('/certificates/<int:cert_id>/delete', methods=['POST'])
def delete_certificate(cert_id):
    """Delete certificate"""
    try:
        certificate = Certificate.query.get_or_404(cert_id)
        name = certificate.name
        db.session.delete(certificate)
        db.session.commit()
        flash(f'Zertifikat "{name}" gelöscht', 'success')
    except Exception as e:
        logger.error(f'Error deleting certificate: {e}', exc_info=True)
        flash(f'Fehler beim Löschen: {str(e)}', 'error')
    
    return redirect(url_for('admin.certificates'))
