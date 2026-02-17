"""Admin routes for managing storage systems"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import StorageSystem, Certificate, AdminUser, AppSettings
from app.discovery import auto_discover_system
from datetime import datetime
import logging
import io
import json

bp = Blueprint('admin', __name__, url_prefix='/admin')
logger = logging.getLogger(__name__)


# Authentication routes

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login page"""
    if current_user.is_authenticated:
        return redirect(url_for('admin.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = AdminUser.query.filter_by(username=username).first()
        
        if user and user.check_password(password) and user.is_active:
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/admin'):
                return redirect(next_page)
            return redirect(url_for('admin.index'))
        else:
            flash('Ungültiger Benutzername oder Passwort', 'error')
    
    return render_template('admin/login.html')


@bp.route('/logout')
@login_required
def logout():
    """Logout admin user"""
    logout_user()
    flash('Sie wurden erfolgreich abgemeldet', 'success')
    return redirect(url_for('admin.login'))


@bp.route('/')
@login_required
def index():
    """Admin dashboard"""
    systems = StorageSystem.query.all()
    return render_template('admin/index.html', systems=systems)


@bp.route('/systems/new', methods=['GET', 'POST'])
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
def docs():
    """API setup documentation"""
    return render_template('admin/docs.html')


# Certificate Management Routes

@bp.route('/certificates')
@login_required
def certificates():
    """List all certificates"""
    certs = Certificate.query.all()
    return render_template('admin/certificates.html', certificates=certs)


@bp.route('/certificates/new', methods=['GET', 'POST'])
@login_required
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
            try:
                cert_pem = cert_file.read().decode('utf-8')
            except UnicodeDecodeError:
                flash('Das Zertifikat muss UTF-8 kodiert sein oder im PEM-Format vorliegen.', 'error')
                return redirect(url_for('admin.new_certificate'))
            
            # Validate PEM format
            if '-----BEGIN CERTIFICATE-----' not in cert_pem:
                flash('Ungültiges Zertifikatsformat. Nur PEM-Format wird unterstützt.', 'error')
                return redirect(url_for('admin.new_certificate'))
            
            # Validate certificate can be parsed
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            except Exception as e:
                flash(f'Zertifikat konnte nicht geladen werden: {str(e)}', 'error')
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
@login_required
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
                    try:
                        cert_pem = cert_file.read().decode('utf-8')
                    except UnicodeDecodeError:
                        flash('Das Zertifikat muss UTF-8 kodiert sein oder im PEM-Format vorliegen.', 'warning')
                        return render_template('admin/certificate_form.html', certificate=certificate, action='Edit')
                    
                    if '-----BEGIN CERTIFICATE-----' in cert_pem:
                        # Validate certificate can be parsed
                        try:
                            from cryptography import x509
                            from cryptography.hazmat.backends import default_backend
                            x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                            certificate.certificate_pem = cert_pem
                        except Exception as e:
                            flash(f'Zertifikat konnte nicht geladen werden: {str(e)}', 'warning')
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
@login_required
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
@login_required
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
@login_required
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


# Export/Import Routes

@bp.route('/export')
@login_required
def export_systems():
    """Export all storage systems as JSON"""
    try:
        systems = StorageSystem.query.all()
        export_data = {
            'version': '1.0',
            'export_date': datetime.utcnow().isoformat(),
            'systems': []
        }
        
        for system in systems:
            system_data = {
                'name': system.name,
                'vendor': system.vendor,
                'ip_address': system.ip_address,
                'port': system.port,
                'api_username': system.api_username,  # Will be decrypted
                'api_password': system.api_password,  # Will be decrypted
                'api_token': system.api_token,  # Will be decrypted
                'enabled': system.enabled,
                'cluster_type': system.cluster_type,
                'node_count': system.node_count,
                'site_count': system.site_count,
                'dns_names': system.get_dns_names(),
                'all_ips': system.get_all_ips(),
            }
            export_data['systems'].append(system_data)
        
        # Create JSON file
        json_data = json.dumps(export_data, indent=2)
        json_bytes = json_data.encode('utf-8')
        json_io = io.BytesIO(json_bytes)
        
        filename = f"storage_systems_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        return send_file(
            json_io,
            mimetype='application/json',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        logger.error(f'Error exporting systems: {e}', exc_info=True)
        flash(f'Fehler beim Exportieren: {str(e)}', 'error')
        return redirect(url_for('admin.index'))


@bp.route('/import', methods=['GET', 'POST'])
@login_required
def import_systems():
    """Import storage systems from JSON"""
    if request.method == 'POST':
        try:
            if 'import_file' not in request.files:
                flash('Keine Datei hochgeladen', 'error')
                return redirect(url_for('admin.import_systems'))
            
            import_file = request.files['import_file']
            if import_file.filename == '':
                flash('Keine Datei ausgewählt', 'error')
                return redirect(url_for('admin.import_systems'))
            
            # Read and parse JSON
            try:
                import_data = json.loads(import_file.read().decode('utf-8'))
            except Exception as e:
                flash(f'Ungültige JSON-Datei: {str(e)}', 'error')
                return redirect(url_for('admin.import_systems'))
            
            # Validate structure
            if 'systems' not in import_data:
                flash('Ungültiges Dateiformat: "systems" nicht gefunden', 'error')
                return redirect(url_for('admin.import_systems'))
            
            imported_count = 0
            skipped_count = 0
            
            for system_data in import_data['systems']:
                # Check if system already exists
                existing = StorageSystem.query.filter_by(name=system_data['name']).first()
                if existing:
                    skipped_count += 1
                    continue
                
                # Create new system
                system = StorageSystem(
                    name=system_data['name'],
                    vendor=system_data['vendor'],
                    ip_address=system_data['ip_address'],
                    port=system_data.get('port', 443),
                    api_username=system_data.get('api_username'),  # Will be encrypted
                    api_password=system_data.get('api_password'),  # Will be encrypted
                    api_token=system_data.get('api_token'),  # Will be encrypted
                    enabled=system_data.get('enabled', True),
                    cluster_type=system_data.get('cluster_type'),
                    node_count=system_data.get('node_count'),
                    site_count=system_data.get('site_count'),
                )
                
                system.set_dns_names(system_data.get('dns_names', []))
                system.set_all_ips(system_data.get('all_ips', []))
                
                db.session.add(system)
                imported_count += 1
            
            db.session.commit()
            
            flash(f'Import erfolgreich: {imported_count} Systeme importiert, {skipped_count} übersprungen (bereits vorhanden)', 'success')
            return redirect(url_for('admin.index'))
            
        except Exception as e:
            logger.error(f'Error importing systems: {e}', exc_info=True)
            flash(f'Fehler beim Importieren: {str(e)}', 'error')
    
    return render_template('admin/import.html')


# Settings Routes

@bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Application settings and customization"""
    # Get or create settings
    app_settings = AppSettings.query.first()
    if not app_settings:
        app_settings = AppSettings()
        db.session.add(app_settings)
        db.session.commit()
    
    if request.method == 'POST':
        try:
            # Update colors
            app_settings.primary_color = request.form.get('primary_color', '#A70240')
            app_settings.secondary_color = request.form.get('secondary_color', '#BED600')
            app_settings.accent_color = request.form.get('accent_color', '#0098DB')
            app_settings.company_name = request.form.get('company_name', 'Storage Dashboard')
            
            # Handle logo upload
            if 'logo_file' in request.files:
                logo_file = request.files['logo_file']
                if logo_file.filename != '':
                    # Validate file type
                    if logo_file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.svg', '.gif')):
                        app_settings.logo_filename = logo_file.filename
                        app_settings.logo_data = logo_file.read()
                    else:
                        flash('Ungültiges Dateiformat. Nur PNG, JPG, SVG, GIF erlaubt.', 'warning')
            
            db.session.commit()
            flash('Einstellungen gespeichert', 'success')
            return redirect(url_for('admin.settings'))
            
        except Exception as e:
            logger.error(f'Error saving settings: {e}', exc_info=True)
            flash(f'Fehler beim Speichern: {str(e)}', 'error')
    
    return render_template('admin/settings.html', settings=app_settings)


@bp.route('/settings/logo')
def settings_logo():
    """Serve the custom logo"""
    app_settings = AppSettings.query.first()
    if app_settings and app_settings.logo_data:
        # Determine mimetype from filename
        mimetype = 'image/png'
        if app_settings.logo_filename:
            if app_settings.logo_filename.lower().endswith('.svg'):
                mimetype = 'image/svg+xml'
            elif app_settings.logo_filename.lower().endswith(('.jpg', '.jpeg')):
                mimetype = 'image/jpeg'
            elif app_settings.logo_filename.lower().endswith('.gif'):
                mimetype = 'image/gif'
        
        return send_file(
            io.BytesIO(app_settings.logo_data),
            mimetype=mimetype
        )
    
    # Return 404 if no logo
    return '', 404

