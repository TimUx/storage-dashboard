"""Admin routes for managing storage systems"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import StorageSystem, Certificate, AdminUser, AppSettings, Tag, TagGroup
from app.discovery import auto_discover_system
from app.constants import (
    VENDOR_DEFAULT_PORTS, 
    VENDOR_PORT_DESCRIPTIONS,
    STANDARD_PORTS
)
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
    # Tag filter: OR within same group, AND across groups
    tag_ids = request.args.getlist('tag', type=int)
    query = StorageSystem.query
    if tag_ids:
        # Load the selected tags to know their groups
        selected_tags = Tag.query.filter(Tag.id.in_(tag_ids)).all()
        # Group tag IDs by their group_id
        from collections import defaultdict
        group_to_tag_ids = defaultdict(list)
        for t in selected_tags:
            group_to_tag_ids[t.group_id].append(t.id)
        # AND across groups, OR within each group
        for ids in group_to_tag_ids.values():
            query = query.filter(StorageSystem.tags.any(Tag.id.in_(ids)))
    systems = query.all()
    tag_groups = TagGroup.query.order_by(TagGroup.name).all()
    return render_template('admin/index.html', systems=systems, tag_groups=tag_groups, selected_tag_ids=tag_ids)


@bp.route('/systems/new', methods=['GET', 'POST'])
@login_required
def new_system():
    """Create new storage system with auto-discovery"""
    if request.method == 'POST':
        try:
            vendor = request.form['vendor']
            
            # Determine default port based on vendor if not specified
            default_port = VENDOR_DEFAULT_PORTS.get(vendor, 443)
            port = int(request.form.get('port', default_port))
            
            # Create system with basic info
            system = StorageSystem(
                name=request.form['name'],
                vendor=vendor,
                ip_address=request.form['ip_address'],
                port=port,
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
                
                # Save HA info if present (for DataDomain)
                if discovery_result.get('ha_info'):
                    system.set_ha_info(discovery_result.get('ha_info'))
                
                # Save OS version and API version if present
                if discovery_result.get('os_version'):
                    system.os_version = discovery_result.get('os_version')
                if discovery_result.get('api_version'):
                    system.api_version = discovery_result.get('api_version')
                
                system.last_discovery = datetime.utcnow()
                
                flash(f'System added and discovered successfully! Found {system.node_count or 0} nodes.', 'success')
            else:
                system.discovery_error = discovery_result.get('error')
                system.set_dns_names(discovery_result.get('dns_names', []))
                system.set_all_ips(discovery_result.get('all_ips', []))
                flash(f'System added but discovery had issues: {discovery_result.get("error")}', 'warning')
            
            db.session.add(system)
            
            # Handle tag assignment
            selected_tag_ids = request.form.getlist('tags')
            system.tags = Tag.query.filter(Tag.id.in_([int(t) for t in selected_tag_ids if t.isdigit()])).all()
            
            db.session.commit()
            return redirect(url_for('admin.index'))
            
        except Exception as e:
            logger.error(f'Error adding system: {e}', exc_info=True)
            flash(f'Error adding system: {str(e)}', 'error')
    
    tag_groups = TagGroup.query.order_by(TagGroup.name).all()
    return render_template('admin/form.html', system=None, action='Create', 
                         vendor_ports=VENDOR_DEFAULT_PORTS, 
                         vendor_port_descriptions=VENDOR_PORT_DESCRIPTIONS,
                         standard_ports=STANDARD_PORTS,
                         tag_groups=tag_groups)


@bp.route('/systems/<int:system_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_system(system_id):
    """Edit storage system"""
    system = StorageSystem.query.get_or_404(system_id)
    
    if request.method == 'POST':
        try:
            vendor = request.form['vendor']
            
            # Determine default port based on vendor if not specified
            default_port = VENDOR_DEFAULT_PORTS.get(vendor, 443)
            port = int(request.form.get('port', default_port))
            
            system.name = request.form['name']
            system.vendor = vendor
            system.ip_address = request.form['ip_address']
            system.port = port
            system.api_username = request.form.get('api_username', '').strip() or None
            system.api_password = request.form.get('api_password', '').strip() or None
            system.api_token = request.form.get('api_token', '').strip() or None
            system.enabled = request.form.get('enabled') == 'on'
            
            # Handle tag assignment
            selected_tag_ids = request.form.getlist('tags')
            system.tags = Tag.query.filter(Tag.id.in_([int(t) for t in selected_tag_ids if t.isdigit()])).all()
            
            db.session.commit()
            flash('Storage system updated successfully', 'success')
            return redirect(url_for('admin.index'))
        except Exception as e:
            flash(f'Error updating system: {str(e)}', 'error')
    
    tag_groups = TagGroup.query.order_by(TagGroup.name).all()
    return render_template('admin/form.html', system=system, action='Edit', 
                         vendor_ports=VENDOR_DEFAULT_PORTS, 
                         vendor_port_descriptions=VENDOR_PORT_DESCRIPTIONS,
                         standard_ports=STANDARD_PORTS,
                         tag_groups=tag_groups)


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
            
            # Save HA info if present (for DataDomain)
            if discovery_result.get('ha_info'):
                system.set_ha_info(discovery_result.get('ha_info'))
            
            # Save OS version and API version if present
            if discovery_result.get('os_version'):
                system.os_version = discovery_result.get('os_version')
            if discovery_result.get('api_version'):
                system.api_version = discovery_result.get('api_version')
            
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


@bp.route('/systems/rediscover-all', methods=['POST'])
@login_required
def rediscover_all_systems():
    """Re-run discovery for all storage systems"""
    from flask import current_app
    ssl_verify = current_app.config.get('SSL_VERIFY', False)
    
    systems = StorageSystem.query.all()
    
    if not systems:
        flash('No storage systems configured', 'warning')
        return redirect(url_for('admin.index'))
    
    success_count = 0
    error_count = 0
    
    for system in systems:
        try:
            discovery_result = auto_discover_system(
                vendor=system.vendor,
                ip_address=system.ip_address,
                username=system.api_username,
                password=system.api_password,
                api_token=system.api_token,
                ssl_verify=ssl_verify
            )
            
            if 'error' not in discovery_result:
                system.cluster_type = discovery_result.get('cluster_type')
                system.node_count = discovery_result.get('node_count')
                system.site_count = discovery_result.get('site_count')
                system.set_dns_names(discovery_result.get('dns_names', []))
                system.set_all_ips(discovery_result.get('all_ips', []))
                system.set_node_details(discovery_result.get('node_details', []))
                
                # Save HA info if present (for DataDomain)
                if discovery_result.get('ha_info'):
                    system.set_ha_info(discovery_result.get('ha_info'))
                
                # Save OS version and API version if present
                if discovery_result.get('os_version'):
                    system.os_version = discovery_result.get('os_version')
                if discovery_result.get('api_version'):
                    system.api_version = discovery_result.get('api_version')
                
                system.last_discovery = datetime.utcnow()
                system.discovery_error = None
                success_count += 1
            else:
                system.discovery_error = discovery_result.get('error')
                system.last_discovery = datetime.utcnow()
                error_count += 1
                logger.warning(f'Discovery error for {system.name}: {discovery_result.get("error")}')
        
        except Exception as e:
            system.discovery_error = str(e)
            system.last_discovery = datetime.utcnow()
            error_count += 1
            logger.error(f'Error re-discovering system {system.name}: {e}', exc_info=True)
    
    # Commit all changes
    try:
        db.session.commit()
        
        if error_count == 0:
            flash(f'All {success_count} systems successfully re-discovered!', 'success')
        elif success_count > 0:
            flash(f'{success_count} systems re-discovered successfully, {error_count} had errors.', 'warning')
        else:
            flash(f'All {error_count} systems had discovery errors. Check system details for more information.', 'error')
    except Exception as e:
        db.session.rollback()
        logger.error(f'Error committing discovery changes: {e}', exc_info=True)
        flash(f'Error saving discovery results: {str(e)}', 'error')
    
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
    """Application settings and customization with tabbed interface"""
    # Get or create settings
    app_settings = AppSettings.query.first()
    if not app_settings:
        app_settings = AppSettings()
        db.session.add(app_settings)
        db.session.commit()
    
    # Get certificates for the certificates tab
    certificates = Certificate.query.order_by(Certificate.created_at.desc()).all()
    
    if request.method == 'POST':
        try:
            # Update design settings
            app_settings.primary_color = request.form.get('primary_color', '#A70240')
            app_settings.secondary_color = request.form.get('secondary_color', '#BED600')
            app_settings.accent_color = request.form.get('accent_color', '#0098DB')
            app_settings.company_name = request.form.get('company_name', 'Storage Dashboard')
            
            # Update system settings
            app_settings.timezone = request.form.get('timezone', 'Europe/Berlin')
            
            # Update log settings
            max_logs = request.form.get('max_logs_per_system')
            if max_logs:
                app_settings.max_logs_per_system = int(max_logs)
            
            retention_days = request.form.get('log_retention_days')
            if retention_days:
                app_settings.log_retention_days = int(retention_days)
            
            app_settings.min_log_level = request.form.get('min_log_level', 'INFO')

            # Update Pure1 API credentials
            # Display name and App ID: always overwrite (empty = clear)
            app_settings.pure1_display_name = request.form.get('pure1_display_name', '').strip() or None
            app_settings.pure1_app_id = request.form.get('pure1_app_id', '').strip() or None
            # Keys: only overwrite if a new value was explicitly submitted
            new_private_key = request.form.get('pure1_private_key', '').strip()
            if new_private_key:
                app_settings.pure1_private_key = new_private_key
            new_public_key = request.form.get('pure1_public_key', '').strip()
            if new_public_key:
                app_settings.pure1_public_key = new_public_key

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
    
    return render_template('admin/settings_tabbed.html', settings=app_settings, certificates=certificates)


@bp.route('/settings/logo')
def settings_logo():
    """Serve the custom logo
    
    Note: This endpoint is intentionally NOT protected by @login_required
    because the logo is displayed in the public navbar and should be
    accessible to all users viewing the application.
    """
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
    from app.system_logging import get_system_logs
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
    
    logs = pagination.items
    
    # Get all systems for the filter dropdown
    systems = StorageSystem.query.order_by(StorageSystem.name).all()
    
    # Get available levels and categories for filters
    available_levels = ['INFO', 'WARNING', 'ERROR', 'CRITICAL']
    available_categories = ['connection', 'authentication', 'api_call', 'data_query']
    
    return render_template('admin/logs.html',
                         logs=logs,
                         systems=systems,
                         pagination=pagination,
                         selected_system_id=system_id,
                         selected_level=level,
                         selected_category=category,
                         available_levels=available_levels,
                         available_categories=available_categories)


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


# Tag Management Routes

@bp.route('/tags')
@login_required
def tags():
    """List all tag groups and tags"""
    tag_groups = TagGroup.query.order_by(TagGroup.name).all()
    return render_template('admin/tags.html', tag_groups=tag_groups)


@bp.route('/tags/groups/new', methods=['GET', 'POST'])
@login_required
def new_tag_group():
    """Create a new tag group"""
    if request.method == 'POST':
        try:
            name = request.form['name'].strip()
            description = request.form.get('description', '').strip()
            if not name:
                flash('Name darf nicht leer sein', 'error')
            elif TagGroup.query.filter_by(name=name).first():
                flash(f'Tag-Gruppe "{name}" existiert bereits', 'error')
            else:
                group = TagGroup(name=name, description=description or None)
                db.session.add(group)
                db.session.commit()
                flash(f'Tag-Gruppe "{name}" erstellt', 'success')
                return redirect(url_for('admin.tags'))
        except Exception as e:
            logger.error(f'Error creating tag group: {e}', exc_info=True)
            flash(f'Fehler: {str(e)}', 'error')
    return render_template('admin/tag_group_form.html', group=None, action='Erstellen')


@bp.route('/tags/groups/<int:group_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_tag_group(group_id):
    """Edit a tag group"""
    group = TagGroup.query.get_or_404(group_id)
    if request.method == 'POST':
        try:
            name = request.form['name'].strip()
            description = request.form.get('description', '').strip()
            if not name:
                flash('Name darf nicht leer sein', 'error')
            else:
                group.name = name
                group.description = description or None
                db.session.commit()
                flash(f'Tag-Gruppe "{name}" aktualisiert', 'success')
                return redirect(url_for('admin.tags'))
        except Exception as e:
            logger.error(f'Error editing tag group: {e}', exc_info=True)
            flash(f'Fehler: {str(e)}', 'error')
    return render_template('admin/tag_group_form.html', group=group, action='Bearbeiten')


@bp.route('/tags/groups/<int:group_id>/delete', methods=['POST'])
@login_required
def delete_tag_group(group_id):
    """Delete a tag group and all its tags"""
    try:
        group = TagGroup.query.get_or_404(group_id)
        name = group.name
        db.session.delete(group)
        db.session.commit()
        flash(f'Tag-Gruppe "{name}" gelöscht', 'success')
    except Exception as e:
        logger.error(f'Error deleting tag group: {e}', exc_info=True)
        flash(f'Fehler: {str(e)}', 'error')
    return redirect(url_for('admin.tags'))


@bp.route('/tags/new', methods=['GET', 'POST'])
@login_required
def new_tag():
    """Create a new tag"""
    tag_groups = TagGroup.query.order_by(TagGroup.name).all()
    if request.method == 'POST':
        try:
            name = request.form['name'].strip()
            group_id = int(request.form['group_id'])
            if not name:
                flash('Name darf nicht leer sein', 'error')
            elif Tag.query.filter_by(name=name, group_id=group_id).first():
                flash(f'Tag "{name}" existiert bereits in dieser Gruppe', 'error')
            else:
                tag = Tag(name=name, group_id=group_id)
                db.session.add(tag)
                db.session.commit()
                flash(f'Tag "{name}" erstellt', 'success')
                return redirect(url_for('admin.tags'))
        except Exception as e:
            logger.error(f'Error creating tag: {e}', exc_info=True)
            flash(f'Fehler: {str(e)}', 'error')
    return render_template('admin/tag_form.html', tag=None, tag_groups=tag_groups, action='Erstellen')


@bp.route('/tags/<int:tag_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_tag(tag_id):
    """Edit a tag"""
    tag = Tag.query.get_or_404(tag_id)
    tag_groups = TagGroup.query.order_by(TagGroup.name).all()
    if request.method == 'POST':
        try:
            name = request.form['name'].strip()
            group_id = int(request.form['group_id'])
            if not name:
                flash('Name darf nicht leer sein', 'error')
            else:
                tag.name = name
                tag.group_id = group_id
                db.session.commit()
                flash(f'Tag "{name}" aktualisiert', 'success')
                return redirect(url_for('admin.tags'))
        except Exception as e:
            logger.error(f'Error editing tag: {e}', exc_info=True)
            flash(f'Fehler: {str(e)}', 'error')
    return render_template('admin/tag_form.html', tag=tag, tag_groups=tag_groups, action='Bearbeiten')


@bp.route('/tags/<int:tag_id>/delete', methods=['POST'])
@login_required
def delete_tag(tag_id):
    """Delete a tag"""
    try:
        tag = Tag.query.get_or_404(tag_id)
        name = tag.name
        db.session.delete(tag)
        db.session.commit()
        flash(f'Tag "{name}" gelöscht', 'success')
    except Exception as e:
        logger.error(f'Error deleting tag: {e}', exc_info=True)
        flash(f'Fehler: {str(e)}', 'error')
    return redirect(url_for('admin.tags'))

