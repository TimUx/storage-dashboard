"""JSON export/import of systems and full backup/restore."""
import base64
import io
import json
import logging
from datetime import datetime

from flask import flash, redirect, render_template, request, send_file, url_for
from flask_login import login_required

from app import db
from app.models import AppSettings, Certificate, StorageSystem, Tag, TagGroup
from app.routes.admin import bp

logger = logging.getLogger(__name__)


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
                'snaps_enabled': system.snaps_enabled,
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
                    snaps_enabled=system_data.get('snaps_enabled', True),
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


@bp.route('/backup/export')
@login_required
def export_backup():
    """Export a full backup: settings, systems (with credentials), certificates and tags."""
    try:
        # --- AppSettings ---
        settings_obj = AppSettings.query.first()
        settings_data = {}
        if settings_obj:
            settings_data = {
                'primary_color': settings_obj.primary_color,
                'secondary_color': settings_obj.secondary_color,
                'accent_color': settings_obj.accent_color,
                'company_name': settings_obj.company_name,
                'timezone': settings_obj.timezone,
                'max_logs_per_system': settings_obj.max_logs_per_system,
                'log_retention_days': settings_obj.log_retention_days,
                'min_log_level': settings_obj.min_log_level,
                'dashboard_refresh_interval': settings_obj.dashboard_refresh_interval,
                # Pure1 credentials (decrypted plain-text in the backup)
                'pure1_display_name': settings_obj.pure1_display_name,
                'pure1_app_id': settings_obj.pure1_app_id,
                'pure1_private_key': settings_obj.pure1_private_key,
                'pure1_private_key_passphrase': settings_obj.pure1_private_key_passphrase,
                'pure1_public_key': settings_obj.pure1_public_key,
                # Proxy settings (decrypted plain-text in the backup)
                'proxy_http': settings_obj.proxy_http,
                'proxy_https': settings_obj.proxy_https,
                'proxy_no_proxy': settings_obj.proxy_no_proxy,
                # Logo (base64-encoded binary)
                'logo_filename': settings_obj.logo_filename,
                'logo_data': base64.b64encode(settings_obj.logo_data).decode() if settings_obj.logo_data else None,
            }

        # --- Storage Systems ---
        systems_data = []
        for sys in StorageSystem.query.order_by(StorageSystem.name).all():
            systems_data.append({
                'name': sys.name,
                'vendor': sys.vendor,
                'ip_address': sys.ip_address,
                'port': sys.port,
                'api_username': sys.api_username,
                'api_password': sys.api_password,
                'api_token': sys.api_token,
                'enabled': sys.enabled,
                'snaps_enabled': sys.snaps_enabled,
                'cluster_type': sys.cluster_type,
                'node_count': sys.node_count,
                'site_count': sys.site_count,
                'dns_names': sys.get_dns_names(),
                'all_ips': sys.get_all_ips(),
                'pure1_array_name': sys.pure1_array_name,
                # Tag references preserved as (group, tag) pairs
                'tags': [{'group': t.group.name, 'tag': t.name} for t in sys.tags],
            })

        # --- Certificates ---
        certs_data = []
        for cert in Certificate.query.order_by(Certificate.name).all():
            certs_data.append({
                'name': cert.name,
                'certificate_type': cert.certificate_type,
                'certificate_pem': cert.certificate_pem,
                'description': cert.description,
                'enabled': cert.enabled,
            })

        # --- Tag Groups + Tags ---
        tag_groups_data = []
        for grp in TagGroup.query.order_by(TagGroup.name).all():
            tag_groups_data.append({
                'name': grp.name,
                'description': grp.description,
                'tags': [{'name': t.name} for t in grp.tags.order_by(Tag.name)],
            })

        backup_payload = {
            'backup_version': '1.0',
            'backup_date': datetime.utcnow().isoformat(),
            'backup_type': 'full',
            'settings': settings_data,
            'systems': systems_data,
            'certificates': certs_data,
            'tag_groups': tag_groups_data,
        }

        json_bytes = json.dumps(backup_payload, indent=2, ensure_ascii=False).encode('utf-8')
        filename = f"storage_dashboard_backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"

        return send_file(
            io.BytesIO(json_bytes),
            mimetype='application/json',
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        logger.error(f'Error creating full backup: {e}', exc_info=True)
        flash(f'Fehler beim Erstellen des Backups: {str(e)}', 'error')
        return redirect(url_for('admin.settings'))


@bp.route('/backup/import', methods=['POST'])
@login_required
def import_backup():
    """Restore from a full-backup JSON file.

    Restore behaviour per section:
    - settings   : always overwrite (full restore)
    - tag_groups : skip groups/tags that already exist by name
    - systems    : skip systems whose name already exists
    - certificates: skip certificates whose name already exists
    """
    try:
        if 'backup_file' not in request.files:
            flash('Keine Datei hochgeladen', 'error')
            return redirect(url_for('admin.settings'))

        backup_file = request.files['backup_file']
        if backup_file.filename == '':
            flash('Keine Datei ausgewählt', 'error')
            return redirect(url_for('admin.settings'))

        try:
            backup_data = json.loads(backup_file.read().decode('utf-8'))
        except Exception as exc:
            flash(f'Ungültige JSON-Datei: {str(exc)}', 'error')
            return redirect(url_for('admin.settings'))

        if backup_data.get('backup_type') != 'full':
            flash('Ungültiges Dateiformat: Dies ist kein Full-Backup (backup_type != "full")', 'error')
            return redirect(url_for('admin.settings'))

        restored = {'settings': False, 'systems': 0, 'systems_skipped': 0,
                    'certs': 0, 'certs_skipped': 0, 'tag_groups': 0, 'tags': 0}

        # ---- Restore AppSettings ----
        if 'settings' in backup_data:
            s = backup_data['settings']
            settings_obj = AppSettings.query.first()
            if not settings_obj:
                settings_obj = AppSettings()
                db.session.add(settings_obj)

            settings_obj.primary_color = s.get('primary_color', '#A70240')
            settings_obj.secondary_color = s.get('secondary_color', '#BED600')
            settings_obj.accent_color = s.get('accent_color', '#0098DB')
            settings_obj.company_name = s.get('company_name', 'Storage Dashboard')
            settings_obj.timezone = s.get('timezone', 'Europe/Berlin')
            settings_obj.max_logs_per_system = s.get('max_logs_per_system', 1000)
            settings_obj.log_retention_days = s.get('log_retention_days', 30)
            settings_obj.min_log_level = s.get('min_log_level', 'INFO')
            settings_obj.dashboard_refresh_interval = s.get('dashboard_refresh_interval', 5)
            # Pure1 credentials
            settings_obj.pure1_display_name = s.get('pure1_display_name') or None
            settings_obj.pure1_app_id = s.get('pure1_app_id') or None
            if s.get('pure1_private_key'):
                settings_obj.pure1_private_key = s['pure1_private_key']
            if s.get('pure1_private_key_passphrase'):
                settings_obj.pure1_private_key_passphrase = s['pure1_private_key_passphrase']
            if s.get('pure1_public_key'):
                settings_obj.pure1_public_key = s['pure1_public_key']
            # Proxy
            settings_obj.proxy_http = s.get('proxy_http') or None
            settings_obj.proxy_https = s.get('proxy_https') or None
            settings_obj.proxy_no_proxy = s.get('proxy_no_proxy') or None
            # Logo
            if s.get('logo_filename') and s.get('logo_data'):
                settings_obj.logo_filename = s['logo_filename']
                settings_obj.logo_data = base64.b64decode(s['logo_data'])
            restored['settings'] = True

        # ---- Restore Tag Groups & Tags (before systems, as systems reference tags) ----
        for grp_data in backup_data.get('tag_groups', []):
            grp = TagGroup.query.filter_by(name=grp_data['name']).first()
            if not grp:
                grp = TagGroup(name=grp_data['name'],
                               description=grp_data.get('description'))
                db.session.add(grp)
                db.session.flush()
                restored['tag_groups'] += 1
            for tag_data in grp_data.get('tags', []):
                existing_tag = Tag.query.filter_by(name=tag_data['name'],
                                                   group_id=grp.id).first()
                if not existing_tag:
                    db.session.add(Tag(name=tag_data['name'], group_id=grp.id))
                    restored['tags'] += 1
        db.session.flush()

        # ---- Restore Storage Systems ----
        for sys_data in backup_data.get('systems', []):
            if StorageSystem.query.filter_by(name=sys_data['name']).first():
                restored['systems_skipped'] += 1
                continue
            system = StorageSystem(
                name=sys_data['name'],
                vendor=sys_data['vendor'],
                ip_address=sys_data['ip_address'],
                port=sys_data.get('port', 443),
                api_username=sys_data.get('api_username'),
                api_password=sys_data.get('api_password'),
                api_token=sys_data.get('api_token'),
                enabled=sys_data.get('enabled', True),
                snaps_enabled=sys_data.get('snaps_enabled', True),
                cluster_type=sys_data.get('cluster_type'),
                node_count=sys_data.get('node_count'),
                site_count=sys_data.get('site_count'),
                pure1_array_name=sys_data.get('pure1_array_name'),
            )
            system.set_dns_names(sys_data.get('dns_names', []))
            system.set_all_ips(sys_data.get('all_ips', []))
            # Re-attach tags
            for tag_ref in sys_data.get('tags', []):
                grp = TagGroup.query.filter_by(name=tag_ref.get('group')).first()
                if grp:
                    tag = Tag.query.filter_by(name=tag_ref.get('tag'),
                                              group_id=grp.id).first()
                    if tag:
                        system.tags.append(tag)
            db.session.add(system)
            restored['systems'] += 1

        # ---- Restore Certificates ----
        for cert_data in backup_data.get('certificates', []):
            if Certificate.query.filter_by(name=cert_data['name']).first():
                restored['certs_skipped'] += 1
                continue
            cert = Certificate(
                name=cert_data['name'],
                certificate_type=cert_data['certificate_type'],
                certificate_pem=cert_data['certificate_pem'],
                description=cert_data.get('description'),
                enabled=cert_data.get('enabled', True),
            )
            db.session.add(cert)
            restored['certs'] += 1

        db.session.commit()

        parts = []
        if restored['settings']:
            parts.append('Einstellungen wiederhergestellt')
        parts.append(f'{restored["systems"]} Systeme importiert'
                     + (f' ({restored["systems_skipped"]} übersprungen)' if restored['systems_skipped'] else ''))
        parts.append(f'{restored["certs"]} Zertifikate importiert'
                     + (f' ({restored["certs_skipped"]} übersprungen)' if restored['certs_skipped'] else ''))
        parts.append(f'{restored["tag_groups"]} Tag-Gruppen / {restored["tags"]} Tags importiert')
        flash('Backup erfolgreich eingespielt: ' + ', '.join(parts), 'success')
        return redirect(url_for('admin.settings'))

    except Exception as e:
        db.session.rollback()
        logger.error(f'Error restoring full backup: {e}', exc_info=True)
        flash(f'Fehler beim Einspielen des Backups: {str(e)}', 'error')
        return redirect(url_for('admin.settings'))
