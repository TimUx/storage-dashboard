"""Application settings UI and public logo route."""
import io
import logging

from flask import flash, redirect, render_template, request, send_file, url_for
from flask_login import login_required

from app import db
from app.models import AppSettings, Certificate
from app.routes.admin import bp

logger = logging.getLogger(__name__)


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

            # Update dashboard background refresh interval
            refresh_interval = request.form.get('dashboard_refresh_interval')
            if refresh_interval and refresh_interval.isdigit():
                app_settings.dashboard_refresh_interval = int(refresh_interval)

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
            # Keys / passphrase: only overwrite if a new value was explicitly submitted
            new_private_key = request.form.get('pure1_private_key', '').strip()
            if new_private_key:
                app_settings.pure1_private_key = new_private_key
            new_passphrase = request.form.get('pure1_private_key_passphrase', '').strip()
            if new_passphrase:
                app_settings.pure1_private_key_passphrase = new_passphrase
            new_public_key = request.form.get('pure1_public_key', '').strip()
            if new_public_key:
                app_settings.pure1_public_key = new_public_key

            # Proxy settings (always overwrite – empty = disabled)
            app_settings.proxy_http = request.form.get('proxy_http', '').strip() or None
            app_settings.proxy_https = request.form.get('proxy_https', '').strip() or None
            app_settings.proxy_no_proxy = request.form.get('proxy_no_proxy', '').strip() or None

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
