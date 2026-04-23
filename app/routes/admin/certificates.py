"""Admin certificate management."""
import io
import logging

from flask import flash, redirect, render_template, request, send_file, url_for
from flask_login import login_required

from app import db
from app.models import Certificate
from app.routes.admin import bp

logger = logging.getLogger(__name__)


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
