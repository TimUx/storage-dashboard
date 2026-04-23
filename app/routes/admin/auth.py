"""Admin authentication (login / logout)."""
import logging
from datetime import datetime

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app import db
from app.models import AdminUser
from app.routes.admin import bp

logger = logging.getLogger(__name__)


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
