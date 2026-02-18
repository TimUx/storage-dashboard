"""Storage Dashboard Application"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
import os
from datetime import datetime

load_dotenv()

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    
    # Configuration
    secret_key = os.getenv('SECRET_KEY')
    if not secret_key:
        if os.getenv('FLASK_ENV') == 'production':
            raise ValueError("SECRET_KEY must be set in production environment")
        secret_key = 'dev-secret-key-change-in-production'
    
    app.config['SECRET_KEY'] = secret_key
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///storage_dashboard.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SSL_VERIFY'] = os.getenv('SSL_VERIFY', 'false').lower() == 'true'
    
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'admin.login'
    login_manager.login_message = 'Bitte melden Sie sich an, um fortzufahren.'
    
    # User loader for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        from app.models import AdminUser
        return AdminUser.query.get(int(user_id))
    
    # Register custom Jinja2 filters
    @app.template_filter('format_datetime')
    def format_datetime_filter(dt, format='%d.%m.%Y %H:%M'):
        """Format datetime safely"""
        if dt is None:
            return '-'
        if isinstance(dt, datetime):
            return dt.strftime(format)
        return str(dt)
    
    # Context processor for settings
    @app.context_processor
    def inject_settings():
        """Make settings available to all templates"""
        try:
            from app.models import AppSettings
            settings = AppSettings.query.first()
            return dict(settings=settings)
        except RuntimeError:
            # Outside application context, return None for settings
            return dict(settings=None)
    
    # Register blueprints
    from app.routes import main, admin, api
    app.register_blueprint(main.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(api.bp)
    
    with app.app_context():
        # Create tables if they don't exist
        # Handle race condition when multiple workers try to create tables simultaneously
        try:
            db.create_all()
        except Exception as e:
            # Check if this is a "table already exists" error (race condition with other workers)
            error_msg = str(e).lower()
            if 'already exists' in error_msg:
                app.logger.info("Database tables already exist (created by another worker)")
            else:
                # Re-raise if it's a different error
                raise
        
        # Run database migrations
        try:
            from app.migrations import run_all_migrations
            migrations_applied = run_all_migrations()
            if migrations_applied:
                app.logger.info(f"Applied {len(migrations_applied)} database migrations: {', '.join(migrations_applied)}")
        except Exception as e:
            app.logger.error(f"CRITICAL: Database migration failed: {e}")
            app.logger.error("The application may not function correctly until migrations are applied successfully.")
            app.logger.error("Please run 'python cli.py migrate' to apply migrations manually.")
            # Don't fail app startup completely, but log critical error for monitoring
    
    return app
