"""Storage Dashboard Application"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
from sqlalchemy.pool import NullPool
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
    
    # Database configuration
    database_url = os.getenv('DATABASE_URL', 'sqlite:///storage_dashboard.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Configure database engine options for better concurrency
    if database_url.startswith('postgresql'):
        # PostgreSQL configuration for high concurrency
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'pool_size': 20,
            'max_overflow': 40,
            'pool_timeout': 30,
            'pool_recycle': 3600,
            'pool_pre_ping': True,
        }
    elif database_url.startswith('sqlite'):
        # SQLite configuration with WAL mode and busy timeout for better concurrency
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'connect_args': {
                'timeout': 30,
                'check_same_thread': False,
            },
            'poolclass': NullPool,  # Disable pooling for SQLite
        }
    
    app.config['SSL_VERIFY'] = os.getenv('SSL_VERIFY', 'false').lower() == 'true'
    
    db.init_app(app)
    
    # Enable WAL mode for SQLite to improve concurrency
    if database_url.startswith('sqlite'):
        def enable_sqlite_wal():
            """Enable WAL mode for SQLite to reduce locking"""
            try:
                with db.engine.connect() as conn:
                    conn.execute(db.text("PRAGMA journal_mode=WAL"))
                    conn.execute(db.text("PRAGMA busy_timeout=30000"))
                    conn.commit()
                app.logger.info("SQLite WAL mode enabled for better concurrency")
            except Exception as e:
                app.logger.warning(f"Could not enable SQLite WAL mode: {e}")
        
        # Register the function to run after app context is set up
        with app.app_context():
            try:
                enable_sqlite_wal()
            except Exception as e:
                app.logger.warning(f"Could not enable SQLite WAL mode during init: {e}")
    
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
        """Format datetime safely with timezone conversion"""
        if dt is None:
            return '-'
        if isinstance(dt, datetime):
            # Convert from UTC to configured timezone
            try:
                from app.models import AppSettings
                import pytz
                
                settings = AppSettings.query.first()
                if settings and settings.timezone:
                    # Assume dt is in UTC, convert to configured timezone
                    utc_dt = dt.replace(tzinfo=pytz.UTC)
                    target_tz = pytz.timezone(settings.timezone)
                    local_dt = utc_dt.astimezone(target_tz)
                    return local_dt.strftime(format)
            except Exception:
                # Fallback to UTC if conversion fails
                pass
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
    
    # Add cache control headers to prevent browser caching
    @app.after_request
    def add_cache_control_headers(response):
        """Add Cache-Control headers to all responses to prevent browser caching"""
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    
    # Register blueprints
    from app.routes import main, admin, api
    app.register_blueprint(main.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(api.bp)
    
    with app.app_context():
        # Create tables if they don't exist
        # Handle race condition when multiple workers try to create tables simultaneously
        # Retry on connection errors to handle cases where the database is not yet ready
        from sqlalchemy.exc import OperationalError
        import time
        max_retries = 5
        retry_delay = 2
        for attempt in range(1, max_retries + 1):
            try:
                db.create_all()
                break
            except OperationalError as e:
                error_msg = str(e).lower()
                if 'already exists' in error_msg:
                    app.logger.info("Database tables already exist (created by another worker)")
                    break
                if attempt < max_retries:
                    app.logger.warning(
                        f"Database not ready (attempt {attempt}/{max_retries}): {e}. "
                        f"Retrying in {retry_delay}s..."
                    )
                    time.sleep(retry_delay)
                else:
                    app.logger.error(f"Could not connect to database after {max_retries} attempts: {e}")
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
