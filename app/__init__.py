"""Storage Dashboard Application"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
from datetime import datetime

load_dotenv()

db = SQLAlchemy()

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
    
    # Register custom Jinja2 filters
    @app.template_filter('format_datetime')
    def format_datetime_filter(dt, format='%d.%m.%Y %H:%M'):
        """Format datetime safely"""
        if dt is None:
            return '-'
        if isinstance(dt, datetime):
            return dt.strftime(format)
        return str(dt)
    
    # Register blueprints
    from app.routes import main, admin, api
    app.register_blueprint(main.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(api.bp)
    
    with app.app_context():
        db.create_all()
    
    return app
