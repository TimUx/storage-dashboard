"""System logs, Pure1 subscription cache, and SoD history."""
from datetime import datetime

from app import db


class SystemLog(db.Model):
    """System log model for tracking connection attempts and errors"""
    __tablename__ = 'system_logs'

    id = db.Column(db.Integer, primary_key=True)
    system_id = db.Column(db.Integer, db.ForeignKey('storage_systems.id', ondelete='CASCADE'), nullable=False)
    system = db.relationship('StorageSystem', backref=db.backref('logs', lazy='dynamic', cascade='all, delete-orphan'))

    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    level = db.Column(db.String(20), nullable=False, index=True)  # INFO, WARNING, ERROR, CRITICAL
    category = db.Column(db.String(50), nullable=False, index=True)  # connection, authentication, api_call, data_query
    message = db.Column(db.Text, nullable=False)
    details = db.Column(db.Text)  # Additional details, stack trace, etc.

    # Additional context
    status_code = db.Column(db.Integer)  # HTTP status code if applicable
    api_endpoint = db.Column(db.String(200))  # API endpoint that was called

    def __repr__(self):
        return f'<SystemLog {self.timestamp} - {self.level} - {self.system.name if self.system else "Unknown"}>'

    def to_dict(self):
        """Convert log entry to dictionary"""
        return {
            'id': self.id,
            'system_id': self.system_id,
            'system_name': self.system.name if self.system else 'Unknown',
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'level': self.level,
            'category': self.category,
            'message': self.message,
            'details': self.details,
            'status_code': self.status_code,
            'api_endpoint': self.api_endpoint
        }


class SubscriptionLicenseCache(db.Model):
    """Single-row cache for Pure1 subscription-license data (Storage on Demand)."""
    __tablename__ = 'subscription_license_cache'

    id = db.Column(db.Integer, primary_key=True)
    fetched_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    data = db.Column(db.Text)   # JSON-encoded list of licence items
    error = db.Column(db.Text)  # Error message from last fetch attempt (or None)

    def __repr__(self):
        return f'<SubscriptionLicenseCache fetched_at={self.fetched_at}>'


class SodHistory(db.Model):
    """Daily historical snapshot for Pure1 Storage on Demand subscription licences.

    One row per (date, subscription_name, license_name) combination.
    Values mirror the Pure1 /subscription-licenses API fields, converted to TiB.
    """
    __tablename__ = 'sod_history'

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, index=True)
    subscription_name = db.Column(db.String(200), nullable=False)
    license_name = db.Column(db.String(200), nullable=False)
    service_tier = db.Column(db.String(100))   # optional, e.g. "//GOLD"
    reserved_tb = db.Column(db.Float, default=0.0)        # reservation.data / 1024**4
    effective_used_tb = db.Column(db.Float, default=0.0)  # usage.data / 1024**4
    on_demand_tb = db.Column(db.Float, default=0.0)       # on_demand_space metric / 1024**4

    __table_args__ = (
        db.UniqueConstraint('date', 'subscription_name', 'license_name',
                            name='uq_sod_history_date_sub_lic'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'date': self.date.isoformat() if self.date else None,
            'subscription_name': self.subscription_name,
            'license_name': self.license_name,
            'service_tier': self.service_tier,
            'reserved_tb': self.reserved_tb,
            'effective_used_tb': self.effective_used_tb,
            'on_demand_tb': self.on_demand_tb,
        }

    def __repr__(self):
        return f'<SodHistory {self.date} {self.subscription_name}/{self.license_name}>'
