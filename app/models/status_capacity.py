"""Cached status and capacity time-series."""
import json
from datetime import datetime

from app import db


class StatusCache(db.Model):
    """Cached health status for each storage system – populated by the background refresh service"""
    __tablename__ = 'status_cache'

    id = db.Column(db.Integer, primary_key=True)
    system_id = db.Column(
        db.Integer,
        db.ForeignKey('storage_systems.id', ondelete='CASCADE'),
        nullable=False,
        unique=True,
    )
    system = db.relationship('StorageSystem', backref=db.backref('status_cache', uselist=False))

    fetched_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    status_json = db.Column(db.Text, nullable=False, default='{}')
    error = db.Column(db.Text)

    def get_status(self):
        try:
            return json.loads(self.status_json)
        except Exception:
            return {}

    def set_status(self, status_dict):
        self.status_json = json.dumps(status_dict)

    def to_dict(self):
        return {
            'system_id': self.system_id,
            'fetched_at': self.fetched_at.isoformat() if self.fetched_at else None,
            'status': self.get_status(),
            'error': self.error,
        }

    def __repr__(self):
        return f'<StatusCache system={self.system_id} at={self.fetched_at}>'


class CapacitySnapshot(db.Model):
    """Hourly capacity snapshot for each storage system (cache)"""
    __tablename__ = 'capacity_snapshots'

    id = db.Column(db.Integer, primary_key=True)
    system_id = db.Column(db.Integer, db.ForeignKey('storage_systems.id', ondelete='CASCADE'), nullable=False)
    system = db.relationship('StorageSystem', backref=db.backref('capacity_snapshots', lazy='dynamic'))

    fetched_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    total_tb = db.Column(db.Float, default=0.0)
    used_tb = db.Column(db.Float, default=0.0)
    free_tb = db.Column(db.Float, default=0.0)
    provisioned_tb = db.Column(db.Float)  # nullable – not all systems expose this
    percent_used = db.Column(db.Float, default=0.0)
    percent_free = db.Column(db.Float, default=0.0)
    percent_provisioned = db.Column(db.Float)  # nullable
    error = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'system_id': self.system_id,
            'fetched_at': self.fetched_at.isoformat() if self.fetched_at else None,
            'total_tb': self.total_tb,
            'used_tb': self.used_tb,
            'free_tb': self.free_tb,
            'provisioned_tb': self.provisioned_tb,
            'percent_used': self.percent_used,
            'percent_free': self.percent_free,
            'percent_provisioned': self.percent_provisioned,
            'error': self.error,
        }

    def __repr__(self):
        return f'<CapacitySnapshot system={self.system_id} at={self.fetched_at}>'


class CapacityHistory(db.Model):
    """Daily capacity snapshot per storage system for trend/history views"""
    __tablename__ = 'capacity_history'

    id = db.Column(db.Integer, primary_key=True)
    system_id = db.Column(db.Integer, db.ForeignKey('storage_systems.id', ondelete='CASCADE'), nullable=False)
    system = db.relationship('StorageSystem', backref=db.backref('capacity_history', lazy='dynamic'))

    date = db.Column(db.Date, nullable=False, index=True)
    total_tb = db.Column(db.Float, default=0.0)
    used_tb = db.Column(db.Float, default=0.0)
    free_tb = db.Column(db.Float, default=0.0)
    provisioned_tb = db.Column(db.Float)
    percent_used = db.Column(db.Float, default=0.0)

    __table_args__ = (db.UniqueConstraint('system_id', 'date', name='uq_capacity_history_system_date'),)

    def to_dict(self):
        return {
            'id': self.id,
            'system_id': self.system_id,
            'date': self.date.isoformat() if self.date else None,
            'total_tb': self.total_tb,
            'used_tb': self.used_tb,
            'free_tb': self.free_tb,
            'provisioned_tb': self.provisioned_tb,
            'percent_used': self.percent_used,
        }

    def __repr__(self):
        return f'<CapacityHistory system={self.system_id} date={self.date}>'
