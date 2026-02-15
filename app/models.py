"""Database models"""
from app import db
from datetime import datetime

class StorageSystem(db.Model):
    """Storage system model"""
    __tablename__ = 'storage_systems'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    vendor = db.Column(db.String(50), nullable=False)  # pure, netapp-ontap, netapp-storagegrid, dell-datadomain
    ip_address = db.Column(db.String(100), nullable=False)
    api_username = db.Column(db.String(100))
    api_password = db.Column(db.String(200))
    api_token = db.Column(db.String(500))
    port = db.Column(db.Integer, default=443)
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'vendor': self.vendor,
            'ip_address': self.ip_address,
            'port': self.port,
            'enabled': self.enabled,
            'has_credentials': bool(self.api_username or self.api_token),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f'<StorageSystem {self.name} ({self.vendor})>'
