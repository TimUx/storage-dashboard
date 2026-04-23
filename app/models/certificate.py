"""SSL custom CA / root certificates."""
from datetime import datetime

from app import db


class Certificate(db.Model):
    """SSL Certificate model for custom CA and root certificates"""
    __tablename__ = 'certificates'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    certificate_type = db.Column(db.String(20), nullable=False)  # 'ca' or 'root'
    certificate_pem = db.Column(db.Text, nullable=False)  # PEM-encoded certificate
    description = db.Column(db.Text)
    enabled = db.Column(db.Boolean, default=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'certificate_type': self.certificate_type,
            'description': self.description,
            'enabled': self.enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f'<Certificate {self.name} ({self.certificate_type})>'
