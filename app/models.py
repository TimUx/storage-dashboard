"""Database models"""
from app import db
from datetime import datetime
import json

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
    
    # Cluster type information
    cluster_type = db.Column(db.String(50))  # e.g., 'local', 'metrocluster', 'ha', 'active-cluster', 'multi-site'
    node_count = db.Column(db.Integer)  # Number of nodes (mainly for StorageGRID)
    site_count = db.Column(db.Integer)  # Number of sites (mainly for StorageGRID)
    
    # Auto-discovered information (JSON fields)
    dns_names = db.Column(db.Text)  # JSON: ["hostname.domain.com", "alias.domain.com"]
    all_ips = db.Column(db.Text)  # JSON: ["192.168.1.1", "10.0.0.1"]
    node_details = db.Column(db.Text)  # JSON: [{name, ip, status, role, ...}]
    
    # Partner cluster reference (for MetroCluster, Active-Cluster)
    partner_cluster_id = db.Column(db.Integer, db.ForeignKey('storage_systems.id', ondelete='SET NULL'))
    partner_cluster = db.relationship('StorageSystem', remote_side=[id], backref='partners')
    
    # Discovery metadata
    last_discovery = db.Column(db.DateTime)
    discovery_error = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def get_dns_names(self):
        """Get DNS names as list"""
        if self.dns_names:
            try:
                return json.loads(self.dns_names)
            except:
                return []
        return []
    
    def set_dns_names(self, names):
        """Set DNS names from list"""
        if names:
            self.dns_names = json.dumps(names)
        else:
            self.dns_names = None
    
    def get_all_ips(self):
        """Get all IPs as list"""
        if self.all_ips:
            try:
                return json.loads(self.all_ips)
            except:
                return []
        return []
    
    def set_all_ips(self, ips):
        """Set all IPs from list"""
        if ips:
            self.all_ips = json.dumps(ips)
        else:
            self.all_ips = None
    
    def get_node_details(self):
        """Get node details as list"""
        if self.node_details:
            try:
                return json.loads(self.node_details)
            except:
                return []
        return []
    
    def set_node_details(self, details):
        """Set node details from list"""
        if details:
            self.node_details = json.dumps(details)
        else:
            self.node_details = None
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'vendor': self.vendor,
            'ip_address': self.ip_address,
            'port': self.port,
            'enabled': self.enabled,
            'cluster_type': self.cluster_type,
            'node_count': self.node_count,
            'site_count': self.site_count,
            'dns_names': self.get_dns_names(),
            'all_ips': self.get_all_ips(),
            'node_details': self.get_node_details(),
            'partner_cluster_id': self.partner_cluster_id,
            'last_discovery': self.last_discovery.isoformat() if self.last_discovery else None,
            'has_credentials': bool(self.api_username or self.api_token),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f'<StorageSystem {self.name} ({self.vendor})>'
