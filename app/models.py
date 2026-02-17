"""Database models"""
from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app.crypto_utils import encrypt_value, decrypt_value
import json

class StorageSystem(db.Model):
    """Storage system model"""
    __tablename__ = 'storage_systems'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    vendor = db.Column(db.String(50), nullable=False)  # pure, netapp-ontap, netapp-storagegrid, dell-datadomain
    ip_address = db.Column(db.String(100), nullable=False)
    _api_username = db.Column('api_username', db.String(500))  # Encrypted
    _api_password = db.Column('api_password', db.String(500))  # Encrypted
    _api_token = db.Column('api_token', db.Text)  # Encrypted
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
    peer_connections = db.Column(db.Text)  # JSON: [{name, status, type, address, ...}] - for Pure Storage array-connections
    metrocluster_info = db.Column(db.Text)  # JSON: {configuration_state, mode, local_cluster_name, partner_cluster_name}
    metrocluster_dr_groups = db.Column(db.Text)  # JSON: [{id, local_nodes, partner_nodes}]
    os_version = db.Column(db.String(100))  # OS/firmware version of the storage system
    api_version = db.Column(db.String(50))  # Detected API version
    
    # Partner cluster reference (for MetroCluster, Active-Cluster)
    partner_cluster_id = db.Column(db.Integer, db.ForeignKey('storage_systems.id', ondelete='SET NULL'))
    partner_cluster = db.relationship('StorageSystem', remote_side=[id], backref='partners')
    
    # Discovery metadata
    last_discovery = db.Column(db.DateTime)
    discovery_error = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Encrypted property accessors
    @property
    def api_username(self):
        """Decrypt and return api_username"""
        return decrypt_value(self._api_username) if self._api_username else None
    
    @api_username.setter
    def api_username(self, value):
        """Encrypt and store api_username"""
        self._api_username = encrypt_value(value) if value else None
    
    @property
    def api_password(self):
        """Decrypt and return api_password"""
        return decrypt_value(self._api_password) if self._api_password else None
    
    @api_password.setter
    def api_password(self, value):
        """Encrypt and store api_password"""
        self._api_password = encrypt_value(value) if value else None
    
    @property
    def api_token(self):
        """Decrypt and return api_token"""
        return decrypt_value(self._api_token) if self._api_token else None
    
    @api_token.setter
    def api_token(self, value):
        """Encrypt and store api_token"""
        self._api_token = encrypt_value(value) if value else None
    
    def get_dns_names(self):
        """Get DNS names as list"""
        if self.dns_names:
            try:
                return json.loads(self.dns_names)
            except (json.JSONDecodeError, TypeError, ValueError):
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
            except (json.JSONDecodeError, TypeError, ValueError):
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
            except (json.JSONDecodeError, TypeError, ValueError):
                return []
        return []
    
    def set_node_details(self, details):
        """Set node details from list"""
        if details:
            self.node_details = json.dumps(details)
        else:
            self.node_details = None
    
    def get_peer_connections(self):
        """Get peer connections as list"""
        if self.peer_connections:
            try:
                return json.loads(self.peer_connections)
            except (json.JSONDecodeError, TypeError, ValueError):
                return []
        return []
    
    def set_peer_connections(self, connections):
        """Set peer connections from list"""
        if connections:
            self.peer_connections = json.dumps(connections)
        else:
            self.peer_connections = None
    
    def get_metrocluster_info(self):
        """Get MetroCluster info as dict"""
        if self.metrocluster_info:
            try:
                return json.loads(self.metrocluster_info)
            except (json.JSONDecodeError, TypeError, ValueError):
                return {}
        return {}
    
    def set_metrocluster_info(self, info):
        """Set MetroCluster info from dict"""
        if info:
            self.metrocluster_info = json.dumps(info)
        else:
            self.metrocluster_info = None
    
    def get_metrocluster_dr_groups(self):
        """Get MetroCluster DR groups as list"""
        if self.metrocluster_dr_groups:
            try:
                return json.loads(self.metrocluster_dr_groups)
            except (json.JSONDecodeError, TypeError, ValueError):
                return []
        return []
    
    def set_metrocluster_dr_groups(self, groups):
        """Set MetroCluster DR groups from list"""
        if groups:
            self.metrocluster_dr_groups = json.dumps(groups)
        else:
            self.metrocluster_dr_groups = None
    
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
            'peer_connections': self.get_peer_connections(),
            'metrocluster_info': self.get_metrocluster_info(),
            'metrocluster_dr_groups': self.get_metrocluster_dr_groups(),
            'partner_cluster_id': self.partner_cluster_id,
            'os_version': self.os_version,
            'api_version': self.api_version,
            'last_discovery': self.last_discovery.isoformat() if self.last_discovery else None,
            'has_credentials': bool(self.api_username or self.api_token),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f'<StorageSystem {self.name} ({self.vendor})>'


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


class AdminUser(UserMixin, db.Model):
    """Admin user for authentication"""
    __tablename__ = 'admin_users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password"""
        return check_password_hash(self.password_hash, password)
    
    def get_id(self):
        """Required for Flask-Login"""
        return str(self.id)
    
    def __repr__(self):
        return f'<AdminUser {self.username}>'


class AppSettings(db.Model):
    """Application settings for customization"""
    __tablename__ = 'app_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    # Color scheme
    primary_color = db.Column(db.String(7), default='#A70240')  # Red
    secondary_color = db.Column(db.String(7), default='#BED600')  # Yellow-green
    accent_color = db.Column(db.String(7), default='#0098DB')  # Blue
    
    # Logo
    logo_filename = db.Column(db.String(255))
    logo_data = db.Column(db.LargeBinary)  # Store logo as binary data
    
    # Other settings
    company_name = db.Column(db.String(100), default='Storage Dashboard')
    
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<AppSettings {self.id}>'

