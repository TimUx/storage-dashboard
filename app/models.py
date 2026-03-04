"""Database models"""
from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app.crypto_utils import encrypt_value, decrypt_value
import json


# Many-to-many junction table for StorageSystem <-> Tag
storage_system_tags = db.Table(
    'storage_system_tags',
    db.Column('system_id', db.Integer, db.ForeignKey('storage_systems.id', ondelete='CASCADE'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tags.id', ondelete='CASCADE'), primary_key=True)
)


class TagGroup(db.Model):
    """Tag group model – groups related tags together (e.g. 'Storage Art', 'Landschaft')"""
    __tablename__ = 'tag_groups'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    tags = db.relationship('Tag', backref='group', lazy='dynamic', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'tags': [t.to_dict() for t in self.tags.order_by(Tag.name)],
        }

    def __repr__(self):
        return f'<TagGroup {self.name}>'


class Tag(db.Model):
    """Tag model – individual label that can be assigned to storage systems"""
    __tablename__ = 'tags'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('tag_groups.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('name', 'group_id', name='uq_tag_name_group'),)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'group_id': self.group_id,
            'group_name': self.group.name if self.group else None,
        }

    def __repr__(self):
        return f'<Tag {self.name} ({self.group.name if self.group else "?"})>'


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
    peer_connections = db.Column(db.Text)  # JSON: [{name, status, type, address, ...}] - for Pure Storage array_connections
    metrocluster_info = db.Column(db.Text)  # JSON: {configuration_state, mode, local_cluster_name, partner_cluster_name}
    metrocluster_dr_groups = db.Column(db.Text)  # JSON: [{id, local_nodes, partner_nodes}]
    ha_info = db.Column(db.Text)  # JSON: {state, role, mode, partner info, ...} - for DataDomain HA clusters
    os_version = db.Column(db.String(100))  # OS/firmware version of the storage system
    api_version = db.Column(db.String(50))  # Detected API version
    
    # Partner cluster reference (for MetroCluster, Active-Cluster)
    partner_cluster_id = db.Column(db.Integer, db.ForeignKey('storage_systems.id', ondelete='SET NULL'))
    partner_cluster = db.relationship('StorageSystem', remote_side=[id], backref='partners')

    # Tags (many-to-many)
    tags = db.relationship('Tag', secondary=storage_system_tags, lazy='subquery',
                           backref=db.backref('systems', lazy=True))
    
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
    
    def get_ha_info(self):
        """Get HA info as dict"""
        if self.ha_info:
            try:
                return json.loads(self.ha_info)
            except (json.JSONDecodeError, TypeError, ValueError):
                return {}
        return {}
    
    def set_ha_info(self, info):
        """Set HA info from dict"""
        if info:
            self.ha_info = json.dumps(info)
        else:
            self.ha_info = None
    
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
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'tags': [t.to_dict() for t in self.tags],
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
    
    # Timezone settings
    timezone = db.Column(db.String(50), default='Europe/Berlin')  # IANA timezone
    
    # Log retention settings
    max_logs_per_system = db.Column(db.Integer, default=1000)  # Maximum logs per system
    log_retention_days = db.Column(db.Integer, default=30)  # Days to keep logs
    min_log_level = db.Column(db.String(20), default='INFO')  # Minimum log level: DEBUG, INFO, WARNING, ERROR, CRITICAL

    # Pure1 API credentials (all encrypted)
    _pure1_display_name = db.Column('pure1_display_name', db.Text)
    _pure1_app_id = db.Column('pure1_app_id', db.Text)
    _pure1_private_key = db.Column('pure1_private_key', db.Text)
    _pure1_private_key_passphrase = db.Column('pure1_private_key_passphrase', db.Text)
    _pure1_public_key = db.Column('pure1_public_key', db.Text)

    @property
    def pure1_display_name(self):
        """Decrypt and return Pure1 display name"""
        return decrypt_value(self._pure1_display_name) if self._pure1_display_name else None

    @pure1_display_name.setter
    def pure1_display_name(self, value):
        self._pure1_display_name = encrypt_value(value) if value else None

    @property
    def pure1_app_id(self):
        """Decrypt and return Pure1 App ID"""
        return decrypt_value(self._pure1_app_id) if self._pure1_app_id else None

    @pure1_app_id.setter
    def pure1_app_id(self, value):
        self._pure1_app_id = encrypt_value(value) if value else None

    @property
    def pure1_private_key(self):
        """Decrypt and return Pure1 private key (PEM)"""
        return decrypt_value(self._pure1_private_key) if self._pure1_private_key else None

    @pure1_private_key.setter
    def pure1_private_key(self, value):
        self._pure1_private_key = encrypt_value(value) if value else None

    @property
    def pure1_private_key_passphrase(self):
        """Decrypt and return Pure1 private key passphrase"""
        return decrypt_value(self._pure1_private_key_passphrase) if self._pure1_private_key_passphrase else None

    @pure1_private_key_passphrase.setter
    def pure1_private_key_passphrase(self, value):
        self._pure1_private_key_passphrase = encrypt_value(value) if value else None

    @property
    def pure1_public_key(self):
        """Decrypt and return Pure1 public key (PEM)"""
        return decrypt_value(self._pure1_public_key) if self._pure1_public_key else None

    @pure1_public_key.setter
    def pure1_public_key(self, value):
        self._pure1_public_key = encrypt_value(value) if value else None

    # Proxy settings
    # http/https URLs may contain credentials and are therefore stored encrypted.
    # no_proxy is a plain comma-separated list with no sensitive data.
    _proxy_http  = db.Column('proxy_http',  db.Text)
    _proxy_https = db.Column('proxy_https', db.Text)
    proxy_no_proxy = db.Column(db.Text)

    @property
    def proxy_http(self):
        """Decrypt and return the HTTP proxy URL."""
        return decrypt_value(self._proxy_http) if self._proxy_http else None

    @proxy_http.setter
    def proxy_http(self, value):
        self._proxy_http = encrypt_value(value) if value else None

    @property
    def proxy_https(self):
        """Decrypt and return the HTTPS proxy URL."""
        return decrypt_value(self._proxy_https) if self._proxy_https else None

    @proxy_https.setter
    def proxy_https(self, value):
        self._proxy_https = encrypt_value(value) if value else None

    def get_proxies(self) -> dict:
        """Return a requests-compatible proxies dict (empty dict when not set)."""
        proxies = {}
        if self.proxy_http:
            proxies['http'] = self.proxy_http
        if self.proxy_https:
            proxies['https'] = self.proxy_https
        return proxies

    # Dashboard refresh interval (minutes): how often the background service polls storage systems
    # Valid values: 1, 5, 15, 30, 60
    dashboard_refresh_interval = db.Column(db.Integer, default=5)

    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<AppSettings {self.id}>'


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
    Values mirror the Pure1 /subscription-licenses API fields, converted to TB.
    """
    __tablename__ = 'sod_history'

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, index=True)
    subscription_name = db.Column(db.String(200), nullable=False)
    license_name = db.Column(db.String(200), nullable=False)
    service_tier = db.Column(db.String(100))   # optional, e.g. "//GOLD"
    reserved_tb = db.Column(db.Float, default=0.0)        # reservation.data / 1e12
    effective_used_tb = db.Column(db.Float, default=0.0)  # usage.data / 1e12
    on_demand_tb = db.Column(db.Float, default=0.0)       # on_demand_space metric / 1e12

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

