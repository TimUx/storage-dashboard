"""Application-wide settings (branding, Pure1, proxy, …)."""
from datetime import datetime

from app import db
from app.crypto_utils import decrypt_value, encrypt_value


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
    _proxy_http = db.Column('proxy_http', db.Text)
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
