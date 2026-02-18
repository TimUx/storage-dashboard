"""SSL certificate utilities"""
import os
import tempfile
import atexit
import ipaddress
import logging
from app import db
from app.models import Certificate

logger = logging.getLogger(__name__)

# Keep track of temporary certificate files for cleanup
_temp_cert_files = []


def _cleanup_temp_files():
    """Clean up all temporary certificate files on exit"""
    for temp_file in _temp_cert_files:
        try:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
        except Exception:
            pass
    _temp_cert_files.clear()


# Register cleanup on exit
atexit.register(_cleanup_temp_files)


def is_ip_address(address):
    """Check if the given address is an IP address (IPv4 or IPv6)
    
    Args:
        address: String to check (IP address or hostname)
        
    Returns:
        bool: True if address is an IP address, False if it's a hostname/DNS name
    """
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def get_ssl_verify(target_address=None):
    """Get SSL verification setting from app config, with custom certificates if available
    
    Args:
        target_address: Optional IP address or hostname being connected to.
                       If provided and it's an IP address, SSL verification will be disabled
                       automatically (even if SSL_VERIFY=true) since IP addresses don't match
                       certificate common names.
    
    Returns:
        bool or str: False to disable SSL verification, True to use system defaults,
                    or path to custom CA bundle
    """
    try:
        # If connecting to an IP address, SSL verification must be disabled
        # because certificates are issued to DNS names, not IP addresses
        if target_address and is_ip_address(target_address):
            logger.debug(f"Disabling SSL verification for IP address: {target_address}")
            return False
        
        from flask import current_app
        ssl_verify_enabled = current_app.config.get('SSL_VERIFY', False)
        
        if not ssl_verify_enabled:
            return False
        
        # Try to get custom certificates from the database
        # Note: get_ssl_context() is defined later in this same module
        try:
            return get_ssl_context()
        except Exception:
            # If custom certificates fail, use default
            return True
            
    except RuntimeError:
        # Outside application context, default to False for development
        return False


def get_ssl_context():
    """
    Get SSL context with custom certificates.
    Returns either path to combined CA bundle or False for no verification.
    """
    # Check if SSL verification is enabled
    ssl_verify = os.getenv('SSL_VERIFY', 'false').lower() == 'true'
    
    if not ssl_verify:
        return False
    
    # Get all enabled certificates from database
    try:
        certificates = Certificate.query.filter_by(enabled=True).all()
        
        if not certificates:
            # No custom certificates, use system defaults
            return True
        
        # Create temporary file with all certificates
        ca_bundle_fd, ca_bundle_path = tempfile.mkstemp(suffix='.pem', prefix='storage_dashboard_ca_')
        _temp_cert_files.append(ca_bundle_path)
        
        with os.fdopen(ca_bundle_fd, 'w') as ca_bundle:
            for cert in certificates:
                ca_bundle.write(cert.certificate_pem)
                ca_bundle.write('\n')
        
        return ca_bundle_path
        
    except Exception as e:
        # If there's an error, fall back to default behavior
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error loading custom certificates: {e}")
        return True  # Use system defaults


def cleanup_ssl_context(ssl_context):
    """Clean up temporary certificate file if needed (deprecated - use automatic cleanup)"""
    if isinstance(ssl_context, str) and os.path.exists(ssl_context):
        try:
            os.unlink(ssl_context)
            if ssl_context in _temp_cert_files:
                _temp_cert_files.remove(ssl_context)
        except Exception:
            pass
