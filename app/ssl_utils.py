"""SSL certificate utilities"""
import os
import tempfile
from app.models import Certificate


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
        from app import db
        certificates = Certificate.query.filter_by(enabled=True).all()
        
        if not certificates:
            # No custom certificates, use system defaults
            return True
        
        # Create temporary file with all certificates
        ca_bundle_fd, ca_bundle_path = tempfile.mkstemp(suffix='.pem', prefix='storage_dashboard_ca_')
        
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
    """Clean up temporary certificate file if needed"""
    if isinstance(ssl_context, str) and os.path.exists(ssl_context):
        try:
            os.unlink(ssl_context)
        except Exception:
            pass
