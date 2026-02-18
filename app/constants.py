"""Shared constants for the storage dashboard application"""

# Vendor-specific default ports
# This is the single source of truth for default ports across the application
VENDOR_DEFAULT_PORTS = {
    'pure': 443,
    'netapp-ontap': 443,
    'netapp-storagegrid': 443,
    'dell-datadomain': 3009  # DataDomain REST API uses port 3009
}

# Vendor-specific port descriptions for UI hints
VENDOR_PORT_DESCRIPTIONS = {
    'pure': 'HTTPS',
    'netapp-ontap': 'HTTPS',
    'netapp-storagegrid': 'HTTPS',
    'dell-datadomain': 'DataDomain REST API'
}
