"""Shared constants for the storage dashboard application"""

# Vendor identifiers
# These are the canonical vendor identifiers used throughout the application
VENDOR_PURE = 'pure'
VENDOR_NETAPP_ONTAP = 'netapp-ontap'
VENDOR_NETAPP_STORAGEGRID = 'netapp-storagegrid'
VENDOR_DELL_DATADOMAIN = 'dell-datadomain'

# Vendor-specific default ports
# This is the single source of truth for default ports across the application
VENDOR_DEFAULT_PORTS = {
    VENDOR_PURE: 443,
    VENDOR_NETAPP_ONTAP: 443,
    VENDOR_NETAPP_STORAGEGRID: 443,
    VENDOR_DELL_DATADOMAIN: 3009  # DataDomain REST API uses port 3009
}

# Vendor-specific port descriptions for UI hints
VENDOR_PORT_DESCRIPTIONS = {
    VENDOR_PURE: 'HTTPS',
    VENDOR_NETAPP_ONTAP: 'HTTPS',
    VENDOR_NETAPP_STORAGEGRID: 'HTTPS',
    VENDOR_DELL_DATADOMAIN: 'DataDomain REST API'
}
