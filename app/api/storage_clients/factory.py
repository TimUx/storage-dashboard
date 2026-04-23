"""Factory for vendor-specific storage API clients."""
from app.api.storage_clients.datadomain_client import DellDataDomainClient
from app.api.storage_clients.grid_client import NetAppStorageGRIDClient
from app.api.storage_clients.ontap_client import NetAppONTAPClient
from app.api.storage_clients.pure_client import PureStorageClient
from app.constants import VENDOR_DEFAULT_PORTS


def get_client(vendor, ip_address, port=None, username=None, password=None, token=None):
    """Return a storage client instance for the given vendor.

    Args:
        vendor: ``pure``, ``netapp-ontap``, ``netapp-storagegrid``, or ``dell-datadomain``.
        ip_address: IP address or hostname of the storage system.
        port: TCP port (defaults to vendor-specific port from ``VENDOR_DEFAULT_PORTS``).
        username: API username (ONTAP, DataDomain).
        password: API password (ONTAP, DataDomain).
        token: API token (Pure, StorageGRID).

    Returns:
        A ``StorageClient`` subclass instance.

    Raises:
        ValueError: If *vendor* is not recognized.
    """
    clients = {
        'pure': PureStorageClient,
        'netapp-ontap': NetAppONTAPClient,
        'netapp-storagegrid': NetAppStorageGRIDClient,
        'dell-datadomain': DellDataDomainClient,
    }

    client_class = clients.get(vendor)
    if not client_class:
        raise ValueError(f"Unknown vendor: {vendor}")

    if port is None:
        port = VENDOR_DEFAULT_PORTS.get(vendor, 443)

    return client_class(ip_address, port, username, password, token)
