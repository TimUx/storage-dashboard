"""Dell DataDomain REST API client (v1.0)."""
import logging
import os
import time
from http.client import RemoteDisconnected

from requests.exceptions import ConnectionError, Timeout

from app.api.base_client import StorageClient
from app.api.storage_clients.common import _epoch_s_to_str
from app.api.storage_clients.http import MAX_RESPONSE_LOG_LENGTH
from app.api.storage_clients.runtime import local_session
from app.discovery import reverse_dns_lookup
from app.ssl_utils import get_ssl_verify

logger = logging.getLogger(__name__)

# requests timeout in seconds (both connect + read). Used for DataDomain REST calls.
# Override via env var to accommodate slower networks / appliances.
DD_API_TIMEOUT_SECONDS = int(os.getenv('DD_API_TIMEOUT_SECONDS', os.getenv('STORAGE_API_TIMEOUT_SECONDS', '90')))
DD_HEALTH_TIMEOUT_RETRIES = int(os.getenv('DD_HEALTH_TIMEOUT_RETRIES', '1'))
DD_HEALTH_TIMEOUT_RETRY_BACKOFF_SECONDS = float(
    os.getenv('DD_HEALTH_TIMEOUT_RETRY_BACKOFF_SECONDS', '1.0')
)
DD_SLOW_CALL_WARN_SECONDS = float(os.getenv('DD_SLOW_CALL_WARN_SECONDS', '5.0'))
DD_API_RETRIES = int(os.getenv('DD_API_RETRIES', '3'))
DD_API_RETRY_BACKOFF_SECONDS = float(os.getenv('DD_API_RETRY_BACKOFF_SECONDS', '2.0'))
DD_API_NIC_RETRIES = int(os.getenv('DD_API_NIC_RETRIES', '2'))
DD_NETWORK_NIC_EXPAND_ALL_DETAILS = os.getenv('DD_NETWORK_NIC_EXPAND_ALL_DETAILS', '0').strip().lower() in {
    '1', 'true', 'yes', 'on'
}
# 0 disables the NIC time budget to avoid early cut-offs.
DD_NETWORK_NICS_MAX_SECONDS = float(os.getenv('DD_NETWORK_NICS_MAX_SECONDS', '0'))


def _is_timeout_error(exc: Exception) -> bool:
    """Return True when ``exc`` (or one of its causes) is a request timeout."""
    cur = exc
    visited: set[int] = set()
    while cur and id(cur) not in visited:
        visited.add(id(cur))
        if isinstance(cur, Timeout):
            return True
        cur = cur.__cause__ or cur.__context__
    return False


def _is_retryable_transport_error(exc: Exception) -> bool:
    """Return True for transient transport errors worth retrying."""
    cur = exc
    visited: set[int] = set()
    while cur and id(cur) not in visited:
        visited.add(id(cur))
        if isinstance(cur, (Timeout, ConnectionError, RemoteDisconnected)):
            return True
        cur = cur.__cause__ or cur.__context__
    return False

class DellDataDomainClient(StorageClient):
    """Dell DataDomain client - REST API v1.0

    Uses token-based authentication.
    Authentication endpoint: POST /rest/v1.0/auth (port 3009)
    Returns X-DD-AUTH-TOKEN in response header
    """

    # Alert state constants for filtering active alerts
    ACTIVE_ALERT_STATES = ['active', 'new', 'unresolved']

    # Hardware component failure states
    FAILED_COMPONENT_STATES = ['failed', 'error', 'critical']

    # Critical alert severity levels
    CRITICAL_ALERT_SEVERITIES = ['critical', 'major']

    # Management network interfaces to check when bulk API fails
    MANAGEMENT_INTERFACES = ['ethMa', 'ethMb', 'ethMc', 'ethMd']

    def _timed_call(self, label: str, func, *args, progress_callback=None, **kwargs):
        """Run a DD API helper and log its runtime for timeout diagnostics."""
        if progress_callback:
            progress_callback('start', label, None)
        start = time.monotonic()
        result = func(*args, **kwargs)
        elapsed = time.monotonic() - start
        if progress_callback:
            progress_callback('done', label, elapsed)
        if elapsed >= DD_SLOW_CALL_WARN_SECONDS:
            logger.warning(
                "DataDomain %s - slow API step '%s': %.2fs",
                self.ip_address,
                label,
                elapsed,
            )
        else:
            logger.debug(
                "DataDomain %s - API step '%s' completed in %.2fs",
                self.ip_address,
                label,
                elapsed,
            )
        return result

    def _request_with_retry(self, operation: str, call):
        """Execute request call with retries for transient transport failures."""
        is_nic_op = '/networks/nics' in operation
        retries = DD_API_NIC_RETRIES if is_nic_op else DD_API_RETRIES
        attempts = max(1, retries + 1)
        for attempt in range(1, attempts + 1):
            try:
                return call()
            except Exception as exc:
                if not _is_retryable_transport_error(exc) or attempt >= attempts:
                    raise
                logger.warning(
                    "DataDomain %s - %s transient error (%s), retry %d/%d in %.1fs",
                    self.ip_address,
                    operation,
                    type(exc).__name__,
                    attempt,
                    retries,
                    DD_API_RETRY_BACKOFF_SECONDS,
                )
                time.sleep(max(0.0, DD_API_RETRY_BACKOFF_SECONDS))

    def authenticate(self):
        """Authenticate with DataDomain and obtain session token

        Uses username and password to authenticate and retrieve a session token.
        The token should be saved to the database for future use.

        Returns:
            str: Session token if successful, None if authentication fails
        """
        if not self.username or not self.password:
            logger.error(f"Cannot authenticate to DataDomain {self.ip_address}: username or password not configured")
            return None

        try:
            ssl_verify = get_ssl_verify(self.resolved_address)

            auth_data = {
                'username': self.username,
                'password': self.password
            }

            logger.debug(f"Authenticating to DataDomain {self.ip_address} via {self.base_url}")

            response = self._request_with_retry(
                "authenticate",
                lambda: local_session().post(
                    f"{self.base_url}/rest/v1.0/auth",
                    json=auth_data,
                    headers={'Content-Type': 'application/json'},
                    verify=ssl_verify,
                    timeout=DD_API_TIMEOUT_SECONDS,
                ),
            )

            if response.status_code == 201:
                # Token is in response header, not body
                token = response.headers.get('X-DD-AUTH-TOKEN')

                if token:
                    logger.debug(f"Successfully obtained session token for DataDomain {self.ip_address}")
                    return token
                else:
                    logger.error("Authentication response did not contain X-DD-AUTH-TOKEN header")
                    logger.error(f"Response headers: {dict(response.headers)}")
                    return None
            else:
                logger.error(f"DataDomain authentication failed for {self.ip_address}: HTTP {response.status_code}")
                try:
                    logger.error(f"Response: {response.text[:MAX_RESPONSE_LOG_LENGTH]}")
                except Exception:
                    pass
                return None

        except Exception as e:
            if _is_timeout_error(e):
                logger.warning(
                    "DataDomain authentication timeout for %s after %ss",
                    self.ip_address,
                    DD_API_TIMEOUT_SECONDS,
                )
            else:
                logger.error(f"Error authenticating to DataDomain {self.ip_address}: {e}")
            return None

    def _make_api_request(self, endpoint, headers=None, ssl_verify=None, method='GET', data=None):
        """Make an API request to DataDomain

        Args:
            endpoint: API endpoint path (e.g., '/rest/v1.0/dd-systems/0/ha')
            headers: HTTP headers (will add auth token)
            ssl_verify: SSL verification setting
            method: HTTP method (GET, POST, PUT, DELETE)
            data: Request body data (for POST/PUT)

        Returns:
            dict: Response JSON data or None on error
        """
        if headers is None:
            headers = {
                'X-DD-AUTH-TOKEN': self.token,
                'Accept': 'application/json'
            }
        if ssl_verify is None:
            ssl_verify = get_ssl_verify(self.resolved_address)

        try:
            url = f"{self.base_url}{endpoint}"

            if method.upper() == 'GET':
                response = self._request_with_retry(
                    f"{method.upper()} {endpoint}",
                    lambda: local_session().get(
                        url,
                        headers=headers,
                        verify=ssl_verify,
                        timeout=DD_API_TIMEOUT_SECONDS,
                    ),
                )
            elif method.upper() == 'POST':
                response = self._request_with_retry(
                    f"{method.upper()} {endpoint}",
                    lambda: local_session().post(
                        url,
                        headers=headers,
                        json=data,
                        verify=ssl_verify,
                        timeout=DD_API_TIMEOUT_SECONDS,
                    ),
                )
            elif method.upper() == 'PUT':
                response = self._request_with_retry(
                    f"{method.upper()} {endpoint}",
                    lambda: local_session().put(
                        url,
                        headers=headers,
                        json=data,
                        verify=ssl_verify,
                        timeout=DD_API_TIMEOUT_SECONDS,
                    ),
                )
            elif method.upper() == 'DELETE':
                response = self._request_with_retry(
                    f"{method.upper()} {endpoint}",
                    lambda: local_session().delete(
                        url,
                        headers=headers,
                        verify=ssl_verify,
                        timeout=DD_API_TIMEOUT_SECONDS,
                    ),
                )
            else:
                logger.error(f"Unsupported HTTP method: {method}")
                return None

            if response.status_code == 200:
                return response.json()
            else:
                logger.debug(f"DataDomain API request to {endpoint} failed: HTTP {response.status_code}")
                return None
        except Exception as e:
            logger.debug(f"Error making DataDomain API request to {endpoint}: {e}")
            return None

    def _get_ha_status(self, headers, ssl_verify, system_type=None):
        """Get High Availability status and partner node information

        Args:
            headers: Request headers
            ssl_verify: SSL verification setting
            system_type: System type from /rest/v1.0/system (e.g., 'HA')

        Returns:
            dict: HA status information or None
        """
        try:
            # Try both API v1 and REST v1.0 endpoints for HA information
            # API v1 provides more structured data with HaSysInfo schema
            data = self._make_api_request('/api/v1/dd-systems/0/ha', headers, ssl_verify)

            # If API v1 fails, fallback to REST v1.0
            if not data:
                data = self._make_api_request('/rest/v1.0/dd-systems/0/ha', headers, ssl_verify)

            if not data:
                return None

            # Extract haInfo section if present (API v1/v2.0 format with HaSysInfo wrapper)
            # If not present, use the entire data object (REST v1.0 format)
            ha_section = data.get('haInfo', data)

            # Check if HA is enabled by multiple indicators:
            # 1. system_type == 'HA' from /rest/v1.0/system (field 'type')
            # 2. mode == 'active_standby' or 'active_passive' from HA info
            # 3. enabled field (may not always be present)
            ha_mode = ha_section.get('mode', '').lower()
            ha_enabled = (
                system_type == 'HA' or
                ha_mode in ['active_standby', 'active_passive'] or
                data.get('enabled', False)
            )

            ha_info = {
                'enabled': ha_enabled,
                'state': ha_section.get('state', 'unknown'),
                'role': ha_section.get('role', 'unknown'),
                'mode': ha_section.get('mode'),
                'node_name': ha_section.get('nodeName'),  # Current node's name
                'origin_hostname': ha_section.get('originHostname'),
                'system_id': ha_section.get('systemId'),
                'partner_name': data.get('partner_name'),  # Will be populated from peer info if not present
                'partner_address': data.get('partner_address'),
                'partner_status': data.get('partner_status'),
                'failover_status': data.get('failover_status')
            }

            # Extract peer information if available
            peer_info = ha_section.get('peerInfo', {})
            if peer_info:
                ha_info['peer'] = {
                    'chassis_no': peer_info.get('chassisno'),
                    'serial_no': peer_info.get('serialno'),
                    'ip': peer_info.get('ip'),
                    'node_name': peer_info.get('nodeName'),
                    'state': peer_info.get('state'),
                    'origin_hostname': peer_info.get('originHostname')
                }
                # Use peer info to populate partner fields if not already set
                if not ha_info['partner_name'] and peer_info.get('nodeName'):
                    ha_info['partner_name'] = peer_info.get('nodeName')
                if not ha_info['partner_address'] and peer_info.get('ip'):
                    ha_info['partner_address'] = peer_info.get('ip')
                if not ha_info['partner_status'] and peer_info.get('state'):
                    ha_info['partner_status'] = peer_info.get('state')

            # Extract failover history if available
            failover_history = data.get('failoverHistory', [])
            if failover_history:
                ha_info['failover_history'] = failover_history

            logger.debug(f"DataDomain {self.ip_address} - HA Status: {ha_info.get('state')}, "
                        f"Role: {ha_info.get('role')}, Mode: {ha_info.get('mode')}, "
                        f"Node: {ha_info.get('node_name')}, Partner: {ha_info.get('partner_name')}")

            return ha_info
        except Exception as e:
            logger.debug(f"Could not get HA status for DataDomain {self.ip_address}: {e}")
            return None

    def _get_active_alerts(self, headers, ssl_verify):
        """Get active alerts from the system

        Returns:
            list: List of active alerts with severity, message, etc.

        API schema reference: dd_api.json – alertDetail definition
        Response key: alert_list (alerts definition)
        Key fields: msg, class, status, alert_gen_epoch, alert_id, description, partError
        """
        try:
            data = self._make_api_request('/rest/v1.0/dd-systems/0/alerts', headers, ssl_verify)
            if not data:
                return []

            # The v1.0 API response wraps the list under 'alert_list' (alerts schema).
            # Fallback to legacy key names for safety.
            alerts = []
            alert_list = (
                data.get('alert_list')
                or data.get('alerts', [])
                or data.get('alert', [])
                or []
            )

            if isinstance(alert_list, list):
                for alert in alert_list:
                    # Filter to only active alerts.
                    # API schema: status field with enum [active, cleared]
                    if alert.get('status', '').lower() in self.ACTIVE_ALERT_STATES:
                        epoch = alert.get('alert_gen_epoch')
                        timestamp = _epoch_s_to_str(epoch) if epoch else '-'

                        alerts.append({
                            'id': alert.get('alert_id', alert.get('id', '-')),
                            'severity': alert.get('severity', 'unknown'),
                            'category': alert.get('class', '-'),
                            'message': alert.get('msg', alert.get('description', '')),
                            'timestamp': timestamp,
                            'state': alert.get('status', 'active'),
                            'error_code': alert.get('partError', '-'),
                            'name': alert.get('name', '-'),
                        })

            logger.debug(f"DataDomain {self.ip_address} - Found {len(alerts)} active alerts")
            return alerts
        except Exception as e:
            logger.debug(f"Could not get alerts for DataDomain {self.ip_address}: {e}")
            return []

    def _get_all_network_interfaces(self, headers, ssl_verify):
        """Get all network interface information

        Returns:
            list: List of network interfaces with IPs
        """
        try:
            data = self._make_api_request('/rest/v1.0/dd-systems/0/networks', headers, ssl_verify)
            if not data:
                return []

            interfaces = []
            # Try multiple possible field names for network list
            network_list = data.get('network')
            if network_list is None:
                network_list = data.get('networks', [])

            if isinstance(network_list, list):
                for iface in network_list:
                    ip_config = iface.get('ip_config', {})
                    ip_address = ip_config.get('ip_address')

                    if ip_address:
                        interfaces.append({
                            'name': iface.get('name', iface.get('id', 'unknown')),
                            'ip_address': ip_address,
                            'enabled': iface.get('enabled', False),
                            'link_status': iface.get('link_status', 'unknown'),
                            'mtu': iface.get('mtu')
                        })

            logger.debug(f"DataDomain {self.ip_address} - Found {len(interfaces)} network interfaces")
            return interfaces
        except Exception as e:
            logger.debug(f"Could not get network interfaces for DataDomain {self.ip_address}: {e}")
            return []

    def _get_network_nics(self, headers, ssl_verify):
        """Get network NICs information from v2.0 API

        Returns:
            list: List of network NICs with detailed configuration
        """
        try:
            step_started = time.monotonic()

            def _nics_time_exceeded() -> bool:
                # 0 or negative disables the NIC time budget entirely.
                if DD_NETWORK_NICS_MAX_SECONDS <= 0:
                    return False
                return (time.monotonic() - step_started) >= DD_NETWORK_NICS_MAX_SECONDS

            # Try v2.0 API first for NICs
            data = self._make_api_request('/rest/v2.0/dd-systems/0/networks/nics', headers, ssl_verify)
            if not data:
                # Fallback to v1.0 API
                return self._get_all_network_interfaces(headers, ssl_verify)

            nics = []
            # Try multiple possible field names for NIC list
            nic_list = data.get('nics')
            if nic_list is None:
                nic_list = data.get('nic', [])

            if isinstance(nic_list, list):
                for nic in nic_list:
                    nic_name = nic.get('name', nic.get('id', 'unknown'))
                    # Management interfaces are the only NICs needed by status/details views.
                    # Keep optional full expansion behind env flag for troubleshooting.
                    if not DD_NETWORK_NIC_EXPAND_ALL_DETAILS and nic_name not in self.MANAGEMENT_INTERFACES:
                        continue
                    nic_info = {
                        'name': nic_name,
                        'enabled': nic.get('enabled', False),
                        'link_status': nic.get('link_status', 'unknown'),
                        'mtu': nic.get('mtu')
                    }

                    # Extract IP configuration - check both 'address' field and 'ip_config' object
                    # v2.0 API can return IP in 'address' field directly
                    if nic.get('address'):
                        nic_info['ip_address'] = nic.get('address')
                        nic_info['netmask'] = nic.get('netmask')
                        nic_info['gateway'] = nic.get('gateway')
                    else:
                        # Fallback to ip_config object format
                        ip_config = nic.get('ip_config', {})
                        if ip_config:
                            nic_info['ip_address'] = ip_config.get('ip_address')
                            nic_info['netmask'] = ip_config.get('netmask')
                            nic_info['gateway'] = ip_config.get('gateway')

                    # Only include NICs with IP addresses
                    if nic_info.get('ip_address'):
                        nics.append(nic_info)

                    # If no IP was found but ID is available, try to fetch individual NIC details
                    elif nic.get('id'):
                        if _nics_time_exceeded():
                            logger.warning(
                                "DataDomain %s - stopping NIC detail expansion after %.1fs (budget %.1fs)",
                                self.ip_address,
                                time.monotonic() - step_started,
                                DD_NETWORK_NICS_MAX_SECONDS,
                            )
                            break
                        if not DD_NETWORK_NIC_EXPAND_ALL_DETAILS and nic_info.get('name') not in self.MANAGEMENT_INTERFACES:
                            continue
                        nic_id = nic.get('id')
                        nic_detail = self._make_api_request(f'/rest/v2.0/dd-systems/0/networks/nics/{nic_id}', headers, ssl_verify)
                        if nic_detail:
                            # Check for 'address' field first, then fallback to 'ip_config'
                            if nic_detail.get('address'):
                                nic_info['ip_address'] = nic_detail.get('address')
                                nic_info['netmask'] = nic_detail.get('netmask')
                                nic_info['gateway'] = nic_detail.get('gateway')
                                nics.append(nic_info)
                            else:
                                ip_config = nic_detail.get('ip_config', {})
                                if ip_config.get('ip_address'):
                                    nic_info['ip_address'] = ip_config.get('ip_address')
                                    nic_info['netmask'] = ip_config.get('netmask')
                                    nic_info['gateway'] = ip_config.get('gateway')
                                    nics.append(nic_info)

            # Always query management interfaces individually to ensure we capture all local IPs
            # This ensures interfaces like ethMa (local IP on primary node) are not missed
            # Track which interfaces were already found to avoid duplicates
            found_interfaces = {nic.get('name') for nic in nics if nic.get('name')}

            for iface_name in self.MANAGEMENT_INTERFACES:
                if _nics_time_exceeded():
                    logger.warning(
                        "DataDomain %s - stopping management NIC lookups after %.1fs (budget %.1fs)",
                        self.ip_address,
                        time.monotonic() - step_started,
                        DD_NETWORK_NICS_MAX_SECONDS,
                    )
                    break
                # Skip if we already found this interface from bulk API
                if iface_name in found_interfaces:
                    continue

                try:
                    iface_data = self._make_api_request(f'/rest/v2.0/dd-systems/0/networks/nics/{iface_name}', headers, ssl_verify)
                    if iface_data:
                        # Check for 'address' field first, then fallback to 'ip_config'
                        ip_address = iface_data.get('address')
                        netmask = iface_data.get('netmask')
                        gateway = iface_data.get('gateway')

                        if not ip_address:
                            ip_config = iface_data.get('ip_config', {})
                            ip_address = ip_config.get('ip_address')
                            netmask = ip_config.get('netmask')
                            gateway = ip_config.get('gateway')

                        if ip_address:
                            logger.debug(f"DataDomain {self.ip_address} - Found IP {ip_address} for interface {iface_name}")
                            nics.append({
                                'name': iface_name,
                                'ip_address': ip_address,
                                'netmask': netmask,
                                'gateway': gateway,
                                'enabled': iface_data.get('enabled', False),
                                'link_status': iface_data.get('link_status', 'unknown'),
                                'mtu': iface_data.get('mtu')
                            })
                except Exception as e:
                    logger.debug(f"Could not get individual NIC {iface_name} for DataDomain {self.ip_address}: {e}")

            logger.debug(f"DataDomain {self.ip_address} - Found {len(nics)} NICs from v2.0 API")

            # Perform reverse DNS lookups for included NICs (management-focused by default).
            nics_with_dns = []
            for nic in nics:
                ip_address = nic.get('ip_address')
                if ip_address:
                    dns_names = reverse_dns_lookup(ip_address)
                    # Maintain both 'ip_address' (for template display) and 'ip' (for extract_ips_from_mgmt_ips)
                    # This dual format ensures compatibility with both DataDomain-specific template code
                    # and the generic IP extraction function used by all vendors
                    nic_with_dns = nic.copy()
                    nic_with_dns['ip'] = ip_address  # Add 'ip' field for extract_ips_from_mgmt_ips compatibility
                    nic_with_dns['dns_names'] = dns_names
                    nics_with_dns.append(nic_with_dns)
                    if dns_names:
                        logger.info(f"DataDomain {self.ip_address} - DNS resolved for {ip_address} ({nic.get('name')}): {dns_names}")
                else:
                    # Keep NICs without IP as-is
                    nics_with_dns.append(nic)

            return nics_with_dns
        except Exception as e:
            logger.debug(f"Could not get NICs from v2.0 API for DataDomain {self.ip_address}: {e}")
            # Fallback to v1.0 API
            return self._get_all_network_interfaces(headers, ssl_verify)

    def _get_replication_status(self, headers, ssl_verify):
        """Get replication context information

        Returns:
            dict: Replication status information
        """
        try:
            data = self._make_api_request('/rest/v1.0/dd-systems/0/replication/contexts', headers, ssl_verify)
            if not data:
                return None

            contexts = []
            context_list = data.get('context', []) or data.get('contexts', []) or []

            if isinstance(context_list, list):
                for ctx in context_list:
                    contexts.append({
                        'id': ctx.get('id'),
                        'name': ctx.get('name'),
                        'state': ctx.get('state', 'unknown'),
                        'direction': ctx.get('direction'),
                        'remote_host': ctx.get('remote_host'),
                        'remote_user': ctx.get('remote_user')
                    })

            repl_info = {
                'context_count': len(contexts),
                'contexts': contexts
            }

            logger.debug(f"DataDomain {self.ip_address} - Found {len(contexts)} replication contexts")
            return repl_info
        except Exception as e:
            logger.debug(f"Could not get replication status for DataDomain {self.ip_address}: {e}")
            return None

    def _get_mtree_replications(self, headers, ssl_verify):
        """Get MTree replication information using the DataDomain API schema endpoint.

        Uses GET /api/v1/dd-systems/0/mtree-replications as defined in the dd_api.json
        schema. Each entry (MtreeReplicationDetail) carries sourceHost, destinationHost,
        sourceMtreePath, destinationMtreePath, mode (SOURCE/TARGET), state and connected.

        Returns:
            list: List of normalised MTree replication dicts, or empty list on failure.
        """
        try:
            data = self._make_api_request('/api/v1/dd-systems/0/mtree-replications', headers, ssl_verify)
            if not data:
                return []

            contexts = data.get('contexts', []) or []
            result = []
            for ctx in contexts:
                if not isinstance(ctx, dict):
                    continue
                result.append({
                    'id': ctx.get('id'),
                    'mode': ctx.get('mode', 'SOURCE'),
                    'state': ctx.get('state', 'unknown'),
                    'connected': ctx.get('connected', False),
                    'source_host': ctx.get('sourceHost'),
                    'destination_host': ctx.get('destinationHost'),
                    'source_mtree': ctx.get('sourceMtreePath'),
                    'destination_mtree': ctx.get('destinationMtreePath'),
                })

            logger.debug(f"DataDomain {self.ip_address} - Found {len(result)} MTree replication contexts")
            return result
        except Exception as e:
            logger.debug(f"Could not get MTree replications for DataDomain {self.ip_address}: {e}")
            return []

    def _get_replication_targets(self, headers, ssl_verify):
        """Get the list of replication target systems for this DataDomain.

        Uses GET /api/v1/dd-systems/0/replication/targets as specified in
        the dd_api.json schema. Each target entry identifies a remote system
        that this DD replicates data TO, providing hostname and connectivity state.

        Returns:
            list: List of target host/state dicts, or empty list on failure.
        """
        try:
            data = self._make_api_request(
                '/api/v1/dd-systems/0/replication/targets', headers, ssl_verify
            )
            if not data:
                return []
            targets_raw = data.get('targets', []) or data.get('replication_target', []) or []
            result = []
            for t in targets_raw:
                if not isinstance(t, dict):
                    continue
                result.append({
                    'host': t.get('hostname') or t.get('host') or t.get('name'),
                    'state': t.get('state', 'unknown'),
                    'port': t.get('port'),
                })
            logger.debug(
                f"DataDomain {self.ip_address} - Found {len(result)} replication targets"
            )
            return result
        except Exception as e:
            logger.debug(
                f"Could not get replication targets for DataDomain {self.ip_address}: {e}"
            )
            return []

    def _get_replication_sources(self, headers, ssl_verify):
        """Get the list of replication source systems for this DataDomain.

        Uses GET /api/v1/dd-systems/0/replication/sources as specified in
        the dd_api.json schema. Each source entry identifies a remote system
        that replicates data TO this DD.

        Returns:
            list: List of source host/state dicts, or empty list on failure.
        """
        try:
            data = self._make_api_request(
                '/api/v1/dd-systems/0/replication/sources', headers, ssl_verify
            )
            if not data:
                return []
            sources_raw = data.get('sources', []) or data.get('replication_source', []) or []
            result = []
            for s in sources_raw:
                if not isinstance(s, dict):
                    continue
                result.append({
                    'host': s.get('hostname') or s.get('host') or s.get('name'),
                    'state': s.get('state', 'unknown'),
                    'port': s.get('port'),
                })
            logger.debug(
                f"DataDomain {self.ip_address} - Found {len(result)} replication sources"
            )
            return result
        except Exception as e:
            logger.debug(
                f"Could not get replication sources for DataDomain {self.ip_address}: {e}"
            )
            return []

    def _get_hardware_status(self, headers, ssl_verify):
        """Get hardware component health status

        Returns:
            dict: Hardware health information
        """
        try:
            data = self._make_api_request('/rest/v1.0/dd-systems/0/hardware', headers, ssl_verify)
            if not data:
                return None

            hw_info = {
                'chassis_status': data.get('chassis', {}).get('status', 'unknown'),
                'controller_count': len(data.get('controllers', [])),
                'disk_count': len(data.get('disks', [])),
                'power_supply_count': len(data.get('power_supplies', [])),
                'fan_count': len(data.get('fans', [])),
                'overall_status': 'ok'  # Will be updated based on component status
            }

            # Check for failed components and distinguish error vs warning
            # Error states (using class constant): failed, error, critical
            # Warning states: degraded, warning, unknown
            failed_components = []
            warning_components = []
            warning_states = ['degraded', 'warning']

            for component_type in ['power_supplies', 'fans', 'controllers']:
                components = data.get(component_type, [])
                if isinstance(components, list):
                    for comp in components:
                        comp_status = comp.get('status', '').lower()
                        comp_id = comp.get('id', 'unknown')
                        if comp_status in self.FAILED_COMPONENT_STATES:
                            failed_components.append(f"{component_type}:{comp_id}")
                        elif comp_status in warning_states:
                            warning_components.append(f"{component_type}:{comp_id}")

            # Also check disk status via dedicated disk API
            disk_data = self._make_api_request('/api/v1/dd-systems/0/storage/disks', headers, ssl_verify)
            if disk_data:
                disk_list = disk_data.get('diskInfo', []) or []
                hw_info['disk_count'] = len(disk_list)
                for disk in disk_list:
                    disk_status = disk.get('status', '').upper()
                    disk_id = disk.get('id', disk.get('device', 'unknown'))
                    # ERROR and FAILED are critical disk states
                    if disk_status in ('ERROR', 'FAILED'):
                        failed_components.append(f"disk:{disk_id}")
                    # ABSENT/POWERED_OFF/NOT_INSTALLED can indicate issues
                    elif disk_status in ('UNKNOWN', 'FOREIGN', 'INVALID'):
                        warning_components.append(f"disk:{disk_id}")

            if failed_components:
                hw_info['overall_status'] = 'error'
                hw_info['failed_components'] = failed_components
            elif warning_components:
                hw_info['overall_status'] = 'warning'
                hw_info['warning_components'] = warning_components

            logger.debug(f"DataDomain {self.ip_address} - Hardware status: {hw_info.get('overall_status')}")
            return hw_info
        except Exception as e:
            logger.debug(f"Could not get hardware status for DataDomain {self.ip_address}: {e}")
            return None

    def _get_service_status(self, headers, ssl_verify):
        """Get system service status

        Returns:
            list: List of services with their status
        """
        try:
            data = self._make_api_request('/rest/v1.0/dd-systems/0/services', headers, ssl_verify)
            if not data:
                return []

            services = []
            service_list = data.get('service', []) or data.get('services', []) or []

            if isinstance(service_list, list):
                for svc in service_list:
                    services.append({
                        'name': svc.get('name', 'unknown'),
                        'status': svc.get('status', 'unknown'),
                        'enabled': svc.get('enabled', False)
                    })

            logger.debug(f"DataDomain {self.ip_address} - Found {len(services)} services")
            return services
        except Exception as e:
            logger.debug(f"Could not get service status for DataDomain {self.ip_address}: {e}")
            return []

    def _get_with_timeout_retry(self, url: str, *, headers, ssl_verify):
        """GET wrapper with timeout-only retry for transient DD health polling hiccups."""
        attempts = max(1, DD_HEALTH_TIMEOUT_RETRIES + 1)
        for attempt in range(1, attempts + 1):
            try:
                return local_session().get(
                    url,
                    headers=headers,
                    verify=ssl_verify,
                    timeout=DD_API_TIMEOUT_SECONDS,
                )
            except Exception as exc:
                if not _is_timeout_error(exc):
                    raise
                if attempt >= attempts:
                    raise
                logger.warning(
                    "DataDomain health request timeout for %s (attempt %d/%d), retrying in %.1fs",
                    self.ip_address,
                    attempt,
                    attempts,
                    DD_HEALTH_TIMEOUT_RETRY_BACKOFF_SECONDS,
                )
                time.sleep(max(0.0, DD_HEALTH_TIMEOUT_RETRY_BACKOFF_SECONDS))

    def get_health_status(self, include_optional_details: bool = True, progress_callback=None):
        try:
            # DataDomain REST API v1.0 with token authentication
            # If no token is configured, try to authenticate automatically
            new_token_generated = False
            if not self.token:
                logger.debug(f"Attempting automatic authentication for DataDomain {self.ip_address}")
                self.token = self.authenticate()
                if self.token:
                    new_token_generated = True
                else:
                    return self._format_response(status='error', hardware='error', cluster='error',
                                                error='Authentication failed. Please check credentials.')

            headers = {
                'X-DD-AUTH-TOKEN': self.token,
                'Accept': 'application/json'
            }
            ssl_verify = get_ssl_verify(self.resolved_address)

            # Get system info from /rest/v1.0/system
            # This provides comprehensive system information including capacity, compression, etc.
            response = self._timed_call(
                "system",
                self._get_with_timeout_retry,
                f"{self.base_url}/rest/v1.0/system",
                headers=headers,
                ssl_verify=ssl_verify,
                progress_callback=progress_callback,
            )

            if response.status_code != 200:
                error_msg = f'API error: {response.status_code}'
                if response.status_code == 401:
                    # Token invalid - try to re-authenticate once
                    logger.debug(f"Re-authenticating to DataDomain {self.ip_address}")

                    new_token = self.authenticate()
                    if new_token:
                        self.token = new_token
                        new_token_generated = True

                        # Retry the request with new token
                        headers['X-DD-AUTH-TOKEN'] = self.token
                        response = self._get_with_timeout_retry(
                            f"{self.base_url}/rest/v1.0/system",
                            headers=headers,
                            ssl_verify=ssl_verify,
                        )

                        if response.status_code != 200:
                            error_msg = f'API error: {response.status_code}'
                            logger.error(f"DataDomain API error for {self.ip_address}: HTTP {response.status_code}")
                            return self._format_response(status='error', hardware='error', cluster='error', error=error_msg)
                    else:
                        error_msg = 'API error: 401 - Authentication failed. Please check credentials.'
                        logger.error(f"DataDomain authentication failed for {self.ip_address}")
                        return self._format_response(status='error', hardware='error', cluster='error', error=error_msg)
                else:
                    logger.error(f"DataDomain API error for {self.ip_address}: HTTP {response.status_code}")
                    try:
                        logger.error(f"Response text: {response.text[:MAX_RESPONSE_LOG_LENGTH]}")
                    except Exception:
                        logger.error("Response text unavailable")
                    return self._format_response(status='error', hardware='error', cluster='error', error=error_msg)

            data = response.json()

            # Extract system information
            os_version = data.get('version')
            system_name = data.get('name')
            model = data.get('model')
            system_type = data.get('type')  # 'HA' for HA clusters

            # Extract capacity information from physical_capacity
            physical_capacity = data.get('physical_capacity', {})
            total_bytes = physical_capacity.get('total', 0)
            used_bytes = physical_capacity.get('used', 0)

            # Get logical capacity and compression factor for additional info
            data.get('logical_capacity', {})
            compression_factor = data.get('compression_factor', 0) or 0

            logger.debug(f"DataDomain {self.ip_address} - System: {system_name}, Type: {system_type}, Model: {model}, "
                        f"Version: {os_version}, Compression: {compression_factor:.2f}x")

            # Gather comprehensive system information using helper methods
            # Get HA status and partner node information
            ha_status = None
            active_alerts = []
            network_interfaces = []
            alert_count = 0
            if include_optional_details:
                ha_status = self._timed_call(
                    "ha_status",
                    self._get_ha_status,
                    headers,
                    ssl_verify,
                    system_type,
                    progress_callback=progress_callback,
                )

                # Get active alerts
                active_alerts = self._timed_call(
                    "active_alerts",
                    self._get_active_alerts,
                    headers,
                    ssl_verify,
                    progress_callback=progress_callback,
                )
                alert_count = len(active_alerts)

                # Get all network interfaces (includes management IPs)
                # Try v2.0 NICs API first, fallback to v1.0 networks API
                network_interfaces = self._timed_call(
                    "network_nics",
                    self._get_network_nics,
                    headers,
                    ssl_verify,
                    progress_callback=progress_callback,
                )

                # If network interfaces API didn't work, try the legacy method for management IPs
                if not network_interfaces:
                    for iface in self.MANAGEMENT_INTERFACES:
                        try:
                            iface_response = local_session().get(
                                f"{self.base_url}/rest/v1.0/dd-systems/0/networks/{iface}",
                                headers=headers,
                                verify=ssl_verify,
                                timeout=DD_API_TIMEOUT_SECONDS
                            )

                            if iface_response.status_code == 200:
                                iface_data = iface_response.json()
                                ip_config = iface_data.get('ip_config', {})
                                ip_address = ip_config.get('ip_address')
                                if ip_address:
                                    network_interfaces.append({
                                        'name': iface,
                                        'ip_address': ip_address,
                                        'enabled': iface_data.get('enabled', False)
                                    })
                        except Exception as iface_error:
                            logger.debug(f"Could not get interface {iface} for DataDomain {self.ip_address}: {iface_error}")

            # Get replication status (legacy context API)
            replication_status = self._timed_call(
                "replication_status",
                self._get_replication_status,
                headers,
                ssl_verify,
                progress_callback=progress_callback,
            )

            # Get MTree replications using the schema-defined endpoint
            # GET /api/v1/dd-systems/0/mtree-replications (per dd_api.json)
            mtree_replications = self._timed_call(
                "mtree_replications",
                self._get_mtree_replications,
                headers,
                ssl_verify,
                progress_callback=progress_callback,
            )

            # Get replication partner information via targets/sources endpoints
            # GET /api/v1/dd-systems/0/replication/targets  – systems this DD replicates TO
            # GET /api/v1/dd-systems/0/replication/sources  – systems replicating TO this DD
            replication_targets = self._timed_call(
                "replication_targets",
                self._get_replication_targets,
                headers,
                ssl_verify,
                progress_callback=progress_callback,
            )
            replication_sources = self._timed_call(
                "replication_sources",
                self._get_replication_sources,
                headers,
                ssl_verify,
                progress_callback=progress_callback,
            )

            hardware_status = None
            service_status = []
            if include_optional_details:
                # Get hardware health status
                hardware_status = self._timed_call(
                    "hardware_status",
                    self._get_hardware_status,
                    headers,
                    ssl_verify,
                    progress_callback=progress_callback,
                )

                # Get service status
                service_status = self._timed_call(
                    "service_status",
                    self._get_service_status,
                    headers,
                    ssl_verify,
                    progress_callback=progress_callback,
                )

            # Determine overall hardware and cluster status based on gathered data
            hardware_health = 'ok'
            cluster_health = 'ok'

            # Check hardware status - propagate 'error' and 'warning' from component checks
            if hardware_status:
                overall = hardware_status.get('overall_status', 'ok')
                if overall == 'error':
                    hardware_health = 'error'
                elif overall == 'warning':
                    hardware_health = 'warning'

            # Check HA/cluster status
            if ha_status:
                ha_state = ha_status.get('state', '').lower()
                if ha_state in ['failed', 'error', 'critical']:
                    cluster_health = 'error'
                elif ha_state in ['degraded', 'warning']:
                    cluster_health = 'warning'

            # Check for critical alerts (using class constant)
            critical_alerts = [a for a in active_alerts
                             if a.get('severity', '').lower() in self.CRITICAL_ALERT_SEVERITIES]
            if critical_alerts:
                if hardware_health != 'error':
                    hardware_health = 'warning'

            # Build comprehensive response
            result = self._format_response(
                status='online',
                hardware=hardware_health,
                cluster=cluster_health,
                alerts=alert_count,
                total_tb=total_bytes / (1024**4),
                used_tb=used_bytes / (1024**4),
                os_version=os_version,
                all_mgmt_ips=network_interfaces if network_interfaces else None
            )

            # Add DataDomain-specific information to result
            if ha_status:
                result['ha_status'] = ha_status

            if include_optional_details and active_alerts:
                result['active_alerts'] = active_alerts

            if replication_status:
                result['replication_status'] = replication_status

            if mtree_replications:
                result['mtree_replications'] = mtree_replications

            if replication_targets:
                result['replication_targets'] = replication_targets

            if replication_sources:
                result['replication_sources'] = replication_sources

            if include_optional_details and hardware_status:
                result['hardware_details'] = hardware_status

            if include_optional_details and service_status:
                result['services'] = service_status

            # Add additional system details
            result['system_name'] = system_name
            result['model'] = model
            if compression_factor:
                result['compression_factor'] = compression_factor

            # Include new token if one was generated
            if new_token_generated:
                result['new_api_token'] = self.token

            return result

        except Exception as e:
            if _is_timeout_error(e):
                err = (
                    f"DataDomain API timeout after {DD_API_TIMEOUT_SECONDS}s "
                    f"({self.base_url}/rest/v1.0/system)"
                )
                logger.warning(
                    "DataDomain health request timed out for %s after %ss",
                    self.ip_address,
                    DD_API_TIMEOUT_SECONDS,
                )
                return self._format_response(
                    status='error',
                    hardware='error',
                    cluster='error',
                    error=err,
                )

            logger.error(f"Error getting Dell DataDomain health status for {self.ip_address}: {e}")
            return self._format_response(status='error', hardware='error', cluster='error', error=str(e))
