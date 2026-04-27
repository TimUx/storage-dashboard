"""Pure Storage FlashArray REST API client."""
import logging
import traceback
from datetime import datetime, timezone

from app.api.base_client import StorageClient
from app.api.storage_clients.common import _epoch_ms_to_str
from app.api.storage_clients.runtime import local_session
from app.discovery import reverse_dns_lookup
from app.ssl_utils import get_ssl_verify

logger = logging.getLogger(__name__)

class PureStorageClient(StorageClient):
    """Pure Storage FlashArray client using REST API"""

    # FlashArray REST API version (will be detected dynamically)
    API_VERSION = '2.4'

    # Hardware component statuses that indicate an error condition
    HW_ERROR_STATES = frozenset(('critical', 'unhealthy', 'failed'))
    # Drive statuses that indicate an error condition
    DRIVE_ERROR_STATES = frozenset(('failed', 'unhealthy', 'missing', 'unrecognized'))
    # Statuses that are considered healthy/normal (no action needed)
    HW_OK_STATES = frozenset(('ok', 'healthy', 'normal', 'identifying'))
    DRIVE_OK_STATES = frozenset(('healthy', 'ok', 'identifying', 'recovering', 'updating', 'unadmitted'))
    # Statuses that mean the slot/bay is empty (skip entirely)
    HW_SKIP_STATES = frozenset(('', 'unused', 'not_installed'))
    DRIVE_SKIP_STATES = frozenset(('', 'empty', 'unused'))
    # Controller statuses that are considered healthy/normal.
    # 'ready'   – normal operational state (REST API and CLI)
    # 'ok'      – alternative healthy status reported by some firmware versions
    # 'online'  – seen on some models when the controller is active
    # 'healthy' – generic healthy status used in newer API revisions
    CTRL_OK_STATES = frozenset(('ready', 'ok', 'online', 'healthy'))

    def detect_api_version(self):
        """Detect the API version supported by the FlashArray"""
        try:
            ssl_verify = get_ssl_verify(self.resolved_address)

            # Query api_version endpoint
            response = local_session().get(
                f"{self.base_url}/api/api_version",
                verify=ssl_verify,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                # Get the latest supported version
                versions = data.get('version', [])
                if versions:
                    # Return the latest version (usually last in the list)
                    latest_version = versions[-1] if isinstance(versions, list) else versions
                    logger.info(f"Detected Pure Storage API version: {latest_version}")
                    return latest_version
        except Exception as e:
            logger.warning(f"Could not detect API version for {self.ip_address}: {e}")

        # Return default version if detection fails
        return self.API_VERSION

    def authenticate(self, api_version):
        """Authenticate and get session token for API 2.x

        For Pure Storage FlashArray API 2.x, authentication requires:
        1. POST to /api/2.x/login with api-token in request header
        2. Receive x-auth-token in response header
        3. Use x-auth-token for subsequent API calls
        4. POST to /api/2.x/logout when done (handled in get_health_status)

        Note: Session tokens are not cached as each client instance performs
        a complete login/query/logout cycle to minimize open sessions.

        Args:
            api_version: API version to use (e.g., '2.4', '2.26')

        Returns:
            Session token string or None if authentication fails
        """
        try:
            ssl_verify = get_ssl_verify(self.resolved_address)

            # For API 2.x, we need to login with the API token to get a session token
            # POST /api/2.x/login with api-token in the request header
            # This is the correct format for Pure Storage FlashArray API 2.x
            response = local_session().post(
                f"{self.base_url}/api/{api_version}/login",
                headers={
                    'api-token': self.token
                },
                verify=ssl_verify,
                timeout=10
            )

            if response.status_code == 200:
                # Extract x-auth-token from response headers
                session_token = response.headers.get('x-auth-token')
                if session_token:
                    logger.info(f"Successfully authenticated to Pure Storage {self.ip_address}")
                    return session_token
                else:
                    logger.warning(f"No x-auth-token in login response for {self.ip_address}")
            elif response.status_code == 401:
                # Invalid API token
                logger.error(f"Authentication failed for {self.ip_address}: Invalid API token (401 Unauthorized)")
                return None
            elif response.status_code == 400:
                # Bad request - possibly malformed token
                logger.error(f"Authentication failed for {self.ip_address}: Bad request (400) - check API token format")
                return None
            else:
                logger.warning(f"Login failed for {self.ip_address}: HTTP {response.status_code}")

        except Exception as e:
            logger.warning(f"Authentication error for {self.ip_address}: {e}")

        return None

    def get_health_status(self):
        try:
            if not self.token:
                return self._format_response(status='error', hardware='error', cluster='error', error='Kein API-Token konfiguriert. Bitte API-Token in den System-Einstellungen eingeben.')

            ssl_verify = get_ssl_verify(self.resolved_address)

            # Detect API version dynamically
            api_version = self.detect_api_version()

            # Authenticate to get session token for API 2.x
            session_token = self.authenticate(api_version)

            if not session_token:
                return self._format_response(
                    status='error',
                    hardware='error',
                    cluster='error',
                    error=f'Authentifizierung fehlgeschlagen - Ungültiger API-Token oder Verbindungsfehler. API Version: {api_version}'
                )

            # FlashArray REST API v2 headers with session token
            headers = {
                'x-auth-token': session_token,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }

            # Get array info to verify connectivity and get OS version
            # REST API v2: GET /api/2.x/arrays
            response = local_session().get(
                f"{self.base_url}/api/{api_version}/arrays",
                headers=headers,
                verify=ssl_verify,
                timeout=10
            )

            if response.status_code != 200:
                return self._format_response(status='error', hardware='error', cluster='error', error=f'API error: {response.status_code}')

            # Extract OS version from array info
            array_data = response.json()
            os_version = None
            if 'items' in array_data and len(array_data['items']) > 0:
                item = array_data['items'][0]
                # Get version string - use 'version' field which contains the actual version number (e.g., "6.5.10")
                # The 'os' field contains "Purity//FA" which is not useful
                os_version = item.get('version')
                item.get('name')

            # Get space/capacity info
            # REST API v2: GET /api/2.x/arrays/space
            space_response = local_session().get(
                f"{self.base_url}/api/{api_version}/arrays/space",
                headers=headers,
                verify=ssl_verify,
                timeout=10
            )

            total_bytes = 0
            used_bytes = 0
            # Evergreen/One Dashboard detection: when the Evergreen/One Dashboard API is
            # active on the array, ``space.total_physical`` is absent or returns 0 and
            # ``capacity`` may report an incorrect (too large) licensed value instead of
            # the physically installed capacity.  Standard Dashboard arrays always return
            # a non-zero ``total_physical``.
            evergreen_one_dashboard_active = False

            if space_response.status_code == 200:
                space_data = space_response.json()

                # Parse space data from response
                # Response format: {"items": [{"capacity": ..., "space": {"total_physical": ...}}]}
                items = space_data.get('items', [])
                if items and len(items) > 0:
                    item = items[0]

                    # Get capacity (total available capacity in bytes)
                    total_bytes = item.get('capacity', 0) or 0

                    # Get used space (total_physical is the actual physically used space).
                    # When the Evergreen/One Dashboard API is active this value is 0 or absent.
                    space_info = item.get('space', {})
                    raw_total_physical = space_info.get('total_physical')
                    used_bytes = raw_total_physical or 0

                    # Detect Evergreen/One Dashboard: total_physical is absent or 0
                    if not raw_total_physical:
                        evergreen_one_dashboard_active = True
                        logger.info(
                            "Evergreen/One Dashboard API detected for %s "
                            "(space.total_physical is absent or 0)",
                            self.ip_address,
                        )

            # Get controllers/nodes information
            # REST API v2: GET /api/2.x/controllers
            controllers = []
            try:
                controllers_response = local_session().get(
                    f"{self.base_url}/api/{api_version}/controllers",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )

                if controllers_response.status_code == 200:
                    controllers_data = controllers_response.json()
                    items = controllers_data.get('items', [])

                    for ctrl in items:
                        ctrl_name = ctrl.get('name', '')

                        # Filter out shelf controllers (names containing .SC like SH9.SC0, SH9.SC1)
                        # These are not actual controller nodes
                        if '.SC' in ctrl_name:
                            logger.debug(f"Skipping shelf controller: {ctrl_name}")
                            continue

                        controller_info = {
                            'name': ctrl_name,
                            'status': ctrl.get('status'),
                            'mode': ctrl.get('mode'),
                            'model': ctrl.get('model'),
                            'version': ctrl.get('version'),
                            'type': 'controller'
                        }

                        # Collect all IPs from the controller
                        ips = []
                        if ctrl.get('ip'):
                            ips.append(ctrl.get('ip'))
                        if ctrl.get('mgmt_ip'):
                            ips.append(ctrl.get('mgmt_ip'))
                        if ctrl.get('replication_ip'):
                            ips.append(ctrl.get('replication_ip'))

                        if ips:
                            controller_info['ips'] = ips

                        controllers.append(controller_info)

                    logger.info(f"Found {len(controllers)} controllers for {self.ip_address} (shelf controllers filtered out)")
            except Exception as ctrl_error:
                logger.warning(f"Could not get controllers for {self.ip_address}: {ctrl_error}")

            # Get all management network interfaces to collect all management IPs
            # REST API v2: GET /api/2.x/network-interfaces?filter=services='management'
            all_mgmt_ips = []
            try:
                network_response = local_session().get(
                    f"{self.base_url}/api/{api_version}/network-interfaces",
                    headers=headers,
                    params={'filter': "services='management'"},
                    verify=ssl_verify,
                    timeout=10
                )

                if network_response.status_code == 200:
                    network_data = network_response.json()
                    items = network_data.get('items', [])

                    for interface in items:
                        # Check if interface is enabled and has an IP address
                        if interface.get('enabled'):
                            eth_info = interface.get('eth', {})
                            ip_address = eth_info.get('address')
                            if ip_address:
                                all_mgmt_ips.append(ip_address)

                    if all_mgmt_ips:
                        logger.info(f"Found {len(all_mgmt_ips)} management IPs for {self.ip_address}: {all_mgmt_ips}")
            except Exception as net_error:
                logger.warning(f"Could not get network interfaces for {self.ip_address}: {net_error}")

            # Perform DNS reverse lookups for all management IPs
            mgmt_ips_with_dns = []
            for mgmt_ip in all_mgmt_ips:
                dns_names = reverse_dns_lookup(mgmt_ip)
                mgmt_ips_with_dns.append({
                    'ip': mgmt_ip,
                    'dns_names': dns_names
                })
                if dns_names:
                    logger.info(f"DNS resolved for {mgmt_ip}: {dns_names}")

            # Get hardware status
            # REST API v2: GET /api/2.x/hardware
            # Types: bay, ct (controller), ch (chassis), eth, fan, fb, fc, fm, ib, iom, nvb, pwr, sas, sh (shelf), tmp (temperature)
            hardware_status = 'ok'
            hardware_details = {'components': [], 'drives': []}
            try:
                hardware_response = local_session().get(
                    f"{self.base_url}/api/{api_version}/hardware",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )

                if hardware_response.status_code == 200:
                    hardware_data = hardware_response.json()
                    items = hardware_data.get('items', [])

                    for hw in items:
                        hw_name = hw.get('name', '')
                        hw_type = hw.get('type', '')
                        hw_status = hw.get('status', '').lower()
                        hw_temp = hw.get('temperature')
                        hw_details_msg = hw.get('details', '')

                        # Only record non-empty slots/bays and components with notable status
                        if hw_status in self.HW_SKIP_STATES:
                            continue

                        component_info = {
                            'name': hw_name,
                            'type': hw_type,
                            'status': hw_status,
                        }
                        if hw_temp is not None:
                            component_info['temperature'] = hw_temp
                        if hw_details_msg:
                            component_info['details'] = hw_details_msg

                        hardware_details['components'].append(component_info)

                        # critical/unhealthy/failed = error, other non-ok states = warning
                        if hw_status in self.HW_ERROR_STATES:
                            hardware_status = 'error'
                            logger.warning(f"Hardware error on {self.ip_address}: {hw_name} ({hw_type}) is {hw_status}")
                        elif hw_status not in self.HW_OK_STATES:
                            if hardware_status != 'error':
                                hardware_status = 'warning'
                            logger.warning(f"Hardware issue on {self.ip_address}: {hw_name} ({hw_type}) is {hw_status}")
            except Exception as hw_error:
                logger.warning(f"Could not get hardware status for {self.ip_address}: {hw_error}")

            # Check drive status
            # REST API v2: GET /api/2.x/drives
            try:
                drives_response = local_session().get(
                    f"{self.base_url}/api/{api_version}/drives",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )

                if drives_response.status_code == 200:
                    drives_data = drives_response.json()
                    drive_items = drives_data.get('items', [])

                    for drive in drive_items:
                        drive_name = drive.get('name', '')
                        drive_status = drive.get('status', '').lower()
                        drive_type = drive.get('type', '')
                        drive_capacity = drive.get('capacity')
                        drive_details_msg = drive.get('details', '')

                        # Skip empty bays
                        if drive_status in self.DRIVE_SKIP_STATES:
                            continue

                        drive_info = {
                            'name': drive_name,
                            'type': drive_type,
                            'status': drive_status,
                        }
                        if drive_capacity:
                            drive_info['capacity_bytes'] = drive_capacity
                        if drive_details_msg:
                            drive_info['details'] = drive_details_msg

                        hardware_details['drives'].append(drive_info)

                        # failed/unhealthy/missing/unrecognized drives = error
                        if drive_status in self.DRIVE_ERROR_STATES:
                            hardware_status = 'error'
                            logger.warning(f"Drive error on {self.ip_address}: {drive_name} is {drive_status}")
                        elif drive_status not in self.DRIVE_OK_STATES:
                            if hardware_status != 'error':
                                hardware_status = 'warning'
                            logger.warning(f"Drive issue on {self.ip_address}: {drive_name} is {drive_status}")
            except Exception as drive_error:
                logger.warning(f"Could not get drive status for {self.ip_address}: {drive_error}")

            # Check controller health status
            # Controllers should all be in 'ready' state; 'not_ready' indicates rebooting/upgrading
            for ctrl in controllers:
                ctrl_status = (ctrl.get('status') or '').lower().replace(' ', '_')
                if ctrl_status and ctrl_status not in self.CTRL_OK_STATES:
                    hardware_status = 'error'
                    logger.warning(
                        f"Controller not ready on {self.ip_address}: "
                        f"{ctrl.get('name')} is {ctrl.get('status')!r}"
                    )

            # Get alerts
            # REST API v2: GET /api/2.x/alerts?filter=state='open'
            alerts_count = 0
            alert_details = []
            try:
                alerts_response = local_session().get(
                    f"{self.base_url}/api/{api_version}/alerts",
                    headers=headers,
                    params={'filter': "state='open'"},
                    verify=ssl_verify,
                    timeout=10
                )

                if alerts_response.status_code == 200:
                    alerts_data = alerts_response.json()
                    items = alerts_data.get('items', [])
                    # API should return only open alerts, but filter as fallback
                    # in case the API doesn't support the filter parameter
                    open_items = [a for a in items if a.get('state', '').lower() != 'closed']
                    alerts_count = len(open_items)

                    for a in open_items:
                        alert_details.append({
                            'id': str(a.get('id', '-')),
                            'title': a.get('name', '-'),
                            # 'summary' is the primary detail; fall back to 'description' or 'issue'
                            'details': a.get('summary') or a.get('description') or a.get('issue') or '-',
                            'severity': a.get('severity', 'unknown'),
                            'error_code': str(a.get('code', '-')),
                            'timestamp': _epoch_ms_to_str(a['created']) if a.get('created') else '-',
                            'component': a.get('component_name', '-'),
                        })

                    if alerts_count > 0:
                        logger.info(f"Found {alerts_count} open alerts for {self.ip_address}")
            except Exception as alerts_error:
                logger.warning(f"Could not get alerts for {self.ip_address}: {alerts_error}")

            # Get array connections (peers)
            # REST API v2: GET /api/2.x/array-connections
            array_connections = []
            try:
                connections_response = local_session().get(
                    f"{self.base_url}/api/{api_version}/array-connections",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )

                if connections_response.status_code == 200:
                    connections_data = connections_response.json()
                    items = connections_data.get('items', [])

                    for conn in items:
                        connection_info = {
                            'name': conn.get('name'),
                            'status': conn.get('status'),
                            'type': conn.get('type'),
                            'management_address': conn.get('management_address'),
                            'replication_address': conn.get('replication_address'),
                            'version': conn.get('version')
                        }
                        array_connections.append(connection_info)

                    if array_connections:
                        logger.info(f"Found {len(array_connections)} array connections for {self.ip_address}")
            except Exception as conn_error:
                logger.warning(f"Could not get array connections for {self.ip_address}: {conn_error}")

            # Check for ActiveCluster configuration
            # REST API v2: GET /api/2.x/pods
            # An array is ActiveCluster if at least one pod has arrays.length > 1
            # Also check for sync-replication type in array connections
            is_active_cluster = False
            pods_info = []

            try:
                pods_response = local_session().get(
                    f"{self.base_url}/api/{api_version}/pods",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )

                if pods_response.status_code == 200:
                    pods_data = pods_response.json()
                    items = pods_data.get('items', [])

                    for pod in items:
                        # Get arrays for this pod
                        pod_arrays = pod.get('arrays', [])

                        pod_info = {
                            'name': pod.get('name'),
                            'source': pod.get('source'),
                            'arrays': [arr.get('name') for arr in pod_arrays],
                            'array_count': pod.get('array_count', len(pod_arrays)),
                            'promotion_status': pod.get('promotion_status'),
                            'stretch': pod.get('stretch', False)
                        }
                        pods_info.append(pod_info)

                        # ActiveCluster detection: pod must have more than 1 array
                        # Check both array_count field and arrays list length
                        array_count = pod.get('array_count', len(pod_arrays))
                        if array_count > 1 or len(pod_arrays) > 1:
                            is_active_cluster = True
                            logger.info(f"ActiveCluster detected: pod '{pod.get('name')}' has {array_count} arrays")

                    if is_active_cluster:
                        logger.info(f"ActiveCluster confirmed for {self.ip_address} with {len(pods_info)} pods")
                    elif pods_info:
                        logger.debug(f"Pods exist for {self.ip_address} but no ActiveCluster (all pods have single array)")
            except Exception as pods_error:
                # Pods endpoint might not be available on all arrays
                logger.debug(f"Could not check pods for {self.ip_address}: {pods_error}")

            # Collect pod-replica-links for pod-level async replication discovery
            # REST API v2: GET /api/2.x/pod-replica-links
            # Per pure_swagger.json schema: each entry has local_pod, remote_pod,
            # direction (outbound/inbound), lag time, and link status. Outbound entries
            # represent pods that this array replicates to a remote array asynchronously.
            pod_replica_links = []
            try:
                prl_response = local_session().get(
                    f"{self.base_url}/api/{api_version}/pod-replica-links",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )
                if prl_response.status_code == 200:
                    pod_replica_links = prl_response.json().get('items', [])
                    if pod_replica_links:
                        logger.info(
                            f"Found {len(pod_replica_links)} pod replica links "
                            f"for {self.ip_address}"
                        )
            except Exception as prl_error:
                logger.debug(f"Could not get pod-replica-links for {self.ip_address}: {prl_error}")

            # Additional ActiveCluster detection via array connections
            # If there's a sync-replication type connection, it indicates ActiveCluster
            if not is_active_cluster and array_connections:
                for conn in array_connections:
                    if conn.get('type') == 'sync-replication':
                        is_active_cluster = True
                        logger.info(f"ActiveCluster detected via sync-replication connection to {conn.get('name')}")
                        break

            # Calculate site count based on peer connections
            # Each array connection represents a peer site, plus local site
            if array_connections:
                site_count = len(array_connections) + 1  # Local site + peer sites
                logger.info(f"Multi-site configuration detected: {site_count} sites (local + {len(array_connections)} peer(s))")
            else:
                site_count = 1  # Single site (no peer connections)

            # Logout to clean up the session
            try:
                local_session().post(
                    f"{self.base_url}/api/{api_version}/logout",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=5
                )
                logger.debug(f"Logged out from Pure Storage {self.ip_address}")
            except Exception as logout_error:
                # Logout errors are not critical, but log for debugging
                logger.debug(f"Logout failed for {self.ip_address}: {logout_error}")

            result = self._format_response(
                status='online',
                hardware=hardware_status,
                cluster='ok',
                alerts=alerts_count,
                total_tb=total_bytes / (1024**4),
                used_tb=used_bytes / (1024**4),
                os_version=os_version,
                api_version=api_version,
                controllers=controllers,
                array_connections=array_connections,
                is_active_cluster=is_active_cluster,
                site_count=site_count,
                pods_info=pods_info if pods_info else None,
                all_mgmt_ips=mgmt_ips_with_dns if mgmt_ips_with_dns else None,
                hardware_details=hardware_details if (hardware_details.get('components') or hardware_details.get('drives')) else None,
                alert_details=alert_details if alert_details else None,
                evergreen_one_dashboard_active=evergreen_one_dashboard_active,
            )
            if pod_replica_links:
                result['pod_replica_links'] = pod_replica_links
            return result

        except Exception as e:
            logger.error(f"Error getting Pure Storage health status for {self.ip_address}: {e}")
            logger.error(traceback.format_exc())
            return self._format_response(status='error', hardware='error', cluster='error', error=str(e))

    def _authenticated_session(self):
        """Return (api_version, session_token, ssl_verify, headers) or raise.

        Callers that need a single-operation authenticated session use this
        helper so that login/logout are handled in one place.

        Raises:
            RuntimeError: if no API token is configured, or if login is
                          rejected by the array.
        """
        if not self.token:
            raise RuntimeError("No API token configured for FlashArray")
        ssl_verify = get_ssl_verify(self.resolved_address)
        api_version = self.detect_api_version()
        session_token = self.authenticate(api_version)
        if not session_token:
            raise RuntimeError(
                f"Authentication failed for FlashArray {self.ip_address}"
            )
        headers = {
            'x-auth-token': session_token,
            'Content-Type': 'application/json',
        }
        return api_version, session_token, ssl_verify, headers

    def _logout(self, api_version, headers, ssl_verify):
        """Best-effort logout – errors are suppressed."""
        try:
            local_session().post(
                f"{self.base_url}/api/{api_version}/logout",
                headers=headers,
                verify=ssl_verify,
                timeout=10,
            )
        except Exception:
            pass

    def rename_volume_snapshot(self, snap_full_name: str, new_name_or_suffix: str) -> tuple[bool, dict]:
        """Rename a volume snapshot.

        Uses the Pure Storage REST API 2.x rename operation:

            PATCH /api/<ver>/volume-snapshots?names=<snap_full_name>
            Body: {"name": "<new_name_or_suffix>"}

        Per ``api/pure_swagger.json`` (PATCH /api/2.26/volume-snapshots):
            - The ``names`` query parameter takes the **full** snapshot name
              (``{source_volume}.{old_suffix}``).
            - The request body ``name`` field is the new resource name; for
              renaming a snapshot's suffix the full new name (``VOL.SUFFIX``)
              is the safest value as it matches the resource name returned
              by GET.

        Args:
            snap_full_name:    Full snapshot name, e.g. ``ABP_data.HDBSNAP-2026-03-13-073434``
            new_name_or_suffix: New snapshot name (``VOL.SUFFIX``) or just a
                                new suffix.

        Returns:
            ``(success, info_dict)`` where ``info_dict`` contains
            ``status_code`` and ``text`` (response body excerpt) for
            diagnostic purposes.
        """
        try:
            api_version, _session_token, ssl_verify, headers = self._authenticated_session()
            try:
                resp = local_session().patch(
                    f"{self.base_url}/api/{api_version}/volume-snapshots",
                    headers=headers,
                    params={'names': snap_full_name},
                    json={'name': new_name_or_suffix},
                    verify=ssl_verify,
                    timeout=30,
                )
                info = {'status_code': resp.status_code, 'text': resp.text[:500],
                        'api_version': api_version}
                if resp.status_code == 200:
                    logger.info(
                        "FlashArray %s: renamed snapshot %s → %s",
                        self.ip_address, snap_full_name, new_name_or_suffix,
                    )
                    return True, info
                else:
                    logger.warning(
                        "FlashArray %s: rename snapshot %s failed (HTTP %d): %s",
                        self.ip_address, snap_full_name, resp.status_code,
                        resp.text[:200],
                    )
                    return False, info
            finally:
                self._logout(api_version, headers, ssl_verify)
        except Exception as exc:
            logger.warning(
                "FlashArray rename_volume_snapshot error for %s / %s: %s",
                self.ip_address, snap_full_name, exc,
            )
            return False, {'error': str(exc)}

    def destroy_volume_snapshot(self, snap_full_name: str) -> tuple[bool, dict]:
        """Mark a volume snapshot as destroyed (pending eradication).

        Per ``api/pure_swagger.json`` (PATCH /api/2.26/volume-snapshots):

            PATCH /api/<ver>/volume-snapshots?names=<snap_full_name>
            Body: {"destroyed": true}

        After destruction the snapshot enters a ``time_remaining`` countdown
        (default 24 h on most arrays) during which it can be recovered by
        calling PATCH with ``{"destroyed": false}``.  The dashboard does
        **not** issue the final eradication DELETE: the FlashArray eradicates
        destroyed snapshots automatically once the eradication-delay expires.

        Args:
            snap_full_name: Full snapshot name, e.g. ``ABP_data.HDBSNAP-2026-03-13-073434``

        Returns:
            ``(success, info_dict)`` where ``info_dict`` contains
            ``status_code``, ``text`` (response body excerpt) and
            ``api_version`` for diagnostic purposes.
        """
        try:
            api_version, _session_token, ssl_verify, headers = self._authenticated_session()
            try:
                resp = local_session().patch(
                    f"{self.base_url}/api/{api_version}/volume-snapshots",
                    headers=headers,
                    params={'names': snap_full_name},
                    json={'destroyed': True},
                    verify=ssl_verify,
                    timeout=30,
                )
                info = {'status_code': resp.status_code, 'text': resp.text[:500],
                        'api_version': api_version}
                if resp.status_code == 200:
                    logger.info(
                        "FlashArray %s: destroyed snapshot %s (pending eradication)",
                        self.ip_address, snap_full_name,
                    )
                    return True, info
                else:
                    logger.warning(
                        "FlashArray %s: destroy snapshot %s failed (HTTP %d): %s",
                        self.ip_address, snap_full_name, resp.status_code,
                        resp.text[:200],
                    )
                    return False, info
            finally:
                self._logout(api_version, headers, ssl_verify)
        except Exception as exc:
            logger.warning(
                "FlashArray destroy_volume_snapshot error for %s / %s: %s",
                self.ip_address, snap_full_name, exc,
            )
            return False, {'error': str(exc)}

    def eradicate_volume_snapshot(self, snap_full_name: str) -> bool:
        """Permanently eradicate a previously destroyed volume snapshot.

        This is the **second step** of the two-step deletion workflow (see
        :py:meth:`destroy_volume_snapshot` for step 1).

            DELETE /api/<ver>/volume-snapshots?names=<snap_full_name>

        Per ``api/pure_swagger.json`` (DELETE /api/2.26/volume-snapshots):
            The snapshot must already be in the destroyed/pending-eradication
            state (``destroyed=true``).  Calling DELETE on an active snapshot
            returns an error.  Once eradicated the snapshot cannot be recovered.

        Args:
            snap_full_name: Full snapshot name (must already be destroyed).

        Returns:
            True on success (HTTP 200), False on failure.
        """
        try:
            api_version, _session_token, ssl_verify, headers = self._authenticated_session()
            try:
                resp = local_session().delete(
                    f"{self.base_url}/api/{api_version}/volume-snapshots",
                    headers=headers,
                    params={'names': snap_full_name},
                    verify=ssl_verify,
                    timeout=30,
                )
                if resp.status_code == 200:
                    logger.info(
                        "FlashArray %s: eradicated snapshot %s",
                        self.ip_address, snap_full_name,
                    )
                    return True
                else:
                    logger.warning(
                        "FlashArray %s: eradicate snapshot %s failed (HTTP %d): %s",
                        self.ip_address, snap_full_name, resp.status_code,
                        resp.text[:200],
                    )
                    return False
            finally:
                self._logout(api_version, headers, ssl_verify)
        except Exception as exc:
            logger.warning(
                "FlashArray eradicate_volume_snapshot error for %s / %s: %s",
                self.ip_address, snap_full_name, exc,
            )
            return False

    def get_volume_snapshots(self):
        """Return active volume snapshots from Pure FlashArray via REST API.

        Queries ``GET /api/<version>/volume-snapshots?destroyed=false`` and
        returns a list of dicts with keys:

            name         – full snapshot name, e.g. ``ABP_data.HDBSNAP-2026-03-13-073434``
            created      – ISO-8601 UTC string converted from epoch-milliseconds
            suffix       – snapshot suffix only, e.g. ``HDBSNAP-2026-03-13-073434``
                           (primary source for TTL extraction)
            source_name  – name of the source volume, e.g. ``ABP_data``
                           (used as SID-extraction fallback)

        Schema reference (api/pure_swagger.json, ``VolumeSnapshot``):
            ``created`` – int64 milliseconds since UNIX epoch (readOnly)
            ``suffix``  – suffix appended to source_name to form ``name``
            ``source``  – {id, name} reference to the parent volume (readOnly)
            ``name``    – full snapshot name = source.name + "." + suffix

        Pagination uses the ``continuation_token`` returned in each response.
        Destroyed snapshots are excluded via ``?destroyed=false``.
        """
        try:
            if not self.token:
                return []
            ssl_verify = get_ssl_verify(self.resolved_address)
            api_version = self.detect_api_version()
            session_token = self.authenticate(api_version)
            if not session_token:
                return []

            headers = {'x-auth-token': session_token, 'Content-Type': 'application/json'}
            results = []
            # Start with first page; only fetch active (non-destroyed) snapshots.
            params = {'limit': 1000, 'destroyed': 'false'}
            while True:
                resp = local_session().get(
                    f"{self.base_url}/api/{api_version}/volume-snapshots",
                    headers=headers,
                    params=params,
                    verify=ssl_verify,
                    timeout=30,
                )
                if resp.status_code != 200:
                    break
                data = resp.json()
                items = data.get('items', [])
                if not items:
                    break
                for item in items:
                    # 'created' is epoch milliseconds (int64) per the Pure
                    # Storage REST API schema.  Convert to ISO-8601 UTC string.
                    created_raw = item.get('created')
                    created_iso = None
                    if isinstance(created_raw, (int, float)) and created_raw:
                        try:
                            created_iso = datetime.fromtimestamp(
                                created_raw / 1000.0, tz=timezone.utc
                            ).strftime('%Y-%m-%dT%H:%M:%SZ')
                        except Exception:
                            pass
                    elif isinstance(created_raw, str) and created_raw:
                        # Already a string (future-proofing)
                        created_iso = created_raw
                    results.append({
                        'name': item.get('name', ''),
                        'created': created_iso,
                        'suffix': item.get('suffix', '') or '',
                        # 'source' is {id, name}; expose the name directly for
                        # SID-extraction fallback in the snapshot service.
                        'source_name': (item.get('source') or {}).get('name', '') or '',
                    })
                # Advance to next page via continuation token
                continuation = data.get('continuation_token')
                if not continuation:
                    break
                params = {'continuation_token': continuation}

            # Logout
            try:
                local_session().post(
                    f"{self.base_url}/api/{api_version}/logout",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10,
                )
            except Exception:
                pass

            return results
        except Exception as exc:
            logger.warning("FlashArray get_volume_snapshots error for %s: %s", self.ip_address, exc)
            return []

