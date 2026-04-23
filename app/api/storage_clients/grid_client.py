"""NetApp StorageGRID management API client (v4)."""
import logging
import traceback

from app.api.base_client import StorageClient
from app.api.storage_clients.common import (
    STORAGEGRID_HEALTHY_NODE_STATES,
    extract_field_with_fallbacks,
)
from app.api.storage_clients.http import MAX_RESPONSE_LOG_LENGTH
from app.api.storage_clients.runtime import local_session
from app.ssl_utils import get_ssl_verify

logger = logging.getLogger(__name__)

class NetAppStorageGRIDClient(StorageClient):
    """NetApp StorageGRID client - API v4

    Based on: https://webscalegmi.netapp.com/grid/apidocs.html
    """

    def authenticate(self):
        """Authenticate with StorageGRID and obtain API token

        Uses username and password to authenticate and retrieve an API token.
        The token should be saved to the database for future use.

        Returns:
            str: API token if successful, None if authentication fails
        """
        if not self.username or not self.password:
            logger.error(f"Cannot authenticate to StorageGRID {self.ip_address}: username or password not configured")
            return None

        try:
            ssl_verify = get_ssl_verify(self.resolved_address)

            auth_data = {
                'username': self.username,
                'password': self.password,
                'cookie': True,
                'csrfToken': False
            }

            logger.debug(f"Authenticating to StorageGRID {self.ip_address}")

            response = local_session().post(
                f"{self.base_url}/api/v4/authorize",
                json=auth_data,
                headers={'Content-Type': 'application/json'},
                verify=ssl_verify,
                timeout=10
            )

            if response.status_code == 200:
                auth_response = response.json()
                token = auth_response.get('data')

                if token:
                    logger.debug(f"Successfully obtained API token for StorageGRID {self.ip_address}")
                    return token
                else:
                    logger.error(f"Authentication response did not contain token data: {auth_response}")
                    return None
            else:
                logger.error(f"StorageGRID authentication failed for {self.ip_address}: HTTP {response.status_code}")
                try:
                    logger.error(f"Response: {response.text[:MAX_RESPONSE_LOG_LENGTH]}")
                except Exception:
                    pass
                return None

        except Exception as e:
            logger.error(f"Error authenticating to StorageGRID {self.ip_address}: {e}")
            logger.error(traceback.format_exc())
            return None

    def get_health_status(self):
        try:
            # StorageGRID REST API v4
            # If no token is configured, try to authenticate automatically
            new_token_generated = False
            if not self.token:
                logger.debug(f"Attempting automatic authentication for StorageGRID {self.ip_address}")
                self.token = self.authenticate()
                if self.token:
                    new_token_generated = True
                else:
                    return self._format_response(status='error', hardware='error', cluster='error',
                                                error='Authentication failed. Please check credentials.')

            headers = {
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            ssl_verify = get_ssl_verify(self.resolved_address)

            # Get grid health to verify connectivity
            # API: GET /api/v4/grid/health
            # This endpoint returns counts of alarms, alerts, and nodes - no general health field exists
            hardware_status = 'ok'
            cluster_status = 'ok'
            try:
                health_response = local_session().get(
                    f"{self.base_url}/api/v4/grid/health",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )

                if health_response.status_code == 200:
                    health_data = health_response.json()
                    data = health_data.get('data', {})

                    # Parse grid health statistics for reference
                    # The actual health status will be determined from alerts and node health
                    alarms = data.get('alarms', {})
                    grid_alerts = data.get('alerts', {})
                    nodes = data.get('nodes', {})

                    logger.debug(f"StorageGRID health stats for {self.ip_address}: "
                               f"Alarms(critical={alarms.get('critical', 0)}, major={alarms.get('major', 0)}), "
                               f"Alerts(critical={grid_alerts.get('critical', 0)}, major={grid_alerts.get('major', 0)}), "
                               f"Nodes(connected={nodes.get('connected', 0)}, unknown={nodes.get('unknown', 0)})")
            except Exception as health_error:
                logger.warning(f"Could not get StorageGRID health for {self.ip_address}: {health_error}")

            # Get grid topology to verify connectivity and get version info
            response = local_session().get(
                f"{self.base_url}/api/v4/grid/health/topology",
                headers=headers,
                verify=ssl_verify,
                timeout=10
            )

            if response.status_code != 200:
                error_msg = f'API error: {response.status_code}'
                if response.status_code == 401:
                    # Token invalid - try to re-authenticate once
                    logger.debug(f"Re-authenticating to StorageGRID {self.ip_address}")

                    new_token = self.authenticate()
                    if new_token:
                        self.token = new_token
                        new_token_generated = True

                        # Retry the request with new token
                        headers['Authorization'] = f'Bearer {self.token}'
                        response = local_session().get(
                            f"{self.base_url}/api/v4/grid/health/topology",
                            headers=headers,
                            verify=ssl_verify,
                            timeout=10
                        )

                        if response.status_code != 200:
                            error_msg = f'API error: {response.status_code}'
                            logger.error(f"StorageGRID API error for {self.ip_address}: HTTP {response.status_code}")
                            return self._format_response(status='error', hardware='error', cluster='error', error=error_msg)
                    else:
                        error_msg = 'API error: 401 - Authentication failed. Please check credentials.'
                        logger.error(f"StorageGRID authentication failed for {self.ip_address}")
                        return self._format_response(status='error', hardware='error', cluster='error', error=error_msg)
                else:
                    logger.error(f"StorageGRID API error for {self.ip_address}: HTTP {response.status_code}")
                    try:
                        logger.error(f"Response text: {response.text[:MAX_RESPONSE_LOG_LENGTH]}")
                    except Exception:
                        logger.error("Response text unavailable")
                    return self._format_response(status='error', hardware='error', cluster='error', error=error_msg)

            # Get product version from grid config
            os_version = None
            try:
                version_response = local_session().get(
                    f"{self.base_url}/api/v4/grid/config/product-version",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )

                if version_response.status_code == 200:
                    version_data = version_response.json()
                    os_version = extract_field_with_fallbacks(version_data, ['data.productVersion', 'productVersion'])
            except Exception as version_error:
                logger.warning(f"Could not get StorageGRID version for {self.ip_address}: {version_error}")

            # Get alerts count and severity
            # API: GET /api/v4/grid/alerts?include=active
            # Schema reference: grid-combined-schema.yml – "alert" definition
            # Severity is nested under alert.labels.severity (not a top-level field)
            alerts_count = 0
            critical_alerts = 0
            major_alerts = 0
            minor_alerts = 0
            alert_details = []
            try:
                alerts_response = local_session().get(
                    f"{self.base_url}/api/v4/grid/alerts",
                    headers=headers,
                    params={'include': 'active'},
                    verify=ssl_verify,
                    timeout=10
                )

                if alerts_response.status_code == 200:
                    alerts_data = alerts_response.json()
                    alerts_list = alerts_data.get('data', [])
                    # API returns only active alerts with include=active parameter
                    alerts_count = len(alerts_list)

                    # Count alerts by severity to determine health status.
                    # Per the API schema, severity lives inside alert.labels.severity
                    for alert in alerts_list:
                        labels = alert.get('labels', {})
                        severity = labels.get('severity', '').lower()
                        if severity == 'critical':
                            critical_alerts += 1
                        elif severity == 'major':
                            major_alerts += 1
                        elif severity == 'minor':
                            minor_alerts += 1

                        annotations = alert.get('annotations', {})
                        alert_details.append({
                            'id': str(alert.get('id', '-')),
                            'title': alert.get('name', '-'),
                            'details': annotations.get('description', annotations.get('summary', '-')),
                            'severity': severity or 'unknown',
                            'error_code': '-',
                            'timestamp': alert.get('startsAt', '-'),
                            'component': labels.get('instance', '-'),
                        })

                    # Determine hardware status based on alert severity
                    if critical_alerts > 0:
                        hardware_status = 'error'
                        logger.warning(f"Found {critical_alerts} critical alerts for StorageGRID {self.ip_address}")
                    elif major_alerts > 0:
                        hardware_status = 'warning'
                        logger.warning(f"Found {major_alerts} major alerts for StorageGRID {self.ip_address}")

                    # Log alert summary (always shown for visibility)
                    if alerts_count > 0:
                        logger.info(f"Total active alerts for StorageGRID {self.ip_address}: {alerts_count} "
                                  f"(critical={critical_alerts}, major={major_alerts}, minor={minor_alerts})")
            except Exception as alerts_error:
                logger.warning(f"Could not get StorageGRID alerts for {self.ip_address}: {alerts_error}")

            # Get node health information
            # API: GET /api/v4/grid/node-health
            nodes_info = []
            site_names = set()  # Track unique site names
            try:
                node_health_response = local_session().get(
                    f"{self.base_url}/api/v4/grid/node-health",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )

                if node_health_response.status_code == 200:
                    node_health_data = node_health_response.json()
                    nodes_list = node_health_data.get('data', [])

                    for node in nodes_list:
                        node_id = node.get('id', '')
                        node_name = node.get('name', 'Unknown')
                        node_state = node.get('state', 'unknown')
                        node_severity = node.get('severity', 'normal')
                        node_type = node.get('type', 'unknown')
                        site_name = node.get('siteName')
                        site_id = node.get('siteId')

                        # Track unique site names for multi-site detection
                        if site_name:
                            site_names.add(site_name)

                        node_info = {
                            'name': node_name,
                            'id': node_id,
                            'type': node_type,
                            'status': node_state,
                            'severity': node_severity
                        }

                        # Add site information if available
                        if site_name:
                            node_info['site'] = site_name
                        if site_id:
                            node_info['site_id'] = site_id

                        # Check node health based on state and severity
                        # State should be 'connected' and severity should be 'normal' for healthy nodes
                        if node_state and node_state.lower() not in STORAGEGRID_HEALTHY_NODE_STATES:
                            hardware_status = 'warning'
                            logger.warning(f"StorageGRID node {node_name} unhealthy state: {node_state}")

                        # Check node severity - anything other than 'normal' indicates an issue
                        if node_severity and node_severity.lower() != 'normal':
                            severity_level = node_severity.lower()
                            if severity_level == 'critical':
                                hardware_status = 'error'
                                logger.warning(f"StorageGRID node {node_name} critical severity: {node_severity}")
                            elif severity_level in ['major', 'minor']:
                                # Only escalate to warning if not already error
                                if hardware_status != 'error':
                                    hardware_status = 'warning'
                                logger.warning(f"StorageGRID node {node_name} {severity_level} severity: {node_severity}")

                        nodes_info.append(node_info)

                    logger.info(f"Found {len(nodes_info)} nodes in StorageGRID {self.ip_address}")
            except Exception as node_health_error:
                logger.warning(f"Could not get StorageGRID node health for {self.ip_address}: {node_health_error}")

            # Determine site count from node siteNames
            # Multi-site detection: if nodes have different siteNames, it's multi-site.
            # This is the fallback path; the expansion/sites API (below) may supersede
            # this with the authoritative site list when it is available.
            site_count = len(site_names) if site_names else 1
            sites_info = []

            if len(site_names) > 1:
                logger.info(f"Multi-site detected from node siteNames: {site_count} unique sites ({', '.join(site_names)})")
                # Create sites_info from unique site names
                for site_name in site_names:
                    sites_info.append({'name': site_name})
            elif len(site_names) == 1:
                logger.info(f"Single-site installation: {list(site_names)[0]}")
            else:
                logger.debug("No site information available from nodes")

            # Try the explicit site list from the expansion/sites API.
            # GET /api/v4/grid/expansion/sites provides the authoritative list of grid
            # sites with their names and IDs, as defined in grid-combined-schema.yml.
            # When available this supersedes the siteNames derived from node-health
            # because it correctly enumerates sites even if no nodes are currently online.
            try:
                sites_api_resp = local_session().get(
                    f"{self.base_url}/api/v4/grid/expansion/sites",
                    headers=headers,
                    verify=ssl_verify,
                    timeout=10
                )
                if sites_api_resp.status_code == 200:
                    sites_api_data = sites_api_resp.json().get('data', []) or []
                    if isinstance(sites_api_data, list) and sites_api_data:
                        explicit_sites = [
                            {'name': s.get('name'), 'id': s.get('id')}
                            for s in sites_api_data
                            if isinstance(s, dict) and s.get('name')
                        ]
                        if explicit_sites:
                            sites_info = explicit_sites
                            site_count = len(explicit_sites)
                            logger.info(
                                f"StorageGRID {self.ip_address}: {site_count} site(s) "
                                f"from expansion/sites API: "
                                f"{', '.join(s['name'] for s in explicit_sites)}"
                            )
            except Exception as sites_api_err:
                logger.debug(
                    f"Could not get StorageGRID expansion/sites for {self.ip_address}: "
                    f"{sites_api_err}"
                )

            # Get capacity info using metric-query API
            # StorageGRID uses Prometheus-style metrics
            total_bytes = 0
            used_bytes = 0

            try:
                # Query total space metric
                # API: GET /api/v4/grid/metric-query?query=storagegrid_storage_utilization_total_space_bytes
                total_metric_response = local_session().get(
                    f"{self.base_url}/api/v4/grid/metric-query",
                    headers=headers,
                    params={
                        'query': 'storagegrid_storage_utilization_total_space_bytes',
                        'timeout': '30s'
                    },
                    verify=ssl_verify,
                    timeout=35  # Allow enough time for the API-level timeout (30s) plus network overhead
                )

                if total_metric_response.status_code == 200:
                    total_metric_data = total_metric_response.json()

                    # Parse metric query response
                    # Response format: {"data": {"resultType": "vector", "result": [{"metric": {...}, "value": [timestamp, "value"]}]}}
                    data = total_metric_data.get('data', {})
                    results = data.get('result', [])

                    # Sum up total space from all storage nodes
                    for result in results:
                        value_array = result.get('value', [])
                        if len(value_array) >= 2:
                            # value is [timestamp, "bytes_value"]
                            try:
                                node_total = int(value_array[1])
                                total_bytes += node_total
                            except (ValueError, TypeError) as e:
                                # Include node identifier for easier debugging
                                metric_info = result.get('metric', {})
                                node_id = metric_info.get('instance', metric_info.get('node_id', 'unknown'))
                                logger.debug(f"Could not parse total space value for node {node_id}: {value_array[1]}, error: {e}")

                    logger.info(f"StorageGRID total capacity from {len(results)} nodes: {total_bytes} bytes")

                # Query used data metric
                # API: GET /api/v4/grid/metric-query?query=storagegrid_storage_utilization_data_bytes
                used_metric_response = local_session().get(
                    f"{self.base_url}/api/v4/grid/metric-query",
                    headers=headers,
                    params={
                        'query': 'storagegrid_storage_utilization_data_bytes',
                        'timeout': '30s'
                    },
                    verify=ssl_verify,
                    timeout=35  # Allow enough time for the API-level timeout (30s) plus network overhead
                )

                if used_metric_response.status_code == 200:
                    used_metric_data = used_metric_response.json()

                    # Parse metric query response
                    data = used_metric_data.get('data', {})
                    results = data.get('result', [])

                    # Sum up used space from all storage nodes
                    for result in results:
                        value_array = result.get('value', [])
                        if len(value_array) >= 2:
                            # value is [timestamp, "bytes_value"]
                            try:
                                node_used = int(value_array[1])
                                used_bytes += node_used
                            except (ValueError, TypeError) as e:
                                # Include node identifier for easier debugging
                                metric_info = result.get('metric', {})
                                node_id = metric_info.get('instance', metric_info.get('node_id', 'unknown'))
                                logger.debug(f"Could not parse used space value for node {node_id}: {value_array[1]}, error: {e}")

                    logger.info(f"StorageGRID used capacity from {len(results)} nodes: {used_bytes} bytes")

            except Exception as usage_error:
                # Log but don't fail if we can't get capacity
                logger.warning(f"Could not get StorageGRID storage metrics: {usage_error}")

            # Convert bytes to TB (1 TB = 1024^4 bytes)
            total_tb = total_bytes / (1024**4) if total_bytes > 0 else 0.0
            used_tb = used_bytes / (1024**4) if used_bytes > 0 else 0.0

            return self._format_response(
                status='online',
                hardware=hardware_status,
                cluster=cluster_status,
                alerts=alerts_count,
                total_tb=total_tb,
                used_tb=used_tb,
                os_version=os_version,
                controllers=nodes_info if nodes_info else None,
                site_count=site_count,
                sites_info=sites_info if sites_info else None,
                new_api_token=self.token if new_token_generated else None,
                alert_details=alert_details if alert_details else None
            )
        except Exception as e:
            logger.error(f"Error getting StorageGRID health status for {self.ip_address}: {e}")
            logger.error(traceback.format_exc())
            return self._format_response(status='error', hardware='error', cluster='error', error=str(e))

