"""Tests for NetApp ONTAP REST status-based alert collection.

Verifies that ``NetAppONTAPClient._get_rest_status_alerts()`` and the integration
in ``get_health_status()`` detect problems from eight REST status endpoints:

1. Cluster health         – /api/cluster?fields=health
2. Node state / health   – /api/cluster/nodes?fields=name,state,health,ha
3. Cluster peers         – /api/cluster/peers
4. Network LIF state     – /api/network/ip/interfaces
5. Ethernet port state   – /api/network/ethernet/ports
6. Aggregate state       – /api/storage/aggregates?fields=name,state
7. Disk health           – /api/storage/disks
8. SnapMirror health     – /api/snapmirror/relationships

Uses unittest.mock to simulate ONTAP REST API responses; no real ONTAP system
is required.
"""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest


# ---------------------------------------------------------------------------
# Shared helpers (mirrors test_ontap_ems_alerts.py pattern)
# ---------------------------------------------------------------------------

def _make_response(status_code, body):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    resp.text = json.dumps(body)
    return resp


def _ok(body):
    return _make_response(200, body)


def _404():
    return _make_response(404, {'error': {'message': 'not found'}})


def _503():
    return _make_response(503, {'error': {'message': 'Service Unavailable'}})


# Healthy / empty stubs for endpoints that are not under test
def _cluster_ok():
    return _ok({'name': 'test-cluster',
                'version': {'full': 'NetApp Release 9.14.1', 'generation': 9}})


def _cluster_health_ok():
    return _ok({'name': 'test-cluster', 'health': {'is_healthy': True, 'status': 'ok'}})


def _cluster_health_degraded():
    return _ok({'name': 'test-cluster', 'health': {'is_healthy': False, 'status': 'degraded'}})


def _nodes_hw_ok():
    """Hardware-check response for /api/cluster/nodes (controller fields)."""
    return _ok({'records': [
        {'name': 'node1',
         'controller': {'failed_power_supply': {'count': 0},
                        'failed_fan': {'count': 0},
                        'over_temperature': 'normal'}},
    ]})


def _nodes_state(records):
    """State-check response for /api/cluster/nodes (state/health/ha fields)."""
    return _ok({'records': records})


def _aggregates_capacity():
    return _ok({'records': [
        {'space': {'block_storage': {'size': 10 * 1024 ** 4, 'used': 5 * 1024 ** 4}}}
    ]})


def _aggregates_state(records):
    return _ok({'records': records})


def _peers_ok():
    return _ok({'records': []})


def _peers_with(records):
    return _ok({'records': records})


def _ems_empty():
    return _ok({'records': [], 'num_records': 0})


def _lifs(records):
    return _ok({'records': records})


def _ports(records):
    return _ok({'records': records})


def _disks(records):
    return _ok({'records': records})


def _snapmirror(records):
    return _ok({'records': records})


# ---------------------------------------------------------------------------
# FakeSession – identical logic to test_ontap_ems_alerts.py
# ---------------------------------------------------------------------------

class _FakeSession:
    """Minimal mock for the module-level _local_session in storage_clients."""

    def __init__(self, route_map):
        self._map = route_map
        self._cursors = {}

    def get(self, url, **kwargs):
        for key, val in self._map.items():
            if key in url:
                if isinstance(val, list):
                    idx = self._cursors.get(key, 0)
                    self._cursors[key] = idx + 1
                    return val[idx] if idx < len(val) else val[-1]
                return val
        raise AssertionError(f"Unexpected GET: {url}")

    def post(self, url, **kwargs):
        return _make_response(200, {})


# ---------------------------------------------------------------------------
# Client factory
# ---------------------------------------------------------------------------

def _make_client():
    from app.api.storage_clients import NetAppONTAPClient
    client = NetAppONTAPClient.__new__(NetAppONTAPClient)
    client.ip_address = '10.0.0.1'
    client.port = 443
    client.username = 'admin'
    client.password = 'password'
    client.token = None
    client.resolved_address = '10.0.0.1'
    client.base_url = 'https://10.0.0.1:443'
    return client


# ---------------------------------------------------------------------------
# Full route map for get_health_status() integration tests
# ---------------------------------------------------------------------------

def _full_route_map(overrides=None):
    """Return a default route map where all endpoints return healthy/empty data.

    Pass ``overrides`` dict to replace individual endpoints.  Keys are URL
    substrings; values are response objects or lists of response objects.
    The ``/api/cluster`` key is matched for BOTH the cluster-info call AND
    the cluster-health call; supply a list of two responses to control each.
    """
    base = {
        '/api/cluster/metrocluster':            _404(),
        '/api/cluster/peers':                   _peers_ok(),
        # Two sequential calls to /api/cluster/nodes:
        #   [0] hardware check (controller fields)
        #   [1] cluster nodes info (uuid/name/state/model/…)
        #   [2] REST status check (name/state/health/ha) – reuses last
        '/api/cluster/nodes':                   [_nodes_hw_ok(), _nodes_hw_ok(), _nodes_hw_ok()],
        '/api/storage/aggregates':              [_aggregates_capacity(), _aggregates_state([])],
        '/api/cluster':                         _cluster_ok(),
        '/api/support/ems/events':              [_ems_empty(), _ems_empty()],
        '/api/network/ip/interfaces':           _lifs([]),
        '/api/network/ethernet/ports':          _ports([]),
        '/api/storage/disks':                   _disks([]),
        '/api/snapmirror/relationships':        _snapmirror([]),
    }
    if overrides:
        base.update(overrides)
    return base


def _run(overrides=None):
    """Run get_health_status() with a controlled route map."""
    client = _make_client()
    fake_session = _FakeSession(_full_route_map(overrides))
    import app.api.storage_clients as sc
    with patch.object(sc, '_local_session', fake_session):
        with patch('app.ssl_utils.get_ssl_verify', return_value=False):
            return client.get_health_status()


def _run_rest_only(route_map):
    """Call _get_rest_status_alerts() directly (unit test helper)."""
    client = _make_client()
    fake_session = _FakeSession(route_map)
    auth = ('admin', 'password')
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    import app.api.storage_clients as sc
    with patch.object(sc, '_local_session', fake_session):
        return client._get_rest_status_alerts('test-cluster', auth, headers, False)


# ===========================================================================
# Tests for _make_rest_alert helper
# ===========================================================================

class TestMakeRestAlert:
    def test_required_fields_present(self):
        from app.api.storage_clients import _make_rest_alert
        a = _make_rest_alert('storage', 'disk0', 'critical', 'Disk failed', '/api/storage/disks')
        assert a['category']   == 'storage'
        assert a['component']  == 'disk0'
        assert a['severity']   == 'critical'
        assert a['details']    == 'Disk failed'
        assert a['source']     == '/api/storage/disks'
        assert a['vendor']     == 'netapp'
        assert a['platform']   == 'ontap'

    def test_id_derived_from_resource(self):
        from app.api.storage_clients import _make_rest_alert
        a = _make_rest_alert('network', 'node1:e0c', 'warning', 'Port down', '/api/network/ethernet/ports')
        assert 'node1' in a['id']

    def test_timestamp_defaults_to_now(self):
        from app.api.storage_clients import _make_rest_alert
        before = datetime.now(timezone.utc).isoformat()
        a = _make_rest_alert('cluster', 'mycluster', 'error', 'Health degraded', '/api/cluster')
        after = datetime.now(timezone.utc).isoformat()
        assert before <= a['timestamp'] <= after

    def test_custom_timestamp_preserved(self):
        from app.api.storage_clients import _make_rest_alert
        ts = '2026-01-15T10:00:00+00:00'
        a = _make_rest_alert('node', 'node1', 'warning', 'HA issue', '/api/cluster/nodes', timestamp=ts)
        assert a['timestamp'] == ts

    def test_title_contains_category_and_resource(self):
        from app.api.storage_clients import _make_rest_alert
        a = _make_rest_alert('replication', 'svm1:vol1 → svm2:vol1', 'warning', 'Unhealthy', '/api/snapmirror/relationships')
        assert 'replication' in a['title'].lower() or 'Replication' in a['title']
        assert 'svm1' in a['title']


# ===========================================================================
# Unit tests for _get_rest_status_alerts()
# ===========================================================================

class TestClusterHealthCheck:
    def test_healthy_cluster_no_alert(self):
        alerts = _run_rest_only({'/api/cluster': _cluster_health_ok()})
        cluster_alerts = [a for a in alerts if a['category'] == 'cluster'
                          and 'health' in a['details'].lower()]
        assert cluster_alerts == []

    def test_degraded_cluster_generates_alert(self):
        alerts = _run_rest_only({'/api/cluster': _cluster_health_degraded()})
        cluster_alerts = [a for a in alerts if a['category'] == 'cluster'
                          and 'health' in a['details'].lower()]
        assert len(cluster_alerts) == 1
        assert cluster_alerts[0]['severity'] == 'error'
        assert 'degraded' in cluster_alerts[0]['details'].lower()

    def test_non200_cluster_health_no_crash(self):
        alerts = _run_rest_only({'/api/cluster': _503()})
        # No crash; also no cluster health alert
        assert all(a.get('source') != '/api/cluster' for a in alerts)


class TestNodeStateCheck:
    def test_node_up_no_alert(self):
        alerts = _run_rest_only({'/api/cluster/nodes': _nodes_state([
            {'name': 'node1', 'state': 'up'}
        ])})
        node_alerts = [a for a in alerts if 'node1' in a.get('component', '')]
        assert node_alerts == []

    def test_node_down_generates_critical_alert(self):
        alerts = _run_rest_only({'/api/cluster/nodes': _nodes_state([
            {'name': 'node1', 'state': 'down'}
        ])})
        node_alerts = [a for a in alerts if 'node1' in a.get('component', '')]
        assert any(a['severity'] == 'critical' and 'down' in a['details'].lower()
                   for a in node_alerts)

    def test_node_health_unhealthy_generates_error_alert(self):
        alerts = _run_rest_only({'/api/cluster/nodes': _nodes_state([
            {'name': 'node1', 'state': 'up', 'health': {'is_healthy': False}}
        ])})
        health_alerts = [a for a in alerts if 'health' in a.get('component', '')]
        assert len(health_alerts) == 1
        assert health_alerts[0]['severity'] == 'error'

    def test_node_ha_giveback_in_progress_generates_warning(self):
        alerts = _run_rest_only({'/api/cluster/nodes': _nodes_state([
            {'name': 'node1', 'state': 'up',
             'ha': {'giveback': {'state': 'in_progress'}}}
        ])})
        ha_alerts = [a for a in alerts if 'ha.giveback' in a.get('component', '')]
        assert len(ha_alerts) == 1
        assert ha_alerts[0]['severity'] == 'warning'

    def test_node_ha_nothing_to_giveback_no_alert(self):
        alerts = _run_rest_only({'/api/cluster/nodes': _nodes_state([
            {'name': 'node1', 'state': 'up',
             'ha': {'giveback': {'state': 'nothing_to_giveback'}}}
        ])})
        ha_alerts = [a for a in alerts if 'ha.giveback' in a.get('component', '')]
        assert ha_alerts == []

    def test_multiple_nodes_mixed_state(self):
        alerts = _run_rest_only({'/api/cluster/nodes': _nodes_state([
            {'name': 'node1', 'state': 'up'},
            {'name': 'node2', 'state': 'down'},
        ])})
        node2_alerts = [a for a in alerts if 'node2' in a.get('component', '')]
        node1_alerts = [a for a in alerts if a.get('component') == 'node1']
        assert any(a['severity'] == 'critical' for a in node2_alerts)
        assert node1_alerts == []


class TestClusterPeerCheck:
    def test_available_peer_no_alert(self):
        alerts = _run_rest_only({'/api/cluster/peers': _peers_with([
            {'name': 'peer-cluster', 'availability': 'available'}
        ])})
        peer_alerts = [a for a in alerts if 'peer' in a.get('component', '')]
        assert peer_alerts == []

    def test_unavailable_peer_generates_error_alert(self):
        alerts = _run_rest_only({'/api/cluster/peers': _peers_with([
            {'name': 'peer-cluster', 'availability': 'unavailable'}
        ])})
        peer_alerts = [a for a in alerts if 'peer' in a.get('component', '')]
        assert len(peer_alerts) == 1
        assert peer_alerts[0]['severity'] == 'error'
        assert 'peer-cluster' in peer_alerts[0]['details']

    def test_no_peers_no_alert(self):
        alerts = _run_rest_only({'/api/cluster/peers': _peers_ok()})
        peer_alerts = [a for a in alerts if a.get('source') == '/api/cluster/peers']
        assert peer_alerts == []


class TestNetworkLifCheck:
    def test_lif_up_no_alert(self):
        alerts = _run_rest_only({'/api/network/ip/interfaces': _lifs([
            {'name': 'lif1', 'state': 'up', 'svm': {'name': 'svm1'}}
        ])})
        lif_alerts = [a for a in alerts if a.get('source') == '/api/network/ip/interfaces']
        assert lif_alerts == []

    def test_lif_down_generates_warning(self):
        alerts = _run_rest_only({'/api/network/ip/interfaces': _lifs([
            {'name': 'lif1', 'state': 'down', 'svm': {'name': 'svm1'}}
        ])})
        lif_alerts = [a for a in alerts if a.get('source') == '/api/network/ip/interfaces']
        assert len(lif_alerts) == 1
        assert lif_alerts[0]['severity'] == 'warning'
        assert 'svm1:lif1' in lif_alerts[0]['component']

    def test_lif_resource_includes_svm(self):
        alerts = _run_rest_only({'/api/network/ip/interfaces': _lifs([
            {'name': 'data_lif', 'state': 'down', 'svm': {'name': 'data_svm'}}
        ])})
        lif_alerts = [a for a in alerts if a.get('source') == '/api/network/ip/interfaces']
        assert lif_alerts[0]['component'] == 'data_svm:data_lif'

    def test_non200_lif_no_crash(self):
        alerts = _run_rest_only({'/api/network/ip/interfaces': _503()})
        lif_alerts = [a for a in alerts if a.get('source') == '/api/network/ip/interfaces']
        assert lif_alerts == []

    def test_mc_vserver_lif_down_no_alert(self):
        # LIFs on MetroCluster destination vservers (SVM name ends with "-mc")
        # are intentionally down; they must not generate alerts.
        alerts = _run_rest_only({'/api/network/ip/interfaces': _lifs([
            {'name': 'ogs01_3481', 'state': 'down', 'svm': {'name': 'ogs01-mc'}}
        ])})
        lif_alerts = [a for a in alerts if a.get('source') == '/api/network/ip/interfaces']
        assert lif_alerts == []

    def test_mc_vserver_lif_up_no_alert(self):
        # Even an "up" LIF on a -mc vserver should produce no alert (state is fine).
        alerts = _run_rest_only({'/api/network/ip/interfaces': _lifs([
            {'name': 'ogs01_3481', 'state': 'up', 'svm': {'name': 'ogs01-mc'}}
        ])})
        lif_alerts = [a for a in alerts if a.get('source') == '/api/network/ip/interfaces']
        assert lif_alerts == []

    def test_non_mc_vserver_lif_down_still_alerts(self):
        # LIFs on regular (non-MetroCluster-destination) vservers must still alert.
        alerts = _run_rest_only({'/api/network/ip/interfaces': _lifs([
            {'name': 'data_lif', 'state': 'down', 'svm': {'name': 'ogs01'}}
        ])})
        lif_alerts = [a for a in alerts if a.get('source') == '/api/network/ip/interfaces']
        assert len(lif_alerts) == 1

    def test_mixed_mc_and_regular_lifs(self):
        # Only the regular-vserver down LIF should alert; the -mc one should not.
        alerts = _run_rest_only({'/api/network/ip/interfaces': _lifs([
            {'name': 'mc_lif',   'state': 'down', 'svm': {'name': 'svm1-mc'}},
            {'name': 'data_lif', 'state': 'down', 'svm': {'name': 'svm1'}},
        ])})
        lif_alerts = [a for a in alerts if a.get('source') == '/api/network/ip/interfaces']
        assert len(lif_alerts) == 1
        assert 'svm1:data_lif' in lif_alerts[0]['component']


class TestEthernetPortCheck:
    def test_port_up_no_alert(self):
        alerts = _run_rest_only({'/api/network/ethernet/ports': _ports([
            {'name': 'e0c', 'node': {'name': 'node1'}, 'state': 'up', 'type': 'physical'}
        ])})
        port_alerts = [a for a in alerts if a.get('source') == '/api/network/ethernet/ports']
        assert port_alerts == []

    def test_port_down_generates_warning(self):
        alerts = _run_rest_only({'/api/network/ethernet/ports': _ports([
            {'name': 'e0c', 'node': {'name': 'node1'}, 'state': 'down', 'type': 'physical'}
        ])})
        port_alerts = [a for a in alerts if a.get('source') == '/api/network/ethernet/ports']
        assert len(port_alerts) == 1
        assert port_alerts[0]['severity'] == 'warning'
        assert 'node1:e0c' in port_alerts[0]['component']

    def test_vlan_port_skipped(self):
        alerts = _run_rest_only({'/api/network/ethernet/ports': _ports([
            {'name': 'e0c-100', 'node': {'name': 'node1'}, 'state': 'down', 'type': 'vlan'}
        ])})
        port_alerts = [a for a in alerts if a.get('source') == '/api/network/ethernet/ports']
        assert port_alerts == []

    def test_resource_includes_node(self):
        alerts = _run_rest_only({'/api/network/ethernet/ports': _ports([
            {'name': 'e0d', 'node': {'name': 'node2'}, 'state': 'down', 'type': 'physical'}
        ])})
        port_alerts = [a for a in alerts if a.get('source') == '/api/network/ethernet/ports']
        assert port_alerts[0]['component'] == 'node2:e0d'


class TestAggregateStateCheck:
    def test_online_aggregate_no_alert(self):
        alerts = _run_rest_only({'/api/storage/aggregates': _aggregates_state([
            {'name': 'aggr1', 'state': 'online'}
        ])})
        aggr_alerts = [a for a in alerts if a.get('source') == '/api/storage/aggregates']
        assert aggr_alerts == []

    def test_offline_aggregate_generates_critical_alert(self):
        alerts = _run_rest_only({'/api/storage/aggregates': _aggregates_state([
            {'name': 'aggr1', 'state': 'offline'}
        ])})
        aggr_alerts = [a for a in alerts if a.get('source') == '/api/storage/aggregates']
        assert len(aggr_alerts) == 1
        assert aggr_alerts[0]['severity'] == 'critical'
        assert 'aggr1' in aggr_alerts[0]['details']

    def test_degraded_aggregate_generates_alert(self):
        alerts = _run_rest_only({'/api/storage/aggregates': _aggregates_state([
            {'name': 'aggr2', 'state': 'degraded'}
        ])})
        aggr_alerts = [a for a in alerts if a.get('source') == '/api/storage/aggregates']
        assert len(aggr_alerts) == 1


class TestDiskHealthCheck:
    def test_healthy_disk_no_alert(self):
        alerts = _run_rest_only({'/api/storage/disks': _disks([
            {'name': '1.0.0', 'state': 'present', 'raid_state': 'normal'}
        ])})
        disk_alerts = [a for a in alerts if a.get('source') == '/api/storage/disks']
        assert disk_alerts == []

    def test_broken_disk_generates_critical_alert(self):
        alerts = _run_rest_only({'/api/storage/disks': _disks([
            {'name': '1.0.1', 'state': 'broken', 'raid_state': 'broken'}
        ])})
        disk_alerts = [a for a in alerts if a.get('source') == '/api/storage/disks']
        assert len(disk_alerts) == 1
        assert disk_alerts[0]['severity'] == 'critical'
        assert '1.0.1' in disk_alerts[0]['component']

    def test_failed_raid_state_generates_critical_alert(self):
        alerts = _run_rest_only({'/api/storage/disks': _disks([
            {'name': '1.0.2', 'state': 'present', 'raid_state': 'failed'}
        ])})
        disk_alerts = [a for a in alerts if a.get('source') == '/api/storage/disks']
        assert len(disk_alerts) == 1
        assert disk_alerts[0]['severity'] == 'critical'

    def test_multiple_disks_only_broken_reported(self):
        alerts = _run_rest_only({'/api/storage/disks': _disks([
            {'name': '1.0.0', 'state': 'present', 'raid_state': 'normal'},
            {'name': '1.0.1', 'state': 'broken',  'raid_state': 'broken'},
            {'name': '1.0.2', 'state': 'present', 'raid_state': 'normal'},
        ])})
        disk_alerts = [a for a in alerts if a.get('source') == '/api/storage/disks']
        assert len(disk_alerts) == 1
        assert '1.0.1' in disk_alerts[0]['component']


class TestSnapMirrorCheck:
    def test_healthy_relationship_no_alert(self):
        alerts = _run_rest_only({'/api/snapmirror/relationships': _snapmirror([
            {'healthy': True, 'source': {'svm': {'name': 's'}, 'path': 'vol1'},
             'destination': {'svm': {'name': 'd'}, 'path': 'vol1'}}
        ])})
        sm_alerts = [a for a in alerts if a.get('source') == '/api/snapmirror/relationships']
        assert sm_alerts == []

    def test_unhealthy_relationship_generates_warning(self):
        alerts = _run_rest_only({'/api/snapmirror/relationships': _snapmirror([
            {'healthy': False,
             'unhealthy_reason': [{'message': 'Transfer in error state'}],
             'source': {'svm': {'name': 'src_svm'}, 'path': 'vol_src'},
             'destination': {'svm': {'name': 'dst_svm'}, 'path': 'vol_dst'}}
        ])})
        sm_alerts = [a for a in alerts if a.get('source') == '/api/snapmirror/relationships']
        assert len(sm_alerts) == 1
        assert sm_alerts[0]['severity'] == 'warning'
        assert 'Transfer in error state' in sm_alerts[0]['details']

    def test_multiple_relationships_only_unhealthy_reported(self):
        alerts = _run_rest_only({'/api/snapmirror/relationships': _snapmirror([
            {'healthy': True,  'source': {'svm': {'name': 's'}, 'path': 'v1'},
             'destination': {'svm': {'name': 'd'}, 'path': 'v1'}},
            {'healthy': False, 'unhealthy_reason': [],
             'source': {'svm': {'name': 's'}, 'path': 'v2'},
             'destination': {'svm': {'name': 'd'}, 'path': 'v2'}},
        ])})
        sm_alerts = [a for a in alerts if a.get('source') == '/api/snapmirror/relationships']
        assert len(sm_alerts) == 1

    def test_non200_snapmirror_no_crash(self):
        alerts = _run_rest_only({'/api/snapmirror/relationships': _503()})
        sm_alerts = [a for a in alerts if a.get('source') == '/api/snapmirror/relationships']
        assert sm_alerts == []


# ===========================================================================
# Integration tests: get_health_status() with REST alerts
# ===========================================================================

class TestGetHealthStatusRestIntegration:
    def test_all_healthy_no_rest_alerts(self):
        """All REST endpoints return healthy state → alerts=0."""
        result = _run()
        assert result['status'] == 'online'
        assert result['alerts'] == 0

    def test_broken_disk_raises_alert_count(self):
        result = _run({
            '/api/storage/disks': _disks([
                {'name': '1.0.1', 'state': 'broken', 'raid_state': 'broken'}
            ])
        })
        assert result['alerts'] >= 1
        disk_alerts = [a for a in (result.get('alert_details') or [])
                       if a.get('source') == '/api/storage/disks']
        assert len(disk_alerts) == 1

    def test_broken_disk_escalates_hardware_status(self):
        result = _run({
            '/api/storage/disks': _disks([
                {'name': '1.0.1', 'state': 'broken', 'raid_state': 'broken'}
            ])
        })
        assert result['hardware_status'] in ('warning', 'error')

    def test_node_down_generates_critical_alert_in_result(self):
        result = _run({
            '/api/cluster/nodes': [
                _nodes_hw_ok(),
                _nodes_state([{'name': 'node1', 'state': 'down'}]),
                _nodes_state([{'name': 'node1', 'state': 'down'}]),
            ]
        })
        assert result['alerts'] >= 1
        node_alerts = [a for a in (result.get('alert_details') or [])
                       if a.get('source') == '/api/cluster/nodes']
        assert any(a['severity'] == 'critical' for a in node_alerts)

    def test_rest_alert_has_normalized_fields(self):
        result = _run({
            '/api/storage/disks': _disks([
                {'name': '1.0.1', 'state': 'broken', 'raid_state': 'broken'}
            ])
        })
        disk_alerts = [a for a in (result.get('alert_details') or [])
                       if a.get('source') == '/api/storage/disks']
        assert disk_alerts, "Expected at least one disk alert in alert_details"
        a = disk_alerts[0]
        assert a['vendor']   == 'netapp'
        assert a['platform'] == 'ontap'
        assert a['category'] == 'storage'
        assert a['source']   == '/api/storage/disks'

    def test_unhealthy_snapmirror_adds_replication_alert(self):
        result = _run({
            '/api/snapmirror/relationships': _snapmirror([
                {'healthy': False, 'unhealthy_reason': [],
                 'source':      {'svm': {'name': 'src'}, 'path': 'v1'},
                 'destination': {'svm': {'name': 'dst'}, 'path': 'v1'}}
            ])
        })
        sm_alerts = [a for a in (result.get('alert_details') or [])
                     if a.get('category') == 'replication']
        assert len(sm_alerts) == 1

    def test_offline_aggregate_appears_in_alert_details(self):
        result = _run({
            '/api/storage/aggregates': [
                _aggregates_capacity(),
                _aggregates_state([{'name': 'aggr_bad', 'state': 'offline'}]),
            ]
        })
        aggr_alerts = [a for a in (result.get('alert_details') or [])
                       if a.get('source') == '/api/storage/aggregates']
        assert len(aggr_alerts) == 1
        assert 'aggr_bad' in aggr_alerts[0]['details']

    def test_ems_and_rest_alerts_combined(self):
        """EMS alert + REST disk alert both appear in alert_details."""
        ems_event = {
            'index': 99,
            'message': {'name': 'callhome.spares.low', 'severity': 'error'},
            'log_message': 'Spare capacity low',
            'time': '2026-03-06T08:00:00+00:00',
            'node': {'name': 'node1'},
        }
        result = _run({
            '/api/support/ems/events': [
                _ok({'records': [ems_event], 'num_records': 1}),
                _ok({'records': [], 'num_records': 0}),
            ],
            '/api/storage/disks': _disks([
                {'name': '1.0.1', 'state': 'broken', 'raid_state': 'broken'}
            ])
        })
        assert result['alerts'] == 2
        details = result.get('alert_details', [])
        sources = {a.get('source') for a in details}
        assert None in sources or '/api/support/ems/events' not in sources  # EMS has no 'source'
        disk_alerts = [a for a in details if a.get('source') == '/api/storage/disks']
        assert len(disk_alerts) == 1

    def test_rest_alerts_endpoint_failure_no_crash(self):
        """All REST status endpoints return 503 → no crash, status stays online."""
        result = _run({
            '/api/network/ip/interfaces':    _503(),
            '/api/network/ethernet/ports':   _503(),
            '/api/storage/disks':            _503(),
            '/api/snapmirror/relationships': _503(),
        })
        assert result['status'] == 'online'
        assert result['alerts'] == 0

    def test_no_duplicate_for_ems_covered_component(self):
        """REST alert for a component already in EMS alert_details is deduped."""
        # EMS event for node1, REST node check also reports node1 down
        ems_event = {
            'index': 1,
            'message': {'name': 'cf.fsm.monitor.globalStatus.critical', 'severity': 'alert'},
            'log_message': 'Failover critical',
            'time': '2026-03-01T08:00:00+00:00',
            'node': {'name': 'node1'},
            'parameters': [],
        }
        result = _run({
            '/api/support/ems/events': [
                _ok({'records': [ems_event], 'num_records': 1}),
                _ok({'records': [], 'num_records': 0}),
            ],
            '/api/cluster/nodes': [
                _nodes_hw_ok(),
                _nodes_state([{'name': 'node1', 'state': 'down'}]),
                _nodes_state([{'name': 'node1', 'state': 'down'}]),
            ],
        })
        # EMS component is 'node1'; REST alert component is 'node1' → deduped
        node1_alerts = [a for a in (result.get('alert_details') or [])
                        if a.get('component') == 'node1']
        assert len(node1_alerts) == 1


# ===========================================================================
# Tests for _strip_version_date helper
# ===========================================================================

class TestStripVersionDate:
    """Verify that the date/timestamp is stripped from ONTAP version strings."""

    def _strip(self, s):
        from app.api.storage_clients import _strip_version_date
        return _strip_version_date(s)

    def test_strips_date_from_full_version_string(self):
        result = self._strip('NetApp Release 9.16.1P11: Thu Jan 15 11:21:38 UTC 2026')
        assert result == 'NetApp Release 9.16.1P11'

    def test_version_without_date_unchanged(self):
        result = self._strip('NetApp Release 9.14.1')
        assert result == 'NetApp Release 9.14.1'

    def test_none_returns_none(self):
        assert self._strip(None) is None

    def test_empty_string_returns_empty(self):
        assert self._strip('') == ''

    def test_non_string_returned_as_is(self):
        assert self._strip(9) == 9

    def test_os_version_stripped_in_get_health_status(self):
        """os_version in get_health_status() response must not contain a timestamp."""
        result = _run({
            '/api/cluster': _ok({
                'name': 'test-cluster',
                'version': {
                    'full': 'NetApp Release 9.16.1P11: Thu Jan 15 11:21:38 UTC 2026',
                    'generation': 9,
                },
            }),
        })
        assert result.get('os_version') == 'NetApp Release 9.16.1P11'

    def test_node_version_stripped_in_get_health_status(self):
        """Node version in controllers list must not contain a timestamp."""
        nodes_with_version = _ok({'records': [
            {
                'name': 'node1',
                'uuid': 'uuid-1',
                'state': 'up',
                'model': 'AFF-A400',
                'serial_number': 'SN123',
                'version': {
                    'full': 'NetApp Release 9.16.1P11: Thu Jan 15 11:21:38 UTC 2026',
                },
                'management_interfaces': [],
            }
        ]})
        # Call order for /api/cluster/nodes in get_health_status():
        #   [0] cluster nodes info (uuid/name/state/model/version/…)
        #   [1] hardware check (controller fields)
        #   [2] REST status check (name/state/health/ha)
        result = _run({
            '/api/cluster/nodes': [nodes_with_version, _nodes_hw_ok(), _nodes_hw_ok()],
        })
        controllers = result.get('controllers', [])
        assert controllers, 'Expected at least one controller'
        assert controllers[0].get('version') == 'NetApp Release 9.16.1P11'
