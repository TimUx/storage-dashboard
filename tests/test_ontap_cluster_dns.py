"""Tests for discover_netapp_ontap DNS name behaviour.

Verifies that only the cluster management IP DNS name ends up in
``discovery_data['dns_names']``, not individual node management IP DNS names.

This prevents WebUI links from pointing to per-node hostnames (e.g.
``fasmc1d.storage.example.com``) instead of the cluster hostname
(``fasmc1.storage.example.com``).
"""

import json
import socket
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(status_code, body):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    return resp


def _ok(body):
    return _make_response(200, body)


def _cluster_response():
    return _ok({'name': 'fasmc1', 'version': {'full': 'NetApp Release 9.14.1'}})


def _metrocluster_not_configured():
    return _ok({'local': {'configuration_state': 'not_configured'}})


def _nodes_response():
    return _ok({
        'records': [
            {'name': 'fasmc1d', 'uuid': 'uuid-node1', 'state': 'online',
             'model': 'AFF-A400', 'serial_number': 'SN1', 'version': {'full': '9.14.1'}},
            {'name': 'fasmc1a', 'uuid': 'uuid-node2', 'state': 'online',
             'model': 'AFF-A400', 'serial_number': 'SN2', 'version': {'full': '9.14.1'}},
        ]
    })


def _node_detail_response(node_ip):
    return _ok({
        'management_interfaces': [
            {'ip': {'address': node_ip}}
        ]
    })


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestONTAPClusterDnsNames:
    """Cluster discovery must only store the cluster-level DNS name."""

    def _run_discovery(self, cluster_ip, cluster_dns, node_ips, node_dns_map):
        """
        Run ``discover_netapp_ontap`` with mocked HTTP and DNS lookups.

        :param cluster_ip:   IP used to reach the cluster management interface.
        :param cluster_dns:  DNS name returned by reverse-lookup of cluster_ip.
        :param node_ips:     List of node management IPs (one per node).
        :param node_dns_map: Dict mapping each node IP to its reverse-DNS name.
        """
        from app.discovery import discover_netapp_ontap

        def _fake_reverse_dns(ip):
            if ip == cluster_ip:
                return [cluster_dns]
            return [node_dns_map.get(ip, ip)]

        def _fake_get(url, **kwargs):
            if url.endswith('/api/cluster'):
                return _cluster_response()
            if url.endswith('/api/cluster/metrocluster'):
                return _metrocluster_not_configured()
            if url.endswith('/api/cluster/nodes'):
                return _nodes_response()
            # Per-node detail endpoint
            for idx, node_ip in enumerate(node_ips):
                node_uuid = f'uuid-node{idx + 1}'
                if url.endswith(f'/api/cluster/nodes/{node_uuid}'):
                    return _node_detail_response(node_ip)
            return _make_response(404, {})

        with patch('app.discovery.reverse_dns_lookup', side_effect=_fake_reverse_dns), \
             patch('requests.get', side_effect=_fake_get):
            return discover_netapp_ontap(cluster_ip, 'admin', 'password')

    def test_only_cluster_dns_name_in_dns_names(self):
        """Node management IP DNS names must NOT appear in dns_names."""
        result = self._run_discovery(
            cluster_ip='10.0.0.1',
            cluster_dns='fasmc1.storage.example.com',
            node_ips=['10.0.0.11', '10.0.0.12'],
            node_dns_map={
                '10.0.0.11': 'fasmc1d.storage.example.com',
                '10.0.0.12': 'fasmc1a.storage.example.com',
            }
        )

        assert 'fasmc1.storage.example.com' in result['dns_names'], \
            "Cluster DNS name must be present"
        assert 'fasmc1d.storage.example.com' not in result['dns_names'], \
            "Node DNS name fasmc1d must not be in dns_names"
        assert 'fasmc1a.storage.example.com' not in result['dns_names'], \
            "Node DNS name fasmc1a must not be in dns_names"

    def test_cluster_dns_name_is_first(self):
        """The cluster DNS name must be the first entry so WebUI links work."""
        result = self._run_discovery(
            cluster_ip='10.0.0.1',
            cluster_dns='fasmc1.storage.example.com',
            node_ips=['10.0.0.11', '10.0.0.12'],
            node_dns_map={
                '10.0.0.11': 'fasmc1d.storage.example.com',
                '10.0.0.12': 'fasmc1a.storage.example.com',
            }
        )

        assert result['dns_names'][0] == 'fasmc1.storage.example.com', \
            "Cluster DNS name must be the first entry in dns_names"

    def test_node_ips_still_in_all_ips(self):
        """Node management IPs must still appear in all_ips for other purposes."""
        result = self._run_discovery(
            cluster_ip='10.0.0.1',
            cluster_dns='fasmc1.storage.example.com',
            node_ips=['10.0.0.11', '10.0.0.12'],
            node_dns_map={
                '10.0.0.11': 'fasmc1d.storage.example.com',
                '10.0.0.12': 'fasmc1a.storage.example.com',
            }
        )

        assert '10.0.0.11' in result['all_ips'], "Node IP 10.0.0.11 must be in all_ips"
        assert '10.0.0.12' in result['all_ips'], "Node IP 10.0.0.12 must be in all_ips"


# ---------------------------------------------------------------------------
# Tests for reverse_dns_lookup forward-verification
# ---------------------------------------------------------------------------

class TestReverseDnsLookupForwardVerification:
    """
    reverse_dns_lookup must return only the DNS name(s) that forward-resolve
    back to the queried IP, so that node hostnames appearing as aliases in
    PTR records do not become WebUI link targets.
    """

    def test_only_matching_name_returned(self):
        """
        When PTR lookup returns a hostname + aliases and only one of them
        forward-resolves to the queried IP, only that name is returned.
        """
        from app.discovery import reverse_dns_lookup

        # PTR record for 10.112.230.169 returns a node hostname first, then
        # the real cluster name as an alias.
        with patch('socket.gethostbyaddr',
                   return_value=('fascl1d.storage.example.com',
                                 ['fascl1.storage.example.com', 'fascl1c.storage.example.com'],
                                 ['10.112.230.169'])), \
             patch('socket.gethostbyname',
                   side_effect=lambda name: {
                       'fascl1d.storage.example.com': '10.112.230.221',   # node IP
                       'fascl1.storage.example.com': '10.112.230.169',    # cluster IP ✓
                       'fascl1c.storage.example.com': '10.112.230.223',   # node IP
                   }[name]):
            result = reverse_dns_lookup('10.112.230.169')

        assert result == ['fascl1.storage.example.com'], (
            "Only the DNS name that resolves back to the cluster IP should be returned"
        )

    def test_node_specific_names_excluded(self):
        """Node hostname and other-node alias must not appear in the result."""
        from app.discovery import reverse_dns_lookup

        with patch('socket.gethostbyaddr',
                   return_value=('fascl1d.storage.example.com',
                                 ['fascl1.storage.example.com', 'fascl1c.storage.example.com'],
                                 ['10.112.230.169'])), \
             patch('socket.gethostbyname',
                   side_effect=lambda name: {
                       'fascl1d.storage.example.com': '10.112.230.221',
                       'fascl1.storage.example.com': '10.112.230.169',
                       'fascl1c.storage.example.com': '10.112.230.223',
                   }[name]):
            result = reverse_dns_lookup('10.112.230.169')

        assert 'fascl1d.storage.example.com' not in result, "Node hostname must be excluded"
        assert 'fascl1c.storage.example.com' not in result, "Other node alias must be excluded"

    def test_fallback_when_forward_resolution_fails(self):
        """
        When forward resolution raises for every name, the function falls back
        to returning the raw reverse-lookup names rather than an empty list.
        """
        from app.discovery import reverse_dns_lookup

        with patch('socket.gethostbyaddr',
                   return_value=('cluster.example.com', [], ['10.0.0.1'])), \
             patch('socket.gethostbyname', side_effect=socket.gaierror("no DNS")):
            result = reverse_dns_lookup('10.0.0.1')

        assert result == ['cluster.example.com'], (
            "Should fall back to the reverse-lookup name when forward DNS is unavailable"
        )

    def test_single_name_that_matches_returned_directly(self):
        """Single PTR result that forward-resolves correctly is kept as-is."""
        from app.discovery import reverse_dns_lookup

        with patch('socket.gethostbyaddr',
                   return_value=('cluster.example.com', [], ['10.0.0.1'])), \
             patch('socket.gethostbyname', return_value='10.0.0.1'):
            result = reverse_dns_lookup('10.0.0.1')

        assert result == ['cluster.example.com']
