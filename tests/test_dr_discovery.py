"""Tests for DR relationship discovery functions in dr_vendor modules.

Verifies that discover_relationships() correctly reads the keys that
get_health_status() actually places in the health_data dict.
"""

import pytest


# ---------------------------------------------------------------------------
# Pure FlashArray
# ---------------------------------------------------------------------------

from app.dr_vendor import pure_flasharray_logic


class TestPureFlashArrayDiscovery:
    """Pure FlashArray discover_relationships uses is_active_cluster /
    array_connections / pods_info (not the old 'activecluster' key)."""

    def test_no_active_cluster_returns_empty(self):
        health = {
            'status': 'online',
            'is_active_cluster': False,
            'array_connections': [],
        }
        result = pure_flasharray_logic.discover_relationships('pure01', health)
        assert result == []

    def test_missing_keys_returns_empty(self):
        # Health data with no DR-related keys at all
        result = pure_flasharray_logic.discover_relationships('pure01', {})
        assert result == []

    def test_sync_replication_connection_detected(self):
        health = {
            'status': 'online',
            'is_active_cluster': True,
            'array_connections': [
                {
                    'name': 'pure02',
                    'status': 'connected',
                    'type': 'sync-replication',
                    'management_address': 'pure02',
                    'version': '6.5.10',
                }
            ],
            'pods_info': [],
        }
        result = pure_flasharray_logic.discover_relationships('pure01', health)
        assert len(result) == 1
        rel = result[0]
        assert rel['replication_type'] == 'activecluster'
        assert rel['vendor'] == 'pure'
        assert rel['primary_cluster'] == 'pure01'
        assert rel['secondary_cluster'] == 'pure02'
        assert rel['replication_state'] == 'healthy'

    def test_async_replication_connection_ignored(self):
        health = {
            'status': 'online',
            'is_active_cluster': False,
            'array_connections': [
                {
                    'name': 'pure02',
                    'status': 'connected',
                    'type': 'async-replication',
                }
            ],
        }
        result = pure_flasharray_logic.discover_relationships('pure01', health)
        assert result == []

    def test_partially_connected_connection_is_degraded(self):
        health = {
            'is_active_cluster': True,
            'array_connections': [
                {
                    'name': 'pure02',
                    'status': 'partially_connected',
                    'type': 'sync-replication',
                }
            ],
        }
        result = pure_flasharray_logic.discover_relationships('pure01', health)
        assert len(result) == 1
        assert result[0]['replication_state'] == 'degraded'

    def test_is_active_cluster_without_sync_conn_yields_fallback(self):
        # is_active_cluster=True but no sync-replication connections
        health = {
            'is_active_cluster': True,
            'array_connections': [],
            'pods_info': [{'name': 'pod1', 'arrays': ['pure01', 'pure02']}],
        }
        result = pure_flasharray_logic.discover_relationships('pure01', health)
        assert len(result) == 1
        assert result[0]['replication_type'] == 'activecluster'

    def test_old_activecluster_key_not_used(self):
        # Old key 'activecluster' must NOT trigger discovery
        health = {
            'activecluster': {'mediator_status': 'connected'},
            'pods': [{'name': 'p', 'arrays': [{'name': 'a1'}, {'name': 'a2'}]}],
        }
        result = pure_flasharray_logic.discover_relationships('pure01', health)
        assert result == []


# ---------------------------------------------------------------------------
# ONTAP MetroCluster
# ---------------------------------------------------------------------------

from app.dr_vendor import ontap_metrocluster_logic


class TestONTAPMetroClusterDiscovery:
    """ONTAP MetroCluster discover_relationships uses is_metrocluster /
    metrocluster_info / metrocluster_peers."""

    def test_not_metrocluster_returns_empty(self):
        health = {'status': 'online', 'is_metrocluster': False}
        result = ontap_metrocluster_logic.discover_relationships('FASMC1', health)
        assert result == []

    def test_missing_is_metrocluster_returns_empty(self):
        result = ontap_metrocluster_logic.discover_relationships('FASMC1', {})
        assert result == []

    def test_old_metrocluster_key_not_used(self):
        health = {
            'metrocluster': {'configuration_state': 'configured', 'sites': [{'name': 'A'}, {'name': 'B'}]},
        }
        result = ontap_metrocluster_logic.discover_relationships('FASMC1', health)
        assert result == []

    def test_metrocluster_with_partner_from_info(self):
        health = {
            'is_metrocluster': True,
            'metrocluster_info': {
                'configuration_state': 'configured',
                'configuration_type': 'fabric',
                'local_cluster_name': 'FASMC1',
                'partner_cluster_name': 'FASMC2',
            },
            'metrocluster_peers': [],
        }
        result = ontap_metrocluster_logic.discover_relationships('FASMC1', health)
        assert len(result) == 1
        rel = result[0]
        assert rel['replication_type'] == 'metrocluster'
        assert rel['vendor'] == 'netapp-ontap'
        assert rel['primary_cluster'] == 'FASMC1'
        assert rel['secondary_cluster'] == 'FASMC2'
        assert rel['replication_state'] == 'healthy'

    def test_metrocluster_partner_from_peers_when_info_missing(self):
        health = {
            'is_metrocluster': True,
            'metrocluster_info': {
                'configuration_state': 'configured',
                'local_cluster_name': 'FASMC1',
                'partner_cluster_name': None,
            },
            'metrocluster_peers': [
                {'name': 'FASMC2', 'state': 'available'},
            ],
        }
        result = ontap_metrocluster_logic.discover_relationships('FASMC1', health)
        assert len(result) == 1
        assert result[0]['secondary_cluster'] == 'FASMC2'

    def test_metrocluster_degraded_state(self):
        health = {
            'is_metrocluster': True,
            'metrocluster_info': {
                'configuration_state': 'unknown',
                'local_cluster_name': 'FASMC1',
                'partner_cluster_name': 'FASMC2',
            },
        }
        result = ontap_metrocluster_logic.discover_relationships('FASMC1', health)
        assert result[0]['replication_state'] == 'degraded'

    def test_metrocluster_ip_type_label(self):
        health = {
            'is_metrocluster': True,
            'metrocluster_info': {
                'configuration_state': 'configured',
                'configuration_type': 'ip_fabric',
                'local_cluster_name': 'CL1',
                'partner_cluster_name': 'CL2',
            },
        }
        result = ontap_metrocluster_logic.discover_relationships('CL1', health)
        mc = result[0]['relationship_data']['metrocluster']
        assert 'IP' in mc['configuration_type']



# ---------------------------------------------------------------------------
# ONTAP MetroCluster – disaster_recovery workflow (new tests)
# ---------------------------------------------------------------------------

class TestMetroClusterDisasterRecovery:
    """Tests for the disaster_recovery direction added to ontap_metrocluster_logic."""

    def _make_rel(self, primary='FASMC1', secondary='FASMC2'):
        return {
            'system_name': primary,
            'vendor': 'netapp-ontap',
            'replication_type': 'metrocluster',
            'primary_site': primary,
            'secondary_site': secondary,
            'primary_cluster': primary,
            'secondary_cluster': secondary,
            'replication_state': 'healthy',
            'relationship_data': {
                'metrocluster': {
                    'configuration_state': 'configured',
                    'configuration_type': 'MetroCluster IP',
                    'local_cluster': primary,
                    'partner_cluster': secondary,
                    'peers': [],
                    'nodes': [],
                }
            },
        }

    # ---- workflow steps ----

    def test_disaster_recovery_has_8_steps(self):
        rel = self._make_rel()
        steps = ontap_metrocluster_logic.generate_workflow(rel, 'disaster_recovery')
        assert len(steps) == 8

    def test_disaster_recovery_phases_in_order(self):
        rel = self._make_rel()
        steps = ontap_metrocluster_logic.generate_workflow(rel, 'disaster_recovery')
        phases = [s['phase'] for s in steps]
        assert phases[0] == 'detection'
        assert phases[1] == 'pre-checks'
        assert phases[2] == 'forced-switchover'
        assert phases[3] == 'verification'
        assert 'aggregate-healing' in phases
        assert 'switchback' in phases
        assert phases[-1] == 'final-verification'

    def test_disaster_recovery_step_numbers_sequential(self):
        rel = self._make_rel()
        steps = ontap_metrocluster_logic.generate_workflow(rel, 'disaster_recovery')
        assert [s['step'] for s in steps] == list(range(1, 9))

    # ---- command generation ----

    def test_forced_switchover_command_present(self):
        rel = self._make_rel()
        cmds = ontap_metrocluster_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert 'metrocluster switchover -forced-on-disaster true' in cli_commands

    def test_forced_switchover_not_in_planned_failover(self):
        """Forced switchover must NOT appear in the negotiated planned_failover."""
        rel = self._make_rel()
        cmds = ontap_metrocluster_logic.generate_commands(rel, 'planned_failover')
        cli_commands = [c['cli'] for c in cmds]
        assert 'metrocluster switchover -forced-on-disaster true' not in cli_commands

    def test_forced_switchover_not_in_failback(self):
        """Forced switchover must NOT appear in the failback direction."""
        rel = self._make_rel()
        cmds = ontap_metrocluster_logic.generate_commands(rel, 'failback')
        cli_commands = [c['cli'] for c in cmds]
        assert 'metrocluster switchover -forced-on-disaster true' not in cli_commands

    def test_aggregate_healing_command_present(self):
        rel = self._make_rel()
        cmds = ontap_metrocluster_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert 'metrocluster heal -phase aggregates' in cli_commands

    def test_root_aggregate_healing_command_present(self):
        rel = self._make_rel()
        cmds = ontap_metrocluster_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert 'metrocluster heal -phase root-aggregates' in cli_commands

    def test_aggregate_healing_before_root(self):
        """Data aggregate healing must precede root aggregate healing."""
        rel = self._make_rel()
        cmds = ontap_metrocluster_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        idx_aggr = cli_commands.index('metrocluster heal -phase aggregates')
        idx_root = cli_commands.index('metrocluster heal -phase root-aggregates')
        assert idx_aggr < idx_root

    def test_pre_check_commands_present(self):
        """All four pre-check commands must be present for disaster_recovery."""
        rel = self._make_rel()
        cmds = ontap_metrocluster_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        for expected in ('metrocluster show', 'metrocluster node show',
                         'metrocluster check run', 'metrocluster check show'):
            assert expected in cli_commands, f'{expected!r} not in disaster_recovery commands'

    def test_post_switchover_verification_commands(self):
        """Post-switchover verification requires operation show, show, and node show."""
        rel = self._make_rel()
        cmds = ontap_metrocluster_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        for expected in ('metrocluster operation show', 'metrocluster show',
                         'metrocluster node show'):
            assert expected in cli_commands

    def test_switchback_command_present(self):
        rel = self._make_rel()
        cmds = ontap_metrocluster_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert 'metrocluster switchback' in cli_commands

    def test_disaster_recovery_commands_target_surviving_site(self):
        """All disaster_recovery commands must target the surviving (secondary) cluster."""
        rel = self._make_rel(primary='FASMC1', secondary='FASMC2')
        cmds = ontap_metrocluster_logic.generate_commands(rel, 'disaster_recovery')
        for cmd in cmds:
            assert cmd['target'] == 'FASMC2', (
                f"Command {cmd['cli']!r} targets {cmd['target']!r} instead of surviving site FASMC2"
            )

    def test_planned_failover_commands_target_primary(self):
        """planned_failover commands must target the primary cluster."""
        rel = self._make_rel(primary='FASMC1', secondary='FASMC2')
        cmds = ontap_metrocluster_logic.generate_commands(rel, 'planned_failover')
        for cmd in cmds:
            assert cmd['target'] == 'FASMC1'

    # ---- runbook ----

    def test_runbook_phases_match_workflow(self):
        rel = self._make_rel()
        runbook = ontap_metrocluster_logic.generate_runbook(rel, 'disaster_recovery')
        runbook_phases = {section['phase'] for section in runbook}
        workflow_phases = {s['phase'] for s in ontap_metrocluster_logic.generate_workflow(rel, 'disaster_recovery')}
        assert runbook_phases == workflow_phases

    def test_runbook_forced_switchover_section_has_command(self):
        rel = self._make_rel()
        runbook = ontap_metrocluster_logic.generate_runbook(rel, 'disaster_recovery')
        forced_section = next(s for s in runbook if s['phase'] == 'forced-switchover')
        cli_commands = [c['cli'] for c in forced_section['commands']]
        assert 'metrocluster switchover -forced-on-disaster true' in cli_commands

    def test_runbook_aggregate_healing_section_has_both_commands(self):
        rel = self._make_rel()
        runbook = ontap_metrocluster_logic.generate_runbook(rel, 'disaster_recovery')
        healing_sections = [s for s in runbook if s['phase'] == 'aggregate-healing']
        assert healing_sections, "aggregate-healing section missing from runbook"
        all_cli = [c['cli'] for s in healing_sections for c in s['commands']]
        assert 'metrocluster heal -phase aggregates' in all_cli
        assert 'metrocluster heal -phase root-aggregates' in all_cli

    # ---- workflow diagram ----

    def test_workflow_diagram_is_flowchart(self):
        rel = self._make_rel()
        diagram = ontap_metrocluster_logic.generate_workflow_diagram(rel, 'disaster_recovery')
        assert diagram.startswith('flowchart TD')

    def test_workflow_diagram_contains_all_8_steps(self):
        rel = self._make_rel()
        diagram = ontap_metrocluster_logic.generate_workflow_diagram(rel, 'disaster_recovery')
        for i in range(1, 9):
            assert f'S{i}[' in diagram, f'Step node S{i} missing from disaster_recovery diagram'

    def test_workflow_diagram_steps_connected(self):
        """Each pair of consecutive steps must have an arrow in the diagram."""
        rel = self._make_rel()
        diagram = ontap_metrocluster_logic.generate_workflow_diagram(rel, 'disaster_recovery')
        for i in range(1, 8):
            assert f'S{i} --> S{i+1}' in diagram

    # ---- planned_failover improvements ----

    def test_planned_failover_includes_node_show(self):
        """planned_failover must include metrocluster node show."""
        rel = self._make_rel()
        cmds = ontap_metrocluster_logic.generate_commands(rel, 'planned_failover')
        cli_commands = [c['cli'] for c in cmds]
        assert 'metrocluster node show' in cli_commands

    def test_planned_failover_includes_operation_show(self):
        """planned_failover must include metrocluster operation show post-switchover."""
        rel = self._make_rel()
        cmds = ontap_metrocluster_logic.generate_commands(rel, 'planned_failover')
        cli_commands = [c['cli'] for c in cmds]
        assert 'metrocluster operation show' in cli_commands


# ---------------------------------------------------------------------------
# NetApp StorageGRID
# ---------------------------------------------------------------------------

from app.dr_vendor import storagegrid_logic


class TestStorageGRIDDiscovery:
    """StorageGRID discover_relationships uses sites_info (not old 'sites')."""

    def test_single_site_returns_empty(self):
        health = {
            'sites_info': [{'name': 'Site A'}],
            'site_count': 1,
        }
        result = storagegrid_logic.discover_relationships('SGCL101', health)
        assert result == []

    def test_no_sites_info_key_returns_empty(self):
        result = storagegrid_logic.discover_relationships('SGCL101', {})
        assert result == []

    def test_old_sites_key_not_used(self):
        health = {
            'sites': [{'name': 'A'}, {'name': 'B'}],
        }
        result = storagegrid_logic.discover_relationships('SGCL101', health)
        assert result == []

    def test_multisite_detected(self):
        health = {
            'sites_info': [{'name': 'Datacenter A'}, {'name': 'Datacenter B'}],
            'site_count': 2,
        }
        result = storagegrid_logic.discover_relationships('SGCL101', health)
        assert len(result) == 1
        rel = result[0]
        assert rel['replication_type'] == 'storagegrid-multisite'
        assert rel['vendor'] == 'netapp-storagegrid'
        assert rel['primary_site'] == 'Datacenter A'
        assert rel['secondary_site'] == 'Datacenter B'

    def test_three_sites_uses_first_two(self):
        health = {
            'sites_info': [{'name': 'A'}, {'name': 'B'}, {'name': 'C'}],
        }
        result = storagegrid_logic.discover_relationships('SGCL101', health)
        assert len(result) == 1
        assert result[0]['primary_site'] == 'A'
        assert result[0]['secondary_site'] == 'B'


# ---------------------------------------------------------------------------
# Dell DataDomain
# ---------------------------------------------------------------------------

from app.dr_vendor import datadomain_logic


class TestDataDomainDiscovery:
    """DataDomain discover_relationships uses mtree_replications (preferred) or
    falls back to replication_status.contexts (legacy)."""

    def test_no_replication_returns_empty(self):
        result = datadomain_logic.discover_relationships('dd1', {})
        assert result == []

    def test_old_replication_key_not_used(self):
        health = {
            'replication': [{'state': 'replicating', 'source': {'host': 'dd1'}, 'destination': {'host': 'dd2'}}],
        }
        result = datadomain_logic.discover_relationships('dd1', health)
        assert result == []

    def test_mtree_replications_source_mode(self):
        health = {
            'mtree_replications': [
                {
                    'mode': 'SOURCE',
                    'state': 'NORMAL',
                    'connected': True,
                    'source_host': 'dd1',
                    'destination_host': 'dd2',
                    'source_mtree': '/data/col1/backup',
                    'destination_mtree': '/data/col1/backup',
                }
            ]
        }
        result = datadomain_logic.discover_relationships('dd1', health)
        assert len(result) == 1
        rel = result[0]
        assert rel['replication_type'] == 'datadomain-replication'
        assert rel['vendor'] == 'dell-datadomain'
        assert rel['primary_cluster'] == 'dd1'
        assert rel['secondary_cluster'] == 'dd2'
        assert rel['replication_state'] == 'healthy'
        assert rel['relationship_data']['source']['mtree'] == '/data/col1/backup'

    def test_mtree_replications_disconnected_is_degraded(self):
        health = {
            'mtree_replications': [
                {
                    'mode': 'SOURCE',
                    'state': 'NORMAL',
                    'connected': False,
                    'source_host': 'dd1',
                    'destination_host': 'dd2',
                    'source_mtree': '/data/col1/backup',
                    'destination_mtree': '/data/col1/backup',
                }
            ]
        }
        result = datadomain_logic.discover_relationships('dd1', health)
        assert result[0]['replication_state'] == 'degraded'

    def test_mtree_replications_connecting_state_is_degraded(self):
        health = {
            'mtree_replications': [
                {
                    'mode': 'SOURCE',
                    'state': 'CONNECTING',
                    'connected': False,
                    'source_host': 'dd1',
                    'destination_host': 'dd2',
                    'source_mtree': None,
                    'destination_mtree': None,
                }
            ]
        }
        result = datadomain_logic.discover_relationships('dd1', health)
        assert result[0]['replication_state'] == 'degraded'

    def test_legacy_replication_status_fallback(self):
        """When mtree_replications is absent, fall back to replication_status.contexts."""
        health = {
            'replication_status': {
                'context_count': 1,
                'contexts': [
                    {
                        'id': '1',
                        'state': 'replicating',
                        'direction': 'outbound',
                        'remote_host': 'dd2',
                    }
                ],
            }
        }
        result = datadomain_logic.discover_relationships('dd1', health)
        assert len(result) == 1
        assert result[0]['replication_type'] == 'datadomain-replication'
        assert result[0]['secondary_cluster'] == 'dd2'

    def test_multiple_mtree_contexts(self):
        health = {
            'mtree_replications': [
                {
                    'mode': 'SOURCE',
                    'state': 'NORMAL',
                    'connected': True,
                    'source_host': 'dd1',
                    'destination_host': 'dd2',
                    'source_mtree': '/data/col1/backup',
                    'destination_mtree': '/data/col1/backup',
                },
                {
                    'mode': 'SOURCE',
                    'state': 'RESYNCING',
                    'connected': True,
                    'source_host': 'dd1',
                    'destination_host': 'dd3',
                    'source_mtree': '/data/col1/veeam',
                    'destination_mtree': '/data/col1/veeam',
                },
            ]
        }
        result = datadomain_logic.discover_relationships('dd1', health)
        assert len(result) == 2
        destinations = {r['secondary_cluster'] for r in result}
        assert 'dd2' in destinations
        assert 'dd3' in destinations


# ---------------------------------------------------------------------------
# Pure FlashArray – pod-replica-links (async pod replication)
# ---------------------------------------------------------------------------

class TestPureFlashArrayPodReplicaLinks:
    """Pure FlashArray discover_relationships also detects pod-replica-links
    collected via GET /api/<ver>/pod-replica-links."""

    def test_outbound_pod_replica_link_creates_relationship(self):
        health = {
            'is_active_cluster': False,
            'array_connections': [],
            'pods_info': [],
            'pod_replica_links': [
                {
                    'direction': 'outbound',
                    'local_pod': {'name': 'pod1'},
                    'remote_pod': {'name': 'pod1'},
                    'remote_arrays': [{'name': 'pure02'}],
                    'status': {'progress': 'replicating'},
                }
            ],
        }
        result = pure_flasharray_logic.discover_relationships('pure01', health)
        assert len(result) == 1
        rel = result[0]
        assert rel['replication_type'] == 'activecluster'
        assert rel['primary_cluster'] == 'pure01'
        assert rel['secondary_cluster'] == 'pure02'
        assert rel['relationship_data']['replication_mode'] == 'asynchronous'

    def test_inbound_pod_replica_link_ignored(self):
        """Inbound links must not create duplicate relationships."""
        health = {
            'is_active_cluster': False,
            'array_connections': [],
            'pod_replica_links': [
                {
                    'direction': 'inbound',
                    'local_pod': {'name': 'pod1'},
                    'remote_pod': {'name': 'pod1'},
                }
            ],
        }
        result = pure_flasharray_logic.discover_relationships('pure01', health)
        assert result == []

    def test_pod_replica_link_paused_is_degraded(self):
        health = {
            'is_active_cluster': False,
            'array_connections': [],
            'pod_replica_links': [
                {
                    'direction': 'outbound',
                    'local_pod': {'name': 'pod1'},
                    'remote_pod': {'name': 'pod1'},
                    'remote_arrays': [{'name': 'pure02'}],
                    'status': {'progress': 'paused'},
                }
            ],
        }
        result = pure_flasharray_logic.discover_relationships('pure01', health)
        assert len(result) == 1
        assert result[0]['replication_state'] == 'degraded'

    def test_sync_and_async_relationships_coexist(self):
        """A system can have both ActiveCluster and pod replica link relationships."""
        health = {
            'is_active_cluster': True,
            'array_connections': [
                {
                    'name': 'pure02',
                    'status': 'connected',
                    'type': 'sync-replication',
                }
            ],
            'pods_info': [],
            'pod_replica_links': [
                {
                    'direction': 'outbound',
                    'local_pod': {'name': 'archive-pod'},
                    'remote_pod': {'name': 'archive-pod'},
                    'remote_arrays': [{'name': 'pure03'}],
                    'status': {},
                }
            ],
        }
        result = pure_flasharray_logic.discover_relationships('pure01', health)
        assert len(result) == 2
        modes = {r['relationship_data'].get('replication_mode') for r in result}
        assert 'synchronous' in modes
        assert 'asynchronous' in modes


# ---------------------------------------------------------------------------
# Pure FlashArray ActiveCluster – disaster_recovery workflow
# ---------------------------------------------------------------------------


class TestPureFlashArrayActiveClusterDisasterRecovery:
    """Tests for the disaster_recovery direction of pure_flasharray_logic.

    ActiveCluster is active-active synchronous replication: hosts continue IO
    automatically via MPIO when one array becomes unavailable.  The DR planner
    must NOT generate failover commands.  It must only generate validation and
    diagnostic procedures targeting the surviving (secondary) array.
    """

    @staticmethod
    def _make_rel(primary='pure01', secondary='pure02', pod='production-pod'):
        return {
            'system_name': primary,
            'vendor': 'pure',
            'replication_type': 'activecluster',
            'primary_site': primary,
            'secondary_site': secondary,
            'primary_cluster': primary,
            'secondary_cluster': secondary,
            'replication_state': 'healthy',
            'relationship_data': {
                'pod_name': pod,
                'replication_mode': 'synchronous',
            },
        }

    # ---- workflow phases ----

    def test_disaster_recovery_has_6_steps(self):
        rel = self._make_rel()
        steps = pure_flasharray_logic.generate_workflow(rel, 'disaster_recovery')
        assert len(steps) == 6

    def test_disaster_recovery_phases_in_order(self):
        rel = self._make_rel()
        steps = pure_flasharray_logic.generate_workflow(rel, 'disaster_recovery')
        phases = [s['phase'] for s in steps]
        assert phases[0] == 'detection'
        assert all(p == 'validation' for p in phases[1:5])
        assert phases[5] == 'support'

    def test_disaster_recovery_step_numbers_sequential(self):
        rel = self._make_rel()
        steps = pure_flasharray_logic.generate_workflow(rel, 'disaster_recovery')
        assert [s['step'] for s in steps] == list(range(1, 7))

    def test_disaster_recovery_titles_cover_required_phases(self):
        rel = self._make_rel()
        steps = pure_flasharray_logic.generate_workflow(rel, 'disaster_recovery')
        titles = ' '.join(s['title'].lower() for s in steps)
        assert 'detection' in titles or 'failure' in titles
        assert 'health' in titles or 'surviving' in titles
        assert 'pod' in titles or 'replication' in titles
        assert 'volume' in titles
        assert 'host' in titles
        assert 'remote' in titles or 'support' in titles

    # ---- no failover commands ----

    def test_no_purepod_remove_in_disaster_recovery(self):
        """purepod remove must NOT appear — active-active, no failover action."""
        rel = self._make_rel()
        cmds = pure_flasharray_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert not any('purepod remove' in cli for cli in cli_commands), \
            'purepod remove must not appear in disaster_recovery commands'

    def test_no_purepod_add_in_disaster_recovery(self):
        """purepod add must NOT appear — no pod manipulation during disaster."""
        rel = self._make_rel()
        cmds = pure_flasharray_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert not any('purepod add' in cli for cli in cli_commands), \
            'purepod add must not appear in disaster_recovery commands'

    # ---- required diagnostic commands ----

    def test_purearray_list_in_disaster_recovery(self):
        rel = self._make_rel()
        cmds = pure_flasharray_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert 'purearray list' in cli_commands

    def test_purepod_list_in_disaster_recovery(self):
        rel = self._make_rel()
        cmds = pure_flasharray_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert 'purepod list' in cli_commands

    def test_purepod_list_replication_in_disaster_recovery(self):
        rel = self._make_rel()
        cmds = pure_flasharray_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert 'purepod list --replication' in cli_commands

    def test_purevol_list_in_disaster_recovery(self):
        rel = self._make_rel()
        cmds = pure_flasharray_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert 'purevol list' in cli_commands

    def test_purehost_list_in_disaster_recovery(self):
        rel = self._make_rel()
        cmds = pure_flasharray_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert 'purehost list' in cli_commands

    def test_purearray_list_connections_in_disaster_recovery(self):
        rel = self._make_rel()
        cmds = pure_flasharray_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert 'purearray list --connections' in cli_commands

    def test_remote_assist_enable_in_disaster_recovery(self):
        rel = self._make_rel()
        cmds = pure_flasharray_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert 'purearray remote-assist enable' in cli_commands

    # ---- commands target surviving (secondary) array ----

    def test_disaster_recovery_commands_target_surviving_array(self):
        """All disaster_recovery commands must target the surviving (secondary) array."""
        rel = self._make_rel(primary='pure01', secondary='pure02')
        cmds = pure_flasharray_logic.generate_commands(rel, 'disaster_recovery')
        for cmd in cmds:
            assert cmd['target'] == 'pure02', \
                f"Command {cmd['cli']!r} targets {cmd['target']!r}, expected 'pure02'"

    # ---- planned_failover is unaffected ----

    def test_planned_failover_unchanged(self):
        """Adding disaster_recovery must not break planned_failover."""
        rel = self._make_rel()
        steps = pure_flasharray_logic.generate_workflow(rel, 'planned_failover')
        assert len(steps) == 8
        cmds = pure_flasharray_logic.generate_commands(rel, 'planned_failover')
        cli_commands = [c['cli'] for c in cmds]
        assert any('purepod remove' in cli for cli in cli_commands)

    # ---- runbook ----

    def test_disaster_recovery_runbook_phases_match_workflow(self):
        rel = self._make_rel()
        runbook = pure_flasharray_logic.generate_runbook(rel, 'disaster_recovery')
        workflow_phases = {s['phase'] for s in pure_flasharray_logic.generate_workflow(rel, 'disaster_recovery')}
        runbook_phases = {section['phase'] for section in runbook}
        assert runbook_phases == workflow_phases

    def test_disaster_recovery_runbook_contains_remote_assist(self):
        rel = self._make_rel()
        runbook = pure_flasharray_logic.generate_runbook(rel, 'disaster_recovery')
        all_cli = [c['cli'] for section in runbook for c in section.get('commands', [])]
        assert 'purearray remote-assist enable' in all_cli

    # ---- diagram ----

    def test_workflow_diagram_is_flowchart(self):
        rel = self._make_rel()
        diagram = pure_flasharray_logic.generate_workflow_diagram(rel, 'disaster_recovery')
        assert diagram.startswith('flowchart TD')

    def test_workflow_diagram_contains_all_6_steps(self):
        rel = self._make_rel()
        diagram = pure_flasharray_logic.generate_workflow_diagram(rel, 'disaster_recovery')
        for i in range(1, 7):
            assert f'S{i}[' in diagram, f'Step node S{i} missing from disaster_recovery diagram'

    def test_workflow_diagram_steps_connected(self):
        rel = self._make_rel()
        diagram = pure_flasharray_logic.generate_workflow_diagram(rel, 'disaster_recovery')
        for i in range(1, 6):
            assert f'S{i} --> S{i+1}' in diagram


# ---------------------------------------------------------------------------
# ONTAP SnapMirror – new inter-cluster filtering and svm_peers enrichment
# ---------------------------------------------------------------------------

from app.dr_vendor import ontap_snapmirror_logic


class TestONTAPSnapMirrorDiscovery:
    """ONTAP SnapMirror discover_relationships uses snapmirror_relationships and
    svm_peers populated by get_health_status() (new in this PR)."""

    def test_no_snapmirror_relationships_returns_empty(self):
        result = ontap_snapmirror_logic.discover_relationships('CL1', {})
        assert result == []

    def test_inter_cluster_snapmirror_detected(self):
        health = {
            'snapmirror_relationships': [
                {
                    'state': 'snapmirrored',
                    'healthy': True,
                    'source': {'svm': {'name': 'svm1'}, 'cluster': {'name': 'CL1'}},
                    'destination': {'svm': {'name': 'svm1-dr'}, 'cluster': {'name': 'CL2'}},
                }
            ]
        }
        result = ontap_snapmirror_logic.discover_relationships('CL1', health)
        assert len(result) == 1
        rel = result[0]
        assert rel['replication_type'] == 'snapmirror'
        assert rel['secondary_cluster'] == 'CL2'
        assert rel['replication_state'] == 'healthy'

    def test_intra_cluster_snapmirror_skipped(self):
        """Relationships with no destination cluster (intra-cluster) must be ignored."""
        health = {
            'snapmirror_relationships': [
                {
                    'state': 'snapmirrored',
                    'source': {'svm': {'name': 'svm1'}},
                    'destination': {'svm': {'name': 'svm1-dp'}},
                    # no 'cluster' in destination → intra-cluster → skip
                }
            ]
        }
        result = ontap_snapmirror_logic.discover_relationships('CL1', health)
        assert result == []

    def test_same_cluster_destination_skipped(self):
        """Destination cluster == local cluster must be skipped."""
        health = {
            'snapmirror_relationships': [
                {
                    'state': 'snapmirrored',
                    'source': {'svm': {'name': 'svm1'}},
                    'destination': {'svm': {'name': 'svm1-dp'}, 'cluster': {'name': 'CL1'}},
                }
            ]
        }
        result = ontap_snapmirror_logic.discover_relationships('CL1', health)
        assert result == []

    def test_broken_snapmirror_is_degraded(self):
        health = {
            'snapmirror_relationships': [
                {
                    'state': 'broken_off',
                    'source': {'svm': {'name': 'svm1'}},
                    'destination': {'svm': {'name': 'svm2'}, 'cluster': {'name': 'CL2'}},
                }
            ]
        }
        result = ontap_snapmirror_logic.discover_relationships('CL1', health)
        assert len(result) == 1
        assert result[0]['replication_state'] == 'degraded'

    def test_svm_peers_enrich_secondary_cluster(self):
        """When destination.cluster.name is missing, svm_peers provides the cluster."""
        health = {
            'snapmirror_relationships': [
                {
                    'state': 'snapmirrored',
                    'source': {'svm': {'name': 'svm1'}},
                    'destination': {'svm': {'name': 'svm2'}},
                    # no cluster in destination
                }
            ],
            'svm_peers': [
                {
                    'svm': {'name': 'svm1'},
                    'peer': {'svm': {'name': 'svm2'}, 'cluster': {'name': 'CL2'}},
                    'state': 'peered',
                }
            ],
        }
        result = ontap_snapmirror_logic.discover_relationships('CL1', health)
        assert len(result) == 1
        assert result[0]['secondary_cluster'] == 'CL2'

    def test_multiple_inter_cluster_relationships(self):
        health = {
            'snapmirror_relationships': [
                {
                    'state': 'snapmirrored',
                    'source': {'svm': {'name': 'svm1'}},
                    'destination': {'svm': {'name': 'svm1-dr'}, 'cluster': {'name': 'CL2'}},
                },
                {
                    'state': 'in_sync',
                    'source': {'svm': {'name': 'svm2'}},
                    'destination': {'svm': {'name': 'svm2-dr'}, 'cluster': {'name': 'CL3'}},
                },
            ]
        }
        result = ontap_snapmirror_logic.discover_relationships('CL1', health)
        assert len(result) == 2
        clusters = {r['secondary_cluster'] for r in result}
        assert 'CL2' in clusters
        assert 'CL3' in clusters


# ---------------------------------------------------------------------------
# ONTAP SnapMirror – disaster_recovery workflow (new tests)
# ---------------------------------------------------------------------------

class TestSnapMirrorDisasterRecovery:
    """Tests for the disaster_recovery direction added to ontap_snapmirror_logic."""

    def _make_rel(self, primary='CL1', secondary='CL2',
                  src_svm='svm1', dst_svm='svm1-dr',
                  src_path='svm1:', dst_path='svm1-dr:'):
        return {
            'system_name': primary,
            'vendor': 'netapp-ontap',
            'replication_type': 'snapmirror',
            'primary_site': src_svm,
            'secondary_site': dst_svm,
            'primary_cluster': primary,
            'secondary_cluster': secondary,
            'replication_state': 'healthy',
            'relationship_data': {
                'state': 'snapmirrored',
                'sm_type': 'svm_dr',
                'source': {'svm': {'name': src_svm}, 'path': src_path, 'cluster': {'name': primary}},
                'destination': {'svm': {'name': dst_svm}, 'path': dst_path, 'cluster': {'name': secondary}},
            },
        }

    # ---- sm_type detection in discovery ----

    def test_svm_dr_type_detected_from_trailing_colon(self):
        health = {
            'snapmirror_relationships': [{
                'state': 'snapmirrored',
                'source': {'svm': {'name': 'svm1'}, 'path': 'svm1:'},
                'destination': {'svm': {'name': 'svm1-dr'}, 'path': 'svm1-dr:', 'cluster': {'name': 'CL2'}},
            }]
        }
        result = ontap_snapmirror_logic.discover_relationships('CL1', health)
        assert len(result) == 1
        assert result[0]['relationship_data']['sm_type'] == 'svm_dr'

    def test_volume_type_detected_from_path(self):
        health = {
            'snapmirror_relationships': [{
                'state': 'snapmirrored',
                'source': {'svm': {'name': 'svm1'}, 'path': 'svm1:vol1'},
                'destination': {'svm': {'name': 'svm1-dr'}, 'path': 'svm1-dr:vol1_dp', 'cluster': {'name': 'CL2'}},
            }]
        }
        result = ontap_snapmirror_logic.discover_relationships('CL1', health)
        assert len(result) == 1
        assert result[0]['relationship_data']['sm_type'] == 'volume'

    # ---- workflow steps ----

    def test_disaster_recovery_has_8_steps(self):
        rel = self._make_rel()
        steps = ontap_snapmirror_logic.generate_workflow(rel, 'disaster_recovery')
        assert len(steps) == 8

    def test_disaster_recovery_phases_in_order(self):
        rel = self._make_rel()
        steps = ontap_snapmirror_logic.generate_workflow(rel, 'disaster_recovery')
        phases = [s['phase'] for s in steps]
        assert phases[0] == 'detection'
        assert phases[1] == 'pre-checks'
        assert phases[2] == 'snapmirror-break'
        assert phases[3] == 'activate-dr'
        assert 'verify-storage' in phases
        assert 'verify-network' in phases
        assert 'serve-clients' in phases
        assert phases[-1] == 'reprotect'

    def test_disaster_recovery_step_numbers_sequential(self):
        rel = self._make_rel()
        steps = ontap_snapmirror_logic.generate_workflow(rel, 'disaster_recovery')
        assert [s['step'] for s in steps] == list(range(1, 9))

    def test_unknown_direction_falls_back_to_planned_failover(self):
        rel = self._make_rel()
        steps = ontap_snapmirror_logic.generate_workflow(rel, 'nonexistent')
        planned = ontap_snapmirror_logic.generate_workflow(rel, 'planned_failover')
        assert steps == planned

    # ---- command generation ----

    def test_snapmirror_break_command_present(self):
        rel = self._make_rel(dst_path='svm1-dr:')
        cmds = ontap_snapmirror_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert any('snapmirror break' in cli for cli in cli_commands)

    def test_snapmirror_break_no_quiesce_in_disaster_recovery(self):
        """Quiesce must NOT appear in disaster_recovery (source is down)."""
        rel = self._make_rel()
        cmds = ontap_snapmirror_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert not any('quiesce' in cli for cli in cli_commands), (
            'snapmirror quiesce must not appear in disaster_recovery commands'
        )

    def test_planned_failover_has_quiesce(self):
        """planned_failover should still quiesce before breaking."""
        rel = self._make_rel()
        cmds = ontap_snapmirror_logic.generate_commands(rel, 'planned_failover')
        cli_commands = [c['cli'] for c in cmds]
        assert any('quiesce' in cli for cli in cli_commands)

    def test_lag_time_precheck_in_disaster_recovery(self):
        """lag-time check must be in disaster_recovery pre-checks."""
        rel = self._make_rel()
        cmds = ontap_snapmirror_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert 'snapmirror show -fields status,health,lag-time' in cli_commands

    def test_lag_time_precheck_in_planned_failover(self):
        """planned_failover should also include the lag-time check."""
        rel = self._make_rel()
        cmds = ontap_snapmirror_logic.generate_commands(rel, 'planned_failover')
        cli_commands = [c['cli'] for c in cmds]
        assert 'snapmirror show -fields status,health,lag-time' in cli_commands

    def test_reprotect_resync_command_present(self):
        rel = self._make_rel(src_path='svm1:', dst_path='svm1-dr:')
        cmds = ontap_snapmirror_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert any('snapmirror resync' in cli for cli in cli_commands)

    def test_vserver_start_in_disaster_recovery(self):
        rel = self._make_rel(dst_svm='svm1-dr')
        cmds = ontap_snapmirror_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert any('vserver start' in cli for cli in cli_commands)

    def test_disaster_recovery_commands_target_dr_cluster(self):
        """All disaster_recovery commands must target the surviving (secondary/DR) cluster."""
        rel = self._make_rel(primary='CL1', secondary='CL2')
        cmds = ontap_snapmirror_logic.generate_commands(rel, 'disaster_recovery')
        for cmd in cmds:
            assert cmd['target'] == 'CL2', (
                f"Command {cmd['cli']!r} targets {cmd['target']!r} instead of DR cluster CL2"
            )

    def test_planned_failover_commands_target_primary(self):
        """planned_failover commands must target the primary cluster."""
        rel = self._make_rel(primary='CL1', secondary='CL2')
        cmds = ontap_snapmirror_logic.generate_commands(rel, 'planned_failover')
        for cmd in cmds:
            assert cmd['target'] == 'CL1'

    # ---- runbook ----

    def test_runbook_phases_match_workflow(self):
        rel = self._make_rel()
        runbook = ontap_snapmirror_logic.generate_runbook(rel, 'disaster_recovery')
        runbook_phases = {section['phase'] for section in runbook}
        workflow_phases = {s['phase'] for s in ontap_snapmirror_logic.generate_workflow(rel, 'disaster_recovery')}
        assert runbook_phases == workflow_phases

    def test_runbook_snapmirror_break_section_has_command(self):
        rel = self._make_rel()
        runbook = ontap_snapmirror_logic.generate_runbook(rel, 'disaster_recovery')
        break_section = next(s for s in runbook if s['phase'] == 'snapmirror-break')
        cli_commands = [c['cli'] for c in break_section['commands']]
        assert any('snapmirror break' in cli for cli in cli_commands)

    def test_runbook_reprotect_section_has_resync(self):
        rel = self._make_rel()
        runbook = ontap_snapmirror_logic.generate_runbook(rel, 'disaster_recovery')
        reprotect = next((s for s in runbook if s['phase'] == 'reprotect'), None)
        assert reprotect is not None, 'reprotect section missing from SnapMirror DR runbook'
        cli_commands = [c['cli'] for c in reprotect['commands']]
        assert any('snapmirror resync' in cli for cli in cli_commands)

    # ---- workflow diagram ----

    def test_workflow_diagram_is_flowchart(self):
        rel = self._make_rel()
        diagram = ontap_snapmirror_logic.generate_workflow_diagram(rel, 'disaster_recovery')
        assert diagram.startswith('flowchart TD')

    def test_workflow_diagram_contains_all_8_steps(self):
        rel = self._make_rel()
        diagram = ontap_snapmirror_logic.generate_workflow_diagram(rel, 'disaster_recovery')
        for i in range(1, 9):
            assert f'S{i}[' in diagram, f'Step node S{i} missing from disaster_recovery diagram'

    def test_workflow_diagram_steps_connected(self):
        rel = self._make_rel()
        diagram = ontap_snapmirror_logic.generate_workflow_diagram(rel, 'disaster_recovery')
        for i in range(1, 8):
            assert f'S{i} --> S{i+1}' in diagram


# ---------------------------------------------------------------------------
# DataDomain – disaster_recovery workflow (new tests)
# ---------------------------------------------------------------------------

class TestDataDomainDisasterRecovery:
    """Tests for the disaster_recovery direction added to datadomain_logic."""

    def _make_rel(self, primary='dd1', secondary='dd2',
                  mtree='/data/col1/backup'):
        return {
            'system_name': primary,
            'vendor': 'dell-datadomain',
            'replication_type': 'datadomain-replication',
            'primary_site': primary,
            'secondary_site': secondary,
            'primary_cluster': primary,
            'secondary_cluster': secondary,
            'replication_state': 'healthy',
            'relationship_data': {
                'source': {'host': primary, 'mtree': mtree},
                'destination': {'host': secondary, 'mtree': mtree},
                'state': 'NORMAL',
                'connected': True,
                'mode': 'SOURCE',
            },
        }

    # ---- workflow steps ----

    def test_disaster_recovery_has_7_steps(self):
        rel = self._make_rel()
        steps = datadomain_logic.generate_workflow(rel, 'disaster_recovery')
        assert len(steps) == 7

    def test_disaster_recovery_phases_in_order(self):
        rel = self._make_rel()
        steps = datadomain_logic.generate_workflow(rel, 'disaster_recovery')
        phases = [s['phase'] for s in steps]
        assert phases[0] == 'detection'
        assert phases[1] == 'validation'
        assert phases[2] == 'break-replication'
        assert phases[3] == 'promote-mtree'
        assert 'validate-filesystem' in phases
        assert 'switch-backup' in phases
        assert phases[-1] == 'recreate-replication'

    def test_disaster_recovery_step_numbers_sequential(self):
        rel = self._make_rel()
        steps = datadomain_logic.generate_workflow(rel, 'disaster_recovery')
        assert [s['step'] for s in steps] == list(range(1, 8))

    def test_unknown_direction_falls_back_to_planned_failover(self):
        rel = self._make_rel()
        steps = datadomain_logic.generate_workflow(rel, 'nonexistent')
        planned = datadomain_logic.generate_workflow(rel, 'planned_failover')
        assert steps == planned

    # ---- command generation ----

    def test_replication_break_command_present(self):
        rel = self._make_rel(mtree='/data/col1/backup')
        cmds = datadomain_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert any('replication break' in cli for cli in cli_commands)

    def test_no_replication_sync_in_disaster_recovery(self):
        """Sync must NOT appear in disaster_recovery (source is down)."""
        rel = self._make_rel()
        cmds = datadomain_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert not any('replication sync' in cli for cli in cli_commands), (
            'replication sync must not appear in disaster_recovery commands'
        )

    def test_planned_failover_has_replication_sync(self):
        """planned_failover should still sync before breaking."""
        rel = self._make_rel()
        cmds = datadomain_logic.generate_commands(rel, 'planned_failover')
        cli_commands = [c['cli'] for c in cmds]
        assert any('replication sync' in cli for cli in cli_commands)

    def test_precheck_replication_status_in_disaster_recovery(self):
        rel = self._make_rel()
        cmds = datadomain_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert 'replication status' in cli_commands

    def test_precheck_replication_show_config_in_disaster_recovery(self):
        rel = self._make_rel()
        cmds = datadomain_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert 'replication show config' in cli_commands

    def test_precheck_filesys_status_in_disaster_recovery(self):
        rel = self._make_rel()
        cmds = datadomain_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert 'filesys status' in cli_commands

    def test_precheck_alerts_show_in_disaster_recovery(self):
        rel = self._make_rel()
        cmds = datadomain_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert 'alerts show' in cli_commands

    def test_precheck_commands_in_planned_failover(self):
        """planned_failover should also include all 4 pre-check commands."""
        rel = self._make_rel()
        cmds = datadomain_logic.generate_commands(rel, 'planned_failover')
        cli_commands = [c['cli'] for c in cmds]
        for expected in ('replication status', 'replication show config',
                         'filesys status', 'alerts show'):
            assert expected in cli_commands, f'{expected!r} missing from planned_failover commands'

    def test_recreate_replication_command_present(self):
        rel = self._make_rel(primary='dd1', mtree='/data/col1/backup')
        cmds = datadomain_logic.generate_commands(rel, 'disaster_recovery')
        cli_commands = [c['cli'] for c in cmds]
        assert any('replication add source' in cli for cli in cli_commands)

    def test_mtree_in_break_command(self):
        rel = self._make_rel(mtree='/data/col1/veeam')
        cmds = datadomain_logic.generate_commands(rel, 'disaster_recovery')
        break_cmd = next(c for c in cmds if 'replication break' in c['cli'])
        assert '/data/col1/veeam' in break_cmd['cli']

    def test_disaster_recovery_commands_target_dr_system(self):
        """All disaster_recovery commands must target the surviving (secondary/DR) system."""
        rel = self._make_rel(primary='dd1', secondary='dd2')
        cmds = datadomain_logic.generate_commands(rel, 'disaster_recovery')
        for cmd in cmds:
            assert cmd['target'] == 'dd2', (
                f"Command {cmd['cli']!r} targets {cmd['target']!r} instead of DR system dd2"
            )

    def test_planned_failover_commands_target_correct_systems(self):
        """Pre-failover commands target primary; failover/post-failover target secondary."""
        rel = self._make_rel(primary='dd1', secondary='dd2')
        cmds = datadomain_logic.generate_commands(rel, 'planned_failover')
        pre = [c for c in cmds if c['phase'] == 'pre-failover']
        failover = [c for c in cmds if c['phase'] == 'failover']
        for cmd in pre:
            assert cmd['target'] == 'dd1', f"pre-failover cmd {cmd['cli']!r} should target primary"
        for cmd in failover:
            assert cmd['target'] == 'dd2', f"failover cmd {cmd['cli']!r} should target secondary"

    # ---- runbook ----

    def test_runbook_phases_match_workflow(self):
        rel = self._make_rel()
        runbook = datadomain_logic.generate_runbook(rel, 'disaster_recovery')
        runbook_phases = {section['phase'] for section in runbook}
        workflow_phases = {s['phase'] for s in datadomain_logic.generate_workflow(rel, 'disaster_recovery')}
        assert runbook_phases == workflow_phases

    def test_runbook_break_replication_section_has_command(self):
        rel = self._make_rel()
        runbook = datadomain_logic.generate_runbook(rel, 'disaster_recovery')
        break_section = next(s for s in runbook if s['phase'] == 'break-replication')
        cli_commands = [c['cli'] for c in break_section['commands']]
        assert any('replication break' in cli for cli in cli_commands)

    def test_runbook_recreate_replication_section_has_add_command(self):
        rel = self._make_rel()
        runbook = datadomain_logic.generate_runbook(rel, 'disaster_recovery')
        recreate = next((s for s in runbook if s['phase'] == 'recreate-replication'), None)
        assert recreate is not None, 'recreate-replication section missing from DataDomain DR runbook'
        cli_commands = [c['cli'] for c in recreate['commands']]
        assert any('replication add source' in cli for cli in cli_commands)

    # ---- workflow diagram ----

    def test_workflow_diagram_is_flowchart(self):
        rel = self._make_rel()
        diagram = datadomain_logic.generate_workflow_diagram(rel, 'disaster_recovery')
        assert diagram.startswith('flowchart TD')

    def test_workflow_diagram_contains_all_7_steps(self):
        rel = self._make_rel()
        diagram = datadomain_logic.generate_workflow_diagram(rel, 'disaster_recovery')
        for i in range(1, 8):
            assert f'S{i}[' in diagram, f'Step node S{i} missing from disaster_recovery diagram'

    def test_workflow_diagram_steps_connected(self):
        rel = self._make_rel()
        diagram = datadomain_logic.generate_workflow_diagram(rel, 'disaster_recovery')
        for i in range(1, 7):
            assert f'S{i} --> S{i+1}' in diagram
