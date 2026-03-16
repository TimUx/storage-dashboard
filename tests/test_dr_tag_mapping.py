"""Tests for DR Planner tag-based environment and DataCenter mapping.

Verifies that:
- The environment is resolved from the "Landschaft" tag group
  ("Produktion" → production, "Test/Dev" → test, anything else → unknown).
- The DataCenter site name is resolved from the "DataCenter" tag group.
- Secondary site is always the DataCenter tag of the partner system (case-insensitive
  lookup); falls back to 'unknown' when the partner has no DataCenter tag.

These mapping rules are applied in app/routes/dr.py::api_systems().
The helper logic is isolated here using SimpleNamespace mocks so we can
test the rules without a running database.
"""

from types import SimpleNamespace

import pytest


# ---------------------------------------------------------------------------
# Helpers that mirror the mapping logic in api_systems()
# ---------------------------------------------------------------------------

def _make_tag(name, group_name):
    group = SimpleNamespace(name=group_name)
    return SimpleNamespace(name=name, group=group)


def _make_system(name, *tags):
    return SimpleNamespace(name=name, tags=list(tags))


def _build_maps(systems):
    """Reproduce the tag-scanning loop from api_systems().

    sys_dc_map uses lowercase keys so that lookups are case-insensitive,
    matching the fix for ONTAP systems where the API may return cluster names
    in a different case than the inventory stores them.
    """
    sys_env_map = {}
    sys_dc_map = {}
    for ss in systems:
        sys_env_map[ss.name] = 'unknown'
        for tag in (ss.tags or []):
            group_name = (tag.group.name if tag.group else '').strip()
            tag_name = tag.name.strip()
            if group_name == 'Landschaft':
                if tag_name == 'Produktion':
                    sys_env_map[ss.name] = 'production'
                elif tag_name == 'Test/Dev':
                    sys_env_map[ss.name] = 'test'
            elif group_name == 'DataCenter':
                # Lowercase key for case-insensitive lookup
                sys_dc_map[ss.name.lower()] = tag_name
    return sys_env_map, sys_dc_map


def _resolve_secondary_dc(sys_dc_map, sname, primary_cluster, secondary_cluster):
    """Reproduce the partner-cluster / secondary-DC resolution from api_systems().

    Returns the DataCenter tag of the partner cluster, 'unknown' when the
    partner exists in the relationship but has no DataCenter tag, or '' when
    no distinct partner cluster can be determined.
    """
    # Identify the partner cluster (the one that is NOT sname)
    if secondary_cluster and secondary_cluster.lower() != sname.lower():
        partner_cl = secondary_cluster
    elif primary_cluster and primary_cluster.lower() != sname.lower():
        partner_cl = primary_cluster
    else:
        partner_cl = ''

    if partner_cl:
        return sys_dc_map.get(partner_cl.lower(), 'unknown')
    return ''


# ---------------------------------------------------------------------------
# Environment mapping tests (Landschaft tag group)
# ---------------------------------------------------------------------------

class TestEnvironmentMapping:

    def test_produktion_maps_to_production(self):
        s = _make_system('sys1', _make_tag('Produktion', 'Landschaft'))
        env_map, _ = _build_maps([s])
        assert env_map['sys1'] == 'production'

    def test_test_dev_maps_to_test(self):
        s = _make_system('sys1', _make_tag('Test/Dev', 'Landschaft'))
        env_map, _ = _build_maps([s])
        assert env_map['sys1'] == 'test'

    def test_no_landschaft_tag_maps_to_unknown(self):
        s = _make_system('sys1', _make_tag('SAN', 'Storage Art'))
        env_map, _ = _build_maps([s])
        assert env_map['sys1'] == 'unknown'

    def test_no_tags_maps_to_unknown(self):
        s = _make_system('sys1')
        env_map, _ = _build_maps([s])
        assert env_map['sys1'] == 'unknown'

    def test_wrong_landschaft_value_maps_to_unknown(self):
        # "File" is a valid Landschaft tag but not a recognised environment value
        s = _make_system('sys1', _make_tag('File', 'Landschaft'))
        env_map, _ = _build_maps([s])
        assert env_map['sys1'] == 'unknown'

    def test_old_prod_tag_name_no_longer_maps(self):
        # Previously the code checked for tag names 'prod' / 'production' directly.
        # The new logic only uses the Landschaft group.
        s = _make_system('sys1', _make_tag('production', 'Environment'))
        env_map, _ = _build_maps([s])
        assert env_map['sys1'] == 'unknown'

    def test_old_test_tag_name_no_longer_maps(self):
        s = _make_system('sys1', _make_tag('test', 'Environment'))
        env_map, _ = _build_maps([s])
        assert env_map['sys1'] == 'unknown'

    def test_whitespace_trimmed_in_tag_name(self):
        s = _make_system('sys1', _make_tag(' Produktion ', 'Landschaft'))
        env_map, _ = _build_maps([s])
        assert env_map['sys1'] == 'production'

    def test_whitespace_trimmed_in_group_name(self):
        s = _make_system('sys1', _make_tag('Test/Dev', ' Landschaft '))
        env_map, _ = _build_maps([s])
        assert env_map['sys1'] == 'test'

    def test_multiple_systems_independently_mapped(self):
        s1 = _make_system('prod-sys', _make_tag('Produktion', 'Landschaft'))
        s2 = _make_system('test-sys', _make_tag('Test/Dev', 'Landschaft'))
        s3 = _make_system('no-env-sys')
        env_map, _ = _build_maps([s1, s2, s3])
        assert env_map['prod-sys'] == 'production'
        assert env_map['test-sys'] == 'test'
        assert env_map['no-env-sys'] == 'unknown'


# ---------------------------------------------------------------------------
# DataCenter mapping tests (DataCenter tag group)
# ---------------------------------------------------------------------------

class TestDataCenterMapping:

    def test_datacenter_tag_captured(self):
        s = _make_system('pure01', _make_tag('DC1 [NTT]', 'DataCenter'))
        _, dc_map = _build_maps([s])
        assert dc_map['pure01'] == 'DC1 [NTT]'

    def test_second_datacenter_captured(self):
        s = _make_system('pure02', _make_tag('DC2 [Equinix]', 'DataCenter'))
        _, dc_map = _build_maps([s])
        assert dc_map['pure02'] == 'DC2 [Equinix]'

    def test_no_datacenter_tag_not_in_map(self):
        s = _make_system('pure03', _make_tag('Produktion', 'Landschaft'))
        _, dc_map = _build_maps([s])
        assert 'pure03' not in dc_map

    def test_multiple_systems_datacenter(self):
        s1 = _make_system('pure01', _make_tag('DC1 [NTT]', 'DataCenter'))
        s2 = _make_system('pure02', _make_tag('DC2 [Equinix]', 'DataCenter'))
        _, dc_map = _build_maps([s1, s2])
        assert dc_map['pure01'] == 'DC1 [NTT]'
        assert dc_map['pure02'] == 'DC2 [Equinix]'

    def test_datacenter_whitespace_trimmed(self):
        s = _make_system('pure01', _make_tag(' DC1 [NTT] ', 'DataCenter'))
        _, dc_map = _build_maps([s])
        assert dc_map['pure01'] == 'DC1 [NTT]'

    def test_combined_env_and_datacenter_tags(self):
        s = _make_system(
            'pure01',
            _make_tag('Produktion', 'Landschaft'),
            _make_tag('DC1 [NTT]', 'DataCenter'),
        )
        env_map, dc_map = _build_maps([s])
        assert env_map['pure01'] == 'production'
        assert dc_map['pure01'] == 'DC1 [NTT]'

    def test_dc_map_uses_lowercase_keys(self):
        # Keys are stored in lowercase so that case-insensitive lookups work
        # when the API returns cluster names in different case than the inventory.
        s = _make_system('FASMC1', _make_tag('DC1 [NTT]', 'DataCenter'))
        _, dc_map = _build_maps([s])
        assert dc_map['fasmc1'] == 'DC1 [NTT]'
        assert 'FASMC1' not in dc_map


# ---------------------------------------------------------------------------
# Secondary site DataCenter resolution tests
# ---------------------------------------------------------------------------

class TestSecondarySiteResolution:
    """Verify secondary_dc is resolved from the partner cluster's DataCenter tag."""

    def _make_dc_map(self, *systems):
        """Build sys_dc_map from given (name, dc_tag) pairs."""
        sys_dc_map = {}
        for name, dc_tag in systems:
            sys_dc_map[name.lower()] = dc_tag
        return sys_dc_map

    def test_metrocluster_secondary_resolved_from_partner_tag(self):
        # fasmc1 (DC1) → fasmc2 (DC2): secondary should be DC2 [Equinix]
        dc_map = self._make_dc_map(('fasmc1', 'DC1 [NTT]'), ('fasmc2', 'DC2 [Equinix]'))
        result = _resolve_secondary_dc(dc_map, 'fasmc1', 'fasmc1', 'fasmc2')
        assert result == 'DC2 [Equinix]'

    def test_metrocluster_inverse_resolved_from_partner_tag(self):
        # fasmc2 (DC2) → fasmc1 (DC1): secondary should be DC1 [NTT]
        dc_map = self._make_dc_map(('fasmc1', 'DC1 [NTT]'), ('fasmc2', 'DC2 [Equinix]'))
        result = _resolve_secondary_dc(dc_map, 'fasmc2', 'fasmc2', 'fasmc1')
        assert result == 'DC1 [NTT]'

    def test_snapmirror_secondary_resolved_from_destination_cluster(self):
        # fascl1 (DC1) mirrors to ogs02m (DC2)
        dc_map = self._make_dc_map(('fascl1', 'DC1 [NTT]'), ('ogs02m', 'DC2 [Equinix]'))
        result = _resolve_secondary_dc(dc_map, 'fascl1', 'fascl1', 'ogs02m')
        assert result == 'DC2 [Equinix]'

    def test_case_insensitive_lookup_uppercase_api_name(self):
        # ONTAP API may return partner cluster name in uppercase (e.g. "FASMC2")
        # while the inventory stores it as lowercase ("fasmc2")
        dc_map = self._make_dc_map(('fasmc1', 'DC1 [NTT]'), ('fasmc2', 'DC2 [Equinix]'))
        # API returns uppercase partner cluster name
        result = _resolve_secondary_dc(dc_map, 'fasmc1', 'fasmc1', 'FASMC2')
        assert result == 'DC2 [Equinix]'

    def test_case_insensitive_lookup_mixed_case(self):
        dc_map = self._make_dc_map(('ogs02m', 'DC2'))
        result = _resolve_secondary_dc(dc_map, 'fascl1', 'fascl1', 'OGS02M')
        assert result == 'DC2'

    def test_partner_not_in_inventory_returns_unknown(self):
        # The partner system exists in the relationship but has no DataCenter tag
        # → must return 'unknown', NOT the system name
        dc_map = self._make_dc_map(('fasmc1', 'DC1 [NTT]'))
        result = _resolve_secondary_dc(dc_map, 'fasmc1', 'fasmc1', 'fasmc2')
        assert result == 'unknown'

    def test_no_distinct_partner_returns_empty_string(self):
        # Both primary_cluster and secondary_cluster equal sname (e.g. StorageGRID
        # single-grid setup) → no partner can be identified, result is ''
        dc_map = self._make_dc_map(('sgw01', 'DC1'))
        result = _resolve_secondary_dc(dc_map, 'sgw01', 'sgw01', 'sgw01')
        assert result == ''

    def test_secondary_cluster_used_when_different_from_sname(self):
        # Normal case: secondary_cluster != sname → use secondary_cluster as partner
        dc_map = self._make_dc_map(('src', 'DC1'), ('dst', 'DC2'))
        result = _resolve_secondary_dc(dc_map, 'src', 'src', 'dst')
        assert result == 'DC2'

    def test_primary_cluster_used_as_partner_for_target_systems(self):
        # DataDomain TARGET case: sname == secondary_cluster, partner = primary_cluster
        dc_map = self._make_dc_map(('dd01', 'DC1'), ('dd02', 'DC2'))
        result = _resolve_secondary_dc(dc_map, 'dd02', 'dd01', 'dd02')
        assert result == 'DC1'

    def test_result_is_never_a_system_name(self):
        # When lookup fails (partner not in inventory), result must not be the
        # system name – it must be 'unknown'
        dc_map = {}  # empty inventory
        result = _resolve_secondary_dc(dc_map, 'fasmc1', 'fasmc1', 'FASMC2')
        assert result != 'FASMC2'
        assert result != 'fasmc2'
        assert result == 'unknown'
