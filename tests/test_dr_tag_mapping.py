"""Tests for DR Planner tag-based environment and DataCenter mapping.

Verifies that:
- The environment is resolved from the "Landschaft" tag group
  ("Produktion" → production, "Test/Dev" → test, anything else → unknown).
- The DataCenter site name is resolved from the "DataCenter" tag group.

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
    """Reproduce the tag-scanning loop from api_systems()."""
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
                sys_dc_map[ss.name] = tag_name
    return sys_env_map, sys_dc_map


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
