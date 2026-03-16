"""Tests for DR system exclusion logic.

ONTAP systems tagged with *both*
  Landschaft = "File"   (tag group "Landschaft", tag name "File")
  Storage Art = "Backup" (tag group "Storage Art", tag name "Backup")
must be excluded from the DR planner.  All other tag combinations must
be included.

Dell DataDomain systems (vendor='dell-datadomain') must NEVER be excluded
regardless of their tags, because DataDomain MTree replication is a
first-class DR scenario.
"""

from types import SimpleNamespace

import pytest

from app.dr_service import _is_dr_excluded


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tag(name, group_name):
    group = SimpleNamespace(name=group_name)
    return SimpleNamespace(name=name, group=group)


def _make_system(*tags, vendor=None):
    ns = SimpleNamespace(tags=list(tags))
    if vendor is not None:
        ns.vendor = vendor
    return ns


# ---------------------------------------------------------------------------
# Exclusion tests
# ---------------------------------------------------------------------------

class TestIsDrExcluded:

    def test_no_tags_not_excluded(self):
        assert _is_dr_excluded(_make_system()) is False

    def test_tags_is_none_not_excluded(self):
        system = SimpleNamespace(tags=None)
        assert _is_dr_excluded(system) is False

    # --- only one of the two required tags present ---

    def test_only_file_landscape_not_excluded(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('File', 'Landschaft'),
        )) is False

    def test_only_backup_storage_art_not_excluded(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('Backup', 'Storage Art'),
        )) is False

    # --- both required tags present → excluded ---

    def test_both_tags_excluded(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('File', 'Landschaft'),
            _make_tag('Backup', 'Storage Art'),
        )) is True

    def test_both_tags_excluded_reversed_order(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('Backup', 'Storage Art'),
            _make_tag('File', 'Landschaft'),
        )) is True

    # --- case insensitivity ---

    def test_case_insensitive_tag_name_lowercase(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('file', 'Landschaft'),
            _make_tag('backup', 'Storage Art'),
        )) is True

    def test_case_insensitive_tag_name_uppercase(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('FILE', 'Landschaft'),
            _make_tag('BACKUP', 'Storage Art'),
        )) is True

    def test_case_insensitive_group_names(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('File', 'LANDSCHAFT'),
            _make_tag('Backup', 'STORAGE ART'),
        )) is True

    def test_case_insensitive_mixed(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('file', 'Landschaft'),
            _make_tag('Backup', 'storage art'),
        )) is True

    # --- wrong tag values ---

    def test_different_tags_not_excluded(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('SAN', 'Storage Art'),
            _make_tag('DC1', 'Landschaft'),
        )) is False

    def test_backup_but_wrong_landscape_not_excluded(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('Backup', 'Storage Art'),
            _make_tag('SAN', 'Landschaft'),
        )) is False

    def test_file_but_wrong_storage_art_not_excluded(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('File', 'Landschaft'),
            _make_tag('NAS', 'Storage Art'),
        )) is False

    def test_backup_in_wrong_group_not_excluded(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('File', 'Landschaft'),
            _make_tag('Backup', 'Environment'),   # wrong group
        )) is False

    def test_file_in_wrong_group_not_excluded(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('File', 'Storage Art'),     # wrong group
            _make_tag('Backup', 'Storage Art'),
        )) is False

    # --- additional tags do not affect outcome ---

    def test_extra_tags_still_excluded(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('File', 'Landschaft'),
            _make_tag('Backup', 'Storage Art'),
            _make_tag('production', 'Environment'),
        )) is True

    def test_extra_tags_without_required_not_excluded(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('SAN', 'Storage Art'),
            _make_tag('production', 'Environment'),
        )) is False

    # --- whitespace tolerance ---

    def test_leading_trailing_whitespace_in_tag_name(self):
        assert _is_dr_excluded(_make_system(
            _make_tag(' File ', 'Landschaft'),
            _make_tag(' Backup ', 'Storage Art'),
        )) is True

    def test_leading_trailing_whitespace_in_group_name(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('File', ' Landschaft '),
            _make_tag('Backup', ' Storage Art '),
        )) is True


# ---------------------------------------------------------------------------
# DataDomain systems are NEVER excluded (vendor='dell-datadomain')
# ---------------------------------------------------------------------------

class TestDataDomainNeverExcluded:

    def test_datadomain_no_tags_not_excluded(self):
        assert _is_dr_excluded(_make_system(vendor='dell-datadomain')) is False

    def test_datadomain_with_backup_tag_not_excluded(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('Backup', 'Storage Art'),
            vendor='dell-datadomain',
        )) is False

    def test_datadomain_with_file_landscape_not_excluded(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('File', 'Landschaft'),
            vendor='dell-datadomain',
        )) is False

    def test_datadomain_with_both_exclusion_tags_still_not_excluded(self):
        """DataDomain systems with BOTH exclusion tags must still appear in the DR planner."""
        assert _is_dr_excluded(_make_system(
            _make_tag('File', 'Landschaft'),
            _make_tag('Backup', 'Storage Art'),
            vendor='dell-datadomain',
        )) is False

    def test_datadomain_uppercase_vendor_not_excluded(self):
        assert _is_dr_excluded(_make_system(
            _make_tag('File', 'Landschaft'),
            _make_tag('Backup', 'Storage Art'),
            vendor='DELL-DATADOMAIN',
        )) is False
