"""Unit tests for TTL auto-delete exclusion rules."""
import json

from app.snap_ttl_auto_delete_exclusions import (
    normalize_rules_from_json,
    snapshot_matches_ttl_exclusion_rules,
    storage_tokens_from_locations,
)


def test_storage_tokens_fa_and_ontap():
    locs = {
        'flasharray_systems': [{'name': 'pure01', 'snapshot_names': ['x']}],
        'ontap_clusters': [{'cluster': 'clu1', 'svm': 'svm_x', 'volumes': []}],
    }
    t = storage_tokens_from_locations(locs)
    assert 'pure01' in t
    assert 'clu1' in t
    assert 'clu1/svm_x' in t


def test_normalize_empty():
    r, e = normalize_rules_from_json(None)
    assert r == [] and e is None


def test_normalize_invalid_type():
    r, e = normalize_rules_from_json('{}')
    assert 'Array' in (e or '')


def test_match_sid_only_glob():
    rules, _ = normalize_rules_from_json(json.dumps([{'sid': 'PRD*'}]))
    ok, idx = snapshot_matches_ttl_exclusion_rules(
        'PRD01',
        {'flasharray_systems': [{'name': 'other', 'snapshot_names': []}]},
        rules,
    )
    assert ok and idx == 0


def test_match_storage_and_sid():
    rules, _ = normalize_rules_from_json(json.dumps([{'storage': 'fa*', 'sid': 'EXP*'}]))
    locs = {'flasharray_systems': [{'name': 'fa01', 'snapshot_names': []}], 'ontap_clusters': []}
    assert snapshot_matches_ttl_exclusion_rules('EXPB', locs, rules)[0]
    assert not snapshot_matches_ttl_exclusion_rules('OTHER', locs, rules)[0]


def test_storage_pattern_must_match_when_not_wild():
    rules, _ = normalize_rules_from_json(json.dumps([{'storage': 'pure-*', 'sid': '*'}]))
    locs = {'flasharray_systems': [{'name': 'dd', 'snapshot_names': []}], 'ontap_clusters': []}
    assert not snapshot_matches_ttl_exclusion_rules('ACP', locs, rules)[0]


def test_ontap_cluster_token():
    rules, _ = normalize_rules_from_json(json.dumps([{'storage': 'clu*', 'sid': 'X'}]))
    locs = {'flasharray_systems': [], 'ontap_clusters': [{'cluster': 'clu99', 'svm': 's', 'volumes': []}]}
    assert snapshot_matches_ttl_exclusion_rules('X', locs, rules)[0]
