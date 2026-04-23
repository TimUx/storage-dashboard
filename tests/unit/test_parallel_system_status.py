"""Unit-Tests für parallele Status-Abfragen."""
from unittest.mock import MagicMock

import pytest

from app.parallel_system_status import MAX_PARALLEL_WORKERS, fetch_system_status_parallel


@pytest.mark.unit
def test_fetch_parallel_empty_systems():
    app = MagicMock()
    assert fetch_system_status_parallel([], app, lambda s, a: None) == []


@pytest.mark.unit
def test_fetch_parallel_calls_fetch_for_each_system():
    calls = []

    def fetch_fn(system, app_ref):
        calls.append((system.id, app_ref))
        return {'system': {'id': system.id, 'name': system.name}, 'status': {'status': 'online'}}

    app = MagicMock()
    systems = []
    for i in range(3):
        m = MagicMock()
        m.id = i + 1
        m.name = f'sys{i}'
        m.to_dict = MagicMock(return_value={'id': m.id, 'name': m.name})
        systems.append(m)

    out = fetch_system_status_parallel(systems, app, fetch_fn, log_failures=False)
    assert len(out) == 3
    assert {c[0] for c in calls} == {1, 2, 3}
    assert all(r['status']['status'] == 'online' for r in out)


@pytest.mark.unit
def test_fetch_parallel_failure_returns_error_status():
    def fetch_fn(system, app_ref):
        if system.id == 2:
            raise ConnectionError('refused')
        return {'system': system.to_dict(), 'status': {'status': 'online'}}

    app = MagicMock()
    s1 = MagicMock()
    s1.id, s1.name = 1, 'ok'
    s1.to_dict = MagicMock(return_value={'id': 1, 'name': 'ok'})
    s2 = MagicMock()
    s2.id, s2.name = 2, 'bad'
    s2.to_dict = MagicMock(return_value={'id': 2, 'name': 'bad'})

    out = fetch_system_status_parallel([s1, s2], app, fetch_fn, log_failures=False)
    assert len(out) == 2
    err = next(x for x in out if x['system']['id'] == 2)
    assert err['status']['status'] == 'error'
    assert 'refused' in err['status']['error']


@pytest.mark.unit
def test_max_workers_constant_is_32():
    assert MAX_PARALLEL_WORKERS == 32
