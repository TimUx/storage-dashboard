"""Realistische Testdaten-Builder für ORM-Modelle."""
from __future__ import annotations

import json
from datetime import datetime, timedelta


def storage_system_kwargs(**overrides):
    """Standardfelder für :class:`app.models.StorageSystem`."""
    base = {
        'name': 'FA-PROD-DC01',
        'vendor': 'pure',
        'ip_address': '10.120.44.50',
        'port': 443,
        'enabled': True,
        'snaps_enabled': True,
        'api_username': 'apiuser',
        'api_password': 'secret-api-pass',
        'api_token': 'pure-api-token-hex',
    }
    base.update(overrides)
    return base


def ontap_system_kwargs(**overrides):
    kw = storage_system_kwargs(
        name='NTAP-CL01',
        vendor='netapp-ontap',
        api_token=None,
        api_username='admin',
        api_password='ontap-secret',
    )
    kw.update(overrides)
    return kw


def status_cache_payload_online(**extra):
    """Typischer erfolgreicher Status-Cache (Pure/ONTAP-ähnlich)."""
    payload = {
        'status': 'online',
        'hardware_status': 'ok',
        'cluster_status': 'ok',
        'alerts': 0,
        'capacity_total_tb': 100.0,
        'capacity_used_tb': 42.5,
        'capacity_percent': 42.5,
    }
    payload.update(extra)
    return payload


def snapshot_record_kwargs(sid='PRD', hours_old=12, **overrides):
    """Felder für :class:`app.models.SnapshotRecord` (naiv UTC)."""
    now = datetime.utcnow()
    created = now - timedelta(hours=hours_old)
    ttl = now + timedelta(days=7)
    locs = {
        'flasharray_systems': [
            {'name': 'FA-01', 'snapshot_names': [f'{sid}_1_data.HDBSNAP-2026-01-01-120000']},
        ],
    }
    base = {
        'sid': sid,
        'creation_time': created,
        'ttl': ttl,
        'flasharray_present': True,
        'ontap_present': False,
        'comment': 'Demo snapshot for pytest',
        'storage_locations': json.dumps(locs),
    }
    base.update(overrides)
    return base
