#!/usr/bin/env python3
"""
Seed realistic demo data for the Storage Dashboard.

Creates storage systems with tags, current capacity snapshots and
2 years of daily history – so all views of the Kapazitätsreport
(/capacity/) show meaningful data immediately.

Usage (from repository root):
    python examples/seed_demo_data.py

Set DEMO_RESET=1 to wipe all existing systems/snapshots first:
    DEMO_RESET=1 python examples/seed_demo_data.py
"""
import os
import sys
import random
from datetime import date, datetime, timedelta

# Make sure the repo root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault('SECRET_KEY', 'demo-seed-secret-key')

from app import create_app, db
from app.models import StorageSystem, TagGroup, Tag, CapacitySnapshot, CapacityHistory

# ---------------------------------------------------------------------------
# Demo system definitions
# Each entry:  (name, vendor, ip, port, tags_dict, total_tb, used_tb)
# tags_dict keys must match TagGroup names seeded by migrations.py
# ---------------------------------------------------------------------------
DEMO_SYSTEMS = [
    # ── Block ──────────────────────────────────────────────────────────────
    {
        'name': 'Pure-Block-PROD-ITS-01',
        'vendor': 'pure',
        'ip': '10.10.1.11',
        'port': 443,
        'tags': {'Storage Art': 'Block', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'ITS'},
        'total_tb': 800.0,
        'used_tb': 568.0,   # 71 %
    },
    {
        'name': 'Pure-Block-PROD-ERZ-01',
        'vendor': 'pure',
        'ip': '10.10.1.12',
        'port': 443,
        'tags': {'Storage Art': 'Block', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'ERZ'},
        'total_tb': 600.0,
        'used_tb': 378.0,   # 63 %
    },
    {
        'name': 'Pure-Block-PROD-EH-01',
        'vendor': 'pure',
        'ip': '10.10.1.13',
        'port': 443,
        'tags': {'Storage Art': 'Block', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'EH'},
        'total_tb': 455.0,
        'used_tb': 41.0,    # 9 %
    },
    {
        'name': 'Pure-Block-TEST-ITS-01',
        'vendor': 'pure',
        'ip': '10.10.1.21',
        'port': 443,
        'tags': {'Storage Art': 'Block', 'Landschaft': 'Test/Dev', 'Themenzugehörigkeit': 'ITS'},
        'total_tb': 350.0,
        'used_tb': 245.0,   # 70 %
    },
    {
        'name': 'Pure-Block-TEST-ERZ-01',
        'vendor': 'pure',
        'ip': '10.10.1.22',
        'port': 443,
        'tags': {'Storage Art': 'Block', 'Landschaft': 'Test/Dev', 'Themenzugehörigkeit': 'ERZ'},
        'total_tb': 250.0,
        'used_tb': 178.0,   # 71 %
    },
    # ── File ───────────────────────────────────────────────────────────────
    {
        'name': 'NetApp-File-PROD-ITS-01',
        'vendor': 'netapp-ontap',
        'ip': '10.10.2.11',
        'port': 443,
        'tags': {'Storage Art': 'File', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'ITS'},
        'total_tb': 1200.0,
        'used_tb': 756.0,   # 63 %
    },
    {
        'name': 'NetApp-File-PROD-ERZ-01',
        'vendor': 'netapp-ontap',
        'ip': '10.10.2.12',
        'port': 443,
        'tags': {'Storage Art': 'File', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'ERZ'},
        'total_tb': 800.0,
        'used_tb': 432.0,   # 54 %
    },
    {
        'name': 'NetApp-File-TEST-ITS-01',
        'vendor': 'netapp-ontap',
        'ip': '10.10.2.21',
        'port': 443,
        'tags': {'Storage Art': 'File', 'Landschaft': 'Test/Dev', 'Themenzugehörigkeit': 'ITS'},
        'total_tb': 300.0,
        'used_tb': 132.0,   # 44 %
    },
    {
        'name': 'NetApp-File-TEST-ERZ-01',
        'vendor': 'netapp-ontap',
        'ip': '10.10.2.22',
        'port': 443,
        'tags': {'Storage Art': 'File', 'Landschaft': 'Test/Dev', 'Themenzugehörigkeit': 'ERZ'},
        'total_tb': 200.0,
        'used_tb': 82.0,    # 41 %
    },
    # ── Archiv ─────────────────────────────────────────────────────────────
    {
        'name': 'NetApp-Archiv-PROD-ITS-WORM',
        'vendor': 'netapp-ontap',
        'ip': '10.10.3.11',
        'port': 443,
        'tags': {'Storage Art': 'Archiv', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'ITS'},
        'total_tb': 1148.0,
        'used_tb': 986.0,   # 86 %
    },
    {
        'name': 'NetApp-Archiv-PROD-ERZ-MAIL',
        'vendor': 'netapp-ontap',
        'ip': '10.10.3.12',
        'port': 443,
        'tags': {'Storage Art': 'Archiv', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'ERZ'},
        'total_tb': 1176.0,
        'used_tb': 652.0,   # 55 %
    },
    # ── Object ─────────────────────────────────────────────────────────────
    {
        'name': 'StorageGRID-Object-PROD-ITS',
        'vendor': 'netapp-storagegrid',
        'ip': '10.10.4.11',
        'port': 443,
        'tags': {'Storage Art': 'Object', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'ITS'},
        'total_tb': 2500.0,
        'used_tb': 835.0,   # 33 %
    },
    {
        'name': 'StorageGRID-Object-PROD-ERZ',
        'vendor': 'netapp-storagegrid',
        'ip': '10.10.4.12',
        'port': 443,
        'tags': {'Storage Art': 'Object', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'ERZ'},
        'total_tb': 1041.0,
        'used_tb': 103.0,   # 10 %
    },
    {
        'name': 'StorageGRID-Object-TEST-ITS',
        'vendor': 'netapp-storagegrid',
        'ip': '10.10.4.21',
        'port': 443,
        'tags': {'Storage Art': 'Object', 'Landschaft': 'Test/Dev', 'Themenzugehörigkeit': 'ITS'},
        'total_tb': 400.0,
        'used_tb': 160.0,   # 40 %
    },
    # ── Backup ─────────────────────────────────────────────────────────────
    {
        'name': 'DataDomain-Backup-PROD-ITS',
        'vendor': 'dell-datadomain',
        'ip': '10.10.5.11',
        'port': 3009,
        'tags': {'Storage Art': 'Backup', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'ITS'},
        'total_tb': 1434.0,
        'used_tb': 1060.0,  # 74 %
    },
    {
        'name': 'DataDomain-Backup-TEST-ITS',
        'vendor': 'dell-datadomain',
        'ip': '10.10.5.21',
        'port': 3009,
        'tags': {'Storage Art': 'Backup', 'Landschaft': 'Test/Dev', 'Themenzugehörigkeit': 'ITS'},
        'total_tb': 1441.0,
        'used_tb': 1007.0,  # 70 %
    },
    {
        'name': 'DataDomain-Backup-PROD-ERZ',
        'vendor': 'dell-datadomain',
        'ip': '10.10.5.12',
        'port': 3009,
        'tags': {'Storage Art': 'Backup', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'ERZ'},
        'total_tb': 1408.0,
        'used_tb': 798.0,   # 57 %
    },
]

# ---------------------------------------------------------------------------
# History generation helpers
# ---------------------------------------------------------------------------

def _growth_curve(start_used, end_used, num_days, jitter_pct=0.015):
    """
    Generate a smooth daily used-TB series from start_used → end_used
    with small random day-to-day jitter.
    """
    values = []
    random.seed(hash(start_used) % 9999)
    for i in range(num_days):
        t = i / max(num_days - 1, 1)
        # Slight S-curve via smoothstep
        smooth_t = t * t * (3 - 2 * t)
        base = start_used + (end_used - start_used) * smooth_t
        jitter = base * jitter_pct * (random.random() * 2 - 1)
        values.append(round(max(base + jitter, 0.0), 2))
    return values


# ---------------------------------------------------------------------------
# Main seeding logic
# ---------------------------------------------------------------------------

def seed(reset=False):
    app = create_app()
    with app.app_context():
        if reset:
            print('Resetting existing systems, snapshots and history…')
            CapacityHistory.query.delete()
            CapacitySnapshot.query.delete()
            StorageSystem.query.delete()
            db.session.commit()

        # Fetch tag lookup: {group_name: {tag_name: Tag}}
        tag_lookup = {}
        for group in TagGroup.query.all():
            tag_lookup[group.name] = {t.name: t for t in group.tags}

        today = date.today()
        history_days = 730  # 2 years
        start_date = today - timedelta(days=history_days - 1)

        print(f'Seeding {len(DEMO_SYSTEMS)} demo storage systems…')

        for sdef in DEMO_SYSTEMS:
            # Create or update StorageSystem
            system = StorageSystem.query.filter_by(name=sdef['name']).first()
            if system is None:
                system = StorageSystem(
                    name=sdef['name'],
                    vendor=sdef['vendor'],
                    ip_address=sdef['ip'],
                    port=sdef['port'],
                    enabled=True,
                    cluster_type='local',
                )
                db.session.add(system)
                db.session.flush()
                print(f'  Created system: {system.name}')
            else:
                print(f'  Updated system: {system.name}')

            # Assign tags
            system.tags = []
            for group_name, tag_name in sdef['tags'].items():
                tag = tag_lookup.get(group_name, {}).get(tag_name)
                if tag:
                    system.tags.append(tag)
                else:
                    print(f'    ⚠ Tag "{tag_name}" in group "{group_name}" not found – skipping')

            db.session.flush()

            total_tb = sdef['total_tb']
            used_tb = sdef['used_tb']
            free_tb = round(total_tb - used_tb, 2)
            pct_used = round(used_tb / total_tb * 100, 1) if total_tb > 0 else 0.0
            pct_free = round(100.0 - pct_used, 1)

            # Upsert current snapshot
            snap = CapacitySnapshot.query.filter_by(system_id=system.id).first()
            if snap is None:
                snap = CapacitySnapshot(system_id=system.id)
                db.session.add(snap)
            snap.fetched_at = datetime.utcnow()
            snap.total_tb = total_tb
            snap.used_tb = used_tb
            snap.free_tb = free_tb
            snap.percent_used = pct_used
            snap.percent_free = pct_free
            snap.error = None

            # Generate 2-year daily history (linear growth → current used)
            # Assume systems started ~40 % used 2 years ago
            start_used = round(used_tb * 0.40, 2)
            daily_values = _growth_curve(start_used, used_tb, history_days)

            for i, day_used in enumerate(daily_values):
                day = start_date + timedelta(days=i)
                hist = CapacityHistory.query.filter_by(
                    system_id=system.id, date=day
                ).first()
                day_free = round(total_tb - day_used, 2)
                day_pct = round(day_used / total_tb * 100, 1) if total_tb > 0 else 0.0
                if hist is None:
                    hist = CapacityHistory(
                        system_id=system.id,
                        date=day,
                        total_tb=total_tb,
                        used_tb=day_used,
                        free_tb=day_free,
                        percent_used=day_pct,
                    )
                    db.session.add(hist)
                else:
                    hist.total_tb = total_tb
                    hist.used_tb = day_used
                    hist.free_tb = day_free
                    hist.percent_used = day_pct

        db.session.commit()
        print()
        print('✓ Demo data seeded successfully.')
        print(f'  Systems:  {StorageSystem.query.count()}')
        print(f'  Snapshots: {CapacitySnapshot.query.count()}')
        print(f'  History rows: {CapacityHistory.query.count()}')
        print()
        print('Open http://localhost:5000/capacity/ to view the Kapazitätsreport.')


if __name__ == '__main__':
    reset = os.environ.get('DEMO_RESET', '0') == '1'
    seed(reset=reset)
