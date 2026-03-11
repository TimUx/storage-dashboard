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
from app.models import StorageSystem, TagGroup, Tag, CapacitySnapshot, CapacityHistory, SodHistory

# ---------------------------------------------------------------------------
# Demo system definitions
# Each entry:  (name, vendor, ip, port, tags_dict, total_tb, used_tb)
# tags_dict keys must match TagGroup names seeded by migrations.py
# ---------------------------------------------------------------------------
DEMO_SYSTEMS = [
    # ── Block ──────────────────────────────────────────────────────────────
    {
        'name': 'Pure-Block-PROD-Mandant1-01',
        'vendor': 'pure',
        'ip': '10.10.1.11',
        'port': 443,
        'tags': {'Storage Art': 'Block', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'Mandant-1'},
        'total_tb': 800.0,
        'used_tb': 568.0,       # 71 %
        'provisioned_tb': 1600.0,  # 200 % – typical overprovisioning for block
    },
    {
        'name': 'Pure-Block-PROD-Mandant2-01',
        'vendor': 'pure',
        'ip': '10.10.1.12',
        'port': 443,
        'tags': {'Storage Art': 'Block', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'Mandant-2'},
        'total_tb': 600.0,
        'used_tb': 378.0,       # 63 %
        'provisioned_tb': 900.0,   # 150 %
    },
    {
        'name': 'Pure-Block-PROD-Apps-01',
        'vendor': 'pure',
        'ip': '10.10.1.13',
        'port': 443,
        'tags': {'Storage Art': 'Block', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'Apps'},
        'total_tb': 455.0,
        'used_tb': 41.0,        # 9 %
        'provisioned_tb': 500.0,   # 110 %
    },
    {
        'name': 'Pure-Block-Test-Mandant1-01',
        'vendor': 'pure',
        'ip': '10.10.1.21',
        'port': 443,
        'tags': {'Storage Art': 'Block', 'Landschaft': 'Test/Dev', 'Themenzugehörigkeit': 'Mandant-1'},
        'total_tb': 350.0,
        'used_tb': 245.0,       # 70 %
        'provisioned_tb': 600.0,   # 171 %
    },
    {
        'name': 'Pure-Block-Test-Mandant2-01',
        'vendor': 'pure',
        'ip': '10.10.1.22',
        'port': 443,
        'tags': {'Storage Art': 'Block', 'Landschaft': 'Test/Dev', 'Themenzugehörigkeit': 'Mandant-2'},
        'total_tb': 250.0,
        'used_tb': 178.0,       # 71 %
        'provisioned_tb': 380.0,   # 152 %
    },
    # ── File ───────────────────────────────────────────────────────────────
    {
        'name': 'NetApp-File-PROD-Mandant1-01',
        'vendor': 'netapp-ontap',
        'ip': '10.10.2.11',
        'port': 443,
        'tags': {'Storage Art': 'File', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'Mandant-1'},
        'total_tb': 1200.0,
        'used_tb': 756.0,       # 63 %
        'provisioned_tb': 3600.0,  # 300 % – NFS/CIFS thin provisioning typical
    },
    {
        'name': 'NetApp-File-PROD-Mandant2-01',
        'vendor': 'netapp-ontap',
        'ip': '10.10.2.12',
        'port': 443,
        'tags': {'Storage Art': 'File', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'Mandant-2'},
        'total_tb': 800.0,
        'used_tb': 432.0,       # 54 %
        'provisioned_tb': 2000.0,  # 250 %
    },
    {
        'name': 'NetApp-File-Test-Mandant1-01',
        'vendor': 'netapp-ontap',
        'ip': '10.10.2.21',
        'port': 443,
        'tags': {'Storage Art': 'File', 'Landschaft': 'Test/Dev', 'Themenzugehörigkeit': 'Mandant-1'},
        'total_tb': 300.0,
        'used_tb': 132.0,       # 44 %
        'provisioned_tb': 600.0,   # 200 %
    },
    {
        'name': 'NetApp-File-Test-Mandant2-01',
        'vendor': 'netapp-ontap',
        'ip': '10.10.2.22',
        'port': 443,
        'tags': {'Storage Art': 'File', 'Landschaft': 'Test/Dev', 'Themenzugehörigkeit': 'Mandant-2'},
        'total_tb': 200.0,
        'used_tb': 82.0,        # 41 %
        'provisioned_tb': 350.0,   # 175 %
    },
    # ── Archiv ─────────────────────────────────────────────────────────────
    {
        'name': 'NetApp-Archiv-PROD-Mandant1-WORM',
        'vendor': 'netapp-ontap',
        'ip': '10.10.3.11',
        'port': 443,
        'tags': {'Storage Art': 'Archiv', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'Mandant-1'},
        'total_tb': 1148.0,
        'used_tb': 986.0,   # 86 %
    },
    {
        'name': 'NetApp-Archiv-PROD-Mandant2-MAIL',
        'vendor': 'netapp-ontap',
        'ip': '10.10.3.12',
        'port': 443,
        'tags': {'Storage Art': 'Archiv', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'Mandant-2'},
        'total_tb': 1176.0,
        'used_tb': 652.0,   # 55 %
    },
    # ── Object ─────────────────────────────────────────────────────────────
    {
        'name': 'StorageGRID-Object-PROD-Mandant1',
        'vendor': 'netapp-storagegrid',
        'ip': '10.10.4.11',
        'port': 443,
        'tags': {'Storage Art': 'Object', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'Mandant-1'},
        'total_tb': 2500.0,
        'used_tb': 835.0,   # 33 %
    },
    {
        'name': 'StorageGRID-Object-PROD-Mandant2',
        'vendor': 'netapp-storagegrid',
        'ip': '10.10.4.12',
        'port': 443,
        'tags': {'Storage Art': 'Object', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'Mandant-2'},
        'total_tb': 1041.0,
        'used_tb': 103.0,   # 10 %
    },
    {
        'name': 'StorageGRID-Object-Test-Mandant1',
        'vendor': 'netapp-storagegrid',
        'ip': '10.10.4.21',
        'port': 443,
        'tags': {'Storage Art': 'Object', 'Landschaft': 'Test/Dev', 'Themenzugehörigkeit': 'Mandant-1'},
        'total_tb': 400.0,
        'used_tb': 160.0,   # 40 %
    },
    # ── Backup ─────────────────────────────────────────────────────────────
    {
        'name': 'DataDomain-Backup-PROD-Mandant1',
        'vendor': 'dell-datadomain',
        'ip': '10.10.5.11',
        'port': 3009,
        'tags': {'Storage Art': 'Backup', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'Mandant-1'},
        'total_tb': 1434.0,
        'used_tb': 1060.0,  # 74 %
    },
    {
        'name': 'DataDomain-Backup-Test-Mandant1',
        'vendor': 'dell-datadomain',
        'ip': '10.10.5.21',
        'port': 3009,
        'tags': {'Storage Art': 'Backup', 'Landschaft': 'Test/Dev', 'Themenzugehörigkeit': 'Mandant-1'},
        'total_tb': 1441.0,
        'used_tb': 1007.0,  # 70 %
    },
    {
        'name': 'DataDomain-Backup-PROD-Mandant2',
        'vendor': 'dell-datadomain',
        'ip': '10.10.5.12',
        'port': 3009,
        'tags': {'Storage Art': 'Backup', 'Landschaft': 'Produktion', 'Themenzugehörigkeit': 'Mandant-2'},
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
            SodHistory.query.delete()
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
            provisioned_tb = sdef.get('provisioned_tb')  # None for non-Block/File types
            pct_provisioned = round(provisioned_tb / total_tb * 100, 1) if provisioned_tb is not None and total_tb > 0 else None

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
            snap.provisioned_tb = provisioned_tb
            snap.percent_provisioned = pct_provisioned
            snap.error = None

            # Generate 2-year daily history (linear growth → current used).
            # For provisioned_tb we hold the current value constant (it changes
            # rarely in practice compared to actual usage growth).
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
                        provisioned_tb=provisioned_tb,
                    )
                    db.session.add(hist)
                else:
                    hist.total_tb = total_tb
                    hist.used_tb = day_used
                    hist.free_tb = day_free
                    hist.percent_used = day_pct
                    hist.provisioned_tb = provisioned_tb

        db.session.commit()
        print()
        print('✓ Demo data seeded successfully.')
        print(f'  Systems:  {StorageSystem.query.count()}')
        print(f'  Snapshots: {CapacitySnapshot.query.count()}')
        print(f'  History rows: {CapacityHistory.query.count()}')
        print()

        # ── Seed SoD (Storage on Demand) history ──────────────────────────
        print('Seeding Storage on Demand (SoD) history…')
        _seed_sod_history(app, today, start_date, history_days)
        print(f'  SoD history rows: {SodHistory.query.count()}')
        print()
        print('Open http://localhost:5000/capacity/ to view the Kapazitätsreport.')


# ---------------------------------------------------------------------------
# SoD history helper
# ---------------------------------------------------------------------------

# Demo SoD contracts: (subscription_name, license_name, service_tier,
#                       reserved_end_tb, effective_used_end_tb, on_demand_end_tb)
_SOD_DEMO_LICENSES = [
    ('Contract-Mandant1-2023', 'Pure-EO-Block-Mandant1-Gold',   '//GOLD',   500.0, 380.0, 15.0),
    ('Contract-Mandant1-2023', 'Pure-EO-Block-Mandant1-Silver',  '//SILVER', 300.0, 210.0,  8.0),
    ('Contract-Mandant2-2022', 'Pure-EO-Block-Mandant2-Gold',    '//GOLD',   400.0, 290.0, 12.0),
    ('Contract-Apps-2024',     'Pure-EO-Block-Apps-Platinum',    '//PLATINUM', 200.0, 45.0,  2.0),
]


def _seed_sod_history(app, today, start_date, history_days):
    """Seed weekly SoD history records for demo purposes."""
    import math
    with app.app_context():
        for sub_name, lic_name, tier, res_end, eff_end, od_end in _SOD_DEMO_LICENSES:
            # Start at 50 % of end values 2 years ago; grow with slight S-curve
            res_start = round(res_end * 0.85, 2)   # reserved changes slowly
            eff_start = round(eff_end * 0.35, 2)
            od_start  = round(od_end * 0.10, 2)

            # Weekly data points (every 7 days)
            week_offsets = range(0, history_days, 7)
            for offset in week_offsets:
                day = start_date + timedelta(days=offset)
                t = offset / max(history_days - 1, 1)
                smooth_t = t * t * (3 - 2 * t)

                reserved       = round(res_start + (res_end - res_start) * smooth_t, 2)
                effective_used = round(eff_start + (eff_end - eff_start) * smooth_t, 2)
                on_demand      = round(od_start  + (od_end  - od_start)  * smooth_t, 2)

                existing = SodHistory.query.filter_by(
                    date=day,
                    subscription_name=sub_name,
                    license_name=lic_name,
                ).first()
                if existing:
                    existing.reserved_tb = reserved
                    existing.effective_used_tb = effective_used
                    existing.on_demand_tb = on_demand
                else:
                    db.session.add(SodHistory(
                        date=day,
                        subscription_name=sub_name,
                        license_name=lic_name,
                        service_tier=tier,
                        reserved_tb=reserved,
                        effective_used_tb=effective_used,
                        on_demand_tb=on_demand,
                    ))
        db.session.commit()


if __name__ == '__main__':
    reset = os.environ.get('DEMO_RESET', '0') == '1'
    seed(reset=reset)
