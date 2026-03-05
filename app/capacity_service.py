"""Capacity data service – hourly background refresh and aggregation helpers"""
import logging
import threading
import traceback
from datetime import datetime, date, timedelta

logger = logging.getLogger(__name__)

# Preferred display order for Storage Art categories.
# Any art not listed here is appended alphabetically after these entries.
STORAGE_ART_ORDER = ['Block', 'File', 'Object', 'Archiv', 'Backup']


def _art_sort_key(art: str):
    """Return a sort key that respects STORAGE_ART_ORDER, then alphabetical."""
    try:
        return (STORAGE_ART_ORDER.index(art), art)
    except ValueError:
        return (len(STORAGE_ART_ORDER), art)

# How often (seconds) the background thread refreshes capacity data
REFRESH_INTERVAL_SECONDS = 60 * 60  # 1 hour

# Module-level flag so that only one background thread is started per process
_background_thread_started = False
_thread_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Background refresh
# ---------------------------------------------------------------------------

def _do_refresh(app):
    """Fetch capacity for all enabled systems and persist snapshots."""
    from app import db
    from app.models import StorageSystem, CapacitySnapshot, CapacityHistory, AppSettings
    from app.api import get_client

    with app.app_context():
        systems = StorageSystem.query.filter_by(enabled=True).all()
        today = date.today()

        # Load Pure1 credentials once for the whole refresh cycle.
        # They are used to supplement physical capacity for Pure FlashArrays.
        settings = AppSettings.query.first()
        pure1_app_id = settings.pure1_app_id if settings else None
        pure1_private_key = settings.pure1_private_key if settings else None
        pure1_passphrase = settings.pure1_private_key_passphrase if settings else None
        pure1_configured = bool(pure1_app_id and pure1_private_key)

        # Build proxy dict once (shared with Pure1 calls).
        proxies = None
        if settings:
            proxy_http  = getattr(settings, 'proxy_http', None)
            proxy_https = getattr(settings, 'proxy_https', None)
            if proxy_http or proxy_https:
                proxies = {}
                if proxy_http:
                    proxies['http'] = proxy_http
                if proxy_https:
                    proxies['https'] = proxy_https

        for system in systems:
            # Fetch existing snapshot once; used both to preserve values on failure
            # and to upsert the snapshot after the API call.
            existing = CapacitySnapshot.query.filter_by(system_id=system.id).first()

            def _values_from_snapshot(snap):
                """Extract capacity fields from an existing snapshot (or return zeros)."""
                if snap is None:
                    return 0.0, 0.0, 0.0, 0.0, 0.0
                return snap.total_tb, snap.used_tb, snap.free_tb, snap.percent_used, snap.percent_free

            try:
                client = get_client(
                    vendor=system.vendor,
                    ip_address=system.ip_address,
                    port=system.port,
                    username=system.api_username,
                    password=system.api_password,
                    token=system.api_token
                )
                status = client.get_health_status()
                error_msg = status.get('error')

                if error_msg:
                    # API returned an error dict (e.g. missing credentials, unreachable).
                    # Preserve last known good capacity values from the existing snapshot.
                    total_tb, used_tb, free_tb, percent_used, percent_free = _values_from_snapshot(existing)
                else:
                    total_tb = status.get('capacity_total_tb', 0.0) or 0.0
                    used_tb = status.get('capacity_used_tb', 0.0) or 0.0
                    free_tb = round(total_tb - used_tb, 2)
                    percent_used = status.get('capacity_percent', 0.0) or 0.0
                    percent_free = round(100.0 - percent_used, 1) if total_tb > 0 else 0.0

                    # For Pure FlashArrays, supplement local capacity data with the
                    # physical used space from Pure1's subscription-assets API.
                    # Arrays enrolled in Evergreen One no longer report physical used
                    # space locally (space.total_physical is 0), so Pure1 is the only
                    # reliable source.  For non-Evergreen arrays the Pure1 value is
                    # equally valid and preferred for consistency.
                    if system.vendor == 'pure' and pure1_configured and total_tb > 0:
                        pure1_name = system.pure1_array_name or system.name
                        try:
                            from app.api.pure1_client import fetch_subscription_asset_physical_used
                            physical_bytes = fetch_subscription_asset_physical_used(
                                pure1_app_id,
                                pure1_private_key,
                                pure1_name,
                                passphrase=pure1_passphrase,
                                proxies=proxies,
                            )
                            if physical_bytes is not None:
                                pure1_used_tb = physical_bytes / (1024 ** 4)
                                logger.info(
                                    "Pure1 physical used for %s (%s): %.2f TB "
                                    "(local reported: %.2f TB)",
                                    system.name, pure1_name, pure1_used_tb, used_tb,
                                )
                                used_tb = round(pure1_used_tb, 2)
                                free_tb = round(total_tb - used_tb, 2)
                                percent_used = round(used_tb / total_tb * 100, 1) if total_tb > 0 else 0.0
                                percent_free = round(100.0 - percent_used, 1) if total_tb > 0 else 0.0
                        except Exception as p1_exc:
                            logger.warning(
                                "Pure1 physical-used fetch failed for %s (%s): %s – "
                                "falling back to local value",
                                system.name, pure1_name, p1_exc,
                            )

            except Exception as exc:
                logger.warning(f"Capacity refresh failed for {system.name}: {exc}")
                # Preserve capacity values from existing snapshot (last known good data)
                total_tb, used_tb, free_tb, percent_used, percent_free = _values_from_snapshot(existing)
                error_msg = str(exc)

            # Upsert latest snapshot (one row per system – replace old one)
            if existing:
                existing.fetched_at = datetime.utcnow()
                existing.total_tb = total_tb
                existing.used_tb = used_tb
                existing.free_tb = free_tb
                existing.percent_used = percent_used
                existing.percent_free = percent_free
                existing.error = error_msg
            else:
                snap = CapacitySnapshot(
                    system_id=system.id,
                    total_tb=total_tb,
                    used_tb=used_tb,
                    free_tb=free_tb,
                    percent_used=percent_used,
                    percent_free=percent_free,
                    error=error_msg
                )
                db.session.add(snap)

            # Write daily history entry (one row per system per day).
            # We skip creation (but still allow updates) when total_tb == 0 to avoid
            # polluting history with failed/unreachable systems that return zero capacity.
            hist = CapacityHistory.query.filter_by(system_id=system.id, date=today).first()
            if hist is None and total_tb > 0:
                hist = CapacityHistory(
                    system_id=system.id,
                    date=today,
                    total_tb=total_tb,
                    used_tb=used_tb,
                    free_tb=free_tb,
                    percent_used=percent_used,
                )
                db.session.add(hist)
            elif hist is not None:
                hist.total_tb = total_tb
                hist.used_tb = used_tb
                hist.free_tb = free_tb
                hist.percent_used = percent_used

        try:
            db.session.commit()
            logger.info("Capacity snapshot refresh completed for %d systems", len(systems))
        except Exception as exc:
            logger.error("Failed to commit capacity snapshots: %s", exc)
            db.session.rollback()


def _background_loop(app):
    """Run _do_refresh in a loop, sleeping REFRESH_INTERVAL_SECONDS between runs."""
    import time
    while True:
        try:
            _do_refresh(app)
        except Exception as exc:
            logger.error("Unhandled error in capacity background refresh: %s\n%s",
                         exc, traceback.format_exc())
        time.sleep(REFRESH_INTERVAL_SECONDS)


def start_background_refresh(app):
    """Start the hourly background refresh thread (idempotent – safe to call multiple times)."""
    global _background_thread_started
    with _thread_lock:
        if _background_thread_started:
            return
        thread = threading.Thread(
            target=_background_loop,
            args=(app,),
            daemon=True,
            name="capacity-refresh"
        )
        thread.start()
        _background_thread_started = True
        logger.info("Capacity background refresh thread started (interval=%ds)", REFRESH_INTERVAL_SECONDS)


def trigger_refresh(app):
    """Trigger an immediate (non-blocking) capacity refresh in a separate thread."""
    t = threading.Thread(target=_do_refresh, args=(app,), daemon=True, name="capacity-refresh-manual")
    t.start()


# ---------------------------------------------------------------------------
# Data aggregation helpers
# ---------------------------------------------------------------------------

def _zero_row():
    return {'total_tb': 0.0, 'used_tb': 0.0, 'free_tb': 0.0,
            'provisioned_tb': None, 'percent_used': 0.0, 'percent_free': 0.0,
            'percent_provisioned': None}


def _accumulate(row, other):
    """Add capacity values from dict or snapshot object into the accumulator row."""
    if isinstance(other, dict):
        row['total_tb'] += other.get('total_tb', 0.0) or 0.0
        row['used_tb'] += other.get('used_tb', 0.0) or 0.0
        row['free_tb'] += other.get('free_tb', 0.0) or 0.0
        provisioned = other.get('provisioned_tb')
        if provisioned is not None:
            row['provisioned_tb'] = (row['provisioned_tb'] or 0.0) + provisioned
    else:
        row['total_tb'] += other.total_tb or 0.0
        row['used_tb'] += other.used_tb or 0.0
        row['free_tb'] += other.free_tb or 0.0
        if hasattr(other, 'provisioned_tb') and other.provisioned_tb is not None:
            row['provisioned_tb'] = (row['provisioned_tb'] or 0.0) + other.provisioned_tb


def _finalize(row):
    """Recompute percentages after accumulation."""
    total = row['total_tb']
    if total > 0:
        row['percent_used'] = round(row['used_tb'] / total * 100, 1)
        row['percent_free'] = round(row['free_tb'] / total * 100, 1)
        if row['provisioned_tb'] is not None:
            row['percent_provisioned'] = round(row['provisioned_tb'] / total * 100, 1)
    else:
        row['percent_used'] = 0.0
        row['percent_free'] = 0.0
    row['total_tb'] = round(row['total_tb'], 2)
    row['used_tb'] = round(row['used_tb'], 2)
    row['free_tb'] = round(row['free_tb'], 2)
    if row['provisioned_tb'] is not None:
        row['provisioned_tb'] = round(row['provisioned_tb'], 2)
    return row


def _tags_by_group(system):
    """Return dict {group_name: [tag_name, ...]} for a system."""
    result = {}
    for tag in system.tags:
        gname = tag.group.name if tag.group else 'Sonstige'
        result.setdefault(gname, []).append(tag.name)
    return result


def get_latest_snapshots():
    """Return dict {system_id: CapacitySnapshot} for all systems."""
    from app.models import CapacitySnapshot
    snaps = CapacitySnapshot.query.all()
    return {s.system_id: s for s in snaps}


def build_by_storage_art(systems, snapshots):
    """
    Group by Storage Art → rows: Produktion, Test/Dev, Total.

    Returns list of:
      {'storage_art': str, 'rows': [{'label', 'total_tb', 'used_tb', ...}, ...],
       'total': {...}}
    """
    from collections import defaultdict

    # storage_art → environment → accumulated row
    data = defaultdict(lambda: defaultdict(_zero_row))

    for system in systems:
        snap = snapshots.get(system.id)
        if snap is None:
            continue
        tgs = _tags_by_group(system)
        arts = tgs.get('Storage Art', [])
        envs = tgs.get('Landschaft', [])
        if not arts:
            arts = ['Sonstige']
        if not envs:
            envs = ['Unbekannt']
        for art in arts:
            for env in envs:
                _accumulate(data[art][env], snap)

    result = []
    all_arts = sorted(data.keys(), key=_art_sort_key)
    for art in all_arts:
        env_data = data[art]
        rows = []
        total_row = _zero_row()
        for env in sorted(env_data.keys()):
            row = dict(env_data[env])
            row['label'] = env
            _finalize(row)
            rows.append(row)
            _accumulate(total_row, row)
        _finalize(total_row)
        result.append({'storage_art': art, 'rows': rows, 'total': total_row})
    return result


def build_by_environment(systems, snapshots):
    """
    Group by Landschaft (environment) → rows per Storage Art + Total.

    Returns list of:
      {'environment': str, 'rows': [{'label', ...}], 'total': {...}}
    """
    from collections import defaultdict

    data = defaultdict(lambda: defaultdict(_zero_row))

    for system in systems:
        snap = snapshots.get(system.id)
        if snap is None:
            continue
        tgs = _tags_by_group(system)
        arts = tgs.get('Storage Art', [])
        envs = tgs.get('Landschaft', [])
        if not arts:
            arts = ['Sonstige']
        if not envs:
            envs = ['Unbekannt']
        for env in envs:
            for art in arts:
                _accumulate(data[env][art], snap)

    result = []
    for env in sorted(data.keys()):
        art_data = data[env]
        rows = []
        total_row = _zero_row()
        for art in sorted(art_data.keys(), key=_art_sort_key):
            row = dict(art_data[art])
            row['label'] = art
            _finalize(row)
            rows.append(row)
            _accumulate(total_row, row)
        _finalize(total_row)
        result.append({'environment': env, 'rows': rows, 'total': total_row})
    return result


def build_by_department(systems, snapshots):
    """
    Group by Themenzugehörigkeit → rows per Environment × Storage Art + Total.

    Returns list of:
      {'department': str,
       'rows': [{'label': 'Produktion – Block', 'env', 'storage_art', ...}],
       'total': {...}}
    """
    from collections import defaultdict

    # dept → (env, art) → accumulated row
    data = defaultdict(lambda: defaultdict(_zero_row))

    for system in systems:
        snap = snapshots.get(system.id)
        if snap is None:
            continue
        tgs = _tags_by_group(system)
        depts = tgs.get('Themenzugehörigkeit', [])
        arts = tgs.get('Storage Art', [])
        envs = tgs.get('Landschaft', [])
        if not depts:
            depts = ['Sonstige']
        if not arts:
            arts = ['Sonstige']
        if not envs:
            envs = ['Unbekannt']
        for dept in depts:
            for env in envs:
                for art in arts:
                    _accumulate(data[dept][(env, art)], snap)

    result = []
    for dept in sorted(data.keys()):
        combo_data = data[dept]
        rows = []
        total_row = _zero_row()
        for (env, art) in sorted(combo_data.keys(), key=lambda x: (x[0], _art_sort_key(x[1]))):
            row = dict(combo_data[(env, art)])
            row['label'] = f'{env} – {art}'
            row['env'] = env
            row['storage_art'] = art
            _finalize(row)
            rows.append(row)
            _accumulate(total_row, row)
        _finalize(total_row)
        result.append({'department': dept, 'rows': rows, 'total': total_row})
    return result


def build_details(systems, snapshots):
    """
    All individual systems grouped by Storage Art.

    Returns list of:
      {'storage_art': str,
       'systems': [{'system_name', 'environment', 'department', 'total_tb', ...}]}
    """
    from collections import defaultdict

    groups = defaultdict(list)

    for system in systems:
        snap = snapshots.get(system.id)
        tgs = _tags_by_group(system)
        arts = tgs.get('Storage Art', ['Sonstige'])
        envs = tgs.get('Landschaft', ['Unbekannt'])
        depts = tgs.get('Themenzugehörigkeit', [])

        row = {
            'system_name': system.name,
            'environment': ', '.join(envs),
            'department': ', '.join(depts),
            'total_tb': 0.0, 'used_tb': 0.0, 'free_tb': 0.0,
            'provisioned_tb': None,
            'percent_used': 0.0, 'percent_free': 0.0,
            'percent_provisioned': None,
            'error': None,
        }
        if snap:
            row['total_tb'] = round(snap.total_tb or 0.0, 2)
            row['used_tb'] = round(snap.used_tb or 0.0, 2)
            row['free_tb'] = round(snap.free_tb or 0.0, 2)
            row['percent_used'] = snap.percent_used or 0.0
            row['percent_free'] = snap.percent_free or 0.0
            row['provisioned_tb'] = round(snap.provisioned_tb, 2) if snap.provisioned_tb is not None else None
            row['percent_provisioned'] = snap.percent_provisioned
            row['error'] = snap.error

        for art in arts:
            groups[art].append(dict(row))

    result = []
    for art in sorted(groups.keys(), key=_art_sort_key):
        result.append({'storage_art': art,
                       'systems': sorted(groups[art], key=lambda x: x['system_name'].lower())})
    return result


def get_history_data(days=None):
    """
    Return history grouped by Storage Art for chart rendering.

    days: None = all, or int = last N days

    Returns dict:
      {storage_art: {'labels': ['2024-01-01', ...],
                     'datasets': [{'label': 'Used TB', 'data': [...]}]}}
    """
    from collections import defaultdict
    from app.models import CapacityHistory, StorageSystem

    query = CapacityHistory.query.order_by(CapacityHistory.date)
    if days:
        cutoff = date.today() - timedelta(days=days)
        query = query.filter(CapacityHistory.date >= cutoff)
    records = query.all()

    # Build system → storage arts mapping
    systems = {s.id: s for s in StorageSystem.query.all()}
    system_arts = {}
    for sid, system in systems.items():
        tgs = _tags_by_group(system)
        system_arts[sid] = tgs.get('Storage Art', ['Sonstige'])

    # Accumulate used_tb per (date, storage_art)
    date_art_used = defaultdict(lambda: defaultdict(float))
    date_art_total = defaultdict(lambda: defaultdict(float))
    all_dates = sorted({r.date for r in records})

    for rec in records:
        arts = system_arts.get(rec.system_id, ['Sonstige'])
        for art in arts:
            date_art_used[rec.date][art] += rec.used_tb or 0.0
            date_art_total[rec.date][art] += rec.total_tb or 0.0

    # Collect all storage arts present
    all_arts = sorted({art for d_arts in date_art_used.values() for art in d_arts}, key=_art_sort_key)

    result = {}
    for art in all_arts:
        labels = [d.isoformat() for d in all_dates]
        used_data = [round(date_art_used[d].get(art, 0.0), 2) for d in all_dates]
        total_data = [round(date_art_total[d].get(art, 0.0), 2) for d in all_dates]
        result[art] = {
            'labels': labels,
            'used': used_data,
            'total': total_data,
        }
    return result


def get_weekly_history_data(days=None):
    """
    Return history aggregated by ISO calendar week for export.

    days: None = all, or int = last N days

    Returns list of dicts:
      [{'week': 'YYYY-Www', 'week_start': 'YYYY-MM-DD', 'storage_art': str,
        'total_tb': float, 'used_tb': float, 'free_tb': float, 'percent_used': float}]
    sorted by (week, storage_art).
    """
    from collections import defaultdict
    from app.models import CapacityHistory, StorageSystem

    query = CapacityHistory.query.order_by(CapacityHistory.date)
    if days:
        cutoff = date.today() - timedelta(days=days)
        query = query.filter(CapacityHistory.date >= cutoff)
    records = query.all()

    systems = {s.id: s for s in StorageSystem.query.all()}
    system_arts = {}
    for sid, system in systems.items():
        tgs = _tags_by_group(system)
        system_arts[sid] = tgs.get('Storage Art', ['Sonstige'])

    # Accumulate by (iso_week_str, week_start_date, storage_art)
    week_art_total = defaultdict(float)
    week_art_used = defaultdict(float)
    week_art_free = defaultdict(float)
    week_start_map = {}  # iso_week_str → week_start date

    for rec in records:
        arts = system_arts.get(rec.system_id, ['Sonstige'])
        iso = rec.date.isocalendar()
        week_str = f'{iso[0]}-W{iso[1]:02d}'
        # Monday of that ISO week (date.fromisocalendar available since Python 3.8)
        if week_str not in week_start_map:
            week_start_map[week_str] = date.fromisocalendar(iso[0], iso[1], 1)
        for art in arts:
            key = (week_str, art)
            week_art_total[key] += rec.total_tb or 0.0
            week_art_used[key] += rec.used_tb or 0.0
            week_art_free[key] += rec.free_tb or 0.0

    result = []
    for (week_str, art) in sorted(week_art_total.keys(), key=lambda k: (k[0], _art_sort_key(k[1]))):
        total = round(week_art_total[(week_str, art)], 2)
        used = round(week_art_used[(week_str, art)], 2)
        free = round(week_art_free[(week_str, art)], 2)
        pct = round(used / total * 100, 1) if total > 0 else 0.0
        result.append({
            'week': week_str,
            'week_start': week_start_map[week_str].isoformat(),
            'storage_art': art,
            'total_tb': total,
            'used_tb': used,
            'free_tb': free,
            'percent_used': pct,
        })
    return result


def import_history_from_csv(csv_file, system_map):
    """
    Import capacity history records from a CSV file object.

    Expected CSV columns (case-insensitive):
      date, system_name, total_tb, used_tb, free_tb, percent_used

    ``system_map`` is a dict {name_lower: StorageSystem} for name lookup.

    Returns (imported_count, skipped_count, errors[]).
    """
    import csv as _csv
    from app import db
    from app.models import CapacityHistory

    reader = _csv.DictReader(csv_file)
    imported = 0
    skipped = 0
    errors = []

    for row in reader:
        lineno = reader.line_num
        norm = {k.strip().lower(): v.strip() for k, v in row.items() if k}
        try:
            date_str = norm.get('date', '')
            system_name = norm.get('system_name', '')
            total_tb = float(norm.get('total_tb', 0) or 0)
            used_tb = float(norm.get('used_tb', 0) or 0)
            free_tb = float(norm.get('free_tb', 0) or 0)
            percent_used = float(norm.get('percent_used', 0) or 0)

            if not date_str or not system_name:
                errors.append(f'Zeile {lineno}: date und system_name sind Pflichtfelder.')
                skipped += 1
                continue

            try:
                rec_date = date.fromisoformat(date_str)
            except ValueError:
                errors.append(f'Zeile {lineno}: Ungültiges Datumsformat "{date_str}" (erwartet: YYYY-MM-DD).')
                skipped += 1
                continue
            system = system_map.get(system_name.lower())
            if system is None:
                errors.append(f'Zeile {lineno}: System "{system_name}" nicht gefunden – übersprungen.')
                skipped += 1
                continue

            existing = CapacityHistory.query.filter_by(system_id=system.id, date=rec_date).first()
            if existing:
                existing.total_tb = total_tb
                existing.used_tb = used_tb
                existing.free_tb = free_tb
                existing.percent_used = percent_used
            else:
                hist = CapacityHistory(
                    system_id=system.id,
                    date=rec_date,
                    total_tb=total_tb,
                    used_tb=used_tb,
                    free_tb=free_tb,
                    percent_used=percent_used,
                )
                db.session.add(hist)
            imported += 1
        except Exception as exc:
            errors.append(f'Zeile {lineno}: {exc}')
            skipped += 1

    db.session.commit()
    return imported, skipped, errors


def import_sod_history_from_csv(csv_file):
    """
    Import Storage on Demand (Pure1) historical data from a CSV file object.

    Expected CSV columns (case-insensitive):
      date, subscription_name, license_name, reserved_tb, effective_used_tb
    Optional column:
      service_tier

    Returns (imported_count, skipped_count, errors[]).
    """
    import csv as _csv
    from app import db
    from app.models import SodHistory

    reader = _csv.DictReader(csv_file)
    imported = 0
    skipped = 0
    errors = []

    for row in reader:
        lineno = reader.line_num
        norm = {k.strip().lower(): v.strip() for k, v in row.items() if k}
        try:
            date_str = norm.get('date', '')
            subscription_name = norm.get('subscription_name', '')
            license_name = norm.get('license_name', '')
            try:
                reserved_tb = float(norm.get('reserved_tb') or 0)
            except ValueError:
                errors.append(f'Zeile {lineno}: Ungültiger Wert für reserved_tb.')
                skipped += 1
                continue
            try:
                effective_used_tb = float(norm.get('effective_used_tb') or 0)
            except ValueError:
                errors.append(f'Zeile {lineno}: Ungültiger Wert für effective_used_tb.')
                skipped += 1
                continue
            service_tier = norm.get('service_tier') or None

            if not date_str or not subscription_name or not license_name:
                errors.append(
                    f'Zeile {lineno}: date, subscription_name und license_name sind Pflichtfelder.'
                )
                skipped += 1
                continue

            try:
                rec_date = date.fromisoformat(date_str)
            except ValueError:
                errors.append(
                    f'Zeile {lineno}: Ungültiges Datumsformat "{date_str}" (erwartet: YYYY-MM-DD).'
                )
                skipped += 1
                continue

            existing = SodHistory.query.filter_by(
                date=rec_date,
                subscription_name=subscription_name,
                license_name=license_name,
            ).first()
            if existing:
                existing.reserved_tb = reserved_tb
                existing.effective_used_tb = effective_used_tb
                if service_tier is not None:
                    existing.service_tier = service_tier
            else:
                hist = SodHistory(
                    date=rec_date,
                    subscription_name=subscription_name,
                    license_name=license_name,
                    service_tier=service_tier,
                    reserved_tb=reserved_tb,
                    effective_used_tb=effective_used_tb,
                )
                db.session.add(hist)
            imported += 1
        except Exception as exc:
            errors.append(f'Zeile {lineno}: {exc}')
            skipped += 1

    db.session.commit()
    return imported, skipped, errors


def import_sod_history_from_pure1(start_date, end_date) -> tuple:
    """Fetch historical SoD data directly from the Pure1 API and persist it.

    Uses ``app.api.pure1_client.fetch_sod_license_history`` to retrieve
    daily metrics for all subscription licenses in the given date range,
    then upserts the results into :class:`~app.models.SodHistory`.

    Args:
        start_date: :class:`datetime.date` – start of the history window.
        end_date:   :class:`datetime.date` – end of the history window (inclusive).

    Returns:
        ``(imported, skipped, errors)`` tuple where *imported* is the number of
        rows written/updated and *skipped*/*errors* capture any issues.

    Raises:
        RuntimeError: When Pure1 credentials are not configured.
    """
    from app import db
    from app.models import AppSettings, SodHistory
    from app.api.pure1_client import fetch_sod_license_history

    settings = AppSettings.query.first()
    if not settings or not settings.pure1_app_id or not settings.pure1_private_key:
        raise RuntimeError(
            "Pure1 API-Zugangsdaten nicht konfiguriert. "
            "Bitte unter Admin → Einstellungen → API-Zugänge konfigurieren."
        )

    items = fetch_sod_license_history(
        settings.pure1_app_id,
        settings.pure1_private_key,
        start_date=start_date,
        end_date=end_date,
        passphrase=settings.pure1_private_key_passphrase,
        proxies=settings.get_proxies() or None,
    )

    imported = 0
    skipped = 0
    errors = []

    for item in items:
        try:
            rec_date = item["date"]
            sub_name = item["subscription_name"]
            lic_name = item["license_name"]
            if not sub_name or not lic_name:
                errors.append(
                    f"{rec_date}: Fehlender subscription_name oder license_name – übersprungen."
                )
                skipped += 1
                continue

            existing = SodHistory.query.filter_by(
                date=rec_date,
                subscription_name=sub_name,
                license_name=lic_name,
            ).first()
            if existing:
                existing.reserved_tb = item["reserved_tb"]
                existing.effective_used_tb = item["effective_used_tb"]
                existing.on_demand_tb = item.get("on_demand_tb", 0.0) or 0.0
                existing.service_tier = item.get("service_tier")
            else:
                db.session.add(SodHistory(
                    date=rec_date,
                    subscription_name=sub_name,
                    license_name=lic_name,
                    service_tier=item.get("service_tier"),
                    reserved_tb=item["reserved_tb"],
                    effective_used_tb=item["effective_used_tb"],
                    on_demand_tb=item.get("on_demand_tb", 0.0) or 0.0,
                ))
            imported += 1
        except Exception as exc:
            errors.append(f"{item.get('date')}: {exc}")
            skipped += 1

    db.session.commit()
    return imported, skipped, errors


def compute_forecast(labels, values, forecast_days=90):
    """
    Simple linear regression forecast.

    Returns {'labels': [...], 'values': [...]} for the forecast period.
    Future labels are spaced at the same interval as the historical data so
    that the forecast portion of the chart is visually proportional to the
    history (avoids the forecast dominating the x-axis).
    Values are clamped to 0.0 so they are always non-negative.
    """
    if len(values) < 2:
        return {'labels': [], 'values': []}

    # Detect the typical step between consecutive data points so the forecast
    # labels match the historical data frequency (e.g. daily vs weekly).
    if len(labels) >= 2:
        step_days = max(1, (date.fromisoformat(labels[1]) - date.fromisoformat(labels[0])).days)
    else:
        step_days = 1

    n = len(values)
    xs = list(range(n))
    ys = values

    # Least-squares linear regression
    sum_x = sum(xs)
    sum_y = sum(ys)
    sum_xy = sum(x * y for x, y in zip(xs, ys))
    sum_x2 = sum(x * x for x in xs)
    denom = n * sum_x2 - sum_x ** 2
    if denom == 0:
        return {'labels': [], 'values': []}
    slope = (n * sum_xy - sum_x * sum_y) / denom
    intercept = (sum_y - slope * sum_x) / n

    # Generate future points at the same step interval as the historical data.
    # n_steps is the number of forecast steps derived from forecast_days.
    last_date = date.fromisoformat(labels[-1]) if labels else date.today()
    future_labels = []
    future_values = []
    n_steps = max(1, forecast_days // step_days)
    for i in range(1, n_steps + 1):
        future_date = last_date + timedelta(days=i * step_days)
        future_labels.append(future_date.isoformat())
        predicted = intercept + slope * (n - 1 + i)
        future_values.append(round(max(predicted, 0.0), 2))

    return {'labels': future_labels, 'values': future_values}


def get_sod_history_data(days=None):
    """Return aggregated SoD (Storage on Demand) history for chart rendering.

    Sums reserved_tb, effective_used_tb and on_demand_tb across all licenses
    per date, so the result represents the total contractual commitment and
    usage over time.

    days: None = all, or int = last N days

    Returns dict:
      {'labels': ['2024-01-01', ...],
       'reserved': [...],
       'effective_used': [...],
       'on_demand': [...]}
    or None when no SoD history rows exist.
    """
    from collections import defaultdict
    from app.models import SodHistory

    query = SodHistory.query.order_by(SodHistory.date)
    if days:
        cutoff = date.today() - timedelta(days=days)
        query = query.filter(SodHistory.date >= cutoff)
    records = query.all()

    if not records:
        return None

    date_reserved = defaultdict(float)
    date_effective = defaultdict(float)
    date_on_demand = defaultdict(float)

    for rec in records:
        d = rec.date
        date_reserved[d] += rec.reserved_tb or 0.0
        date_effective[d] += rec.effective_used_tb or 0.0
        date_on_demand[d] += rec.on_demand_tb or 0.0

    all_dates = sorted(date_reserved.keys())
    labels = [d.isoformat() for d in all_dates]
    reserved = [round(date_reserved[d], 2) for d in all_dates]
    effective_used = [round(date_effective[d], 2) for d in all_dates]
    on_demand = [round(date_on_demand[d], 2) for d in all_dates]

    return {
        'labels': labels,
        'reserved': reserved,
        'effective_used': effective_used,
        'on_demand': on_demand,
    }
