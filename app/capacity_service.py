"""Capacity data service – hourly background refresh and aggregation helpers"""
import logging
import threading
import traceback
from datetime import datetime, date, timedelta

logger = logging.getLogger(__name__)

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
    from app.models import StorageSystem, CapacitySnapshot, CapacityHistory
    from app.api import get_client

    with app.app_context():
        systems = StorageSystem.query.filter_by(enabled=True).all()
        today = date.today()

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
    else:
        row['total_tb'] += other.total_tb or 0.0
        row['used_tb'] += other.used_tb or 0.0
        row['free_tb'] += other.free_tb or 0.0


def _finalize(row):
    """Recompute percentages after accumulation."""
    total = row['total_tb']
    if total > 0:
        row['percent_used'] = round(row['used_tb'] / total * 100, 1)
        row['percent_free'] = round(row['free_tb'] / total * 100, 1)
    else:
        row['percent_used'] = 0.0
        row['percent_free'] = 0.0
    row['total_tb'] = round(row['total_tb'], 2)
    row['used_tb'] = round(row['used_tb'], 2)
    row['free_tb'] = round(row['free_tb'], 2)
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
    all_arts = sorted(data.keys())
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
        for art in sorted(art_data.keys()):
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
        for (env, art) in sorted(combo_data.keys()):
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
            'error': None,
        }
        if snap:
            row['total_tb'] = round(snap.total_tb or 0.0, 2)
            row['used_tb'] = round(snap.used_tb or 0.0, 2)
            row['free_tb'] = round(snap.free_tb or 0.0, 2)
            row['percent_used'] = snap.percent_used or 0.0
            row['percent_free'] = snap.percent_free or 0.0
            row['error'] = snap.error

        for art in arts:
            groups[art].append(dict(row))

    result = []
    for art in sorted(groups.keys()):
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
    all_arts = sorted({art for d_arts in date_art_used.values() for art in d_arts})

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


def compute_forecast(labels, values, forecast_days=90):
    """
    Simple linear regression forecast.

    Returns {'labels': [...], 'values': [...]} for the forecast period.
    Values list may contain None for days with no data.
    """
    if len(values) < 2:
        return {'labels': [], 'values': []}

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

    # Generate future points
    last_date = date.fromisoformat(labels[-1]) if labels else date.today()
    future_labels = []
    future_values = []
    for i in range(1, forecast_days + 1):
        future_date = last_date + timedelta(days=i)
        future_labels.append(future_date.isoformat())
        predicted = intercept + slope * (n - 1 + i)
        future_values.append(round(max(predicted, 0.0), 2))

    return {'labels': future_labels, 'values': future_values}
