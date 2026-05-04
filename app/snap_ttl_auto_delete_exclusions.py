"""TTL auto-delete exclusion rules (Admin): wildcard match on storage + SID.

Rules are stored as JSON on :class:`app.models.settings.AppSettings`.
Each rule is ``{"storage": "<fnmatch pattern>", "sid": "<fnmatch pattern>"}``.
Omitted or empty ``storage`` / ``sid`` defaults to ``*`` (match any).
A rule matches a snapshot when **all** non-wildcard parts match: SID must
match the SID pattern and at least one storage token derived from
``storage_locations`` must match the storage pattern (unless storage is ``*``).
"""
from __future__ import annotations

import fnmatch
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def storage_tokens_from_locations(locs: dict | None) -> list[str]:
    """Names / cluster labels used for pattern matching (FlashArray + ONTAP)."""
    if not locs:
        return []
    out: list[str] = []
    for fa in locs.get('flasharray_systems') or []:
        n = (fa.get('name') or '').strip()
        if n:
            out.append(n)
    for oc in locs.get('ontap_clusters') or []:
        c = (oc.get('cluster') or '').strip()
        svm = (oc.get('svm') or '').strip()
        if c:
            out.append(c)
        if c and svm:
            out.append(f'{c}/{svm}')
    return out


def _pat_match(value: str, pattern: str) -> bool:
    """Case-insensitive ``fnmatch`` (``*``, ``?``, ``[seq]``)."""
    return fnmatch.fnmatchcase(value.upper(), pattern.strip().upper())


def normalize_rules_from_json(raw: str | None) -> tuple[list[dict[str, str]], str | None]:
    """Parse exclusion JSON. Returns ``(rules, error_message)``.

    ``rules`` entries are ``{'storage': str, 'sid': str}`` with non-empty patterns.
    """
    if raw is None or not str(raw).strip():
        return [], None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return [], f'Ungültiges JSON: {exc}'

    if not isinstance(data, list):
        return [], 'JSON muss ein Array von Regel-Objekten sein'

    rules: list[dict[str, str]] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            return [], f'Regel #{i + 1}: Objekt erwartet, nicht {type(item).__name__}'
        storage = (item.get('storage') or '*').strip() or '*'
        sid_pat = (item.get('sid') or '*').strip() or '*'
        if storage == '*' and sid_pat == '*':
            logger.warning('TTL auto-delete exclusion rule #%s skipped (nur Platzhalter *)', i + 1)
            continue
        rules.append({'storage': storage, 'sid': sid_pat})

    return rules, None


def snapshot_matches_ttl_exclusion_rules(
    sid: str,
    locs: dict | None,
    rules: list[dict[str, str]],
) -> tuple[bool, int | None]:
    """Return ``(matches, rule_index)`` if this snapshot is excluded by any rule."""
    if not rules or not sid:
        return False, None
    sid_u = sid.strip().upper()
    tokens = storage_tokens_from_locations(locs)

    for idx, rule in enumerate(rules):
        sp = rule['storage']
        sip = rule['sid']
        if not _pat_match(sid_u, sip):
            continue
        if sp == '*':
            return True, idx
        if not tokens:
            continue
        if any(_pat_match(t, sp) for t in tokens):
            return True, idx
    return False, None


def preview_excluded_snapshots(
    records: list[Any],
    raw_json: str | None,
    *,
    limit: int = 500,
) -> tuple[list[dict[str, Any]], str | None, int]:
    """Build preview rows for admin UI. Returns ``(rows, parse_error, total_match_count)``."""
    rules, err = normalize_rules_from_json(raw_json)
    if err:
        return [], err, 0
    if not rules:
        return [], None, 0

    matches: list[tuple[Any, int]] = []
    for rec in records:
        ok, ridx = snapshot_matches_ttl_exclusion_rules(rec.sid, rec.get_storage_locations(), rules)
        if ok and ridx is not None:
            matches.append((rec, ridx))

    total = len(matches)
    locs_preview_max = 120

    def fmt_row(rec: Any, ridx: int) -> dict[str, Any]:
        locs = rec.get_storage_locations()
        tokens = storage_tokens_from_locations(locs)
        stor = ', '.join(tokens)
        if len(stor) > locs_preview_max:
            stor = stor[: locs_preview_max - 1] + '…'
        ttl_s = rec.ttl.isoformat() + 'Z' if getattr(rec, 'ttl', None) else None
        return {
            'id': rec.id,
            'sid': rec.sid,
            'ttl': ttl_s,
            'storage_summary': stor or '–',
            'matched_rule_index': ridx,
            'matched_rule': rules[ridx],
        }

    rows = [fmt_row(rec, ridx) for rec, ridx in matches[:limit]]
    return rows, None, total
