"""Entscheidet, ob dieser Prozess Hintergrund-Threads starten soll.

Um doppelte Jobs bei mehreren Gunicorn-Workern zu vermeiden:

* ``BACKGROUND_JOBS_ENABLED=0`` – keine Hintergrund-Threads (z. B. reine Web-Worker).
* ``BACKGROUND_JOB_LOCKFILE=/pfad/zur/lockdatei`` – nur ein Prozess hält ein
  ``flock(LOCK_EX|LOCK_NB)``; andere überspringen den Start (Unix).

Ohne Lock-Datei verhalten sich alle Worker wie bisher (jeder startet Threads).
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

_job_lock_fp = None


def should_start_background_threads(app) -> bool:
    """True, wenn Capacity/Status/SoD/DR/Snap-Threads gestartet werden sollen."""
    raw = os.getenv('BACKGROUND_JOBS_ENABLED', '1').strip().lower()
    if raw in ('0', 'false', 'no', 'off'):
        app.logger.info('Background jobs disabled (BACKGROUND_JOBS_ENABLED).')
        return False

    lock_path = os.getenv('BACKGROUND_JOB_LOCKFILE', '').strip()
    if not lock_path:
        return True

    try:
        import fcntl
    except ImportError:
        app.logger.warning(
            'BACKGROUND_JOB_LOCKFILE is set but fcntl is unavailable; starting background jobs anyway.'
        )
        return True

    global _job_lock_fp
    try:
        fp = open(lock_path, 'a+', encoding='utf-8')
        fcntl.flock(fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        app.logger.info(
            'Another process holds the background-job lock (%s); skipping background threads.',
            lock_path,
        )
        return False
    except OSError as exc:
        app.logger.warning(
            'Could not acquire background-job lock (%s): %s; skipping background threads.',
            lock_path,
            exc,
        )
        return False

    _job_lock_fp = fp
    app.extensions['_background_job_lock_file'] = fp
    app.logger.info('Background job lock acquired: %s', lock_path)
    return True
