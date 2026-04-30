"""Disaster Recovery (DR) build service.

Architecture mirrors ``sod_service`` and ``capacity_service``:
- A single daemon thread runs ``_background_loop`` and calls ``_do_build``
  once on startup, then sleeps for ``DR_BUILD_INTERVAL_SECONDS``.
- ``trigger_build`` spawns a one-shot thread for on-demand rebuilds.
- Stored artifacts are retrieved via helper functions; the UI never
  calls storage APIs directly.

DR Build Pipeline:
  1. Discover DR relationships via DRDiscoveryEngine
  2. Retrieve system configuration via existing API clients
  3. Build DR topology models
  4. Generate DR workflows
  5. Generate Mermaid diagrams
  6. Generate CLI command sets
  7. Generate DR runbook structures
  8. Store all generated artifacts in PostgreSQL
"""
import json
import logging
import os
import threading
import time
import traceback
from queue import Queue
from datetime import datetime

logger = logging.getLogger(__name__)

# Build interval – configurable via DR_BUILD_INTERVAL_SECONDS env var.
# Default: once per week (7 days).
DR_BUILD_INTERVAL_SECONDS = int(os.getenv('DR_BUILD_INTERVAL_SECONDS', str(7 * 24 * 60 * 60)))
DR_SYSTEM_FETCH_TIMEOUT_SECONDS = int(os.getenv('DR_SYSTEM_FETCH_TIMEOUT_SECONDS', '60'))
DR_STALE_RUNNING_BUILD_SECONDS = int(os.getenv('DR_STALE_RUNNING_BUILD_SECONDS', '3600'))
DR_DATADOMAIN_FAST_HEALTH_FETCH = os.getenv('DR_DATADOMAIN_FAST_HEALTH_FETCH', '1').strip().lower() in {
    '1', 'true', 'yes', 'on'
}

_background_thread_started = False
_thread_lock = threading.Lock()
_build_lock = threading.Lock()

# Event for manual rebuild trigger
_rebuild_event = threading.Event()


# ---------------------------------------------------------------------------
# Exclusion logic
# ---------------------------------------------------------------------------

def _is_dr_excluded(system) -> bool:
    """Return True when *system* must be excluded from DR failover.

    ONTAP systems tagged with *both*:
    - tag group "Landschaft", tag name "File"   (landscape = file services)
    - tag group "Storage Art", tag name "Backup" (storage type = backup)

    are outside the DR scope and must be ignored by the DR planner.

    Dell DataDomain systems are *never* excluded regardless of their tags –
    DataDomain MTree replication is a first-class DR scenario and DataDomain
    appliances are typically tagged as backup systems, which must not cause
    them to be silently dropped from the DR planner.

    The tag check is case-insensitive and ignores surrounding whitespace.
    """
    # DataDomain systems are always included in DR scope
    vendor = (getattr(system, 'vendor', '') or '').lower()
    if vendor == 'dell-datadomain':
        return False

    has_file_landscape = False
    has_backup_storage_art = False
    for tag in (system.tags or []):
        group_name = (tag.group.name if tag.group else '').strip().lower()
        tag_name = tag.name.strip().lower()
        if group_name == 'landschaft' and tag_name == 'file':
            has_file_landscape = True
        elif group_name == 'storage art' and tag_name == 'backup':
            has_backup_storage_art = True
    return has_file_landscape and has_backup_storage_art


# ---------------------------------------------------------------------------
# Build pipeline
# ---------------------------------------------------------------------------

def _do_build(app):
    """Run the full DR build pipeline within the given app context."""
    from app import db
    from app.models import (
        StorageSystem,
        DRBuildMetadata, DRRelationship, DRTopologyModel,
        DRWorkflow, DRRunbook, DRCommandSet, DRMermaidDiagram,
    )
    from app.dr_generators import (
        DRDiscoveryEngine, DRTopologyBuilder,
        DRWorkflowGenerator, DRRunbookGenerator,
        DRCommandGenerator, DRDiagramGenerator,
    )

    with _build_lock:
        with app.app_context():
            _mark_stale_running_builds_error()
            start_time = datetime.utcnow()
            build = DRBuildMetadata(
                build_timestamp=start_time,
                build_status='running',
                systems_processed=0,
                dr_relationships_detected=0,
            )
            db.session.add(build)
            try:
                db.session.commit()
            except Exception as exc:
                logger.error("Failed to create DR build record: %s", exc)
                db.session.rollback()
                return

            build_id = build.id
            systems_processed = 0
            total_relationships = 0
            error_message = None

            try:
                systems = StorageSystem.query.filter_by(enabled=True).all()
                discovery_engine = DRDiscoveryEngine()
                topology_builder = DRTopologyBuilder()
                workflow_gen = DRWorkflowGenerator()
                runbook_gen = DRRunbookGenerator()
                command_gen = DRCommandGenerator()
                diagram_gen = DRDiagramGenerator()

                for system in systems:
                    if _is_dr_excluded(system):
                        logger.debug(
                            "DR build: skipping %s (Landschaft=File, Storage Art=Backup – outside DR scope)",
                            system.name,
                        )
                        continue
                    systems_processed += 1
                    try:
                        # The DR build pipeline calls storage APIs directly to get full
                        # system configuration including DR-specific fields (activecluster,
                        # metrocluster, snapmirror, etc.) that are not preserved in the
                        # normalized StatusCache. This is correct: API calls happen only
                        # during the scheduled build pipeline, not on page rendering.
                        health_data = _fetch_live_health_with_timeout(
                            system, timeout_seconds=DR_SYSTEM_FETCH_TIMEOUT_SECONDS
                        )

                        if not health_data:
                            continue

                        # Step 1: Discover DR relationships
                        relationships = discovery_engine.discover(
                            system.name, system.vendor, health_data
                        )

                        for rel_dict in relationships:
                            total_relationships += 1
                            rel_dict_copy = dict(rel_dict)

                            # Store relationship
                            dr_rel = DRRelationship(
                                build_id=build_id,
                                system_name=rel_dict_copy['system_name'],
                                vendor=rel_dict_copy['vendor'],
                                replication_type=rel_dict_copy['replication_type'],
                                primary_site=rel_dict_copy.get('primary_site', ''),
                                secondary_site=rel_dict_copy.get('secondary_site', ''),
                                primary_cluster=rel_dict_copy.get('primary_cluster', ''),
                                secondary_cluster=rel_dict_copy.get('secondary_cluster', ''),
                                replication_state=rel_dict_copy.get('replication_state', 'unknown'),
                                relationship_data=json.dumps(rel_dict_copy.get('relationship_data', {})),
                            )
                            db.session.add(dr_rel)
                            db.session.flush()  # get dr_rel.id

                            # Step 2: Build topology
                            topo_data = topology_builder.build(rel_dict_copy)
                            db.session.add(DRTopologyModel(
                                build_id=build_id,
                                relationship_id=dr_rel.id,
                                system_name=rel_dict_copy['system_name'],
                                vendor=rel_dict_copy['vendor'],
                                topology_data=json.dumps(topo_data),
                            ))

                            from app.dr_generators import _FAILOVER_DIRECTIONS
                            # MetroCluster, SnapMirror, and DataDomain all support
                            # disaster_recovery in addition to planned_failover and failback.
                            # Other replication types only use the base two directions.
                            replication_type = rel_dict_copy.get('replication_type', '')
                            if replication_type in ('metrocluster', 'snapmirror',
                                                    'datadomain-replication',
                                                    'activecluster'):
                                directions = _FAILOVER_DIRECTIONS
                            else:
                                directions = ['planned_failover', 'failback']

                            for direction in directions:
                                # Step 3: Generate workflow
                                workflow_steps = workflow_gen.generate(rel_dict_copy, direction)
                                db.session.add(DRWorkflow(
                                    build_id=build_id,
                                    relationship_id=dr_rel.id,
                                    system_name=rel_dict_copy['system_name'],
                                    vendor=rel_dict_copy['vendor'],
                                    failover_direction=direction,
                                    workflow_data=json.dumps(workflow_steps),
                                ))

                                # Step 4: Generate CLI commands
                                commands = command_gen.generate(rel_dict_copy, direction)
                                db.session.add(DRCommandSet(
                                    build_id=build_id,
                                    relationship_id=dr_rel.id,
                                    system_name=rel_dict_copy['system_name'],
                                    vendor=rel_dict_copy['vendor'],
                                    failover_direction=direction,
                                    phase='all',
                                    commands_data=json.dumps(commands),
                                ))

                                # Step 5: Generate runbook
                                runbook_sections = runbook_gen.generate(rel_dict_copy, direction)
                                db.session.add(DRRunbook(
                                    build_id=build_id,
                                    relationship_id=dr_rel.id,
                                    system_name=rel_dict_copy['system_name'],
                                    vendor=rel_dict_copy['vendor'],
                                    failover_direction=direction,
                                    runbook_data=json.dumps(runbook_sections),
                                ))

                                # Step 6: Generate Mermaid workflow diagram
                                wf_diagram = diagram_gen.generate_workflow(rel_dict_copy, direction)
                                db.session.add(DRMermaidDiagram(
                                    build_id=build_id,
                                    relationship_id=dr_rel.id,
                                    system_name=rel_dict_copy['system_name'],
                                    vendor=rel_dict_copy['vendor'],
                                    diagram_type=f'workflow_{direction}',
                                    diagram_definition=wf_diagram,
                                ))

                            # Step 7: Generate topology diagram (once per relationship)
                            topo_diagram = diagram_gen.generate_topology(rel_dict_copy)
                            db.session.add(DRMermaidDiagram(
                                build_id=build_id,
                                relationship_id=dr_rel.id,
                                system_name=rel_dict_copy['system_name'],
                                vendor=rel_dict_copy['vendor'],
                                diagram_type='topology',
                                diagram_definition=topo_diagram,
                            ))

                    except Exception as exc:
                        logger.error(
                            "DR build failed for system %s: %s\n%s",
                            system.name, exc, traceback.format_exc()
                        )

                db.session.commit()
                duration = (datetime.utcnow() - start_time).total_seconds()
                build.build_status = 'success'
                build.build_duration_seconds = duration
                build.systems_processed = systems_processed
                build.dr_relationships_detected = total_relationships
                db.session.commit()

                logger.info(
                    "DR build #%d completed: %d systems, %d relationships, %.1fs",
                    build_id, systems_processed, total_relationships, duration
                )

            except Exception as exc:
                error_message = str(exc)
                logger.error("DR build pipeline failed: %s\n%s", exc, traceback.format_exc())
                try:
                    db.session.rollback()
                    duration = (datetime.utcnow() - start_time).total_seconds()
                    build.build_status = 'error'
                    build.build_duration_seconds = duration
                    build.systems_processed = systems_processed
                    build.dr_relationships_detected = total_relationships
                    build.error_message = error_message
                    db.session.commit()
                except Exception:
                    pass


def _mark_stale_running_builds_error():
    """Mark abandoned running builds as error to avoid permanent 'running' state."""
    from app import db
    from app.models import DRBuildMetadata

    now = datetime.utcnow()
    running_builds = DRBuildMetadata.query.filter_by(build_status='running').all()
    changed = False
    for stale in running_builds:
        if not stale.build_timestamp:
            continue
        age = (now - stale.build_timestamp).total_seconds()
        if age < DR_STALE_RUNNING_BUILD_SECONDS:
            continue
        stale.build_status = 'error'
        stale.error_message = (
            f"Build exceeded {DR_STALE_RUNNING_BUILD_SECONDS}s without completion; "
            "marked as stale by watchdog."
        )
        stale.build_duration_seconds = age
        changed = True

    if changed:
        db.session.commit()


def _fetch_live_health(system, progress=None):
    """Fetch live health data from a storage system as fallback."""
    started = time.monotonic()
    try:
        from app.api import get_client
        client = get_client(
            vendor=system.vendor,
            ip_address=system.ip_address,
            port=system.port,
            username=system.api_username,
            password=system.api_password,
            token=system.api_token,
        )
        vendor = (getattr(system, 'vendor', '') or '').lower()
        if vendor == 'dell-datadomain' and DR_DATADOMAIN_FAST_HEALTH_FETCH:
            def _dd_progress(event, step, elapsed_seconds):
                if progress is None:
                    return
                if event == 'start':
                    progress['last_started_step'] = step
                    progress['last_started_at'] = time.monotonic()
                elif event == 'done':
                    progress['last_completed_step'] = step
                    progress['last_completed_elapsed_seconds'] = elapsed_seconds

            data = client.get_health_status(
                include_optional_details=False,
                progress_callback=_dd_progress,
            )
        else:
            data = client.get_health_status()
        logger.info(
            "Live health fetch completed for %s (%s) in %.2fs.",
            system.name,
            system.vendor,
            time.monotonic() - started,
        )
        return data
    except Exception as exc:
        logger.warning(
            "Live health fetch failed for %s after %.2fs: %s",
            system.name,
            time.monotonic() - started,
            exc,
        )
        return {}


def _fetch_live_health_with_timeout(system, timeout_seconds=60):
    """Fetch health with a hard timeout guard to prevent stuck DR builds."""
    result_q = Queue(maxsize=1)
    progress = {}

    def _worker():
        try:
            result_q.put((True, _fetch_live_health(system, progress=progress)))
        except Exception as exc:
            result_q.put((False, exc))

    worker = threading.Thread(target=_worker, name=f"dr-health-{system.name}", daemon=True)
    worker.start()
    if timeout_seconds and timeout_seconds > 0:
        worker.join(timeout=timeout_seconds)
    else:
        # No hard timeout: wait until complete to prefer completeness over speed.
        worker.join()

    if timeout_seconds and timeout_seconds > 0 and worker.is_alive():
        last_started = progress.get('last_started_step')
        last_done = progress.get('last_completed_step')
        step_runtime = None
        if progress.get('last_started_at') is not None:
            step_runtime = time.monotonic() - progress['last_started_at']
        logger.warning(
            (
                "Live health fetch timeout for %s after %ss; skipping system. "
                "last_started_step=%s%s%s"
            ),
            system.name,
            timeout_seconds,
            last_started or '-',
            ", last_completed_step=",
            last_done or '-',
        )
        if step_runtime is not None:
            logger.warning(
                "Live health fetch timeout context for %s: current_step_runtime=%.2fs",
                system.name,
                step_runtime,
            )
        last_done_elapsed = progress.get('last_completed_elapsed_seconds')
        if last_done and last_done_elapsed is not None:
            logger.warning(
                "Live health fetch timeout context for %s: last_completed_step_duration=%.2fs",
                system.name,
                last_done_elapsed,
            )
        return {}

    if result_q.empty():
        return {}

    success, payload = result_q.get()
    if success:
        return payload or {}
    logger.warning("Live health fetch failed for %s: %s", system.name, payload)
    return {}


# ---------------------------------------------------------------------------
# Background loop
# ---------------------------------------------------------------------------

def _background_loop(app):
    """Main background loop: run DR build on startup, then at configured interval."""
    while True:
        try:
            _do_build(app)
        except Exception as exc:
            logger.error(
                "Unhandled error in DR background build: %s\n%s",
                exc, traceback.format_exc(),
            )
        # Wait for either the interval or a manual rebuild trigger
        _rebuild_event.wait(timeout=DR_BUILD_INTERVAL_SECONDS)
        _rebuild_event.clear()


def start_background_refresh(app):
    """Start the DR build background thread (idempotent).

    Called once from create_app().  Subsequent calls are no-ops.
    """
    global _background_thread_started

    with _thread_lock:
        if _background_thread_started:
            return
        _background_thread_started = True

    thread = threading.Thread(
        target=_background_loop,
        args=(app,),
        name='dr-build',
        daemon=True,
    )
    thread.start()
    logger.info("DR build background thread started (interval=%ds).", DR_BUILD_INTERVAL_SECONDS)


def trigger_rebuild(app):
    """Trigger an immediate DR rebuild (one-shot thread for responsiveness)."""
    def _run():
        try:
            _do_build(app)
        except Exception as exc:
            logger.error("Manual DR rebuild failed: %s\n%s", exc, traceback.format_exc())
        finally:
            _rebuild_event.set()

    thread = threading.Thread(target=_run, name='dr-manual-build', daemon=True)
    thread.start()
    logger.info("Manual DR rebuild triggered.")


# ---------------------------------------------------------------------------
# Data access helpers (used by UI routes – no live API calls)
# ---------------------------------------------------------------------------

def get_latest_build(include_running=False):
    """Return newest DR build metadata.

    By default only completed builds are considered so UI data endpoints keep
    showing the last usable data while a new build is still running.
    """
    from app.models import DRBuildMetadata
    query = DRBuildMetadata.query
    if not include_running:
        query = query.filter(DRBuildMetadata.build_status == 'success')
    return query.order_by(DRBuildMetadata.build_timestamp.desc()).first()


def get_dr_relationships(build_id=None):
    """Return DRRelationship rows for the given build (or latest build)."""
    from app.models import DRBuildMetadata, DRRelationship
    if build_id is None:
        latest = get_latest_build()
        if not latest:
            return []
        build_id = latest.id
    return DRRelationship.query.filter_by(build_id=build_id).all()


def get_topology(system_name, build_id=None):
    """Return DRTopologyModel for the given system_name in the given build."""
    from app.models import DRBuildMetadata, DRTopologyModel
    if build_id is None:
        latest = get_latest_build()
        if not latest:
            return None
        build_id = latest.id
    return (
        DRTopologyModel.query
        .filter_by(build_id=build_id, system_name=system_name)
        .first()
    )


def get_workflow(system_name, failover_direction='planned_failover', build_id=None):
    """Return DRWorkflow for the given system and direction."""
    from app.models import DRBuildMetadata, DRWorkflow
    if build_id is None:
        latest = get_latest_build()
        if not latest:
            return None
        build_id = latest.id
    return (
        DRWorkflow.query
        .filter_by(build_id=build_id, system_name=system_name, failover_direction=failover_direction)
        .first()
    )


def get_runbook(system_name, failover_direction='planned_failover', build_id=None):
    """Return DRRunbook for the given system and direction."""
    from app.models import DRBuildMetadata, DRRunbook
    if build_id is None:
        latest = get_latest_build()
        if not latest:
            return None
        build_id = latest.id
    return (
        DRRunbook.query
        .filter_by(build_id=build_id, system_name=system_name, failover_direction=failover_direction)
        .first()
    )


def get_command_set(system_name, failover_direction='planned_failover', build_id=None):
    """Return DRCommandSet for the given system and direction."""
    from app.models import DRBuildMetadata, DRCommandSet
    if build_id is None:
        latest = get_latest_build()
        if not latest:
            return None
        build_id = latest.id
    return (
        DRCommandSet.query
        .filter_by(build_id=build_id, system_name=system_name, failover_direction=failover_direction)
        .first()
    )


def get_diagram(system_name, diagram_type='topology', build_id=None):
    """Return DRMermaidDiagram for the given system and diagram type."""
    from app.models import DRBuildMetadata, DRMermaidDiagram
    if build_id is None:
        latest = get_latest_build()
        if not latest:
            return None
        build_id = latest.id
    return (
        DRMermaidDiagram.query
        .filter_by(build_id=build_id, system_name=system_name, diagram_type=diagram_type)
        .first()
    )
