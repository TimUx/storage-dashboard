"""Admin dashboard, storage system CRUD, discovery, API docs links."""
import logging
from collections import defaultdict
from datetime import datetime

from flask import current_app, flash, redirect, render_template, request, url_for
from flask_login import login_required

from app import db
from app.constants import (
    STANDARD_PORTS,
    VENDOR_DEFAULT_PORTS,
    VENDOR_PORT_DESCRIPTIONS,
)
from app.discovery import auto_discover_system
from app.models import StorageSystem, Tag, TagGroup
from app.routes.admin import bp

logger = logging.getLogger(__name__)


@bp.route('/')
@login_required
def index():
    """Admin dashboard"""
    # Tag filter: OR within same group, AND across groups
    tag_ids = request.args.getlist('tag', type=int)
    query = StorageSystem.query
    if tag_ids:
        # Load the selected tags to know their groups
        selected_tags = Tag.query.filter(Tag.id.in_(tag_ids)).all()
        # Group tag IDs by their group_id
        group_to_tag_ids = defaultdict(list)
        for t in selected_tags:
            group_to_tag_ids[t.group_id].append(t.id)
        # AND across groups, OR within each group
        for ids in group_to_tag_ids.values():
            query = query.filter(StorageSystem.tags.any(Tag.id.in_(ids)))
    systems = query.order_by(StorageSystem.name).all()
    tag_groups = TagGroup.query.order_by(TagGroup.name).all()
    return render_template(
        'admin/index.html',
        systems=systems,
        tag_groups=tag_groups,
        selected_tag_ids=tag_ids,
    )


@bp.route('/systems/new', methods=['GET', 'POST'])
@login_required
def new_system():
    """Create new storage system with auto-discovery"""
    if request.method == 'POST':
        try:
            vendor = request.form['vendor']

            # Determine default port based on vendor if not specified
            default_port = VENDOR_DEFAULT_PORTS.get(vendor, 443)
            port = int(request.form.get('port', default_port))

            # Create system with basic info
            system = StorageSystem(
                name=request.form['name'],
                vendor=vendor,
                ip_address=request.form['ip_address'],
                port=port,
                api_username=request.form.get('api_username', '').strip() or None,
                api_password=request.form.get('api_password', '').strip() or None,
                api_token=request.form.get('api_token', '').strip() or None,
                pure1_array_name=request.form.get('pure1_array_name', '').strip() or None,
                enabled=request.form.get('enabled') == 'on',
                snaps_enabled=request.form.get('snaps_enabled') == 'on',
            )

            # Auto-discover system details
            discovery_result = auto_discover_system(
                vendor=system.vendor,
                ip_address=system.ip_address,
                username=system.api_username,
                password=system.api_password,
                api_token=system.api_token,
                ssl_verify=False  # Could be made configurable
            )

            # Update system with discovered info
            if 'error' not in discovery_result:
                system.cluster_type = discovery_result.get('cluster_type')
                system.node_count = discovery_result.get('node_count')
                system.site_count = discovery_result.get('site_count')
                system.set_dns_names(discovery_result.get('dns_names', []))
                system.set_all_ips(discovery_result.get('all_ips', []))
                system.set_node_details(discovery_result.get('node_details', []))

                # Save HA info if present (for DataDomain)
                if discovery_result.get('ha_info'):
                    system.set_ha_info(discovery_result.get('ha_info'))

                # Save OS version and API version if present
                if discovery_result.get('os_version'):
                    system.os_version = discovery_result.get('os_version')
                if discovery_result.get('api_version'):
                    system.api_version = discovery_result.get('api_version')

                system.last_discovery = datetime.utcnow()

                flash(f'System added and discovered successfully! Found {system.node_count or 0} nodes.', 'success')
            else:
                system.discovery_error = discovery_result.get('error')
                system.set_dns_names(discovery_result.get('dns_names', []))
                system.set_all_ips(discovery_result.get('all_ips', []))
                flash(f'System added but discovery had issues: {discovery_result.get("error")}', 'warning')

            db.session.add(system)

            # Handle tag assignment
            selected_tag_ids = request.form.getlist('tags')
            system.tags = Tag.query.filter(Tag.id.in_([int(t) for t in selected_tag_ids if t.isdigit()])).all()

            db.session.commit()
            return redirect(url_for('admin.index'))

        except Exception as e:
            logger.error(f'Error adding system: {e}', exc_info=True)
            flash(f'Error adding system: {str(e)}', 'error')

    tag_groups = TagGroup.query.order_by(TagGroup.name).all()
    return render_template(
        'admin/form.html',
        system=None,
        action='Create',
        vendor_ports=VENDOR_DEFAULT_PORTS,
        vendor_port_descriptions=VENDOR_PORT_DESCRIPTIONS,
        standard_ports=STANDARD_PORTS,
        tag_groups=tag_groups,
    )


@bp.route('/systems/<int:system_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_system(system_id):
    """Edit storage system"""
    system = StorageSystem.query.get_or_404(system_id)

    if request.method == 'POST':
        try:
            vendor = request.form['vendor']

            # Determine default port based on vendor if not specified
            default_port = VENDOR_DEFAULT_PORTS.get(vendor, 443)
            port = int(request.form.get('port', default_port))

            system.name = request.form['name']
            system.vendor = vendor
            system.ip_address = request.form['ip_address']
            system.port = port
            system.api_username = request.form.get('api_username', '').strip() or None
            system.api_password = request.form.get('api_password', '').strip() or None
            system.api_token = request.form.get('api_token', '').strip() or None
            system.pure1_array_name = request.form.get('pure1_array_name', '').strip() or None
            system.enabled = request.form.get('enabled') == 'on'
            system.snaps_enabled = request.form.get('snaps_enabled') == 'on'

            # Handle tag assignment
            selected_tag_ids = request.form.getlist('tags')
            system.tags = Tag.query.filter(Tag.id.in_([int(t) for t in selected_tag_ids if t.isdigit()])).all()

            db.session.commit()
            flash('Storage system updated successfully', 'success')
            return redirect(url_for('admin.index'))
        except Exception as e:
            flash(f'Error updating system: {str(e)}', 'error')

    tag_groups = TagGroup.query.order_by(TagGroup.name).all()
    return render_template(
        'admin/form.html',
        system=system,
        action='Edit',
        vendor_ports=VENDOR_DEFAULT_PORTS,
        vendor_port_descriptions=VENDOR_PORT_DESCRIPTIONS,
        standard_ports=STANDARD_PORTS,
        tag_groups=tag_groups,
    )


@bp.route('/systems/<int:system_id>/rediscover', methods=['POST'])
@login_required
def rediscover_system(system_id):
    """Re-run discovery for a system"""
    system = StorageSystem.query.get_or_404(system_id)

    try:
        discovery_result = auto_discover_system(
            vendor=system.vendor,
            ip_address=system.ip_address,
            username=system.api_username,
            password=system.api_password,
            api_token=system.api_token,
            ssl_verify=False
        )

        if 'error' not in discovery_result:
            system.cluster_type = discovery_result.get('cluster_type')
            system.node_count = discovery_result.get('node_count')
            system.site_count = discovery_result.get('site_count')
            system.set_dns_names(discovery_result.get('dns_names', []))
            system.set_all_ips(discovery_result.get('all_ips', []))
            system.set_node_details(discovery_result.get('node_details', []))

            # Save HA info if present (for DataDomain)
            if discovery_result.get('ha_info'):
                system.set_ha_info(discovery_result.get('ha_info'))

            # Save OS version and API version if present
            if discovery_result.get('os_version'):
                system.os_version = discovery_result.get('os_version')
            if discovery_result.get('api_version'):
                system.api_version = discovery_result.get('api_version')

            system.last_discovery = datetime.utcnow()
            system.discovery_error = None

            db.session.commit()
            flash(f'System re-discovered successfully! Found {system.node_count or 0} nodes.', 'success')
        else:
            system.discovery_error = discovery_result.get('error')
            system.last_discovery = datetime.utcnow()
            db.session.commit()
            flash(f'Discovery had issues: {discovery_result.get("error")}', 'warning')

    except Exception as e:
        logger.error(f'Error re-discovering system: {e}', exc_info=True)
        flash(f'Error re-discovering system: {str(e)}', 'error')

    return redirect(url_for('admin.index'))


@bp.route('/systems/rediscover-all', methods=['POST'])
@login_required
def rediscover_all_systems():
    """Re-run discovery for all storage systems"""
    ssl_verify = current_app.config.get('SSL_VERIFY', False)

    systems = StorageSystem.query.all()

    if not systems:
        flash('No storage systems configured', 'warning')
        return redirect(url_for('admin.index'))

    success_count = 0
    error_count = 0

    for system in systems:
        try:
            discovery_result = auto_discover_system(
                vendor=system.vendor,
                ip_address=system.ip_address,
                username=system.api_username,
                password=system.api_password,
                api_token=system.api_token,
                ssl_verify=ssl_verify
            )

            if 'error' not in discovery_result:
                system.cluster_type = discovery_result.get('cluster_type')
                system.node_count = discovery_result.get('node_count')
                system.site_count = discovery_result.get('site_count')
                system.set_dns_names(discovery_result.get('dns_names', []))
                system.set_all_ips(discovery_result.get('all_ips', []))
                system.set_node_details(discovery_result.get('node_details', []))

                # Save HA info if present (for DataDomain)
                if discovery_result.get('ha_info'):
                    system.set_ha_info(discovery_result.get('ha_info'))

                # Save OS version and API version if present
                if discovery_result.get('os_version'):
                    system.os_version = discovery_result.get('os_version')
                if discovery_result.get('api_version'):
                    system.api_version = discovery_result.get('api_version')

                system.last_discovery = datetime.utcnow()
                system.discovery_error = None
                success_count += 1
            else:
                system.discovery_error = discovery_result.get('error')
                system.last_discovery = datetime.utcnow()
                error_count += 1
                logger.warning(f'Discovery error for {system.name}: {discovery_result.get("error")}')

        except Exception as e:
            system.discovery_error = str(e)
            system.last_discovery = datetime.utcnow()
            error_count += 1
            logger.error(f'Error re-discovering system {system.name}: {e}', exc_info=True)

    # Commit all changes
    try:
        db.session.commit()

        if error_count == 0:
            flash(f'All {success_count} systems successfully re-discovered!', 'success')
        elif success_count > 0:
            flash(f'{success_count} systems re-discovered successfully, {error_count} had errors.', 'warning')
        else:
            flash(f'All {error_count} systems had discovery errors. Check system details for more information.', 'error')
    except Exception as e:
        db.session.rollback()
        logger.error(f'Error committing discovery changes: {e}', exc_info=True)
        flash(f'Error saving discovery results: {str(e)}', 'error')

    return redirect(url_for('admin.index'))


@bp.route('/systems/<int:system_id>/delete', methods=['POST'])
@login_required
def delete_system(system_id):
    """Delete storage system"""
    try:
        system = StorageSystem.query.get_or_404(system_id)
        db.session.delete(system)
        db.session.commit()
        flash('Storage system deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting system: {str(e)}', 'error')

    return redirect(url_for('admin.index'))


@bp.route('/docs')
@login_required
def docs():
    """API setup documentation"""
    return render_template('admin/docs.html')


@bp.route('/swagger')
@login_required
def swagger():
    """Swagger UI for the Storage Dashboard API"""
    return render_template('admin/swagger.html')
