"""Admin tag and tag-group management."""
import logging

from flask import flash, redirect, render_template, request, url_for
from flask_login import login_required

from app import db
from app.models import Tag, TagGroup
from app.routes.admin import bp

logger = logging.getLogger(__name__)


@bp.route('/tags')
@login_required
def tags():
    """List all tag groups and tags"""
    tag_groups = TagGroup.query.order_by(TagGroup.name).all()
    return render_template('admin/tags.html', tag_groups=tag_groups)


@bp.route('/tags/groups/new', methods=['GET', 'POST'])
@login_required
def new_tag_group():
    """Create a new tag group"""
    if request.method == 'POST':
        try:
            name = request.form['name'].strip()
            description = request.form.get('description', '').strip()
            if not name:
                flash('Name darf nicht leer sein', 'error')
            elif TagGroup.query.filter_by(name=name).first():
                flash(f'Tag-Gruppe "{name}" existiert bereits', 'error')
            else:
                group = TagGroup(name=name, description=description or None)
                db.session.add(group)
                db.session.commit()
                flash(f'Tag-Gruppe "{name}" erstellt', 'success')
                return redirect(url_for('admin.tags'))
        except Exception as e:
            logger.error(f'Error creating tag group: {e}', exc_info=True)
            flash(f'Fehler: {str(e)}', 'error')
    return render_template('admin/tag_group_form.html', group=None, action='Erstellen')


@bp.route('/tags/groups/<int:group_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_tag_group(group_id):
    """Edit a tag group"""
    group = TagGroup.query.get_or_404(group_id)
    if request.method == 'POST':
        try:
            name = request.form['name'].strip()
            description = request.form.get('description', '').strip()
            if not name:
                flash('Name darf nicht leer sein', 'error')
            else:
                group.name = name
                group.description = description or None
                db.session.commit()
                flash(f'Tag-Gruppe "{name}" aktualisiert', 'success')
                return redirect(url_for('admin.tags'))
        except Exception as e:
            logger.error(f'Error editing tag group: {e}', exc_info=True)
            flash(f'Fehler: {str(e)}', 'error')
    return render_template('admin/tag_group_form.html', group=group, action='Bearbeiten')


@bp.route('/tags/groups/<int:group_id>/delete', methods=['POST'])
@login_required
def delete_tag_group(group_id):
    """Delete a tag group and all its tags"""
    try:
        group = TagGroup.query.get_or_404(group_id)
        name = group.name
        db.session.delete(group)
        db.session.commit()
        flash(f'Tag-Gruppe "{name}" gelöscht', 'success')
    except Exception as e:
        logger.error(f'Error deleting tag group: {e}', exc_info=True)
        flash(f'Fehler: {str(e)}', 'error')
    return redirect(url_for('admin.tags'))


@bp.route('/tags/new', methods=['GET', 'POST'])
@login_required
def new_tag():
    """Create a new tag"""
    tag_groups = TagGroup.query.order_by(TagGroup.name).all()
    if request.method == 'POST':
        try:
            name = request.form['name'].strip()
            group_id = int(request.form['group_id'])
            if not name:
                flash('Name darf nicht leer sein', 'error')
            elif Tag.query.filter_by(name=name, group_id=group_id).first():
                flash(f'Tag "{name}" existiert bereits in dieser Gruppe', 'error')
            else:
                tag = Tag(name=name, group_id=group_id)
                db.session.add(tag)
                db.session.commit()
                flash(f'Tag "{name}" erstellt', 'success')
                return redirect(url_for('admin.tags'))
        except Exception as e:
            logger.error(f'Error creating tag: {e}', exc_info=True)
            flash(f'Fehler: {str(e)}', 'error')
    return render_template('admin/tag_form.html', tag=None, tag_groups=tag_groups, action='Erstellen')


@bp.route('/tags/<int:tag_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_tag(tag_id):
    """Edit a tag"""
    tag = Tag.query.get_or_404(tag_id)
    tag_groups = TagGroup.query.order_by(TagGroup.name).all()
    if request.method == 'POST':
        try:
            name = request.form['name'].strip()
            group_id = int(request.form['group_id'])
            if not name:
                flash('Name darf nicht leer sein', 'error')
            else:
                tag.name = name
                tag.group_id = group_id
                db.session.commit()
                flash(f'Tag "{name}" aktualisiert', 'success')
                return redirect(url_for('admin.tags'))
        except Exception as e:
            logger.error(f'Error editing tag: {e}', exc_info=True)
            flash(f'Fehler: {str(e)}', 'error')
    return render_template('admin/tag_form.html', tag=tag, tag_groups=tag_groups, action='Bearbeiten')


@bp.route('/tags/<int:tag_id>/delete', methods=['POST'])
@login_required
def delete_tag(tag_id):
    """Delete a tag"""
    try:
        tag = Tag.query.get_or_404(tag_id)
        name = tag.name
        db.session.delete(tag)
        db.session.commit()
        flash(f'Tag "{name}" gelöscht', 'success')
    except Exception as e:
        logger.error(f'Error deleting tag: {e}', exc_info=True)
        flash(f'Fehler: {str(e)}', 'error')
    return redirect(url_for('admin.tags'))
