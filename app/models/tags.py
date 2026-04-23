"""Tag groups, tags, and the storage-system ↔ tag association table."""
from datetime import datetime

from app import db

# Many-to-many junction table for StorageSystem <-> Tag
storage_system_tags = db.Table(
    'storage_system_tags',
    db.Column('system_id', db.Integer, db.ForeignKey('storage_systems.id', ondelete='CASCADE'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tags.id', ondelete='CASCADE'), primary_key=True)
)


class TagGroup(db.Model):
    """Tag group model – groups related tags together (e.g. 'Storage Art', 'Landschaft')"""
    __tablename__ = 'tag_groups'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    tags = db.relationship('Tag', backref='group', lazy='dynamic', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'tags': [t.to_dict() for t in self.tags.order_by(Tag.name)],
        }

    def __repr__(self):
        return f'<TagGroup {self.name}>'


class Tag(db.Model):
    """Tag model – individual label that can be assigned to storage systems"""
    __tablename__ = 'tags'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('tag_groups.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('name', 'group_id', name='uq_tag_name_group'),)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'group_id': self.group_id,
            'group_name': self.group.name if self.group else None,
        }

    def __repr__(self):
        return f'<Tag {self.name} ({self.group.name if self.group else "?"})>'
