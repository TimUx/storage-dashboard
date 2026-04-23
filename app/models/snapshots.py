"""Snapshot management (/snaps) persistence."""
import json
from datetime import datetime

from app import db


class SnapshotRecord(db.Model):
    """Aggregated database snapshot record collected from Pure FlashArray and/or ONTAP.

    One row represents a single logical snapshot identified by SID + creation_time.
    Multiple FlashArray LUN snapshots sharing the same SID and timestamp are collapsed
    into one record.  The storage_locations field carries the full detail (arrays,
    LUN names, ONTAP cluster / SVM / volumes) as a JSON blob.
    """
    __tablename__ = 'snapshot_records'

    id = db.Column(db.Integer, primary_key=True)

    # Snapshot identity
    sid = db.Column(db.String(10), nullable=False, index=True)
    creation_time = db.Column(db.DateTime, nullable=False)
    ttl = db.Column(db.DateTime)                         # Expiration parsed from snapshot name

    # Presence flags (editable by users)
    flasharray_present = db.Column(db.Boolean, default=False, nullable=False)
    ontap_present = db.Column(db.Boolean, default=False, nullable=False)

    # User-editable text overrides (NULL = use auto-detected value)
    db_override = db.Column(db.String(50))               # override for DB (FlashArray) column
    nfs_override = db.Column(db.String(50))              # override for NFS (ONTAP) column

    # Comment entered by operators
    comment = db.Column(db.Text)

    # Soft-delete / deletion scheduling
    delete_marked = db.Column(db.Boolean, default=False, nullable=False)
    delete_deadline = db.Column(db.DateTime)             # UTC deadline for actual deletion

    # Storage detail – JSON blob with keys:
    #   flasharray_systems: [{name, snapshot_names: [...]}]
    #   ontap_clusters:     [{cluster, svm, volumes: [...]}]
    storage_locations = db.Column(db.Text)

    # Housekeeping
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('sid', 'creation_time', name='uq_snapshot_sid_time'),
    )

    def get_storage_locations(self):
        """Return decoded storage_locations dict (never raises)."""
        try:
            return json.loads(self.storage_locations) if self.storage_locations else {}
        except Exception:
            return {}

    def to_dict(self):
        locs = self.get_storage_locations()
        return {
            'id': self.id,
            'sid': self.sid,
            'creation_time': self.creation_time.isoformat() if self.creation_time else None,
            'ttl': self.ttl.isoformat() if self.ttl else None,
            'flasharray_present': self.flasharray_present,
            'ontap_present': self.ontap_present,
            'db_override': self.db_override,
            'nfs_override': self.nfs_override,
            'comment': self.comment or '',
            'delete_marked': self.delete_marked,
            'delete_deadline': self.delete_deadline.isoformat() if self.delete_deadline else None,
            'storage_locations': locs,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
        }

    def __repr__(self):
        return f'<SnapshotRecord {self.sid} {self.creation_time}>'


class SnapshotAuditLog(db.Model):
    """Audit trail for TTL changes on snapshot records.

    Each row records one TTL modification: old value, new value, operator,
    and when the change was made.
    """
    __tablename__ = 'snapshot_audit_log'

    id = db.Column(db.Integer, primary_key=True)
    snapshot_id = db.Column(db.Integer, db.ForeignKey('snapshot_records.id', ondelete='CASCADE'),
                            nullable=False, index=True)
    old_ttl = db.Column(db.DateTime)
    new_ttl = db.Column(db.DateTime)
    changed_by = db.Column(db.String(200))               # operator name / IP
    changed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    snapshot = db.relationship('SnapshotRecord', backref='audit_logs')

    def to_dict(self):
        return {
            'id': self.id,
            'snapshot_id': self.snapshot_id,
            'old_ttl': self.old_ttl.isoformat() if self.old_ttl else None,
            'new_ttl': self.new_ttl.isoformat() if self.new_ttl else None,
            'changed_by': self.changed_by,
            'changed_at': self.changed_at.isoformat() if self.changed_at else None,
        }

    def __repr__(self):
        return f'<SnapshotAuditLog snap={self.snapshot_id} by={self.changed_by}>'


class SnapshotCollectorMetadata(db.Model):
    """Metadata written by the snapshot background collector after each run.

    One row per execution – used by the UI to show "Letzte Aktualisierung".
    """
    __tablename__ = 'snapshot_collector_metadata'

    id = db.Column(db.Integer, primary_key=True)
    run_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    duration_seconds = db.Column(db.Float)
    systems_queried = db.Column(db.Integer, default=0)
    snapshots_stored = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='success')  # success / error
    error_message = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'run_at': self.run_at.isoformat() if self.run_at else None,
            'duration_seconds': self.duration_seconds,
            'systems_queried': self.systems_queried,
            'snapshots_stored': self.snapshots_stored,
            'status': self.status,
            'error_message': self.error_message,
        }

    def __repr__(self):
        return f'<SnapshotCollectorMetadata run_at={self.run_at} status={self.status}>'
