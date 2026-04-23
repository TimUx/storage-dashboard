"""Alert UI state and assignee autocomplete history."""
from datetime import datetime

from app import db


class AlertState(db.Model):
    """Per-alert user state: acknowledged flag, assigned administrator, and free-text comment.

    The ``alert_key`` is a composite identifier built from ``system_name``,
    ``alert_id``, and ``title`` so that the same alert can be re-matched if it
    disappears and reappears.  States whose keys no longer appear in
    ``collect_alerts()`` are orphaned but harmless – they are never shown to
    the user because they cannot be joined to a live alert.
    """
    __tablename__ = 'alert_states'

    id = db.Column(db.Integer, primary_key=True)
    alert_key = db.Column(db.String(500), nullable=False, unique=True, index=True)
    acknowledged = db.Column(db.Boolean, default=False, nullable=False)
    assignee = db.Column(db.String(200))
    comment = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @staticmethod
    def make_key(system_name, alert_id, title):
        """Build a stable composite key for an alert."""
        raw = f"{system_name}|{alert_id}|{title}"
        return raw[:500]

    def __repr__(self):
        return f'<AlertState key={self.alert_key!r} ack={self.acknowledged}>'


class AssigneeHistory(db.Model):
    """History of assignee names entered by operators – used for the autocomplete dropdown."""
    __tablename__ = 'assignee_history'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    used_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<AssigneeHistory {self.name!r}>'
