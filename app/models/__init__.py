"""Database models (split across submodules; import from ``app.models`` as before)."""
from app import db
from app.models.admin_user import AdminUser
from app.models.alerts import AlertState, AssigneeHistory
from app.models.certificate import Certificate
from app.models.dr import (
    DRBuildMetadata,
    DRCommandSet,
    DRMermaidDiagram,
    DRRelationship,
    DRRunbook,
    DRTopologyModel,
    DRWorkflow,
)
from app.models.logs_licenses import SodHistory, SubscriptionLicenseCache, SystemLog
from app.models.settings import AppSettings
from app.models.snapshots import SnapshotAuditLog, SnapshotCollectorMetadata, SnapshotRecord
from app.models.status_capacity import CapacityHistory, CapacitySnapshot, StatusCache
from app.models.storage import StorageSystem
from app.models.tags import Tag, TagGroup, storage_system_tags

__all__ = (
    'db',
    'storage_system_tags',
    'TagGroup',
    'Tag',
    'StorageSystem',
    'Certificate',
    'AdminUser',
    'AppSettings',
    'StatusCache',
    'CapacitySnapshot',
    'CapacityHistory',
    'SystemLog',
    'SubscriptionLicenseCache',
    'SodHistory',
    'AlertState',
    'AssigneeHistory',
    'DRBuildMetadata',
    'DRRelationship',
    'DRTopologyModel',
    'DRWorkflow',
    'DRRunbook',
    'DRCommandSet',
    'DRMermaidDiagram',
    'SnapshotRecord',
    'SnapshotAuditLog',
    'SnapshotCollectorMetadata',
)
