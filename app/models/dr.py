"""Disaster Recovery (DR) build artifacts and generated content."""
import json as _json
from datetime import datetime

from app import db


class DRBuildMetadata(db.Model):
    """Metadata for each DR information build run."""
    __tablename__ = 'dr_build_metadata'

    id = db.Column(db.Integer, primary_key=True)
    build_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    build_duration_seconds = db.Column(db.Float)
    build_status = db.Column(db.String(50), default='pending')  # pending, running, success, error
    systems_processed = db.Column(db.Integer, default=0)
    dr_relationships_detected = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'build_timestamp': self.build_timestamp.isoformat() if self.build_timestamp else None,
            'build_duration_seconds': self.build_duration_seconds,
            'build_status': self.build_status,
            'systems_processed': self.systems_processed,
            'dr_relationships_detected': self.dr_relationships_detected,
            'error_message': self.error_message,
        }

    def __repr__(self):
        return f'<DRBuildMetadata id={self.id} status={self.build_status}>'


class DRRelationship(db.Model):
    """Discovered DR relationship between two storage systems."""
    __tablename__ = 'dr_relationships'

    id = db.Column(db.Integer, primary_key=True)
    build_id = db.Column(db.Integer, db.ForeignKey('dr_build_metadata.id'), nullable=False, index=True)
    system_name = db.Column(db.String(200), nullable=False)
    vendor = db.Column(db.String(50), nullable=False)
    replication_type = db.Column(db.String(100), nullable=False)  # activecluster, metrocluster, snapmirror, storagegrid-multisite, datadomain-replication
    primary_site = db.Column(db.String(200))
    secondary_site = db.Column(db.String(200))
    primary_cluster = db.Column(db.String(200))
    secondary_cluster = db.Column(db.String(200))
    replication_state = db.Column(db.String(100))  # healthy, degraded, broken, unknown
    relationship_data = db.Column(db.Text)  # JSON: full relationship details from API

    build = db.relationship('DRBuildMetadata', backref='relationships')

    def to_dict(self):
        return {
            'id': self.id,
            'build_id': self.build_id,
            'system_name': self.system_name,
            'vendor': self.vendor,
            'replication_type': self.replication_type,
            'primary_site': self.primary_site,
            'secondary_site': self.secondary_site,
            'primary_cluster': self.primary_cluster,
            'secondary_cluster': self.secondary_cluster,
            'replication_state': self.replication_state,
            'relationship_data': _json.loads(self.relationship_data) if self.relationship_data else {},
        }

    def __repr__(self):
        return f'<DRRelationship {self.system_name} {self.replication_type}>'


class DRTopologyModel(db.Model):
    """Topology model for a DR system, containing nodes, sites, and links."""
    __tablename__ = 'dr_topology_models'

    id = db.Column(db.Integer, primary_key=True)
    build_id = db.Column(db.Integer, db.ForeignKey('dr_build_metadata.id'), nullable=False, index=True)
    relationship_id = db.Column(db.Integer, db.ForeignKey('dr_relationships.id'))
    system_name = db.Column(db.String(200), nullable=False)
    vendor = db.Column(db.String(50), nullable=False)
    topology_data = db.Column(db.Text, nullable=False)  # JSON: sites, nodes, links, vips

    build = db.relationship('DRBuildMetadata', backref='topologies')
    relationship = db.relationship('DRRelationship', backref='topology')

    def to_dict(self):
        return {
            'id': self.id,
            'build_id': self.build_id,
            'relationship_id': self.relationship_id,
            'system_name': self.system_name,
            'vendor': self.vendor,
            'topology_data': _json.loads(self.topology_data) if self.topology_data else {},
        }

    def __repr__(self):
        return f'<DRTopologyModel {self.system_name}>'


class DRWorkflow(db.Model):
    """Generated DR failover workflow for a DR relationship."""
    __tablename__ = 'dr_workflows'

    id = db.Column(db.Integer, primary_key=True)
    build_id = db.Column(db.Integer, db.ForeignKey('dr_build_metadata.id'), nullable=False, index=True)
    relationship_id = db.Column(db.Integer, db.ForeignKey('dr_relationships.id'))
    system_name = db.Column(db.String(200), nullable=False)
    vendor = db.Column(db.String(50), nullable=False)
    failover_direction = db.Column(db.String(200))  # e.g. "DC1 → DC2"
    workflow_data = db.Column(db.Text, nullable=False)  # JSON: steps list

    build = db.relationship('DRBuildMetadata', backref='workflows')
    relationship = db.relationship('DRRelationship', backref='workflows')

    def to_dict(self):
        return {
            'id': self.id,
            'build_id': self.build_id,
            'relationship_id': self.relationship_id,
            'system_name': self.system_name,
            'vendor': self.vendor,
            'failover_direction': self.failover_direction,
            'workflow_data': _json.loads(self.workflow_data) if self.workflow_data else [],
        }

    def __repr__(self):
        return f'<DRWorkflow {self.system_name} {self.failover_direction}>'


class DRRunbook(db.Model):
    """Generated DR runbook structure for a DR relationship."""
    __tablename__ = 'dr_runbooks'

    id = db.Column(db.Integer, primary_key=True)
    build_id = db.Column(db.Integer, db.ForeignKey('dr_build_metadata.id'), nullable=False, index=True)
    relationship_id = db.Column(db.Integer, db.ForeignKey('dr_relationships.id'))
    system_name = db.Column(db.String(200), nullable=False)
    vendor = db.Column(db.String(50), nullable=False)
    failover_direction = db.Column(db.String(200))
    runbook_data = db.Column(db.Text, nullable=False)  # JSON: sections with steps

    build = db.relationship('DRBuildMetadata', backref='runbooks')
    relationship = db.relationship('DRRelationship', backref='runbooks')

    def to_dict(self):
        return {
            'id': self.id,
            'build_id': self.build_id,
            'relationship_id': self.relationship_id,
            'system_name': self.system_name,
            'vendor': self.vendor,
            'failover_direction': self.failover_direction,
            'runbook_data': _json.loads(self.runbook_data) if self.runbook_data else [],
        }

    def __repr__(self):
        return f'<DRRunbook {self.system_name}>'


class DRCommandSet(db.Model):
    """Generated CLI command set for a DR relationship."""
    __tablename__ = 'dr_command_sets'

    id = db.Column(db.Integer, primary_key=True)
    build_id = db.Column(db.Integer, db.ForeignKey('dr_build_metadata.id'), nullable=False, index=True)
    relationship_id = db.Column(db.Integer, db.ForeignKey('dr_relationships.id'))
    system_name = db.Column(db.String(200), nullable=False)
    vendor = db.Column(db.String(50), nullable=False)
    failover_direction = db.Column(db.String(200))
    phase = db.Column(db.String(100))  # pre-failover, failover, post-failover, failback
    commands_data = db.Column(db.Text, nullable=False)  # JSON: command objects

    build = db.relationship('DRBuildMetadata', backref='command_sets')
    relationship = db.relationship('DRRelationship', backref='command_sets')

    def to_dict(self):
        return {
            'id': self.id,
            'build_id': self.build_id,
            'relationship_id': self.relationship_id,
            'system_name': self.system_name,
            'vendor': self.vendor,
            'failover_direction': self.failover_direction,
            'phase': self.phase,
            'commands_data': _json.loads(self.commands_data) if self.commands_data else [],
        }

    def __repr__(self):
        return f'<DRCommandSet {self.system_name} {self.phase}>'


class DRMermaidDiagram(db.Model):
    """Generated Mermaid diagram definition for a DR relationship."""
    __tablename__ = 'dr_mermaid_diagrams'

    id = db.Column(db.Integer, primary_key=True)
    build_id = db.Column(db.Integer, db.ForeignKey('dr_build_metadata.id'), nullable=False, index=True)
    relationship_id = db.Column(db.Integer, db.ForeignKey('dr_relationships.id'))
    system_name = db.Column(db.String(200), nullable=False)
    vendor = db.Column(db.String(50), nullable=False)
    diagram_type = db.Column(db.String(50))  # topology, workflow
    diagram_definition = db.Column(db.Text, nullable=False)  # Mermaid diagram text

    build = db.relationship('DRBuildMetadata', backref='diagrams')
    relationship = db.relationship('DRRelationship', backref='diagrams')

    def to_dict(self):
        return {
            'id': self.id,
            'build_id': self.build_id,
            'relationship_id': self.relationship_id,
            'system_name': self.system_name,
            'vendor': self.vendor,
            'diagram_type': self.diagram_type,
            'diagram_definition': self.diagram_definition,
        }

    def __repr__(self):
        return f'<DRMermaidDiagram {self.system_name} {self.diagram_type}>'
