"""DR generation engine.

Converts system metadata and DR relationships into structured DR
operational information: workflows, runbooks, command sets, and diagrams.

The generators dispatch to vendor-specific logic modules based on the
replication_type detected during discovery.
"""
import logging

logger = logging.getLogger(__name__)

# Map replication type → vendor logic module
_VENDOR_MODULES = {
    'activecluster': 'app.dr_vendor.pure_flasharray_logic',
    'metrocluster': 'app.dr_vendor.ontap_metrocluster_logic',
    'snapmirror': 'app.dr_vendor.ontap_snapmirror_logic',
    'storagegrid-multisite': 'app.dr_vendor.storagegrid_logic',
    'datadomain-replication': 'app.dr_vendor.datadomain_logic',
}

_FAILOVER_DIRECTIONS = ['planned_failover', 'failback', 'disaster_recovery']


def _get_logic_module(replication_type):
    """Import and return the vendor logic module for the given replication type."""
    import importlib
    module_path = _VENDOR_MODULES.get(replication_type)
    if not module_path:
        logger.warning("No vendor logic module for replication_type=%r", replication_type)
        return None
    try:
        return importlib.import_module(module_path)
    except ImportError as exc:
        logger.error("Failed to import vendor logic module %s: %s", module_path, exc)
        return None


class DRTopologyBuilder:
    """Builds topology models from discovered DR relationships."""

    def build(self, relationship):
        """Return a topology dict for the given relationship dict.

        Args:
            relationship: dict produced by DRDiscoveryEngine (or from DRRelationship.to_dict())

        Returns:
            topology dict with keys: sites, nodes, links, vips
        """
        module = _get_logic_module(relationship.get('replication_type'))
        if module and hasattr(module, 'build_topology'):
            try:
                return module.build_topology(relationship)
            except Exception as exc:
                logger.error("Topology build failed for %s: %s", relationship.get('system_name'), exc)
        # Fallback generic topology
        return {
            'sites': [
                {'name': relationship.get('primary_site', 'Site A'), 'role': 'primary'},
                {'name': relationship.get('secondary_site', 'Site B'), 'role': 'secondary'},
            ],
            'nodes': [],
            'links': [
                {
                    'source': relationship.get('primary_site', 'Site A'),
                    'target': relationship.get('secondary_site', 'Site B'),
                    'type': 'replication',
                    'label': relationship.get('replication_type', 'replication'),
                }
            ],
            'vips': [],
        }


class DRWorkflowGenerator:
    """Generates DR failover workflow step lists."""

    def generate(self, relationship, failover_direction='planned_failover'):
        """Return a list of workflow step dicts for the given relationship and direction.

        Args:
            relationship: dict with replication_type, system_name, site info, etc.
            failover_direction: 'planned_failover' or 'failback'

        Returns:
            list of step dicts: {phase, step, title, description}
        """
        module = _get_logic_module(relationship.get('replication_type'))
        if module and hasattr(module, 'generate_workflow'):
            try:
                return module.generate_workflow(relationship, failover_direction)
            except Exception as exc:
                logger.error("Workflow generation failed for %s: %s", relationship.get('system_name'), exc)
        return []


class DRRunbookGenerator:
    """Generates structured DR runbook sections."""

    def generate(self, relationship, failover_direction='planned_failover'):
        """Return a list of runbook section dicts.

        Args:
            relationship: DR relationship dict
            failover_direction: 'planned_failover' or 'failback'

        Returns:
            list of section dicts: {phase, steps: [...], commands: [...]}
        """
        module = _get_logic_module(relationship.get('replication_type'))
        if module and hasattr(module, 'generate_runbook'):
            try:
                return module.generate_runbook(relationship, failover_direction)
            except Exception as exc:
                logger.error("Runbook generation failed for %s: %s", relationship.get('system_name'), exc)
        return []


class DRCommandGenerator:
    """Generates CLI command objects for DR operations."""

    def generate(self, relationship, failover_direction='planned_failover'):
        """Return a list of command dicts for the given relationship and direction.

        Args:
            relationship: DR relationship dict
            failover_direction: 'planned_failover' or 'failback'

        Returns:
            list of command dicts: {phase, description, cli, target}
        """
        module = _get_logic_module(relationship.get('replication_type'))
        if module and hasattr(module, 'generate_commands'):
            try:
                return module.generate_commands(relationship, failover_direction)
            except Exception as exc:
                logger.error("Command generation failed for %s: %s", relationship.get('system_name'), exc)
        return []


class DRDiagramGenerator:
    """Generates Mermaid diagram definitions for DR topology and workflows."""

    def generate_topology(self, relationship):
        """Return a Mermaid topology diagram string.

        Args:
            relationship: DR relationship dict

        Returns:
            Mermaid diagram string (graph LR format)
        """
        module = _get_logic_module(relationship.get('replication_type'))
        if module and hasattr(module, 'generate_topology_diagram'):
            try:
                return module.generate_topology_diagram(relationship)
            except Exception as exc:
                logger.error("Topology diagram generation failed for %s: %s", relationship.get('system_name'), exc)
        # Fallback
        site_a = relationship.get('primary_site', 'Site A')
        site_b = relationship.get('secondary_site', 'Site B')
        return (
            f'graph LR\n'
            f'  A["{site_a}"] -->|"Replication"| B["{site_b}"]'
        )

    def generate_workflow(self, relationship, failover_direction='planned_failover'):
        """Return a Mermaid workflow flowchart string.

        Args:
            relationship: DR relationship dict
            failover_direction: 'planned_failover' or 'failback'

        Returns:
            Mermaid diagram string (flowchart TD format)
        """
        module = _get_logic_module(relationship.get('replication_type'))
        if module and hasattr(module, 'generate_workflow_diagram'):
            try:
                return module.generate_workflow_diagram(relationship, failover_direction)
            except Exception as exc:
                logger.error("Workflow diagram generation failed for %s: %s", relationship.get('system_name'), exc)
        return 'flowchart TD\n  A["Start"] --> B["End"]'


class DRDiscoveryEngine:
    """Discovers DR relationships from storage system health data."""

    def discover(self, system_name, vendor, health_data):
        """Discover DR relationships from a system's health data.

        Tries all relevant vendor logic modules for the given vendor.

        Args:
            system_name: name of the storage system
            vendor: 'pure', 'netapp-ontap', 'netapp-storagegrid', 'dell-datadomain'
            health_data: dict returned by StorageClient.get_health_status()

        Returns:
            list of normalised relationship dicts
        """
        relationships = []

        vendor_type_map = {
            'pure': ['activecluster'],
            'netapp-ontap': ['metrocluster', 'snapmirror'],
            'netapp-storagegrid': ['storagegrid-multisite'],
            'dell-datadomain': ['datadomain-replication'],
        }

        rep_types = vendor_type_map.get(vendor, [])
        for rep_type in rep_types:
            module = _get_logic_module(rep_type)
            if module and hasattr(module, 'discover_relationships'):
                try:
                    found = module.discover_relationships(system_name, health_data)
                    if found:
                        relationships.extend(found)
                        logger.debug(
                            "Discovered %d %s relationships for %s",
                            len(found), rep_type, system_name
                        )
                except Exception as exc:
                    logger.error(
                        "Discovery failed for %s (%s): %s", system_name, rep_type, exc
                    )

        return relationships
