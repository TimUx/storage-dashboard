# DataDomain API Integration Documentation

## Overview

The DataDomain client now retrieves comprehensive system information using the DataDomain REST API v1.0. This document describes all available data fields and their sources.

## API Endpoints Used

Based on `app/api/dd_api.json`, the following endpoints are queried:

### Core Endpoints
1. **System Information** - `/rest/v1.0/system`
   - System name, model, version
   - Physical and logical capacity
   - Compression and deduplication factors

2. **HA Status** - `/rest/v1.0/dd-systems/0/ha`
   - HA enabled/disabled status
   - Current state (active, standby, failed)
   - Role (primary, secondary)
   - Partner node name and IP address
   - Failover status

3. **Active Alerts** - `/rest/v1.0/dd-systems/0/alerts`
   - Alert ID, severity, category
   - Alert message and timestamp
   - Alert state (active, new, unresolved)

4. **Network Interfaces** - `/rest/v1.0/dd-systems/0/networks`
   - Interface name (ethMa, ethMb, ethV0, etc.)
   - IP address configuration
   - Link status and enabled state

5. **Replication** - `/rest/v1.0/dd-systems/0/replication/contexts`
   - Replication context ID and name
   - Replication state and direction
   - Remote host and user information

6. **Hardware Health** - `/rest/v1.0/dd-systems/0/hardware`
   - Chassis status
   - Component counts (controllers, disks, PSUs, fans)
   - Failed component identification

7. **Services** - `/rest/v1.0/dd-systems/0/services`
   - Service name (NFS, CIFS, DD Boost, etc.)
   - Service status (running, stopped)
   - Enabled/disabled state

## Response Structure

### Standard Health Status Fields
```json
{
  "status": "online|offline|error",
  "hardware_status": "ok|warning|error",
  "cluster_status": "ok|warning|error",
  "alerts": 0,
  "capacity_total_tb": 50.5,
  "capacity_used_tb": 35.2,
  "capacity_percent": 69.7,
  "os_version": "7.7.0.10"
}
```

### DataDomain-Specific Fields

#### HA Status
```json
{
  "ha_status": {
    "enabled": true,
    "state": "active",
    "role": "primary",
    "partner_name": "dd7300-02",
    "partner_address": "10.112.228.76",
    "partner_status": "online",
    "failover_status": "ready"
  }
}
```

#### Active Alerts
```json
{
  "active_alerts": [
    {
      "id": "ALERT-001",
      "severity": "warning|critical|major|minor|info",
      "category": "capacity|replication|hardware|general",
      "message": "Alert description",
      "timestamp": "2026-02-18T14:30:00Z",
      "state": "active"
    }
  ]
}
```

#### Network Interfaces
```json
{
  "all_mgmt_ips": [
    {
      "name": "ethMa",
      "ip_address": "10.112.228.75",
      "enabled": true,
      "link_status": "up"
    }
  ]
}
```

#### Replication Status
```json
{
  "replication_status": {
    "context_count": 2,
    "contexts": [
      {
        "id": "ctx-001",
        "name": "prod-to-dr",
        "state": "replicating|idle|paused",
        "direction": "source|destination",
        "remote_host": "dd7300-dr",
        "remote_user": "repl_user"
      }
    ]
  }
}
```

#### Hardware Details
```json
{
  "hardware_details": {
    "chassis_status": "ok",
    "controller_count": 2,
    "disk_count": 60,
    "power_supply_count": 4,
    "fan_count": 8,
    "overall_status": "ok|warning",
    "failed_components": [
      "power_supplies:PSU-01",
      "fans:FAN-03"
    ]
  }
}
```

#### Services
```json
{
  "services": [
    {
      "name": "nfs",
      "status": "running|stopped",
      "enabled": true
    }
  ]
}
```

#### System Details
```json
{
  "system_name": "dd7300-01",
  "model": "DD7300",
  "compression_factor": 15.2
}
```

## Dashboard Use Cases

### 1. Network Topology View
- **Data Source**: `all_mgmt_ips`
- **Usage**: Display all IP addresses for connectivity tracking
- **Example**: Show management interfaces ethMa-ethMd with IPs

### 2. HA/Cluster Status
- **Data Source**: `ha_status`, `cluster_status`
- **Usage**: Show HA state, partner node, and failover readiness
- **Example**: "Primary (active) - Partner: dd7300-02 (10.112.228.76)"

### 3. Active Alerts Dashboard
- **Data Source**: `active_alerts`, `alerts` (count)
- **Usage**: Display critical alerts requiring attention
- **Example**: Show alerts grouped by severity with timestamps

### 4. Hardware Health Monitoring
- **Data Source**: `hardware_details`, `hardware_status`
- **Usage**: Component-level health display
- **Example**: "60 disks, 4 PSUs (all OK), 8 fans (1 failed)"

### 5. Replication Monitoring
- **Data Source**: `replication_status`
- **Usage**: Track replication contexts and remote systems
- **Example**: "2 active contexts: prod-to-dr (replicating), backup-sync (idle)"

### 6. Service Status
- **Data Source**: `services`
- **Usage**: Monitor enabled protocols and services
- **Example**: "NFS: running, CIFS: running, DD Boost: running"

## Constants

The client uses the following constants for consistency:

### Alert States (Active)
- `active`
- `new`
- `unresolved`

### Hardware Failure States
- `failed`
- `error`
- `critical`

### Critical Alert Severities
- `critical`
- `major`

## Error Handling

- If an API endpoint fails, the helper method returns `None` or `[]`
- The main `get_health_status()` continues to work with partial data
- Missing data fields are gracefully handled with defaults
- Authentication failures trigger automatic re-authentication

## Performance Considerations

- All API calls use 10-second timeout
- Failed endpoints are logged at DEBUG level (don't spam logs)
- API requests run sequentially to avoid overwhelming the system
- Token-based authentication minimizes overhead

## Future Enhancements

Additional endpoints available in dd_api.json but not yet implemented:

1. **Statistics** - `/rest/v1.0/dd-systems/0/stats`
   - CPU, memory, throughput metrics

2. **Storage Units** - `/rest/v1.0/dd-systems/0/storage-units`
   - Pre/post-compression capacity per unit

3. **Filesystems** - `/rest/v1.0/dd-systems/0/file-systems`
   - Filesystem-level capacity and status

4. **MTrees** - `/rest/v1.0/dd-systems/0/mtrees`
   - MTree tenant information

5. **Disks** - `/rest/v1.0/dd-systems/0/disks`
   - Individual disk status and tier information

6. **Protocols** - `/rest/v1.0/dd-systems/0/protocols`
   - Detailed protocol configuration

7. **Licenses** - `/rest/v1.0/dd-systems/0/licenses`
   - License status and expiration
