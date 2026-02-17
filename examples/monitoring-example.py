#!/usr/bin/env python3
"""
Example Python script for monitoring storage dashboard
Demonstrates how to programmatically query the dashboard via remote CLI
"""

import subprocess
import json
import sys
import os


def get_dashboard_url():
    """Get dashboard URL from environment or use default"""
    return os.environ.get('DASHBOARD_URL', 'http://localhost:5000')


def run_remote_cli(command, format='json'):
    """Run remote CLI command and return output"""
    url = get_dashboard_url()
    cmd = ['python3', 'remote-cli.py', '--url', url]
    
    if isinstance(command, str):
        cmd.append(command)
    else:
        cmd.extend(command)
    
    if format:
        cmd.extend(['--format', format])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running remote CLI: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_storage_status():
    """Get status of all storage systems"""
    output = run_remote_cli('export', format='json')
    return json.loads(output)


def check_capacity_threshold(threshold=80):
    """Check if any system exceeds capacity threshold"""
    status = get_storage_status()
    alerts = []
    
    for item in status:
        system = item.get('system', {})
        status_data = item.get('status', {})
        
        if status_data.get('error'):
            alerts.append({
                'system': system.get('name'),
                'type': 'error',
                'message': status_data.get('error')
            })
        else:
            capacity_percent = status_data.get('capacity_percent', 0)
            if capacity_percent > threshold:
                alerts.append({
                    'system': system.get('name'),
                    'type': 'capacity',
                    'capacity': capacity_percent,
                    'threshold': threshold
                })
    
    return alerts


def check_system_health():
    """Check health status of all systems"""
    status = get_storage_status()
    unhealthy = []
    
    for item in status:
        system = item.get('system', {})
        status_data = item.get('status', {})
        
        if status_data.get('status') != 'healthy':
            unhealthy.append({
                'system': system.get('name'),
                'status': status_data.get('status', 'unknown')
            })
    
    return unhealthy


def main():
    """Main monitoring function"""
    print("=== Storage Dashboard Monitoring ===")
    print(f"Dashboard URL: {get_dashboard_url()}")
    print()
    
    # Test connection
    print("Testing connection...")
    try:
        run_remote_cli('version', format=None)
        print("✓ Connection successful")
    except SystemExit:
        print("✗ Cannot connect to dashboard")
        return 1
    
    print()
    
    # Check capacity
    print("Checking capacity thresholds...")
    capacity_alerts = check_capacity_threshold(threshold=80)
    
    if not capacity_alerts:
        print("✓ All systems below capacity threshold")
    else:
        print(f"⚠ {len(capacity_alerts)} alert(s) found:")
        for alert in capacity_alerts:
            if alert['type'] == 'capacity':
                print(f"  - {alert['system']}: {alert['capacity']:.1f}% (threshold: {alert['threshold']}%)")
            elif alert['type'] == 'error':
                print(f"  - {alert['system']}: ERROR - {alert['message']}")
    
    print()
    
    # Check health
    print("Checking system health...")
    unhealthy = check_system_health()
    
    if not unhealthy:
        print("✓ All systems healthy")
    else:
        print(f"⚠ {len(unhealthy)} unhealthy system(s):")
        for system in unhealthy:
            print(f"  - {system['system']}: {system['status']}")
    
    print()
    
    # Display summary
    print("=== Status Summary ===")
    status = get_storage_status()
    
    total_capacity_tb = sum(item['status'].get('capacity_total_tb', 0) for item in status)
    total_used_tb = sum(item['status'].get('capacity_used_tb', 0) for item in status)
    
    if total_capacity_tb > 0:
        total_percent = (total_used_tb / total_capacity_tb) * 100
        print(f"Total Storage: {total_capacity_tb:.1f} TB")
        print(f"Total Used: {total_used_tb:.1f} TB ({total_percent:.1f}%)")
        print(f"Total Available: {total_capacity_tb - total_used_tb:.1f} TB")
    
    print(f"Systems monitored: {len(status)}")
    
    # Return exit code based on alerts
    if capacity_alerts or unhealthy:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
