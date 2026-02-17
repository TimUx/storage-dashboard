#!/usr/bin/env python3
"""
Remote CLI for Storage Dashboard
This script allows querying the Storage Dashboard from outside the container
and from remote systems using the REST API.
"""
import click
import requests
import sys
from tabulate import tabulate
import json


@click.group()
@click.option('--url', envvar='DASHBOARD_URL', default='http://localhost:5000',
              help='Dashboard URL (default: http://localhost:5000, or set DASHBOARD_URL env var)')
@click.option('--api-key', envvar='DASHBOARD_API_KEY', default=None,
              help='API key for authentication (optional, or set DASHBOARD_API_KEY env var)')
@click.pass_context
def cli(ctx, url, api_key):
    """Storage Dashboard Remote CLI
    
    Query your storage dashboard from anywhere via HTTP API.
    
    Examples:
    
        # Query local container
        remote-cli.py dashboard
        
        # Query remote dashboard
        remote-cli.py --url http://dashboard.example.com:5000 dashboard
        
        # Use environment variable
        export DASHBOARD_URL=http://dashboard.example.com:5000
        remote-cli.py dashboard
        
        # With API key (if authentication is enabled)
        remote-cli.py --api-key YOUR_KEY dashboard
    """
    ctx.ensure_object(dict)
    ctx.obj['url'] = url.rstrip('/')
    ctx.obj['api_key'] = api_key
    ctx.obj['headers'] = {}
    if api_key:
        ctx.obj['headers']['X-API-Key'] = api_key


def make_request(ctx, endpoint, method='GET'):
    """Make HTTP request to dashboard API"""
    url = f"{ctx.obj['url']}{endpoint}"
    headers = ctx.obj['headers']
    
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, timeout=30)
        else:
            response = requests.request(method, url, headers=headers, timeout=30)
        
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        click.echo(f"✗ Fehler: Verbindung zu {ctx.obj['url']} fehlgeschlagen.", err=True)
        click.echo(f"   Stellen Sie sicher, dass das Dashboard läuft und erreichbar ist.", err=True)
        sys.exit(1)
    except requests.exceptions.Timeout:
        click.echo(f"✗ Fehler: Zeitüberschreitung bei Verbindung zu {ctx.obj['url']}.", err=True)
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            click.echo(f"✗ Fehler: Authentifizierung fehlgeschlagen.", err=True)
            click.echo(f"   Verwenden Sie --api-key oder setzen Sie DASHBOARD_API_KEY.", err=True)
        elif e.response.status_code == 404:
            click.echo(f"✗ Fehler: Endpunkt nicht gefunden: {endpoint}", err=True)
        else:
            click.echo(f"✗ HTTP Fehler {e.response.status_code}: {e.response.text}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"✗ Unerwarteter Fehler: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def dashboard(ctx):
    """Display storage dashboard in terminal"""
    # Get all systems
    systems_data = make_request(ctx, '/api/systems')
    
    if not systems_data:
        click.echo("Keine Storage Systeme konfiguriert.")
        return
    
    # Get status for all enabled systems
    status_data = make_request(ctx, '/api/status')
    
    click.echo(f"\n=== Storage Dashboard ({ctx.obj['url']}) ===\n")
    
    # Create a mapping of system id to status
    status_map = {}
    for item in status_data:
        system_id = item.get('system', {}).get('id')
        if system_id:
            status_map[system_id] = item.get('status', {})
    
    # Group by vendor
    vendors = {}
    for system in systems_data:
        if not system.get('enabled'):
            continue
        vendor = system.get('vendor')
        if vendor not in vendors:
            vendors[vendor] = []
        vendors[vendor].append(system)
    
    vendor_names = {
        'pure': 'Pure Storage',
        'netapp-ontap': 'NetApp ONTAP',
        'netapp-storagegrid': 'NetApp StorageGRID',
        'dell-datadomain': 'Dell DataDomain'
    }
    
    for vendor, vendor_systems in vendors.items():
        click.echo(f"\n{vendor_names.get(vendor, vendor)}:")
        click.echo("=" * 80)
        
        table_data = []
        for system in vendor_systems:
            system_id = system.get('id')
            status = status_map.get(system_id, {})
            
            if status.get('error'):
                table_data.append([
                    system.get('name'),
                    system.get('ip_address'),
                    'ERROR',
                    '-',
                    '-',
                    '-',
                    '-',
                    status.get('error', '')[:40]
                ])
            else:
                table_data.append([
                    system.get('name'),
                    system.get('ip_address'),
                    status.get('status', '-'),
                    status.get('hardware_status', '-'),
                    status.get('cluster_status', '-'),
                    status.get('alerts', '-'),
                    f"{status.get('capacity_used_tb', 0):.1f} / {status.get('capacity_total_tb', 0):.1f} TB",
                    f"{status.get('capacity_percent', 0):.1f}%"
                ])
        
        headers = ['Name', 'IP', 'Status', 'Hardware', 'Cluster', 'Alerts', 'Kapazität', 'Belegt']
        click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))


@cli.command()
@click.pass_context
def systems(ctx):
    """List all storage systems"""
    systems_data = make_request(ctx, '/api/systems')
    
    if not systems_data:
        click.echo("Keine Storage Systeme vorhanden.")
        return
    
    table_data = []
    for system in systems_data:
        table_data.append([
            system.get('id'),
            system.get('name'),
            system.get('vendor'),
            system.get('ip_address'),
            system.get('port'),
            'Ja' if system.get('enabled') else 'Nein',
            'Ja' if system.get('has_credentials') else 'Nein',
            system.get('cluster_type', '-'),
        ])
    
    headers = ['ID', 'Name', 'Hersteller', 'IP', 'Port', 'Aktiv', 'Credentials', 'Cluster-Typ']
    click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))


@cli.command()
@click.argument('system_id', type=int)
@click.pass_context
def status(ctx, system_id):
    """Get detailed status of a specific system"""
    result = make_request(ctx, f'/api/systems/{system_id}/status')
    
    system = result.get('system', {})
    status = result.get('status', {})
    
    click.echo(f"\n=== System: {system.get('name')} ===\n")
    
    # System information
    click.echo("System Information:")
    click.echo(f"  Hersteller:  {system.get('vendor')}")
    click.echo(f"  IP-Adresse:  {system.get('ip_address')}")
    click.echo(f"  Port:        {system.get('port')}")
    click.echo(f"  Cluster-Typ: {system.get('cluster_type', 'N/A')}")
    
    if system.get('dns_names'):
        click.echo(f"  DNS-Namen:   {', '.join(system.get('dns_names'))}")
    
    if system.get('node_count'):
        click.echo(f"  Nodes:       {system.get('node_count')}")
    if system.get('site_count'):
        click.echo(f"  Sites:       {system.get('site_count')}")
    
    # Status information
    click.echo("\nStatus:")
    if status.get('error'):
        click.echo(f"  ✗ Fehler: {status.get('error')}")
    else:
        click.echo(f"  Status:      {status.get('status', 'N/A')}")
        click.echo(f"  Hardware:    {status.get('hardware_status', 'N/A')}")
        click.echo(f"  Cluster:     {status.get('cluster_status', 'N/A')}")
        click.echo(f"  Alerts:      {status.get('alerts', 'N/A')}")
        
        # Capacity information
        click.echo("\nKapazität:")
        click.echo(f"  Gesamt:      {status.get('capacity_total_tb', 0):.2f} TB")
        click.echo(f"  Belegt:      {status.get('capacity_used_tb', 0):.2f} TB")
        click.echo(f"  Verfügbar:   {status.get('capacity_available_tb', 0):.2f} TB")
        click.echo(f"  Auslastung:  {status.get('capacity_percent', 0):.1f}%")
        
        # Additional details if available
        if status.get('details'):
            click.echo("\nDetails:")
            details = status.get('details')
            if isinstance(details, dict):
                for key, value in details.items():
                    click.echo(f"  {key}: {value}")


@cli.command()
@click.option('--format', type=click.Choice(['json', 'table']), default='table',
              help='Output format (default: table)')
@click.pass_context
def export(ctx, format):
    """Export all system status data"""
    status_data = make_request(ctx, '/api/status')
    
    if format == 'json':
        click.echo(json.dumps(status_data, indent=2))
    else:
        table_data = []
        for item in status_data:
            system = item.get('system', {})
            status = item.get('status', {})
            
            table_data.append([
                system.get('id'),
                system.get('name'),
                system.get('vendor'),
                system.get('ip_address'),
                status.get('status', 'ERROR'),
                status.get('hardware_status', '-'),
                status.get('cluster_status', '-'),
                status.get('alerts', '-'),
                f"{status.get('capacity_total_tb', 0):.1f}",
                f"{status.get('capacity_used_tb', 0):.1f}",
                f"{status.get('capacity_percent', 0):.1f}%",
            ])
        
        headers = ['ID', 'Name', 'Vendor', 'IP', 'Status', 'HW', 'Cluster', 
                   'Alerts', 'Total TB', 'Used TB', 'Used %']
        click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))


@cli.command()
@click.pass_context
def version(ctx):
    """Show dashboard version and connectivity"""
    try:
        # Try to get systems to verify connection
        make_request(ctx, '/api/systems')
        click.echo(f"✓ Verbunden mit: {ctx.obj['url']}")
        click.echo(f"  Dashboard läuft und ist erreichbar")
    except SystemExit:
        # Error already handled by make_request
        pass


if __name__ == '__main__':
    cli(obj={})
