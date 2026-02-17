#!/usr/bin/env python3
"""CLI interface for Storage Dashboard"""
import click
import sys
import getpass
from app import create_app, db
from app.models import StorageSystem, AdminUser, AppSettings
from app.api import get_client
from tabulate import tabulate


@click.group()
def cli():
    """Storage Dashboard CLI"""
    pass


@cli.command()
def dashboard():
    """Display dashboard in terminal"""
    app = create_app()
    with app.app_context():
        systems = StorageSystem.query.filter_by(enabled=True).all()
        
        if not systems:
            click.echo("Keine Storage Systeme konfiguriert.")
            click.echo("Verwenden Sie 'cli.py admin list' um Systeme zu verwalten.")
            return
        
        click.echo("\n=== Storage Dashboard ===\n")
        
        # Group by vendor
        vendors = {}
        for system in systems:
            if system.vendor not in vendors:
                vendors[system.vendor] = []
            vendors[system.vendor].append(system)
        
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
                try:
                    client = get_client(
                        vendor=system.vendor,
                        ip_address=system.ip_address,
                        port=system.port,
                        username=system.api_username,
                        password=system.api_password,
                        token=system.api_token
                    )
                    status = client.get_health_status()
                    
                    table_data.append([
                        system.name,
                        system.ip_address,
                        status['status'],
                        status['hardware_status'],
                        status['cluster_status'],
                        status['alerts'],
                        f"{status['capacity_used_tb']:.1f} / {status['capacity_total_tb']:.1f} TB",
                        f"{status['capacity_percent']:.1f}%"
                    ])
                except Exception as e:
                    table_data.append([
                        system.name,
                        system.ip_address,
                        'ERROR',
                        '-',
                        '-',
                        '-',
                        '-',
                        str(e)[:40]
                    ])
            
            headers = ['Name', 'IP', 'Status', 'Hardware', 'Cluster', 'Alerts', 'Kapazität', 'Belegt']
            click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))


@cli.group()
def admin():
    """Admin commands for managing storage systems"""
    pass


@admin.command('list')
def admin_list():
    """List all storage systems"""
    app = create_app()
    with app.app_context():
        systems = StorageSystem.query.all()
        
        if not systems:
            click.echo("Keine Storage Systeme vorhanden.")
            return
        
        table_data = []
        for system in systems:
            table_data.append([
                system.id,
                system.name,
                system.vendor,
                system.ip_address,
                system.port,
                'Ja' if system.enabled else 'Nein',
                'Ja' if (system.api_username or system.api_token) else 'Nein'
            ])
        
        headers = ['ID', 'Name', 'Hersteller', 'IP', 'Port', 'Aktiv', 'Credentials']
        click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))


@admin.command('add')
@click.option('--name', prompt=True, help='System name')
@click.option('--vendor', type=click.Choice(['pure', 'netapp-ontap', 'netapp-storagegrid', 'dell-datadomain']), 
              prompt=True, help='Vendor type')
@click.option('--ip', prompt=True, help='IP address or hostname')
@click.option('--port', default=443, help='Port (default: 443)')
@click.option('--username', default='', help='API username')
@click.option('--password', default='', help='API password')
@click.option('--token', default='', help='API token')
@click.option('--enabled/--disabled', default=True, help='Enable system')
def admin_add(name, vendor, ip, port, username, password, token, enabled):
    """Add a new storage system"""
    app = create_app()
    with app.app_context():
        try:
            system = StorageSystem(
                name=name,
                vendor=vendor,
                ip_address=ip,
                port=port,
                api_username=username if username else None,
                api_password=password if password else None,
                api_token=token if token else None,
                enabled=enabled
            )
            db.session.add(system)
            db.session.commit()
            click.echo(f"✓ Storage System '{name}' erfolgreich hinzugefügt.")
        except Exception as e:
            click.echo(f"✗ Fehler: {str(e)}", err=True)
            sys.exit(1)


@admin.command('remove')
@click.argument('system_id', type=int)
@click.confirmation_option(prompt='Sind Sie sicher, dass Sie dieses System löschen möchten?')
def admin_remove(system_id):
    """Remove a storage system"""
    app = create_app()
    with app.app_context():
        system = StorageSystem.query.get(system_id)
        if not system:
            click.echo(f"✗ System mit ID {system_id} nicht gefunden.", err=True)
            sys.exit(1)
        
        name = system.name
        db.session.delete(system)
        db.session.commit()
        click.echo(f"✓ Storage System '{name}' erfolgreich gelöscht.")


@admin.command('enable')
@click.argument('system_id', type=int)
def admin_enable(system_id):
    """Enable a storage system"""
    app = create_app()
    with app.app_context():
        system = StorageSystem.query.get(system_id)
        if not system:
            click.echo(f"✗ System mit ID {system_id} nicht gefunden.", err=True)
            sys.exit(1)
        
        system.enabled = True
        db.session.commit()
        click.echo(f"✓ Storage System '{system.name}' aktiviert.")


@admin.command('disable')
@click.argument('system_id', type=int)
def admin_disable(system_id):
    """Disable a storage system"""
    app = create_app()
    with app.app_context():
        system = StorageSystem.query.get(system_id)
        if not system:
            click.echo(f"✗ System mit ID {system_id} nicht gefunden.", err=True)
            sys.exit(1)
        
        system.enabled = False
        db.session.commit()
        click.echo(f"✓ Storage System '{system.name}' deaktiviert.")


@admin.command('create-user')
@click.option('--username', prompt='Username', help='Admin username')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Admin password')
def admin_create_user(username, password):
    """Create a new admin user"""
    app = create_app()
    with app.app_context():
        # Check if user already exists
        existing = AdminUser.query.filter_by(username=username).first()
        if existing:
            click.echo(f"✗ Benutzer '{username}' existiert bereits.", err=True)
            sys.exit(1)
        
        # Create new admin user
        user = AdminUser(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        click.echo(f"✓ Admin-Benutzer '{username}' erfolgreich erstellt.")


@admin.command('list-users')
def admin_list_users():
    """List all admin users"""
    app = create_app()
    with app.app_context():
        users = AdminUser.query.all()
        
        if not users:
            click.echo("Keine Admin-Benutzer vorhanden.")
            click.echo("Verwenden Sie 'cli.py admin create-user' um einen Benutzer zu erstellen.")
            return
        
        table_data = []
        for user in users:
            table_data.append([
                user.id,
                user.username,
                '✓' if user.is_active else '✗',
                user.last_login.strftime('%d.%m.%Y %H:%M') if user.last_login else '-',
                user.created_at.strftime('%d.%m.%Y %H:%M') if user.created_at else '-'
            ])
        
        headers = ['ID', 'Benutzername', 'Aktiv', 'Letzter Login', 'Erstellt']
        click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))


if __name__ == '__main__':
    cli()

