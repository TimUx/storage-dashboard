# Remote CLI - Anleitung

Die Remote CLI ermöglicht den Zugriff auf das Storage Dashboard von außerhalb des Containers und von Remote-Systemen über die HTTP API.

## Übersicht

- **Datei**: `remote-cli.py`
- **Anforderungen**: Python 3.8+, Pakete: `click`, `requests`, `tabulate`
- **Zugriff**: Via HTTP API (Standard: `http://localhost:5000`)

## Installation

### Im Container

Die Remote CLI ist bereits im Container enthalten und kann direkt verwendet werden:

```bash
podman exec -it storage-dashboard python /app/remote-cli.py --help
```

### Auf einem Remote-System

1. Kopieren Sie `remote-cli.py` auf Ihr System:

```bash
# Mit scp
scp user@dashboard-host:/pfad/zu/storage-dashboard/remote-cli.py .

# Oder laden Sie es vom Repository herunter
wget https://raw.githubusercontent.com/TimUx/storage-dashboard/main/remote-cli.py
```

2. Installieren Sie die erforderlichen Python-Pakete:

```bash
pip install click requests tabulate
```

3. Machen Sie das Skript ausführbar (optional):

```bash
chmod +x remote-cli.py
```

## Verwendung

### Grundlegende Syntax

```bash
python remote-cli.py [OPTIONEN] BEFEHL [ARGUMENTE]
```

### Optionen

- `--url TEXT`: Dashboard URL (Standard: `http://localhost:5000`)
- `--api-key TEXT`: API-Schlüssel für Authentifizierung (optional)
- `--help`: Zeigt die Hilfe an

### Umgebungsvariablen

Anstelle von Kommandozeilen-Optionen können Sie auch Umgebungsvariablen verwenden:

```bash
export DASHBOARD_URL=http://dashboard.example.com:5000
export DASHBOARD_API_KEY=ihr-api-key  # Falls benötigt
```

## Befehle

### 1. Dashboard anzeigen

Zeigt alle aktivierten Storage-Systeme mit ihrem Status an:

```bash
# Lokal
python remote-cli.py dashboard

# Remote
python remote-cli.py --url http://dashboard.example.com:5000 dashboard
```

**Ausgabe:**
```
=== Storage Dashboard (http://localhost:5000) ===

Pure Storage:
================================================================================
+----------+-------------+----------+------------+-----------+----------+-------------+----------+
| Name     | IP          | Status   | Hardware   | Cluster   | Alerts   | Kapazität   | Belegt   |
+==========+=============+==========+============+===========+==========+=============+==========+
| FlashA1  | 10.0.1.100  | healthy  | OK         | OK        | 0        | 50.0/100.0  | 50.0%    |
+----------+-------------+----------+------------+-----------+----------+-------------+----------+
```

### 2. Systeme auflisten

Listet alle konfigurierten Storage-Systeme auf:

```bash
python remote-cli.py systems
```

**Ausgabe:**
```
+------+-----------+--------------+-------------+--------+---------+---------------+---------------+
|   ID | Name      | Hersteller   | IP          |   Port | Aktiv   | Credentials   | Cluster-Typ   |
+======+===========+==============+=============+========+=========+===============+===============+
|    1 | FlashA1   | pure         | 10.0.1.100  |    443 | Ja      | Ja            | ha            |
+------+-----------+--------------+-------------+--------+---------+---------------+---------------+
```

### 3. System-Status abfragen

Zeigt detaillierte Informationen zu einem spezifischen System:

```bash
python remote-cli.py status <SYSTEM_ID>
```

**Beispiel:**
```bash
python remote-cli.py status 1
```

**Ausgabe:**
```
=== System: FlashA1 ===

System Information:
  Hersteller:  pure
  IP-Adresse:  10.0.1.100
  Port:        443
  Cluster-Typ: ha
  DNS-Namen:   flash01.example.com

Status:
  Status:      healthy
  Hardware:    OK
  Cluster:     OK
  Alerts:      0

Kapazität:
  Gesamt:      100.00 TB
  Belegt:      50.00 TB
  Verfügbar:   50.00 TB
  Auslastung:  50.0%
```

### 4. Daten exportieren

Exportiert alle System-Status-Daten in verschiedenen Formaten:

```bash
# Als Tabelle (Standard)
python remote-cli.py export --format table

# Als JSON
python remote-cli.py export --format json

# JSON in Datei speichern
python remote-cli.py export --format json > status.json
```

### 5. Verbindung testen

Überprüft die Verbindung zum Dashboard:

```bash
python remote-cli.py version
```

**Ausgabe:**
```
✓ Verbunden mit: http://localhost:5000
  Dashboard läuft und ist erreichbar
```

## Anwendungsfälle

### 1. Überwachung von einem Remote-System

```bash
#!/bin/bash
# Überwachungsskript auf einem Monitoring-Server

export DASHBOARD_URL=http://storage-dashboard.internal:5000

# Status aller Systeme prüfen
python remote-cli.py dashboard

# Bei Bedarf Alerts auslösen
if python remote-cli.py export --format json | grep -q "ERROR"; then
    echo "ALERT: Ein oder mehrere Storage-Systeme haben Fehler!"
fi
```

### 2. Automatisches Reporting

```bash
#!/bin/bash
# Täglicher Status-Report

REPORT_FILE="storage-report-$(date +%Y%m%d).txt"

echo "Storage Dashboard Report - $(date)" > "$REPORT_FILE"
echo "=======================================" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

python remote-cli.py --url http://dashboard.example.com:5000 dashboard >> "$REPORT_FILE"

# Report versenden
mail -s "Storage Dashboard Report" admin@example.com < "$REPORT_FILE"
```

### 3. Vom Container aus auf den Container zugreifen

```bash
# Innerhalb des Containers
podman exec -it storage-dashboard python /app/remote-cli.py dashboard

# Oder von außerhalb
python remote-cli.py --url http://localhost:5000 dashboard
```

### 4. Integration in Monitoring-Tools

```python
#!/usr/bin/env python3
# monitoring_integration.py

import subprocess
import json
import sys

def get_storage_status():
    """Holt den Storage-Status via Remote CLI"""
    result = subprocess.run(
        ['python', 'remote-cli.py', 'export', '--format', 'json'],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        sys.exit(1)
    
    return json.loads(result.stdout)

def check_capacity_alerts(threshold=80):
    """Prüft auf Kapazitäts-Warnungen"""
    status = get_storage_status()
    alerts = []
    
    for system in status:
        capacity_percent = system['status'].get('capacity_percent', 0)
        if capacity_percent > threshold:
            alerts.append({
                'system': system['system']['name'],
                'capacity': capacity_percent
            })
    
    return alerts

if __name__ == '__main__':
    alerts = check_capacity_alerts()
    if alerts:
        print("WARNUNG: Folgende Systeme überschreiten den Kapazitätsschwellwert:")
        for alert in alerts:
            print(f"  - {alert['system']}: {alert['capacity']:.1f}%")
        sys.exit(1)
    else:
        print("OK: Alle Systeme unter dem Kapazitätsschwellwert")
        sys.exit(0)
```

## Fehlerbehebung

### Verbindungsfehler

```
✗ Fehler: Verbindung zu http://localhost:5000 fehlgeschlagen.
   Stellen Sie sicher, dass das Dashboard läuft und erreichbar ist.
```

**Lösung:**
- Prüfen Sie, ob das Dashboard läuft: `podman ps` oder `curl http://localhost:5000/api/systems`
- Prüfen Sie die Firewall-Regeln
- Verwenden Sie die korrekte URL und Port

### Zeitüberschreitung

```
✗ Fehler: Zeitüberschreitung bei Verbindung zu http://localhost:5000.
```

**Lösung:**
- Das Dashboard ist überlastet oder antwortet nicht
- Netzwerkprobleme zwischen Client und Dashboard
- Erhöhen Sie das Timeout (kann im Code angepasst werden)

### Authentifizierungsfehler

```
✗ Fehler: Authentifizierung fehlgeschlagen.
   Verwenden Sie --api-key oder setzen Sie DASHBOARD_API_KEY.
```

**Lösung:**
- Verwenden Sie einen gültigen API-Schlüssel
- Setzen Sie die Umgebungsvariable `DASHBOARD_API_KEY`

## Sicherheitshinweise

1. **Netzwerkzugriff**: Die Remote CLI kommuniziert über HTTP. In Produktivumgebungen sollten Sie:
   - Einen Reverse Proxy mit HTTPS verwenden
   - Die Firewall entsprechend konfigurieren
   - Nur vertrauenswürdigen Systemen Zugriff gewähren

2. **API-Authentifizierung**: Falls Sie API-Authentifizierung implementieren:
   - Speichern Sie API-Schlüssel sicher (z.B. in Umgebungsvariablen)
   - Verwenden Sie keine API-Schlüssel in Skripten im Klartext
   - Rotieren Sie API-Schlüssel regelmäßig

3. **Container-Sicherheit**: 
   - Der Container läuft als Nicht-Root-User
   - Begrenzen Sie den Netzwerkzugriff auf benötigte Ports
   - Verwenden Sie podman/docker Netzwerk-Isolation

## Unterschiede zur lokalen CLI

| Feature | Lokale CLI (`cli.py`) | Remote CLI (`remote-cli.py`) |
|---------|----------------------|------------------------------|
| Datenbankzugriff | Direkt | Via API |
| Standort | Im Container / Lokal | Überall (Remote) |
| Admin-Funktionen | Ja (add, remove, etc.) | Nein (nur lesend) |
| Authentifizierung | Nicht erforderlich | Optional (API-Key) |
| Abhängigkeiten | Flask, SQLAlchemy, etc. | Nur click, requests, tabulate |
| Netzwerk | Nicht erforderlich | HTTP/HTTPS erforderlich |

## API-Endpunkte

Die Remote CLI verwendet folgende API-Endpunkte:

- `GET /api/systems` - Liste aller Systeme
- `GET /api/status` - Status aller aktivierten Systeme
- `GET /api/systems/<id>/status` - Status eines spezifischen Systems

Weitere Informationen zu den API-Endpunkten finden Sie im README.md.

## Support

Bei Fragen oder Problemen:
- GitHub Issues: https://github.com/TimUx/storage-dashboard/issues
- Dokumentation: https://github.com/TimUx/storage-dashboard
