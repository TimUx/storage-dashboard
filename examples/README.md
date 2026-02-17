# Beispiele für Remote CLI

Diese Verzeichnis enthält Beispiel-Skripte, die zeigen, wie man die Remote CLI für verschiedene Zwecke verwenden kann.

## Monitoring-Beispiel (Bash)

**Datei**: `monitoring-example.sh`

Ein einfaches Bash-Skript, das zeigt, wie man die Remote CLI für Monitoring-Zwecke verwenden kann.

**Verwendung:**
```bash
# Mit Standard-URL (http://localhost:5000)
./monitoring-example.sh

# Mit benutzerdefinierter URL
DASHBOARD_URL=http://dashboard.example.com:5000 ./monitoring-example.sh

# Mit Kapazitätsschwellwert
DASHBOARD_URL=http://dashboard.example.com:5000 CAPACITY_THRESHOLD=85 ./monitoring-example.sh
```

## Monitoring-Beispiel (Python)

**Datei**: `monitoring-example.py`

Ein Python-Skript, das erweiterte Monitoring-Funktionalität bietet:
- Prüfung von Kapazitätsschwellwerten
- Gesundheitsstatus-Überwachung
- JSON-basierte Datenverarbeitung
- Zusammenfassung der Gesamtkapazität

**Verwendung:**
```bash
# Mit Standard-URL (http://localhost:5000)
python3 monitoring-example.py

# Mit benutzerdefinierter URL
DASHBOARD_URL=http://dashboard.example.com:5000 python3 monitoring-example.py
```

**Exit Codes:**
- `0`: Alles OK, keine Alerts
- `1`: Alerts gefunden (Kapazität oder Gesundheit)

## Integration in Cron

Für automatisches Monitoring können Sie die Skripte in Cron einbinden:

```bash
# Bearbeiten Sie die Crontab
crontab -e

# Fügen Sie eine Zeile für stündliches Monitoring hinzu
0 * * * * /pfad/zu/storage-dashboard/examples/monitoring-example.sh >> /var/log/storage-monitoring.log 2>&1

# Oder alle 15 Minuten
*/15 * * * * cd /pfad/zu/storage-dashboard && python3 examples/monitoring-example.py
```

## Integration in Nagios/Icinga

```bash
# In Nagios/Icinga Konfiguration
define command {
    command_name    check_storage_dashboard
    command_line    /usr/local/bin/monitoring-example.py
}

define service {
    use                     generic-service
    host_name               storage-monitor
    service_description     Storage Dashboard
    check_command           check_storage_dashboard
}
```

## Weitere Verwendungsmöglichkeiten

### Automatische Berichte

```bash
#!/bin/bash
# daily-report.sh

REPORT_FILE="/var/reports/storage-$(date +%Y%m%d).txt"

echo "Storage Dashboard Report - $(date)" > "$REPORT_FILE"
echo "=======================================" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

python3 remote-cli.py --url http://dashboard.example.com:5000 dashboard >> "$REPORT_FILE"

# Report per E-Mail versenden
mail -s "Storage Dashboard Report" admin@example.com < "$REPORT_FILE"
```

### Prometheus Exporter

```python
#!/usr/bin/env python3
# prometheus-exporter.py

import subprocess
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/metrics':
            self.send_response(404)
            self.end_headers()
            return
        
        # Hole Status von Dashboard
        result = subprocess.run(
            ['python3', 'remote-cli.py', 'export', '--format', 'json'],
            capture_output=True, text=True
        )
        
        status = json.loads(result.stdout)
        
        # Generiere Prometheus Metriken
        metrics = []
        for item in status:
            system = item['system']
            st = item['status']
            
            labels = f'system="{system["name"]}",vendor="{system["vendor"]}"'
            
            if not st.get('error'):
                metrics.append(f'storage_capacity_total_tb{{{labels}}} {st.get("capacity_total_tb", 0)}')
                metrics.append(f'storage_capacity_used_tb{{{labels}}} {st.get("capacity_used_tb", 0)}')
                metrics.append(f'storage_capacity_percent{{{labels}}} {st.get("capacity_percent", 0)}')
        
        # Sende Metriken
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write('\n'.join(metrics).encode())

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 9100), MetricsHandler)
    print("Prometheus exporter running on :9100/metrics")
    server.serve_forever()
```

## Hinweise

- Alle Beispiele benötigen `remote-cli.py` im übergeordneten Verzeichnis oder im PATH
- Stellen Sie sicher, dass die erforderlichen Python-Pakete installiert sind: `pip install click requests tabulate`
- Passen Sie die URLs und Schwellwerte an Ihre Umgebung an
- Für Produktivumgebungen sollten Sie API-Authentifizierung verwenden
