# Settings Tabs Feature Documentation

## Übersicht

Die Admin-Einstellungen wurden in eine moderne Tabbed-Oberfläche umgewandelt, die folgende Bereiche umfasst:

### 🎨 Design
- **Firmenname**: Wird im Header angezeigt
- **Logo**: Upload von PNG, JPG, SVG, GIF
- **Farbschema**: Primär (Rot), Sekundär (Gelb-Grün), Akzent (Blau)
- **Live-Vorschau**: Sofortige Anzeige der gewählten Farben

### 📋 Logs
- **Maximale Logs pro System**: 100-10.000 Einträge (Standard: 1.000)
- **Aufbewahrungsdauer**: 1-365 Tage (Standard: 30)
- **Minimales Log-Level**: DEBUG, INFO, WARNING, ERROR, CRITICAL (Standard: INFO)

**Hinweis**: Log-Level-Änderungen betreffen nur neue Logs. Bestehende Logs bleiben erhalten.

### 🔒 Zertifikate
- **Übersicht**: Alle SSL/TLS-Zertifikate direkt in den Einstellungen
- **Aktionen**: Bearbeiten, Download, Aktivieren/Deaktivieren
- **Upload**: Neues Zertifikat hochladen

### ⚙️ System
- **Zeitzone**: Auswahl aus gängigen Zeitzonen
  - Europe/Berlin (MEZ/MESZ) - Standard
  - Europe/London (GMT/BST)
  - UTC (Koordinierte Weltzeit)
  - America/New_York (EST/EDT)
  - Und weitere...

**Wichtig**: Zeitstempel werden in UTC gespeichert und für die Anzeige in die gewählte Zeitzone konvertiert.

## Zeitzone-Konfiguration

### Container-Ebene (docker-compose.yml)
```yaml
environment:
  - TZ=${TZ:-Europe/Berlin}
```

### Anwendungs-Ebene (Settings → System)
Die Zeitzone kann auch über die Admin-Einstellungen konfiguriert werden. Dies betrifft:
- Log-Zeitstempel
- Zertifikat-Erstellungszeiten
- System-Discovery-Zeiten
- Alle anderen Zeitangaben in der Anwendung

### .env Konfiguration
```env
TZ=Europe/Berlin
```

## UI-Verbesserungen

### Dashboard
- **Border**: Nur noch einfarbige Primärfarbe (Rot) statt dreifarbigem Gradient
- **Konsistent**: Gleiche Änderung auf Dashboard, Details und Login-Seiten

### Header
- **Kein vertikaler Strich**: Trennlinie rechts neben dem Titel entfernt
- **Größere Schrift**: Titel von 1.5rem auf 1.8rem erhöht
- **Kleineres Logo**: Von 50px/200px auf 40px/160px reduziert

## Log-Verwaltung

### Automatische Bereinigung
Logs werden automatisch bereinigt basierend auf:
1. **Anzahl**: Maximal konfigurierte Anzahl pro System
2. **Alter**: Logs älter als Aufbewahrungsdauer werden gelöscht

### Log-Level-Filterung
Nur Logs mit dem konfigurierten Mindest-Level oder höher werden gespeichert:
- **DEBUG**: Alle Details (sehr ausführlich)
- **INFO**: Informationen und höher (Standard)
- **WARNING**: Warnungen und Fehler
- **ERROR**: Nur Fehler
- **CRITICAL**: Nur kritische Fehler

## Technische Details

### Neue Abhängigkeiten
- **pytz**: Zeitzone-Konvertierung und -Verwaltung

### Datenbank-Erweiterungen
Neue Felder in `app_settings`:
- `timezone` (VARCHAR 50): IANA Zeitzone
- `max_logs_per_system` (INTEGER): Maximale Logs
- `log_retention_days` (INTEGER): Aufbewahrungstage
- `min_log_level` (VARCHAR 20): Minimales Log-Level

### Migration
Keine manuelle Migration erforderlich. Neue Felder werden automatisch beim Start erstellt mit Standardwerten.

## Zugriff

1. Login als Admin: `/admin/login`
2. Klick auf "⚙️ Einstellungen"
3. Tabs zum Navigieren zwischen Bereichen nutzen
4. "💾 Einstellungen speichern" zum Speichern

## Best Practices

### Timezone
- **Empfohlen**: `Europe/Berlin` für Deutschland
- **Alternative**: `UTC` für internationale Deployments
- **Wichtig**: Container-TZ und App-TZ sollten übereinstimmen

### Log-Retention
- **Entwicklung**: 7-14 Tage, DEBUG-Level
- **Produktion**: 30-90 Tage, INFO-Level
- **Langzeit-Archiv**: Export und externe Speicherung

### Zertifikate
- Regelmäßig auf Ablauf prüfen
- Inaktive Zertifikate deaktivieren
- Beschreibung für schnelle Identifikation pflegen
