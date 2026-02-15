# Storage Dashboard

Ein Python-basiertes Dashboard zur Überwachung von Storage-Systemen verschiedener Hersteller über Browser und CLI.

## Features

- **Multi-Vendor Support**: Überwachung von Pure Storage, NetApp ONTAP 9, NetApp StorageGRID 11 und Dell DataDomain
- **Web Dashboard**: Übersichtliche Card/Grid-Ansicht aller Storage-Systeme
- **CLI Interface**: Zugriff auf Dashboard-Daten über die Kommandozeile
- **Admin-Bereich**: Verwaltung von Storage-Systemen mit Namen, IPs und API-Credentials
- **API-Abfrage**: Automatische Abfrage von Health-Status über Hersteller-APIs
- **Status-Übersicht**: Hardware-Status, Cluster-Status, Alerts und Kapazität
- **Gruppierung**: Systeme nach Hersteller gruppiert
- **Single-Page-View**: Alle Systeme auf einen Blick ohne Scrollen

## Unterstützte Storage-Systeme

### Mit offiziellen Python-Bibliotheken:
- **Pure Storage Arrays** - Verwendet `py-pure-client` (offizielle Pure Storage SDK)
- **NetApp ONTAP 9** - Verwendet `netapp-ontap` (offizielle NetApp SDK)

### Mit REST API (requests):
- **NetApp StorageGRID 11** - REST API Integration
- **Dell DataDomain** - REST API v1.0 Integration

> **Hinweis:** Für StorageGRID und DataDomain sind keine offiziellen Python SDKs verfügbar. Das Dashboard verwendet direkte REST API Calls mit dem `requests` Modul.

## Systemanforderungen

- SUSE Linux 15 (oder andere Linux-Distribution)
- Python 3.8 oder höher
- Netzwerkzugriff zu den Storage-Systemen

## Installation

### 1. Repository klonen

```bash
git clone https://github.com/TimUx/storage-dashboard.git
cd storage-dashboard
```

### 2. Python Virtual Environment erstellen

```bash
python3 -m venv venv
source venv/bin/activate  # Auf Linux/Mac
```

### 3. Abhängigkeiten installieren

```bash
pip install -r requirements.txt
```

### 4. Konfiguration

Kopieren Sie die Beispiel-Konfiguration:

```bash
cp .env.example .env
```

Optional: Passen Sie die `.env` Datei an (für Produktivumgebungen):

```
SECRET_KEY=your-secure-secret-key
DATABASE_URL=sqlite:///storage_dashboard.db
FLASK_ENV=production
```

## Verwendung

### Web-Dashboard starten

```bash
python run.py
```

Das Dashboard ist dann verfügbar unter: `http://localhost:5000`

Für Produktivumgebungen mit Gunicorn:

```bash
gunicorn -w 4 -b 0.0.0.0:5000 run:app
```

### CLI verwenden

**Dashboard anzeigen:**

```bash
python cli.py dashboard
```

**Systeme verwalten:**

```bash
# Alle Systeme auflisten
python cli.py admin list

# Neues System hinzufügen
python cli.py admin add

# System aktivieren/deaktivieren
python cli.py admin enable <ID>
python cli.py admin disable <ID>

# System löschen
python cli.py admin remove <ID>
```

## Web-Interface

### Dashboard (`/`)

Zeigt alle aktivierten Storage-Systeme gruppiert nach Hersteller:
- Hardware-Status
- Cluster-Status
- Anzahl Alerts
- Kapazität (gesamt, belegt, Prozent)
- Visuelle Kapazitäts-Anzeige

### Admin-Bereich (`/admin`)

- Übersicht aller konfigurierten Systeme
- Systeme hinzufügen, bearbeiten, löschen
- Aktivieren/Deaktivieren von Systemen

### Dokumentation (`/admin/docs`)

Detaillierte Anleitungen zur API-Einrichtung für jedes Storage-System.

## API-Einrichtung

### Pure Storage

1. Im FlashArray unter **System → Users** einen API-Token erstellen
2. Token im Dashboard unter "API Token" eintragen

### NetApp ONTAP 9

1. Benutzer mit REST API-Zugriff erstellen
2. Benutzername und Passwort im Dashboard eintragen

### NetApp StorageGRID 11

1. Im Management Interface API-Credentials erstellen
2. Bearer Token generieren und im Dashboard eintragen

### Dell DataDomain

1. REST API aktivieren
2. Benutzer mit entsprechenden Rechten erstellen
3. Benutzername und Passwort im Dashboard eintragen

Detaillierte Anleitungen finden Sie in der Web-Dokumentation unter `/admin/docs`.

## REST API Endpoints

Das Dashboard bietet auch programmatischen Zugriff:

- `GET /api/systems` - Liste aller Systeme
- `GET /api/status` - Status aller aktivierten Systeme
- `GET /api/systems/<id>/status` - Status eines spezifischen Systems

## Entwicklung

### Projektstruktur

```
storage-dashboard/
├── app/
│   ├── __init__.py          # Flask App Factory
│   ├── models.py            # Datenbankmodelle
│   ├── api/                 # Storage API Clients
│   │   ├── base_client.py
│   │   └── storage_clients.py
│   ├── routes/              # Flask Routes
│   │   ├── main.py          # Dashboard
│   │   ├── admin.py         # Admin-Bereich
│   │   └── api.py           # REST API
│   └── templates/           # HTML Templates
│       ├── base.html
│       ├── dashboard.html
│       └── admin/
├── run.py                   # Web-Server Startskript
├── cli.py                   # CLI Interface
├── requirements.txt         # Python-Abhängigkeiten
└── README.md
```

### Neue Storage-Systeme hinzufügen

Um ein neues Storage-System zu unterstützen:

1. Erstellen Sie eine neue Client-Klasse in `app/api/storage_clients.py`
2. Implementieren Sie die `get_health_status()` Methode
3. Registrieren Sie den Client in der `get_client()` Factory-Funktion
4. Fügen Sie die Vendor-Option in den Admin-Formularen hinzu

## Sicherheit

- API-Credentials werden verschlüsselt in der Datenbank gespeichert
- HTTPS-Verbindungen zu Storage-Systemen (SSL-Verifizierung in Produktion empfohlen)
- Verwenden Sie dedizierte Read-Only-Accounts
- Ändern Sie den `SECRET_KEY` in Produktivumgebungen
- Setzen Sie `SSL_VERIFY=true` in `.env` für Produktionsumgebungen mit gültigen SSL-Zertifikaten

**Hinweis zur Passwort-Speicherung**: In der aktuellen Version werden Passwörter im Klartext in der Datenbank gespeichert. Für produktive Umgebungen sollte eine Verschlüsselung implementiert werden (z.B. mit `cryptography.fernet`).

## Lizenz

Siehe LICENSE Datei.

## Support

Bei Fragen oder Problemen erstellen Sie bitte ein Issue im GitHub Repository.