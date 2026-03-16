# Storage Dashboard

Ein Python/Flask-basiertes Dashboard zur Überwachung von Storage-Systemen verschiedener Hersteller über Browser und CLI.

---

## Inhaltsverzeichnis

1. [Übersicht & Features](#1-übersicht--features)
2. [Unterstützte Storage-Systeme](#2-unterstützte-storage-systeme)
3. [Dashboard-Ansicht](#3-dashboard-ansicht)
4. [Alerts-Seite](#4-alerts-seite)
5. [Snapshot-Verwaltung](#5-snapshot-verwaltung)
6. [System-Detailansicht](#6-system-detailansicht)
7. [Kapazitätsreport](#7-kapazitätsreport)
8. [Admin-Bereich](#8-admin-bereich)
9. [Einstellungen](#9-einstellungen)
10. [API & Swagger UI](#10-api--swagger-ui)
11. [Systemanforderungen](#11-systemanforderungen)
12. [Installation](#12-installation)
13. [Admin-Benutzer erstellen](#13-admin-benutzer-erstellen)
14. [CLI-Interface](#14-cli-interface)
15. [Deployment](#15-deployment)
16. [DR Planner – Disaster Recovery Operations](#16-dr-planner--disaster-recovery-operations)

---

## 1. Übersicht & Features

Storage Dashboard überwacht Pure Storage, NetApp ONTAP, NetApp StorageGRID und Dell DataDomain zentral über deren REST APIs – ohne herstellerspezifische SDKs.

**Kernfunktionen:**

| Funktion | Beschreibung |
|----------|-------------|
| **Multi-Vendor Support** | Pure Storage, NetApp ONTAP 9, NetApp StorageGRID 11, Dell DataDomain |
| **Echtzeit-Dashboard** | Card- und Table-Ansicht aller Systeme mit farbkodierten Status-Badges |
| **Alerts-Seite** | Konsolidierte Übersicht aller offenen Alerts aller Systeme inkl. ONTAP EMS Events |
| **Snapshot-Verwaltung** | Automatische Erfassung von HANA DB-Snapshots (FlashArray + ONTAP), TTL-Verwaltung, Abgleich mit Storage |
| **Kapazitätsreport** | Tabellarische und grafische Kapazitätsübersicht (5 Ansichten) mit 2-Jahres-Verlauf |
| **System-Detailansicht** | Einzelsystem-Daten mit Capacity, Hardware-Status, Node-Infos und Alerts |
| **Hintergrund-Polling** | Konfigurierbarer Hintergrunddienst (1–60 min) mit UI-seitigem Caching |
| **Auto-Refresh** | Automatische Dashboard-Aktualisierung ohne Seiten-Reload |
| **Pure1 Integration** | Storage on Demand (SoD) Daten mit Verlauf und Effektivwerten |
| **Proxy-Unterstützung** | HTTP/HTTPS-Proxy für ausgehende Verbindungen (z.B. Pure1) |
| **CLI Interface** | Lokal und Remote (HTTP API) |
| **REST API + Swagger UI** | Vollständig dokumentierte API mit interaktiver Swagger-Oberfläche |
| **SSL-Zertifikatsverwaltung** | Upload eigener CA/Root-Zertifikate für interne Storage-Systeme |
| **Tag-System** | Flexibles Tagging (Storage Art, Landschaft, Tätigkeitsfeld) |
| **Admin-Bereich** | Systemverwaltung, Einstellungen, Logs, Zertifikate |

---

## 2. Unterstützte Storage-Systeme

Alle Systeme werden über standardmäßige REST API Calls angebunden:

| System | API | Authentifizierung |
|--------|-----|-------------------|
| **Pure Storage FlashArray** | REST API v2 | API Token |
| **NetApp ONTAP 9** | ONTAP REST API | Benutzername / Passwort |
| **NetApp StorageGRID 11** | Grid Management API v4 | Benutzername / Passwort |
| **Dell DataDomain** | DataDomain REST API v1.0 | Benutzername / Passwort |

> **Hinweis:** Das Dashboard liest für NetApp ONTAP automatisch EMS-Events (Emergency/Alert/Error) aus dem Event Management System aus – vollständig via REST API, ohne SNMP oder proprietäre Agenten.

---

## 3. Dashboard-Ansicht

Das Haupt-Dashboard zeigt alle Storage-Systeme gruppiert nach Hersteller in zwei wählbaren Ansichten.

### Card-Ansicht – Light & Dark Mode

Das Dashboard unterstützt einen hellen (Standard) und einen dunklen Modus, umschaltbar über den 🌙/☀️-Button in der Navbar.

**Light Mode (Standard):**

![Dashboard – Card-Ansicht (Light)](screenshots/dashboard-card-view.png)

**Dark Mode:**

![Dashboard – Card-Ansicht (Dark)](screenshots/dashboard-card-view-dark.png)

### Table-Ansicht

Kompakte Tabellenansicht aller Systeme mit denselben Statusinformationen – ideal bei vielen Systemen.

![Dashboard – Table-Ansicht](screenshots/dashboard-table-view.png)

**Dashboard-Features:**
- **Filter**: Hersteller, Status, Cluster-Typ, Tags, Freitext
- **🔔 Alerts-Badge**: Navbar-Button zeigt Anzahl offener Alerts aller Systeme
- **↻ Aktualisieren**: Sofortige manuelle Datenaktualisierung per Button
- **Auto-Refresh**: 30–120 Sekunden (konfigurierbar), ohne Seiten-Reload
- **Spaltenbreite**: 1–4 Spalten umschaltbar (Card-Ansicht)
- **Hintergrund-Caching**: Status-Daten werden im Hintergrund gecacht – die UI erscheint sofort

---

## 4. Alerts-Seite

Die Alerts-Seite aggregiert alle offenen Alerts aus dem Status-Cache aller Systeme in einer zentralen Tabelle. Sie ist über den orangen 🔔-Button in der Navbar erreichbar (zeigt Anzahl offener Alerts).

![Alerts-Seite](screenshots/alerts-page.png)

**Unterstützte Alert-Quellen:**

| Hersteller | Alert-Quelle | Felder |
|-----------|-------------|--------|
| **NetApp ONTAP** | EMS Events (`/api/support/ems/events`) | Severity (Emergency/Alert/Error), EMS-Name, Log-Message, Node, Zeitstempel |
| **Pure Storage** | Array Alerts | Severity, Titel, Details, Error-Code, Komponente |
| **NetApp StorageGRID** | Grid Alerts | Severity, Alert-Name, Details, Node |
| **Dell DataDomain** | Active Alerts | Severity, Alert-Name, Kategorie, Meldung |

**ONTAP EMS Alert-Abfrage:**  
Das Dashboard ruft via `GET /api/support/ems/events?message.severity=emergency,alert,error` die letzten 100 EMS Events ab. Die Severity wird auf den Hardware-Status gemappt:
- `emergency` → `hardware_status = error`
- `alert` / `error` → `hardware_status = warning`

---

## 5. Snapshot-Verwaltung

Die Snapshot-Verwaltung ist unter `/snaps/` erreichbar (📸 Snapshots in der Navbar, zwischen Alerts und Kapazitätsreport) und bietet eine zentrale Übersicht aller HANA-Datenbank-Snapshots, die auf Pure FlashArray- und NetApp ONTAP-Systemen gespeichert sind.

### Übersicht

Der Hintergrund-Collector erfasst alle 15 Minuten automatisch die aktuellen Snapshots aller konfigurierten Systeme und schreibt sie in die Datenbank. Bestehende Einträge werden aktualisiert, Snapshots die auf dem Storage nicht mehr existieren (manuell gelöscht oder umbenannt), werden automatisch aus der Datenbank entfernt – bei Einträgen mit Operator-Kommentar werden stattdessen die Präsenz-Flags auf ✘ gesetzt, sodass die Anmerkung erhalten bleibt.

![Snapshot-Verwaltung – Übersicht](screenshots/snaps-overview.png)

*Übersicht mit Statistik-Panel (18 Snapshots, davon 9 älter als 5 Tage), Filter-Leiste und sortierbare Tabelle mit automatischen DB/NFS-Präsenz-Badges (✔/✘)*

### Detail-Ansicht (aufgeklappt)

Durch Klick auf den ▶-Button wird eine Zeile aufgeklappt und zeigt die konkreten Storage-Objekte:

![Snapshot-Detail mit FlashArray und ONTAP](screenshots/snaps-detail.png)

*Detail-Ansicht: FlashArray-Snapshots (fa-prod-block-01) mit LUN-Namen und ONTAP-Volumes (vol_bwp_data, vol_bwp_log) auf ontap-prod-01 / svm_bwp*

### Funktionen im Überblick

| Funktion | Beschreibung |
|---------|-------------|
| **Automatische Erfassung** | Hintergrund-Collector (alle 15 Min.) liest FlashArray- und ONTAP-Snapshots via REST API |
| **Abgleich mit Storage** | Bei jedem Lauf werden Datenbankeinträge, die nicht mehr auf dem Storage existieren, gelöscht oder als abwesend markiert |
| **SID-Erkennung** | Extraktion der 3–5-stelligen SAP-SID aus dem Snapshot-Namen (z.B. `ACP_1_data.HDBSNAP-…` → SID `ACP`) |
| **TTL-Anzeige & Bearbeitung** | Ablaufzeitstempel wird aus dem Snapshot-Namen extrahiert, per ✏️-Modal bearbeitbar; generiert CURL-Simulation für Rename |
| **DB / NFS-Präsenz** | Automatisch befüllt: ✔ wenn FlashArray-Snapshot vorhanden, ✔ wenn ONTAP-Snapshot vorhanden |
| **Operator-Kommentare** | Freitext-Bemerkung pro Snapshot, in-place editierbar |
| **Lösch-Planung** | Lösch-Markierung mit 24h-Countdown und Rückgängig-Funktion |
| **Filter** | Filterung nach SID, Erstellungsdatum (von/bis) und TTL (von/bis) |
| **Sortierung** | Alle Spalten sortierbar (SID, Datum, TTL, DB, NFS) |
| **Statistik-Panel** | Schnellüberblick: Snapshots gesamt, älter 5 Tage (orange), älter 10 Tage (rot), letzte Aktualisierung |
| **Manueller Trigger** | 🔄-Button löst sofortigen Collector-Lauf aus |

### Hintergrund-Collector

Der Collector (`app/snap_service.py`) läuft als Daemon-Thread parallel zu den anderen Services:

- **Intervall**: 15 Minuten (konfigurierbar via `SNAP_COLLECT_INTERVAL_SECONDS`)
- **Quellen**: Pure FlashArray (REST API v2 `/volume-snapshots`) + NetApp ONTAP (`/storage/volumes/{uuid}/snapshots`)
- **SID-Extraktion**: Regex-basiert aus Snapshot-Name (`ACP_1_data.HDBSNAP-…` → `ACP`)
- **TTL-Extraktion**: Zeitstempel-Suffix `HDBSNAP-YYYY-MM-DD-HHMMSS` oder `vgSID.YYYY-MM-DD-HHMMSS`
- **Aggregierung**: Mehrere FlashArray-LUN-Snapshots derselben SID + Zeitstempel werden zu einem Datensatz zusammengefasst
- **Reconciliation**: Nach jedem Lauf werden veraltete DB-Einträge (nicht mehr auf Storage vorhanden) gelöscht oder als abwesend markiert

---

## 6. System-Detailansicht

Erreichbar über den **Details**-Button einer Systemkarte oder direkt via `/systems/<id>/details`.

![System-Detailansicht](screenshots/system-details.png)

**Angezeigte Informationen:**
- Hersteller, Live-Status (oder letzter Caching-Zustand mit Hinweis-Banner)
- Hardware-Status, Cluster-Status, Alerts-Zähler
- Kapazität (Gesamt/Genutzt/Frei/Auslastung) – mit Pure1-Korrekturwerten wenn verfügbar
- Netzwerk-Information (IP, Ports)
- Cluster-Informationen (Typ, Partner)
- Node-Details, Hardware-Komponenten (wenn verfügbar)

> **Caching-Fallback**: Wenn die Live-Abfrage fehlschlägt (z.B. kein Netz), werden automatisch die zuletzt gecachten Status-Daten angezeigt – mit gelbem Hinweis-Banner.

---

## 7. Kapazitätsreport

Der Kapazitätsreport ist unter `/capacity/` erreichbar und bietet fünf Tabs.

### Tab: Nach Storage Art

Kapazitäten gruppiert nach Storage-Typ (Block → File → Object → Archiv → Backup), jeweils mit Untergruppierung nach Umgebung.

![Kapazitätsreport – Nach Storage Art](screenshots/capacity-by-storage-art.png)

### Tab: Nach Umgebung

Kapazitäten gruppiert nach Betriebsumgebung (Produktion / Test/Dev), jeweils mit Untergruppierung nach Storage Art.

![Kapazitätsreport – Nach Umgebung](screenshots/capacity-by-environment.png)

### Tab: Nach Tätigkeitsfeld

Kapazitäten gruppiert nach Themenzugehörigkeit (Mandant-1, Mandant-2, Apps, …), jeweils mit Aufschlüsselung nach Umgebung und Storage Art.

![Kapazitätsreport – Nach Tätigkeitsfeld](screenshots/capacity-by-department.png)

### Tab: Details

Alle Einzelsysteme mit Umgebung, Tätigkeitsfeld, Gesamt/Genutzt/Frei und Auslastungs-Balken.

![Kapazitätsreport – Details](screenshots/capacity-details.png)

### Tab: Verlauf

Historische Kapazitätsgraphen (2 Jahre tägliche Datenpunkte) für alle Storage-Typen:
- **Block**: Physische Kapazität + SoD-Vertragswerte parallel (mit Linienfilter)
- **File / Object / Archiv / Backup**: Genutzte Kapazität je System

![Kapazitätsreport – Verlauf](screenshots/capacity-history.png)

**Verlauf-Steuerleiste** (Zeitraum, Export, Import):

![Kapazitätsreport – Verlauf Steuerleiste](screenshots/capacity-history-controls.png)

**Weitere Kapazitäts-Features:**
- Zeitraum-Filter: Alle / 2 Jahre / 1 Jahr / 6 Monate / 3 Monate
- Export: CSV, Excel, PDF
- Import: CSV-Upload für physische Systeme und SoD-Daten
- Prognose: Wachstumsprognose im Verlaufsgraphen
- Pure1 SoD-Tab: Nur sichtbar wenn Pure1 in Einstellungen konfiguriert

---

## 8. Admin-Bereich

Der Admin-Bereich (`/admin`) ist durch Login geschützt und enthält Systemverwaltung, Einstellungen, Logs, Zertifikate und Tags.

![Admin-Bereich](screenshots/admin-area.png)

**Hauptfunktionen:**
- Storage-Systeme hinzufügen, bearbeiten, löschen
- Systeme aktivieren/deaktivieren
- Auto-Discovery (Erkennung von Cluster-Topologien, IPs, Node-Details)
- Import/Export von Systemkonfigurationen
- Logs-Viewer mit Filter- und Such-Funktionen
- Zertifikatsverwaltung
- Tag-Verwaltung

### Logs-Viewer

![Admin Logs](screenshots/admin-logs.png)

### Zertifikatsverwaltung

Upload eigener CA- und Root-Zertifikate für Storage-Systeme mit selbst-signierten Zertifikaten.

![Zertifikate](screenshots/certificates-page.png)

### Tag-Verwaltung

Tags können in Gruppen organisiert werden (z.B. „Storage Art", „Landschaft", „Themenzugehörigkeit") und werden für Filterung und Kapazitätsgrupierung verwendet.

![Tags](screenshots/tags-page.png)

---

## 9. Einstellungen

Erreichbar unter **Admin → Einstellungen** (`/admin/settings`). Die Einstellungen sind in sechs Tabs unterteilt.

### Tab: Design

Firmenname, Logo und Farbschema (Primär-, Sekundär- und Akzentfarbe).

![Einstellungen – Design](screenshots/settings-design.png)

### Tab: Logs

Maximale Anzahl Logs pro System, Aufbewahrungsdauer und minimales Log-Level.

![Einstellungen – Logs](screenshots/settings-logs.png)

### Tab: Zertifikate

Upload eigener CA- und Root-Zertifikate für Storage-Systeme mit selbst-signierten Zertifikaten.

![Einstellungen – Zertifikate](screenshots/settings-certificates.png)

### Tab: API-Zugänge (Pure1)

Konfiguration der Pure1 REST API für Storage on Demand Daten. App-ID, Private Key (PEM), Passphrase und Public Key werden **verschlüsselt** gespeichert.

![Einstellungen – API-Zugänge (Pure1)](screenshots/settings-api-access-pure1.png)

### Tab: Proxy

HTTP/HTTPS-Proxy für ausgehende Internet-Verbindungen (z.B. für Pure1). Proxy-URLs werden **verschlüsselt** gespeichert.

![Einstellungen – Proxy](screenshots/settings-proxy.png)

### Tab: System

Zeitzone und Hintergrund-Aktualisierungsintervall (1–60 Minuten).

![Einstellungen – System](screenshots/settings-system.png)

---

## 10. API & Swagger UI

Das Dashboard stellt eine vollständige REST API bereit. Die interaktive Swagger UI ist unter `/admin/swagger` erreichbar.

### Swagger UI

![Swagger UI](screenshots/swagger-ui.png)

Die API umfasst folgende Endpunkte:

| Methode | Pfad | Beschreibung |
|---------|------|-------------|
| `GET` | `/` | Haupt-Dashboard (HTML) |
| `GET` | `/api/systems` | Alle Storage-Systeme auflisten |
| `GET` | `/api/status` | Live-Status aller aktiven Systeme |
| `GET` | `/api/systems/{id}/status` | Live-Status eines einzelnen Systems |
| `GET` | `/api/cached-status` | Gecachter Status aller aktiven Systeme |
| `POST` | `/api/trigger-status-refresh` | Sofortige Statusaktualisierung auslösen |
| `GET` | `/systems/{id}/details` | Detailansicht eines Systems |
| `GET` | `/capacity/` | Kapazitätsreport |
| `GET` | `/alerts/` | Alerts-Seite |
| `GET` | `/admin/*` | Admin-Bereich (erfordert Anmeldung) |

### API-Dokumentation (Einrichtungsanleitung)

Unter `/admin/docs` finden Sie eine detaillierte Einrichtungsanleitung für jeden unterstützten Hersteller.

![API-Dokumentation](screenshots/admin-docs.png)

**OpenAPI-Spezifikation** herunterladen: `/static/openapi.json`

---

## 11. Systemanforderungen

- **Betriebssystem**: Linux (SUSE 15, Ubuntu 22+, RHEL 8+, oder vergleichbar)
- **Python**: 3.8 oder höher
- **Datenbank**: PostgreSQL (empfohlen) oder SQLite
- **Netzwerk**: HTTPS-Zugriff zu den Storage-Systemen (Port 443)

> **Empfehlung**: PostgreSQL für Produktivumgebungen – SQLite kann bei vielen parallelen Zugriffen zu Sperrkonflikten führen. Für Container-Deployments wird PostgreSQL automatisch über `docker-compose.yml` mitgestartet.

---

## 12. Installation

### Option 1: Container-Deployment (Empfohlen)

```bash
git clone https://github.com/TimUx/storage-dashboard.git
cd storage-dashboard

# Secret Keys generieren und in .env speichern
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env
python3 -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_hex(32))" >> .env
echo "SSL_VERIFY=false" >> .env

# Mit Podman starten
podman-compose up -d

# Oder mit Docker
docker-compose up -d

# Oder mit nerdctl
nerdctl compose up -d
```

Das Dashboard ist dann verfügbar unter: `http://localhost:5000`

📖 **Container-Dokumentation**: [CONTAINER.md](CONTAINER.md)

### Option 2: Manuelle Installation

```bash
# 1. Repository klonen
git clone https://github.com/TimUx/storage-dashboard.git
cd storage-dashboard

# 2. Virtual Environment erstellen
python3 -m venv venv
source venv/bin/activate

# 3. Abhängigkeiten installieren
pip install -r requirements.txt

# 4. Konfiguration anpassen
cp .env.example .env
# .env bearbeiten: SECRET_KEY, DATABASE_URL, SSL_VERIFY

# 5. Datenbank initialisieren und migrieren
python cli.py migrate

# 6. Server starten
python run.py
```

---

## 13. Admin-Benutzer erstellen

Vor der ersten Nutzung muss ein Admin-Benutzer angelegt werden:

### Manuelle Installation

```bash
python cli.py admin create-user
```

### Container (Docker/Podman/nerdctl)

```bash
# Docker
docker exec -it storage-dashboard python cli.py admin create-user

# Podman
podman exec -it storage-dashboard python cli.py admin create-user

# nerdctl
nerdctl exec -it storage-dashboard python cli.py admin create-user
```

Der Admin-Bereich ist dann unter `http://localhost:5000/admin` erreichbar.

---

## 14. CLI-Interface

### Lokale CLI (`cli.py`)

```bash
# Dashboard anzeigen
python cli.py dashboard

# Systeme verwalten
python cli.py admin list
python cli.py admin add
python cli.py admin enable <ID>
python cli.py admin disable <ID>
python cli.py admin remove <ID>

# Datenbank migrieren
python cli.py migrate
```

### Remote CLI (`remote-cli.py`)

```bash
# Dashboard (Standard: http://localhost:5000)
python remote-cli.py dashboard

# Remote-System
python remote-cli.py --url http://dashboard.example.com:5000 dashboard

# Alle Systeme auflisten
python remote-cli.py systems

# Status eines Systems
python remote-cli.py status <ID>

# Daten exportieren
python remote-cli.py export --format json
python remote-cli.py export --format table
```

📖 **Remote-CLI-Dokumentation**: [REMOTE_CLI.md](REMOTE_CLI.md)

---

## 15. Deployment

### Produktivumgebung mit Gunicorn

```bash
gunicorn -w 4 -b 0.0.0.0:5000 run:app
```

### systemd-Service

```bash
sudo cp storage-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable storage-dashboard
sudo systemctl start storage-dashboard
```

### Datenbankmigrationen

Das Dashboard verfügt über ein eingebautes Migrationssystem (`app/migrations.py`), das bei jedem Start automatisch ausgeführt wird und fehlende Spalten ergänzt. Bei Bedarf kann die Migration auch manuell ausgeführt werden:

```bash
python cli.py migrate
```

### Umgebungsvariablen

| Variable | Beschreibung | Standard |
|----------|-------------|---------|
| `SECRET_KEY` | Flask Session-Secret (zufälliger Hex-String) | — (Pflichtfeld) |
| `DATABASE_URL` | Datenbankverbindung | `sqlite:///storage_dashboard.db` |
| `SSL_VERIFY` | TLS-Zertifikate prüfen | `true` |
| `FLASK_ENV` | `development` oder `production` | `production` |
| `POSTGRES_PASSWORD` | PostgreSQL-Passwort (nur Container) | — |

📖 **Deployment-Dokumentation**: [DEPLOYMENT.md](DEPLOYMENT.md)  
📖 **Sicherheits-Dokumentation**: [SECURITY.md](SECURITY.md)  
📖 **Container-Dokumentation**: [CONTAINER.md](CONTAINER.md)  
📖 **Administrator-Handbuch**: [ADMIN_GUIDE.md](ADMIN_GUIDE.md)  
📖 **Developer Guide**: [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md)  
📖 **REST API Schnittstellendokumentation**: [API_DOCUMENTATION.md](API_DOCUMENTATION.md)

---

## 16. DR Planner – Disaster Recovery Operations

### Überblick

Der DR Planner ist ein integriertes Modul für Disaster Recovery Operations, das unter `/dr/` erreichbar ist. Er ermöglicht Betreibern, DR-Beziehungen automatisch zu entdecken, Runbooks dynamisch zu generieren und CLI-Befehle für Failover-Szenarien bereitzustellen – alles basierend auf tatsächlichen Systemkonfigurationen.

### DR-Beziehungen entdecken

Der DR Planner erkennt automatisch DR-Beziehungen für folgende Technologien:

| Technologie | Hersteller | Erkannte Beziehungstypen |
|---|---|---|
| Pure FlashArray | Pure Storage | ActiveCluster (Synchron) |
| ONTAP MetroCluster | NetApp | MetroCluster (Synchron, Site-Level) |
| ONTAP SnapMirror | NetApp | SnapMirror (Asynchron) |
| StorageGRID | NetApp | Multi-Site Grid (ILM-Replikation) |
| DataDomain | Dell | MTree-Replikation |

Die Erkennung analysiert die zwischengespeicherten Statusdaten (`StatusCache`) der konfigurierten Systeme und identifiziert:
- Cluster-Beziehungen
- Replikationspaare
- Multi-Site Grid-Mitgliedschaften
- Replikationsstatus (healthy / degraded / unknown)

### DR-Informationen generieren

Der DR Planner generiert alle DR-Artefakte **dynamisch** auf Basis von:
- Entdeckten DR-Beziehungen
- Systemkonfiguration aus den APIs
- Erkannter Storage-Technologie
- Herstellerspezifischer Best-Practice-Logik

Generierte Artefakte je DR-Beziehung:
- **DR Workflows**: Strukturierte Failover-Schrittlisten
- **DR Runbooks**: Phasenweise Anleitungen (Pre-Failover / Failover / Post-Failover)
- **CLI-Befehlssätze**: Systemspezifische Befehle mit konkreten Systemwerten
- **Mermaid-Diagramme**: Topologie- und Workflow-Diagramme

### DR Build Pipeline (Hintergrundjob)

Der DR Planner verwendet einen wöchentlichen Hintergrund-Build-Job (Standard: einmal pro Woche). Die Pipeline führt folgende Schritte aus:

1. DR-Beziehungen entdecken
2. Systemkonfiguration über bestehende API-Clients abrufen
3. DR-Topologiemodelle erstellen
4. DR-Workflows generieren
5. Mermaid-Diagramme generieren
6. CLI-Befehlssätze generieren
7. DR-Runbook-Strukturen generieren
8. Alle Artefakte in PostgreSQL speichern

**Wichtig**: Die DR-Seite im Browser ruft zur Laufzeit keine Storage-APIs auf. Alle Daten stammen aus der PostgreSQL-Datenbank.

### Scheduler-Konfiguration

Der Build-Intervall ist über die Umgebungsvariable `DR_BUILD_INTERVAL_SECONDS` konfigurierbar:

```bash
# Standard: 1 Woche (604800 Sekunden)
DR_BUILD_INTERVAL_SECONDS=604800

# Beispiel: täglich um Mitternacht (86400 Sekunden)
DR_BUILD_INTERVAL_SECONDS=86400

# Beispiel: alle 12 Stunden
DR_BUILD_INTERVAL_SECONDS=43200
```

Ohne die Umgebungsvariable wird der Standard von 7 Tagen (eine Woche) verwendet.

### DR Planner bedienen

1. **DR Planner öffnen**: `/dr/` im Browser aufrufen oder auf „🛡️ DR Planner" in der Navigation klicken.
2. **Topologie-Übersicht**: Alle erkannten DR-Beziehungen werden in einer Tabelle angezeigt.
3. **System auswählen**: Auf eine Zeile klicken oder das Dropdown „System auswählen" verwenden.
4. **Failover-Richtung**: Zwischen „Planned Failover" und „Failback" umschalten.
5. **Architektur-Diagramm**: Zeigt die Topologie des gewählten Systems inkl. Rechenzentren, Cluster, Controller, VIPs und Replikationslinks.
6. **Workflow-Diagramm**: Zeigt den Failover-Ablauf als Flussdiagramm.
7. **Runbook**: Strukturierte Schritt-für-Schritt-Anleitung für den Failover.
8. **CLI Console**: Herstellerspezifische Befehle für das gewählte System und die Richtung.
9. **Manueller Rebuild**: „🔄 Rebuild DR Information"-Button mit Bestätigungsdialog.

### Screenshots

![DR Topology Overview](screenshots/dr-topology-overview.png)

*DR Topology Overview – Übersicht aller erkannten DR-Beziehungen mit Build-Status-Panel*

![DR Architecture & Workflow Diagrams](screenshots/dr-architecture-diagram.png)

*DR Architecture Diagram (links) zeigt Rechenzentren, Controller und VIPs; Failover Workflow Diagram (rechts) zeigt die Ablaufschritte*

![DR Runbook & CLI Console](screenshots/dr-runbook-cli.png)

*DR Runbook (oben) mit phasenweisen Schritten; CLI Command Console (unten) mit herstellerspezifischen Befehlen*

### DR-Build-Status

Der Build-Status-Bereich oben auf der DR-Seite zeigt:
- **Last Generated**: Zeitpunkt des letzten Builds
- **Build Status**: success / running / error
- **Systems Processed**: Anzahl verarbeiteter Systeme
- **DR Relationships Detected**: Anzahl erkannter DR-Beziehungen
- **Next Scheduled Build**: Geplanter nächster automatischer Build

Bei veralteten Daten (älter als der konfigurierten Build-Intervall) wird eine Warnung angezeigt.

### DR API-Endpunkte

| Methode | Endpunkt | Beschreibung |
|---|---|---|
| GET | `/dr/api/topology` | Alle DR-Beziehungen im letzten Build |
| GET | `/dr/api/system/<name>` | Alle DR-Artefakte für ein System |
| GET | `/dr/api/architecture/<name>` | Topologiemodell und Architekturdiagramm |
| GET | `/dr/api/workflow/<name>` | Workflow-Schritte und Diagramm |
| GET | `/dr/api/runbook/<name>` | Runbook-Sektionen |
| GET | `/dr/api/commands/<name>` | CLI-Befehlssatz |
| GET | `/dr/api/build-status` | Metadaten des letzten Builds |
| POST | `/dr/api/rebuild` | Manuellen Rebuild auslösen |

Parameter `?direction=planned_failover` oder `?direction=failback` für alle systemspezifischen Endpunkte.

### DR-Datenbank-Schema

Der DR Planner nutzt dieselbe PostgreSQL-Datenbank wie das gesamte Dashboard. Neue Tabellen:

| Tabelle | Inhalt |
|---|---|
| `dr_build_metadata` | Build-Metadaten (Timestamp, Status, Anzahl Systeme/Beziehungen) |
| `dr_relationships` | Entdeckte DR-Beziehungen |
| `dr_topology_models` | Topologiemodelle je System |
| `dr_workflows` | Generierte Failover-Workflows |
| `dr_runbooks` | Generierte Runbook-Strukturen |
| `dr_command_sets` | Generierte CLI-Befehlssätze |
| `dr_mermaid_diagrams` | Generierte Mermaid-Diagramme |

---

*Storage Dashboard v1.3 – Created by [Timo Braun](mailto:github@timobraun.de)*
