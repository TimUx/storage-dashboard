# Storage Dashboard – Developer Guide

Dieses Dokument beschreibt die Architektur, Codestruktur, verwendeten Technologien,
Module, Komponenten, Workflows und Abhängigkeiten des Storage Dashboard.

---

## Inhaltsverzeichnis

1. [Projektübersicht](#1-projektübersicht)
2. [Technologie-Stack](#2-technologie-stack)
3. [Architektur](#3-architektur)
4. [Verzeichnisstruktur](#4-verzeichnisstruktur)
5. [Datenmodell (Database Schema)](#5-datenmodell-database-schema)
6. [Module und Komponenten](#6-module-und-komponenten)
7. [API-Client-Schicht](#7-api-client-schicht)
8. [Hintergrund-Services](#8-hintergrund-services)
9. [HTTP-Routen und Blueprints](#9-http-routen-und-blueprints)
10. [Frontend-Architektur](#10-frontend-architektur)
11. [Workflows](#11-workflows)
12. [Authentifizierung und Sicherheit](#12-authentifizierung-und-sicherheit)
13. [Konfiguration und Umgebungsvariablen](#13-konfiguration-und-umgebungsvariablen)
14. [Tests](#14-tests)
15. [CI/CD und Container](#15-cicd-und-container)
16. [Abhängigkeiten](#16-abhängigkeiten)
17. [Erweiterung: Neuen Vendor hinzufügen](#17-erweiterung-neuen-vendor-hinzufügen)

---

## 1. Projektübersicht

Storage Dashboard ist eine **Python/Flask-basierte Webanwendung** zur zentralen
Überwachung heterogener Storage-Umgebungen. Es verbindet sich über herstellerspezifische
REST APIs ohne proprietäre SDKs mit Storage-Systemen und aggregiert Status-, Kapazitäts-
und Alert-Daten in einer einheitlichen Oberfläche.

**Unterstützte Vendors:**
- Pure Storage FlashArray (REST API v2)
- NetApp ONTAP 9 (ONTAP REST API)
- NetApp StorageGRID 11 (Grid Management API v4)
- Dell DataDomain (DataDomain REST API v1.0)

---

## 2. Technologie-Stack

### Backend

| Technologie | Version | Zweck |
|------------|---------|-------|
| **Python** | 3.11+ | Primäre Sprache |
| **Flask** | 3.0.0 | Web-Framework |
| **Flask-SQLAlchemy** | 3.1.1 | ORM und Datenbankabstraktion |
| **Flask-Login** | 0.6.3 | Session-basierte Authentifizierung |
| **Gunicorn** | 22.0.0 | WSGI-Server für Produktion |
| **requests** | 2.31.0 | HTTP-Client für API-Calls |
| **cryptography** | ≥41.0.0 | Fernet-Verschlüsselung + Pure1 JWT (RSA/RS256) |
| **python-dotenv** | 1.0.0 | Konfiguration über .env-Dateien |
| **pytz** | 2024.1 | Zeitzonenkonvertierung |
| **openpyxl** | 3.1.2 | Excel-Export |
| **tabulate** | 0.9.0 | Tabellenformatierung für CLI |
| **click** | 8.1.7 | CLI-Framework |

### Datenbank

| Option | Zweck |
|--------|-------|
| **PostgreSQL 16** | Empfohlen für Produktion (parallele Schreibzugriffe, mehrere Worker) |
| **SQLite** | Entwicklung / kleine Deployments (WAL-Modus, NullPool-Konfiguration) |
| **psycopg2-binary** | PostgreSQL-Datenbankadapter für Python |

### Frontend

| Technologie | Zweck |
|------------|-------|
| **Jinja2** | Server-seitiges HTML-Templating (Flask built-in) |
| **Bootstrap 5** | CSS-Framework (CDN) |
| **Vanilla JavaScript** | Interaktivität, Auto-Refresh, Filter |
| **Chart.js** | Kapazitätsgraphen (lokal gebundelt: `chart.umd.min.js`) |
| **Swagger UI** | Interaktive API-Dokumentation (lokal gebundelt) |

### Containerisierung

| Technologie | Zweck |
|------------|-------|
| **Docker / Podman / nerdctl** | Container-Runtime |
| **docker-compose** | Multi-Container-Orchestrierung |
| **GitHub Container Registry** | Image-Distribution (`ghcr.io/timux/storage-dashboard`) |

---

## 3. Architektur

### 3.1 Systemarchitektur (Überblick)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Browser / CLI                                │
│                    (Dashboard, Admin, API)                          │
└────────────────────────────┬────────────────────────────────────────┘
                             │ HTTP/HTTPS
┌────────────────────────────▼────────────────────────────────────────┐
│                  Nginx Reverse Proxy (optional)                     │
│                         Port 443 / 80                               │
└────────────────────────────┬────────────────────────────────────────┘
                             │ HTTP
┌────────────────────────────▼────────────────────────────────────────┐
│                   Flask/Gunicorn (Port 5000)                        │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                   Flask Application                          │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────────────┐  │   │
│  │  │  Blueprint  │  │  Blueprint  │  │     Blueprint      │  │   │
│  │  │   /main     │  │   /admin    │  │      /api          │  │   │
│  │  └──────┬──────┘  └──────┬──────┘  └────────┬───────────┘  │   │
│  │         │                │                   │              │   │
│  │  ┌──────▼────────────────▼───────────────────▼───────────┐  │   │
│  │  │              Service Layer                             │  │   │
│  │  │  status_service │ capacity_service │ sod_service       │  │   │
│  │  └──────────────────────┬────────────────────────────────┘  │   │
│  │                         │                                    │   │
│  │  ┌──────────────────────▼────────────────────────────────┐  │   │
│  │  │              API Client Layer                          │  │   │
│  │  │  PureStorageClient │ NetAppONTAPClient │               │  │   │
│  │  │  StorageGRIDClient │ DellDataDomainClient              │  │   │
│  │  └──────────────────────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────┘   │
└────────────────────────────┬────────────────────────────────────────┘
                             │ SQLAlchemy ORM
┌────────────────────────────▼────────────────────────────────────────┐
│               PostgreSQL / SQLite Datenbank                         │
└─────────────────────────────────────────────────────────────────────┘
                             │
       ┌─────────────────────┼──────────────────────┐
       │ HTTPS               │ HTTPS                │ HTTPS/3009
┌──────▼──────┐   ┌──────────▼──────────┐   ┌──────▼──────────────┐
│Pure Storage │   │ NetApp ONTAP/        │   │ Dell DataDomain     │
│FlashArray   │   │ StorageGRID          │   │                     │
└─────────────┘   └─────────────────────┘   └─────────────────────┘
```

### 3.2 Hintergrund-Threading-Architektur

```
Gunicorn Master Process
│
├── Worker 1 (Flask)
│   ├── HTTP Request Handler
│   └── Background Threads:
│       ├── status_service._background_loop()    (kontinuierlich, konfigurierbar 1-60 min)
│       ├── capacity_service._background_loop()  (stündlich)
│       └── sod_service._background_loop()       (wöchentlich)
│
├── Worker 2 (Flask) — nur Request Handler (keine weiteren Background Threads)
├── Worker 3 ...
└── Worker 4 ...
```

> **Hinweis:** Background Threads werden pro Worker-Prozess mit einem Lock-Mechanismus
> (`_background_thread_started`) auf genau einen Thread beschränkt.

### 3.3 Datenfluss: Status-Refresh

```
Browser (Auto-Refresh / manueller Click)
    │
    ▼
GET /api/cached-status
    │
    ▼
StatusCache (DB-Tabelle)
    │ liest gecachten Wert
    ▼
JSON-Response → UI aktualisiert sich

(Hintergrund, parallel)
status_service._background_loop()
    │
    ▼
StorageSystem.query.filter_by(enabled=True)  ← Alle aktiven Systeme
    │
    ▼
ThreadPoolExecutor (max 32 Worker)
    │
    ├── fetch_system_status(system_1)  → get_client() → API-Call → StatusCache schreiben
    ├── fetch_system_status(system_2)  → ...
    └── fetch_system_status(system_N)  → ...
```

---

## 4. Verzeichnisstruktur

```
storage-dashboard/
│
├── app/                          # Hauptanwendung (Flask-Package)
│   ├── __init__.py               # App-Factory, DB-Init, Login-Manager, Jinja2-Filter
│   ├── models.py                 # SQLAlchemy ORM-Modelle (DB-Schema)
│   ├── constants.py              # Globale Konstanten (Vendor-Ports, etc.)
│   ├── crypto_utils.py           # Fernet-Verschlüsselung für sensible Felder
│   ├── ssl_utils.py              # SSL-Verifizierungs-Helfer (CA-Zertifikate, is_ip_address)
│   ├── migrations.py             # Datenbank-Migrationssystem (schema-updates ohne ORM)
│   ├── discovery.py              # Auto-Discovery: Reverse-DNS, Cluster-Topologie
│   ├── status_service.py         # Background-Service: Status-Polling & Caching
│   ├── capacity_service.py       # Background-Service: Kapazitätsdaten & History
│   ├── sod_service.py            # Background-Service: Pure1 SoD (wöchentlich)
│   ├── system_logging.py         # System-Log-Helfer (log_system_event)
│   │
│   ├── api/                      # Storage-System API-Clients
│   │   ├── __init__.py           # get_client() Factory-Funktion
│   │   ├── base_client.py        # Abstrakte Basisklasse StorageClient
│   │   ├── storage_clients.py    # Konkrete Clients: Pure, ONTAP, StorageGRID, DataDomain
│   │   ├── pure1_client.py       # Pure1 REST API Client (JWT/RS256)
│   │   └── dd_api.json           # DataDomain API-Spezifikation (Referenz)
│   │
│   ├── routes/                   # Flask Blueprints
│   │   ├── main.py               # Haupt-Dashboard, Detailansicht (/,  /systems/<id>/details)
│   │   ├── admin.py              # Admin-Bereich (/admin/*)
│   │   ├── api.py                # REST API Endpunkte (/api/*)
│   │   ├── alerts.py             # Alerts-Seite (/alerts/)
│   │   └── capacity.py           # Kapazitätsreport (/capacity/)
│   │
│   ├── templates/                # Jinja2 HTML-Templates
│   │   ├── base.html             # Basis-Layout (Navbar, CSS-Links, Block-Definitionen)
│   │   ├── dashboard.html        # Haupt-Dashboard
│   │   ├── alerts.html           # Alerts-Seite
│   │   ├── details.html          # System-Detailansicht
│   │   ├── capacity.html         # Kapazitätsreport
│   │   └── admin/                # Admin-Templates
│   │       ├── index.html        # Admin-Übersicht
│   │       ├── form.html         # Formular: System hinzufügen/bearbeiten
│   │       ├── settings_tabbed.html  # Einstellungen (6 Tabs)
│   │       ├── certificates.html     # Zertifikatsverwaltung
│   │       ├── tags.html             # Tag-Verwaltung
│   │       ├── logs.html             # Log-Viewer
│   │       ├── login.html            # Login-Seite
│   │       └── swagger.html          # Swagger UI Container
│   │
│   └── static/                   # Statische Assets
│       ├── openapi.json          # OpenAPI-Spezifikation (REST API)
│       ├── js/chart.umd.min.js   # Chart.js (lokal gebundelt)
│       └── swagger-ui/           # Swagger UI Assets (lokal gebundelt)
│
├── tests/                        # Pytest-Testsuites
│   ├── __init__.py
│   ├── test_alerts_page.py
│   ├── test_cached_status_capacity.py
│   ├── test_capacity_service_pure_dual_method.py
│   ├── test_compute_forecast.py
│   ├── test_dashboard_acknowledged_status.py
│   ├── test_migrations.py
│   ├── test_ontap_cluster_dns.py
│   ├── test_ontap_ems_alerts.py
│   ├── test_ontap_rest_status_alerts.py
│   ├── test_pure1_client.py
│   └── test_pure_controller_status.py
│
├── api/                          # API-Spezifikationen (Referenz)
│   ├── ontap_swagger.yaml        # NetApp ONTAP REST API Spec
│   ├── pure_swagger.json         # Pure Storage API Spec
│   ├── Pure1-1.latest.spec.yaml  # Pure1 API Spec
│   ├── grid-combined-schema.yml  # StorageGRID API Schema
│   └── dd_api.json               # DataDomain API Spec
│
├── examples/                     # Beispielskripte
│   ├── monitoring-example.py     # Python-Monitoring-Beispiel
│   ├── monitoring-example.sh     # Shell-Monitoring-Beispiel
│   └── seed_demo_data.py         # Demo-Datenbankbefüllung
│
├── run.py                        # Flask-Einstiegspunkt (dev/prod)
├── cli.py                        # Lokale CLI (click-basiert)
├── remote-cli.py                 # Remote CLI (HTTP API)
├── entrypoint.sh                 # Docker-Entrypoint (DB-Wait + Migrations)
├── Dockerfile                    # Multi-stage Dockerfile
├── docker-compose.yml            # Docker-Compose (App + PostgreSQL)
├── storage-dashboard.service     # systemd Service-Unit
├── requirements.txt              # Python-Abhängigkeiten
└── .env.example                  # Beispiel-Konfiguration
```

---

## 5. Datenmodell (Database Schema)

### 5.1 Entitäten-Übersicht

```
TagGroup (1) ──────────── (*) Tag
                                │ (M:N via storage_system_tags)
StorageSystem (*) ──────── (*) Tag
    │
    ├──── (1:N) StatusCache
    ├──── (1:N) CapacitySnapshot
    ├──── (1:N) CapacityHistory
    ├──── (1:N) SystemLog
    └──── (M:1 self) partner_cluster (MetroCluster/Active-Cluster)

AppSettings (1 Zeile)           # Singleton: Anwendungseinstellungen
AdminUser (N)                   # Login-Benutzer
Certificate (N)                 # CA/Root-Zertifikate
SubscriptionLicenseCache (1)    # Pure1 SoD-Lizenzdaten (JSON)
SodHistory (N)                  # Historische SoD-Werte
AlertState (N)                  # Alert-Acknowledge/Assignee/Kommentar
AssigneeHistory (N)             # Assignee-Verlauf (Autocomplete)
```

### 5.2 Wichtige Modelle im Detail

#### StorageSystem

Zentrale Entität – repräsentiert ein Storage-System.

| Feld | Typ | Beschreibung |
|------|-----|-------------|
| `id` | Integer PK | Automatische ID |
| `name` | String(100) unique | Systemname |
| `vendor` | String(50) | `pure`, `netapp-ontap`, `netapp-storagegrid`, `dell-datadomain` |
| `ip_address` | String(100) | Management-IP oder Hostname |
| `port` | Integer | API-Port (Standard: 443) |
| `enabled` | Boolean | Aktiv/Inaktiv |
| `_api_username` | String(500) | **Verschlüsselt** (Fernet) |
| `_api_password` | String(500) | **Verschlüsselt** (Fernet) |
| `_api_token` | Text | **Verschlüsselt** (Fernet) |
| `cluster_type` | String(50) | `local`, `ha`, `metrocluster`, `active-cluster`, `multi-site` |
| `node_count` | Integer | Anzahl Nodes (Auto-Discovery) |
| `dns_names` | Text (JSON) | Auto-entdeckte DNS-Namen |
| `all_ips` | Text (JSON) | Alle Management-IPs |
| `node_details` | Text (JSON) | Node-Details (Name, IP, Status, Rolle) |
| `os_version` | String(100) | OS/Firmware-Version |
| `partner_cluster_id` | FK → self | Für MetroCluster/Active-Cluster |
| `pure1_array_name` | String(100) | Pure1-Lookup-Name (überschreibt `name`) |

#### StatusCache

Gecachte Status-Daten (1 Zeile pro System, immer überschrieben).

| Feld | Typ | Beschreibung |
|------|-----|-------------|
| `system_id` | FK → StorageSystem | Unique (1:1) |
| `status_json` | Text | Vollständiges Status-Objekt als JSON |
| `error` | Text | Fehlermeldung (falls vorhanden) |
| `fetched_at` | DateTime | Zeitpunkt des letzten Fetches |

Das Status-JSON-Format:

```json
{
  "status": "ok | warning | error | offline",
  "hardware_status": "ok | warning | error",
  "cluster_status": "ok | warning | error",
  "alerts": [...],
  "capacity_total_tb": 100.0,
  "capacity_used_tb": 60.0,
  "capacity_percent": 60.0,
  "vendor": "pure",
  "platform": "FlashArray//X70R3",
  "nodes": [...],
  "error": null
}
```

#### CapacityHistory

Tägliche Kapazitätsdatenpunkte (max. 2 Jahre Verlauf).

| Feld | Typ | Beschreibung |
|------|-----|-------------|
| `system_id` | FK → StorageSystem | |
| `date` | Date | Datum des Datenpunkts |
| `total_tb` | Float | Gesamtkapazität in TB |
| `used_tb` | Float | Genutzte Kapazität in TB |
| `free_tb` | Float | Freie Kapazität in TB |
| `percent_used` | Float | Auslastung in % |
| Unique: | (`system_id`, `date`) | Pro System und Tag ein Datenpunkt |

#### AlertState

Speichert Acknowledge-/Assignee-/Kommentar-Zustand pro Alert.

| Feld | Typ | Beschreibung |
|------|-----|-------------|
| `key` | String(255) unique | `make_key(system_name, alert_id, title)` |
| `acknowledged` | Boolean | Alert bestätigt |
| `assignee` | String(100) | Zugewiesener Benutzer |
| `comment` | Text | Freitext-Kommentar |
| `updated_at` | DateTime | Letzter Update |


---

## 6. Module und Komponenten

### 6.1 App-Factory (`app/__init__.py`)

Die Flask-Anwendung wird über eine Factory-Funktion `create_app()` erstellt (Application Factory Pattern).

**Aufgaben:**
- Flask-Instanz erstellen
- Datenbankverbindung konfigurieren (PostgreSQL oder SQLite)
- SQLite WAL-Mode aktivieren (bei SQLite-Betrieb)
- Flask-Login initialisieren (`LoginManager`)
- Blueprint-Registrierung
- Jinja2-Filter registrieren (`format_datetime`)
- Hintergrund-Threads starten (`status_service`, `capacity_service`, `sod_service`)

```python
# Vereinfachter Ablauf create_app():
app = Flask(__name__)
app.config[...] = ...          # Konfiguration
db.init_app(app)               # SQLAlchemy
login_manager.init_app(app)    # Flask-Login

# Blueprints registrieren
app.register_blueprint(main_bp)
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(api_bp, url_prefix='/api')
app.register_blueprint(alerts_bp, url_prefix='/alerts')
app.register_blueprint(capacity_bp, url_prefix='/capacity')

# Hintergrund-Threads starten
status_service.start_background_thread(app)
capacity_service.start_background_thread(app)
sod_service.start_background_thread(app)
```

### 6.2 Datenbankmigrationen (`app/migrations.py`)

Eigenständiges Migrationssystem (kein Alembic), das beim Start über `cli.py migrate`
oder automatisch im Entrypoint ausgeführt wird.

**Funktionsweise:**
- Prüft schema-Version und fehlende Spalten
- Fügt fehlende Spalten per `ALTER TABLE` hinzu
- Idempotent: Kann beliebig oft ausgeführt werden

### 6.3 Kryptographie (`app/crypto_utils.py`)

Alle sensiblen Felder (Passwörter, API-Tokens, Proxy-URLs, Pure1-Schlüssel) werden
transparent verschlüsselt gespeichert.

**Implementierung:**
- Verschlüsselung: **Fernet** (AES-128-CBC + HMAC-SHA256, authenticated encryption)
- Schlüsselableitung: **PBKDF2-HMAC-SHA256** aus `SECRET_KEY` Umgebungsvariable
- Salt: Fix (`b'storage-dashboard-salt'`) – sichert konsistente Schlüssel über Neustarts
- Backward-Compatibility: `decrypt_value()` gibt Plaintext zurück, wenn Token ungültig

```python
# Property-Pattern in SQLAlchemy-Modellen:
@property
def api_password(self):
    return decrypt_value(self._api_password)

@api_password.setter
def api_password(self, value):
    self._api_password = encrypt_value(value)
```

### 6.4 SSL-Utilities (`app/ssl_utils.py`)

Verwaltet die SSL-Verifizierungslogik für ausgehende API-Calls.

**Aufgaben:**
- `get_ssl_verify()`: Gibt `True`, Pfad zu CA-Bundle oder `False` zurück
- Lädt hochgeladene CA-Zertifikate aus der Datenbank
- Kombiniert firmeneigene CAs zu einem temporären Bundle

### 6.5 Auto-Discovery (`app/discovery.py`)

Ermittelt automatisch Cluster-Topologie, IPs und DNS-Namen.

**Funktionen:**
- `reverse_dns_lookup(ip)`: Reverse-DNS mit Forward-Verification
- `discover_system(system, app)`: Hersteller-spezifische Discovery
- Gibt Cluster-Typ, Node-Details, IPs und DNS-Namen zurück

---

## 7. API-Client-Schicht

### 7.1 Klassenhierarchie

```
StorageClient (ABC, app/api/base_client.py)
├── PureStorageClient       (app/api/storage_clients.py)
├── NetAppONTAPClient       (app/api/storage_clients.py)
├── NetAppStorageGRIDClient (app/api/storage_clients.py)
└── DellDataDomainClient    (app/api/storage_clients.py)
```

### 7.2 Abstrakte Basisklasse `StorageClient`

```python
class StorageClient(ABC):
    def __init__(self, ip_address, port, username, password, token):
        self.resolved_address = self._resolve_address(ip_address)
        self.base_url = f"https://{self.resolved_address}:{port}"

    @abstractmethod
    def get_health_status(self) -> dict:
        """Gibt vollständigen Status-Dict zurück"""

    @abstractmethod
    def get_capacity(self) -> dict:
        """Gibt Kapazitätsdaten zurück"""
```

**Gemeinsame Merkmale aller Clients:**
- Automatisches Reverse-DNS-Lookup beim Init
- Nutzung einer gemeinsamen `_local_session` (kein HTTP_PROXY für lokale Systeme!)
- SSL-Verifizierung über `get_ssl_verify()`
- Einheitliches Rückgabe-Format für `get_health_status()`

### 7.3 `PureStorageClient`

**Authentifizierung:** API-Token im Header `Authorization: Bearer <token>`

**Wichtige REST-Endpunkte:**

| Endpunkt | Zweck |
|---------|-------|
| `GET /api/2.0/arrays` | Array-Informationen und Kapazität |
| `GET /api/2.0/hardware` | Hardware-Komponenten-Status |
| `GET /api/2.0/alerts` | Aktive Alerts |
| `GET /api/2.0/array-connections` | Peer-Verbindungen (Active-Cluster) |
| `GET /api/2.0/pods` | Pod-Status (Active-Cluster) |

**Besonderheiten:**
- Erkennt automatisch Evergreen/One Dashboard API vs. Standard API
- Filtert Shelf-Controller aus Node-Liste heraus (`.SC`-Muster)
- Bei Evergreen/One: Kapazitätsdaten kommen von Pure1, nicht vom lokalen Array

### 7.4 `NetAppONTAPClient`

**Authentifizierung:** HTTP Basic Auth (`username:password`)

**Wichtige REST-Endpunkte:**

| Endpunkt | Zweck |
|---------|-------|
| `GET /api/cluster` | Cluster-Infos, OS-Version |
| `GET /api/cluster/nodes` | Node-Status und HA-State |
| `GET /api/cluster/health/alerts` | Hardware-Alerts |
| `GET /api/support/ems/events` | EMS Events (Emergency/Alert/Error) |
| `GET /api/cluster/peers` | Cluster-Peering |
| `GET /api/network/ethernet/ports` | Port-Status |
| `GET /api/network/ip/interfaces` | Netzwerk-Interfaces |
| `GET /api/storage/aggregates` | Aggregat-Status und Kapazität |
| `GET /api/storage/disks` | Festplatten-Status |
| `GET /api/snapmirror/relationships` | SnapMirror-Status |

**EMS-Alert-Filterung:**

ONTAP EMS ist ein Event-Log (kein State). Das Dashboard rekonstruiert den aktuellen
Zustand durch:
1. Problem/Recovery-Paare (`hm.alert.raised` / `hm.alert.cleared`)
2. Altersfilter: Nur Events der letzten 48h
3. Hardware/Nicht-Hardware Severity-Split
4. Nicht-Hardware `error`-Events werden unterdrückt

### 7.5 `NetAppStorageGRIDClient`

**Authentifizierung:** Bearer Token (auto-generiert aus User/PW wenn nötig)

**Wichtige REST-Endpunkte:**

| Endpunkt | Zweck |
|---------|-------|
| `GET /api/v3/authorize` | Token generieren |
| `GET /api/v3/grid/health/topology` | Grid-Topologie und Node-Status |
| `GET /api/v3/grid/health/status` | Gesundheitsstatus |
| `GET /api/v3/grid/storage-api-usage` | Storage-Nutzung |
| `GET /api/v3/grid/regions` | Regionen/Sites |

### 7.6 `DellDataDomainClient`

**Authentifizierung:** HTTP Basic Auth

**Wichtige REST-Endpunkte:**

| Endpunkt | Zweck |
|---------|-------|
| `GET /rest/v1.0/dd-systems/0/health` | System-Gesundheit |
| `GET /rest/v1.0/dd-systems/0/storage-units` | Storage-Informationen |
| `GET /rest/v1.0/dd-systems/0/alerts` | Aktive Alerts |
| `GET /rest/v1.0/dd-systems/0/services` | Service-Status |

### 7.7 Client-Factory `get_client()`

```python
# app/api/__init__.py (vereinfacht)
def get_client(vendor, ip_address, port, username, password, token):
    clients = {
        'pure':                PureStorageClient,
        'netapp-ontap':        NetAppONTAPClient,
        'netapp-storagegrid':  NetAppStorageGRIDClient,
        'dell-datadomain':     DellDataDomainClient,
    }
    return clients[vendor](ip_address, port, username, password, token)
```

---

## 8. Hintergrund-Services

### 8.1 `status_service.py` – Status-Polling

**Aufgabe:** Regelmäßiges Abrufen des Status aller aktiven Systeme und Caching in DB.

**Konfiguration:** Intervall konfigurierbar (1–60 Minuten) in Admin → Einstellungen → System.

```
start_background_thread(app)
    │
    ▼
_background_loop() [Thread]
    │
    ├── _do_refresh(app)          # Alle Systeme abfragen
    │   │
    │   ├── StorageSystem.query.filter_by(enabled=True)
    │   │
    │   └── _run_parallel_fetch(systems, app)
    │       │
    │       └── ThreadPoolExecutor (max 32 Worker)
    │           └── fetch_system_status(system, app)
    │               ├── get_client(vendor, ...)
    │               ├── client.get_health_status()
    │               └── log_system_event(...)
    │
    └── _upsert_cache_entry(StatusCache, db, system_id, status, now)
```

**Manueller Trigger:** `POST /api/trigger-status-refresh` → setzt `_refresh_now_event`

### 8.2 `capacity_service.py` – Kapazitätsdaten

**Aufgabe:** Stündliches Aktualisieren der Kapazitätsdaten und tägliches Speichern
von Verlaufsdatenpunkten (bis 2 Jahre).

**Intervall:** 1 Stunde (fest: `REFRESH_INTERVAL_SECONDS = 3600`)

**Pure1 Integration:**
- Bei Pure FlashArrays mit Evergreen/One Dashboard API: Kapazität kommt von Pure1
- Pure1-Daten werden über `pure1_client.py` via JWT/RS256-signierte Anfragen abgerufen

### 8.3 `sod_service.py` – Storage on Demand (Pure1)

**Aufgabe:** Wöchentliches Abrufen von Pure1 Subscription-Lizenz-Daten (SoD-Vertragswerte).

**Intervall:** 7 Tage (fest: `SOD_REFRESH_INTERVAL_SECONDS = 7 * 24 * 60 * 60`)

**Ablauf:**
1. `AppSettings` lesen (Pure1 App-ID und Private Key)
2. `pure1_client.fetch_subscription_licenses()` aufrufen
3. Ergebnis in `SubscriptionLicenseCache` (1 Zeile, Singleton) speichern

### 8.4 Thread-Sicherheit

Alle drei Services verwenden dasselbe Muster:

```python
_background_thread_started = False
_thread_lock = threading.Lock()

def start_background_thread(app):
    global _background_thread_started
    with _thread_lock:
        if _background_thread_started:
            return  # Nur ein Thread pro Prozess!
        _background_thread_started = True
    thread = threading.Thread(target=_background_loop, args=(app,), daemon=True)
    thread.start()
```

---

## 9. HTTP-Routen und Blueprints

### 9.1 Blueprint-Übersicht

| Blueprint | Prefix | Datei | Zweck |
|-----------|--------|-------|-------|
| `main` | `/` | `routes/main.py` | Dashboard, Details |
| `admin` | `/admin` | `routes/admin.py` | Admin-UI, Login |
| `api` | `/api` | `routes/api.py` | REST API |
| `alerts` | `/alerts` | `routes/alerts.py` | Alerts-Seite |
| `capacity` | `/capacity` | `routes/capacity.py` | Kapazitätsreport |

### 9.2 Wichtige Endpunkte

**Dashboard (`main`):**

| Route | Methode | Beschreibung |
|-------|---------|-------------|
| `/` | GET | Haupt-Dashboard (HTML) |
| `/systems/<id>/details` | GET | System-Detailansicht (HTML) |

**Admin (`admin`):**

| Route | Methode | Beschreibung |
|-------|---------|-------------|
| `/admin/` | GET | Admin-Übersicht (Login required) |
| `/admin/login` | GET/POST | Login |
| `/admin/logout` | GET | Logout |
| `/admin/systems/add` | GET/POST | System hinzufügen |
| `/admin/systems/<id>/edit` | GET/POST | System bearbeiten |
| `/admin/systems/<id>/delete` | POST | System löschen |
| `/admin/systems/<id>/toggle` | POST | Aktiv/Inaktiv umschalten |
| `/admin/systems/<id>/discover` | POST | Discovery erneut ausführen |
| `/admin/settings` | GET/POST | Einstellungen |
| `/admin/certificates` | GET | Zertifikatsverwaltung |
| `/admin/certificates/upload` | POST | Zertifikat hochladen |
| `/admin/tags` | GET | Tag-Verwaltung |
| `/admin/logs` | GET | Log-Viewer |
| `/admin/swagger` | GET | Swagger UI |
| `/admin/docs` | GET | API-Dokumentation |

**REST API (`api`):**

| Route | Methode | Beschreibung |
|-------|---------|-------------|
| `/api/systems` | GET | Alle Systeme auflisten |
| `/api/status` | GET | Live-Status aller aktiven Systeme |
| `/api/systems/<id>/status` | GET | Live-Status eines Systems |
| `/api/cached-status` | GET | Gecachter Status aller Systeme |
| `/api/trigger-status-refresh` | POST | Sofortaktualisierung auslösen |
| `/api/alerts/state` | POST | Alert-Zustände aktualisieren (bulk) |
| `/api/alerts/assignees` | GET | Assignee-Historie |
| `/api/alerts/assignees/<name>` | DELETE | Assignee aus Historie entfernen |

---

## 10. Frontend-Architektur

### 10.1 Template-Vererbung

```
base.html
├── dashboard.html
├── alerts.html
├── details.html
├── capacity.html
└── admin/
    ├── index.html
    ├── form.html
    ├── settings_tabbed.html
    └── ...
```

**`base.html` definiert:**
- `{% block styles %}` – Zusätzliche CSS-Stile
- `{% block content %}` – Hauptinhalt (inkl. `<script>`-Tags)

> **Wichtig:** `<script>`-Tags gehören in `{% block content %}`, da `base.html`
> keinen `{% block scripts %}` definiert.

### 10.2 JavaScript-Komponenten

Das Frontend nutzt ausschließlich **Vanilla JavaScript** (kein React/Vue/Angular).

**Dashboard (`dashboard.html`):**
- Auto-Refresh: `setInterval()` ruft `/api/cached-status` alle X Sekunden ab
- Filter: clientseitig via `data-*`-Attributen auf DOM-Elementen
- Card/Table-Ansicht: CSS-Klassen-Umschalten

**Kapazitätsreport (`capacity.html`):**
- Chart.js für Verlaufsgraphen (lokal gebundelt)
- Tab-Steuerung (Bootstrap 5 Tabs)
- Export: Download-Links mit Server-generierten Dateiinhalten

**Alerts (`alerts.html`):**
- Acknowledge/Assignee/Kommentar: AJAX `POST /api/alerts/state`
- Live-Filter: clientseitige Suche ohne Server-Roundtrip

### 10.3 Statische Assets

| Datei | Beschreibung |
|-------|-------------|
| `static/js/chart.umd.min.js` | Chart.js (lokal, keine CDN-Abhängigkeit) |
| `static/swagger-ui/` | Swagger UI Assets (lokal gebundelt) |
| `static/openapi.json` | OpenAPI 3.0 Spezifikation der REST API |

---

## 11. Workflows

### 11.1 Workflow: Neues Storage-System hinzufügen

```
Admin-Benutzer
    │
    ▼
POST /admin/systems/add (Formular)
    │
    ▼
admin.py: add_system()
    │
    ├── StorageSystem() erstellen
    ├── Credentials verschlüsseln (crypto_utils)
    ├── db.session.add() + commit()
    │
    └── discovery.discover_system(system, app)
        │
        ├── get_client(vendor, ...) instanziieren
        ├── Cluster-Typ ermitteln
        ├── Nodes abfragen
        ├── DNS-Namen ermitteln (reverse_dns_lookup)
        ├── IPs sammeln
        └── system.cluster_type, node_details, etc. setzen
            └── db.session.commit()
```

### 11.2 Workflow: Dashboard-Anzeige (gecacht)

```
Browser
    │
    ▼
GET / (dashboard.html rendern)
    │
    ├── JavaScript: setInterval(fetchStatus, refreshInterval)
    │
    ├── GET /api/cached-status
    │   │
    │   ▼
    │   api.py: cached_status()
    │       ├── StorageSystem.query.all()
    │       ├── StatusCache.query.all()
    │       └── JSON-Response mit gecachten Statusdaten
    │
    └── DOM aktualisieren (Status-Badges, Kapazitätsbalken, Alert-Zähler)
```

### 11.3 Workflow: Status-Refresh (Hintergrund)

```
status_service._background_loop()
    │
    ▼ (nach Ablauf des Intervalls oder Event)
_do_refresh(app)
    │
    ├── WITH app.app_context():
    ├── systems = StorageSystem.query.filter_by(enabled=True).all()
    │
    ├── _run_parallel_fetch(systems, app)
    │   │
    │   └── ThreadPoolExecutor(max_workers=32)
    │       └── fetch_system_status(system, app) [parallel]
    │           │
    │           ├── get_client(vendor, ip, port, user, pw, token)
    │           │   └── PureStorageClient / NetAppONTAPClient / ...
    │           │
    │           ├── client.get_health_status()
    │           │   └── HTTP-Request an Storage-System-API
    │           │
    │           ├── log_system_event(level='INFO', category='connection', ...)
    │           │
    │           └── return {'system': {...}, 'status': {...}}
    │
    └── for result in results:
        └── _upsert_cache_entry(StatusCache, db, system_id, status, now)
            └── StatusCache.set_status(status)  # JSON serialisieren
```

### 11.4 Workflow: Kapazitätsverlauf (täglich)

```
capacity_service._background_loop()
    │
    ▼ (stündlich)
_do_refresh(app)
    │
    ├── Alle aktiven Systeme laden
    ├── _fetch_system_capacity(system, ...) parallel
    │   └── client.get_health_status() → capacity_total_tb, capacity_used_tb, ...
    │
    ├── CapacitySnapshot aktualisieren (1 Zeile pro System, aktuelle Werte)
    │
    └── _update_capacity_history()
        └── Wenn heute noch kein CapacityHistory-Eintrag existiert:
            └── Neuen Eintrag anlegen (1 Datenpunkt/Tag)
```

### 11.5 Workflow: Alert-Acknowledge

```
Browser (Alerts-Seite)
    │
    ▼ (Benutzer klickt "Acknowledge")
AJAX POST /api/alerts/state
    Body: [{key: "...", acknowledged: true, assignee: "admin", comment: "OK"}]
    │
    ▼
api.py: update_alert_state()
    │
    ├── for item in request.json:
    │   ├── AlertState.query.filter_by(key=item['key']).first()
    │   │   └── (oder neuen AlertState erstellen)
    │   │
    │   ├── state.acknowledged = item.get('acknowledged', False)
    │   ├── state.assignee = item.get('assignee')
    │   └── state.comment = item.get('comment')
    │
    ├── AssigneeHistory aktualisieren (für Autocomplete)
    └── db.session.commit()
        └── JSON-Response: {"success": true}
```

### 11.6 Workflow: Pure1 JWT-Authentifizierung

```
pure1_client.fetch_subscription_licenses(app_id, private_key, ...)
    │
    ▼
_generate_jwt_token(app_id, private_key, passphrase)
    │
    ├── RSA Private Key laden (PEM → cryptography-Objekt)
    ├── JWT-Payload erstellen:
    │   {iss: app_id, iat: now, exp: now + 600s, sub: app_id}
    ├── JWT signieren (RS256, RSA-SHA256)
    └── return jwt_token
    │
    ▼
GET https://api.pure1.purestorage.com/api/1.0/oauth2/token
    Body: {grant_type: urn:ietf:params:oauth2:grant-type:jwt-bearer, assertion: jwt}
    Response: {access_token: "Bearer ..."}
    │
    ▼
GET https://api.pure1.purestorage.com/api/1.0/subscription-assets
    Header: Authorization: Bearer <access_token>
    Response: Liste der SoD-Lizenzen
```

---

## 12. Authentifizierung und Sicherheit

### 12.1 Admin-Login

**Implementierung:** Flask-Login mit Session-Cookie

```python
# AdminUser Model (Flask-Login UserMixin)
class AdminUser(UserMixin, db.Model):
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)  # Werkzeug PBKDF2

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
```

Alle Admin-Routen sind mit `@login_required` geschützt.

### 12.2 API-Credential-Verschlüsselung

Sensible Felder in der Datenbank werden mit **Fernet**-Verschlüsselung gespeichert:

| Feld | Modell |
|------|--------|
| `api_username` | StorageSystem |
| `api_password` | StorageSystem |
| `api_token` | StorageSystem |
| `pure1_app_id` | AppSettings |
| `pure1_private_key` | AppSettings |
| `pure1_private_key_passphrase` | AppSettings |
| `pure1_public_key` | AppSettings |
| `proxy_http` | AppSettings |
| `proxy_https` | AppSettings |

**Schlüsselableitung:**
```
SECRET_KEY (Env)
    │
    ▼ PBKDF2-HMAC-SHA256 (100.000 Iterationen, Salt='storage-dashboard-salt')
    │
    ▼ 32-Byte Schlüssel
    │
    ▼ Base64URL → Fernet-Schlüssel
```

### 12.3 Storage-API-Verbindungen

- Kein HTTP_PROXY für lokale Storage-Systeme (explizit unterdrückt durch `_local_session`)
- Proxy wird nur für externe API-Calls (Pure1) verwendet
- SSL-Verifizierung über firmeneigene CA-Zertifikate
- Reverse-DNS-Lookup für korrekte Hostnamen-Validierung

---

## 13. Konfiguration und Umgebungsvariablen

Die Anwendung wird ausschließlich über Umgebungsvariablen (`.env`-Datei) konfiguriert:

| Variable | Pflicht | Standard | Beschreibung |
|----------|---------|---------|-------------|
| `SECRET_KEY` | ✅ | – | Flask Session + Verschlüsselungsschlüssel |
| `DATABASE_URL` | – | `sqlite:///storage_dashboard.db` | Datenbankverbindung |
| `SSL_VERIFY` | – | `false` | TLS-Zertifikate der Storage-Systeme prüfen |
| `FLASK_ENV` | – | `production` | `development` oder `production` |
| `POSTGRES_PASSWORD` | Container | – | PostgreSQL-Passwort |
| `POSTGRES_DB` | Container | `storage_dashboard` | Datenbankname |
| `POSTGRES_USER` | Container | `dashboard` | Datenbankbenutzer |
| `TZ` | – | `Europe/Berlin` | Zeitzone für Logs |

---

## 14. Tests

### 14.1 Test-Framework

- **pytest** (≥8.0.0)
- Alle Tests in `tests/`

### 14.2 Tests ausführen

```bash
# Alle Tests
pytest tests/

# Einzelner Test
pytest tests/test_ontap_ems_alerts.py -v

# Mit Coverage
pytest tests/ --cov=app
```

### 14.3 Test-Übersicht

| Testdatei | Testet |
|-----------|--------|
| `test_alerts_page.py` | Alert-Seite und Merge-Logik |
| `test_cached_status_capacity.py` | Gecachte Status-Kapazitätsdaten |
| `test_capacity_service_pure_dual_method.py` | Pure-Kapazität: Standard vs. Evergreen/One |
| `test_compute_forecast.py` | Kapazitätsprognose-Berechnung |
| `test_dashboard_acknowledged_status.py` | Alert-Acknowledge-Status im Dashboard |
| `test_migrations.py` | Datenbankmigrationen |
| `test_ontap_cluster_dns.py` | ONTAP DNS-Auflösung |
| `test_ontap_ems_alerts.py` | EMS Alert-Filterlogik |
| `test_ontap_rest_status_alerts.py` | ONTAP REST-Status-Alerts |
| `test_pure1_client.py` | Pure1 JWT-Client |
| `test_pure_controller_status.py` | Pure Shelf-Controller-Filterung |

---

## 15. CI/CD und Container

### 15.1 GitHub Actions

Die Datei `.github/workflows/build-and-push-image.yml` baut automatisch ein Docker Image
und lädt es auf GitHub Container Registry hoch.

**Trigger:**
- Manuell (`workflow_dispatch`) mit optionalem Tag-Namen

**Ablauf:**
1. Code auschecken
2. Docker Build (Multi-Stage)
3. Image taggen (`latest` oder benutzerdefinierter Tag)
4. Push zu `ghcr.io/timux/storage-dashboard:<tag>`

### 15.2 Dockerfile (Multi-Stage)

```dockerfile
# Stage 1: Builder
FROM python:3.11-slim as builder
RUN apt-get install gcc libpq-dev libssl-dev libffi-dev
RUN pip install --user -r requirements.txt

# Stage 2: Final Image
FROM python:3.11-slim
RUN apt-get install libpq5   # PostgreSQL Runtime-Bibliothek
COPY --from=builder /root/.local /home/dashboard/.local
USER dashboard (uid=1000)
EXPOSE 5000
ENTRYPOINT ["/entrypoint.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "run:app"]
```

### 15.3 Entrypoint (`entrypoint.sh`)

```bash
# Wartet auf PostgreSQL-Verfügbarkeit (DB_WAIT)
# Führt Datenbankmigrationen aus: python cli.py migrate
# Startet Gunicorn mit CMD-Argumenten
```

### 15.4 Docker-Compose-Architektur

```yaml
services:
  postgres:
    image: postgres:16-alpine
    networks: [dashboard-network]
    healthcheck: pg_isready

  storage-dashboard:
    image: ghcr.io/timux/storage-dashboard:latest
    depends_on: postgres (healthy)
    ports: ["5000:5000"]
    networks: [dashboard-network]

volumes:
  postgres-data:
  storage-data:
```

---

## 16. Abhängigkeiten

### 16.1 Python-Abhängigkeiten

```
Flask==3.0.0                # Web-Framework
Flask-SQLAlchemy==3.1.1     # ORM
Flask-Login==0.6.3          # Authentifizierung
gunicorn==22.0.0            # WSGI-Server
requests==2.31.0            # HTTP-Client
click==8.1.7                # CLI-Framework
python-dotenv==1.0.0        # .env-Datei
tabulate==0.9.0             # Tabellen (CLI)
cryptography>=41.0.0        # Fernet + Pure1 JWT (RSA/RS256)
pytz==2024.1                # Zeitzonenverwaltung
psycopg2-binary==2.9.9      # PostgreSQL-Adapter
openpyxl==3.1.2             # Excel-Export
pytest>=8.0.0               # Testing
```

### 16.2 Externe Dienste

| Dienst | Zweck | Optional? |
|--------|-------|-----------|
| Pure Storage FlashArray | Datenquelle (Status, Kapazität, Alerts) | Ja |
| NetApp ONTAP | Datenquelle | Ja |
| NetApp StorageGRID | Datenquelle | Ja |
| Dell DataDomain | Datenquelle | Ja |
| Pure1 API (`api.pure1.purestorage.com`) | SoD-Lizenzdaten | Ja (Pure1-Feature) |
| PostgreSQL | Datenbank | Nein (oder SQLite) |

### 16.3 Abhängigkeits-Diagramm

```
storage-dashboard
├── Flask                ← Web-Framework
│   ├── Jinja2           ← Templating
│   ├── Werkzeug         ← HTTP-Utilities, Passwort-Hashing
│   └── click            ← CLI (intern Flask, extern cli.py)
│
├── Flask-SQLAlchemy     ← ORM
│   └── SQLAlchemy       ← Core ORM
│       ├── psycopg2     ← PostgreSQL-Adapter
│       └── (sqlite3)    ← SQLite (Python built-in)
│
├── Flask-Login          ← Session-Auth
│
├── requests             ← HTTP-Client (alle Storage-API-Calls)
│
├── cryptography         ← Fernet (DB-Verschlüsselung)
│                           + RSA/RS256 (Pure1 JWT)
│
├── gunicorn             ← WSGI-Server
│
├── openpyxl             ← Excel-Export
│
└── pytz                 ← Zeitzonenverwaltung
```

---

## 17. Erweiterung: Neuen Vendor hinzufügen

Um einen neuen Storage-Vendor hinzuzufügen, sind folgende Schritte notwendig:

### Schritt 1: Neuen Client erstellen

```python
# app/api/storage_clients.py

class MyNewVendorClient(StorageClient):
    """Client für MyNewVendor Storage-Systeme"""

    def get_health_status(self) -> dict:
        """Status abrufen und in einheitlichem Format zurückgeben"""
        try:
            response = _local_session.get(
                f"{self.base_url}/api/v1/status",
                headers={"Authorization": f"Bearer {self.token}"},
                verify=get_ssl_verify(),
                timeout=30
            )
            data = response.json()

            return {
                'status': 'ok',                          # ok | warning | error | offline
                'hardware_status': 'ok',                  # ok | warning | error
                'cluster_status': 'ok',                   # ok | warning | error
                'vendor': 'my-new-vendor',
                'platform': data.get('model', 'Unknown'),
                'capacity_total_tb': data.get('total_capacity_bytes', 0) / 1e12,
                'capacity_used_tb': data.get('used_capacity_bytes', 0) / 1e12,
                'capacity_percent': data.get('percent_used', 0.0),
                'alerts': [],                             # Liste von Alert-Dicts
                'nodes': [],                              # Liste von Node-Dicts
                'error': None
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
```

### Schritt 2: Client in Factory registrieren

```python
# app/api/__init__.py oder storage_clients.py: get_client()
def get_client(vendor, ip_address, port, username, password, token):
    clients = {
        'pure':                PureStorageClient,
        'netapp-ontap':        NetAppONTAPClient,
        'netapp-storagegrid':  NetAppStorageGRIDClient,
        'dell-datadomain':     DellDataDomainClient,
        'my-new-vendor':       MyNewVendorClient,    # ← hinzufügen
    }
    return clients[vendor](ip_address, port, username, password, token)
```

### Schritt 3: Vendor in Konstanten und Templates eintragen

```python
# app/constants.py
VENDOR_DEFAULT_PORTS = {
    'pure': 443,
    'netapp-ontap': 443,
    'netapp-storagegrid': 443,
    'dell-datadomain': 3009,
    'my-new-vendor': 443,    # ← hinzufügen
}
```

Formulare und Templates (`admin/form.html`) müssen den neuen Vendor in der
Dropdown-Liste aufnehmen.

### Schritt 4: Discovery implementieren (optional)

In `app/discovery.py` für hersteller-spezifische Auto-Discovery-Logik.

### Schritt 5: Tests schreiben

```bash
tests/test_my_new_vendor.py
```

---

*Storage Dashboard Developer Guide – Version 1.0 – März 2026*
