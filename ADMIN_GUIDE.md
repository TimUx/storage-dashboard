# Storage Dashboard - Administrator-Handbuch

## Inhaltsverzeichnis

1. [Übersicht](#übersicht)
2. [Systemvoraussetzungen](#systemvoraussetzungen)
3. [Admin-Bereich](#admin-bereich)
4. [Neue Storage-Systeme hinzufügen](#neue-storage-systeme-hinzufügen)
5. [API-Zugriff und Authentifizierung](#api-zugriff-und-authentifizierung)
6. [Zertifikatsverwaltung](#zertifikatsverwaltung)
7. [System-spezifische API-Konfiguration](#system-spezifische-api-konfiguration)
8. [Fehlerbehebung](#fehlerbehebung)

---

## Übersicht

Das Storage Dashboard ist für den Einsatz in **internen Firmennetzwerken** konzipiert und bietet eine zentrale Überwachungsplattform für verschiedene Storage-Systeme. Das Dashboard unterstützt:

- Pure Storage FlashArray
- NetApp ONTAP 9
- NetApp StorageGRID 11
- Dell DataDomain

**Wichtiger Hinweis:** Das Dashboard ist ausschließlich für interne Netzwerke gedacht. Es verwendet firmeneigene CA- und Root-Zertifikate anstelle von Let's Encrypt oder anderen öffentlichen Zertifizierungsstellen.

---

## Systemvoraussetzungen

### Server-Anforderungen

- **Betriebssystem:** SUSE Linux 15 oder andere Linux-Distribution
- **Python:** Version 3.8 oder höher
- **RAM:** Mindestens 2 GB (empfohlen: 4 GB)
- **Festplatte:** Mindestens 1 GB freier Speicher
- **Netzwerk:** Zugriff auf die Management-Schnittstellen der Storage-Systeme

### Netzwerk-Anforderungen

Das Dashboard benötigt Netzwerkzugriff zu folgenden Ports auf den Storage-Systemen:

- **Pure Storage:** Port 443 (HTTPS)
- **NetApp ONTAP:** Port 443 (HTTPS)
- **NetApp StorageGRID:** Port 443 (HTTPS)
- **Dell DataDomain:** Port 3009 (HTTPS - REST API)

**Firewall-Konfiguration:**
```bash
# Beispiel: Firewall-Regeln für ausgehende Verbindungen
# Port 443 für Pure, NetApp ONTAP und StorageGRID
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" destination address="<storage-ip>" port port="443" protocol="tcp" accept'
# Port 3009 für Dell DataDomain
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" destination address="<datadomain-ip>" port port="3009" protocol="tcp" accept'
firewall-cmd --reload
```

### Storage-System-Anforderungen

Jedes Storage-System muss folgende Voraussetzungen erfüllen:

1. **REST API aktiviert:** Die REST API muss auf dem Storage-System aktiviert sein
2. **API-Benutzer:** Ein dedizierter Benutzer mit Read-Only-Rechten
3. **Netzwerkerreichbarkeit:** Das Storage-System muss vom Dashboard-Server erreichbar sein
4. **SSL/TLS:** HTTPS-Zugriff mit gültigen Zertifikaten (firmeneigene CA)

---

## Admin-Bereich

Der Admin-Bereich ist unter `/admin` erreichbar und bietet zentrale Verwaltungsfunktionen.

![Admin-Bereich](screenshots/admin-area.png)

### Funktionen des Admin-Bereichs

1. **System-Übersicht:**
   - Liste aller konfigurierten Storage-Systeme
   - Status (Aktiv/Inaktiv)
   - Cluster-Informationen
   - Erkennungsstatus

2. **System-Verwaltung:**
   - Neue Systeme hinzufügen
   - Bestehende Systeme bearbeiten
   - Systeme aktivieren/deaktivieren
   - Systeme löschen
   - Auto-Discovery erneut ausführen

3. **Zertifikatsverwaltung:** (siehe [Zertifikatsverwaltung](#zertifikatsverwaltung))
   - CA-Zertifikate hochladen
   - Root-Zertifikate verwalten
   - Zertifikate aktivieren/deaktivieren

### Navigation

- **Dashboard:** Zurück zur Hauptansicht
- **Admin:** System-Verwaltung
- **Dokumentation:** API-Einrichtungsanleitung

---

## Neue Storage-Systeme hinzufügen

### Schritt-für-Schritt-Anleitung

#### 1. Admin-Bereich öffnen

Navigieren Sie zu: `http://<dashboard-server>:5000/admin`

#### 2. "Neues System" klicken

Klicken Sie auf den Button **"+ Neues System"** in der oberen rechten Ecke.

#### 3. System-Informationen eingeben

Füllen Sie das Formular mit folgenden Informationen aus:

**Grundlegende Informationen:**
- **Name:** Ein aussagekräftiger Name für das System (z.B. "Pure-FlashArray-DC1")
- **Hersteller:** Wählen Sie den Hersteller aus der Dropdown-Liste
  - `pure` - Pure Storage FlashArray
  - `netapp-ontap` - NetApp ONTAP 9
  - `netapp-storagegrid` - NetApp StorageGRID 11
  - `dell-datadomain` - Dell DataDomain
- **IP-Adresse:** Management-IP des Storage-Systems
- **Port:** Standard ist 443 (nur ändern, wenn abweichend)

**API-Zugangsdaten:**

Abhängig vom Hersteller:

- **Pure Storage:**
  - Nur **API Token** ausfüllen
  - Benutzername und Passwort leer lassen

- **NetApp ONTAP:**
  - **Benutzername** und **Passwort** ausfüllen
  - API Token leer lassen

- **NetApp StorageGRID:**
  - Nur **API Token** ausfüllen (Bearer Token)
  - Benutzername und Passwort leer lassen

- **Dell DataDomain:**
  - **Benutzername** und **Passwort** ausfüllen
  - API Token leer lassen

**Status:**
- **Aktiviert:** System ist sofort aktiv und wird im Dashboard angezeigt
- **Deaktiviert:** System wird nicht abgefragt (für Wartungsarbeiten)

#### 4. System speichern

Klicken Sie auf **"Speichern"**. Das Dashboard führt automatisch eine Auto-Discovery durch und ermittelt:

- Cluster-Typ (HA, MetroCluster, etc.)
- Anzahl der Nodes
- DNS-Namen
- Alle IP-Adressen
- Node-Details

#### 5. Erfolgsmeldung überprüfen

Nach erfolgreichem Hinzufügen erscheint eine Bestätigung:
- **Erfolg:** "System added and discovered successfully! Found X nodes."
- **Warnung:** "System added but discovery had issues: [Fehlerdetails]"

### Auto-Discovery

Die Auto-Discovery-Funktion ermittelt automatisch:

1. **Cluster-Typ:**
   - `local` - Einzelnes System oder lokaler Cluster
   - `ha` - High-Availability Konfiguration
   - `metrocluster` - NetApp MetroCluster
   - `multi-site` - Multi-Site Konfiguration (StorageGRID)

2. **Node-Informationen:**
   - Anzahl der Nodes
   - Node-Namen
   - Node-IPs
   - Node-Status

3. **Netzwerk-Details:**
   - Alle IP-Adressen
   - DNS-Namen/Hostnamen

### Discovery erneut ausführen

Falls sich die Konfiguration eines Systems ändert (z.B. nach einem Cluster-Upgrade):

1. Navigieren Sie zum Admin-Bereich
2. Klicken Sie auf **"🔄 Discovery"** beim entsprechenden System
3. Das System wird erneut gescannt

---

## API-Zugriff und Authentifizierung

Das Dashboard verwendet ausschließlich Read-Only-Zugriff auf die Storage-Systeme. Es werden **keine** Änderungen an den Systemen vorgenommen.

### Authentifizierungsmethoden

#### 1. API Token (Pure Storage, StorageGRID)

**Vorteile:**
- Sicherer als Benutzername/Passwort
- Kann ohne Passwortänderung widerrufen werden
- Zeitlich begrenzte Gültigkeit möglich

**Verwendung im Dashboard:**
- Token im Feld "API Token" eintragen
- Benutzername und Passwort leer lassen

#### 2. Basic Authentication (ONTAP, DataDomain)

**Vorteile:**
- Einfache Einrichtung
- Standard HTTP Basic Auth

**Verwendung im Dashboard:**
- Benutzername und Passwort eintragen
- API Token leer lassen

### Berechtigungen

Erstellen Sie für das Dashboard dedizierte Read-Only-Accounts mit minimalen Berechtigungen:

**Benötigte Berechtigungen:**
- Storage-Status abfragen
- Cluster-Informationen lesen
- Alert-Status abrufen
- Kapazitätsinformationen lesen

**KEINE Berechtigungen erforderlich:**
- Konfigurationsänderungen
- Volume-Operationen
- Snapshot-Management
- Replikations-Management

### Credential-Rotation

**Best Practices:**
- Rotieren Sie API-Tokens alle 90 Tage
- Verwenden Sie dedizierte Service-Accounts
- Dokumentieren Sie Credential-Änderungen
- Testen Sie neue Credentials vor dem Produktiveinsatz

**Credentials ändern:**
1. Admin-Bereich öffnen
2. System bearbeiten
3. Neue Credentials eingeben
4. Speichern und testen

---

## Zertifikatsverwaltung

Das Dashboard unterstützt firmeneigene CA- und Root-Zertifikate für sichere Verbindungen zu Storage-Systemen im internen Netzwerk.

### Warum Zertifikatsverwaltung?

In internen Firmennetzwerken werden oft selbst-signierte Zertifikate oder Zertifikate von firmeneigenen Certificate Authorities (CA) verwendet. Das Dashboard muss diesen Zertifikaten vertrauen, um sichere HTTPS-Verbindungen aufbauen zu können.

### Zertifikate hochladen

#### 1. Zertifikatsdatei vorbereiten

**Unterstützte Formate:**
- PEM (`.pem`, `.crt`, `.cer`)
- DER (`.der`)

**Beispiel CA-Zertifikat (PEM):**
```
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRkmFMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
...
-----END CERTIFICATE-----
```

#### 2. Zertifikat im Admin-Bereich hochladen

1. Navigieren Sie zu `/admin/certificates`
2. Klicken Sie auf **"+ Neues Zertifikat"**
3. Füllen Sie das Formular aus:
   - **Name:** Beschreibender Name (z.B. "Firmen-Root-CA")
   - **Typ:** CA Certificate oder Root Certificate
   - **Zertifikat-Datei:** Datei hochladen
   - **Beschreibung:** Optional (z.B. "Gültig bis 2030")
4. Klicken Sie auf **"Speichern"**

#### 3. Zertifikat aktivieren

Neu hochgeladene Zertifikate sind automatisch aktiv. Sie können Zertifikate temporär deaktivieren ohne sie zu löschen.

### Zertifikatskette

Für korrekte SSL-Verifizierung sollten alle Zertifikate der Zertifikatskette hochgeladen werden:

1. **Root CA Certificate** (oberste Ebene)
2. **Intermediate CA Certificates** (falls vorhanden)
3. **Server Certificates** (optional, falls spezifisch)

**Beispiel:**
```
Firmen-Root-CA
└── Intermediate-CA-IT
    └── Storage-Subdomain-CA
```

### SSL-Verifizierung konfigurieren

**Mit Zertifikaten (.env):**
```bash
SSL_VERIFY=true
```

**Ohne Zertifikate (nur für Test/Entwicklung):**
```bash
SSL_VERIFY=false
```

⚠️ **Warnung:** `SSL_VERIFY=false` sollte nur in Testumgebungen verwendet werden!

### Zertifikate exportieren

Falls Sie die gespeicherten Zertifikate auf einem anderen System benötigen:

1. Admin-Bereich → Zertifikate
2. Zertifikat auswählen
3. **"Exportieren"** klicken
4. PEM-Datei herunterladen

---

## System-spezifische API-Konfiguration

### 1. Pure Storage FlashArray

#### API-Zugriff aktivieren

Die REST API ist standardmäßig aktiviert auf Pure Storage FlashArray.

#### API-Token erstellen

**Über die Web-GUI:**

1. Melden Sie sich am FlashArray an: `https://<flasharray-ip>`
2. Navigieren Sie zu **System → Users**
3. Wählen Sie einen Benutzer oder erstellen Sie einen neuen
4. Klicken Sie auf **Create API Token**
5. Kopieren Sie den generierten Token (er wird nur einmal angezeigt!)
6. Speichern Sie den Token sicher

**Über die CLI:**

```bash
# API Token für bestehenden Benutzer erstellen
pureadmin create --api-token <username>

# Ausgabe:
# API Token: T-c4925090-c9bf-4033-8537-d24ee1bcs3d4
```

#### Dashboard-Konfiguration

Im Admin-Bereich:
- **Name:** Z.B. "Pure-FlashArray-Prod"
- **Hersteller:** `pure`
- **IP-Adresse:** Management-IP des FlashArray
- **Port:** 443
- **API Token:** Der generierte Token
- **Benutzername:** Leer lassen
- **Passwort:** Leer lassen

#### REST API Details

```
Pure Storage FlashArray REST API v2.4
Endpoint: https://<array-ip>/api/2.4/
Authentication: x-auth-token header
```

**Verwendete API-Endpunkte:**
- `GET /api/2.4/arrays` - Array-Informationen
- `GET /api/2.4/arrays/space` - Kapazitätsinformationen
- `GET /api/2.4/controllers` - Controller-/Node-Informationen (für Discovery)

**Referenz:**
- [Pure Storage REST API 2.x Documentation](https://support.purestorage.com/FlashArray/PurityFA/REST_API)
- [Pure Storage REST API Swagger Reference](https://code.purestorage.com/swagger/)

#### Benötigte Berechtigungen

- **read-only** Role ist ausreichend
- Alternativ: Storage Administrator (nur Read-Operations werden verwendet)

---

### 2. NetApp ONTAP 9

#### API-Zugriff aktivieren

Die ONTAP REST API ist ab ONTAP 9.6 verfügbar und standardmäßig aktiviert.

#### API-Benutzer erstellen

**Über die CLI:**

```bash
# Read-Only Benutzer für API-Zugriff erstellen
security login create -user-or-group-name dashboard_api \
  -application http \
  -authentication-method password \
  -role readonly

# Passwort setzen
security login password -username dashboard_api

# Benutzer verifizieren
security login show -user-or-group-name dashboard_api
```

**Über System Manager:**

1. Melden Sie sich bei System Manager an: `https://<ontap-cluster-ip>`
2. Navigieren Sie zu **Cluster → Settings → Users and Roles**
3. Klicken Sie auf **Add**
4. User-Details eingeben:
   - **Username:** dashboard_api
   - **Role:** readonly
   - **Application:** http
   - **Authentication Method:** password
5. Passwort setzen und speichern

#### Dashboard-Konfiguration

Im Admin-Bereich:
- **Name:** Z.B. "NetApp-ONTAP-Cluster1"
- **Hersteller:** `netapp-ontap`
- **IP-Adresse:** Cluster Management IP
- **Port:** 443
- **Benutzername:** dashboard_api
- **Passwort:** Das gesetzte Passwort
- **API Token:** Leer lassen

#### REST API Details

```
NetApp ONTAP REST API
Endpoint: https://<cluster-ip>/api/
Authentication: Basic Auth (username:password)
```

**Verwendete API-Endpunkte:**
- `GET /api/cluster` - Cluster-Informationen
- `GET /api/storage/aggregates?fields=space` - Aggregate-Kapazität
- `GET /api/cluster/nodes` - Node-Informationen (für Discovery)

**Referenz:**
- [ONTAP REST API Documentation](https://docs.netapp.com/us-en/ontap-automation/)
- [ONTAP REST API 9.16.1 Swagger](https://docs.netapp.com/us-en/ontap-restapi-9161/ontap/swagger-ui/index.html)

#### Benötigte Berechtigungen

**Empfohlene Custom Role:**

```bash
# Custom Read-Only Role für Dashboard
security login role create -role dashboard-readonly \
  -cmddirname "cluster show" -access readonly

security login role create -role dashboard-readonly \
  -cmddirname "storage aggregate show" -access readonly

security login role create -role dashboard-readonly \
  -cmddirname "volume show" -access readonly

security login role create -role dashboard-readonly \
  -cmddirname "system health status show" -access readonly

# Benutzer mit Custom Role erstellen
security login create -user-or-group-name dashboard_api \
  -application http \
  -authentication-method password \
  -role dashboard-readonly
```

---

### 3. NetApp StorageGRID 11

#### API-Zugriff aktivieren

Die StorageGRID Management API ist standardmäßig aktiviert.

#### API-Token generieren

**Über die Web-GUI:**

1. Melden Sie sich am Grid Manager an: `https://<storagegrid-ip>`
2. Navigieren Sie zu **Users**
3. Wählen Sie Ihren Benutzer oder erstellen Sie einen Service-Account
4. Klicken Sie auf **Generate Token**

**Über die REST API:**

```bash
# Token direkt über API generieren
curl -X POST "https://<storagegrid-ip>/api/v3/authorize" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "root",
    "password": "your-password",
    "cookie": true,
    "csrfToken": false
  }' \
  -k

# Response enthält Bearer Token:
# {
#   "responseTime": "2024-01-01T12:00:00.000Z",
#   "status": "success",
#   "apiVersion": "3.0",
#   "data": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
# }
```

**Token-Gültigkeit:**

StorageGRID-Tokens sind zeitlich begrenzt (Standard: 16 Stunden). Für das Dashboard sollten Sie:
- Einen dedizierten Service-Account verwenden
- Token regelmäßig erneuern
- Oder: Benutzername/Passwort verwenden (das Dashboard generiert dann automatisch Tokens)

#### Dashboard-Konfiguration

**Option 1: Mit Bearer Token**
- **Name:** Z.B. "StorageGRID-Site1"
- **Hersteller:** `netapp-storagegrid`
- **IP-Adresse:** Admin Node IP
- **Port:** 443
- **API Token:** Bearer Token (inkl. "Bearer " Prefix)
- **Benutzername:** Leer lassen
- **Passwort:** Leer lassen

**Option 2: Mit Benutzername/Passwort** (empfohlen)
- **Name:** Z.B. "StorageGRID-Site1"
- **Hersteller:** `netapp-storagegrid`
- **IP-Adresse:** Admin Node IP
- **Port:** 443
- **Benutzername:** Service-Account
- **Passwort:** Passwort
- **API Token:** Leer lassen (wird automatisch generiert)

#### Verwendete Technologie

Da kein offizielles Python SDK verfügbar ist, verwendet das Dashboard direkte REST API Calls:

```python
# Direct REST API calls mit requests
import requests

headers = {
    'Authorization': f'Bearer {token}',
    'Accept': 'application/json'
}
response = requests.get(
    f'https://{ip}/api/v3/grid/health/topology',
    headers=headers,
    verify=False
)
```

**API-Endpunkte:**
- `/api/v3/grid/health/topology` - Grid-Topologie und Node-Status
- `/api/v3/grid/regions` - Regionen/Sites
- `/api/v3/grid/health/status` - Gesundheitsstatus
- `/api/v3/grid/storage-api-usage` - Storage-Nutzung

**Referenz:**
- [StorageGRID 11.8 API Documentation](https://docs.netapp.com/us-en/storagegrid-118/admin/using-grid-management-api.html)

#### Benötigte Berechtigungen

**Minimum:**
- **Grid Topology Page Access**
- **Storage Appliances Pages Access**
- **Read-Only Access** zu Grid-Konfiguration

**Empfohlene Gruppe:**
- Erstellen Sie eine "Dashboard Monitoring" Gruppe mit Read-Only-Berechtigungen
- Fügen Sie den Service-Account dieser Gruppe hinzu

---

### 4. Dell DataDomain

#### API-Zugriff aktivieren

Die REST API muss möglicherweise explizit aktiviert werden:

```bash
# REST API aktivieren (auf dem DataDomain-System)
rest enable

# REST API Status prüfen
rest show

# Output:
# REST access is enabled
# REST port: 443
```

#### API-Benutzer erstellen

**Über die CLI:**

```bash
# Benutzer erstellen
user add dashboard_api

# Passwort setzen
password set dashboard_api

# Read-Only Rolle zuweisen
user modify dashboard_api role read-only

# Benutzer verifizieren
user show dashboard_api
```

**Über die Web-GUI:**

1. Melden Sie sich an der DataDomain GUI an: `https://<datadomain-ip>`
2. Navigieren Sie zu **Administration → Access → Local Users**
3. Klicken Sie auf **Create**
4. User-Details:
   - **Username:** dashboard_api
   - **Role:** read-only oder admin (nur Read-Operations)
   - **Password:** Sicheres Passwort
5. Speichern

#### Dashboard-Konfiguration

Im Admin-Bereich:
- **Name:** Z.B. "DataDomain-DD9800"
- **Hersteller:** `dell-datadomain`
- **IP-Adresse:** Management-IP
- **Port:** 3009 (Standard-Port für DataDomain REST API)
- **Benutzername:** dashboard_api
- **Passwort:** Das gesetzte Passwort
- **API Token:** Leer lassen

#### Verwendete Technologie

Wie bei StorageGRID verwendet das Dashboard direkte REST API Calls:

```python
# Direct REST API calls mit requests
import requests
from requests.auth import HTTPBasicAuth

auth = HTTPBasicAuth(username, password)
response = requests.get(
    f'https://{ip}:3009/rest/v1.0/dd-systems/0/health',
    auth=auth,
    verify=False
)
```

**API-Endpunkte:**
- `/rest/v1.0/dd-systems/0/health` - System-Gesundheit
- `/rest/v1.0/dd-systems/0/storage-units` - Storage-Informationen
- `/rest/v1.0/dd-systems/0/alerts` - Aktive Alerts
- `/rest/v1.0/dd-systems/0/services` - Service-Status

**Referenz:**
- [Dell DataDomain REST API Guide](https://www.dell.com/support/manuals/en-us/data-domain-os/dd-os-rest-api)

#### Benötigte Berechtigungen

**Minimum:**
- **read-only** Role

**Oder Custom Role:**
```bash
# Custom Role mit minimalen Berechtigungen
role create dashboard-monitor
role modify dashboard-monitor add system read
role modify dashboard-monitor add storage read
role modify dashboard-monitor add alerts read

user modify dashboard_api role dashboard-monitor
```

---

## Fehlerbehebung

### Häufige Probleme und Lösungen

#### 1. Verbindungsfehler

**Problem:** "Connection timeout" oder "Unable to connect"

**Lösungen:**
```bash
# Netzwerk-Konnektivität testen
ping <storage-ip>

# Port-Erreichbarkeit prüfen
telnet <storage-ip> 443
# oder
nc -zv <storage-ip> 443

# Firewall-Regeln prüfen (auf dem Dashboard-Server)
iptables -L OUTPUT -v -n | grep <storage-ip>

# Routen prüfen
traceroute <storage-ip>
```

#### 2. SSL/TLS-Fehler

**Problem:** "SSL Certificate Verify Failed"

**Lösungen:**

**Option A: CA-Zertifikat hinzufügen** (empfohlen)
1. Zertifikat vom Storage-System exportieren
2. Im Dashboard unter `/admin/certificates` hochladen
3. `SSL_VERIFY=true` in `.env` setzen

**Option B: SSL-Verifizierung deaktivieren** (nur für Tests!)
```bash
# In .env
SSL_VERIFY=false
```

**Zertifikat manuell testen:**
```bash
# Zertifikat vom Server abrufen
openssl s_client -connect <storage-ip>:443 -showcerts

# Zertifikat Details anzeigen
echo | openssl s_client -connect <storage-ip>:443 2>/dev/null | openssl x509 -noout -text
```

#### 3. Authentifizierungsfehler

**Problem:** "401 Unauthorized" oder "403 Forbidden"

**Lösungen:**

**Credentials testen:**

Pure Storage:
```bash
curl -k -H "Authorization: Bearer <api-token>" \
  https://<pure-ip>/api/2.0/arrays
```

NetApp ONTAP:
```bash
curl -k -u <username>:<password> \
  https://<ontap-ip>/api/cluster
```

StorageGRID:
```bash
curl -k -H "Authorization: Bearer <token>" \
  https://<storagegrid-ip>/api/v3/grid/health/topology
```

DataDomain:
```bash
curl -k -u <username>:<password> \
  https://<datadomain-ip>:3009/rest/v1.0/dd-systems/0/health
```

**Berechtigungen prüfen:**
- Stellen Sie sicher, dass der Benutzer die erforderlichen Rechte hat
- Prüfen Sie, ob der API-Zugriff aktiviert ist
- Bei Tokens: Prüfen Sie die Gültigkeit

#### 4. Discovery-Fehler

**Problem:** "System added but discovery had issues"

**Ursachen:**
- API-Endpunkte nicht erreichbar
- Unvollständige Berechtigungen
- Timeouts bei großen Clustern

**Lösungen:**
1. Discovery manuell erneut ausführen: Admin → 🔄 Discovery
2. Logs prüfen:
```bash
# Dashboard-Logs anzeigen
journalctl -u storage-dashboard -f

# Oder bei manueller Ausführung
python3 run.py
```

3. API-Zugriff einzeln testen (siehe oben)

#### 5. Performance-Probleme

**Problem:** Dashboard-Laden dauert sehr lange

**Lösungen:**

**Auto-Refresh-Intervall anpassen:**

In `app/templates/dashboard.html` (Standard: 45 Sekunden):
```javascript
// Intervall auf 60 Sekunden erhöhen
const refreshInterval = 60;
```

**Timeouts erhöhen:**

In `app/api/base_client.py`:
```python
# Timeout auf 30 Sekunden erhöhen
self.timeout = 30
```

**Multithreading optimieren:**

In `app/routes/main.py`:
```python
# Max. parallele Threads reduzieren bei vielen Systemen
with ThreadPoolExecutor(max_workers=10) as executor:
```

#### 6. Datenbank-Probleme

**Problem:** "Database locked" oder "Integrity Error"

**Lösungen:**

```bash
# Datenbank-Backup erstellen
cp storage_dashboard.db storage_dashboard.db.backup

# Bei Corruption: Datenbank neu erstellen
python3 << EOF
from app import create_app, db
app = create_app()
with app.app_context():
    db.create_all()
EOF

# Permissions prüfen
ls -la storage_dashboard.db
chmod 644 storage_dashboard.db
```

### Logs und Debugging

#### Dashboard-Logs

**Systemd Service:**
```bash
# Live-Logs anzeigen
journalctl -u storage-dashboard -f

# Letzte 100 Zeilen
journalctl -u storage-dashboard -n 100

# Logs seit heute
journalctl -u storage-dashboard --since today
```

**Manuelle Ausführung (Debug-Modus):**
```bash
cd /opt/storage-dashboard
source venv/bin/activate

# Flask Debug-Modus aktivieren
export FLASK_ENV=development
export FLASK_DEBUG=1

python3 run.py
```

#### Log-Level erhöhen

In `app/__init__.py`:
```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
```

### Support und weitere Hilfe

Bei Problemen:

1. **Logs prüfen:** Siehe oben
2. **GitHub Issues:** [Repository Issues](https://github.com/TimUx/storage-dashboard/issues)
3. **Dokumentation:** `/admin/docs` im Dashboard
4. **API-Dokumentation:** Links zu Hersteller-Dokumentationen (siehe oben)

---

## Anhang

### Beispiel .env-Datei

```bash
# Sicherheit
SECRET_KEY=c1d7d6e19f57612de0371fd01c171be3589d8197cf47966b4a138204d1ca73bf

# Datenbank
DATABASE_URL=sqlite:///storage_dashboard.db

# Flask
FLASK_ENV=production

# SSL/TLS
SSL_VERIFY=true

# Optional: Logging
LOG_LEVEL=INFO
```

### Nützliche CLI-Befehle

```bash
# Alle Systeme auflisten
python3 cli.py admin list

# Neues System hinzufügen (interaktiv)
python3 cli.py admin add

# System aktivieren
python3 cli.py admin enable <id>

# System deaktivieren
python3 cli.py admin disable <id>

# System löschen
python3 cli.py admin remove <id>

# Dashboard-Status anzeigen
python3 cli.py dashboard
```

### Systemd Service-Verwaltung

```bash
# Service starten
systemctl start storage-dashboard

# Service stoppen
systemctl stop storage-dashboard

# Service neustarten
systemctl restart storage-dashboard

# Service-Status prüfen
systemctl status storage-dashboard

# Service aktivieren (Auto-Start)
systemctl enable storage-dashboard

# Service-Logs
journalctl -u storage-dashboard -f
```

### Backup und Recovery

**Backup erstellen:**
```bash
#!/bin/bash
BACKUP_DIR="/backup/storage-dashboard"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Datenbank sichern
cp /opt/storage-dashboard/storage_dashboard.db \
   $BACKUP_DIR/storage_dashboard_${DATE}.db

# Config sichern
cp /opt/storage-dashboard/.env \
   $BACKUP_DIR/.env_${DATE}

echo "Backup created: $BACKUP_DIR/storage_dashboard_${DATE}.db"
```

**Recovery:**
```bash
# Service stoppen
systemctl stop storage-dashboard

# Backup wiederherstellen
cp /backup/storage-dashboard/storage_dashboard_YYYYMMDD_HHMMSS.db \
   /opt/storage-dashboard/storage_dashboard.db

# Permissions setzen
chown dashboard:dashboard /opt/storage-dashboard/storage_dashboard.db
chmod 644 /opt/storage-dashboard/storage_dashboard.db

# Service starten
systemctl start storage-dashboard
```

---

**Dokumentversion:** 1.0  
**Letzte Aktualisierung:** Februar 2026  
**Lizenz:** Siehe LICENSE-Datei im Repository
