# Storage Dashboard – Administrator-Handbuch

---

## Inhaltsverzeichnis

### A – Übersicht & Einstieg
1. [Systemübersicht](#1-systemübersicht)
2. [Systemvoraussetzungen](#2-systemvoraussetzungen)
3. [Erste Schritte nach der Installation](#3-erste-schritte-nach-der-installation)

### B – Benutzerverwaltung & Zugang
4. [Admin-Login und Benutzerverwaltung](#4-admin-login-und-benutzerverwaltung)

### C – Storage-Systeme verwalten
5. [Storage-Systeme hinzufügen und bearbeiten](#5-storage-systeme-hinzufügen-und-bearbeiten)
6. [Hersteller-spezifische API-Konfiguration](#6-hersteller-spezifische-api-konfiguration)
7. [Auto-Discovery](#7-auto-discovery)
8. [Tags und Gruppierung](#8-tags-und-gruppierung)

### D – Zertifikate & Sicherheit
9. [Zertifikatsverwaltung](#9-zertifikatsverwaltung)
10. [Sicherheitskonfiguration](#10-sicherheitskonfiguration)

### E – Anwendungseinstellungen
11. [Einstellungen](#11-einstellungen)
12. [Proxy-Konfiguration](#12-proxy-konfiguration)
13. [Pure1 Integration](#13-pure1-integration)

### F – Monitoring & Betrieb
14. [Dashboard-Ansichten](#14-dashboard-ansichten)
15. [Alerts und Ereignisse](#15-alerts-und-ereignisse)
16. [Kapazitätsreport](#16-kapazitätsreport)
17. [Logs und Diagnose](#17-logs-und-diagnose)

### G – CLI und API
18. [CLI-Interface](#18-cli-interface)
19. [REST API und Swagger UI](#19-rest-api-und-swagger-ui)

### H – Wartung & Notfall
20. [Backup und Recovery](#20-backup-und-recovery)
21. [Updates einspielen](#21-updates-einspielen)
22. [Fehlerbehebung](#22-fehlerbehebung)

### Anhang
- [Umgebungsvariablen-Referenz](#anhang-umgebungsvariablen-referenz)
- [Nützliche CLI-Befehle](#anhang-nützliche-cli-befehle)

---

## 1. Systemübersicht

Das Storage Dashboard ist eine Python/Flask-basierte Überwachungsplattform für heterogene
Storage-Umgebungen. Es richtet sich an Administratoren, die mehrere Storage-Systeme
verschiedener Hersteller zentral überwachen möchten.

**Unterstützte Storage-Systeme:**

| System | API | Authentifizierung | Standard-Port |
|--------|-----|-------------------|---------------|
| **Pure Storage FlashArray** | REST API v2 | API Token | 443 |
| **NetApp ONTAP 9** | ONTAP REST API | Benutzername / Passwort | 443 |
| **NetApp StorageGRID 11** | Grid Management API v4 | Bearer Token oder User/PW | 443 |
| **Dell DataDomain** | DataDomain REST API v1.0 | Benutzername / Passwort | 3009 |

**Kernfunktionen:**

- Echtzeit-Dashboard mit Card- und Table-Ansicht
- Konsolidierte Alerts aller Systeme (inkl. ONTAP EMS Events)
- Kapazitätsreport mit historischen Verläufen (2 Jahre)
- System-Detailansicht (Hardware-Status, Node-Infos, Capacity)
- Hintergrund-Polling mit konfigurierbarem Intervall
- Tags-System für flexible Kategorisierung
- REST API mit Swagger UI
- CLI-Interface (lokal und remote)
- Pure1 Integration (Storage on Demand)

> **Hinweis:** Das Dashboard ist für den Einsatz in **internen Firmennetzwerken** konzipiert.
> Es unterstützt firmeneigene CA- und Root-Zertifikate.

---

## 2. Systemvoraussetzungen

### Server-Anforderungen

| Ressource | Minimum | Empfohlen |
|-----------|---------|-----------|
| **Betriebssystem** | Linux (SLES 15, Ubuntu 22+, RHEL 8+) | SLES 15 SP5+ oder Ubuntu 24 |
| **CPU** | 2 Cores | 4 Cores |
| **RAM** | 2 GB | 4 GB |
| **Festplatte** | 10 GB | 20 GB |
| **Python** | 3.8+ | 3.11+ |
| **Datenbank** | SQLite | PostgreSQL 16 |

### Netzwerk-Anforderungen

Das Dashboard benötigt ausgehenden HTTPS-Zugriff zu den Storage-Systemen:

| System | Port | Protokoll |
|--------|------|-----------|
| Pure Storage | 443 | HTTPS |
| NetApp ONTAP | 443 | HTTPS |
| NetApp StorageGRID | 443 | HTTPS |
| Dell DataDomain | 3009 | HTTPS |

**Firewall-Konfiguration (SLES 15):**
```bash
# Ausgehende Verbindungen zu Storage-Systemen erlauben
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" destination address="<storage-ip>" port port="443" protocol="tcp" accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" destination address="<datadomain-ip>" port port="3009" protocol="tcp" accept'
sudo firewall-cmd --reload
```

**Eingehende Verbindungen zum Dashboard (Port 5000):**
```bash
sudo firewall-cmd --permanent --add-port=5000/tcp
sudo firewall-cmd --reload
```

---

## 3. Erste Schritte nach der Installation

Nach der Installation (siehe [DEPLOYMENT.md](DEPLOYMENT.md)) müssen folgende Schritte
ausgeführt werden, bevor das Dashboard nutzbar ist.

### 3.1 Admin-Benutzer anlegen

```bash
# Container-Deployment (Docker)
docker exec -it storage-dashboard python cli.py admin create-user

# Container-Deployment (nerdctl)
sudo nerdctl exec -it storage-dashboard python cli.py admin create-user

# Manuelle Installation
cd /opt/storage-dashboard
source venv/bin/activate
python cli.py admin create-user
```

Folgen Sie der interaktiven Eingabe: Benutzername → Passwort → Bestätigung.

### 3.2 Dashboard aufrufen

Öffnen Sie im Browser:
```
http://<server-ip>:5000
```

### 3.3 Admin-Bereich öffnen

```
http://<server-ip>:5000/admin
```

![Admin-Bereich](screenshots/admin-area.png)

### 3.4 Erstes Storage-System hinzufügen

Klicken Sie im Admin-Bereich auf **„+ Neues System"** und folgen Sie den Anweisungen
in [Abschnitt 5](#5-storage-systeme-hinzufügen-und-bearbeiten).

---

## 4. Admin-Login und Benutzerverwaltung

### Login

Der Admin-Bereich ist passwortgeschützt und unter `/admin` erreichbar. Nach erfolgreichem
Login bleibt die Sitzung aktiv, bis der Browser geschlossen wird oder ein manueller Logout erfolgt.

![Admin Login](screenshots/admin-area.png)

### Passwort ändern

```bash
# Container
docker exec -it storage-dashboard python cli.py admin change-password

# Manuelle Installation
python cli.py admin change-password
```

### Weitere Admin-Befehle

```bash
# Alle Admin-Benutzer auflisten
python cli.py admin list-users

# Benutzer löschen
python cli.py admin delete-user <benutzername>
```

---

## 5. Storage-Systeme hinzufügen und bearbeiten

### 5.1 Neues System hinzufügen

#### Schritt 1: Admin-Bereich öffnen

Navigieren Sie zu: `http://<dashboard-server>:5000/admin`

#### Schritt 2: „+ Neues System" klicken

Button befindet sich in der oberen rechten Ecke der Systemliste.

#### Schritt 3: Formular ausfüllen

**Grundlegende Informationen:**

| Feld | Beschreibung | Beispiel |
|------|-------------|---------|
| **Name** | Eindeutiger Systemname | `Pure-FlashArray-DC1` |
| **Hersteller** | Vendor aus Dropdown | `pure` |
| **IP-Adresse** | Management-IP des Systems | `192.168.10.50` |
| **Port** | API-Port (Standard: 443) | `443` |

**API-Zugangsdaten nach Hersteller:**

| Hersteller | Benutzername | Passwort | API Token |
|-----------|-------------|---------|-----------|
| Pure Storage | leer lassen | leer lassen | ✅ Pflichtfeld |
| NetApp ONTAP | ✅ Pflichtfeld | ✅ Pflichtfeld | leer lassen |
| NetApp StorageGRID | optional | optional | ✅ oder User/PW |
| Dell DataDomain | ✅ Pflichtfeld | ✅ Pflichtfeld | leer lassen |

**Status:**
- **Aktiviert** → System wird abgefragt und im Dashboard angezeigt
- **Deaktiviert** → System wird nicht abgefragt (für Wartungsarbeiten)

#### Schritt 4: Speichern

Nach dem Speichern führt das Dashboard automatisch eine Auto-Discovery durch.

**Erfolgsmeldungen:**
- ✅ *„System added and discovered successfully! Found X nodes."*
- ⚠️ *„System added but discovery had issues: [Details]"* (System wird trotzdem gespeichert)

### 5.2 System bearbeiten

Klicken Sie auf **„✏️ Bearbeiten"** beim entsprechenden System in der Admin-Übersicht.
Alle Felder sind editierbar, Passwörter und Tokens werden verschlüsselt gespeichert.

### 5.3 System aktivieren / deaktivieren

Klicken Sie auf den **Aktiv/Inaktiv**-Schalter in der Systemliste. Deaktivierte Systeme
erscheinen nicht im Dashboard und werden nicht abgefragt.

### 5.4 System löschen

Klicken Sie auf **„🗑️ Löschen"** und bestätigen Sie den Dialog. Alle gespeicherten Daten
(Logs, Kapazitätsdaten, Cache) des Systems werden ebenfalls gelöscht.

---

## 6. Hersteller-spezifische API-Konfiguration

### 6.1 Pure Storage FlashArray

#### API Token erstellen

**Über die Web-GUI:**
1. Anmelden: `https://<pure-ip>`
2. **System → Users** öffnen
3. Benutzer „dashboard_api" anlegen
4. **„Create API Token"** klicken
5. Token kopieren und im Dashboard-Formular eintragen

**Über die CLI:**
```bash
# Token für bestehenden Benutzer erstellen
purecli user apitoken create --user dashboard_api

# Token anzeigen
purecli user apitoken list --user dashboard_api
```

**Empfohlene Rechte:**
- `readonly` oder dedizierte Read-Only-Gruppe

**API-Test:**
```bash
curl -k -H "Authorization: Bearer <api-token>" \
  https://<pure-ip>/api/2.0/arrays
```

---

### 6.2 NetApp ONTAP 9

#### API-Benutzer erstellen

**Über die CLI (SSH auf ONTAP):**
```bash
# Benutzer anlegen
security login create -user-or-group-name dashboard_api \
  -application http \
  -authentication-method password \
  -role readonly
```

**Über die System Manager GUI:**
1. **Cluster → Settings → Users and Roles** öffnen
2. **„Add"** klicken
3. Username: `dashboard_api`, Role: `readonly`, Application: `HTTP`

**API-Test:**
```bash
curl -k -u dashboard_api:<password> \
  https://<ontap-ip>/api/cluster
```

**Verwendete API-Endpunkte:**
- `GET /api/cluster` – Cluster-Informationen
- `GET /api/cluster/nodes` – Node-Status
- `GET /api/cluster/health/alerts` – Hardware-Alerts
- `GET /api/support/ems/events` – EMS Events (Emergency/Alert/Error)
- `GET /api/cluster/peers` – Cluster-Peering
- `GET /api/storage/aggregates` – Aggregat-Status
- `GET /api/storage/disks` – Festplatten-Status
- `GET /api/snapmirror/relationships` – SnapMirror-Status

---

### 6.3 NetApp StorageGRID 11

#### Bearer Token generieren

```bash
# Token via API generieren
curl -k -X POST "https://<storagegrid-ip>/api/v3/authorize" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "<password>", "cookie": false, "csrfToken": false}'

# Response enthält Bearer Token:
# {"data": "Bearer eyJhbGci..."}
```

**Token-Gültigkeit:** Standard: 16 Stunden. Empfehlung: Benutzername/Passwort verwenden
(Dashboard generiert dann automatisch neue Tokens).

#### Dashboard-Konfiguration (empfohlen: User/PW)

| Feld | Wert |
|------|------|
| Hersteller | `netapp-storagegrid` |
| IP-Adresse | Admin Node IP |
| Port | 443 |
| Benutzername | Service-Account |
| Passwort | Passwort |
| API Token | leer lassen |

#### Benötigte Berechtigungen

- Grid Topology Page Access
- Storage Appliances Pages Access
- Read-Only Access zur Grid-Konfiguration

---

### 6.4 Dell DataDomain

#### REST API aktivieren

```bash
# REST API auf dem DataDomain-System aktivieren
rest enable
rest show
```

#### API-Benutzer erstellen

**Über die CLI:**
```bash
user add dashboard_api
password set dashboard_api
user modify dashboard_api role read-only
user show dashboard_api
```

**Über die Web-GUI:**
1. `https://<datadomain-ip>` öffnen
2. **Administration → Access → Local Users → Create**
3. Username: `dashboard_api`, Role: `read-only`

**Dashboard-Konfiguration:**

| Feld | Wert |
|------|------|
| Hersteller | `dell-datadomain` |
| IP-Adresse | Management-IP |
| Port | **3009** (abweichend von Standard!) |
| Benutzername | `dashboard_api` |
| Passwort | Gesetztes Passwort |

**API-Test:**
```bash
curl -k -u dashboard_api:<password> \
  https://<datadomain-ip>:3009/rest/v1.0/dd-systems/0/health
```

---

## 7. Auto-Discovery

Die Auto-Discovery wird automatisch beim Hinzufügen eines Systems ausgeführt und
ermittelt folgende Informationen:

| Information | Beschreibung |
|------------|-------------|
| **Cluster-Typ** | `local`, `ha`, `metrocluster`, `active-cluster`, `multi-site` |
| **Node-Anzahl** | Anzahl der erkannten Nodes |
| **Node-Details** | Name, IP, Status, Rolle |
| **DNS-Namen** | Alle Hostnamen / FQDNs |
| **IP-Adressen** | Alle Management-IPs |
| **OS-Version** | Firmware/Betriebssystemversion |

### Discovery erneut ausführen

Falls sich die Systemkonfiguration ändert (z.B. nach Cluster-Erweiterung):

1. Admin-Bereich öffnen
2. **„🔄 Discovery"** beim entsprechenden System klicken

---

## 8. Tags und Gruppierung

Tags ermöglichen die flexible Kategorisierung und Filterung von Storage-Systemen.

![Tags](screenshots/tags-page.png)

### 8.1 Tag-Gruppen

Tags sind in Gruppen organisiert. Empfohlene Gruppen:

| Gruppe | Beispiel-Tags |
|--------|--------------|
| Storage Art | Block, File, Object, Archiv, Backup |
| Landschaft | Produktion, Test/Dev, Labor |
| Tätigkeitsfeld | ITS, ERZ, EH, Extern |

### 8.2 Tag-Gruppe anlegen

1. Admin → **Tags** → **„+ Neue Gruppe"**
2. Name und Beschreibung eingeben
3. Speichern

### 8.3 Tag anlegen

1. Admin → **Tags** → Gruppe auswählen → **„+ Neuer Tag"**
2. Tag-Name eingeben
3. Speichern

### 8.4 Tags einem System zuweisen

1. Admin → System **bearbeiten**
2. Im Formular unter **„Tags"** die gewünschten Tags anklicken
3. Speichern

Tags wirken sich aus auf:
- **Dashboard-Filter**: Filtern nach Tag
- **Kapazitätsreport**: Gruppierung nach Storage Art, Landschaft, Tätigkeitsfeld

---

## 9. Zertifikatsverwaltung

Das Dashboard unterstützt firmeneigene CA- und Root-Zertifikate für Storage-Systeme
mit selbst-signierten Zertifikaten.

![Zertifikate](screenshots/certificates-page.png)

### 9.1 Zertifikat exportieren

**Aus dem Browser:**
1. Storage-System im Browser öffnen
2. Schloss-Symbol in der Adressleiste anklicken
3. Zertifikat anzeigen → exportieren als `.crt` oder `.pem`

**Via openssl:**
```bash
# Zertifikat vom Server abrufen und speichern
echo | openssl s_client -connect <storage-ip>:443 2>/dev/null \
  | openssl x509 > storage-ca.crt

# Zertifikat-Details anzeigen
openssl x509 -in storage-ca.crt -noout -text
```

### 9.2 Zertifikat hochladen

1. Admin → **Zertifikate** → **„Zertifikat hochladen"**
2. PEM- oder CRT-Datei auswählen
3. Namen vergeben
4. **„Hochladen"** klicken

### 9.3 SSL-Verifizierung aktivieren

Nach dem Hochladen aller CA-Zertifikate:

```bash
# In .env
SSL_VERIFY=true

# Container neu starten
docker-compose restart storage-dashboard
```

![Einstellungen – Zertifikate](screenshots/settings-certificates.png)

### 9.4 Zertifikat aktivieren / deaktivieren

Unter Admin → Zertifikate können einzelne Zertifikate per Schalter aktiviert oder
deaktiviert werden, ohne sie zu löschen.

---

## 10. Sicherheitskonfiguration

### Empfehlungen

| Maßnahme | Priorität | Beschreibung |
|---------|-----------|-------------|
| **HTTPS-Reverse-Proxy** | Hoch | Nginx mit firmeneigenem Zertifikat vorschalten |
| **Starker Secret Key** | Hoch | 64-Zeichen Hex-String: `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| **Read-Only-API-Accounts** | Hoch | Nur lesende Rechte für Storage-Systeme |
| **SSL-Verifizierung** | Mittel | `SSL_VERIFY=true` nach Zertifikat-Upload |
| **Firewall** | Hoch | Nur Port 5000 (oder 443 bei Proxy) öffnen |
| **Backups** | Mittel | Regelmäßige Datenbank-Backups |
| **Container-Updates** | Mittel | Images und Host-OS aktuell halten |

### Secret Key rotieren

```bash
# Neuen Secret Key generieren
python3 -c "import secrets; print(secrets.token_hex(32))"

# In .env ersetzen und Container neu starten
# Achtung: Alle aktiven Sitzungen werden ungültig
docker-compose restart storage-dashboard
```

---

## 11. Einstellungen

Erreichbar unter: **Admin → Einstellungen** (`/admin/settings`)

Die Einstellungen sind in sechs Tabs organisiert:

### Tab: Design

Firmenname, Logo-URL und Farbschema (Primär-, Sekundär- und Akzentfarbe).

![Einstellungen – Design](screenshots/settings-design.png)

### Tab: Logs

- **Max. Logs pro System**: Maximale Anzahl gespeicherter Log-Einträge pro Storage-System
- **Aufbewahrungsdauer**: Wie lange Logs aufbewahrt werden (in Tagen)
- **Minimales Log-Level**: `DEBUG`, `INFO`, `WARNING`, `ERROR`

![Einstellungen – Logs](screenshots/settings-logs.png)

### Tab: Zertifikate

Upload und Verwaltung von CA-Zertifikaten (Kurzübersicht; Details in [Abschnitt 9](#9-zertifikatsverwaltung)).

![Einstellungen – Zertifikate](screenshots/settings-certificates.png)

### Tab: API-Zugänge (Pure1)

Konfiguration der Pure1 Integration (Details in [Abschnitt 13](#13-pure1-integration)).

![Einstellungen – API-Zugänge (Pure1)](screenshots/settings-api-access-pure1.png)

### Tab: Proxy

HTTP/HTTPS-Proxy für ausgehende Internetverbindungen (Details in [Abschnitt 12](#12-proxy-konfiguration)).

![Einstellungen – Proxy](screenshots/settings-proxy.png)

### Tab: System

- **Zeitzone**: z.B. `Europe/Berlin` (MEZ/MESZ)
- **Hintergrund-Aktualisierungsintervall**: 1–60 Minuten (wie oft Statusdaten vom Polling-Service aktualisiert werden)

![Einstellungen – System](screenshots/settings-system.png)

---

## 12. Proxy-Konfiguration

Ein HTTP/HTTPS-Proxy ist erforderlich, wenn das Dashboard-System keinen direkten
Internetzugang hat (z.B. für Pure1).

### Proxy konfigurieren

1. Admin → **Einstellungen** → Tab **„Proxy"**
2. HTTP-Proxy-URL eingeben: `http://proxy.example.com:3128`
3. HTTPS-Proxy-URL eingeben: `https://proxy.example.com:3128`
4. **„Speichern"** klicken

Proxy-URLs werden **verschlüsselt** in der Datenbank gespeichert.

> **Hinweis:** Der Proxy wird ausschließlich für ausgehende Internetverbindungen verwendet
> (z.B. Pure1 API). Verbindungen zu lokalen Storage-Systemen werden **nie** über den Proxy
> geleitet.

---

## 13. Pure1 Integration

Pure1 liefert Storage-on-Demand (SoD) Vertragsdaten und ergänzt die lokalen Kapazitätswerte
bei Pure FlashArrays mit Evergreen/One Dashboard.

### 13.1 Pure1 App-ID und Schlüsselpaar erstellen

1. Anmelden auf [https://pure1.purestorage.com](https://pure1.purestorage.com)
2. **Administration → API Registration → Register Application**
3. Namen vergeben (z.B. `storage-dashboard`)
4. RSA-Schlüsselpaar generieren:
   ```bash
   openssl genrsa -out pure1_private.pem 2048
   openssl rsa -in pure1_private.pem -pubout -out pure1_public.pem
   ```
5. Public Key in Pure1 hochladen → App-ID notieren

### 13.2 Pure1 in Dashboard konfigurieren

1. Admin → **Einstellungen** → Tab **„API-Zugänge (Pure1)"**
2. Felder ausfüllen:
   - **App-ID**: z.B. `pure1:apikey:xxxxxxxx`
   - **Private Key (PEM)**: Inhalt der `pure1_private.pem`-Datei
   - **Passphrase**: Falls der Key passwortgeschützt ist (sonst leer)
3. **„Speichern"** klicken

App-ID, Private Key und Passphrase werden **verschlüsselt** gespeichert.

![Einstellungen – API-Zugänge (Pure1)](screenshots/settings-api-access-pure1.png)

---

## 14. Dashboard-Ansichten

### 14.1 Card-Ansicht

Jede Systemkarte zeigt: Name, IP, Status-Badge, Hardware-Status, Alerts-Zähler,
Kapazitätsbalken und zugewiesene Tags.

![Dashboard – Card-Ansicht](screenshots/dashboard-card-view.png)

### 14.2 Table-Ansicht

Kompakte Tabellenansicht – ideal bei vielen Systemen.

![Dashboard – Table-Ansicht](screenshots/dashboard-table-view.png)

### 14.3 Dashboard-Funktionen

| Funktion | Beschreibung |
|---------|-------------|
| **Filter** | Nach Hersteller, Status, Cluster-Typ, Tags, Freitext |
| **🔔 Alerts-Badge** | Navbar-Button zeigt Anzahl offener Alerts |
| **↻ Aktualisieren** | Sofortige manuelle Datenaktualisierung |
| **Auto-Refresh** | 30–120 Sekunden, ohne Seiten-Reload |
| **Spaltenbreite** | 1–4 Spalten (Card-Ansicht) |
| **Caching** | Status-Daten aus Hintergrund-Cache – UI erscheint sofort |

### 14.4 System-Detailansicht

Erreichbar über **„Details"**-Button oder `/systems/<id>/details`.

![System-Detailansicht](screenshots/system-details.png)

**Angezeigte Informationen:**
- Hersteller, Live-Status (oder gecachter Status mit Hinweis-Banner)
- Hardware-Status, Cluster-Status, Alerts-Zähler
- Kapazität (Gesamt/Genutzt/Frei/Auslastung)
- Netzwerk-Information (IP, Ports)
- Cluster-/Node-Details, Hardware-Komponenten

---

## 15. Alerts und Ereignisse

### 15.1 Alerts-Seite

Erreichbar über den orangen **🔔-Button** in der Navbar (zeigt Anzahl offener Alerts).

![Alerts-Seite](screenshots/alerts-page.png)

### 15.2 Alert-Quellen

| Hersteller | Quelle | Felder |
|-----------|--------|--------|
| **NetApp ONTAP** | EMS Events (`/api/support/ems/events`) | Severity, EMS-Name, Log-Message, Node, Zeitstempel |
| **Pure Storage** | Array Alerts | Severity, Titel, Details, Error-Code, Komponente |
| **NetApp StorageGRID** | Grid Alerts | Severity, Alert-Name, Details, Node |
| **Dell DataDomain** | Active Alerts | Severity, Alert-Name, Kategorie, Meldung |

### 15.3 Alert-Bearbeitung

Alerts können direkt in der Alerts-Seite bearbeitet werden:

- **Acknowledgen**: Alert als „zur Kenntnis genommen" markieren
- **Assignee setzen**: Verantwortlichen Benutzer zuweisen
- **Kommentar hinzufügen**: Freitext-Notiz zum Alert

Diese Zustände werden in der Datenbank gespeichert und bleiben erhalten, bis der Alert
vom Storage-System aufgehoben wird.

### 15.4 ONTAP EMS Alert-Filterung

Das Dashboard wendet folgende Filter auf EMS Events an:

- **Altersfilter**: Nur Events der letzten 48 Stunden
- **Severity-Split**: Hardware- und Nicht-Hardware-Events werden unterschiedlich bewertet
- **Problem/Recovery-Paare**: Bereits aufgelöste Events werden ausgeblendet

---

## 16. Kapazitätsreport

Erreichbar unter `/capacity/`

![Kapazitätsreport – Details](screenshots/capacity-details.png)

### 16.1 Tab: Nach Storage Art

Kapazitäten gruppiert nach Storage-Typ (Block → File → Object → Archiv → Backup),
mit Untergruppierung nach Umgebung.

![Kapazitätsreport – Nach Storage Art](screenshots/capacity-by-storage-art.png)

### 16.2 Tab: Nach Umgebung

Kapazitäten gruppiert nach Betriebsumgebung (Produktion / Test/Dev).

![Kapazitätsreport – Nach Umgebung](screenshots/capacity-by-environment.png)

### 16.3 Tab: Nach Tätigkeitsfeld

Kapazitäten gruppiert nach Themenzugehörigkeit (ITS, ERZ, EH, …).

![Kapazitätsreport – Nach Tätigkeitsfeld](screenshots/capacity-by-department.png)

### 16.4 Tab: Details

Alle Einzelsysteme mit Umgebung, Tätigkeitsfeld, Gesamt/Genutzt/Frei und Auslastungs-Balken.

### 16.5 Tab: Verlauf

Historische Kapazitätsgraphen (bis zu 2 Jahre, tägliche Datenpunkte).

![Kapazitätsreport – Verlauf](screenshots/capacity-history.png)

**Verlauf-Steuerleiste** (Zeitraum, Export, Import):

![Kapazitätsreport – Verlauf Steuerleiste](screenshots/capacity-history-controls.png)

### 16.6 Import / Export

| Format | Funktion |
|--------|---------|
| **CSV-Export** | Alle Kapazitätsdaten als CSV herunterladen |
| **Excel-Export** | Alle Kapazitätsdaten als XLSX herunterladen |
| **PDF-Export** | Bericht als PDF exportieren |
| **CSV-Import** | Kapazitätsdaten (inkl. SoD) manuell importieren |

---

## 17. Logs und Diagnose

### 17.1 Log-Viewer im Dashboard

Admin → **Logs** zeigt alle gespeicherten Log-Einträge mit Filter- und Such-Funktionen.

![Admin Logs](screenshots/admin-logs.png)

**Filter-Optionen:**
- System
- Log-Level (DEBUG, INFO, WARNING, ERROR)
- Kategorie (connection, api_call, discovery, …)
- Zeitraum
- Freitext-Suche

### 17.2 System-Logs (Container)

```bash
# Alle Logs verfolgen (Docker)
docker-compose logs -f

# Nur Dashboard-Logs
docker-compose logs -f storage-dashboard

# Letzte 100 Zeilen
docker-compose logs --tail=100 storage-dashboard
```

```bash
# nerdctl
sudo nerdctl compose logs -f storage-dashboard
```

### 17.3 System-Logs (manuelle Installation)

```bash
# Systemd-Journal
sudo journalctl -u storage-dashboard -f
sudo journalctl -u storage-dashboard -n 100
sudo journalctl -u storage-dashboard --since today

# Debug-Modus aktivieren
export FLASK_ENV=development
export FLASK_DEBUG=1
python3 run.py
```

### 17.4 Log-Level konfigurieren

Admin → **Einstellungen** → Tab **„Logs"** → Minimales Log-Level setzen.

---

## 18. CLI-Interface

### 18.1 Lokale CLI (`cli.py`)

```bash
# Datenbank-Migrationen ausführen
python cli.py migrate

# Admin-Benutzer erstellen
python cli.py admin create-user

# Alle Systeme auflisten
python cli.py admin list

# Neues System hinzufügen (interaktiv)
python cli.py admin add

# System aktivieren/deaktivieren
python cli.py admin enable <id>
python cli.py admin disable <id>

# System löschen
python cli.py admin remove <id>

# Dashboard-Status anzeigen
python cli.py dashboard
```

### 18.2 Remote CLI (`remote-cli.py`)

Die Remote CLI kommuniziert über die HTTP API mit dem Dashboard:

```bash
# Dashboard anzeigen (Standard: http://localhost:5000)
python remote-cli.py dashboard

# Remote-Server angeben
python remote-cli.py --url http://dashboard.example.com:5000 dashboard

# Alle Systeme auflisten
python remote-cli.py systems

# Status eines Systems
python remote-cli.py status <id>

# Daten exportieren
python remote-cli.py export --format json
python remote-cli.py export --format table
```

📖 **Remote-CLI-Dokumentation**: [REMOTE_CLI.md](REMOTE_CLI.md)

---

## 19. REST API und Swagger UI

Die vollständige REST API ist unter `/admin/swagger` mit interaktiver Swagger UI erreichbar.

![Swagger UI](screenshots/swagger-ui.png)

### Wichtige API-Endpunkte

| Methode | Pfad | Beschreibung |
|---------|------|-------------|
| `GET` | `/api/systems` | Alle Storage-Systeme auflisten |
| `GET` | `/api/status` | Live-Status aller aktiven Systeme |
| `GET` | `/api/systems/{id}/status` | Live-Status eines einzelnen Systems |
| `GET` | `/api/cached-status` | Gecachter Status aller aktiven Systeme |
| `POST` | `/api/trigger-status-refresh` | Sofortige Statusaktualisierung auslösen |
| `POST` | `/api/alerts/state` | Alert-Zustände aktualisieren (bulk) |
| `GET` | `/api/alerts/assignees` | Assignee-Historie |
| `GET` | `/systems/{id}/details` | Detailansicht eines Systems |
| `GET` | `/capacity/` | Kapazitätsreport |
| `GET` | `/alerts/` | Alerts-Seite |

**OpenAPI-Spezifikation** herunterladen: `/static/openapi.json`

### API-Dokumentation für Storage-Systeme

Unter `/admin/docs` finden Sie detaillierte Einrichtungsanleitungen für jeden
unterstützten Hersteller.

![API-Dokumentation](screenshots/admin-docs.png)

---

## 20. Backup und Recovery

### 20.1 Backup erstellen

**PostgreSQL (Container):**
```bash
# Backup-Verzeichnis erstellen
mkdir -p /backup/storage-dashboard

# Datenbankdump erstellen
docker exec storage-dashboard-db pg_dump \
  -U dashboard storage_dashboard \
  > /backup/storage-dashboard/db_$(date +%Y%m%d_%H%M%S).sql

# Konfiguration sichern
cp /opt/storage-dashboard/.env \
   /backup/storage-dashboard/.env_$(date +%Y%m%d)
```

**SQLite (manuelle Installation):**
```bash
#!/bin/bash
BACKUP_DIR="/backup/storage-dashboard"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Service kurz stoppen für konsistentes Backup
sudo systemctl stop storage-dashboard

cp /opt/storage-dashboard/storage_dashboard.db \
   $BACKUP_DIR/storage_dashboard_${DATE}.db
cp /opt/storage-dashboard/.env \
   $BACKUP_DIR/.env_${DATE}

sudo systemctl start storage-dashboard
echo "Backup erstellt: $BACKUP_DIR/storage_dashboard_${DATE}.db"
```

### 20.2 Recovery

**PostgreSQL:**
```bash
# Container stoppen
docker-compose down

# PostgreSQL-Container allein starten
docker-compose up -d postgres

# Backup wiederherstellen
docker exec -i storage-dashboard-db psql \
  -U dashboard storage_dashboard \
  < /backup/storage-dashboard/db_YYYYMMDD_HHMMSS.sql

# Alle Container starten
docker-compose up -d
```

**SQLite:**
```bash
sudo systemctl stop storage-dashboard

cp /backup/storage-dashboard/storage_dashboard_YYYYMMDD_HHMMSS.db \
   /opt/storage-dashboard/storage_dashboard.db

sudo chown dashboard:dashboard /opt/storage-dashboard/storage_dashboard.db
sudo chmod 644 /opt/storage-dashboard/storage_dashboard.db

sudo systemctl start storage-dashboard
```

---

## 21. Updates einspielen

### Container-Deployment (Docker)

```bash
cd /opt/storage-dashboard

# Neustes Image herunterladen
docker-compose pull

# Container mit neuer Version neu starten
docker-compose up -d

# Datenbank-Migrationen ausführen (automatisch beim Start)
# Falls manuell nötig:
docker exec storage-dashboard python cli.py migrate

# Alte Images aufräumen
docker image prune -f
```

### Container-Deployment (nerdctl)

```bash
cd /opt/storage-dashboard

sudo nerdctl compose pull
sudo nerdctl compose up -d
sudo nerdctl image prune -f
```

### Manuelle Installation

```bash
sudo su - dashboard
cd /opt/storage-dashboard
source venv/bin/activate

# Code aktualisieren
git pull

# Abhängigkeiten aktualisieren
pip install -r requirements.txt --upgrade

# Datenbank-Migrationen ausführen
python cli.py migrate

# Service neu starten
exit
sudo systemctl restart storage-dashboard
```

---

## 22. Fehlerbehebung

### 22.1 Verbindungsfehler

**Problem:** „Connection timeout" oder „Unable to connect"

```bash
# Netzwerk-Konnektivität testen
ping <storage-ip>

# Port-Erreichbarkeit prüfen
nc -zv <storage-ip> 443
nc -zv <datadomain-ip> 3009

# Firewall-Regeln prüfen
sudo firewall-cmd --list-all    # SLES 15
sudo ufw status                 # Ubuntu
```

### 22.2 SSL/TLS-Fehler

**Problem:** „SSL Certificate Verify Failed"

**Lösung A:** CA-Zertifikat hochladen (empfohlen – siehe [Abschnitt 9](#9-zertifikatsverwaltung)):
```bash
# Zertifikat manuell testen
echo | openssl s_client -connect <storage-ip>:443 -showcerts
```

**Lösung B:** SSL-Verifizierung deaktivieren (nur für Tests!):
```bash
# In .env
SSL_VERIFY=false
docker-compose restart storage-dashboard
```

### 22.3 Authentifizierungsfehler

**Problem:** „401 Unauthorized" oder „403 Forbidden"

```bash
# Credentials manuell testen:

# Pure Storage
curl -k -H "Authorization: Bearer <api-token>" \
  https://<pure-ip>/api/2.0/arrays

# NetApp ONTAP
curl -k -u <username>:<password> \
  https://<ontap-ip>/api/cluster

# StorageGRID
curl -k -H "Authorization: Bearer <token>" \
  https://<storagegrid-ip>/api/v3/grid/health/topology

# DataDomain
curl -k -u <username>:<password> \
  https://<datadomain-ip>:3009/rest/v1.0/dd-systems/0/health
```

### 22.4 Discovery-Fehler

**Problem:** „System added but discovery had issues"

1. Discovery manuell erneut ausführen: Admin → **🔄 Discovery**
2. Logs prüfen (siehe [Abschnitt 17](#17-logs-und-diagnose))
3. API-Zugriff einzeln testen (siehe oben)
4. Berechtigungen des API-Benutzers prüfen

### 22.5 Performance-Probleme

**Problem:** Dashboard-Laden dauert sehr lange

- **Hintergrund-Polling-Intervall erhöhen**: Admin → Einstellungen → System → Intervall auf 10+ Minuten
- **Auto-Refresh-Intervall erhöhen**: Im Browser-Dashboard Auto-Refresh auf 60+ Sekunden
- **Anzahl gleichzeitiger Abfragen begrenzen**: Weniger Systeme gleichzeitig aktiviert lassen

### 22.6 Datenbankprobleme

**Problem:** „Database locked" oder „Integrity Error"

```bash
# Container: Datenbank-Migration ausführen
docker exec storage-dashboard python cli.py migrate

# SQLite: Datenbankdatei prüfen
sqlite3 storage_dashboard.db "PRAGMA integrity_check;"
sqlite3 storage_dashboard.db "PRAGMA journal_mode;"  # Sollte 'wal' sein

# SQLite: Rechte prüfen
ls -la /opt/storage-dashboard/storage_dashboard.db
chmod 644 /opt/storage-dashboard/storage_dashboard.db
```

---

## Anhang: Umgebungsvariablen-Referenz

```bash
# ---- Pflichtfelder ----
SECRET_KEY=<64-Zeichen Hex-String>           # Flask Session Secret
POSTGRES_PASSWORD=<Passwort>                 # PostgreSQL-Passwort (Container)

# ---- Datenbank ----
DATABASE_URL=postgresql://dashboard:<PW>@postgres:5432/storage_dashboard
# Alternative (nur kleine Deployments):
# DATABASE_URL=sqlite:////app/data/storage_dashboard.db
POSTGRES_DB=storage_dashboard
POSTGRES_USER=dashboard

# ---- Anwendung ----
FLASK_ENV=production
SSL_VERIFY=false                             # TLS-Verifizierung der Storage-Systeme
TZ=Europe/Berlin                             # Zeitzone

# ---- Optional ----
LOG_LEVEL=INFO
GUNICORN_WORKERS=4
GUNICORN_TIMEOUT=120
```

---

## Anhang: Nützliche CLI-Befehle

```bash
# ---- Systemverwaltung ----
python cli.py admin list                 # Alle Systeme auflisten
python cli.py admin add                  # System hinzufügen (interaktiv)
python cli.py admin enable <id>          # System aktivieren
python cli.py admin disable <id>         # System deaktivieren
python cli.py admin remove <id>          # System löschen

# ---- Benutzerverwaltung ----
python cli.py admin create-user          # Admin-Benutzer erstellen
python cli.py admin list-users           # Benutzer auflisten
python cli.py admin change-password      # Passwort ändern

# ---- Datenbank ----
python cli.py migrate                    # Migrationen ausführen

# ---- Dashboard ----
python cli.py dashboard                  # Status im Terminal anzeigen
```

---

**Dokumentversion:** 2.0  
**Letzte Aktualisierung:** März 2026  
**Lizenz:** Siehe LICENSE-Datei im Repository  
**Support:** [GitHub Issues](https://github.com/TimUx/storage-dashboard/issues)
