# REST API Schnittstellendokumentation – Storage Dashboard

Diese Dokumentation beschreibt, wie das Storage Dashboard die REST APIs der verschiedenen Storage-Systeme einbindet und verwendet.
Für jedes System werden die **Authentifizierungsmethode**, typische **API-Aufrufe** und ein vollständiger **Beispielablauf mit cURL-Kommandos** beschrieben.

---

## Inhaltsverzeichnis

1. [Pure Storage FlashArray](#1-pure-storage-flasharray)
2. [NetApp ONTAP 9](#2-netapp-ontap-9)
3. [NetApp StorageGRID 11](#3-netapp-storagegrid-11)
4. [Dell DataDomain](#4-dell-datadomain)
5. [Gemeinsamkeiten & Konventionen](#5-gemeinsamkeiten--konventionen)

---

## 1. Pure Storage FlashArray

### Übersicht

| Eigenschaft          | Wert                                           |
|----------------------|------------------------------------------------|
| **API-Typ**          | Pure Storage FlashArray REST API v2.x          |
| **Standard-Port**    | `443` (HTTPS)                                  |
| **Basis-URL**        | `https://<ip-oder-hostname>/api/<version>`     |
| **Authentifizierung**| API-Token → Session-Token (x-auth-token)       |
| **Credential-Typ**   | API-Token (kein Benutzername/Passwort)         |

### Authentifizierungsmethode

Die FlashArray-API verwendet ein zweistufiges Verfahren:

1. Der **API-Token** (dauerhaft, im Dashboard konfiguriert) wird als Request-Header `api-token` beim `POST /api/<version>/login` übergeben.
2. Die API antwortet mit einem kurzlebigen **Session-Token** im Response-Header `x-auth-token`.
3. Alle weiteren Requests senden diesen Session-Token im Header `x-auth-token`.
4. Nach dem Abschluss der Abfragen wird mit `POST /api/<version>/logout` die Session beendet.

> **API-Version:** Das Dashboard erkennt die unterstützte API-Version automatisch via `GET /api/api_version` und verwendet immer die neueste verfügbare Version (mindestens `2.4`).

### Typische API-Aufrufe

| Zweck                     | Methode | Endpunkt                                  |
|---------------------------|---------|-------------------------------------------|
| API-Version erkennen      | GET     | `/api/api_version`                        |
| Authentifizieren          | POST    | `/api/<version>/login`                    |
| Array-Name / Purity-Version| GET    | `/api/<version>/arrays`                   |
| Kapazität (total / used)  | GET     | `/api/<version>/arrays/space`             |
| Controller / Nodes        | GET     | `/api/<version>/controllers`              |
| Netzwerk-Interfaces       | GET     | `/api/<version>/network-interfaces`       |
| Hardware-Komponenten      | GET     | `/api/<version>/hardware`                 |
| Laufwerksstatus           | GET     | `/api/<version>/drives`                   |
| Offene Alerts             | GET     | `/api/<version>/alerts?filter=state='open'` |
| Array-Verbindungen (Replication) | GET | `/api/<version>/array-connections`  |
| ActiveCluster Pods        | GET     | `/api/<version>/pods`                     |
| Session beenden           | POST    | `/api/<version>/logout`                   |

### Beispielablauf mit cURL

Ersetzen Sie `<ARRAY>` durch IP-Adresse oder Hostname Ihres FlashArray und `<API_TOKEN>` durch den konfigurierten API-Token.

#### Schritt 1 – API-Version erkennen

```bash
curl -sk https://<ARRAY>/api/api_version | python3 -m json.tool
```

Beispiel-Antwort:
```json
{
  "version": ["2.4", "2.5", "2.10", "2.26"]
}
```

Verwenden Sie die höchste Version für alle weiteren Aufrufe, hier `2.26`.

#### Schritt 2 – Authentifizieren (Session-Token holen)

```bash
SESSION_TOKEN=$(curl -sk -X POST https://<ARRAY>/api/2.26/login \
  -H "api-token: <API_TOKEN>" \
  -H "Content-Type: application/json" \
  -D - 2>&1 | grep -i "x-auth-token" | awk '{print $2}' | tr -d '\r')

echo "Session-Token: $SESSION_TOKEN"
```

> Der `x-auth-token` befindet sich im **Response-Header**, nicht im Body.  
> Der obige Befehl gibt alle Headers aus (`-D -`) und filtert dann den Token heraus.

Alternativ, falls Sie den Header direkt sehen möchten:

```bash
curl -sk -X POST https://<ARRAY>/api/2.26/login \
  -H "api-token: <API_TOKEN>" \
  -H "Content-Type: application/json" \
  -D /dev/stderr -o /dev/null
```

#### Schritt 3 – Array-Info abrufen (Systemname, Purity-Version)

```bash
curl -sk https://<ARRAY>/api/2.26/arrays \
  -H "x-auth-token: $SESSION_TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

Beispiel-Antwort:
```json
{
  "items": [
    {
      "id": "abc123...",
      "name": "flasharray-prod-01",
      "os": "Purity//FA",
      "version": "6.5.10"
    }
  ]
}
```

#### Schritt 4 – Kapazität abrufen

```bash
curl -sk https://<ARRAY>/api/2.26/arrays/space \
  -H "x-auth-token: $SESSION_TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

Beispiel-Antwort:
```json
{
  "items": [
    {
      "capacity": 107374182400,
      "space": {
        "total_physical": 52428800000,
        "data_reduction": 3.2,
        "shared": 1073741824,
        "snapshots": 2147483648,
        "unique": 49207574528
      }
    }
  ]
}
```

#### Schritt 5 – Offene Alerts abfragen

```bash
curl -sk "https://<ARRAY>/api/2.26/alerts?filter=state%3D%27open%27" \
  -H "x-auth-token: $SESSION_TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

#### Schritt 6 – Hardware-Status abfragen

```bash
curl -sk https://<ARRAY>/api/2.26/hardware \
  -H "x-auth-token: $SESSION_TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

#### Schritt 7 – Session beenden (Logout)

```bash
curl -sk -X POST https://<ARRAY>/api/2.26/logout \
  -H "x-auth-token: $SESSION_TOKEN" \
  -H "Content-Type: application/json"
```

---

## 2. NetApp ONTAP 9

### Übersicht

| Eigenschaft          | Wert                                           |
|----------------------|------------------------------------------------|
| **API-Typ**          | NetApp ONTAP REST API                          |
| **Standard-Port**    | `443` (HTTPS)                                  |
| **Basis-URL**        | `https://<ip-oder-hostname>/api`               |
| **Authentifizierung**| HTTP Basic Authentication (Benutzername/Passwort) |
| **Credential-Typ**   | Benutzername + Passwort                        |

### Authentifizierungsmethode

ONTAP verwendet **HTTP Basic Authentication**. Benutzername und Passwort werden bei jedem Request als Base64-kodierter `Authorization`-Header mitgesendet (`Authorization: Basic <base64(user:password)>`). Es gibt keinen separaten Login-Schritt – jeder API-Call ist eigenständig authentifiziert.

> **Benutzerrechte:** Der konfigurierte Benutzer benötigt mindestens Leserechte auf `api/cluster`, `api/storage`, `api/network`, `api/support/ems` und `api/snapmirror`.

### Typische API-Aufrufe

| Zweck                          | Methode | Endpunkt                                              |
|--------------------------------|---------|-------------------------------------------------------|
| Cluster-Info / Gesundheit      | GET     | `/api/cluster`                                        |
| Node-Status / HA-Konfiguration | GET     | `/api/cluster/nodes`                                  |
| Cluster-Peers (Replikation)    | GET     | `/api/cluster/peers`                                  |
| MetroCluster-Status            | GET     | `/api/cluster/metrocluster`                           |
| MetroCluster-Nodes             | GET     | `/api/cluster/metrocluster/nodes`                     |
| MetroCluster DR-Gruppen        | GET     | `/api/cluster/metrocluster/dr-groups`                 |
| Aggregate (Kapazität)          | GET     | `/api/storage/aggregates?fields=space`                |
| Festplatten-Status             | GET     | `/api/storage/disks`                                  |
| EMS-Events (Alerts)            | GET     | `/api/support/ems/events`                             |
| LIF-Status (Netzwerk)          | GET     | `/api/network/ip/interfaces`                          |
| Ethernet-Ports                 | GET     | `/api/network/ethernet/ports`                         |
| SnapMirror-Beziehungen         | GET     | `/api/snapmirror/relationships`                       |
| Controller-Hardware            | GET     | `/api/cluster/nodes?fields=controller.*`              |

### Beispielablauf mit cURL

Ersetzen Sie `<CLUSTER>` durch IP-Adresse oder Hostname Ihres ONTAP-Clusters, `<USER>` durch den API-Benutzernamen und `<PASS>` durch das Passwort.

#### Schritt 1 – Cluster-Info / Systemgesundheit abrufen

```bash
curl -sk https://<CLUSTER>/api/cluster \
  -u "<USER>:<PASS>" \
  -H "Accept: application/json" | python3 -m json.tool
```

Beispiel-Antwort:
```json
{
  "uuid": "abc123...",
  "name": "cluster-prod-01",
  "version": {
    "full": "NetApp Release 9.16.1P11: Thu Jan 15 11:21:38 UTC 2026"
  },
  "health": {
    "is_healthy": true,
    "status": "ok"
  }
}
```

#### Schritt 2 – Cluster-Nodes und HA-Status abrufen

```bash
curl -sk "https://<CLUSTER>/api/cluster/nodes?fields=name,state,health,ha" \
  -u "<USER>:<PASS>" \
  -H "Accept: application/json" | python3 -m json.tool
```

Beispiel-Antwort:
```json
{
  "records": [
    {
      "uuid": "node1-uuid",
      "name": "cluster-01-01",
      "state": "up",
      "health": { "is_healthy": true },
      "ha": {
        "giveback": { "state": "nothing_to_giveback" },
        "takeover": { "state": "not_attempted" }
      }
    }
  ]
}
```

#### Schritt 3 – Aggregate (Kapazität) abrufen

```bash
curl -sk "https://<CLUSTER>/api/storage/aggregates?fields=space" \
  -u "<USER>:<PASS>" \
  -H "Accept: application/json" | python3 -m json.tool
```

Beispiel-Antwort:
```json
{
  "records": [
    {
      "name": "aggr0_node01",
      "space": {
        "block_storage": {
          "size": 107374182400,
          "used": 52428800000,
          "available": 54945382400
        }
      }
    }
  ]
}
```

#### Schritt 4 – EMS-Events (Alerts) abrufen

Die ONTAP-EMS ist ein Ereignislog, keine Statusdatenbank. Das Dashboard rekonstruiert den aktuellen Zustand durch Abgleich von Problem- und Recovery-Events.

```bash
# Aktuelle Problem-Events (emergency, alert, error)
curl -sk "https://<CLUSTER>/api/support/ems/events?message.severity=emergency,alert,error&max_records=100&orderby=time+desc" \
  -u "<USER>:<PASS>" \
  -H "Accept: application/json" | python3 -m json.tool
```

```bash
# Recovery-Events zum Abgleich (um aufgelöste Probleme zu filtern)
curl -sk "https://<CLUSTER>/api/support/ems/events?message.name=hm.alert.cleared,cpeer.available,cf.fsm.monitor.globalStatus.ok&max_records=100" \
  -u "<USER>:<PASS>" \
  -H "Accept: application/json" | python3 -m json.tool
```

#### Schritt 5 – SnapMirror-Beziehungen abrufen

```bash
curl -sk https://<CLUSTER>/api/snapmirror/relationships \
  -u "<USER>:<PASS>" \
  -H "Accept: application/json" | python3 -m json.tool
```

#### Schritt 6 – MetroCluster-Status (falls konfiguriert)

```bash
curl -sk https://<CLUSTER>/api/cluster/metrocluster \
  -u "<USER>:<PASS>" \
  -H "Accept: application/json" | python3 -m json.tool
```

Beispiel-Antwort:
```json
{
  "configuration_state": "configured",
  "mode": "normal",
  "partner_cluster_reachable": true
}
```

#### Schritt 7 – Hardware-Status der Controller (PSU, Lüfter, Temperatur)

```bash
curl -sk "https://<CLUSTER>/api/cluster/nodes?fields=name,controller.*" \
  -u "<USER>:<PASS>" \
  -H "Accept: application/json" | python3 -m json.tool
```

---

## 3. NetApp StorageGRID 11

### Übersicht

| Eigenschaft          | Wert                                                  |
|----------------------|-------------------------------------------------------|
| **API-Typ**          | NetApp StorageGRID Grid Management REST API v4        |
| **Standard-Port**    | `443` (HTTPS)                                         |
| **Basis-URL**        | `https://<ip-oder-hostname>/api/v4`                   |
| **Authentifizierung**| Benutzername/Passwort → Bearer-Token                  |
| **Credential-Typ**   | Benutzername + Passwort (Token wird automatisch erneuert) |

### Authentifizierungsmethode

StorageGRID verwendet eine **Token-basierte Authentifizierung**:

1. Benutzername und Passwort werden via `POST /api/v4/authorize` mit einem JSON-Body übergeben.
2. Die Antwort enthält einen **Bearer-Token** im Feld `data`.
3. Alle weiteren Requests senden diesen Token im Header `Authorization: Bearer <token>`.
4. Bei einem `401 Unauthorized` wird automatisch ein neuer Token angefordert.

> **Token-Lebensdauer:** StorageGRID-Tokens sind zeitlich begrenzt. Das Dashboard erneuert den Token automatisch bei einem `401`-Fehler und speichert den neuen Token in der Datenbank.

### Typische API-Aufrufe

| Zweck                          | Methode | Endpunkt                                                          |
|--------------------------------|---------|-------------------------------------------------------------------|
| Authentifizieren               | POST    | `/api/v4/authorize`                                               |
| Grid-Gesundheit (Alarm-Zähler) | GET     | `/api/v4/grid/health`                                             |
| Grid-Topologie (Konnektivität) | GET     | `/api/v4/grid/health/topology`                                    |
| Purity-Version / OS-Version    | GET     | `/api/v4/grid/config/product-version`                             |
| Node-Status / Standorte        | GET     | `/api/v4/grid/node-health`                                        |
| Aktive Alerts                  | GET     | `/api/v4/grid/alerts?include=active`                              |
| Gesamtkapazität (Bytes)        | GET     | `/api/v4/grid/metric-query?query=storagegrid_storage_utilization_total_space_bytes` |
| Genutzte Kapazität (Bytes)     | GET     | `/api/v4/grid/metric-query?query=storagegrid_storage_utilization_data_bytes` |

### Beispielablauf mit cURL

Ersetzen Sie `<GRID>` durch IP-Adresse oder Hostname des Grid-Management-Knotens, `<USER>` und `<PASS>` durch die konfigurierten Zugangsdaten.

#### Schritt 1 – Authentifizieren (Bearer-Token holen)

```bash
TOKEN=$(curl -sk -X POST https://<GRID>/api/v4/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "username": "<USER>",
    "password": "<PASS>",
    "cookie": true,
    "csrfToken": false
  }' | python3 -c "import sys, json; print(json.load(sys.stdin)['data'])")

echo "Bearer-Token: $TOKEN"
```

Beispiel-Antwort der `/api/v4/authorize`-Anfrage:
```json
{
  "status": "success",
  "apiVersion": "4.0",
  "data": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

> Der Token ist ein JWT-String im Feld `data`.

#### Schritt 2 – Grid-Gesundheit abrufen

```bash
curl -sk https://<GRID>/api/v4/grid/health \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

Beispiel-Antwort:
```json
{
  "status": "success",
  "data": {
    "alarms": { "critical": 0, "major": 0, "minor": 0 },
    "alerts": { "critical": 0, "major": 1, "minor": 2 },
    "nodes": { "connected": 12, "unknown": 0 }
  }
}
```

#### Schritt 3 – Grid-Topologie (Konnektivitätsprüfung)

```bash
curl -sk https://<GRID>/api/v4/grid/health/topology \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

#### Schritt 4 – StorageGRID-Version abrufen

```bash
curl -sk https://<GRID>/api/v4/grid/config/product-version \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

Beispiel-Antwort:
```json
{
  "status": "success",
  "data": {
    "productVersion": "11.8.0.3"
  }
}
```

#### Schritt 5 – Node-Status abrufen

```bash
curl -sk https://<GRID>/api/v4/grid/node-health \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

Beispiel-Antwort:
```json
{
  "status": "success",
  "data": [
    {
      "id": "node-uuid-1",
      "name": "dc1-adm1",
      "type": "adminNode",
      "state": "connected",
      "severity": "normal",
      "siteId": "site-uuid-1",
      "siteName": "Rechenzentrum 1"
    }
  ]
}
```

#### Schritt 6 – Aktive Alerts abrufen

```bash
curl -sk "https://<GRID>/api/v4/grid/alerts?include=active" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

Beispiel-Antwort:
```json
{
  "status": "success",
  "data": [
    {
      "id": "alert-uuid-1",
      "name": "LowFreeSpace",
      "state": "active",
      "labels": {
        "severity": "warning",
        "node": "dc1-sn1"
      },
      "annotations": {
        "description": "The amount of free space on the storage volume is getting low."
      },
      "startTime": "2024-01-15T10:30:00.000Z"
    }
  ]
}
```

#### Schritt 7 – Kapazität über Prometheus-Metriken abrufen

```bash
# Gesamtkapazität
curl -sk "https://<GRID>/api/v4/grid/metric-query?query=storagegrid_storage_utilization_total_space_bytes" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool

# Genutzte Kapazität
curl -sk "https://<GRID>/api/v4/grid/metric-query?query=storagegrid_storage_utilization_data_bytes" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

Beispiel-Antwort:
```json
{
  "status": "success",
  "data": {
    "resultType": "vector",
    "result": [
      {
        "metric": {},
        "value": [1705316400, "107374182400"]
      }
    ]
  }
}
```

> Der zweite Wert im `value`-Array enthält den Kapazitätswert in Bytes als String.

---

## 4. Dell DataDomain

### Übersicht

| Eigenschaft          | Wert                                                  |
|----------------------|-------------------------------------------------------|
| **API-Typ**          | Dell DataDomain REST API v1.0 / v2.0                  |
| **Standard-Port**    | **`3009`** (DataDomain-spezifischer Management-Port)  |
| **Basis-URL**        | `https://<ip-oder-hostname>:3009`                     |
| **Authentifizierung**| Benutzername/Passwort → Session-Token (X-DD-AUTH-TOKEN) |
| **Credential-Typ**   | Benutzername + Passwort                               |

> **Wichtig:** Dell DataDomain verwendet Port **3009** (nicht 443). Dies ist der Standard-REST-API-Port des DataDomain-Management-Interfaces.

### Authentifizierungsmethode

DataDomain verwendet **Session-Token-Authentifizierung**:

1. Benutzername und Passwort werden via `POST /rest/v1.0/auth` mit einem JSON-Body übergeben.
2. Die Antwort liefert **HTTP-Statuscode `201 Created`** und enthält den Session-Token im Response-Header **`X-DD-AUTH-TOKEN`** (nicht im Body).
3. Alle weiteren Requests senden diesen Token im Header `X-DD-AUTH-TOKEN`.
4. Bei einem `401 Unauthorized` wird automatisch ein neuer Token angefordert.

> **API-Versionen:** DataDomain verwendet mehrere parallele API-Versionspfade: `/rest/v1.0/` und `/rest/v2.0/` für die meisten Endpunkte sowie `/api/v1/` und `/api/v2.0/` für einige spezifische Endpunkte (z.B. HA, Disks).

### Typische API-Aufrufe

| Zweck                          | Methode | Endpunkt                                          |
|--------------------------------|---------|---------------------------------------------------|
| Authentifizieren               | POST    | `/rest/v1.0/auth`                                 |
| System-Info / Version          | GET     | `/rest/v1.0/system`                               |
| HA-Status (primärer Pfad)      | GET     | `/api/v1/dd-systems/0/ha`                         |
| HA-Status (Fallback-Pfad)      | GET     | `/rest/v1.0/dd-systems/0/ha`                      |
| Aktive Alerts                  | GET     | `/rest/v1.0/dd-systems/0/alerts`                  |
| Netzwerk-NICs (v2.0)           | GET     | `/rest/v2.0/dd-systems/0/networks/nics`           |
| Einzelne NIC                   | GET     | `/rest/v2.0/dd-systems/0/networks/nics/<name>`    |
| Hardware-Status                | GET     | `/rest/v1.0/dd-systems/0/hardware`                |
| Disk-Status                    | GET     | `/api/v1/dd-systems/0/storage/disks`              |
| Replikations-Contexts          | GET     | `/rest/v1.0/dd-systems/0/replication/contexts`    |
| Service-Status                 | GET     | `/rest/v1.0/dd-systems/0/services`                |

### Beispielablauf mit cURL

Ersetzen Sie `<DD>` durch IP-Adresse oder Hostname Ihres DataDomain-Systems, `<USER>` und `<PASS>` durch die konfigurierten Zugangsdaten.

> **Hinweis:** Port **3009** muss in allen URLs angegeben werden.

#### Schritt 1 – Authentifizieren (Session-Token holen)

```bash
DD_TOKEN=$(curl -sk -X POST https://<DD>:3009/rest/v1.0/auth \
  -H "Content-Type: application/json" \
  -d '{
    "username": "<USER>",
    "password": "<PASS>"
  }' \
  -D - 2>&1 | grep -i "X-DD-AUTH-TOKEN" | awk '{print $2}' | tr -d '\r')

echo "Session-Token: $DD_TOKEN"
```

> **Wichtig:** Der Token befindet sich im **Response-Header** `X-DD-AUTH-TOKEN`, **nicht** im Response-Body. Der HTTP-Statuscode bei Erfolg ist **`201 Created`**.

Alle Response-Header sehen (zum Debuggen):
```bash
curl -sk -X POST https://<DD>:3009/rest/v1.0/auth \
  -H "Content-Type: application/json" \
  -d '{"username": "<USER>", "password": "<PASS>"}' \
  -D /dev/stderr -o /dev/null
```

#### Schritt 2 – System-Info abrufen (Name, Version, Kapazität)

```bash
curl -sk https://<DD>:3009/rest/v1.0/system \
  -H "X-DD-AUTH-TOKEN: $DD_TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

Beispiel-Antwort:
```json
{
  "name": "datadomain-prod-01",
  "model": "DD9800",
  "version": "7.13.0.20",
  "type": "HA",
  "capacity": {
    "total": 107374182400,
    "used": 52428800000,
    "available": 54945382400,
    "compression": 4.2
  }
}
```

#### Schritt 3 – HA-Status abrufen

```bash
# Primärer API-Pfad (v1)
curl -sk https://<DD>:3009/api/v1/dd-systems/0/ha \
  -H "X-DD-AUTH-TOKEN: $DD_TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool

# Falls oben fehlschlägt: Fallback auf REST v1.0
curl -sk https://<DD>:3009/rest/v1.0/dd-systems/0/ha \
  -H "X-DD-AUTH-TOKEN: $DD_TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

Beispiel-Antwort:
```json
{
  "haInfo": {
    "state": "normal",
    "role": "primary",
    "mode": "active_standby",
    "nodeName": "datadomain-prod-01",
    "peerInfo": {
      "nodeName": "datadomain-prod-02",
      "ip": "10.0.0.12",
      "state": "online"
    }
  }
}
```

#### Schritt 4 – Aktive Alerts abrufen

```bash
curl -sk https://<DD>:3009/rest/v1.0/dd-systems/0/alerts \
  -H "X-DD-AUTH-TOKEN: $DD_TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

Beispiel-Antwort:
```json
{
  "alert_list": [
    {
      "alert_id": "42",
      "severity": "critical",
      "class": "hardware",
      "msg": "Power supply PSU-1 has failed",
      "status": "active",
      "alert_gen_epoch": 1705316400,
      "description": "Replace power supply unit PSU-1 immediately"
    }
  ]
}
```

#### Schritt 5 – Netzwerk-NICs abrufen (v2.0 API)

```bash
# Alle NICs
curl -sk https://<DD>:3009/rest/v2.0/dd-systems/0/networks/nics \
  -H "X-DD-AUTH-TOKEN: $DD_TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool

# Einzelne Management-NIC (z.B. ethMa)
curl -sk https://<DD>:3009/rest/v2.0/dd-systems/0/networks/nics/ethMa \
  -H "X-DD-AUTH-TOKEN: $DD_TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

#### Schritt 6 – Hardware-Status abrufen

```bash
curl -sk https://<DD>:3009/rest/v1.0/dd-systems/0/hardware \
  -H "X-DD-AUTH-TOKEN: $DD_TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

#### Schritt 7 – Disk-Status abrufen

```bash
curl -sk https://<DD>:3009/api/v1/dd-systems/0/storage/disks \
  -H "X-DD-AUTH-TOKEN: $DD_TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

#### Schritt 8 – Replikations-Contexts abrufen

```bash
curl -sk https://<DD>:3009/rest/v1.0/dd-systems/0/replication/contexts \
  -H "X-DD-AUTH-TOKEN: $DD_TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool
```

---

## 5. Gemeinsamkeiten & Konventionen

### SSL/TLS-Zertifikatsverifizierung

Das Storage Dashboard unterstützt eigene CA-/Root-Zertifikate für interne Storage-Systeme (Upload im Admin-Bereich). In den cURL-Beispielen oben wird `-sk` (skip SSL-Verifikation) verwendet, um das Testen zu vereinfachen.

**In der Produktion sollten Sie SSL-Zertifikate immer verifizieren:**

```bash
# Mit eigenem CA-Zertifikat verifizieren
curl --cacert /etc/ssl/certs/storage-ca.crt https://<SYSTEM>/api/...

# Mit Systemzertifikaten verifizieren (ohne -k)
curl -s https://<SYSTEM>/api/...
```

### Proxy-Konfiguration

Das Dashboard umgeht bewusst HTTP/HTTPS-Proxy-Einstellungen für lokale Storage-Systeme. Wenn Sie cURL direkt über einen Proxy nutzen möchten:

```bash
# Proxy explizit deaktivieren für lokale Systeme
curl --noproxy '*' https://<SYSTEM>/api/...
```

### Authentifizierungsvergleich

| System             | Token-Typ          | Header-Name            | Erneuerung   |
|--------------------|--------------------|------------------------|--------------|
| Pure Storage       | Session-Token      | `x-auth-token`         | Login/Logout per Abfragezyklus |
| NetApp ONTAP       | Basic Auth         | `Authorization: Basic` | Nicht nötig  |
| NetApp StorageGRID | Bearer JWT-Token   | `Authorization: Bearer`| Bei 401 automatisch |
| Dell DataDomain    | Session-Token      | `X-DD-AUTH-TOKEN`      | Bei 401 automatisch |

### Fehlerbehandlung

Alle Clients implementieren **Fehlertoleranz** – ein Fehler bei einem einzelnen API-Endpunkt blockiert nicht die anderen Abfragen. Bei `401 Unauthorized`-Antworten wird automatisch eine erneute Authentifizierung versucht (außer bei ONTAP Basic Auth, das zustandslos ist).

### Verschlüsselung der Zugangsdaten

Im Storage Dashboard werden alle Zugangsdaten (Benutzername, Passwort, API-Token) **verschlüsselt** in der Datenbank gespeichert und erst zur Laufzeit entschlüsselt. Zugangsdaten werden niemals im Klartext protokolliert.

---

*Dokumentation generiert aus dem Quellcode: `app/api/storage_clients.py`, `app/constants.py`*
