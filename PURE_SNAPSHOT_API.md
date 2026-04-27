# Pure Storage FlashArray – Snapshot API (cURL-Referenz)

Diese Datei dokumentiert alle notwendigen REST-API-Aufrufe, um Snapshots von einem Pure Storage FlashArray abzurufen und zu verwalten. Alle Beispiele verwenden `curl`.

---

## Inhaltsverzeichnis

1. [Authentifizierung & Session-Token](#1-authentifizierung--session-token)
2. [API-Version erkennen](#2-api-version-erkennen)
3. [Snapshots auflisten](#3-snapshots-auflisten)
4. [Snapshots filtern](#4-snapshots-filtern)
5. [Snapshot-Details abrufen](#5-snapshot-details-abrufen)
6. [Pagination (große Arrays)](#6-pagination-große-arrays)
7. [Snapshot umbenennen (TTL ändern)](#7-snapshot-umbenennen-ttl-ändern)
8. [Snapshot als gelöscht markieren (Destroy)](#8-snapshot-als-gelöscht-markieren-destroy)
9. [Snapshot endgültig löschen (Eradicate)](#9-snapshot-endgültig-löschen-eradicate)
10. [Session beenden (Logout)](#10-session-beenden-logout)
11. [Vollständiges Shell-Skript](#11-vollständiges-shell-skript)
12. [Wie das Dashboard Snapshots abruft](#12-wie-das-dashboard-snapshots-abruft)

---

## Variablen

Alle Beispiele verwenden die folgenden Shell-Variablen. Ersetzen Sie diese durch Ihre tatsächlichen Werte:

```bash
ARRAY="<IP-Adresse oder Hostname des FlashArray>"  # z. B. "10.0.0.10" oder "flasharray.example.com"
API_TOKEN="<Ihr API-Token>"                         # z. B. "T-a1b2c3d4-..."
VERSION="2.26"                                      # API-Version (siehe Schritt 2)
```

---

## 1. Authentifizierung & Session-Token

Die FlashArray REST API v2.x verwendet ein **zweistufiges Authentifizierungsverfahren**:

| Stufe | Beschreibung |
|-------|--------------|
| **API-Token** | Dauerhafter Token, der im System konfiguriert ist (im Dashboard unter „API-Token" gespeichert) |
| **Session-Token** | Kurzlebiger Token, der per Login-Endpunkt erzeugt wird und für alle API-Aufrufe verwendet wird |

### Schritt 1a – Session-Token holen und in Variable speichern

```bash
SESSION_TOKEN=$(curl -sk -X POST "https://${ARRAY}/api/${VERSION}/login" \
  -H "api-token: ${API_TOKEN}" \
  -H "Content-Type: application/json" \
  -D - -o /dev/null 2>&1 \
  | grep -i "x-auth-token" \
  | awk '{print $2}' \
  | tr -d '\r\n')

echo "Session-Token: ${SESSION_TOKEN}"
```

> **Hinweis:** Der `x-auth-token` befindet sich im **Response-Header**, nicht im Response-Body. Das Flag `-D -` gibt die Header aus, `-o /dev/null` unterdrückt den Body.

### Schritt 1b – Alternativ: Header direkt anzeigen (Diagnose)

```bash
curl -sk -X POST "https://${ARRAY}/api/${VERSION}/login" \
  -H "api-token: ${API_TOKEN}" \
  -H "Content-Type: application/json" \
  -D /dev/stderr -o /dev/null
```

Beispiel-Response-Header (relevant):
```
HTTP/2 200
x-auth-token: T-abc123xyz...
content-type: application/json
```

### Fehlercodes bei der Authentifizierung

| HTTP-Status | Bedeutung | Lösung |
|-------------|-----------|--------|
| `200 OK` | Erfolgreich | `x-auth-token` aus Header extrahieren |
| `400 Bad Request` | Ungültiges Token-Format | API-Token-Format prüfen |
| `401 Unauthorized` | Ungültiger oder abgelaufener API-Token | API-Token erneuern |
| `403 Forbidden` | Token hat keine Login-Berechtigung | Token-Berechtigungen prüfen |

---

## 2. API-Version erkennen

Das Dashboard erkennt die unterstützte API-Version automatisch. Für manuelle Tests:

```bash
curl -sk "https://${ARRAY}/api/api_version" | python3 -m json.tool
```

Beispiel-Antwort:
```json
{
  "version": ["2.4", "2.5", "2.10", "2.26"]
}
```

Verwenden Sie für alle weiteren Aufrufe die **höchste** verfügbare Version (hier: `2.26`).

```bash
VERSION=$(curl -sk "https://${ARRAY}/api/api_version" \
  | python3 -c "import sys,json; v=json.load(sys.stdin)['version']; print(v[-1])")
echo "Verwendete API-Version: ${VERSION}"
```

---

## 3. Snapshots auflisten

Der zentrale Endpunkt für Snapshot-Abfragen lautet `GET /api/<version>/volume-snapshots`.

### Alle aktiven (nicht gelöschten) Snapshots

```bash
curl -sk "https://${ARRAY}/api/${VERSION}/volume-snapshots?destroyed=false&limit=100" \
  -H "x-auth-token: ${SESSION_TOKEN}" \
  -H "Accept: application/json" \
  | python3 -m json.tool
```

### Beispiel-Antwort

```json
{
  "items": [
    {
      "id": "abc123...",
      "name": "ABP_data.HDBSNAP-2026-03-18-024722",
      "suffix": "HDBSNAP-2026-03-18-024722",
      "created": 1742258842000,
      "source": {
        "id": "vol-id-...",
        "name": "ABP_data"
      },
      "destroyed": false,
      "space": {
        "snapshots": 2147483648
      }
    },
    {
      "id": "def456...",
      "name": "vgAQP_1.2026-03-19-123749",
      "suffix": "2026-03-19-123749",
      "created": 1742383069000,
      "source": {
        "id": "vol-id-...",
        "name": "vgAQP_1"
      },
      "destroyed": false
    }
  ],
  "total_item_count": 142
}
```

### Bedeutung der Felder

| Feld | Typ | Beschreibung |
|------|-----|--------------|
| `name` | String | Vollständiger Snapshot-Name (`<volume>.<suffix>`) |
| `suffix` | String | Nur der Suffix-Teil (primäre Quelle für TTL-Extraktion) |
| `created` | Int64 | Erstellungszeitpunkt als Millisekunden seit Unix-Epoch |
| `source.name` | String | Name des Quell-Volumes (Fallback für SID-Extraktion) |
| `destroyed` | Boolean | `false` = aktiv, `true` = als gelöscht markiert |
| `id` | String | Eindeutige Snapshot-ID (für PATCH/DELETE-Operationen benötigt) |

> **Zeitstempel:** Das Dashboard konvertiert `created` (Epoch-ms) in einen ISO-8601-UTC-String, z. B. `"2026-03-18T02:47:22Z"`.

---

## 4. Snapshots filtern

### Nach Namen filtern (HDBSNAP-Snapshots)

```bash
curl -sk "https://${ARRAY}/api/${VERSION}/volume-snapshots?destroyed=false&filter=contains(name%2C%27HDBSNAP%27)" \
  -H "x-auth-token: ${SESSION_TOKEN}" \
  -H "Accept: application/json" \
  | python3 -m json.tool
```

> Der Filter verwendet die Pure Storage Filter-Syntax. URL-kodiert: `contains(name,'HDBSNAP')` → `contains(name%2C%27HDBSNAP%27)`

### Nach Quell-Volume filtern

```bash
# Snapshots eines bestimmten Volumes (z. B. ABP_data)
curl -sk "https://${ARRAY}/api/${VERSION}/volume-snapshots?destroyed=false&filter=source.name%3D%27ABP_data%27" \
  -H "x-auth-token: ${SESSION_TOKEN}" \
  -H "Accept: application/json" \
  | python3 -m json.tool
```

URL-dekodiert entspricht der Filter: `source.name='ABP_data'`

### Nur gelöschte Snapshots anzeigen

```bash
curl -sk "https://${ARRAY}/api/${VERSION}/volume-snapshots?destroyed=true" \
  -H "x-auth-token: ${SESSION_TOKEN}" \
  -H "Accept: application/json" \
  | python3 -m json.tool
```

---

## 5. Snapshot-Details abrufen

### Einzelnen Snapshot per Name abrufen

```bash
SNAP_NAME="ABP_data.HDBSNAP-2026-03-18-024722"
curl -sk "https://${ARRAY}/api/${VERSION}/volume-snapshots?names=${SNAP_NAME}" \
  -H "x-auth-token: ${SESSION_TOKEN}" \
  -H "Accept: application/json" \
  | python3 -m json.tool
```

### Einzelnen Snapshot per ID abrufen

```bash
SNAP_ID="abc123..."
curl -sk "https://${ARRAY}/api/${VERSION}/volume-snapshots?ids=${SNAP_ID}" \
  -H "x-auth-token: ${SESSION_TOKEN}" \
  -H "Accept: application/json" \
  | python3 -m json.tool
```

---

## 6. Pagination (große Arrays)

Bei Arrays mit mehr als 1000 Snapshots wird die Antwort paginiert. Das Dashboard verwendet `continuation_token` für automatisches Blättern.

### Erste Seite (1000 Einträge)

```bash
curl -sk "https://${ARRAY}/api/${VERSION}/volume-snapshots?destroyed=false&limit=1000" \
  -H "x-auth-token: ${SESSION_TOKEN}" \
  -H "Accept: application/json" \
  > /tmp/page1.json

cat /tmp/page1.json | python3 -c "
import sys, json
data = json.load(sys.stdin)
print('Anzahl Items:', len(data.get('items', [])))
print('continuation_token:', data.get('continuation_token', 'keiner (letzte Seite)'))
"
```

### Folgeseiten abrufen

```bash
CONTINUATION_TOKEN="<token aus vorheriger Antwort>"

curl -sk "https://${ARRAY}/api/${VERSION}/volume-snapshots?continuation_token=${CONTINUATION_TOKEN}" \
  -H "x-auth-token: ${SESSION_TOKEN}" \
  -H "Accept: application/json" \
  | python3 -m json.tool
```

### Vollständige paginierte Abfrage (Shell-Schleife)

```bash
ALL_SNAPS=()
PARAMS="destroyed=false&limit=1000"

while true; do
  RESPONSE=$(curl -sk "https://${ARRAY}/api/${VERSION}/volume-snapshots?${PARAMS}" \
    -H "x-auth-token: ${SESSION_TOKEN}" \
    -H "Accept: application/json")

  COUNT=$(echo "${RESPONSE}" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('items',[])))")
  echo "Seite: ${COUNT} Snapshots abgerufen"

  TOKEN=$(echo "${RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('continuation_token',''))")
  if [ -z "${TOKEN}" ]; then
    echo "Letzte Seite erreicht."
    break
  fi
  PARAMS="continuation_token=${TOKEN}"
done
```

---

## 7. Snapshot umbenennen (TTL ändern)

Das Dashboard verwendet diesen Endpunkt, um den TTL-Zeitstempel im Snapshot-Namen zu aktualisieren (PATCH-Request auf `/api/<version>/volume-snapshots`).

```bash
OLD_SNAP_NAME="ABP_data.HDBSNAP-2026-03-18-024722"
NEW_SNAP_NAME="ABP_data.HDBSNAP-2026-04-01-000000"

curl -sk -X PATCH "https://${ARRAY}/api/${VERSION}/volume-snapshots?names=${OLD_SNAP_NAME}" \
  -H "x-auth-token: ${SESSION_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d "{\"name\": \"${NEW_SNAP_NAME}\"}" \
  | python3 -m json.tool
```

> **Hinweis:** Der neue Name muss den gleichen Volume-Prefix und gültiges Datum-Format (`YYYY-MM-DD-HHMMSS`) enthalten. Das Datum im Namen entspricht dem TTL (Ablaufdatum) des Snapshots.

Beispiel-Antwort (Erfolg):
```json
{
  "items": [
    {
      "id": "abc123...",
      "name": "ABP_data.HDBSNAP-2026-04-01-000000",
      "suffix": "HDBSNAP-2026-04-01-000000"
    }
  ]
}
```

---

## 8. Snapshot als gelöscht markieren (Destroy)

Ein Snapshot wird zunächst nur als `destroyed=true` markiert (Soft-Delete). Er kann innerhalb der Eradication-Periode noch wiederhergestellt werden.

```bash
SNAP_NAME="ABP_data.HDBSNAP-2026-03-18-024722"

curl -sk -X PATCH "https://${ARRAY}/api/${VERSION}/volume-snapshots?names=${SNAP_NAME}" \
  -H "x-auth-token: ${SESSION_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"destroyed": true}' \
  | python3 -m json.tool
```

### Gelöschten Snapshot wiederherstellen (Undo Destroy)

```bash
curl -sk -X PATCH "https://${ARRAY}/api/${VERSION}/volume-snapshots?names=${SNAP_NAME}" \
  -H "x-auth-token: ${SESSION_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"destroyed": false}' \
  | python3 -m json.tool
```

---

## 9. Snapshot endgültig löschen (Eradicate)

Ein als `destroyed=true` markierter Snapshot wird mit DELETE **unwiderruflich** gelöscht. Dies ist erst möglich, nachdem der Snapshot als destroyed markiert wurde.

```bash
SNAP_NAME="ABP_data.HDBSNAP-2026-03-18-024722"

curl -sk -X DELETE "https://${ARRAY}/api/${VERSION}/volume-snapshots?names=${SNAP_NAME}" \
  -H "x-auth-token: ${SESSION_TOKEN}" \
  -H "Accept: application/json"
```

> **Warnung:** Diese Operation ist **nicht rückgängig zu machen**. Der Snapshot wird sofort und dauerhaft gelöscht.

Bei Erfolg antwortet die API mit HTTP `200` und leerem Body oder `{}`.

> **Hinweis (Dashboard-Verhalten):** Das Dashboard führt diesen Schritt **nicht** aus.
> Das FlashArray eradiziert destroyed-Snapshots automatisch nach Ablauf der konfigurierten
> Eradication-Delay (Default 24 Stunden). Der Dashboard-Workflow für das Löschen eines
> Pure-Snapshots besteht daher ausschließlich aus *Destroy* (`destroyed=true`); ein
> vorgelagerter Rename / eine Anpassung des Expiration-Dates ist auf dem FlashArray
> nicht erforderlich (zwingend nur auf ONTAP, dort über `expiry_time`).

---

## 10. Session beenden (Logout)

Nach dem Abschluss aller Abfragen sollte die Session explizit beendet werden, um offene Sessions auf dem Array zu minimieren.

```bash
curl -sk -X POST "https://${ARRAY}/api/${VERSION}/logout" \
  -H "x-auth-token: ${SESSION_TOKEN}" \
  -H "Content-Type: application/json"
```

---

## 11. Vollständiges Shell-Skript

Das folgende Skript führt den vollständigen Ablauf durch: API-Version erkennen, einloggen, alle aktiven Snapshots abrufen, und ausloggen.

```bash
#!/bin/bash
# Pure Storage FlashArray – Snapshots abrufen
# Verwendung: ./get_pure_snapshots.sh <ARRAY-IP> <API-TOKEN>

set -euo pipefail

ARRAY="${1:?Bitte Array-IP oder Hostname angeben}"
API_TOKEN="${2:?Bitte API-Token angeben}"

echo "=== Pure Storage FlashArray Snapshot-Abfrage ==="
echo "Array: ${ARRAY}"

# 1. API-Version erkennen
echo ""
echo "--- Schritt 1: API-Version erkennen ---"
VERSION=$(curl -sk "https://${ARRAY}/api/api_version" \
  | python3 -c "import sys,json; v=json.load(sys.stdin)['version']; print(v[-1])")
echo "Verwende API-Version: ${VERSION}"

# 2. Authentifizieren und Session-Token holen
echo ""
echo "--- Schritt 2: Authentifizieren ---"
SESSION_TOKEN=$(curl -sk -X POST "https://${ARRAY}/api/${VERSION}/login" \
  -H "api-token: ${API_TOKEN}" \
  -H "Content-Type: application/json" \
  -D - -o /dev/null 2>&1 \
  | grep -i "x-auth-token" \
  | awk '{print $2}' \
  | tr -d '\r\n')

if [ -z "${SESSION_TOKEN}" ]; then
  echo "FEHLER: Authentifizierung fehlgeschlagen. Bitte API-Token prüfen."
  exit 1
fi
echo "Session-Token erhalten: ${SESSION_TOKEN:0:20}..."

# 3. Snapshots abrufen (erste Seite, bis 1000 Einträge)
echo ""
echo "--- Schritt 3: Aktive Snapshots abrufen ---"
RESPONSE=$(curl -sk "https://${ARRAY}/api/${VERSION}/volume-snapshots?destroyed=false&limit=1000" \
  -H "x-auth-token: ${SESSION_TOKEN}" \
  -H "Accept: application/json")

SNAP_COUNT=$(echo "${RESPONSE}" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('items',[])))")
echo "Abgerufene Snapshots: ${SNAP_COUNT}"

# Ausgabe der Snapshot-Namen
echo ""
echo "--- Snapshot-Liste ---"
echo "${RESPONSE}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('items', []):
    created_ms = item.get('created', 0)
    from datetime import datetime, timezone
    created_str = datetime.fromtimestamp(created_ms / 1000.0, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC') if created_ms else 'unbekannt'
    print(f\"  {item['name']}  (erstellt: {created_str})\")
"

# 4. Ausloggen
echo ""
echo "--- Schritt 4: Ausloggen ---"
curl -sk -X POST "https://${ARRAY}/api/${VERSION}/logout" \
  -H "x-auth-token: ${SESSION_TOKEN}" \
  -H "Content-Type: application/json" \
  > /dev/null
echo "Session beendet."
echo ""
echo "=== Fertig ==="
```

---

## 12. Wie das Dashboard Snapshots abruft

Das Storage Dashboard ruft Pure Snapshots im Hintergrund alle 15 Minuten automatisch ab. Hier ist der interne Ablauf mit den verwendeten API-Calls:

### Ablauf im Dashboard

```
1. GET  https://<ARRAY>/api/api_version
   → Automatische Erkennung der API-Version (z. B. 2.26)

2. POST https://<ARRAY>/api/<version>/login
   Header: api-token: <gespeicherter-API-Token>
   → x-auth-token Session-Token aus Response-Header

3. GET  https://<ARRAY>/api/<version>/volume-snapshots?destroyed=false&limit=1000
   Header: x-auth-token: <session-token>
   → Liste aller aktiven Snapshots (paginiert mit continuation_token)
   → Wiederholt bis kein continuation_token mehr vorhanden

4. POST https://<ARRAY>/api/<version>/logout
   Header: x-auth-token: <session-token>
   → Session beenden
```

### Snapshot-Verarbeitungslogik im Dashboard

Das Dashboard filtert und verarbeitet die Snapshots folgendermaßen:

| Schritt | Logik |
|---------|-------|
| **Filter** | Akzeptiert Snapshots, die `HDBSNAP` im Namen/Suffix enthalten ODER die mit einer 3–5-stelligen SID beginnen (z. B. `ACP_`, `vgAQP_`) |
| **SID-Extraktion** | Aus dem Snapshot-Namen (z. B. `ACP_data.HDBSNAP-…` → SID `ACP`) oder als Fallback aus `source.name` |
| **TTL-Extraktion** | Aus dem `suffix`-Feld (z. B. `HDBSNAP-2026-03-18-024722` → TTL `2026-03-18 02:47:22`) |
| **Zeitstempel** | `created`-Feld (Epoch-Millisekunden) wird in ISO-8601 UTC konvertiert |
| **Deduplizierung** | ActiveCluster-Arrays melden denselben Snapshot zweifach → werden nach (SID, Name, TTL) dedupliziert |
| **Gruppierung** | Mehrere LUN-Snapshots derselben DB (gleiches SID + gleiches Erstellungsminute) werden zu einem logischen Datensatz zusammengefasst |

### Snapshot-Namenskonventionen

Das Dashboard erkennt die folgenden Namensschemata:

| Snapshot-Name | SID | TTL |
|---------------|-----|-----|
| `ACP_1_data.HDBSNAP-2026-03-18-024722` | `ACP` | `2026-03-18 02:47:22` |
| `vgAQP_1.2026-03-19-123749` | `AQP` | `2026-03-19 12:37:49` |
| `HANA_ABP_data.HDBSNAP-2026-03-13-073434` | `ABP` | `2026-03-13 07:34:34` |
| `ORA_WQ4_archivelog.HDBSNAP-2026-03-16-110000` | `WQ4` | `2026-03-16 11:00:00` |

### Konfiguration im Dashboard

| Einstellung | Beschreibung |
|-------------|--------------|
| `snaps_enabled` | Pro System konfigurierbar (Admin → System bearbeiten). Muss `True` sein, damit Snapshots abgerufen werden. |
| `SNAP_COLLECT_INTERVAL_SECONDS` | Umgebungsvariable, Standard: `900` (15 Minuten) |
| API-Token | Wird verschlüsselt in der Datenbank gespeichert (Feld `api_token` bei System-Typ `pure`) |

> **Hinweis:** Das Dashboard ruft Snapshots nur von Systemen ab, bei denen `enabled=True` **und** `snaps_enabled=True` (oder `snaps_enabled IS NULL` für migrierte Altdaten) gesetzt ist.

---

## Weiterführende Dokumentation

- `API_DOCUMENTATION.md` – Vollständige REST-API-Dokumentation des Dashboards (inkl. `/snaps/api/list`, TTL-Update, Löschverwaltung)
- `api/pure_swagger.json` – Vollständige OpenAPI/Swagger-Spezifikation der Pure Storage FlashArray REST API v2.26
- Pure Storage Dokumentation: [Pure Storage REST API Guide](https://support.purestorage.com/)
