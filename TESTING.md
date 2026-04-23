# Test-Strategie – Storage Dashboard

Dieses Dokument beschreibt die **automatisierte Test-Suite**, kritische **User-Flows**, die Ausführung **lokal** und in **CI**, sowie die Abdeckungsziele.

---

## 1. Feature-Übersicht (was die App tut)

| Bereich | Kurzbeschreibung |
|--------|------------------|
| **Dashboard** | Übersicht aller Systeme (async), Status-Badges, Filter, Auto-Refresh |
| **Öffentliche API** | `/api/systems`, `/api/status`, `/api/cached-status`, `/api/alerts`, Trigger-Refresh |
| **Alerts-Seite** | Aggregation aus `StatusCache`, inkl. synthetischem „System nicht erreichbar“ |
| **Kapazität** | Tabs, `/capacity/api/data`, Historie, Export/Import (teilweise login-geschützt) |
| **Snapshots** | UI + `/snaps/api/*`, Collector-Service |
| **DR Planner** | `/dr/`, Build-Pipeline, JSON-APIs |
| **Admin** | Login, Systeme, Tags, Zertifikate, Logs, Einstellungen, Backup/Import |
| **Hintergrund** | Status-, Kapazitäts-, SoD-, DR-, Snapshot-Threads |
| **Sicherheit** | Flask-Login (Admin), verschlüsselte Secrets, optionales SSL |

---

## 2. Kritische User-Flows (manuell & automatisiert abgedeckt)

1. **Anonym**: Dashboard und öffentliche Seiten (Kapazität, Snaps, DR, Alerts) laden; `/api/systems`, `/api/cached-status`, `/api/alerts` liefern konsistente JSON-Strukturen.
2. **Admin-Login**: Anmeldung → `/admin/`, Einstellungen erreichbar.
3. **System + Status-Cache**: Gespeichertes System und `StatusCache` → Alerts-JSON und Cached-Status zeigen erwartete Daten.
4. **Vendor-Clients** (Unit-Ebene): ONTAP/Pure/EMS/REST-Alerts (bestehende große Testsuite).
5. **Querschnitt**: Migrationen, Backup/Restore, Snap-Service, DR-Discovery, Kapazität, Pure1-Client (bestehende Module-Tests).

---

## 3. Test-Arten und Marker

| Marker | Verzeichnis / Nutzung |
|--------|------------------------|
| `@pytest.mark.unit` | `tests/unit/` – schnelle isolierte Logik (z. B. `parallel_system_status`, `crypto_utils`) |
| `@pytest.mark.integration` | `tests/integration/` – Flask-`test_client`, DB, keine echten Storage-APIs |
| `@pytest.mark.e2e` | `tests/e2e/` – mehrstufige Flows über denselben Client (Session wie im Browser) |

Weitere Tests liegen weiterhin direkt unter `tests/` (Vendor-Logik, Migrationen, …) und sind **standardmäßig immer aktiv**.

Konfiguration: `pytest.ini` (`testpaths`, `strict-markers`).

---

## 4. Lokale Ausführung (CLI)

```bash
# Empfohlen: Dev-Abhängigkeiten inkl. pytest-cov
pip install -r requirements.txt -r requirements-dev.txt

# Gesamte Suite (alle Tests)
python3 -m pytest tests/ -v --tb=short

# Nur schnelle Unit-Tests
python3 -m pytest tests/unit -m unit -v

# Nur Integration
python3 -m pytest tests/integration -m integration -v

# Nur E2E-Flows
python3 -m pytest tests/e2e -m e2e -v

# Mit Coverage-Report (HTML unter ./htmlcov)
python3 -m pytest tests/ --cov=app --cov-config=.coveragerc --cov-report=term-missing --cov-report=html

# Wrapper-Skript (optional Dependencies installieren)
chmod +x scripts/run_tests.sh
./scripts/run_tests.sh --install
COV=1 ./scripts/run_tests.sh
```

Umgebungsvariablen (optional):

| Variable | Bedeutung |
|----------|-----------|
| `SECRET_KEY` | Pflicht in Production; für Tests setzen |
| `DATABASE_URL` | z. B. `sqlite://` in-memory |
| `SSL_VERIFY` | `false` in Tests üblich |
| `API_ACCESS_TOKEN` | Wenn gesetzt: alle `/api/*`-Aufrufe (außer `/api/health`) benötigen Bearer oder `X-API-Key` |
| `BACKGROUND_JOBS_ENABLED` | `0` schaltet Hintergrund-Threads in diesem Prozess aus |
| `BACKGROUND_JOB_LOCKFILE` | Unix-`flock`-Datei: nur ein Worker startet Hintergrund-Jobs |
| `OPEN_ALERTS_CACHE_SECONDS` | TTL für Navbar-Alert-Zähler (Standard 30) |

Coverage-Konfiguration: **`.coveragerc`** (mit `pytest --cov-config=.coveragerc`).

**Ruff:** `ruff check app/services …` (siehe CI) bzw. `ruff check app` lokal.

---

## 5. CI (GitHub Actions)

Workflow: **`.github/workflows/ci-tests.yml`**

- Auslöser: `push` / `pull_request` auf `main`/`master`
- Python **3.10** und **3.11**
- `pip install -r requirements.txt -r requirements-dev.txt`
- **Ruff** auf ausgewählten Modulen (schnelle Qualitätsprüfung)
- `pytest tests/ -v --cov=app --cov-config=.coveragerc --cov-report=term-missing`

Optionaler Browser-E2E-Platzhalter: `tests/browser/` mit Marker `browser_e2e` (nur mit `PLAYWRIGHT_E2E=1`).

---

## 6. Abdeckungsziel („100 % kritisch“)

- **Vollständige Zeilenabdeckung** der gesamten Codebasis ist hier bewusst **nicht** als harter CI-Gate gesetzt (viele UI-/Template-/Vendor-Pfade wären aufwendig zu mocken).
- **Kritische Pfade** sind abgedeckt durch: bestehende **~17** Modul-Testdateien + neue **Unit/Integration/E2E**-Schicht + gemeinsame Fixtures in `tests/conftest.py` und `tests/support/factories.py`.
- Für Release-Qualität empfohlen: regelmäßig `COV=1 ./scripts/run_tests.sh` und Lücken in riskanten Modulen (`routes/admin.py`, `capacity_service.py`, …) gezielt schließen.

---

## 7. Optionales echtes Browser-E2E

Die mitgelieferten **E2E-Tests** nutzen den Flask-`test_client` (kein Headless-Browser).

Für **Playwright** o. Ä.:

```bash
pip install playwright pytest-playwright
playwright install chromium
# eigene Suite z. B. tests/browser/ – nicht im Repo-Pflichtumfang
```

---

## 8. Realistische Testdaten

Zentrale Builder: **`tests/support/factories.py`** (`storage_system_kwargs`, `ontap_system_kwargs`, `status_cache_payload_online`, `snapshot_record_kwargs`). Erweiterungen dort halten Tests konsistent und lesbar.
