# GitHub Actions - Automatischer Docker Image Build

## Übersicht

Das Repository enthält eine GitHub Action, die automatisch ein Docker Image des Storage Dashboards erstellt und auf GitHub Container Registry (ghcr.io) veröffentlicht.

## Workflow: Build and Push Docker Image

**Datei:** `.github/workflows/build-and-push-image.yml`

### Features

- **Manueller Trigger:** Der Workflow kann manuell über die GitHub UI ausgelöst werden
- **Anpassbarer Tag:** Optional kann ein eigener Tag-Name vergeben werden
- **Automatisches Pushen:** Das Image wird automatisch auf ghcr.io hochgeladen
- **Build-Cache:** Nutzt GitHub Actions Cache für schnellere Builds
- **Multi-Stage Build:** Verwendet den optimierten Multi-Stage Dockerfile

### Workflow manuell starten

#### Via GitHub Web Interface

1. Navigieren Sie zu: https://github.com/TimUx/storage-dashboard/actions/workflows/build-and-push-image.yml
2. Klicken Sie auf den Button **"Run workflow"**
3. Optional: Geben Sie einen Tag-Namen ein (Standard: `latest`)
4. Klicken Sie auf **"Run workflow"** zum Bestätigen

Der Workflow startet automatisch und Sie können den Fortschritt in Echtzeit verfolgen.

#### Via GitHub CLI

```bash
# Mit Standard-Tag (latest)
gh workflow run build-and-push-image.yml

# Mit eigenem Tag
gh workflow run build-and-push-image.yml -f tag=v1.0.0
```

### Generierte Images

Nach erfolgreichem Build sind die Images verfügbar unter:

```
ghcr.io/timux/storage-dashboard:latest
ghcr.io/timux/storage-dashboard:<custom-tag>
ghcr.io/timux/storage-dashboard:<branch>-<commit-sha>
```

### Image verwenden

#### Mit Docker/Podman

```bash
# Image herunterladen
podman pull ghcr.io/timux/storage-dashboard:latest

# Container starten
podman run -d \
  --name storage-dashboard \
  -p 5000:5000 \
  -v storage-data:/app/data:Z \
  --env-file .env \
  ghcr.io/timux/storage-dashboard:latest
```

#### Mit Docker Compose

Die Datei `docker-compose.yml` ist bereits für die Verwendung des GitHub-Images konfiguriert:

```bash
# Secret Key generieren
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env
echo "SSL_VERIFY=false" >> .env

# Container starten
podman-compose up -d
```

Das Image wird automatisch von ghcr.io heruntergeladen.

### Spezifischen Tag verwenden

```bash
# Image mit spezifischem Tag herunterladen
podman pull ghcr.io/timux/storage-dashboard:v1.0.0

# In docker-compose.yml anpassen
services:
  storage-dashboard:
    image: ghcr.io/timux/storage-dashboard:v1.0.0
```

## Workflow-Konfiguration

### Trigger

Der Workflow wird ausschließlich manuell ausgelöst (`workflow_dispatch`). Es gibt keine automatischen Trigger bei Commits oder Pull Requests.

### Berechtigungen

Der Workflow benötigt folgende Berechtigungen:
- `contents: read` - Zum Auschecken des Repository-Codes
- `packages: write` - Zum Hochladen des Images auf GitHub Container Registry

Diese Berechtigungen werden automatisch durch `GITHUB_TOKEN` bereitgestellt.

### Build-Prozess

1. **Checkout:** Repository-Code wird ausgecheckt
2. **Docker Buildx:** Docker Buildx wird für erweiterte Build-Features eingerichtet
3. **Registry Login:** Authentifizierung bei GitHub Container Registry
4. **Metadata:** Docker-Metadata und Tags werden generiert
5. **Build & Push:** Image wird gebaut und auf ghcr.io hochgeladen
6. **Summary:** Erfolgsmeldung mit Verwendungshinweisen

### Build-Cache

Der Workflow nutzt GitHub Actions Cache (`type=gha`) für:
- Schnellere Builds bei wiederholter Ausführung
- Effiziente Nutzung von Docker Layer Caching
- Reduzierte Build-Zeit und Ressourcenverbrauch

## Image-Sichtbarkeit

Die Images auf ghcr.io sind standardmäßig **privat**. Um sie öffentlich zu machen:

1. Gehen Sie zu: https://github.com/users/TimUx/packages/container/storage-dashboard/settings
2. Unter "Danger Zone" → "Change visibility"
3. Wählen Sie "Public"
4. Bestätigen Sie die Änderung

**Hinweis:** Öffentliche Images können von jedem heruntergeladen werden.

## Fehlerbehebung

### Workflow schlägt fehl

**Problem:** "Error: buildx failed with: ERROR: failed to solve: ..."

**Lösung:**
- Überprüfen Sie, ob der Dockerfile korrekt ist
- Stellen Sie sicher, dass alle benötigten Dateien im Repository vorhanden sind
- Prüfen Sie die Build-Logs für detaillierte Fehlermeldungen

### Image kann nicht heruntergeladen werden

**Problem:** "Error: unauthorized: unauthenticated"

**Lösung:**
```bash
# Bei GitHub Container Registry einloggen
echo $GITHUB_TOKEN | podman login ghcr.io -u USERNAME --password-stdin

# Oder Image öffentlich machen (siehe oben)
```

### Build dauert zu lange

**Lösung:**
- Der erste Build kann länger dauern (keine Cache-Daten vorhanden)
- Nachfolgende Builds nutzen den Cache und sind deutlich schneller
- Erwartete Build-Zeit: 2-5 Minuten (erster Build), 1-2 Minuten (mit Cache)

## Best Practices

### Tagging-Strategie

```bash
# Produktionsrelease
gh workflow run build-and-push-image.yml -f tag=v1.0.0

# Development-Build
gh workflow run build-and-push-image.yml -f tag=dev

# Feature-Build
gh workflow run build-and-push-image.yml -f tag=feature-xyz

# Latest (Standard)
gh workflow run build-and-push-image.yml
```

### Versionierung

Empfohlene Tag-Namen:
- `latest` - Neueste stabile Version (Standard)
- `v1.0.0` - Semantische Versionierung
- `dev` - Development-Version
- `staging` - Staging-Version

### Cleanup alter Images

Alte, ungenutzte Images sollten regelmäßig gelöscht werden:

1. Gehen Sie zu: https://github.com/users/TimUx/packages/container/storage-dashboard
2. Wählen Sie alte Versionen aus
3. Klicken Sie auf "Delete"

## Automatisierung

### Automatischer Build bei Release

Um einen automatischen Build bei GitHub Releases zu aktivieren, fügen Sie folgendes zum Workflow hinzu:

```yaml
on:
  workflow_dispatch:
    # ... existing config ...
  release:
    types: [published]
```

### Automatischer Build bei Push

Um einen automatischen Build bei Push auf main zu aktivieren:

```yaml
on:
  workflow_dispatch:
    # ... existing config ...
  push:
    branches:
      - main
```

**Hinweis:** Diese Änderungen sollten nur vorgenommen werden, wenn automatische Builds gewünscht sind.

## Sicherheit

### GITHUB_TOKEN

Der Workflow verwendet `GITHUB_TOKEN`, das automatisch von GitHub Actions bereitgestellt wird. Keine manuellen Secrets erforderlich.

### Image-Sicherheit

- Das Image wird im Namen des Repository-Owners veröffentlicht
- Zugriffskontrolle über GitHub Packages
- Unterstützt private und öffentliche Visibility

### Best Practices

1. **Nur vertrauenswürdigen Code bauen:** Überprüfen Sie Code-Änderungen vor dem Build
2. **Regelmäßige Updates:** Halten Sie Base-Images und Dependencies aktuell
3. **Scan auf Vulnerabilities:** Nutzen Sie Tools wie Trivy oder Snyk
4. **Minimale Berechtigungen:** Workflow verwendet minimal notwendige Permissions

## Support

Bei Fragen oder Problemen:
- GitHub Issues: https://github.com/TimUx/storage-dashboard/issues
- GitHub Actions Logs: https://github.com/TimUx/storage-dashboard/actions

## Siehe auch

- [CONTAINER.md](CONTAINER.md) - Container-Deployment-Guide
- [README.md](README.md) - Hauptdokumentation
- [Dockerfile](Dockerfile) - Docker-Image-Konfiguration
