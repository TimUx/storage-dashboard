# Container Deployment Guide

Diese Anleitung beschreibt die Verwendung des Storage Dashboard als Podman/Docker/nerdctl Container.

## Voraussetzungen

### Podman Installation (empfohlen)

**SUSE Linux Enterprise / openSUSE:**
```bash
sudo zypper install podman podman-compose
```

**Red Hat / CentOS / Fedora:**
```bash
sudo dnf install podman podman-compose
```

**Ubuntu / Debian:**
```bash
sudo apt-get update
sudo apt-get install podman podman-compose
```

### containerd + nerdctl Installation (Alternative)

**SUSE Linux Enterprise / openSUSE:**
```bash
# containerd installieren
sudo zypper install containerd

# nerdctl herunterladen und installieren
NERDCTL_VERSION=1.7.6
wget https://github.com/containerd/nerdctl/releases/download/v${NERDCTL_VERSION}/nerdctl-${NERDCTL_VERSION}-linux-amd64.tar.gz
sudo tar Cxzvf /usr/local/bin nerdctl-${NERDCTL_VERSION}-linux-amd64.tar.gz

# containerd starten und aktivieren
sudo systemctl enable --now containerd
```

**Ubuntu / Debian:**
```bash
# containerd installieren
sudo apt-get update
sudo apt-get install containerd

# nerdctl herunterladen und installieren
NERDCTL_VERSION=1.7.6
wget https://github.com/containerd/nerdctl/releases/download/v${NERDCTL_VERSION}/nerdctl-${NERDCTL_VERSION}-linux-amd64.tar.gz
sudo tar Cxzvf /usr/local/bin nerdctl-${NERDCTL_VERSION}-linux-amd64.tar.gz

# containerd starten und aktivieren
sudo systemctl enable --now containerd
```

**Red Hat / CentOS / Fedora:**
```bash
# containerd installieren
sudo dnf install containerd

# nerdctl herunterladen und installieren
NERDCTL_VERSION=1.7.6
wget https://github.com/containerd/nerdctl/releases/download/v${NERDCTL_VERSION}/nerdctl-${NERDCTL_VERSION}-linux-amd64.tar.gz
sudo tar Cxzvf /usr/local/bin nerdctl-${NERDCTL_VERSION}-linux-amd64.tar.gz

# containerd starten und aktivieren
sudo systemctl enable --now containerd
```

**nerdctl compose Plugin (für docker-compose Kompatibilität):**

nerdctl unterstützt `docker-compose.yml` nativ. Für erweiterte Funktionen:
```bash
# BuildKit installieren (optional, für erweiterte Build-Features)
sudo systemctl enable --now buildkit

# CNI Plugins installieren (für Netzwerke)
CNI_VERSION=1.3.0
sudo mkdir -p /opt/cni/bin
wget https://github.com/containernetworking/plugins/releases/download/v${CNI_VERSION}/cni-plugins-linux-amd64-v${CNI_VERSION}.tgz
sudo tar Cxzvf /opt/cni/bin cni-plugins-linux-amd64-v${CNI_VERSION}.tgz
```

### Docker Installation (Alternative)

Falls Sie Docker statt Podman oder nerdctl verwenden möchten:
```bash
# Siehe: https://docs.docker.com/engine/install/
```

## Schnellstart

### 1. Repository klonen

```bash
git clone https://github.com/TimUx/storage-dashboard.git
cd storage-dashboard
```

### 2. Umgebungsvariablen konfigurieren

Erstellen Sie eine `.env` Datei für die Konfiguration:

```bash
# Generieren Sie einen sicheren Secret Key
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env

# Fügen Sie weitere Optionen hinzu
cat >> .env << 'EOF'
# SSL Verifizierung für Storage APIs
SSL_VERIFY=false

# Optional: Weitere Konfigurationen
# FLASK_ENV=production
EOF
```

**Wichtig:** Der Secret Key ist essentiell für die Sicherheit der Anwendung!

### 3. Container starten

**Mit Podman (empfohlen):**
```bash
# Container bauen und starten
podman-compose up -d

# Oder mit podman direkt:
podman build -t storage-dashboard:latest .
podman run -d \
  --name storage-dashboard \
  -p 5000:5000 \
  -v storage-data:/app/data:Z \
  -e SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
  -e SSL_VERIFY=false \
  storage-dashboard:latest
```

**Mit nerdctl:**
```bash
# Container bauen und starten mit compose
nerdctl compose up -d

# Oder mit nerdctl direkt:
nerdctl build -t storage-dashboard:latest .
nerdctl run -d \
  --name storage-dashboard \
  -p 5000:5000 \
  -v storage-data:/app/data \
  -e SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
  -e SSL_VERIFY=false \
  storage-dashboard:latest
```

**Mit Docker:**
```bash
# Container bauen und starten
docker-compose up -d

# Oder mit docker direkt:
docker build -t storage-dashboard:latest .
docker run -d \
  --name storage-dashboard \
  -p 5000:5000 \
  -v storage-data:/app/data \
  --env-file .env \
  storage-dashboard:latest
```

### 4. Dashboard aufrufen

Öffnen Sie in Ihrem Browser:
```
http://localhost:5000
```

## Remote CLI Verwendung

Das Dashboard bietet eine Remote CLI für den Zugriff von außerhalb des Containers:

### Von außerhalb des Containers zugreifen

**Ohne Installation im Container:**
```bash
# Erstellen Sie eine Kopie der Remote CLI
curl -o remote-cli.py https://raw.githubusercontent.com/TimUx/storage-dashboard/main/remote-cli.py
chmod +x remote-cli.py

# Installieren Sie die Abhängigkeiten
pip3 install click requests tabulate

# Verwenden Sie die CLI
python3 remote-cli.py --url http://localhost:5000 dashboard
python3 remote-cli.py --url http://localhost:5000 systems
```

**Mit Container exec:**
```bash
# Podman
podman exec storage-dashboard python /app/remote-cli.py dashboard

# nerdctl
nerdctl exec storage-dashboard python /app/remote-cli.py dashboard

# Docker
docker exec storage-dashboard python /app/remote-cli.py dashboard
```

### Von einem Remote-System zugreifen

```bash
# Setzen Sie die Dashboard-URL als Umgebungsvariable
export DASHBOARD_URL=http://dashboard-server.example.com:5000

# Verwenden Sie die Remote CLI
python3 remote-cli.py dashboard
python3 remote-cli.py systems
python3 remote-cli.py status 1
python3 remote-cli.py export --format json
```

**Weitere Informationen:** Siehe [REMOTE_CLI.md](REMOTE_CLI.md) für detaillierte Anleitung.

## Container-Verwaltung

### Status prüfen

**Podman:**
```bash
# Container-Status anzeigen
podman ps

# Logs anzeigen
podman logs storage-dashboard

# Logs live verfolgen
podman logs -f storage-dashboard
```

**nerdctl:**
```bash
# Container-Status anzeigen
nerdctl ps

# Logs anzeigen
nerdctl logs storage-dashboard

# Logs live verfolgen
nerdctl logs -f storage-dashboard
```

**Docker:**
```bash
# Container-Status anzeigen
docker ps

# Logs anzeigen
docker logs storage-dashboard

# Logs live verfolgen
docker logs -f storage-dashboard
```

### Container neu starten

**Podman:**
```bash
podman-compose restart
# oder
podman restart storage-dashboard
```

**nerdctl:**
```bash
nerdctl compose restart
# oder
nerdctl restart storage-dashboard
```

**Docker:**
```bash
docker-compose restart
# oder
docker restart storage-dashboard
```

### Container stoppen

**Podman:**
```bash
podman-compose down
# oder
podman stop storage-dashboard
```

**nerdctl:**
```bash
nerdctl compose down
# oder
nerdctl stop storage-dashboard
```

**Docker:**
```bash
docker-compose down
# oder
docker stop storage-dashboard
```

### Updates durchführen

```bash
# Code aktualisieren
git pull

# Container neu bauen und starten
podman-compose up -d --build
# oder
nerdctl compose up -d --build
# oder
docker-compose up -d --build

# Nach dem Update: Datenbank-Migrationen ausführen (wichtig!)
podman exec -it storage-dashboard python cli.py migrate
# oder
nerdctl exec -it storage-dashboard python cli.py migrate
# oder
docker exec -it storage-dashboard python cli.py migrate
```

## Erweiterte Konfiguration

### Eigenes Image bauen

```bash
# Mit spezifischem Tag
podman build -t storage-dashboard:v1.0 .

# Mit nerdctl
nerdctl build -t storage-dashboard:v1.0 .

# Für andere Plattformen (z.B. ARM)
podman build --platform linux/arm64 -t storage-dashboard:arm64 .
# oder
nerdctl build --platform linux/arm64 -t storage-dashboard:arm64 .
```

### Persistente Daten sichern

**Volume-Backup:**
```bash
# Podman
podman run --rm \
  -v storage-data:/data:ro \
  -v $(pwd):/backup \
  alpine tar czf /backup/storage-dashboard-backup-$(date +%Y%m%d).tar.gz -C /data .

# nerdctl
nerdctl run --rm \
  -v storage-data:/data:ro \
  -v $(pwd):/backup \
  alpine tar czf /backup/storage-dashboard-backup-$(date +%Y%m%d).tar.gz -C /data .

# Docker
docker run --rm \
  -v storage-data:/data:ro \
  -v $(pwd):/backup \
  alpine tar czf /backup/storage-dashboard-backup-$(date +%Y%m%d).tar.gz -C /data .
```

**Backup wiederherstellen:**
```bash
# Podman
podman run --rm \
  -v storage-data:/data \
  -v $(pwd):/backup \
  alpine sh -c "cd /data && tar xzf /backup/storage-dashboard-backup-YYYYMMDD.tar.gz"

# nerdctl
nerdctl run --rm \
  -v storage-data:/data \
  -v $(pwd):/backup \
  alpine sh -c "cd /data && tar xzf /backup/storage-dashboard-backup-YYYYMMDD.tar.gz"

# Docker
docker run --rm \
  -v storage-data:/data \
  -v $(pwd):/backup \
  alpine sh -c "cd /data && tar xzf /backup/storage-dashboard-backup-YYYYMMDD.tar.gz"
```

### Container im Host-Netzwerk betreiben

Für direkten Zugriff auf Storage-Systeme im lokalen Netzwerk:

**Podman:**
```bash
podman run -d \
  --name storage-dashboard \
  --network host \
  -v storage-data:/app/data:Z \
  --env-file .env \
  storage-dashboard:latest
```

**nerdctl:**
```bash
nerdctl run -d \
  --name storage-dashboard \
  --network host \
  -v storage-data:/app/data \
  --env-file .env \
  storage-dashboard:latest
```

**Docker:**
```bash
docker run -d \
  --name storage-dashboard \
  --network host \
  -v storage-data:/app/data \
  --env-file .env \
  storage-dashboard:latest
```

### Eigenen Port verwenden

Ändern Sie in `docker-compose.yml`:
```yaml
ports:
  - "8080:5000"  # Host-Port:Container-Port
```

Oder beim manuellen Start:
```bash
# Podman
podman run -d -p 8080:5000 ...

# nerdctl
nerdctl run -d -p 8080:5000 ...

# Docker
docker run -d -p 8080:5000 ...
```

## Systemd Integration

### Container als Systemd-Service (Podman)

Erstellen Sie eine Systemd-Unit-Datei:

```bash
# User-Service (empfohlen)
mkdir -p ~/.config/systemd/user/
podman generate systemd --new --name storage-dashboard > ~/.config/systemd/user/storage-dashboard.service

# Service aktivieren und starten
systemctl --user enable --now storage-dashboard.service

# Optional: Autostart auch ohne User-Login
loginctl enable-linger $USER
```

**Oder als System-Service (als root):**

```bash
# Als root
sudo podman generate systemd --new --name storage-dashboard > /etc/systemd/system/storage-dashboard.service

# Service aktivieren
sudo systemctl daemon-reload
sudo systemctl enable --now storage-dashboard.service
```

### Container als Systemd-Service (nerdctl)

nerdctl kann auch mit systemd integriert werden, jedoch ohne automatische Unit-Generierung:

```bash
# Manuelle Systemd-Unit erstellen
sudo nano /etc/systemd/system/storage-dashboard.service
```

Fügen Sie folgenden Inhalt ein:

```ini
[Unit]
Description=Storage Dashboard Container
After=network-online.target containerd.service
Wants=network-online.target
Requires=containerd.service

[Service]
Type=simple
Restart=always
RestartSec=5s
ExecStartPre=-/usr/local/bin/nerdctl stop storage-dashboard
ExecStartPre=-/usr/local/bin/nerdctl rm storage-dashboard
ExecStart=/usr/local/bin/nerdctl run --rm \
  --name storage-dashboard \
  -p 5000:5000 \
  -v storage-data:/app/data \
  --env-file /opt/storage-dashboard/.env \
  ghcr.io/timux/storage-dashboard:latest
ExecStop=/usr/local/bin/nerdctl stop storage-dashboard

[Install]
WantedBy=multi-user.target
```

Service aktivieren:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now storage-dashboard.service
```

### Service-Verwaltung

```bash
# Status prüfen
systemctl --user status storage-dashboard  # für Podman User-Service
# oder
sudo systemctl status storage-dashboard     # für System-Service

# Neu starten
systemctl --user restart storage-dashboard
# oder
sudo systemctl restart storage-dashboard

# Stoppen
systemctl --user stop storage-dashboard
# oder
sudo systemctl stop storage-dashboard

# Logs anzeigen
journalctl --user -u storage-dashboard -f
# oder
sudo journalctl -u storage-dashboard -f
```

## Fehlerbehebung

### Container startet nicht

```bash
# Logs prüfen
podman logs storage-dashboard
# oder
nerdctl logs storage-dashboard
# oder
docker logs storage-dashboard

# Container-Konfiguration prüfen
podman inspect storage-dashboard
# oder
nerdctl inspect storage-dashboard
# oder
docker inspect storage-dashboard

# Container interaktiv starten
podman run -it --rm --entrypoint /bin/bash storage-dashboard:latest
# oder
nerdctl run -it --rm --entrypoint /bin/bash storage-dashboard:latest
# oder
docker run -it --rm --entrypoint /bin/bash storage-dashboard:latest
```

### Datenbankprobleme

```bash
# Schema-Fehler (z.B. "no such column")
# Führen Sie die Datenbank-Migrationen aus
podman exec -it storage-dashboard python cli.py migrate
# oder
nerdctl exec -it storage-dashboard python cli.py migrate
# oder
docker exec -it storage-dashboard python cli.py migrate

# Datenbank neu initialisieren (ACHTUNG: Löscht alle Daten!)
podman exec -it storage-dashboard python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.drop_all(); db.create_all()"
# oder
nerdctl exec -it storage-dashboard python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.drop_all(); db.create_all()"
# oder
docker exec -it storage-dashboard python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.drop_all(); db.create_all()"
```

### Berechtigungsprobleme mit Volumes

Bei Podman auf SELinux-Systemen (RHEL, CentOS, Fedora):
```bash
# Volume mit korrekten SELinux-Labels mounten
podman run -d -v storage-data:/app/data:Z ...

# Z = private volume (empfohlen)
# z = shared volume
```

Bei nerdctl auf SELinux-Systemen:
```bash
# nerdctl unterstützt SELinux-Labels nicht direkt
# Verwenden Sie stattdessen:
sudo chcon -Rt container_file_t /var/lib/containerd/volumes/storage-data
# oder deaktivieren Sie SELinux für den Container (nicht empfohlen)
```

**Hinweis:** Für SELinux-Umgebungen wird Podman empfohlen, da es native SELinux-Label-Unterstützung bietet.

### Netzwerkprobleme

```bash
# Podman: Netzwerkkonfiguration prüfen
podman network ls
podman network inspect bridge

# Container-Netzwerk prüfen
podman inspect storage-dashboard | grep -A 10 NetworkSettings

# nerdctl: Netzwerkkonfiguration prüfen
nerdctl network ls
nerdctl network inspect bridge

# Container-Netzwerk prüfen
nerdctl inspect storage-dashboard | grep -A 10 NetworkSettings

# Docker: Netzwerkkonfiguration prüfen
docker network ls
docker network inspect bridge

# Container-Netzwerk prüfen
docker inspect storage-dashboard | grep -A 10 NetworkSettings
```

## GitHub Container Registry

### Vorgefertigtes Image verwenden

Das Storage Dashboard wird automatisch als Docker Image auf GitHub Container Registry (ghcr.io) bereitgestellt.

**Vorteile:**
- Kein lokales Build notwendig
- Schnellerer Start
- Offizielle, getestete Images

#### Image herunterladen und starten

```bash
# Podman: Image herunterladen
podman pull ghcr.io/timux/storage-dashboard:latest

# Container starten
podman run -d \
  --name storage-dashboard \
  -p 5000:5000 \
  -v storage-data:/app/data:Z \
  --env-file .env \
  ghcr.io/timux/storage-dashboard:latest
```

**Mit nerdctl:**
```bash
# Image herunterladen
nerdctl pull ghcr.io/timux/storage-dashboard:latest

# Container starten
nerdctl run -d \
  --name storage-dashboard \
  -p 5000:5000 \
  -v storage-data:/app/data \
  --env-file .env \
  ghcr.io/timux/storage-dashboard:latest
```

**Mit Docker:**
```bash
docker pull ghcr.io/timux/storage-dashboard:latest
docker run -d \
  --name storage-dashboard \
  -p 5000:5000 \
  -v storage-data:/app/data \
  --env-file .env \
  ghcr.io/timux/storage-dashboard:latest
```

#### Docker-Compose / Podman-Compose / nerdctl compose mit GitHub Image

Die Datei `docker-compose.yml` ist bereits für die Verwendung des GitHub-Images konfiguriert:

```bash
# Starten mit vorgefertigtem Image
podman-compose up -d
# oder
nerdctl compose up -d
# oder
docker-compose up -d
```

Das Image wird automatisch von ghcr.io heruntergeladen, falls es noch nicht lokal vorhanden ist.

#### Lokales Build erzwingen

Wenn Sie dennoch lokal bauen möchten, kommentieren Sie in `docker-compose.yml` die Build-Zeilen aus:

```yaml
services:
  storage-dashboard:
    # image: ghcr.io/timux/storage-dashboard:latest
    build:
      context: .
      dockerfile: Dockerfile
```

Dann:
```bash
podman-compose up -d --build
# oder
nerdctl compose up -d --build
# oder
docker-compose up -d --build
```

### GitHub Action: Image automatisch bauen

Das Repository verfügt über eine GitHub Action, die automatisch ein Docker Image erstellt und auf GitHub Container Registry hochlädt.

**Workflow manuell auslösen:**
1. Gehen Sie zu: `https://github.com/TimUx/storage-dashboard/actions/workflows/build-and-push-image.yml`
2. Klicken Sie auf "Run workflow"
3. Optional: Geben Sie einen Tag-Namen ein (Standard: `latest`)
4. Klicken Sie auf "Run workflow"

Das Image wird dann automatisch gebaut und unter `ghcr.io/timux/storage-dashboard:TAG` bereitgestellt.

**Verwendung eines spezifischen Tags:**
```bash
# Podman
podman pull ghcr.io/timux/storage-dashboard:v1.0.0
podman run -d \
  --name storage-dashboard \
  -p 5000:5000 \
  -v storage-data:/app/data:Z \
  --env-file .env \
  ghcr.io/timux/storage-dashboard:v1.0.0

# nerdctl
nerdctl pull ghcr.io/timux/storage-dashboard:v1.0.0
nerdctl run -d \
  --name storage-dashboard \
  -p 5000:5000 \
  -v storage-data:/app/data \
  --env-file .env \
  ghcr.io/timux/storage-dashboard:v1.0.0

# Docker
docker pull ghcr.io/timux/storage-dashboard:v1.0.0
docker run -d \
  --name storage-dashboard \
  -p 5000:5000 \
  -v storage-data:/app/data \
  --env-file .env \
  ghcr.io/timux/storage-dashboard:v1.0.0
```

## Container Registry

### Image in Registry hochladen

```bash
# Podman: Tag erstellen
podman tag storage-dashboard:latest registry.example.com/storage-dashboard:latest

# Login in Registry
podman login registry.example.com

# Image hochladen
podman push registry.example.com/storage-dashboard:latest

# nerdctl: Tag erstellen
nerdctl tag storage-dashboard:latest registry.example.com/storage-dashboard:latest

# Login in Registry
nerdctl login registry.example.com

# Image hochladen
nerdctl push registry.example.com/storage-dashboard:latest

# Docker: Tag erstellen
docker tag storage-dashboard:latest registry.example.com/storage-dashboard:latest

# Login in Registry
docker login registry.example.com

# Image hochladen
docker push registry.example.com/storage-dashboard:latest
```

### Image von Registry herunterladen

```bash
# Podman
podman pull registry.example.com/storage-dashboard:latest
podman run -d \
  --name storage-dashboard \
  -p 5000:5000 \
  -v storage-data:/app/data:Z \
  --env-file .env \
  registry.example.com/storage-dashboard:latest

# nerdctl
nerdctl pull registry.example.com/storage-dashboard:latest
nerdctl run -d \
  --name storage-dashboard \
  -p 5000:5000 \
  -v storage-data:/app/data \
  --env-file .env \
  registry.example.com/storage-dashboard:latest

# Docker
docker pull registry.example.com/storage-dashboard:latest
docker run -d \
  --name storage-dashboard \
  -p 5000:5000 \
  -v storage-data:/app/data \
  --env-file .env \
  registry.example.com/storage-dashboard:latest
```

## Sicherheitshinweise

1. **Secret Key**: Verwenden Sie immer einen starken, zufälligen Secret Key
2. **Netzwerk**: Exponieren Sie den Container nur in vertrauenswürdigen Netzwerken
3. **Updates**: Halten Sie das Base-Image und die Dependencies aktuell
4. **Volumes**: Sichern Sie regelmäßig Ihre Datenbank
5. **Nicht-Root**: Der Container läuft als Nicht-Root-User (UID 1000)
6. **Resource Limits**: Konfigurieren Sie CPU/Memory-Limits in docker-compose.yml
7. **Reverse Proxy**: Verwenden Sie einen Reverse Proxy (nginx/traefik) mit SSL für Produktionsumgebungen

## Reverse Proxy mit Traefik (Podman-Compose)

Beispiel-Konfiguration für Traefik v2:

```yaml
version: '3.8'

services:
  traefik:
    image: traefik:v2.10
    container_name: traefik
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/podman/podman.sock:/var/run/docker.sock:ro
      - ./traefik.yml:/traefik.yml:ro
      - ./certs:/certs

  storage-dashboard:
    build: .
    container_name: storage-dashboard
    restart: unless-stopped
    volumes:
      - storage-data:/app/data
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - SSL_VERIFY=false
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.dashboard.rule=Host(`dashboard.example.com`)"
      - "traefik.http.routers.dashboard.entrypoints=websecure"
      - "traefik.http.routers.dashboard.tls=true"
      - "traefik.http.services.dashboard.loadbalancer.server.port=5000"

volumes:
  storage-data:
```

## Performance-Optimierung

### Gunicorn-Worker anpassen

In `docker-compose.yml`:
```yaml
environment:
  - GUNICORN_WORKERS=4        # Anzahl Worker-Prozesse
  - GUNICORN_THREADS=2        # Threads pro Worker
  - GUNICORN_TIMEOUT=120      # Request-Timeout
```

Oder überschreiben Sie den CMD in der `docker-compose.yml`:
```yaml
command: gunicorn --bind 0.0.0.0:5000 --workers 8 --threads 4 --timeout 180 run:app
```

### Resource-Limits optimieren

```yaml
deploy:
  resources:
    limits:
      cpus: '4'
      memory: 2G
    reservations:
      cpus: '1'
      memory: 512M
```

## Support

Bei Fragen oder Problemen:
- GitHub Issues: https://github.com/TimUx/storage-dashboard/issues
- Dokumentation: https://github.com/TimUx/storage-dashboard

## Lizenz

Siehe [LICENSE](LICENSE) Datei im Repository.
