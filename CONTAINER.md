# Container Deployment Guide

Diese Anleitung beschreibt die Verwendung des Storage Dashboard als Podman/Docker Container.

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

### Docker Installation (Alternative)

Falls Sie Docker statt Podman verwenden möchten:
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
cat > .env << 'EOF'
# Secret Key für Flask Session (ÄNDERN!)
SECRET_KEY=your-super-secret-key-here-change-this

# SSL Verifizierung für Storage APIs
SSL_VERIFY=false

# Optional: Weitere Konfigurationen
# FLASK_ENV=production
EOF
```

**Wichtig:** Generieren Sie einen sicheren Secret Key:
```bash
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" >> .env
```

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
  --env-file .env \
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
docker-compose up -d --build
```

## Erweiterte Konfiguration

### Eigenes Image bauen

```bash
# Mit spezifischem Tag
podman build -t storage-dashboard:v1.0 .

# Für andere Plattformen (z.B. ARM)
podman build --platform linux/arm64 -t storage-dashboard:arm64 .
```

### Persistente Daten sichern

**Volume-Backup:**
```bash
# Podman
podman run --rm \
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
podman run -d -p 8080:5000 ...
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

### Service-Verwaltung

```bash
# Status prüfen
systemctl --user status storage-dashboard

# Neu starten
systemctl --user restart storage-dashboard

# Stoppen
systemctl --user stop storage-dashboard

# Logs anzeigen
journalctl --user -u storage-dashboard -f
```

## Fehlerbehebung

### Container startet nicht

```bash
# Logs prüfen
podman logs storage-dashboard

# Container-Konfiguration prüfen
podman inspect storage-dashboard

# Container interaktiv starten
podman run -it --rm --entrypoint /bin/bash storage-dashboard:latest
```

### Datenbankprobleme

```bash
# Datenbank neu initialisieren (ACHTUNG: Löscht alle Daten!)
podman exec -it storage-dashboard python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.drop_all(); db.create_all()"
```

### Berechtigungsprobleme mit Volumes

Bei Podman auf SELinux-Systemen (RHEL, CentOS, Fedora):
```bash
# Volume mit korrekten SELinux-Labels mounten
podman run -d -v storage-data:/app/data:Z ...

# Z = private volume (empfohlen)
# z = shared volume
```

### Netzwerkprobleme

```bash
# Netzwerkkonfiguration prüfen
podman network ls
podman network inspect bridge

# Container-Netzwerk prüfen
podman inspect storage-dashboard | grep -A 10 NetworkSettings
```

## Container Registry

### Image in Registry hochladen

```bash
# Tag erstellen
podman tag storage-dashboard:latest registry.example.com/storage-dashboard:latest

# Login in Registry
podman login registry.example.com

# Image hochladen
podman push registry.example.com/storage-dashboard:latest
```

### Image von Registry herunterladen

```bash
podman pull registry.example.com/storage-dashboard:latest
podman run -d \
  --name storage-dashboard \
  -p 5000:5000 \
  -v storage-data:/app/data:Z \
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
