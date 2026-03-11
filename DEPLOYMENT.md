# Deployment-Anleitung für Storage Dashboard

Diese Anleitung beschreibt die Installation des Storage Dashboard in verschiedenen Varianten.

---

## Inhaltsverzeichnis

1. [Option A: SLES 15 mit Docker (Empfohlen)](#option-a-sles-15-mit-docker-empfohlen)
2. [Option B: Ubuntu Server 24 mit containerd/nerdctl](#option-b-ubuntu-server-24-mit-containerdnerdctl)
3. [Option C: Manuelle Installation (ohne Container)](#option-c-manuelle-installation-ohne-container)
4. [Nginx Reverse Proxy](#nginx-reverse-proxy)
5. [Verwaltung und Betrieb](#verwaltung-und-betrieb)
6. [Sicherheitsempfehlungen](#sicherheitsempfehlungen)

---

## Option A: SLES 15 mit Docker (Empfohlen)

Diese Option nutzt Docker auf SUSE Linux Enterprise Server 15 und ist die empfohlene
Produktionsumgebung. Die Anwendung und eine PostgreSQL-Datenbank laufen in separaten
Containern und werden über `docker-compose` verwaltet.

### 1. Voraussetzungen

```bash
# Paketverwaltung aktualisieren
sudo zypper refresh

# Docker installieren
sudo zypper install docker docker-compose

# Docker-Dienst aktivieren und starten
sudo systemctl enable docker
sudo systemctl start docker

# Aktuellen Benutzer zur Docker-Gruppe hinzufügen (ggf. neu anmelden)
sudo usermod -aG docker $USER
```

> **Hinweis:** Melden Sie sich nach `usermod` neu an, damit die Gruppenmitgliedschaft wirksam wird.

### 2. Repository klonen

```bash
sudo mkdir -p /opt/storage-dashboard
sudo git clone https://github.com/TimUx/storage-dashboard.git /opt/storage-dashboard
cd /opt/storage-dashboard
sudo chown -R $USER:$USER /opt/storage-dashboard
```

### 3. Konfiguration erstellen

```bash
cd /opt/storage-dashboard

# Sicheren Secret Key und PostgreSQL-Passwort generieren
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env
python3 -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_hex(32))" >> .env

# Weitere Pflichteinstellungen
cat >> .env << 'EOF'
POSTGRES_DB=storage_dashboard
POSTGRES_USER=dashboard
SSL_VERIFY=false
FLASK_ENV=production
TZ=Europe/Berlin
EOF
```

### 4. Container starten

```bash
# Image herunterladen und Container starten
docker-compose up -d

# Status prüfen
docker-compose ps

# Logs verfolgen
docker-compose logs -f storage-dashboard
```

Das Dashboard ist erreichbar unter: `http://<server-ip>:5000`

### 5. Admin-Benutzer erstellen

```bash
docker exec -it storage-dashboard python cli.py admin create-user
```

### 6. Firewall konfigurieren (SLES 15)

```bash
# Port 5000 in der Firewall freigeben
sudo firewall-cmd --permanent --add-port=5000/tcp
sudo firewall-cmd --reload

# Status prüfen
sudo firewall-cmd --list-ports
```

### 7. Container automatisch neu starten

Die Container sind mit `restart: unless-stopped` konfiguriert und starten automatisch
nach einem Systemneustart.

```bash
# Service-Status prüfen
docker-compose ps

# Nach einem Systemneustart: Container manuell starten (falls nötig)
cd /opt/storage-dashboard
docker-compose up -d
```

### 8. Updates einspielen

```bash
cd /opt/storage-dashboard

# Neustes Image herunterladen
docker-compose pull

# Container mit neuer Version neu starten
docker-compose up -d

# Alte Images aufräumen
docker image prune -f
```

---

## Option B: Ubuntu Server 24 mit containerd/nerdctl

Diese Option nutzt `containerd` als Container-Runtime und `nerdctl` als Docker-kompatibles
CLI-Tool auf Ubuntu Server 24.04 LTS.

### 1. Voraussetzungen

#### containerd installieren

```bash
# Systemaktualisierung
sudo apt-get update && sudo apt-get upgrade -y

# containerd installieren
sudo apt-get install -y containerd

# containerd Standardkonfiguration generieren
sudo mkdir -p /etc/containerd
sudo containerd config default | sudo tee /etc/containerd/config.toml

# SystemdCgroup aktivieren (wichtig für Ubuntu 24!)
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml

# containerd starten und aktivieren
sudo systemctl enable --now containerd

# Status prüfen
sudo systemctl status containerd
```

#### nerdctl installieren

```bash
# Aktuelle nerdctl-Version herunterladen (Full-Bundle inkl. CNI-Plugins)
NERDCTL_VERSION=2.0.3
wget https://github.com/containerd/nerdctl/releases/download/v${NERDCTL_VERSION}/nerdctl-full-${NERDCTL_VERSION}-linux-amd64.tar.gz

# Entpacken und installieren
sudo tar Cxzvf /usr/local nerdctl-full-${NERDCTL_VERSION}-linux-amd64.tar.gz

# BuildKit aktivieren (für Image-Builds)
sudo systemctl enable --now buildkit

# CNI-Netzwerk-Bridge aktivieren
sudo nerdctl network create bridge 2>/dev/null || true

# nerdctl-Version prüfen
nerdctl version
```

> **Hinweis:** Das Full-Bundle enthält CNI-Plugins, BuildKit und weitere Hilfsprogramme.
> Achten Sie auf die aktuelle Version unter https://github.com/containerd/nerdctl/releases

#### compose-Plugin für nerdctl einrichten

`nerdctl compose` ist im Full-Bundle bereits enthalten und unterstützt `docker-compose.yml`-Dateien nativ.

```bash
# Funktionstest
nerdctl compose version
```

### 2. Repository klonen

```bash
sudo mkdir -p /opt/storage-dashboard
sudo git clone https://github.com/TimUx/storage-dashboard.git /opt/storage-dashboard
cd /opt/storage-dashboard
sudo chown -R $USER:$USER /opt/storage-dashboard
```

### 3. Konfiguration erstellen

```bash
cd /opt/storage-dashboard

# Sicheren Secret Key und PostgreSQL-Passwort generieren
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env
python3 -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_hex(32))" >> .env

# Weitere Pflichteinstellungen
cat >> .env << 'EOF'
POSTGRES_DB=storage_dashboard
POSTGRES_USER=dashboard
SSL_VERIFY=false
FLASK_ENV=production
TZ=Europe/Berlin
EOF
```

### 4. Container starten

```bash
# Image herunterladen und Container starten
sudo nerdctl compose up -d

# Status prüfen
sudo nerdctl compose ps

# Logs verfolgen
sudo nerdctl compose logs -f storage-dashboard
```

Das Dashboard ist erreichbar unter: `http://<server-ip>:5000`

> **Hinweis:** `nerdctl compose` erfordert unter Ubuntu 24 standardmäßig `sudo`, da containerd
> als root-Dienst läuft. Alternativ können Sie rootless containerd einrichten.

### 5. Admin-Benutzer erstellen

```bash
sudo nerdctl exec -it storage-dashboard python cli.py admin create-user
```

### 6. Firewall konfigurieren (Ubuntu 24)

```bash
# ufw Port freigeben
sudo ufw allow 5000/tcp
sudo ufw reload

# Status prüfen
sudo ufw status
```

### 7. Systemd-Service für automatischen Start einrichten

Da `nerdctl compose` keinen eingebauten `--restart`-Service hat, empfiehlt sich ein
systemd-Unit-File:

```bash
sudo tee /etc/systemd/system/storage-dashboard.service << 'EOF'
[Unit]
Description=Storage Dashboard (nerdctl compose)
After=network.target containerd.service
Requires=containerd.service

[Service]
Type=forking
WorkingDirectory=/opt/storage-dashboard
ExecStart=/usr/local/bin/nerdctl compose up -d
ExecStop=/usr/local/bin/nerdctl compose down
RemainAfterExit=yes
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable storage-dashboard
sudo systemctl start storage-dashboard
```

### 8. Updates einspielen

```bash
cd /opt/storage-dashboard

# Neustes Image herunterladen
sudo nerdctl compose pull

# Container mit neuer Version neu starten
sudo nerdctl compose up -d

# Ungenutzte Images aufräumen
sudo nerdctl image prune -f
```

### Rootless containerd einrichten (optional)

Für einen Betrieb ohne `sudo` kann rootless containerd konfiguriert werden:

```bash
# Rootless Abhängigkeiten installieren
sudo apt-get install -y uidmap slirp4netns

# Rootless containerd für aktuellen Benutzer einrichten
containerd-rootless-setuptool.sh install

# Systemd-Service für rootless containerd aktivieren
systemctl --user enable --now containerd

# Umgebungsvariablen setzen
export CONTAINERD_SNAPSHOTTER=native
export NERDCTL_HOST=unix:///run/user/$(id -u)/containerd/containerd.sock
```

---

## Option C: Manuelle Installation (ohne Container)

Diese Option beschreibt die direkte Installation auf dem Host-System (ohne Container).

### Voraussetzungen

**SUSE Linux Enterprise 15:**
```bash
sudo zypper install python3 python3-pip python3-devel git
```

**Ubuntu Server 24:**
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-dev git
```

### 1. Benutzer erstellen (empfohlen)

```bash
sudo useradd -r -s /bin/bash -d /opt/storage-dashboard dashboard
```

### 2. Anwendung installieren

```bash
sudo mkdir -p /opt/storage-dashboard
sudo git clone https://github.com/TimUx/storage-dashboard.git /opt/storage-dashboard
sudo chown -R dashboard:dashboard /opt/storage-dashboard

# Als dashboard-Benutzer fortfahren
sudo su - dashboard
cd /opt/storage-dashboard

# Virtual Environment erstellen und Abhängigkeiten installieren
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. PostgreSQL einrichten (Empfohlen)

**SUSE Linux Enterprise 15:**
```bash
sudo zypper install postgresql-server postgresql
sudo systemctl enable --now postgresql
```

**Ubuntu Server 24:**
```bash
sudo apt-get install -y postgresql postgresql-contrib
sudo systemctl enable --now postgresql
```

**Datenbank und Benutzer anlegen:**
```bash
sudo -u postgres psql << EOF
CREATE DATABASE storage_dashboard;
CREATE USER dashboard WITH PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE storage_dashboard TO dashboard;
EOF
```

### 4. Konfiguration

```bash
cd /opt/storage-dashboard
cp .env.example .env

# Sicheren Secret Key generieren
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" >> .env

# PostgreSQL-Verbindung
echo "DATABASE_URL=postgresql://dashboard:secure_password_here@localhost:5432/storage_dashboard" >> .env
echo "FLASK_ENV=production" >> .env
echo "SSL_VERIFY=false" >> .env
```

### 5. Systemd Service einrichten

```bash
# Service-Datei kopieren (als root)
sudo cp /opt/storage-dashboard/storage-dashboard.service /etc/systemd/system/

# Service aktivieren und starten
sudo systemctl daemon-reload
sudo systemctl enable storage-dashboard
sudo systemctl start storage-dashboard

# Status prüfen
sudo systemctl status storage-dashboard
```

### 6. CLI-Befehle

```bash
sudo su - dashboard
cd /opt/storage-dashboard
source venv/bin/activate

# Admin-Benutzer erstellen
python cli.py admin create-user

# Dashboard anzeigen
python cli.py dashboard

# Datenbank-Migrationen ausführen
python cli.py migrate
```

---

## Nginx Reverse Proxy

Für Produktivumgebungen empfiehlt sich ein Reverse Proxy mit SSL/TLS.

### Installation

**SUSE Linux Enterprise 15:**
```bash
sudo zypper install nginx
```

**Ubuntu Server 24:**
```bash
sudo apt-get install -y nginx
```

### Konfiguration

```bash
sudo tee /etc/nginx/conf.d/storage-dashboard.conf << 'EOF'
server {
    listen 80;
    server_name dashboard.example.com;

    # Weiterleitung zu HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name dashboard.example.com;

    # SSL-Zertifikate (firmeneigene CA)
    ssl_certificate     /etc/ssl/certs/dashboard.crt;
    ssl_certificate_key /etc/ssl/private/dashboard.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
EOF

sudo systemctl enable --now nginx
```

---

## Verwaltung und Betrieb

### Service-Befehle (Container)

| Aktion | Docker | nerdctl |
|--------|--------|---------|
| Status prüfen | `docker-compose ps` | `sudo nerdctl compose ps` |
| Logs verfolgen | `docker-compose logs -f` | `sudo nerdctl compose logs -f` |
| Neu starten | `docker-compose restart` | `sudo nerdctl compose restart` |
| Stoppen | `docker-compose down` | `sudo nerdctl compose down` |
| CLI ausführen | `docker exec -it storage-dashboard python cli.py ...` | `sudo nerdctl exec -it storage-dashboard python cli.py ...` |

### Backup der Datenbank

**PostgreSQL (Container):**
```bash
# Backup erstellen
docker exec storage-dashboard-db pg_dump -U dashboard storage_dashboard > backup_$(date +%Y%m%d).sql

# Backup wiederherstellen
docker exec -i storage-dashboard-db psql -U dashboard storage_dashboard < backup_YYYYMMDD.sql
```

**SQLite (manuelle Installation):**
```bash
cp /opt/storage-dashboard/storage_dashboard.db /backup/storage_dashboard_$(date +%Y%m%d).db
```

### Troubleshooting

**Container startet nicht:**
```bash
# Logs prüfen
docker-compose logs storage-dashboard

# Container-Status prüfen
docker inspect storage-dashboard
```

**Datenbankprobleme:**
```bash
# Schema-Fehler beheben (fehlende Spalten ergänzen)
docker exec -it storage-dashboard python cli.py migrate
```

**Verbindungsprobleme zu Storage-Systemen:**
```bash
# SSL-Verifizierung temporär deaktivieren (für Tests)
# In .env: SSL_VERIFY=false
# Container neu starten: docker-compose restart storage-dashboard
```

---

## Sicherheitsempfehlungen

1. **Firewall**: Öffnen Sie nur notwendige Ports (5000 oder 443 bei Reverse Proxy)
2. **SSL/TLS**: Verwenden Sie HTTPS in der Produktion (Reverse Proxy + firmeneigene CA)
3. **Secrets**: Verwenden Sie immer starke, zufällige Secret Keys
4. **Storage-Credentials**: Verwenden Sie Read-Only-Accounts für Storage-Systeme
5. **Container-Updates**: Halten Sie Images und Betriebssystem aktuell
6. **Backup**: Erstellen Sie regelmäßige Datenbank-Backups
7. **Netzwerk**: Betreiben Sie das Dashboard ausschließlich im internen Netzwerk

---

## Umgebungsvariablen

| Variable | Beschreibung | Standard |
|----------|-------------|---------|
| `SECRET_KEY` | Flask Session-Secret (zufälliger Hex-String) | — (Pflichtfeld) |
| `DATABASE_URL` | Datenbankverbindung | `sqlite:///storage_dashboard.db` |
| `POSTGRES_PASSWORD` | PostgreSQL-Passwort (Container) | — (Pflichtfeld bei Container) |
| `POSTGRES_DB` | PostgreSQL-Datenbankname | `storage_dashboard` |
| `POSTGRES_USER` | PostgreSQL-Benutzername | `dashboard` |
| `SSL_VERIFY` | TLS-Zertifikate der Storage-Systeme prüfen | `false` |
| `FLASK_ENV` | `development` oder `production` | `production` |
| `TZ` | Zeitzone (z.B. `Europe/Berlin`) | `Europe/Berlin` |

---

## Support

Bei Problemen oder Fragen erstellen Sie bitte ein Issue im GitHub Repository:
https://github.com/TimUx/storage-dashboard/issues

📖 **Weitere Dokumentation:**
- [CONTAINER.md](CONTAINER.md) – Detaillierte Container-Dokumentation
- [ADMIN_GUIDE.md](ADMIN_GUIDE.md) – Administrator-Handbuch
- [SECURITY.md](SECURITY.md) – Sicherheitshinweise
