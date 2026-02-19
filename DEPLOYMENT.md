# Deployment-Anleitung für SUSE Linux Enterprise 15

Diese Anleitung beschreibt die Installation des Storage Dashboard auf einem SUSE Linux Enterprise Server 15.

## Voraussetzungen

```bash
# Python 3 und pip installieren
sudo zypper install python3 python3-pip python3-devel

# Git installieren (falls nicht vorhanden)
sudo zypper install git
```

## Installation

### 1. Benutzer erstellen (optional, empfohlen)

```bash
sudo useradd -r -s /bin/bash -d /opt/storage-dashboard dashboard
```

### 2. Anwendung installieren

```bash
# Repository klonen
sudo mkdir -p /opt/storage-dashboard
sudo git clone https://github.com/TimUx/storage-dashboard.git /opt/storage-dashboard
cd /opt/storage-dashboard

# Berechtigungen setzen
sudo chown -R dashboard:dashboard /opt/storage-dashboard

# Als dashboard-Benutzer fortfahren
sudo su - dashboard
cd /opt/storage-dashboard

# Virtual Environment erstellen
python3 -m venv venv
source venv/bin/activate

# Abhängigkeiten installieren
pip install -r requirements.txt
```

### 3. Konfiguration

#### Option A: Mit PostgreSQL (Empfohlen für Produktion)

PostgreSQL wird für Produktivumgebungen empfohlen, besonders wenn:
- Mehrere Storage-Systeme überwacht werden (>5)
- Hohe Logging-Aktivität besteht
- Mehrere Gunicorn Worker verwendet werden

**PostgreSQL installieren:**

```bash
# PostgreSQL installieren
sudo zypper install postgresql-server postgresql

# PostgreSQL initialisieren und starten
sudo systemctl enable postgresql
sudo systemctl start postgresql

# Datenbank und Benutzer erstellen
sudo -u postgres psql << EOF
CREATE DATABASE storage_dashboard;
CREATE USER dashboard WITH PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE storage_dashboard TO dashboard;
EOF
```

**Konfigurationsdatei erstellen:**

```bash
# Konfigurationsdatei erstellen
cp .env.example .env

# Sicheren Secret Key generieren
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" >> .env

# PostgreSQL-Verbindung konfigurieren
echo "DATABASE_URL=postgresql://dashboard:secure_password_here@localhost:5432/storage_dashboard" >> .env
echo "FLASK_ENV=production" >> .env
```

#### Option B: Mit SQLite (Nur für kleine Deployments)

**Warnung:** SQLite kann bei mehreren gleichzeitigen Zugriffen zu "database is locked" Fehlern führen. Für Produktivumgebungen wird PostgreSQL empfohlen.

```bash
# Konfigurationsdatei erstellen
cp .env.example .env

# Sicheren Secret Key generieren
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" >> .env

# SQLite-Pfad anpassen
echo "DATABASE_URL=sqlite:////opt/storage-dashboard/storage_dashboard.db" >> .env
echo "FLASK_ENV=production" >> .env
```

Siehe [DATABASE_MIGRATION.md](DATABASE_MIGRATION.md) für Details zu Datenbankoptionen.

### 4. Systemd Service einrichten

```bash
# Service-Datei kopieren (als root)
exit  # Zurück zu root
sudo cp /opt/storage-dashboard/storage-dashboard.service /etc/systemd/system/

# Service-Datei anpassen (Benutzer ändern falls nötig)
sudo nano /etc/systemd/system/storage-dashboard.service
# Ändern Sie User und Group wenn Sie einen anderen Benutzer verwenden

# Service aktivieren und starten
sudo systemctl daemon-reload
sudo systemctl enable storage-dashboard
sudo systemctl start storage-dashboard

# Status überprüfen
sudo systemctl status storage-dashboard
```

### 5. Firewall konfigurieren

```bash
# Port 5000 öffnen
sudo firewall-cmd --permanent --add-port=5000/tcp
sudo firewall-cmd --reload
```

## Nginx Reverse Proxy (empfohlen für Produktion)

### 1. Nginx installieren

```bash
sudo zypper install nginx
```

### 2. Nginx konfigurieren

```bash
sudo nano /etc/nginx/conf.d/storage-dashboard.conf
```

Fügen Sie folgende Konfiguration ein:

```nginx
server {
    listen 80;
    server_name your-server-name.example.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 3. Nginx starten

```bash
sudo systemctl enable nginx
sudo systemctl start nginx
```

### 4. SSL/TLS mit Let's Encrypt (optional)

```bash
# Certbot installieren
sudo zypper install certbot python3-certbot-nginx

# Zertifikat erstellen
sudo certbot --nginx -d your-server-name.example.com
```

## Verwaltung

### Service-Befehle

```bash
# Status prüfen
sudo systemctl status storage-dashboard

# Service neu starten
sudo systemctl restart storage-dashboard

# Service stoppen
sudo systemctl stop storage-dashboard

# Logs anzeigen
sudo journalctl -u storage-dashboard -f
```

### Backup der Datenbank

```bash
# Datenbank sichern
sudo cp /opt/storage-dashboard/storage_dashboard.db /backup/storage_dashboard_$(date +%Y%m%d).db
```

### Updates

```bash
sudo su - dashboard
cd /opt/storage-dashboard
source venv/bin/activate

# Code aktualisieren
git pull

# Abhängigkeiten aktualisieren
pip install -r requirements.txt --upgrade

# Datenbank-Migrationen ausführen (wichtig nach Updates!)
python cli.py migrate

# Service neu starten (als root)
exit
sudo systemctl restart storage-dashboard
```

## CLI-Befehle

```bash
# Als dashboard-Benutzer
sudo su - dashboard
cd /opt/storage-dashboard
source venv/bin/activate

# Dashboard anzeigen
python cli.py dashboard

# Datenbank-Migrationen ausführen
python cli.py migrate

# Systeme verwalten
python cli.py admin list
python cli.py admin add
```

## Troubleshooting

### Service startet nicht

```bash
# Logs prüfen
sudo journalctl -u storage-dashboard -n 50 --no-pager

# Manuell testen
sudo su - dashboard
cd /opt/storage-dashboard
source venv/bin/activate
python run.py
```

### Datenbankprobleme

```bash
# Schema-Fehler (z.B. "no such column")
# Führen Sie die Datenbank-Migrationen aus
sudo su - dashboard
cd /opt/storage-dashboard
source venv/bin/activate
python cli.py migrate

# Datenbank neu initialisieren (Achtung: löscht alle Daten!)
sudo su - dashboard
cd /opt/storage-dashboard
source venv/bin/activate
python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all()"
```

### Berechtigungsprobleme

```bash
# Berechtigungen korrigieren
sudo chown -R dashboard:dashboard /opt/storage-dashboard
sudo chmod 755 /opt/storage-dashboard
sudo chmod 644 /opt/storage-dashboard/*.py
```

## Sicherheitsempfehlungen

1. **Firewall**: Öffnen Sie nur notwendige Ports
2. **SSL/TLS**: Verwenden Sie HTTPS in der Produktion
3. **Benutzerrechte**: Verwenden Sie einen dedizierten Benutzer ohne Root-Rechte
4. **Backup**: Erstellen Sie regelmäßige Backups der Datenbank
5. **Updates**: Halten Sie das System und die Abhängigkeiten aktuell
6. **Secret Key**: Verwenden Sie einen sicheren, zufälligen Secret Key
7. **Storage-Credentials**: Verwenden Sie Read-Only-Accounts für Storage-Systeme

## Support

Bei Problemen oder Fragen erstellen Sie bitte ein Issue im GitHub Repository:
https://github.com/TimUx/storage-dashboard/issues
