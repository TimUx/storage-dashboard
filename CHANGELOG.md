# Changelog - Settings Tabs & UI Improvements

## Version: 2024-02-18

### 🎨 UI-Verbesserungen

#### Dashboard & Details
- **Border**: Dreifarbiger Gradient wurde durch einfarbige Primärfarbe (Rot) ersetzt
  - Betrifft: Dashboard Overview Card, Details Header, Admin Login Container
  - Konsistente Verwendung von `var(--itscare-red)` bzw. `#A70240`

#### Header
- **Vertikale Linie entfernt**: Trennstrich rechts neben dem Titel wurde gelöscht
- **Schrift vergrößert**: Titel-Font-Size von 1.5rem auf 1.8rem erhöht
- **Logo verkleinert**: Logo-Höhe von 50px auf 40px, Breite von 200px auf 160px reduziert
- **Icon angepasst**: Emoji-Icon von 2rem auf 1.6rem verkleinert

### ⚙️ Settings Tabs Interface

#### Neue Tab-Struktur
Die Admin-Einstellungen wurden in 4 thematische Tabs aufgeteilt:

**1. Design 🎨**
- Firmenname-Konfiguration
- Logo-Upload (PNG, JPG, SVG, GIF)
- Farbschema-Editor (Primär, Sekundär, Akzent)
- Live-Farbvorschau

**2. Logs 📋**
- Maximale Logs pro System (100-10.000)
- Aufbewahrungsdauer in Tagen (1-365)
- Minimales Log-Level (DEBUG bis CRITICAL)
- Automatische Bereinigung

**3. Zertifikate 🔒**
- Inline-Anzeige aller SSL/TLS-Zertifikate
- Quick-Actions: Bearbeiten, Download, Toggle
- Upload-Button für neue Zertifikate
- Ersetzt separate Zertifikate-Seite

**4. System ⚙️**
- Zeitzone-Auswahl (IANA-Datenbank)
- Container-TZ und App-TZ Konfiguration
- Bereit für weitere System-Einstellungen

#### Tab-Features
- Session-Persistenz (aktiver Tab wird gespeichert)
- Responsive Design mit CSS Grid
- Smooth Transitions
- Keyboard-Navigation ready

### 🌍 Timezone-Unterstützung

#### Container-Ebene
```yaml
# docker-compose.yml
environment:
  - TZ=${TZ:-Europe/Berlin}
```

#### Anwendungs-Ebene
- Neue AppSettings-Felder für Zeitzone
- Enhanced `format_datetime` Jinja2-Filter
- Automatische UTC → Local-Time Konvertierung
- Korrekte DST-Behandlung via pytz

#### Betroffene Bereiche
- Log-Zeitstempel
- Zertifikat-Erstellungszeiten
- System-Discovery-Zeiten
- Alle datetime-Anzeigen

### 📋 Log-Management

#### Neue Einstellungen
- `max_logs_per_system`: Maximale Log-Anzahl (Standard: 1.000)
- `log_retention_days`: Aufbewahrung in Tagen (Standard: 30)
- `min_log_level`: Minimales Level (Standard: INFO)

#### Automatische Bereinigung
- Löscht Logs älter als Retention-Periode
- Begrenzt auf max. Anzahl pro System
- Läuft bei jedem neuen Log-Eintrag
- Verhindert unkontrolliertes DB-Wachstum

#### Log-Level-Filterung
```
DEBUG (10)    → Alle Details
INFO (20)     → Standard
WARNING (30)  → Warnungen + Fehler
ERROR (40)    → Nur Fehler
CRITICAL (50) → Kritische Fehler
```

### 🗄️ Datenbank

#### Neue Felder in `app_settings`
```sql
timezone            VARCHAR(50)  DEFAULT 'Europe/Berlin'
max_logs_per_system INTEGER      DEFAULT 1000
log_retention_days  INTEGER      DEFAULT 30
min_log_level       VARCHAR(20)  DEFAULT 'INFO'
```

#### Migration
- Automatisch beim App-Start
- Keine manuelle Migration nötig
- Backward-kompatibel (Defaults gesetzt)

### 📦 Abhängigkeiten

#### Neu
- `pytz==2024.1` - Timezone-Handling

#### Aktualisiert
- Keine Breaking Changes

### 📁 Geänderte Dateien

| Datei | Änderungen | Zeilen |
|-------|-----------|--------|
| `app/templates/base.html` | Header-Styling | -18, +7 |
| `app/templates/dashboard.html` | Border-Fix | -2, +1 |
| `app/templates/details.html` | Border-Fix | -2, +1 |
| `app/templates/admin/login.html` | Border-Fix | -2, +1 |
| `app/templates/admin/settings_tabbed.html` | NEU | +501 |
| `app/models.py` | AppSettings erweitert | +8 |
| `app/routes/admin.py` | Settings-Route | +23 |
| `app/system_logging.py` | Log-Management | +70 |
| `app/__init__.py` | TZ-Filter | +17 |
| `docker-compose.yml` | TZ-Variable | +3 |
| `.env.example` | TZ-Config | +1 |
| `requirements.txt` | pytz | +1 |
| `SETTINGS_TABS.md` | Doku | +118 |

**Gesamt**: 13 Dateien, ~738 Zeilen geändert

### 🔒 Sicherheit

- Keine SQL-Injection (SQLAlchemy ORM)
- File-Upload-Validierung
- CSRF-Protection (Flask built-in)
- Keine exponierten Credentials

### ⚡ Performance

- Automatische Log-Bereinigung
- Effiziente TZ-Konvertierung (Cached Settings)
- Tab-Interface reduziert Page-Loads
- SessionStorage für Client-State

### 🧪 Tests

#### Manuell getestet
- [x] Tab-Switching funktioniert
- [x] Tab-Persistenz via sessionStorage
- [x] Form-Submission speichert alle Felder
- [x] Border-Änderungen auf allen Seiten
- [x] Header ohne vertikale Linie
- [x] Größere Schrift, kleineres Logo

#### Automatisiert
- [ ] Unit-Tests für Log-Management
- [ ] Integration-Tests für Settings
- [ ] E2E-Tests für Tab-Navigation

### 📝 Dokumentation

#### Neu erstellt
- `SETTINGS_TABS.md` - Benutzerhandbuch (Deutsch)
- `CHANGELOG.md` - Diese Datei
- Code-Kommentare in allen geänderten Dateien

#### Aktualisiert
- `.env.example` - TZ-Konfiguration
- Inline-Kommentare in Python-Modulen

### 🚀 Deployment

#### Neu starten erforderlich
```bash
# Mit docker-compose
docker-compose down
docker-compose up -d

# Manuell
pip install -r requirements.txt
export TZ=Europe/Berlin
python run.py
```

#### Konfiguration
```env
# .env
TZ=Europe/Berlin
SECRET_KEY=your-secret-key
DATABASE_URL=sqlite:///storage_dashboard.db
```

### 🔄 Rollback

Bei Problemen auf vorherige Version zurücksetzen:
```bash
git revert eb372b6  # Documentation
git revert 82894e9  # Settings Tabs
git revert 248bf21  # UI Fixes
```

### 🎯 Zukünftige Erweiterungen

#### Geplant
- [ ] Notification Settings Tab (Email, Slack)
- [ ] Performance Settings Tab (Timeouts, Pools)
- [ ] Security Settings Tab (2FA, Password Policy)
- [ ] Backup Settings Tab (Auto-Backup)

#### Ideen
- Dark Mode Support
- Multi-Language Support (i18n)
- Advanced Log Filtering
- Export/Import Settings

### 🐛 Known Issues

Keine bekannten Probleme zum Zeitpunkt des Releases.

### 👥 Credits

- Implementiert von: GitHub Copilot
- Review durch: TimUx
- Repository: TimUx/storage-dashboard

### 📄 Lizenz

Siehe LICENSE-Datei im Repository.

---

**Version**: 2024-02-18  
**Branch**: copilot/fix-column-alignment-and-loading-icon  
**Status**: ✅ Production Ready
