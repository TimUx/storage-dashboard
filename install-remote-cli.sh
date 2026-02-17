#!/bin/bash
# Installation script for remote CLI
# This script installs the remote CLI on a system for remote access

set -e

echo "=== Storage Dashboard Remote CLI Installer ==="
echo ""

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "✗ Python 3 ist nicht installiert. Bitte installieren Sie Python 3.8 oder höher."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "✓ Python 3 gefunden: $(python3 --version)"

# Check for pip
if ! command -v pip3 &> /dev/null; then
    echo "✗ pip3 ist nicht installiert. Bitte installieren Sie pip3."
    exit 1
fi

echo "✓ pip3 gefunden"
echo ""

# Install dependencies
echo "Installiere Python-Abhängigkeiten..."
pip3 install --user click requests tabulate

if [ $? -eq 0 ]; then
    echo "✓ Abhängigkeiten installiert"
else
    echo "✗ Fehler beim Installieren der Abhängigkeiten"
    exit 1
fi

echo ""

# Determine installation directory
INSTALL_DIR="${HOME}/.local/bin"
if [ ! -d "$INSTALL_DIR" ]; then
    echo "Erstelle Installation-Verzeichnis: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
fi

# Copy remote-cli.py
if [ -f "remote-cli.py" ]; then
    echo "Kopiere remote-cli.py nach $INSTALL_DIR..."
    cp remote-cli.py "$INSTALL_DIR/storage-dashboard-cli"
    chmod +x "$INSTALL_DIR/storage-dashboard-cli"
    echo "✓ Remote CLI installiert als: $INSTALL_DIR/storage-dashboard-cli"
else
    echo "✗ remote-cli.py nicht gefunden. Bitte führen Sie dieses Skript im Repository-Verzeichnis aus."
    exit 1
fi

echo ""

# Check if installation directory is in PATH
if [[ ":$PATH:" == *":$INSTALL_DIR:"* ]]; then
    echo "✓ $INSTALL_DIR ist bereits im PATH"
else
    echo "⚠ $INSTALL_DIR ist nicht im PATH"
    echo ""
    echo "Fügen Sie folgende Zeile zu Ihrer ~/.bashrc oder ~/.profile hinzu:"
    echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    echo "Dann führen Sie aus: source ~/.bashrc"
fi

echo ""
echo "=== Installation abgeschlossen ==="
echo ""
echo "Verwendung:"
echo "  # Mit vollständigem Pfad"
echo "  $INSTALL_DIR/storage-dashboard-cli --url http://dashboard.example.com:5000 dashboard"
echo ""
echo "  # Wenn im PATH:"
echo "  storage-dashboard-cli --url http://dashboard.example.com:5000 dashboard"
echo ""
echo "  # Mit Umgebungsvariable:"
echo "  export DASHBOARD_URL=http://dashboard.example.com:5000"
echo "  storage-dashboard-cli dashboard"
echo ""
echo "Für weitere Informationen siehe: REMOTE_CLI.md"
