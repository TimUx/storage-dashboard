#!/bin/bash
# Example monitoring script using the remote CLI
# This script demonstrates how to use remote-cli.py for monitoring

set -e

# Configuration
DASHBOARD_URL="${DASHBOARD_URL:-http://localhost:5000}"
ALERT_THRESHOLD="${CAPACITY_THRESHOLD:-80}"

echo "=== Storage Dashboard Monitoring ==="
echo "Dashboard URL: $DASHBOARD_URL"
echo "Capacity Threshold: $ALERT_THRESHOLD%"
echo ""

# Test connection
echo "Testing connection to dashboard..."
if ! python3 remote-cli.py --url "$DASHBOARD_URL" version > /dev/null 2>&1; then
    echo "ERROR: Cannot connect to dashboard at $DASHBOARD_URL"
    exit 1
fi
echo "✓ Connected successfully"
echo ""

# Display dashboard status
echo "=== Storage Status ==="
python3 remote-cli.py --url "$DASHBOARD_URL" dashboard

echo ""
echo "Monitoring check complete"

exit 0
