#!/bin/sh
# Entrypoint script for storage-dashboard
# Waits for PostgreSQL to be ready before starting the application

set -e

# Retry configuration
RETRY_DELAY=2

# Only wait for PostgreSQL if DATABASE_URL points to PostgreSQL
if echo "${DATABASE_URL:-}" | grep -q "^postgresql"; then
    echo "Waiting for PostgreSQL to be ready..."
    until python -c "
import os, sys
try:
    import psycopg2
    conn = psycopg2.connect(os.environ['DATABASE_URL'], connect_timeout=2)
    conn.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; do
        echo "PostgreSQL is not ready yet - retrying in ${RETRY_DELAY} seconds..."
        sleep "${RETRY_DELAY}"
    done
    echo "PostgreSQL is ready."
fi

exec "$@"
