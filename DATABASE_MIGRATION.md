# Database Migration Guide

## Problem: SQLite Database Locking

The Storage Dashboard uses concurrent threads to query multiple storage systems simultaneously. SQLite has limited support for concurrent writes, which can lead to "database is locked" errors when multiple threads try to write logs simultaneously.

## Solution: PostgreSQL (Recommended for Production)

PostgreSQL is recommended for production deployments, especially when:
- Running multiple gunicorn workers
- Monitoring many storage systems (>5)
- High logging activity
- Need for high availability

## Quick Migration: Docker Compose (Recommended)

### 1. Update your .env file

```bash
# Generate a PostgreSQL password
python3 -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_hex(32))" >> .env

# Add PostgreSQL configuration
echo "POSTGRES_DB=storage_dashboard" >> .env
echo "POSTGRES_USER=dashboard" >> .env
```

### 2. Stop current deployment

```bash
docker-compose down
```

### 3. Start with PostgreSQL

The updated `docker-compose.yml` now includes PostgreSQL by default:

```bash
docker-compose up -d
```

That's it! The application will automatically create all tables in PostgreSQL on first startup.

### 4. (Optional) Migrate existing data

If you have existing data in SQLite that you want to migrate:

```bash
# Export data from SQLite (while old container is still running)
docker exec storage-dashboard python cli.py export-data > backup.json

# Start new deployment with PostgreSQL
docker-compose down
docker-compose up -d

# Wait for PostgreSQL to be ready
sleep 10

# Import data to PostgreSQL
docker exec storage-dashboard python cli.py import-data < backup.json
```

Note: The `export-data` and `import-data` CLI commands need to be implemented if data migration is required.

## Manual PostgreSQL Setup

### 1. Install PostgreSQL

**SUSE Linux:**
```bash
sudo zypper install postgresql-server postgresql
sudo systemctl enable postgresql
sudo systemctl start postgresql
```

**Ubuntu/Debian:**
```bash
sudo apt-get install postgresql postgresql-contrib
sudo systemctl enable postgresql
sudo systemctl start postgresql
```

### 2. Create Database and User

```bash
sudo -u postgres psql

CREATE DATABASE storage_dashboard;
CREATE USER dashboard WITH PASSWORD 'your-secure-password';
GRANT ALL PRIVILEGES ON DATABASE storage_dashboard TO dashboard;
\q
```

### 3. Update Application Configuration

Update your `.env` file:

```bash
DATABASE_URL=postgresql://dashboard:your-secure-password@localhost:5432/storage_dashboard
```

### 4. Restart Application

```bash
sudo systemctl restart storage-dashboard
```

The application will automatically create all tables on startup.

## Keeping SQLite (Not Recommended for Production)

If you must continue using SQLite, the updated version includes improvements:

1. **WAL Mode**: Write-Ahead Logging for better concurrency
2. **Retry Logic**: Automatic retry with exponential backoff on lock errors
3. **Reduced Cleanup**: Less frequent log cleanup to reduce write contention
4. **Increased Timeout**: 30-second busy timeout

These improvements reduce but don't eliminate database locking errors.

To continue using SQLite, ensure your `.env` contains:

```bash
DATABASE_URL=sqlite:///storage_dashboard.db
```

## Performance Comparison

| Feature | SQLite | PostgreSQL |
|---------|--------|------------|
| Concurrent Writes | Limited | Excellent |
| Multiple Workers | Not recommended | Fully supported |
| Large Datasets | Good | Excellent |
| Setup Complexity | Simple | Moderate |
| Backup/Restore | File copy | pg_dump/pg_restore |
| High Availability | No | Yes |

## Troubleshooting

### PostgreSQL Connection Issues

**Error: "could not connect to server"**

Check if PostgreSQL is running:
```bash
sudo systemctl status postgresql
```

Check PostgreSQL logs:
```bash
sudo journalctl -u postgresql -n 50
```

**Error: "password authentication failed"**

Verify credentials in `.env` match PostgreSQL user:
```bash
sudo -u postgres psql
\du  # List users
```

### SQLite Still Showing Lock Errors

1. Verify WAL mode is enabled:
```bash
sqlite3 storage_dashboard.db "PRAGMA journal_mode;"
# Should show: wal
```

2. Check for multiple processes accessing the database
3. Consider reducing the number of gunicorn workers
4. Switch to PostgreSQL for production use

## Support

For issues or questions, please open an issue on GitHub.
