#!/bin/bash

set -e

echo "==========================================="
echo "Initializing Vulnerability Management DB"
echo "==========================================="
echo ""

# Database configuration
DB_CONTAINER="${DB_CONTAINER:-vuln-demo-postgres}"
DB_NAME="${DB_NAME:-vulndb}"
DB_USER="${DB_USER:-vulnuser}"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Check if PostgreSQL container is running
echo "📡 Checking PostgreSQL container..."
if ! docker ps --filter "name=$DB_CONTAINER" --format "{{.Names}}" | grep -q "$DB_CONTAINER"; then
    echo "❌ PostgreSQL container $DB_CONTAINER is not running"
    echo "   Start it with: docker-compose up -d postgres"
    exit 1
fi

echo "✓ PostgreSQL container is running"
echo ""

# Check if database exists
echo "📡 Checking database connection..."
if ! docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -c '\q' 2>/dev/null; then
    echo "❌ Cannot connect to database $DB_NAME"
    echo "   The database may not exist or credentials are incorrect"
    exit 1
fi

echo "✓ Connected to database"
echo ""

# Create schema
echo "📊 Creating database schema..."
docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" < "$SCRIPT_DIR/schema.sql"

if [ $? -eq 0 ]; then
    echo "✓ Schema created successfully"
else
    echo "❌ Schema creation failed"
    exit 1
fi

echo ""

# Verify tables
echo "🔍 Verifying tables..."
TABLE_COUNT=$(docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE';")

echo "✓ Created $TABLE_COUNT tables"
echo ""

# List tables
echo "📋 Tables created:"
docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -c "\dt"

echo ""
echo "==========================================="
echo "✅ Database Initialization Complete!"
echo "==========================================="
echo ""
echo "Database: $DB_NAME"
echo "Container: $DB_CONTAINER"
echo "User: $DB_USER"
echo ""
echo "Next steps:"
echo "  1. Run vulnerability scans: ./scripts/scan-vulnerabilities.sh"
echo "  2. Load scan results: python3 scripts/load-to-database.py"
echo "  3. Query data: docker exec -it $DB_CONTAINER psql -U $DB_USER -d $DB_NAME"
echo ""
