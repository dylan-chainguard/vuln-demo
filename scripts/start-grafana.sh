#!/bin/bash

set -e

echo "=========================================="
echo "Starting Vulnerability Monitoring Stack"
echo "=========================================="
echo ""

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Step 1: Prepare the data
echo "📊 Step 1: Preparing vulnerability data..."
./scripts/prepare-grafana-data.sh

echo ""
echo "🐳 Step 2: Starting Docker containers..."
cd monitoring
docker-compose up -d

echo ""
echo "⏳ Step 3: Waiting for services to be ready..."
sleep 10

# Check if Grafana is up
echo "   Checking Grafana..."
for i in {1..30}; do
    if curl -s http://localhost:3001/api/health > /dev/null 2>&1; then
        echo "   ✅ Grafana is ready!"
        break
    fi
    echo -n "."
    sleep 2
done

echo ""
echo "=========================================="
echo "✅ Monitoring Stack is Running!"
echo "=========================================="
echo ""
echo "📊 Access Points:"
echo "  Grafana:    http://localhost:3001"
echo "              (Login: admin / admin)"
echo ""
echo "  Prometheus: http://localhost:9090"
echo ""
echo "📈 Dashboard:"
echo "  The 'Vulnerability Management Dashboard' should be"
echo "  automatically loaded and available in Grafana."
echo ""
echo "💡 Tips:"
echo "  - Dashboard shows real-time vulnerability metrics"
echo "  - Data is based on the latest Trivy scans"
echo "  - Re-run './scripts/scan-vulnerabilities.sh' to update"
echo "  - Then run './scripts/prepare-grafana-data.sh' to refresh metrics"
echo ""
echo "🛑 To stop:"
echo "  cd monitoring && docker-compose down"
echo ""
