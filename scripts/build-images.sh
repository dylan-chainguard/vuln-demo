#!/bin/bash

set -e

# Get variant from argument (default: baseline)
VARIANT="${1:-baseline}"

if [[ "$VARIANT" != "baseline" && "$VARIANT" != "chainguard" ]]; then
    echo "❌ Invalid variant. Use 'baseline' or 'chainguard'"
    echo "Usage: $0 [baseline|chainguard]"
    exit 1
fi

echo "=========================================="
echo "Building Microservices Images ($VARIANT)"
echo "=========================================="
echo ""

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Set source directory based on variant
SRC_DIR="$VARIANT"

# Build API Service (Python)
echo "🐍 Building API Service (Python) - $VARIANT..."
docker build -t vuln-demo/api-service:$VARIANT ./$SRC_DIR/api-service
echo "✅ API Service built"
echo ""

# Build Frontend Service (Node.js)
echo "📦 Building Frontend Service (Node.js) - $VARIANT..."
docker build -t vuln-demo/frontend-service:$VARIANT ./$SRC_DIR/frontend-service
echo "✅ Frontend Service built"
echo ""

# Build Worker Service (Java)
echo "☕ Building Worker Service (Java) - $VARIANT..."
docker build -t vuln-demo/worker-service:$VARIANT ./$SRC_DIR/worker-service
echo "✅ Worker Service built"
echo ""

# Build Nginx
echo "🌐 Building Nginx - $VARIANT..."
docker build -t vuln-demo/nginx:$VARIANT ./$SRC_DIR/nginx
echo "✅ Nginx built"
echo ""

echo "=========================================="
echo "✅ All $VARIANT images built successfully!"
echo "=========================================="
echo ""
echo "Images created:"
docker images | grep vuln-demo | grep $VARIANT
