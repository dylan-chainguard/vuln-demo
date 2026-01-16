#!/bin/bash

set -e

echo "=========================================="
echo "Deploying to Kubernetes"
echo "=========================================="
echo ""

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
K8S_DIR="$PROJECT_ROOT/k8s"

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found. Please install kubectl first."
    exit 1
fi

# Check if running in minikube
if kubectl config current-context | grep -q "minikube"; then
    echo "🎯 Using Minikube context"
    eval $(minikube docker-env)
else
    echo "🎯 Using current kubectl context: $(kubectl config current-context)"
fi

echo ""
echo "📦 Applying Kubernetes manifests..."
echo ""

# Create namespace
kubectl apply -f "$K8S_DIR/namespace.yaml"

# Deploy Postgres
echo "🐘 Deploying Postgres..."
kubectl apply -f "$K8S_DIR/postgres.yaml"

# Wait for Postgres to be ready
echo "⏳ Waiting for Postgres to be ready..."
kubectl wait --for=condition=ready pod -l app=postgres -n vuln-demo --timeout=120s

# Deploy services
echo "🐍 Deploying API Service..."
kubectl apply -f "$K8S_DIR/api-service.yaml"

echo "📦 Deploying Frontend Service..."
kubectl apply -f "$K8S_DIR/frontend-service.yaml"

echo "☕ Deploying Worker Service..."
kubectl apply -f "$K8S_DIR/worker-service.yaml"

echo "🌐 Deploying Nginx..."
kubectl apply -f "$K8S_DIR/nginx.yaml"

echo ""
echo "⏳ Waiting for deployments to be ready..."
kubectl wait --for=condition=available deployment --all -n vuln-demo --timeout=180s

echo ""
echo "=========================================="
echo "✅ Deployment Complete!"
echo "=========================================="
echo ""
echo "📊 Current status:"
kubectl get all -n vuln-demo
echo ""
echo "🌐 Access the application:"
if kubectl config current-context | grep -q "minikube"; then
    echo "   http://$(minikube ip):30080"
else
    echo "   kubectl port-forward -n vuln-demo svc/nginx 8080:80"
    echo "   Then visit: http://localhost:8080"
fi
