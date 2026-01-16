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
echo "Scanning Images for Vulnerabilities ($VARIANT)"
echo "=========================================="
echo ""

# Check if Trivy is installed
if ! command -v trivy &> /dev/null; then
    echo "📥 Trivy not found. Installing..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install aquasecurity/trivy/trivy
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
        echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
        sudo apt-get update
        sudo apt-get install trivy
    fi
fi

# Check if Grype is installed
if ! command -v grype &> /dev/null; then
    echo "📥 Grype not found. Installing..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install anchore/grype/grype
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
    fi
fi

# Create reports directory with variant subdirectory
REPORTS_DIR="./reports/$VARIANT"
mkdir -p "$REPORTS_DIR"

# Application images with variant tags
APP_IMAGES=(
    "vuln-demo/api-service:$VARIANT"
    "vuln-demo/frontend-service:$VARIANT"
    "vuln-demo/worker-service:$VARIANT"
    "vuln-demo/nginx:$VARIANT"
)

# Infrastructure images based on variant
if [[ "$VARIANT" == "baseline" ]]; then
    INFRA_IMAGES=(
        "postgres:13"
        "grafana/grafana:latest"
        "prom/prometheus:latest"
        "python:3.12"
    )
else  # chainguard
    INFRA_IMAGES=(
        "cgr.dev/chainguard-private/postgres:13"
        "cgr.dev/chainguard-private/grafana:latest"
        "cgr.dev/chainguard-private/prometheus:latest"
        "cgr.dev/chrisbro.com/python:3.12"
    )
fi

# Combine all images
IMAGES=("${APP_IMAGES[@]}" "${INFRA_IMAGES[@]}")

# Function to extract base image from Dockerfile
get_base_image() {
    local image=$1
    local variant=$2

    # Check if this is an app image (has a Dockerfile)
    local service_name=$(echo "$image" | sed "s/:$variant$//" | sed 's/vuln-demo\///')
    local dockerfile="/Users/chrisbroesamle/development/demo/vuln-demo/$variant/$service_name/Dockerfile"

    if [ -f "$dockerfile" ]; then
        # Get the last FROM statement that doesn't have "AS" (final stage)
        grep "^FROM" "$dockerfile" | grep -v " AS " | tail -1 | sed 's/^FROM //' | tr -d '\r'
    else
        # Infrastructure images - they ARE the base image
        echo "$image"
    fi
}

echo "Scanning ${#IMAGES[@]} images..."
echo ""

for IMAGE in "${IMAGES[@]}"; do
    IMAGE_NAME=$(echo "$IMAGE" | tr '/:' '_')

    # Extract base image info
    BASE_IMAGE=$(get_base_image "$IMAGE" "$VARIANT")
    echo "📦 Base image: $BASE_IMAGE"

    echo "🔍 Scanning $IMAGE with Trivy..."

    # Trivy scan
    trivy image \
        --severity CRITICAL,HIGH,MEDIUM,LOW \
        --format json \
        --output "$REPORTS_DIR/${IMAGE_NAME}_trivy_scan.json" \
        "$IMAGE" 2>/dev/null

    trivy image \
        --severity CRITICAL,HIGH,MEDIUM,LOW \
        --format table \
        --output "$REPORTS_DIR/${IMAGE_NAME}_scan.txt" \
        "$IMAGE" 2>/dev/null

    echo "   🔍 Scanning $IMAGE with Grype..."

    # Grype scan
    grype -q "$IMAGE" -o json > "$REPORTS_DIR/${IMAGE_NAME}_grype_scan.json" 2>/dev/null

    echo "   🔀 Merging results..."

    # Merge results with base image metadata
    python3 ./scripts/merge-scan-results.py \
        "$REPORTS_DIR/${IMAGE_NAME}_trivy_scan.json" \
        "$REPORTS_DIR/${IMAGE_NAME}_grype_scan.json" \
        "$REPORTS_DIR/${IMAGE_NAME}_scan.json" \
        "$BASE_IMAGE"

    # Quick summary from merged results
    CRITICAL=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$REPORTS_DIR/${IMAGE_NAME}_scan.json")
    HIGH=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "$REPORTS_DIR/${IMAGE_NAME}_scan.json")
    MEDIUM=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length' "$REPORTS_DIR/${IMAGE_NAME}_scan.json")
    LOW=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="LOW")] | length' "$REPORTS_DIR/${IMAGE_NAME}_scan.json")
    TOTAL=$((CRITICAL + HIGH + MEDIUM + LOW))

    echo "   ✅ Merged: $TOTAL vulnerabilities (C:$CRITICAL H:$HIGH M:$MEDIUM L:$LOW)"
    echo ""
done

echo "=========================================="
echo "✅ Vulnerability Scanning Complete!"
echo "=========================================="
echo ""
echo "📊 Reports available in: $REPORTS_DIR/"
echo ""
echo "Summary of all images:"
for IMAGE in "${IMAGES[@]}"; do
    IMAGE_NAME=$(echo "$IMAGE" | tr '/:' '_')
    if [ -f "$REPORTS_DIR/${IMAGE_NAME}_scan.json" ]; then
        CRITICAL=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$REPORTS_DIR/${IMAGE_NAME}_scan.json")
        HIGH=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "$REPORTS_DIR/${IMAGE_NAME}_scan.json")
        MEDIUM=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length' "$REPORTS_DIR/${IMAGE_NAME}_scan.json")
        LOW=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="LOW")] | length' "$REPORTS_DIR/${IMAGE_NAME}_scan.json")

        TOTAL=$((CRITICAL + HIGH + MEDIUM + LOW))
        echo "  $IMAGE: $TOTAL vulnerabilities (C:$CRITICAL H:$HIGH M:$MEDIUM L:$LOW)"
    fi
done
