#!/bin/bash
# Extract FROM statements from Dockerfiles and update database with base image info

set -e

echo "======================================"
echo "Updating Base Image Information"
echo "======================================"
echo ""

# Function to extract final FROM statement (ignoring AS builder stages)
get_base_image() {
    dockerfile=$1
    # Get the last FROM statement that doesn't have "AS" (final stage)
    base=$(grep "^FROM" "$dockerfile" | grep -v " AS " | tail -1 | sed 's/^FROM //' | tr -d '\r')
    echo "$base"
}

# Function to split image:tag
split_image_tag() {
    full_image=$1
    if [[ "$full_image" == *":"* ]]; then
        image="${full_image%:*}"
        tag="${full_image##*:}"
    else
        image="$full_image"
        tag="latest"
    fi
    echo "$image|$tag"
}

# Update baseline images
echo "📦 Processing baseline images..."
for service_dir in /Users/chrisbroesamle/development/demo/vuln-demo/baseline/*/; do
    service=$(basename "$service_dir")
    dockerfile="$service_dir/Dockerfile"

    if [ -f "$dockerfile" ]; then
        base_full=$(get_base_image "$dockerfile")
        IFS='|' read -r base_image base_tag <<< "$(split_image_tag "$base_full")"

        echo "  $service: FROM $base_image:$base_tag"

        # Update database
        docker exec -i vuln-demo-postgres psql -U vulnuser -d vulndb <<SQL
UPDATE images
SET base_image = '$base_image',
    base_image_tag = '$base_tag'
WHERE image_name = 'vuln-demo/$service'
  AND image_variant = 'baseline';
SQL
    fi
done

echo ""
echo "📦 Processing chainguard images..."
for service_dir in /Users/chrisbroesamle/development/demo/vuln-demo/chainguard/*/; do
    service=$(basename "$service_dir")
    dockerfile="$service_dir/Dockerfile"

    if [ -f "$dockerfile" ]; then
        base_full=$(get_base_image "$dockerfile")
        IFS='|' read -r base_image base_tag <<< "$(split_image_tag "$base_full")"

        echo "  $service: FROM $base_image:$base_tag"

        # Update database
        docker exec -i vuln-demo-postgres psql -U vulnuser -d vulndb <<SQL
UPDATE images
SET base_image = '$base_image',
    base_image_tag = '$base_tag'
WHERE image_name = 'vuln-demo/$service'
  AND image_variant = 'chainguard';
SQL
    fi
done

echo ""
echo "======================================"
echo "✅ Base Image Information Updated"
echo "======================================"
