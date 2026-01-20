#!/usr/bin/env python3
"""
Load vulnerability artifact JSON into PostgreSQL database
Creates scan records per image with vulnerability count summaries
"""

import json
import sys
import os
import uuid
import argparse
from pathlib import Path
from datetime import datetime
import psycopg2
from psycopg2.extras import Json

# Database configuration from environment
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '5432')),
    'database': os.getenv('DB_NAME', 'vulndb'),
    'user': os.getenv('DB_USER', 'vulnuser'),
    'password': os.getenv('DB_PASSWORD', 'vulnpass')
}

# Hard coded variant
IMAGE_VARIANT = 'baseline'

def get_db_connection():
    """Create database connection"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        sys.exit(1)

def parse_image_name(full_image_name):
    """Parse image name into name and tag"""
    if ':' in full_image_name:
        image_name, image_tag = full_image_name.rsplit(':', 1)
    else:
        image_name = full_image_name
        image_tag = 'latest'
    return image_name, image_tag

def get_or_create_image(conn, image_name, image_tag, variant):
    """Check if image exists, create if not"""
    cur = conn.cursor()

    full_name = f"{image_name}:{image_tag}"

    # Check if image exists by name (image_name is UNIQUE in schema)
    cur.execute("""
        SELECT id FROM images 
        WHERE image_name = %s
    """, (image_name,))

    result = cur.fetchone()
    if result:
        image_id = result[0]
        print(f"  ✓ Image exists: {full_name} (id: {image_id})")
    else:
        # Create new image record
        print(f"  + Creating new image: {full_name}")
        cur.execute("""
            INSERT INTO images (image_name, image_tag, full_name, image_variant)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (image_name, image_tag, full_name, variant))
        image_id = cur.fetchone()[0]
        conn.commit()

    cur.close()
    return image_id

def create_scan_from_artifact(conn, image_id, image_data, batch_id, variant, timestamp):
    """Create a scan record from artifact image data"""
    cur = conn.cursor()

    # Get vulnerability counts from the artifact
    total_data = image_data.get('total', {})
    critical = total_data.get('critical', 0)
    high = total_data.get('high', 0)
    medium = total_data.get('medium', 0)
    low = total_data.get('low', 0) + total_data.get('negligible', 0)
    total = total_data.get('total', 0)

    # Create JSON structure for raw outputs
    # Using the entire image data as the scan output
    scan_json = {
        "image": image_data.get('image'),
        "os_level": image_data.get('os_level', {}),
        "app_level": image_data.get('app_level', {}),
        "total": image_data.get('total', {})
    }

    # Create scan record
    cur.execute("""
        INSERT INTO scans (
            image_id, scan_date, scan_batch_id, image_variant,
            total_vulnerabilities, critical_count, high_count, medium_count, low_count,
            trivy_raw_output, grype_raw_output, merged_output,
            scan_status
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id, scan_uuid
    """, (
        image_id, timestamp, batch_id, variant,
        total, critical, high, medium, low,
        Json(scan_json),
        Json(scan_json),
        Json(scan_json),
        'completed'
    ))

    scan_id, scan_uuid = cur.fetchone()
    conn.commit()
    cur.close()

    return scan_id, scan_uuid

def load_artifact_file(artifact_file):
    """Load artifact JSON file"""
    try:
        with open(artifact_file) as f:
            data = json.load(f)
        return data
    except Exception as e:
        print(f"❌ Error reading artifact file: {e}")
        sys.exit(1)

def main():
    print("=" * 60)
    print("Loading Artifact to Database")
    print("=" * 60)
    print()

    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Load vulnerability artifact JSON into PostgreSQL database')
    parser.add_argument('artifact_file', nargs='?', default='example-artifact.json',
                        help='Path to artifact JSON file (default: example-artifact.json)')
    args = parser.parse_args()

    # Get script directory and artifact file
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    # Resolve artifact file path
    artifact_path = Path(args.artifact_file)
    if not artifact_path.is_absolute():
        artifact_path = project_root / artifact_path
    artifact_file = artifact_path

    if not artifact_file.exists():
        print(f"❌ Artifact file not found: {artifact_file}")
        sys.exit(1)

    print(f"📄 Reading artifact file: {artifact_file.name}")
    artifact_data = load_artifact_file(artifact_file)

    # Get images from artifact
    images = artifact_data.get('images', [])
    timestamp = artifact_data.get('timestamp', None)
    if not images:
        print("❌ No images found in artifact")
        sys.exit(1)

    print(f"✓ Found {len(images)} images in artifact")
    print()

    # Connect to database
    print(f"🔌 Connecting to database at {DB_CONFIG['host']}:{DB_CONFIG['port']}...")
    conn = get_db_connection()
    print("✓ Connected to database")
    print()

    # Generate a batch ID for this scan run
    batch_id = str(uuid.uuid4())
    print(f"📦 Scan Batch ID: {batch_id}")
    print()

    # Process each image
    total_scans = 0

    for image_data in images:
        image_full_name = image_data.get('image', '')
        if not image_full_name:
            print("⚠️  Skipping image with no name")
            continue

        print(f"Processing: {image_full_name}")

        # Parse image name and tag
        image_name, image_tag = parse_image_name(image_full_name)

        # Get or create image
        image_id = get_or_create_image(conn, image_name, image_tag, IMAGE_VARIANT)

        # Create scan record
        try:
            scan_id, scan_uuid = create_scan_from_artifact(
                conn, image_id, image_data, batch_id, IMAGE_VARIANT, timestamp
            )
            print(f"  ✓ Created scan (id: {scan_id}, uuid: {scan_uuid})")
            total_scans += 1
        except Exception as e:
            print(f"  ❌ Error creating scan: {e}")
            import traceback
            traceback.print_exc()
            continue

        print()

    conn.close()

    print("=" * 60)
    print("✅ Artifact Loading Complete!")
    print("=" * 60)
    print()
    print(f"Image Variant: {IMAGE_VARIANT}")
    print(f"Batch ID: {batch_id}")
    print(f"Scans Created: {total_scans}")
    print()
    print("Verify with:")
    print(f"  psql -h {DB_CONFIG['host']} -U {DB_CONFIG['user']} -d {DB_CONFIG['database']} -c \"SELECT image_id, id, total_vulnerabilities, critical_count, high_count, medium_count, low_count FROM scans WHERE scan_batch_id = '{batch_id}';\"")
    print()

if __name__ == "__main__":
    main()
