#!/usr/bin/env python3
"""
Load vulnerability scan results into PostgreSQL database
"""

import json
import sys
import os
import subprocess
import uuid
import argparse
from pathlib import Path
from datetime import datetime, timezone
import psycopg2
from psycopg2.extras import Json, execute_values

# Database configuration from environment
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '5432')),
    'database': os.getenv('DB_NAME', 'vulndb'),
    'user': os.getenv('DB_USER', 'vulnuser'),
    'password': os.getenv('DB_PASSWORD', 'vulnpass')
}

# Image variant - can be 'baseline' or 'chainguard'
IMAGE_VARIANT = os.getenv('IMAGE_VARIANT', 'baseline')

def get_db_connection():
    """Create database connection"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        sys.exit(1)

def extract_image_metadata(image_full_name, base_image_from_scan=None):
    """Extract metadata about the image using docker inspect"""
    try:
        result = subprocess.run(
            ['docker', 'inspect', image_full_name],
            capture_output=True,
            text=True,
            check=True
        )
        metadata = json.loads(result.stdout)[0]

        # Use base image from scan if provided, otherwise try docker history
        base_image = None
        base_image_tag = None

        if base_image_from_scan:
            if ':' in base_image_from_scan:
                base_image, base_image_tag = base_image_from_scan.rsplit(':', 1)
            else:
                base_image = base_image_from_scan
                base_image_tag = 'latest'
        else:
            # Fallback: Extract base image from docker history
            # For multi-stage builds, we want the LAST FROM statement (the final runtime stage)
            history_result = subprocess.run(
                ['docker', 'history', image_full_name, '--no-trunc', '--format', '{{.CreatedBy}}'],
                capture_output=True,
                text=True
            )
            last_from_line = None
            for line in history_result.stdout.split('\n'):
                if 'FROM' in line:
                    last_from_line = line

            if last_from_line:
                parts = last_from_line.split('FROM')
                if len(parts) > 1:
                    base_full = parts[1].strip().split()[0]
                    # Remove AS builder/stage aliases if present
                    if ' AS ' in base_full.upper():
                        base_full = base_full.split()[0]
                    if ':' in base_full:
                        base_image, base_image_tag = base_full.split(':', 1)
                    else:
                        base_image = base_full
                        base_image_tag = 'latest'

        return {
            'created_date': metadata['Created'],
            'size_bytes': metadata['Size'],
            'architecture': metadata['Architecture'],
            'os': metadata['Os'],
            'os_version': metadata.get('OsVersion', ''),
            'base_image': base_image,
            'base_image_tag': base_image_tag,
            'docker_metadata': metadata
        }
    except Exception as e:
        print(f"⚠️  Could not extract metadata for {image_full_name}: {e}")
        return None

def get_or_create_image(conn, image_name, image_tag, variant, metadata=None):
    """Get or create image record"""
    cur = conn.cursor()

    full_name = f"{image_name}:{image_tag}"

    # Check if image exists with this variant
    cur.execute("""
        SELECT id FROM images WHERE image_name = %s AND image_tag = %s AND image_variant = %s
    """, (image_name, image_tag, variant))

    result = cur.fetchone()
    if result:
        image_id = result[0]
        # Update last_scanned
        cur.execute("""
            UPDATE images SET last_scanned = NOW() WHERE id = %s
        """, (image_id,))
    else:
        # Create new image record
        if metadata:
            cur.execute("""
                INSERT INTO images (
                    image_name, image_tag, full_name, image_variant, base_image, base_image_tag,
                    created_date, size_bytes, architecture, os, os_version, docker_metadata
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                image_name, image_tag, full_name, variant,
                metadata.get('base_image'), metadata.get('base_image_tag'),
                metadata.get('created_date'), metadata.get('size_bytes'),
                metadata.get('architecture'), metadata.get('os'), metadata.get('os_version'),
                Json(metadata.get('docker_metadata', {}))
            ))
        else:
            cur.execute("""
                INSERT INTO images (image_name, image_tag, full_name, image_variant)
                VALUES (%s, %s, %s, %s)
                RETURNING id
            """, (image_name, image_tag, full_name, variant))

        image_id = cur.fetchone()[0]

    conn.commit()
    cur.close()
    return image_id

def create_scan_record(conn, image_id, merged_data, trivy_data, grype_data, batch_id, variant):
    """Create scan record"""
    cur = conn.cursor()

    # Get tool versions
    trivy_version = trivy_data.get('Metadata', {}).get('ImageID', '')[:50] if trivy_data else None
    grype_version = None  # Grype doesn't expose version in JSON easily

    # Get merge stats
    merge_stats = merged_data.get('MergeStats', {})

    # Count vulnerabilities by severity
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for result in merged_data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            severity = vuln.get('Severity', 'UNKNOWN').upper()
            if severity in counts:
                counts[severity] += 1

    total = sum(counts.values())

    # Create scan record
    cur.execute("""
        INSERT INTO scans (
            image_id, scan_batch_id, image_variant, trivy_version, grype_version,
            total_vulnerabilities, critical_count, high_count, medium_count, low_count,
            trivy_only_count, grype_only_count, both_tools_count,
            trivy_raw_output, grype_raw_output, merged_output,
            scan_status
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id, scan_uuid
    """, (
        image_id, batch_id, variant, trivy_version, grype_version,
        total, counts['CRITICAL'], counts['HIGH'], counts['MEDIUM'], counts['LOW'],
        merge_stats.get('trivy_only', 0),
        merge_stats.get('grype_only', 0),
        merge_stats.get('found_by_both', 0),
        Json(trivy_data) if trivy_data else None,
        Json(grype_data) if grype_data else None,
        Json(merged_data),
        'completed'
    ))

    scan_id, scan_uuid = cur.fetchone()
    conn.commit()
    cur.close()
    return scan_id, scan_uuid

def categorize_package_type(package_type):
    """Categorize package type as OS, application, binary, or unknown"""
    os_types = {'debian', 'ubuntu', 'alpine', 'rhel', 'centos', 'fedora',
                'amazonlinux', 'photon', 'rocky', 'almalinux', 'oraclelinux',
                'suse', 'opensuse', 'arch', 'wolfi'}
    app_types = {'python-pkg', 'python', 'npm', 'nodejs', 'yarn', 'pnpm',
                 'go-module', 'gomod', 'java', 'jar', 'maven', 'gradle',
                 'ruby', 'gem', 'bundler', 'php', 'composer', 'rust', 'cargo',
                 'nuget', 'dotnet', 'swift', 'cocoapods', 'hex', 'mix'}
    binary_types = {'binary', 'gobinary'}

    package_type_lower = package_type.lower()
    if package_type_lower in os_types:
        return 'os'
    elif package_type_lower in app_types:
        return 'application'
    elif package_type_lower in binary_types:
        return 'binary'
    else:
        return 'unknown'

def load_vulnerabilities(conn, scan_id, image_id, merged_data):
    """Load vulnerabilities from merged scan data"""
    cur = conn.cursor()

    vulnerabilities = []

    for result in merged_data.get('Results', []):
        package_type = result.get('Type', '')
        target = result.get('Target', '')

        for vuln in result.get('Vulnerabilities', []):
            package_category = categorize_package_type(package_type)
            vuln_record = (
                scan_id,
                image_id,
                vuln.get('VulnerabilityID', ''),
                vuln.get('PkgName', ''),
                vuln.get('InstalledVersion', ''),
                package_type,
                package_category,
                target,
                vuln.get('Severity', 'UNKNOWN').upper(),
                vuln.get('Title', ''),
                vuln.get('Description', ''),
                vuln.get('FixedVersion', ''),
                None,  # published_date - would need to parse
                None,  # modified_date
                vuln.get('FoundBy', 'unknown'),
                Json(vuln.get('References', [])),
                vuln.get('CVSSScore'),  # cvss_score
                vuln.get('CVSSVector'),  # cvss_vector
                vuln.get('CVSSV2Score'),  # cvss_v2_score
                vuln.get('CVSSV3Score'),  # cvss_v3_score
                False,  # exploit_available
                True if vuln.get('FixedVersion') else False  # patch_available
            )
            vulnerabilities.append(vuln_record)

    if vulnerabilities:
        execute_values(cur, """
            INSERT INTO vulnerabilities (
                scan_id, image_id, cve_id, package_name, package_version,
                package_type, package_category, package_path, severity, title, description,
                fixed_version, published_date, modified_date, found_by,
                reference_urls, cvss_score, cvss_vector, cvss_v2_score, cvss_v3_score,
                exploit_available, patch_available
            ) VALUES %s
            ON CONFLICT (scan_id, cve_id, package_name, package_version) DO NOTHING
        """, vulnerabilities)

        inserted_count = cur.rowcount
        conn.commit()
        cur.close()
        return inserted_count

    cur.close()
    return 0

def update_vulnerability_lifecycle(conn, image_id):
    """Update vulnerability lifecycle tracking"""
    cur = conn.cursor()

    # This would track when vulnerabilities appear and disappear
    # For now, just update first/last seen dates
    cur.execute("""
        INSERT INTO vulnerability_lifecycle (
            image_id, cve_id, package_name, package_version,
            first_seen_scan_id, last_seen_scan_id,
            first_seen_date, last_seen_date, status
        )
        SELECT
            image_id, cve_id, package_name, package_version,
            MIN(scan_id), MAX(scan_id),
            MIN(first_detected), MAX(last_detected),
            'active'
        FROM vulnerabilities
        WHERE image_id = %s
        GROUP BY image_id, cve_id, package_name, package_version
        ON CONFLICT (image_id, cve_id, package_name, package_version)
        DO UPDATE SET
            last_seen_scan_id = EXCLUDED.last_seen_scan_id,
            last_seen_date = EXCLUDED.last_seen_date,
            updated_at = NOW()
    """, (image_id,))

    conn.commit()
    cur.close()

def process_scan_file(conn, scan_file, batch_id, variant):
    """Process a single merged scan file"""
    print(f"\n📄 Processing {scan_file.name}...")

    # Load merged scan data
    with open(scan_file) as f:
        merged_data = json.load(f)

    # Get image name from filename
    image_name_parts = scan_file.stem.replace('_scan', '').replace('_', '/', 1).rsplit('_', 1)
    if len(image_name_parts) == 2:
        image_name = image_name_parts[0].replace('_', '/')
        image_tag = image_name_parts[1]
    else:
        image_name = scan_file.stem.replace('_scan', '').replace('_', '/')
        image_tag = 'latest'

    full_image_name = f"{image_name}:{image_tag}"

    # Extract base image from scan data if available
    base_image_from_scan = merged_data.get('BaseImage')

    # Extract image metadata
    print(f"  🔍 Extracting metadata for {full_image_name}...")
    if base_image_from_scan:
        print(f"      Base image from scan: {base_image_from_scan}")
    metadata = extract_image_metadata(full_image_name, base_image_from_scan)

    # Get or create image record
    print(f"  💾 Creating/updating image record (variant: {variant})...")
    image_id = get_or_create_image(conn, image_name, image_tag, variant, metadata)

    # Load individual scan files
    base_name = scan_file.stem.replace('_scan', '')
    trivy_file = scan_file.parent / f"{base_name}_trivy_scan.json"
    grype_file = scan_file.parent / f"{base_name}_grype_scan.json"

    trivy_data = None
    grype_data = None

    if trivy_file.exists():
        with open(trivy_file) as f:
            trivy_data = json.load(f)

    if grype_file.exists():
        with open(grype_file) as f:
            grype_data = json.load(f)

    # Create scan record
    print(f"  📊 Creating scan record...")
    scan_id, scan_uuid = create_scan_record(conn, image_id, merged_data, trivy_data, grype_data, batch_id, variant)

    # Load vulnerabilities
    print(f"  🐛 Loading vulnerabilities...")
    vuln_count = load_vulnerabilities(conn, scan_id, image_id, merged_data)

    # Update lifecycle
    print(f"  📈 Updating vulnerability lifecycle...")
    update_vulnerability_lifecycle(conn, image_id)

    print(f"  ✅ Loaded {vuln_count} vulnerabilities (scan_id: {scan_id}, uuid: {scan_uuid})")

    return scan_id, vuln_count

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Load vulnerability scan results into PostgreSQL database')
    parser.add_argument('--variant',
                        choices=['baseline', 'chainguard'],
                        default=IMAGE_VARIANT,
                        help='Image variant: baseline or chainguard (default: from IMAGE_VARIANT env var or baseline)')
    args = parser.parse_args()

    variant = args.variant

    print("=" * 50)
    print("Loading Vulnerability Scans to Database")
    print("=" * 50)
    print(f"Image Variant: {variant}")
    print()

    # Get script directory and reports directory
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    reports_dir = project_root / "reports" / variant

    if not reports_dir.exists():
        print(f"❌ Reports directory not found: {reports_dir}")
        sys.exit(1)

    # Find all merged scan files (exclude _trivy_scan and _grype_scan)
    scan_files = [
        f for f in sorted(reports_dir.glob("*_scan.json"))
        if '_trivy_scan' not in f.name and '_grype_scan' not in f.name
    ]

    if not scan_files:
        print(f"❌ No scan files found in {reports_dir}")
        sys.exit(1)

    print(f"📂 Found {len(scan_files)} scan files to process")

    # Connect to database
    print(f"🔌 Connecting to database at {DB_CONFIG['host']}:{DB_CONFIG['port']}...")
    conn = get_db_connection()
    print("✅ Connected to database")

    # Generate a batch ID for this scan run
    batch_id = str(uuid.uuid4())
    print(f"📦 Scan Batch ID: {batch_id}")
    print()

    # Process each scan file
    total_scans = 0
    total_vulns = 0

    for scan_file in scan_files:
        try:
            scan_id, vuln_count = process_scan_file(conn, scan_file, batch_id, variant)
            total_scans += 1
            total_vulns += vuln_count
        except Exception as e:
            print(f"❌ Error processing {scan_file.name}: {e}")
            import traceback
            traceback.print_exc()
            continue

    conn.close()

    print()
    print("=" * 50)
    print("✅ Database Loading Complete!")
    print("=" * 50)
    print()
    print(f"Variant: {variant}")
    print(f"Processed: {total_scans} scans")
    print(f"Loaded: {total_vulns} vulnerabilities")
    print()
    print("Query examples:")
    print(f"  psql -h {DB_CONFIG['host']} -U {DB_CONFIG['user']} -d {DB_CONFIG['database']} -c 'SELECT * FROM current_vulnerabilities WHERE image_variant = \\'{variant}\\' LIMIT 10;'")
    print(f"  psql -h {DB_CONFIG['host']} -U {DB_CONFIG['user']} -d {DB_CONFIG['database']} -c 'SELECT * FROM vulnerability_trends WHERE image_variant = \\'{variant}\\';'")
    print()

if __name__ == "__main__":
    main()
