-- Vulnerability Management Database Schema
-- Comprehensive tracking of image vulnerabilities over time

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Images table: Core information about container images
CREATE TABLE IF NOT EXISTS images (
    id SERIAL PRIMARY KEY,
    image_name VARCHAR(255) UNIQUE NOT NULL,
    image_tag VARCHAR(100) NOT NULL,
    full_name VARCHAR(512) NOT NULL, -- image_name:image_tag
    image_variant VARCHAR(50) DEFAULT 'baseline', -- 'baseline' or 'chainguard'
    base_image VARCHAR(255),
    base_image_tag VARCHAR(100),
    created_date TIMESTAMP,
    size_bytes BIGINT,
    architecture VARCHAR(50),
    os VARCHAR(100),
    os_version VARCHAR(100),
    docker_metadata JSONB, -- Full Docker inspect output
    first_scanned TIMESTAMP DEFAULT NOW(),
    last_scanned TIMESTAMP DEFAULT NOW(),
    CONSTRAINT unique_image_tag_variant UNIQUE(image_name, image_tag, image_variant)
);

-- Scans table: Individual scan execution records
CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    scan_uuid UUID UNIQUE NOT NULL DEFAULT uuid_generate_v4(),
    scan_batch_id UUID, -- Groups all images scanned in one script run
    image_id INT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    image_variant VARCHAR(50) DEFAULT 'baseline', -- 'baseline' or 'chainguard'
    scan_date TIMESTAMP DEFAULT NOW(),
    trivy_version VARCHAR(50),
    grype_version VARCHAR(50),
    total_vulnerabilities INT DEFAULT 0,
    critical_count INT DEFAULT 0,
    high_count INT DEFAULT 0,
    medium_count INT DEFAULT 0,
    low_count INT DEFAULT 0,
    trivy_only_count INT DEFAULT 0,
    grype_only_count INT DEFAULT 0,
    both_tools_count INT DEFAULT 0,
    scan_duration_seconds INT,
    scan_status VARCHAR(50) DEFAULT 'completed', -- completed, failed, in_progress
    trivy_raw_output JSONB, -- Full Trivy scan JSON
    grype_raw_output JSONB, -- Full Grype scan JSON
    merged_output JSONB, -- Merged scan JSON
    scan_metadata JSONB, -- Environment, config, etc
    created_at TIMESTAMP DEFAULT NOW()
);

-- Vulnerabilities table: Individual vulnerability findings
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    vuln_uuid UUID UNIQUE NOT NULL DEFAULT uuid_generate_v4(),
    scan_id INT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    image_id INT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    cve_id VARCHAR(50) NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    package_version VARCHAR(100),
    package_type VARCHAR(50), -- 'debian', 'python-pkg', 'node-pkg', 'gobinary', etc
    package_path VARCHAR(500), -- Path to package file
    severity VARCHAR(20) NOT NULL,
    title TEXT,
    description TEXT,
    fixed_version VARCHAR(100),
    published_date TIMESTAMP,
    modified_date TIMESTAMP,
    found_by VARCHAR(50) NOT NULL, -- 'trivy', 'grype', 'both'
    first_detected TIMESTAMP DEFAULT NOW(),
    last_detected TIMESTAMP DEFAULT NOW(),
    remediation TEXT,
    reference_urls JSONB, -- Array of reference URLs
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(255),
    cvss_v2_score DECIMAL(3,1),
    cvss_v3_score DECIMAL(3,1),
    exploit_available BOOLEAN DEFAULT FALSE,
    patch_available BOOLEAN,
    created_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT unique_scan_vuln UNIQUE(scan_id, cve_id, package_name, package_version)
);

-- Vulnerability lifecycle tracking table
CREATE TABLE IF NOT EXISTS vulnerability_lifecycle (
    id SERIAL PRIMARY KEY,
    image_id INT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    cve_id VARCHAR(50) NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    package_version VARCHAR(100),
    first_seen_scan_id INT REFERENCES scans(id),
    last_seen_scan_id INT REFERENCES scans(id),
    first_seen_date TIMESTAMP NOT NULL,
    last_seen_date TIMESTAMP NOT NULL,
    status VARCHAR(50) DEFAULT 'active', -- active, fixed, ignored
    fixed_in_scan_id INT REFERENCES scans(id),
    fixed_date TIMESTAMP,
    days_to_fix INT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT unique_lifecycle UNIQUE(image_id, cve_id, package_name, package_version)
);

-- Scan comparison table: Track changes between consecutive scans
CREATE TABLE IF NOT EXISTS scan_comparisons (
    id SERIAL PRIMARY KEY,
    image_id INT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    previous_scan_id INT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    current_scan_id INT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    new_vulnerabilities INT DEFAULT 0,
    fixed_vulnerabilities INT DEFAULT 0,
    unchanged_vulnerabilities INT DEFAULT 0,
    severity_increased INT DEFAULT 0,
    severity_decreased INT DEFAULT 0,
    comparison_date TIMESTAMP DEFAULT NOW(),
    details JSONB, -- Detailed diff information
    CONSTRAINT unique_comparison UNIQUE(previous_scan_id, current_scan_id)
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_scans_image_date ON scans(image_id, scan_date DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(scan_status);
CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(scan_date DESC);
CREATE INDEX IF NOT EXISTS idx_scans_variant ON scans(image_variant);
CREATE INDEX IF NOT EXISTS idx_scans_batch ON scans(scan_batch_id);

CREATE INDEX IF NOT EXISTS idx_images_variant ON images(image_variant);

CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_image ON vulnerabilities(image_id);
CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_package ON vulnerabilities(package_name);
CREATE INDEX IF NOT EXISTS idx_vulns_found_by ON vulnerabilities(found_by);
CREATE INDEX IF NOT EXISTS idx_vulns_image_date ON vulnerabilities(image_id, last_detected DESC);

CREATE INDEX IF NOT EXISTS idx_lifecycle_image ON vulnerability_lifecycle(image_id);
CREATE INDEX IF NOT EXISTS idx_lifecycle_cve ON vulnerability_lifecycle(cve_id);
CREATE INDEX IF NOT EXISTS idx_lifecycle_status ON vulnerability_lifecycle(status);
CREATE INDEX IF NOT EXISTS idx_lifecycle_dates ON vulnerability_lifecycle(first_seen_date, last_seen_date);

CREATE INDEX IF NOT EXISTS idx_comparisons_image ON scan_comparisons(image_id, comparison_date DESC);

-- Useful views for Grafana

-- Current vulnerabilities by image (latest scan)
CREATE OR REPLACE VIEW current_vulnerabilities AS
SELECT
    i.image_name,
    i.image_tag,
    i.image_variant,
    v.cve_id,
    v.package_name,
    v.package_version,
    v.severity,
    v.found_by,
    v.cvss_score,
    s.scan_date,
    s.id as scan_id
FROM vulnerabilities v
JOIN scans s ON v.scan_id = s.id
JOIN images i ON v.image_id = i.id
WHERE s.id IN (
    SELECT MAX(id)
    FROM scans
    WHERE scan_status = 'completed'
    GROUP BY image_id
);

-- Vulnerability trends over time
CREATE OR REPLACE VIEW vulnerability_trends AS
SELECT
    i.image_name,
    i.image_tag,
    i.image_variant,
    s.scan_batch_id,
    s.scan_date,
    s.total_vulnerabilities,
    s.critical_count,
    s.high_count,
    s.medium_count,
    s.low_count,
    s.trivy_only_count,
    s.grype_only_count,
    s.both_tools_count
FROM scans s
JOIN images i ON s.image_id = i.id
WHERE s.scan_status = 'completed'
ORDER BY i.image_name, s.scan_date;

-- Top CVEs across all images
CREATE OR REPLACE VIEW top_cves AS
SELECT
    v.cve_id,
    v.severity,
    COUNT(DISTINCT v.image_id) as affected_images,
    COUNT(DISTINCT v.package_name) as affected_packages,
    MAX(v.cvss_score) as max_cvss_score,
    MIN(v.first_detected) as first_detected,
    MAX(v.last_detected) as last_detected
FROM vulnerabilities v
JOIN scans s ON v.scan_id = s.id
WHERE s.id IN (
    SELECT MAX(id)
    FROM scans
    WHERE scan_status = 'completed'
    GROUP BY image_id
)
GROUP BY v.cve_id, v.severity
ORDER BY affected_images DESC, max_cvss_score DESC;

-- Scanner comparison statistics
CREATE OR REPLACE VIEW scanner_comparison AS
SELECT
    i.image_name,
    i.image_tag,
    i.image_variant,
    s.scan_date,
    SUM(CASE WHEN v.found_by = 'trivy' THEN 1 ELSE 0 END) as trivy_only,
    SUM(CASE WHEN v.found_by = 'grype' THEN 1 ELSE 0 END) as grype_only,
    SUM(CASE WHEN v.found_by LIKE '%,%' THEN 1 ELSE 0 END) as both_tools,
    COUNT(*) as total
FROM vulnerabilities v
JOIN scans s ON v.scan_id = s.id
JOIN images i ON v.image_id = i.id
WHERE s.id IN (
    SELECT MAX(id)
    FROM scans
    WHERE scan_status = 'completed'
    GROUP BY image_id
)
GROUP BY i.image_name, i.image_tag, i.image_variant, s.scan_date;

-- Comments
COMMENT ON TABLE images IS 'Container images being scanned for vulnerabilities';
COMMENT ON TABLE scans IS 'Individual vulnerability scan executions';
COMMENT ON TABLE vulnerabilities IS 'Individual vulnerability findings from scans';
COMMENT ON TABLE vulnerability_lifecycle IS 'Tracks when vulnerabilities appear and get fixed';
COMMENT ON TABLE scan_comparisons IS 'Tracks changes between consecutive scans';

COMMENT ON COLUMN scans.trivy_raw_output IS 'Full Trivy JSON output for audit trail';
COMMENT ON COLUMN scans.grype_raw_output IS 'Full Grype JSON output for audit trail';
COMMENT ON COLUMN vulnerabilities.found_by IS 'Which tool(s) detected this: trivy, grype, or both';
