-- Migration: Add image_variant column to support baseline vs chainguard comparison
-- Run this on existing database to add new columns without dropping data

BEGIN;

-- Add image_variant column to images table
ALTER TABLE images
ADD COLUMN IF NOT EXISTS image_variant VARCHAR(50) DEFAULT 'baseline';

-- Add scan_batch_id column to scans table (if not already present)
ALTER TABLE scans
ADD COLUMN IF NOT EXISTS scan_batch_id UUID;

-- Add image_variant column to scans table
ALTER TABLE scans
ADD COLUMN IF NOT EXISTS image_variant VARCHAR(50) DEFAULT 'baseline';

-- Drop old unique constraint and add new one with variant
ALTER TABLE images DROP CONSTRAINT IF EXISTS unique_image_tag;
ALTER TABLE images DROP CONSTRAINT IF EXISTS unique_image_tag_variant;
ALTER TABLE images ADD CONSTRAINT unique_image_tag_variant UNIQUE(image_name, image_tag, image_variant);

-- Create indexes for new columns
CREATE INDEX IF NOT EXISTS idx_scans_variant ON scans(image_variant);
CREATE INDEX IF NOT EXISTS idx_scans_batch ON scans(scan_batch_id);
CREATE INDEX IF NOT EXISTS idx_images_variant ON images(image_variant);

-- Recreate views with new columns
DROP VIEW IF EXISTS current_vulnerabilities CASCADE;
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

DROP VIEW IF EXISTS vulnerability_trends CASCADE;
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

DROP VIEW IF EXISTS scanner_comparison CASCADE;
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

COMMIT;

-- Verify migration
SELECT
    'Images with variant' as check_type,
    COUNT(*) as count,
    image_variant
FROM images
GROUP BY image_variant;

SELECT
    'Scans with variant' as check_type,
    COUNT(*) as count,
    image_variant
FROM scans
GROUP BY image_variant;
