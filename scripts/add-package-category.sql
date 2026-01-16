-- Add package_category column to vulnerabilities table
ALTER TABLE vulnerabilities
ADD COLUMN IF NOT EXISTS package_category VARCHAR(20) DEFAULT 'unknown';

-- Create index for better query performance
CREATE INDEX IF NOT EXISTS idx_vulns_package_category ON vulnerabilities(package_category);

-- Update existing records to categorize them
UPDATE vulnerabilities
SET package_category = CASE
    -- OS-level packages
    WHEN package_type IN ('debian', 'ubuntu', 'alpine', 'rhel', 'centos', 'fedora', 'amazonlinux', 'photon', 'rocky', 'almalinux', 'oraclelinux', 'suse', 'opensuse', 'arch', 'wolfi', 'deb', 'apk') THEN 'os'
    -- Application-level packages
    WHEN package_type IN ('python-pkg', 'python', 'npm', 'nodejs', 'yarn', 'pnpm', 'go-module', 'gomod', 'java', 'jar', 'maven', 'gradle', 'ruby', 'gem', 'bundler', 'php', 'composer', 'rust', 'cargo', 'nuget', 'dotnet', 'swift', 'cocoapods', 'hex', 'mix', 'node-pkg') THEN 'application'
    -- Binary/other
    WHEN package_type IN ('binary', 'gobinary') THEN 'binary'
    ELSE 'unknown'
END
WHERE package_category = 'unknown' OR package_category IS NULL;

-- Create a view for easy querying of vulnerability breakdown by category
CREATE OR REPLACE VIEW vulnerability_breakdown_by_category AS
SELECT
    i.image_name,
    i.image_tag,
    i.image_variant,
    s.scan_date,
    v.package_category,
    COUNT(*) as total_vulnerabilities,
    COUNT(CASE WHEN v.severity = 'CRITICAL' THEN 1 END) as critical_count,
    COUNT(CASE WHEN v.severity = 'HIGH' THEN 1 END) as high_count,
    COUNT(CASE WHEN v.severity = 'MEDIUM' THEN 1 END) as medium_count,
    COUNT(CASE WHEN v.severity = 'LOW' THEN 1 END) as low_count
FROM vulnerabilities v
JOIN scans s ON v.scan_id = s.id
JOIN images i ON v.image_id = i.id
WHERE s.scan_status = 'completed'
GROUP BY i.image_name, i.image_tag, i.image_variant, s.scan_date, v.package_category
ORDER BY s.scan_date DESC, i.image_name, v.package_category;

-- Create a view for latest scan breakdown by category
CREATE OR REPLACE VIEW latest_vulnerability_breakdown_by_category AS
WITH latest_scans AS (
    SELECT image_id, MAX(id) as latest_scan_id
    FROM scans
    WHERE scan_status = 'completed'
    GROUP BY image_id
)
SELECT
    i.image_name,
    i.image_tag,
    i.image_variant,
    s.scan_date,
    v.package_category,
    COUNT(*) as total_vulnerabilities,
    COUNT(CASE WHEN v.severity = 'CRITICAL' THEN 1 END) as critical_count,
    COUNT(CASE WHEN v.severity = 'HIGH' THEN 1 END) as high_count,
    COUNT(CASE WHEN v.severity = 'MEDIUM' THEN 1 END) as medium_count,
    COUNT(CASE WHEN v.severity = 'LOW' THEN 1 END) as low_count
FROM vulnerabilities v
JOIN scans s ON v.scan_id = s.id
JOIN images i ON v.image_id = i.id
JOIN latest_scans ls ON s.id = ls.latest_scan_id AND s.image_id = ls.image_id
GROUP BY i.image_name, i.image_tag, i.image_variant, s.scan_date, v.package_category
ORDER BY i.image_variant, i.image_name, v.package_category;

-- Grant permissions
GRANT SELECT ON vulnerability_breakdown_by_category TO vulnuser;
GRANT SELECT ON latest_vulnerability_breakdown_by_category TO vulnuser;

COMMENT ON COLUMN vulnerabilities.package_category IS 'Category of the package: os, application, binary, or unknown';
COMMENT ON VIEW vulnerability_breakdown_by_category IS 'Breakdown of vulnerabilities by package category over time';
COMMENT ON VIEW latest_vulnerability_breakdown_by_category IS 'Breakdown of vulnerabilities by package category for the latest scan of each image';
