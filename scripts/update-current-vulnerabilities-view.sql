-- Update current_vulnerabilities view to include package_category
DROP VIEW IF EXISTS current_vulnerabilities;
CREATE VIEW current_vulnerabilities AS
SELECT
    i.image_name,
    i.image_tag,
    i.image_variant,
    v.cve_id,
    v.package_name,
    v.package_version,
    v.package_category,
    v.severity,
    v.found_by,
    v.cvss_score,
    s.scan_date,
    s.id AS scan_id
FROM vulnerabilities v
JOIN scans s ON v.scan_id = s.id
JOIN images i ON v.image_id = i.id
WHERE s.id IN (
    SELECT MAX(id)
    FROM scans
    WHERE scan_status = 'completed'
    GROUP BY image_id
);

COMMENT ON VIEW current_vulnerabilities IS 'Current vulnerabilities from the latest scan for each image, now includes package_category';
