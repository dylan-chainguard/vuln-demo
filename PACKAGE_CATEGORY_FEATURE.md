# Package Category Feature - OS vs Application Level Vulnerabilities

## Overview

This feature adds automatic categorization of vulnerabilities into **OS-level** and **Application-level** packages, making it easy to understand where vulnerabilities originate.

## Database Changes

### New Column
- **`vulnerabilities.package_category`**: VARCHAR(20) - Values: `os`, `application`, `binary`, `unknown`

### New Views

1. **`vulnerability_breakdown_by_category`**: Historical breakdown by package category
2. **`latest_vulnerability_breakdown_by_category`**: Latest scan breakdown by category

## Package Type Categorization

### OS-Level Packages
Operating system packages managed by the base image:
- `debian`, `ubuntu`, `alpine`, `rhel`, `centos`, `fedora`
- `amazonlinux`, `photon`, `rocky`, `almalinux`, `oraclelinux`
- `suse`, `opensuse`, `arch`, `wolfi`

### Application-Level Packages
Language-specific packages added by your application:
- **Python**: `python-pkg`, `python`
- **JavaScript**: `npm`, `nodejs`, `yarn`, `pnpm`
- **Go**: `go-module`, `gomod`
- **Java**: `java`, `jar`, `maven`, `gradle`
- **Ruby**: `ruby`, `gem`, `bundler`
- **PHP**: `php`, `composer`
- **Rust**: `rust`, `cargo`
- **.NET**: `nuget`, `dotnet`
- **Swift**: `swift`, `cocoapods`
- **Elixir**: `hex`, `mix`

### Binary Packages
Compiled binaries:
- `binary`, `gobinary`

## Usage Examples

### Query Latest Vulnerabilities by Category

```sql
SELECT * FROM latest_vulnerability_breakdown_by_category
ORDER BY image_variant, image_name, package_category;
```

### Summary by Variant and Category

```sql
SELECT
    image_variant,
    package_category,
    SUM(total_vulnerabilities) as total_vulns,
    SUM(critical_count) as critical,
    SUM(high_count) as high,
    SUM(medium_count) as medium,
    SUM(low_count) as low
FROM latest_vulnerability_breakdown_by_category
GROUP BY image_variant, package_category
ORDER BY image_variant, package_category;
```

### Example Output (Current Data)

```
image_variant | package_category | total_vulns | critical | high | medium | low
--------------+------------------+-------------+----------+------+--------+------
baseline      | application      |          88 |        0 |   31 |     49 |    8
baseline      | binary           |          26 |        2 |    2 |     16 |    6
baseline      | os               |        1916 |        6 |  110 |    420 | 1380
baseline      | unknown          |          69 |        0 |   15 |     34 |   17
chainguard    | application      |           1 |        0 |    1 |      0 |    0
chainguard    | unknown          |           7 |        0 |    0 |      7 |    0
```

### Key Insights from Data

**Baseline Images:**
- **91.7%** of vulnerabilities are **OS-level** (1,916 out of 2,099)
- **4.2%** are **Application-level** (88 out of 2,099)
- Chainguard eliminates virtually all OS-level vulnerabilities!

**Chainguard Images:**
- **0 OS-level vulnerabilities** (down from 1,916)
- Only 1 application vulnerability + 7 unknown
- **99.6% reduction in total vulnerabilities**

### Compare Baseline vs Chainguard by Category

```sql
WITH baseline AS (
    SELECT
        package_category,
        SUM(total_vulnerabilities) as baseline_vulns,
        SUM(critical_count) as baseline_critical,
        SUM(high_count) as baseline_high
    FROM latest_vulnerability_breakdown_by_category
    WHERE image_variant = 'baseline'
    GROUP BY package_category
),
chainguard AS (
    SELECT
        package_category,
        SUM(total_vulnerabilities) as chainguard_vulns,
        SUM(critical_count) as chainguard_critical,
        SUM(high_count) as chainguard_high
    FROM latest_vulnerability_breakdown_by_category
    WHERE image_variant = 'chainguard'
    GROUP BY package_category
)
SELECT
    COALESCE(b.package_category, c.package_category) as category,
    COALESCE(b.baseline_vulns, 0) as baseline_total,
    COALESCE(c.chainguard_vulns, 0) as chainguard_total,
    COALESCE(b.baseline_vulns, 0) - COALESCE(c.chainguard_vulns, 0) as reduction,
    ROUND(
        (COALESCE(b.baseline_vulns, 0) - COALESCE(c.chainguard_vulns, 0))::numeric /
        NULLIF(COALESCE(b.baseline_vulns, 1), 0) * 100,
        1
    ) as reduction_pct
FROM baseline b
FULL OUTER JOIN chainguard c ON b.package_category = c.package_category
ORDER BY reduction DESC;
```

## Automatic Categorization

The `load-to-database.py` script now automatically categorizes new vulnerabilities using the `categorize_package_type()` function. No manual intervention needed!

## Migration Applied

File: `scripts/add-package-category.sql`

To apply to a fresh database:
```bash
docker exec -i vuln-demo-postgres psql -U vulnuser -d vulndb < ./scripts/add-package-category.sql
```

## Benefits

1. **Clear Attribution**: Know if vulnerabilities come from OS or your application code
2. **Better Prioritization**: Focus remediation efforts appropriately
3. **Vendor Comparison**: Compare base image security (Chainguard vs Standard)
4. **Supply Chain Visibility**: Track dependency sources
5. **Dashboard Enhancement**: Add category-based charts to Grafana

## Future Enhancements

1. Add Grafana dashboard panels showing OS vs Application breakdown
2. Track category trends over time
3. Alert on application-level vulnerabilities (under your control)
4. Add SBOM (Software Bill of Materials) export by category
