# Package Category Dashboard Filter Feature

## Overview

Both Grafana dashboards now include a **Package Category** filter that allows you to analyze vulnerabilities by their source: OS-level packages, application/language dependencies, binaries, or unknown packages.

## What's New

### Dashboard Updates

1. **Baseline vs Chainguard Comparison Dashboard**
   - URL: http://localhost:3003/d/baseline-chainguard-comparison
   - New "Package Category" dropdown at the top
   - All vulnerability counts, charts, and ROI calculations now respect this filter

2. **Vulnerability Database Dashboard**
   - New "Package Category" dropdown alongside the variant selector
   - All vulnerability counts and detailed views now respect this filter

### Database Updates

- Updated `current_vulnerabilities` view to include `package_category` column
- All vulnerability queries now support filtering by package category

## Package Categories

### OS (os)
Operating system packages from base images:
- debian, ubuntu, alpine, rhel, centos, fedora
- amazonlinux, photon, rocky, almalinux, oraclelinux
- suse, opensuse, arch, wolfi

### Language (application)
Application-level language packages:
- **Python**: python-pkg, python
- **JavaScript**: npm, nodejs, yarn, pnpm
- **Go**: go-module, gomod
- **Java**: java, jar, maven, gradle
- **Ruby**: ruby, gem, bundler
- **PHP**: php, composer
- **Rust**: rust, cargo
- **.NET**: nuget, dotnet
- **Swift**: swift, cocoapods
- **Elixir**: hex, mix

### Binary (binary)
Compiled binaries:
- binary, gobinary

### Unknown (unknown)
Packages that don't match any known category

## How to Use

### Basic Usage

1. Open either Grafana dashboard
2. Look for the **"Package Category"** dropdown at the top of the dashboard
3. Select a category:
   - **All** - Shows all vulnerabilities (default)
   - **OS** - Shows only OS-level vulnerabilities
   - **Language** - Shows only application/language vulnerabilities
   - **Binary** - Shows only binary vulnerabilities
   - **Unknown** - Shows only unclassified vulnerabilities

4. The entire dashboard updates automatically to show only vulnerabilities from that category

### Example Use Cases

#### 1. Compare OS-level Security: Baseline vs Chainguard

**Goal**: See how Chainguard's distroless images eliminate OS vulnerabilities

**Steps**:
1. Go to "Baseline vs Chainguard Comparison" dashboard
2. Select **"OS"** from Package Category dropdown
3. Observe the results:
   - Baseline: 2,153 OS vulnerabilities
   - Chainguard: 2 OS vulnerabilities
   - **99.9% reduction!**

**Key Insight**: Chainguard's distroless approach virtually eliminates OS-level attack surface.

#### 2. Analyze Application Dependencies

**Goal**: Understand vulnerabilities in your application code and dependencies

**Steps**:
1. Go to "Baseline vs Chainguard Comparison" dashboard
2. Select **"Language"** from Package Category dropdown
3. Observe the results:
   - Baseline: 88 application vulnerabilities
   - Chainguard: 70 application vulnerabilities
   - **20.5% reduction**

**Key Insight**: Both variants include the same application code, but some reduction occurs due to fewer transitive dependencies in minimal base images.

#### 3. Focus ROI on OS Vulnerabilities

**Goal**: Calculate business value specifically from OS-level vulnerability reduction

**Steps**:
1. Go to "Baseline vs Chainguard Comparison" dashboard
2. Select **"OS"** from Package Category dropdown
3. View the "Total Business Value" panel
4. See ROI calculation based only on OS-level Critical & High vulnerabilities

**Key Insight**: Most of the security ROI comes from eliminating OS-level vulnerabilities.

#### 4. Track Application Vulnerabilities Over Time

**Goal**: Monitor vulnerabilities in your application dependencies across scans

**Steps**:
1. Go to "Vulnerability Database Dashboard"
2. Select your image variant (baseline or chainguard)
3. Select **"Language"** from Package Category dropdown
4. View trend charts showing only application-level vulnerabilities

**Key Insight**: Application vulnerabilities are under your control and should be addressed through dependency updates.

## Current Data Snapshot

Based on the latest scan results:

### Baseline Images
| Category    | Count | % of Total |
|-------------|-------|------------|
| OS          | 2,153 | 92.1%      |
| Language    | 88    | 3.8%       |
| Binary      | 26    | 1.1%       |
| Unknown     | 70    | 3.0%       |
| **Total**   | 2,337 | 100%       |

### Chainguard Images
| Category    | Count | % of Total |
|-------------|-------|------------|
| OS          | 2     | 1.9%       |
| Language    | 70    | 68.0%      |
| Binary      | 0     | 0.0%       |
| Unknown     | 31    | 30.1%      |
| **Total**   | 103   | 100%       |

### Key Findings

1. **OS vulnerabilities dominate baseline images** (92.1%)
2. **Chainguard eliminates 99.9% of OS vulnerabilities** (2,153 → 2)
3. **Application vulnerabilities are consistent** across both variants (88 vs 70)
4. **Chainguard's remaining vulnerabilities are primarily application-level** (68.0%)

## Technical Implementation

### SQL Filter Pattern

All queries use this pattern for the filter:
```sql
-- For tables with package_category column
WHERE ... AND (NULLIF('$package_category', 'All') IS NULL OR package_category = '$package_category')

-- For specific categories
WHERE ... AND package_category = 'os'
WHERE ... AND package_category = 'application'
```

### Updated Database Objects

1. **View**: `current_vulnerabilities`
   - Now includes `package_category` column
   - Location: scripts/update-current-vulnerabilities-view.sql

2. **Dashboard Variables**: `$package_category`
   - Type: Custom dropdown
   - Values: All, OS (os), Language (application), Binary (binary), Unknown (unknown)

### Dashboard Panels Updated

**Baseline vs Chainguard Comparison Dashboard** (7 panels):
- Critical & High Vuln Reduction gauge
- Total Vulnerability Reduction gauge
- Chainguard - Vulnerabilities Over Time chart
- Baseline - Vulnerabilities Over Time chart
- Baseline vs Chainguard comparison table
- ROI Analysis table
- Total Business Value stat panel

**Vulnerability Database Dashboard** (6 panels):
- Total Vulnerabilities
- Critical Vulnerabilities
- High Vulnerabilities
- Vulnerabilities by Severity
- Top CVEs (Critical & High)
- Critical & High Vulnerabilities Detail

## Benefits

1. **Clear Attribution**: Distinguish between OS and application vulnerabilities
2. **Better Prioritization**: Focus remediation efforts appropriately
3. **Vendor Comparison**: Quantify base image security improvements
4. **Supply Chain Visibility**: Track dependency sources
5. **Accurate ROI**: Calculate business value by vulnerability source
6. **Stakeholder Communication**: Show clear responsibility boundaries

## Next Steps

1. **Create Category-Specific Alerts**: Set up alerts for application-level vulnerabilities (under your control)
2. **Add Grafana Dashboard Panels**: Create dedicated panels showing category breakdown over time
3. **SBOM Export**: Generate Software Bill of Materials by category
4. **Policy Enforcement**: Set thresholds by category (e.g., zero OS Critical/High allowed)

## Files Modified

- `/monitoring/grafana/dashboards/baseline-vs-chainguard-comparison.json`
- `/monitoring/grafana/dashboards/vulnerability-database-dashboard.json`
- `/scripts/update-current-vulnerabilities-view.sql` (new file)

## Testing

Verify the feature works:
```bash
# Test the view includes package_category
docker exec -i vuln-demo-postgres psql -U vulnuser -d vulndb -c \
  "SELECT package_category, COUNT(*) FROM current_vulnerabilities WHERE image_variant = 'baseline' GROUP BY package_category;"

# Test the filter with OS category
docker exec -i vuln-demo-postgres psql -U vulnuser -d vulndb -c \
  "SELECT COUNT(*) FROM current_vulnerabilities WHERE image_variant = 'baseline' AND (NULLIF('os', 'All') IS NULL OR package_category = 'os');"

# Test the filter with All category
docker exec -i vuln-demo-postgres psql -U vulnuser -d vulndb -c \
  "SELECT COUNT(*) FROM current_vulnerabilities WHERE image_variant = 'baseline' AND (NULLIF('All', 'All') IS NULL OR package_category = 'All');"
```

Expected results:
- First query: Shows breakdown by category (os: 2153, application: 88, binary: 26, unknown: 70)
- Second query: 2153 (OS-only vulnerabilities)
- Third query: 2337 (all vulnerabilities)
