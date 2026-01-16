# Grafana Vulnerability Monitoring

Interactive dashboards for visualizing vulnerability scan results with PostgreSQL datasource.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│  Trivy + Grype Scan Results                     │
│  └─ reports/{baseline|chainguard}/*.json        │
└──────────────┬──────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────┐
│  Load Script (scripts/load-to-database.py)      │
│  - Parse scan results                           │
│  - Extract metadata                             │
│  - Store in PostgreSQL                          │
└──────────────┬──────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────┐
│  PostgreSQL Database (vulndb)                   │
│  - images, scans, vulnerabilities tables        │
│  - Historical tracking with batch IDs           │
│  - Pre-built views for common queries           │
└──────────────┬──────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────┐
│  Grafana Dashboards                             │
│  - Direct SQL queries to PostgreSQL             │
│  - Interactive visualizations                   │
│  - Baseline vs Chainguard comparison            │
│  - ROI and business value analysis              │
└─────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Vulnerability scan results loaded in PostgreSQL database
- PostgreSQL database running (see main README.md for setup)

### Start Grafana

```bash
# From the monitoring directory
docker-compose up -d

# View logs
docker-compose logs -f grafana
```

### Access Grafana

```
URL: http://localhost:3001
Username: admin
Password: admin
```

The dashboards will be automatically provisioned and ready to use.

## 📊 Available Dashboards

### 1. Vulnerability Management - Comparison

Primary dashboard for vulnerability analysis:

**Panels:**
- **Vulnerabilities by Image** - Table showing vulnerability counts by service and base image
- **Top CVEs** - Most common vulnerabilities across all images
- **Vulnerabilities Over Time** - Trend chart showing vulnerability counts per scan batch
- **Resolved Vulnerabilities** - CVEs fixed between batches with exposure time
- **New Vulnerabilities** - CVEs introduced in latest batch
- **Package Category Filter** - Toggle between OS, Application, Binary, or All vulnerabilities

**Use Cases:**
- Track vulnerability trends over time
- Identify which images need attention
- Monitor vulnerability lifecycle (new/resolved)
- Filter by package type for targeted remediation

### 2. Baseline vs Chainguard Comparison

Side-by-side comparison dashboard:

**Panels:**
- **Image Size & Vulnerability Comparison** - Side-by-side stats with reduction percentages
- **Vulnerabilities Over Time (Baseline)** - Historical baseline vulnerability counts
- **Vulnerabilities Over Time (Chainguard)** - Historical Chainguard vulnerability counts
- **Combined Trend** - Baseline history + latest Chainguard for migration visualization
- **Severity breakdown** - Stacked bar charts (Critical, High, Medium, Low)

**Use Cases:**
- Demonstrate ROI of Chainguard migration
- Visualize vulnerability reduction
- Show security improvement to stakeholders
- Track image size reduction

### 3. ROI & Business Value Analysis

Business-focused metrics:

**Panels:**
- **Total Business Value** - Estimated time savings from reduced vulnerabilities
- **ROI Analysis Table** - Per-image cost-benefit breakdown
- **Critical & High Vulnerability Reduction** - Focus on high-severity improvements

**Use Cases:**
- Quantify security investment returns
- Present business case for image hardening
- Calculate developer time savings
- Justify continued investment

## 🔄 Updating Dashboard Data

Dashboards automatically refresh with new data. To add new scan results:

```bash
# From project root
# 1. Run new scans
./scripts/scan-vulnerabilities.sh baseline
./scripts/scan-vulnerabilities.sh chainguard

# 2. Load results to database
python3 scripts/load-to-database.py --variant baseline
python3 scripts/load-to-database.py --variant chainguard

# 3. Refresh Grafana dashboard in browser
# New batch will appear automatically in time-series charts
```

## 📁 Directory Structure

```
monitoring/
├── docker-compose.yml              # Grafana container definition
├── grafana/
│   ├── provisioning/
│   │   ├── datasources/           # PostgreSQL datasource config
│   │   │   └── datasource.yml
│   │   └── dashboards/            # Dashboard provisioning
│   │       └── dashboard.yml
│   └── dashboards/                # Dashboard JSON definitions
│       ├── baseline-vs-chainguard-comparison.json
│       ├── roi-business-value.json
│       └── vulnerability-database-dashboard_comparison.json
└── grafana-data/                  # Grafana persistent data (generated)
```

## 🎨 Dashboard Customization

### Edit Existing Dashboard

1. Open Grafana (http://localhost:3001)
2. Navigate to dashboard
3. Click "⚙️" (Dashboard settings) → "JSON Model"
4. Edit JSON or use UI editor
5. Save changes

**Note:** Changes made in the UI are ephemeral unless you export the JSON and save it to `grafana/dashboards/`.

### Add New Panel

1. Click "Add" → "Visualization"
2. Select "PostgreSQL" datasource
3. Write SQL query:
   ```sql
   SELECT * FROM current_vulnerabilities
   WHERE image_variant = '$variant'
   LIMIT 10;
   ```
4. Configure visualization type (table, bar chart, etc.)
5. Save dashboard

### Create Dashboard Variables

Many dashboards use template variables like `$variant`, `$scan_batch`, `$package_category`:

1. Dashboard settings → Variables → New variable
2. Set query type to "Query" with PostgreSQL datasource
3. Example query for scan batch selector:
   ```sql
   SELECT DISTINCT scan_batch_id as __value,
     'Batch #' || ROW_NUMBER() OVER (ORDER BY MIN(scan_date)) as __text
   FROM scans
   WHERE image_variant = 'baseline'
   GROUP BY scan_batch_id
   ORDER BY MIN(scan_date) DESC;
   ```

## 🔧 Configuration

### Change Grafana Port

Edit `docker-compose.yml`:
```yaml
grafana:
  ports:
    - "3001:3000"  # Change 3001 to desired port
```

### Add Additional Datasources

Add to `grafana/provisioning/datasources/datasource.yml`:
```yaml
datasources:
  - name: MyCustomDB
    type: postgres
    url: my-postgres-host:5432
    database: mydb
    user: myuser
    secureJsonData:
      password: mypassword
```

### Persistent Data

Grafana data (dashboards, settings, users) persists in the `grafana-data/` volume. To reset:

```bash
docker-compose down -v
rm -rf grafana-data/
docker-compose up -d
```

## 🔍 SQL Query Examples

Use these queries in Grafana panels or PostgreSQL directly:

**Vulnerability count by severity:**
```sql
SELECT severity, COUNT(*) as count
FROM current_vulnerabilities
WHERE image_variant = 'chainguard'
GROUP BY severity;
```

**Top 10 CVEs:**
```sql
SELECT cve_id, COUNT(*) as occurrences, severity
FROM current_vulnerabilities
WHERE image_variant = 'baseline'
GROUP BY cve_id, severity
ORDER BY occurrences DESC
LIMIT 10;
```

**Batch-to-batch comparison:**
```sql
SELECT
  scan_batch_id,
  COUNT(*) as total_vulns,
  SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical
FROM scans s
JOIN vulnerabilities v ON v.scan_id = s.id
WHERE image_variant = 'baseline'
GROUP BY scan_batch_id
ORDER BY s.scan_date;
```

## 🛑 Stop Grafana

```bash
cd monitoring
docker-compose down

# Remove all data (including dashboards)
docker-compose down -v
rm -rf grafana-data/
```

## 🐛 Troubleshooting

### Dashboard Not Loading

1. Check if Grafana is running:
   ```bash
   docker-compose ps
   ```

2. Check Grafana logs:
   ```bash
   docker-compose logs grafana
   ```

3. Verify dashboard files exist:
   ```bash
   ls -la grafana/dashboards/
   ```

### No Data in Panels

1. Verify PostgreSQL is accessible:
   ```bash
   docker exec vuln-demo-postgres psql -U vulnuser -d vulndb -c "\dt"
   ```

2. Check if scans are loaded:
   ```bash
   docker exec vuln-demo-postgres psql -U vulnuser -d vulndb -c "SELECT COUNT(*) FROM scans;"
   ```

3. Test datasource in Grafana:
   - Configuration → Data sources → PostgreSQL
   - Click "Test" button

### Permission Errors

If Grafana can't write to `grafana-data/`:
```bash
sudo chown -R 472:472 grafana-data/
```

(UID 472 is the default Grafana user in the container)

## 📚 Resources

- [Grafana Documentation](https://grafana.com/docs/)
- [Grafana PostgreSQL Datasource](https://grafana.com/docs/grafana/latest/datasources/postgres/)
- [Dashboard JSON Model](https://grafana.com/docs/grafana/latest/dashboards/json-model/)

## 🔒 Security Considerations

For production deployments:
- Change default admin password immediately
- Enable HTTPS with valid certificates
- Restrict network access to Grafana port
- Use read-only database credentials for Grafana
- Enable authentication (LDAP, OAuth, SAML)
- Review dashboard permissions

---

**Questions?** See the main project README or open an issue.
