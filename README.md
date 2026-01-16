# Vulnerable Microservices Demo

A complete microservices application demonstrating **vulnerability management, scanning, and remediation workflows** with PostgreSQL-backed historical tracking and Grafana visualization. Compare baseline images vs. hardened Chainguard images side-by-side.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Nginx (80)                          │
│                    (Reverse Proxy)                          │
└────────────┬────────────────────────┬───────────────────────┘
             │                        │
    ┌────────▼────────┐      ┌───────▼────────┐
    │  Frontend (3000)│      │   API (5000)   │
    │    Node.js      │─────▶│    Python      │
    └─────────────────┘      └────────┬───────┘
                                      │
                             ┌────────▼────────┐
                             │  Postgres (5432)│
                             │   Database      │
                             └────────┬────────┘
                                      │
                             ┌────────▼────────┐
                             │   Worker        │
                             │     Java        │
                             └─────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   Vulnerability Management                  │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌──────────┐    │
│  │  Trivy   │  │  Grype   │─▶│PostgreSQL │─▶│ Grafana  │    │
│  │ Scanner  │  │ Scanner  │  │  Database │  │Dashboard │    │
│  └──────────┘  └──────────┘  └───────────┘  └──────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## 🎯 Key Features

- **Dual Image Variants**: Compare baseline vs. Chainguard hardened images
- **Multi-Scanner Approach**: Combines Trivy and Grype for comprehensive coverage
- **Historical Tracking**: PostgreSQL database tracks vulnerability trends over time
- **Interactive Dashboards**: Grafana visualizations with ROI analysis
- **Automated Scheduling**: Optional Go-based scheduler for continuous monitoring
- **Package Category Filtering**: Filter by OS packages, application dependencies, or binaries

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.9+

Trivy and Grype will be automatically installed by the scan script.

### Step 1: Build Application Images

```bash
# Build baseline images (standard vulnerable base images)
./scripts/build-images.sh baseline

# Build Chainguard images (hardened minimal base images)
./scripts/build-images.sh chainguard

# Start the application stack
docker-compose up -d
```

The application will be available at http://localhost

### Step 2: Initialize Vulnerability Database

```bash
# Initialize PostgreSQL database with schema
./database/init-db.sh
```

This creates:
- `images` table - Container image metadata and base images
- `scans` table - Individual scan executions with batch tracking
- `vulnerabilities` table - CVE findings with CVSS scores
- `vulnerability_lifecycle` table - Tracks when CVEs appear/disappear
- Helpful views for querying and visualization

### Step 3: Scan for Vulnerabilities

```bash
# Scan baseline images
./scripts/scan-vulnerabilities.sh baseline

# Scan Chainguard images
./scripts/scan-vulnerabilities.sh chainguard
```

This will:
- Scan all images (4 app services + 4 infrastructure images)
- Run both Trivy and Grype scanners
- Intelligently merge results (deduplicating by CVE + Package + Version)
- Track which tool found each vulnerability
- Generate reports in `./reports/{baseline|chainguard}/`

### Step 4: Load Scan Results to Database

```bash
# Load baseline results
python3 scripts/load-to-database.py --variant baseline

# Load Chainguard results
python3 scripts/load-to-database.py --variant chainguard
```

This will:
- Extract Docker image metadata (base images, architecture, OS)
- Store scan results with batch tracking and variant tagging
- Load individual vulnerability findings
- Track vulnerability lifecycle
- Preserve raw Trivy and Grype outputs for audit

### Step 5: View in Grafana

```bash
# Start Grafana monitoring stack
cd monitoring
docker-compose up -d
```

Access Grafana at http://localhost:3001
- **Username**: admin
- **Password**: admin

**Available Dashboards:**

1. **Vulnerability Management - Comparison**
   - Vulnerabilities by image with base image details
   - Top CVEs across all images
   - Resolved and new vulnerabilities (batch comparison)
   - Package category filtering (OS, Application, Binary, All)
   - Vulnerability trends over time

2. **Baseline vs Chainguard Comparison**
   - Side-by-side vulnerability counts
   - Image size and vulnerability reduction percentages
   - Combined trend chart showing migration impact
   - Severity-stacked bar charts

3. **ROI & Business Value Analysis**
   - Total business value of vulnerability reduction
   - ROI analysis with developer time savings
   - Cost-benefit metrics

## 📊 Understanding the Results

### Image Variants

**Baseline Variant:**
- Uses standard Docker Hub images (python:3.12, node:20-alpine, etc.)
- Typical enterprise starting point
- Contains OS-level and dependency vulnerabilities

**Chainguard Variant:**
- Uses minimal, hardened Chainguard images
- Wolfi-based (APK package manager)
- Dramatically reduced vulnerability counts
- Non-root by default

### Typical Vulnerability Reduction

| Service | Baseline | Chainguard | Reduction |
|---------|----------|------------|-----------|
| **api-service** | 900+ | 49 | ~95% |
| **frontend-service** | 140+ | 43 | ~70% |
| **worker-service** | 80+ | 3 | ~96% |
| **nginx** | 150+ | 1 | ~99% |

## 🔄 Automated Scanning (Optional)

The project includes a Go-based scheduler for automated vulnerability scanning:

```bash
# Start scheduler with daily scans at 2 AM UTC
docker-compose -f docker-compose.scheduler.yml up -d

# Run immediate scan + daily schedule
RUN_IMMEDIATELY=true docker-compose -f docker-compose.scheduler.yml up -d

# View scheduler logs
docker-compose -f docker-compose.scheduler.yml logs -f

# Stop scheduler
docker-compose -f docker-compose.scheduler.yml down
```

See [scheduler/README.md](scheduler/README.md) for configuration options.

## 📈 Tracking Trends Over Time

Each time you run a scan + load cycle, a new batch is created:

```bash
# Run new scan
./scripts/scan-vulnerabilities.sh baseline

# Load to database (creates new batch)
python3 scripts/load-to-database.py --variant baseline
```

The Grafana dashboards automatically show:
- Vulnerability trends over time (one bar per batch)
- New vulnerabilities compared to previous batch
- Resolved vulnerabilities with exposure time
- Batch-to-batch comparison

## 🧹 Cleanup

```bash
# Stop application
docker-compose down

# Stop monitoring stack
cd monitoring && docker-compose down && cd ..

# Stop scheduler (if running)
docker-compose -f docker-compose.scheduler.yml down

# Remove Docker images
docker rmi $(docker images 'vuln-demo/*' -q)

# Clean up reports (optional)
rm -rf reports/

# Reset database (optional)
docker exec vuln-demo-postgres psql -U vulnuser -d vulndb -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
./database/init-db.sh
```

## 📁 Project Structure

```
vuln-demo/
├── baseline/                   # Baseline variant Dockerfiles
│   ├── api-service/           # Python Flask API
│   ├── frontend-service/      # Node.js Express frontend
│   ├── worker-service/        # Java background worker
│   └── nginx/                 # Nginx reverse proxy
├── chainguard/                # Chainguard variant Dockerfiles
│   ├── api-service/           # Hardened Python API
│   ├── frontend-service/      # Hardened Node.js frontend
│   ├── worker-service/        # Hardened Java worker
│   └── nginx/                 # Hardened Nginx
├── database/                  # PostgreSQL schema and init scripts
│   ├── schema.sql             # Database schema with views
│   └── init-db.sh             # Initialization script
├── scripts/
│   ├── build-images.sh        # Build baseline or chainguard images
│   ├── scan-vulnerabilities.sh # Scan with Trivy + Grype
│   ├── merge-scan-results.py  # Merge scanner outputs
│   └── load-to-database.py    # Load results to PostgreSQL
├── monitoring/
│   ├── docker-compose.yml     # Grafana + Postgres datasource
│   └── grafana/
│       ├── dashboards/        # 3 pre-built dashboards
│       └── provisioning/      # Datasources and dashboard config
├── scheduler/                 # Go-based automated scanner
│   ├── main.go               # Scheduler implementation
│   └── Dockerfile            # Scheduler container
├── reports/                   # Scan results (JSON)
│   ├── baseline/             # Baseline scan results
│   └── chainguard/           # Chainguard scan results
└── docker-compose.yml         # Application stack
```

## 🔍 Database Queries

```bash
# Connect to database
docker exec -it vuln-demo-postgres psql -U vulnuser -d vulndb

# Query current vulnerabilities for a variant
SELECT * FROM current_vulnerabilities
WHERE image_variant = 'chainguard'
  AND severity IN ('CRITICAL', 'HIGH')
LIMIT 10;

# View vulnerability trends by batch
SELECT * FROM vulnerability_trends
WHERE image_variant = 'baseline';

# Compare scanner findings
SELECT * FROM scanner_comparison;

# Check top CVEs across all images
SELECT * FROM top_cves LIMIT 20;

# Get batch summary
SELECT * FROM scan_batch_summary
ORDER BY batch_date DESC;
```

## 📝 Notes

- **DO NOT** deploy this to production or expose it to the internet
- This is for **educational and demonstration purposes only**
- The baseline variant intentionally contains vulnerable dependencies
- The database preserves raw scan outputs for audit trails
- Both Trivy and Grype find different vulnerabilities - using both provides comprehensive coverage

## 📚 Resources

- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Grype Documentation](https://github.com/anchore/grype)
- [CVE Database](https://cve.mitre.org/)
- [Chainguard Images](https://www.chainguard.dev/chainguard-images)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Grafana Documentation](https://grafana.com/docs/)

## 🤝 Contributing

This is a demonstration project. Feel free to fork and adapt for your own use cases.

## 📄 License

MIT License - See LICENSE file for details
