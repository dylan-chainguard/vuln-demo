# Vulnerability Scanner Scheduler

Automated Go-based scheduler for running vulnerability scans on baseline and Chainguard image variants on a configurable schedule.

## Overview

This service automatically orchestrates the complete vulnerability scanning pipeline:

1. **Scan images** with Trivy and Grype (both baseline and chainguard variants)
2. **Merge scan results** to deduplicate findings
3. **Load results** to PostgreSQL database for historical tracking

## Features

- **Automated Scheduling** - Uses cron to run scans on a configurable schedule
- **Immediate Execution** - Optionally run a scan immediately on startup
- **Dual Variant Support** - Scans both baseline and chainguard image variants
- **Containerized** - Runs as a Docker container with access to Docker socket
- **Comprehensive Logging** - Detailed logs for monitoring scan progress and errors
- **Database Integration** - Automatically loads results to PostgreSQL with batch tracking

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_SCHEDULE` | `0 2 * * *` | Cron expression for scan schedule (daily at 2 AM UTC) |
| `RUN_IMMEDIATELY` | `false` | Set to `true` to run a scan immediately on startup |
| `DB_HOST` | `postgres` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_NAME` | `vulndb` | Database name |
| `DB_USER` | `vulnuser` | Database user |
| `DB_PASSWORD` | `vulnpass` | Database password |

### Cron Schedule Examples

| Expression | Description |
|------------|-------------|
| `0 2 * * *` | Daily at 2 AM UTC |
| `0 */6 * * *` | Every 6 hours |
| `0 0 * * 1` | Weekly on Monday at midnight |
| `0 0 1 * *` | Monthly on the 1st at midnight |
| `*/30 * * * *` | Every 30 minutes |

## Usage

### Start with Default Schedule

```bash
# Build and start (daily at 2 AM UTC)
docker-compose -f docker-compose.scheduler.yml up -d

# View logs
docker-compose -f docker-compose.scheduler.yml logs -f
```

### Run with Immediate Scan

```bash
# Run scan immediately + continue with schedule
RUN_IMMEDIATELY=true docker-compose -f docker-compose.scheduler.yml up -d

# View progress
docker-compose -f docker-compose.scheduler.yml logs -f
```

### Custom Schedule

```bash
# Scan every 6 hours
SCAN_SCHEDULE="0 */6 * * *" docker-compose -f docker-compose.scheduler.yml up -d
```

### Stop the Scheduler

```bash
docker-compose -f docker-compose.scheduler.yml down
```

## Architecture

The scheduler:

1. **Runs as a long-lived process** inside a Docker container
2. **Has access to Docker socket** to execute scanning tools (Trivy, Grype)
3. **Executes shell scripts** from the `/scripts` directory mounted as a volume
4. **Stores scan results** in `/reports/{baseline|chainguard}` directories
5. **Loads results to PostgreSQL** using Python scripts with variant tagging

## What Gets Scanned

Each scheduled run scans:

**Baseline Variant:**
- `vuln-demo/api-service:baseline`
- `vuln-demo/frontend-service:baseline`
- `vuln-demo/worker-service:baseline`
- `vuln-demo/nginx:baseline`
- `postgres:17`
- `grafana/grafana:latest`
- `prom/prometheus:latest`
- `python:3.12`

**Chainguard Variant:**
- `vuln-demo/api-service:chainguard`
- `vuln-demo/frontend-service:chainguard`
- `vuln-demo/worker-service:chainguard`
- `vuln-demo/nginx:chainguard`
- `cgr.dev/chainguard-private/postgres:17`
- `cgr.dev/chainguard-private/grafana:latest`
- `cgr.dev/chainguard-private/prometheus:latest`
- `cgr.dev/chrisbro.com/python:3.12`

## Dependencies

**Runtime:**
- Docker CLI (in container)
- Python 3
- Trivy (auto-installed)
- Grype (auto-installed)

**Build:**
- Go 1.21+
- `github.com/robfig/cron/v3` for scheduling

## Integration

The scheduler integrates with existing project components:

- **Scanning**: Executes `scripts/scan-vulnerabilities.sh` for both variants
- **Database Loading**: Executes `scripts/load-to-database.py` with variant tagging
- **PostgreSQL**: Connects to database for storing results
- **Reports**: Reads/writes to shared `/reports` volume

## Monitoring

### View Logs

```bash
# Follow all logs
docker-compose -f docker-compose.scheduler.yml logs -f vulnerability-scanner-scheduler

# View last 50 lines
docker-compose -f docker-compose.scheduler.yml logs --tail=50 vulnerability-scanner-scheduler
```

### Log Output

The logs show:
- **Scheduler startup** and configuration
- **Next scheduled scan time**
- **Scan execution progress** (Trivy, Grype, merge, database load)
- **Vulnerability counts** per image and variant
- **Any errors** encountered during scanning or database loading

Example log output:
```
INFO: Scheduler starting with schedule: 0 2 * * *
INFO: Next scan scheduled for: 2025-01-16 02:00:00 UTC
INFO: Starting vulnerability scan (immediate run)...
INFO: Scanning baseline images...
INFO: [BASELINE] Scanning vuln-demo/api-service:baseline...
INFO: [BASELINE] Found 900+ vulnerabilities
INFO: Scanning chainguard images...
INFO: [CHAINGUARD] Scanning vuln-demo/api-service:chainguard...
INFO: [CHAINGUARD] Found 49 vulnerabilities
INFO: Loading scan results to database...
INFO: Scan complete! Next scan: 2025-01-16 02:00:00 UTC
```

## Build Locally

```bash
cd scheduler
go mod download
go build -o scheduler main.go

# Run locally (requires Docker socket access)
./scheduler
```

## Troubleshooting

### Scheduler Not Starting

Check if Docker socket is accessible:
```bash
docker-compose -f docker-compose.scheduler.yml logs vulnerability-scanner-scheduler
```

### Scans Failing

1. Verify images exist:
   ```bash
   docker images | grep vuln-demo
   ```

2. Check if scripts are executable:
   ```bash
   ls -la scripts/scan-vulnerabilities.sh
   ls -la scripts/load-to-database.py
   ```

3. Verify database connection:
   ```bash
   docker exec vuln-demo-postgres psql -U vulnuser -d vulndb -c "\dt"
   ```

### Scheduler Running But Not Scanning

Check the cron expression:
```bash
docker-compose -f docker-compose.scheduler.yml exec vulnerability-scanner-scheduler env | grep SCAN_SCHEDULE
```

Validate cron expression at [crontab.guru](https://crontab.guru/)

## Security Considerations

⚠️ **Important Security Notes:**

- The container requires access to `/var/run/docker.sock`
- This grants the container ability to run Docker commands on the host
- **Only deploy in trusted environments**
- The scripts directory is mounted read-only to prevent modification
- Consider using a read-write-execute security profile (AppArmor/SELinux) in production

## Advanced Configuration

### Custom Docker Socket Path

Edit `docker-compose.scheduler.yml`:
```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock  # Change left side for custom socket path
```

### Change Database Connection

```bash
DB_HOST=my-postgres-host DB_PORT=5433 docker-compose -f docker-compose.scheduler.yml up -d
```

### Scan Only One Variant

Modify `scheduler/main.go` to comment out one of the variant scan calls:

```go
// runVulnerabilityScan("baseline")  // Skip baseline
runVulnerabilityScan("chainguard")  // Only scan chainguard
```

Then rebuild:
```bash
docker-compose -f docker-compose.scheduler.yml build
docker-compose -f docker-compose.scheduler.yml up -d
```

---

**Questions?** See the main project README or open an issue.
