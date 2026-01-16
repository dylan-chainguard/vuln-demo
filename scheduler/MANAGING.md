# Managing the Vulnerability Scanner Scheduler

## Current Configuration

The scheduler is configured to run twice daily:
- **8 AM Pacific** (4 PM UTC / 16:00 UTC)
- **6 PM Pacific** (2 AM UTC / 02:00 UTC)

**Note**: These times are for PST (Pacific Standard Time, UTC-8). During Daylight Saving Time (PDT, UTC-7), adjust by adding 1 hour to UTC times.

## How to Update the Schedule

### Method 1: Edit docker-compose.scheduler.yml (Persistent)

1. Edit the file:
```bash
nano docker-compose.scheduler.yml
```

2. Update the `SCAN_SCHEDULE` environment variable:
```yaml
environment:
  SCAN_SCHEDULE: "0 16,2 * * *"  # Change this line
```

3. Restart the scheduler:
```bash
docker-compose -f docker-compose.scheduler.yml down
docker-compose -f docker-compose.scheduler.yml up -d
```

### Method 2: Override with Environment Variable (Temporary)

```bash
# Stop current scheduler
docker-compose -f docker-compose.scheduler.yml down

# Start with custom schedule
SCAN_SCHEDULE="0 16,2 * * *" docker-compose -f docker-compose.scheduler.yml up -d
```

### Method 3: Update Running Container (Not Persistent)

**Not recommended** - changes are lost on restart. Better to use Method 1 or 2.

## Cron Expression Reference

Cron format: `minute hour day month weekday`

### Common Schedule Examples

| Description | Cron Expression | Explanation |
|-------------|----------------|-------------|
| Every hour | `0 * * * *` | At minute 0 of every hour |
| Every 6 hours | `0 */6 * * *` | At 00:00, 06:00, 12:00, 18:00 UTC |
| Twice daily (8am, 6pm PT) | `0 16,2 * * *` | At 16:00 and 02:00 UTC |
| Daily at midnight PT | `0 8 * * *` | At 08:00 UTC (midnight PST) |
| Every Monday at noon PT | `0 20 * * 1` | At 20:00 UTC on Mondays |
| First of month | `0 0 1 * *` | At 00:00 on day 1 |
| Weekdays only at 9am PT | `0 17 * * 1-5` | At 17:00 UTC Mon-Fri |

### Pacific Time to UTC Conversion

**PST (Pacific Standard Time, UTC-8):**
- 12:00 AM PT = 08:00 UTC
- 06:00 AM PT = 14:00 UTC
- 08:00 AM PT = 16:00 UTC ⬅️ Current config
- 12:00 PM PT = 20:00 UTC
- 06:00 PM PT = 02:00 UTC (next day) ⬅️ Current config
- 11:00 PM PT = 07:00 UTC (next day)

**PDT (Pacific Daylight Time, UTC-7):**
Add 1 hour to all UTC times above.

## Viewing and Monitoring

### Check Current Schedule
```bash
# View scheduler logs
docker-compose -f docker-compose.scheduler.yml logs

# Follow logs in real-time
docker-compose -f docker-compose.scheduler.yml logs -f
```

The logs will show:
```
Scan schedule: 0 16,2 * * *
Next scan scheduled for: 2026-01-14 16:00:00 +0000 UTC
```

### Check if Scheduler is Running
```bash
docker ps | grep vuln-scanner-scheduler
```

### View Recent Scan Results
```bash
# Check reports directory
ls -lh reports/baseline/
ls -lh reports/chainguard/

# Query database for latest scans
psql -h localhost -U vulnuser -d vulndb -c "SELECT scan_date, image_variant, total_vulnerabilities FROM scans ORDER BY scan_date DESC LIMIT 10;"
```

## Running Manual Scans

### Run Immediate Scan on Startup
```bash
docker-compose -f docker-compose.scheduler.yml down
RUN_IMMEDIATELY=true docker-compose -f docker-compose.scheduler.yml up -d
```

### Run One-Time Scan (Without Scheduler)
```bash
# Scan baseline
./scripts/scan-vulnerabilities.sh baseline
python3 ./scripts/load-to-database.py --variant baseline

# Scan chainguard
./scripts/scan-vulnerabilities.sh chainguard
python3 ./scripts/load-to-database.py --variant chainguard
```

## Troubleshooting

### Scheduler Not Running Scans

1. **Check logs for errors:**
```bash
docker-compose -f docker-compose.scheduler.yml logs --tail=100
```

2. **Verify cron schedule is valid:**
Use [crontab.guru](https://crontab.guru/) to validate your expression

3. **Check Docker socket access:**
```bash
docker exec vuln-scanner-scheduler docker ps
```
Should list containers. If it fails, Docker socket mount may be incorrect.

### Scans Failing

1. **Check if images exist:**
```bash
docker images | grep vuln-demo
```

2. **Verify database connectivity:**
```bash
docker exec vuln-scanner-scheduler python3 -c "import psycopg2; psycopg2.connect(host='postgres', database='vulndb', user='vulnuser', password='vulnpass')"
```

3. **Check disk space:**
```bash
df -h
du -sh reports/
```

### Restart Scheduler
```bash
docker-compose -f docker-compose.scheduler.yml restart
```

## Best Practices

1. **Keep schedule consistent** - Don't change too frequently to maintain trend data
2. **Monitor disk usage** - Reports accumulate over time; consider cleanup policy
3. **Check logs regularly** - Catch issues early
4. **Test before production** - Use `RUN_IMMEDIATELY=true` to test schedule changes
5. **Document changes** - Note when and why you changed schedules

## Cleanup Old Reports (Optional)

To prevent reports directory from growing indefinitely:

```bash
# Keep only last 30 days of reports
find reports/ -type f -mtime +30 -delete

# Or create a cleanup script
cat > scripts/cleanup-old-reports.sh << 'EOF'
#!/bin/bash
# Remove reports older than 30 days
find reports/ -type f -mtime +30 -delete
echo "Cleanup completed: $(date)"
EOF

chmod +x scripts/cleanup-old-reports.sh
```

Add to scheduler or run as separate cron job.
