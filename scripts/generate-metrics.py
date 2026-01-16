#!/usr/bin/env python3
"""
Generate Grafana-compatible metrics from Trivy scan results
"""

import json
import glob
import sys
from datetime import datetime, timezone
from pathlib import Path

def main():
    # Get script directory and project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    reports_dir = project_root / "reports"
    output_dir = project_root / "monitoring" / "metrics"
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 50)
    print("Preparing Vulnerability Data for Grafana")
    print("=" * 50)
    print()

    # Initialize totals
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    images = []
    all_cves = []
    merge_stats_summary = {"trivy_only": 0, "grype_only": 0, "found_by_both": 0}

    # Process each scan file
    print("📊 Processing merged vulnerability scan results...")
    for scan_file in sorted(reports_dir.glob("*_scan.json")):
        try:
            with open(scan_file) as f:
                data = json.load(f)

            image_name = scan_file.stem.replace("_scan", "")

            # Skip individual trivy/grype scans, only process merged
            if "_trivy_scan" in str(scan_file) or "_grype_scan" in str(scan_file):
                continue

            print(f"  Processing {image_name}...")

            # Check for merge statistics
            merge_stats = data.get("MergeStats", {})
            if merge_stats:
                merge_stats_summary["trivy_only"] += merge_stats.get("trivy_only", 0)
                merge_stats_summary["grype_only"] += merge_stats.get("grype_only", 0)
                merge_stats_summary["found_by_both"] += merge_stats.get("found_by_both", 0)

            # Count vulnerabilities by severity
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    severity = vuln.get("Severity", "").lower()
                    if severity in counts:
                        counts[severity] += 1
                    all_cves.append(vuln)

            # Update totals
            for severity in counts:
                totals[severity] += counts[severity]

            total_count = sum(counts.values())
            print(f"    Critical: {counts['critical']} | High: {counts['high']} | Medium: {counts['medium']} | Low: {counts['low']}")

            # Add to images list
            images.append({
                "name": image_name,
                "vulnerabilities": {
                    "critical": counts["critical"],
                    "high": counts["high"],
                    "medium": counts["medium"],
                    "low": counts["low"],
                    "total": total_count
                }
            })

        except Exception as e:
            print(f"    Error processing {scan_file}: {e}", file=sys.stderr)

    # Create metrics JSON
    total_vulns = sum(totals.values())
    metrics = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_vulnerabilities": total_vulns,
            "by_severity": totals,
            "merge_statistics": merge_stats_summary
        },
        "images": images
    }

    # Write metrics
    metrics_file = output_dir / "vulnerability-metrics.json"
    with open(metrics_file, "w") as f:
        json.dump(metrics, f, indent=2)

    # Extract top CVEs
    print("  Extracting top CVEs...")
    cve_counts = {}
    for vuln in all_cves:
        severity = vuln.get("Severity", "")
        if severity in ["CRITICAL", "HIGH"]:
            cve_id = vuln.get("VulnerabilityID", "")
            if cve_id:
                if cve_id not in cve_counts:
                    cve_counts[cve_id] = {
                        "cve": cve_id,
                        "severity": severity,
                        "title": vuln.get("Title", ""),
                        "count": 0,
                        "packages": set()
                    }
                cve_counts[cve_id]["count"] += 1
                pkg_name = vuln.get("PkgName", "")
                if pkg_name:
                    cve_counts[cve_id]["packages"].add(pkg_name)

    # Sort by count and take top 20
    top_cves = sorted(cve_counts.values(), key=lambda x: x["count"], reverse=True)[:20]
    for cve in top_cves:
        cve["packages"] = list(cve["packages"])

    top_cves_file = output_dir / "top-cves.json"
    with open(top_cves_file, "w") as f:
        json.dump(top_cves, f, indent=2)

    # Print summary
    print()
    print("=" * 50)
    print("✅ Data Preparation Complete!")
    print("=" * 50)
    print()
    print("📈 Overall Statistics:")
    print(f"  Total Vulnerabilities: {total_vulns}")
    print(f"  Critical: {totals['critical']}")
    print(f"  High: {totals['high']}")
    print(f"  Medium: {totals['medium']}")
    print(f"  Low: {totals['low']}")
    print()
    print("🔀 Merge Statistics:")
    print(f"  Found by Trivy only: {merge_stats_summary['trivy_only']}")
    print(f"  Found by Grype only: {merge_stats_summary['grype_only']}")
    print(f"  Found by both tools: {merge_stats_summary['found_by_both']}")
    print()
    print("📁 Metrics files created:")
    print(f"  - {metrics_file}")
    print(f"  - {top_cves_file}")
    print()
    print("🚀 Ready to start Grafana:")
    print("  cd monitoring && docker-compose up -d")
    print("  Then visit: http://localhost:3001")
    print("  Login: admin / admin")
    print()

if __name__ == "__main__":
    main()
