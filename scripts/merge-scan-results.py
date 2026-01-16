#!/usr/bin/env python3
"""
Merge Trivy and Grype scan results, deduplicating vulnerabilities
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

def normalize_severity(severity):
    """Normalize severity to uppercase"""
    return severity.upper() if severity else "UNKNOWN"

def parse_trivy_results(trivy_data):
    """Parse Trivy JSON format and extract vulnerabilities"""
    vulnerabilities = []

    for result in trivy_data.get("Results", []):
        target = result.get("Target", "")
        vuln_type = result.get("Type", "")

        for vuln in result.get("Vulnerabilities", []):
            # Extract CVSS scores from CVSS field
            cvss_data = vuln.get("CVSS", {})
            cvss_v2_score = None
            cvss_v3_score = None
            cvss_vector = None

            # Try to get scores from various sources (nvd, redhat, etc.)
            for source_data in cvss_data.values():
                if isinstance(source_data, dict):
                    if not cvss_v2_score and "V2Score" in source_data:
                        cvss_v2_score = source_data["V2Score"]
                    if not cvss_v3_score and "V3Score" in source_data:
                        cvss_v3_score = source_data["V3Score"]
                    if not cvss_vector and "V3Vector" in source_data:
                        cvss_vector = source_data["V3Vector"]
                    elif not cvss_vector and "V2Vector" in source_data:
                        cvss_vector = source_data["V2Vector"]

            # Use highest score as main CVSS score
            cvss_score = cvss_v3_score or cvss_v2_score

            normalized = {
                "id": vuln.get("VulnerabilityID", ""),
                "package": vuln.get("PkgName", ""),
                "version": vuln.get("InstalledVersion", ""),
                "severity": normalize_severity(vuln.get("Severity", "")),
                "title": vuln.get("Title", ""),
                "description": vuln.get("Description", ""),
                "fixed_version": vuln.get("FixedVersion", ""),
                "cvss_score": cvss_score,
                "cvss_v2_score": cvss_v2_score,
                "cvss_v3_score": cvss_v3_score,
                "cvss_vector": cvss_vector,
                "references": vuln.get("References", []),
                "target": target,
                "type": vuln_type,
                "source": "trivy"
            }
            vulnerabilities.append(normalized)

    return vulnerabilities

def parse_grype_results(grype_data):
    """Parse Grype JSON format and extract vulnerabilities"""
    vulnerabilities = []

    for match in grype_data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        # Grype doesn't have CVSS in the same format, set to None
        normalized = {
            "id": vuln.get("id", ""),
            "package": artifact.get("name", ""),
            "version": artifact.get("version", ""),
            "severity": normalize_severity(vuln.get("severity", "")),
            "title": "",  # Grype doesn't provide title
            "description": vuln.get("description", ""),
            "fixed_version": vuln.get("fix", {}).get("versions", [""])[0] if vuln.get("fix", {}).get("versions") else "",
            "cvss_score": None,
            "cvss_v2_score": None,
            "cvss_v3_score": None,
            "cvss_vector": None,
            "references": vuln.get("urls", []),
            "target": artifact.get("type", ""),
            "type": artifact.get("type", ""),
            "source": "grype"
        }
        vulnerabilities.append(normalized)

    return vulnerabilities

def create_vuln_key(vuln):
    """Create unique key for deduplication"""
    # Key = CVE ID + Package Name + Package Version
    return (
        vuln["id"],
        vuln["package"].lower(),
        vuln["version"]
    )

def merge_vulnerabilities(trivy_vulns, grype_vulns):
    """Merge vulnerabilities from both sources, removing duplicates"""
    merged = {}
    stats = {
        "trivy_only": 0,
        "grype_only": 0,
        "both": 0
    }

    # Add all Trivy vulnerabilities
    for vuln in trivy_vulns:
        key = create_vuln_key(vuln)
        vuln["found_by"] = ["trivy"]
        merged[key] = vuln

    # Add or merge Grype vulnerabilities
    for vuln in grype_vulns:
        key = create_vuln_key(vuln)

        if key in merged:
            # Duplicate found - merge information
            existing = merged[key]
            existing["found_by"].append("grype")

            # Keep more detailed description
            if len(vuln["description"]) > len(existing["description"]):
                existing["description"] = vuln["description"]

            # Keep fixed version if not present
            if not existing["fixed_version"] and vuln["fixed_version"]:
                existing["fixed_version"] = vuln["fixed_version"]

            # Merge references (URLs) from both sources
            existing_refs = set(existing.get("references", []))
            new_refs = set(vuln.get("references", []))
            existing["references"] = list(existing_refs | new_refs)

            # Keep CVSS from Trivy (Grype doesn't have it)
            # Trivy data already has CVSS, Grype has None

            stats["both"] += 1
        else:
            # New vulnerability from Grype
            vuln["found_by"] = ["grype"]
            merged[key] = vuln
            stats["grype_only"] += 1

    # Count Trivy-only
    stats["trivy_only"] = sum(1 for v in merged.values() if v["found_by"] == ["trivy"])

    return list(merged.values()), stats

def create_trivy_compatible_output(merged_vulns, original_trivy_data):
    """Create output in Trivy JSON format with merged results"""

    # Group vulnerabilities by target
    by_target = defaultdict(list)
    for vuln in merged_vulns:
        target = vuln.get("target", "merged")
        by_target[target].append(vuln)

    # Create Results array
    results = []
    for target, vulns in by_target.items():
        # Convert back to Trivy format
        trivy_vulns = []
        for v in vulns:
            trivy_vuln = {
                "VulnerabilityID": v["id"],
                "PkgName": v["package"],
                "InstalledVersion": v["version"],
                "Severity": v["severity"],
                "Title": v["title"],
                "Description": v["description"],
                "FixedVersion": v["fixed_version"],
                "References": v.get("references", []),
                "FoundBy": ",".join(v["found_by"])  # Custom field
            }

            # Add CVSS scores if available
            if v.get("cvss_score"):
                trivy_vuln["CVSSScore"] = v["cvss_score"]
            if v.get("cvss_v2_score"):
                trivy_vuln["CVSSV2Score"] = v["cvss_v2_score"]
            if v.get("cvss_v3_score"):
                trivy_vuln["CVSSV3Score"] = v["cvss_v3_score"]
            if v.get("cvss_vector"):
                trivy_vuln["CVSSVector"] = v["cvss_vector"]

            trivy_vulns.append(trivy_vuln)

        result = {
            "Target": target,
            "Type": vulns[0]["type"] if vulns else "",
            "Vulnerabilities": trivy_vulns
        }
        results.append(result)

    # Create full output
    output = {
        "SchemaVersion": original_trivy_data.get("SchemaVersion", 2),
        "ArtifactName": original_trivy_data.get("ArtifactName", ""),
        "ArtifactType": original_trivy_data.get("ArtifactType", ""),
        "Metadata": original_trivy_data.get("Metadata", {}),
        "Results": results
    }

    return output

def main():
    if len(sys.argv) < 4:
        print("Usage: merge-scan-results.py <trivy.json> <grype.json> <output.json> [base_image]")
        sys.exit(1)

    trivy_file = Path(sys.argv[1])
    grype_file = Path(sys.argv[2])
    output_file = Path(sys.argv[3])
    base_image = sys.argv[4] if len(sys.argv) > 4 else None

    # Load input files
    try:
        with open(trivy_file) as f:
            trivy_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Trivy file not found: {trivy_file}")
        sys.exit(1)

    try:
        with open(grype_file) as f:
            grype_data = json.load(f)
    except FileNotFoundError:
        print(f"Warning: Grype file not found: {grype_file}, using Trivy data only")
        grype_data = {"matches": []}

    # Parse vulnerabilities
    trivy_vulns = parse_trivy_results(trivy_data)
    grype_vulns = parse_grype_results(grype_data)

    # Merge
    merged_vulns, stats = merge_vulnerabilities(trivy_vulns, grype_vulns)

    # Create output
    output = create_trivy_compatible_output(merged_vulns, trivy_data)

    # Add merge statistics as metadata
    output["MergeStats"] = {
        "trivy_count": len(trivy_vulns),
        "grype_count": len(grype_vulns),
        "merged_count": len(merged_vulns),
        "trivy_only": stats["trivy_only"],
        "grype_only": stats["grype_only"],
        "found_by_both": stats["both"]
    }

    # Add base image metadata if provided
    if base_image:
        output["BaseImage"] = base_image

    # Write output
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)

    # Print summary
    image_name = trivy_file.stem.replace("_scan", "")
    print(f"✓ Merged {image_name}:")
    print(f"  Trivy: {len(trivy_vulns)} | Grype: {len(grype_vulns)} | Merged: {len(merged_vulns)}")
    print(f"  Trivy-only: {stats['trivy_only']} | Grype-only: {stats['grype_only']} | Both: {stats['both']}")

if __name__ == "__main__":
    main()
