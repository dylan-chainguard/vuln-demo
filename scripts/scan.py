#!/usr/bin/env python3
"""
Docker Image Vulnerability Scanner
Builds the banking-app image and scans all images from docker-compose.yml using Grype
"""

import subprocess
import json
import os
import yaml
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import sys
from datetime import datetime


@dataclass
class VulnerabilityStats:
    """Store vulnerability statistics for an image"""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    negligible: int = 0
    unknown: int = 0

    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.negligible + self.unknown


@dataclass
class ImageVulnerabilities:
    """Store vulnerability data per image"""
    image_name: str
    os_level: VulnerabilityStats = field(default_factory=VulnerabilityStats)
    app_level: VulnerabilityStats = field(default_factory=VulnerabilityStats)


def run_command(cmd: List[str], cwd: str = None) -> Tuple[int, str, str]:
    """Run a shell command and return exit code, stdout, stderr"""
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def build_docker_image(dockerfile_path: str, image_name: str = "banking-app") -> bool:
    """Build the Docker image"""
    print(f"🔨 Building Docker image '{image_name}' from {dockerfile_path}...")
    build_dir = str(Path(dockerfile_path).parent)
    
    cmd = ["docker", "build", "-t", image_name, "-f", dockerfile_path, "."]
    exit_code, stdout, stderr = run_command(cmd, cwd=build_dir)
    
    if exit_code != 0:
        print(f"❌ Failed to build Docker image:")
        print(stderr)
        return False
    
    print(f"✅ Successfully built Docker image '{image_name}'")
    return True


def build_baseline_images(baseline_dir: str) -> List[str]:
    """Build all images in the baseline/ directory"""
    baseline_path = Path(baseline_dir)
    built_images = []
    
    print(f"\n🔨 Building all images in baseline/ directory...")
    
    # Find all Dockerfiles in subdirectories
    service_dirs = sorted([d for d in baseline_path.iterdir() if d.is_dir()])
    
    for service_dir in service_dirs:
        dockerfile = service_dir / "Dockerfile"
        if not dockerfile.exists():
            print(f"⚠️  No Dockerfile found in {service_dir.name}, skipping...")
            continue
        
        # Create image name from service directory name
        image_name = f"vuln-demo/{service_dir.name}:latest"
        
        print(f"\n📦 Building {service_dir.name}...")
        if build_docker_image(str(dockerfile), image_name):
            built_images.append(image_name)
    
    return built_images


def parse_docker_compose(compose_file: str) -> List[str]:
    """Parse docker-compose.yml and extract all image names"""
    print(f"📄 Parsing docker-compose.yml: {compose_file}")
    
    with open(compose_file, 'r') as f:
        compose_data = yaml.safe_load(f)
    
    images = []
    if 'services' in compose_data:
        for service_name, service_config in compose_data['services'].items():
            if isinstance(service_config, dict) and 'image' in service_config:
                images.append(service_config['image'])
    
    print(f"Found {len(images)} images: {', '.join(images)}")
    return images


def scan_image_with_grype(image: str) -> Dict:
    """Scan an image with grype and return JSON output"""
    print(f"🔍 Scanning image: {image}")
    
    cmd = ["grype", image, "-o", "json"]
    exit_code, stdout, stderr = run_command(cmd)
    
    if exit_code != 0:
        print(f"⚠️  Warning: Grype scan returned exit code {exit_code} for {image}")
        if stderr:
            print(f"   Error: {stderr[:200]}")
    
    try:
        grype_output = json.loads(stdout)
        return grype_output
    except json.JSONDecodeError:
        print(f"⚠️  Failed to parse grype JSON output for {image}")
        return {}


def categorize_vulnerability(vuln: Dict) -> Tuple[str, str]:
    """
    Categorize vulnerability as OS-level or Application-level
    Returns (category, package_type)
    """
    package_type = vuln.get('artifact', {}).get('type', '').lower()
    
    # OS/Container-level package managers
    os_level_types = {'deb', 'rpm', 'apk', 'jar', 'rpm'}
    
    # Application-level package managers
    app_level_types = {'npm', 'pip', 'gem', 'maven', 'composer', 'cargo', 'nuget', 'go'}
    
    if package_type in os_level_types:
        return 'os_level', package_type
    elif package_type in app_level_types:
        return 'app_level', package_type
    else:
        # Default to app_level for unknown types
        return 'app_level', package_type


def process_grype_results(grype_output: Dict) -> Tuple[VulnerabilityStats, VulnerabilityStats]:
    """
    Process grype JSON output and categorize vulnerabilities
    Returns (os_level_stats, app_level_stats)
    """
    os_stats = VulnerabilityStats()
    app_stats = VulnerabilityStats()
    
    matches = grype_output.get('matches', [])
    
    for vuln in matches:
        severity = vuln.get('vulnerability', {}).get('severity', 'unknown').lower()
        category, _ = categorize_vulnerability(vuln)
        
        # Increment appropriate severity counter
        if category == 'os_level':
            stats = os_stats
        else:
            stats = app_stats
        
        if severity == 'critical':
            stats.critical += 1
        elif severity == 'high':
            stats.high += 1
        elif severity == 'medium':
            stats.medium += 1
        elif severity == 'low':
            stats.low += 1
        elif severity == 'negligible':
            stats.negligible += 1
        else:
            stats.unknown += 1
    
    return os_stats, app_stats


def save_results_to_json(results: List[ImageVulnerabilities], output_file: str = "scan-results.json") -> str:
    """Save vulnerability results to a JSON file for later comparison"""
    output_data = {
        "timestamp": datetime.now().isoformat(),
        "images": []
    }
    
    for result in results:
        image_data = {
            "image": result.image_name,
            "os_level": {
                "critical": result.os_level.critical,
                "high": result.os_level.high,
                "medium": result.os_level.medium,
                "low": result.os_level.low,
                "negligible": result.os_level.negligible,
                "unknown": result.os_level.unknown,
                "total": result.os_level.total()
            },
            "app_level": {
                "critical": result.app_level.critical,
                "high": result.app_level.high,
                "medium": result.app_level.medium,
                "low": result.app_level.low,
                "negligible": result.app_level.negligible,
                "unknown": result.app_level.unknown,
                "total": result.app_level.total()
            },
            "total": {
                "critical": result.os_level.critical + result.app_level.critical,
                "high": result.os_level.high + result.app_level.high,
                "medium": result.os_level.medium + result.app_level.medium,
                "low": result.os_level.low + result.app_level.low,
                "negligible": result.os_level.negligible + result.app_level.negligible,
                "unknown": result.os_level.unknown + result.app_level.unknown,
                "total": result.os_level.total() + result.app_level.total()
            }
        }
        output_data["images"].append(image_data)
    
    # Calculate overall totals
    output_data["summary"] = {
        "os_level": {
            "critical": sum(r.os_level.critical for r in results),
            "high": sum(r.os_level.high for r in results),
            "medium": sum(r.os_level.medium for r in results),
            "low": sum(r.os_level.low for r in results),
            "negligible": sum(r.os_level.negligible for r in results),
            "unknown": sum(r.os_level.unknown for r in results),
            "total": sum(r.os_level.total() for r in results)
        },
        "app_level": {
            "critical": sum(r.app_level.critical for r in results),
            "high": sum(r.app_level.high for r in results),
            "medium": sum(r.app_level.medium for r in results),
            "low": sum(r.app_level.low for r in results),
            "negligible": sum(r.app_level.negligible for r in results),
            "unknown": sum(r.app_level.unknown for r in results),
            "total": sum(r.app_level.total() for r in results)
        },
        "total": {
            "critical": sum(r.os_level.critical + r.app_level.critical for r in results),
            "high": sum(r.os_level.high + r.app_level.high for r in results),
            "medium": sum(r.os_level.medium + r.app_level.medium for r in results),
            "low": sum(r.os_level.low + r.app_level.low for r in results),
            "negligible": sum(r.os_level.negligible + r.app_level.negligible for r in results),
            "unknown": sum(r.os_level.unknown + r.app_level.unknown for r in results),
            "total": sum(r.os_level.total() + r.app_level.total() for r in results)
        }
    }
    
    # Write to file
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"📊 Results saved to {output_file}")
    return output_file


def print_vulnerability_table(results: List[ImageVulnerabilities]):
    """Print a formatted vulnerability summary table"""
    print("\n" + "="*120)
    print("VULNERABILITY SUMMARY BY IMAGE AND SEVERITY")
    print("="*120)
    
    # Header
    header = (
        f"{'Image':<40} | {'Type':<12} | "
        f"{'Critical':<10} {'High':<10} {'Medium':<10} {'Low':<10} {'Negligible':<10} {'Total':<10}"
    )
    print(header)
    print("-"*120)
    
    # Data rows
    for result in results:
        # OS-level vulnerabilities
        os_total = result.os_level.total()
        print(
            f"{result.image_name:<40} | {'OS/Container':<12} | "
            f"{result.os_level.critical:<10} {result.os_level.high:<10} {result.os_level.medium:<10} "
            f"{result.os_level.low:<10} {result.os_level.negligible:<10} {os_total:<10}"
        )
        
        # Application-level vulnerabilities
        app_total = result.app_level.total()
        print(
            f"{'(continued)':<40} | {'Application':<12} | "
            f"{result.app_level.critical:<10} {result.app_level.high:<10} {result.app_level.medium:<10} "
            f"{result.app_level.low:<10} {result.app_level.negligible:<10} {app_total:<10}"
        )
        
        # Total row for this image
        total_critical = result.os_level.critical + result.app_level.critical
        total_high = result.os_level.high + result.app_level.high
        total_medium = result.os_level.medium + result.app_level.medium
        total_low = result.os_level.low + result.app_level.low
        total_negligible = result.os_level.negligible + result.app_level.negligible
        grand_total = os_total + app_total
        
        print(
            f"{'(TOTAL)':<40} | {'All':<12} | "
            f"{total_critical:<10} {total_high:<10} {total_medium:<10} "
            f"{total_low:<10} {total_negligible:<10} {grand_total:<10}"
        )
        print("-"*120)
    
    print()


def main():
    """Main function"""
    # Get the vuln-demo directory
    script_dir = Path(__file__).parent.parent
    baseline_dir = script_dir / "baseline"
    compose_file = script_dir / "docker-compose.yml"
    
    # Verify required directories exist
    if not baseline_dir.exists():
        print(f"❌ Error: baseline directory not found at {baseline_dir}")
        sys.exit(1)
    
    if not compose_file.exists():
        print(f"❌ Error: docker-compose.yml not found at {compose_file}")
        sys.exit(1)
    
    # Check if grype is installed
    exit_code, _, _ = run_command(["grype", "--version"])
    if exit_code != 0:
        print("❌ Error: grype is not installed or not in PATH")
        print("   Install grype: brew install grype (on macOS)")
        sys.exit(1)
    
    # Step 1: Build all images in the baseline/ directory
    built_images = build_baseline_images(str(baseline_dir))
    if not built_images:
        print("❌ No images were built from baseline/ directory")
        sys.exit(1)
    
    # Step 2: Parse docker-compose.yml to determine which images to scan
    images = parse_docker_compose(str(compose_file))
    if not images:
        print("❌ No images found in docker-compose.yml")
        sys.exit(1)
    
    # Step 3: Scan all images
    
    results = []
    for image in images:
        grype_output = scan_image_with_grype(image)
        if grype_output:
            os_stats, app_stats = process_grype_results(grype_output)
            results.append(ImageVulnerabilities(
                image_name=image,
                os_level=os_stats,
                app_level=app_stats
            ))
    
    # Step 4: Print summary table
    if results:
        print_vulnerability_table(results)
        
        # Step 5: Save results to JSON file
        output_file = save_results_to_json(results)
        
        # Print summary statistics
        print("\nSUMMARY STATISTICS")
        print("="*120)
        
        total_os_critical = sum(r.os_level.critical for r in results)
        total_os_high = sum(r.os_level.high for r in results)
        total_app_critical = sum(r.app_level.critical for r in results)
        total_app_high = sum(r.app_level.high for r in results)
        
        print(f"Total OS-level vulnerabilities: {sum(r.os_level.total() for r in results)}")
        print(f"  - Critical: {total_os_critical}, High: {total_os_high}")
        print(f"\nTotal Application-level vulnerabilities: {sum(r.app_level.total() for r in results)}")
        print(f"  - Critical: {total_app_critical}, High: {total_app_high}")
        
        overall_critical = total_os_critical + total_app_critical
        overall_high = total_os_high + total_app_high
        print(f"\n⚠️  CRITICAL FINDINGS:")
        print(f"  - Overall Critical: {overall_critical}")
        print(f"  - Overall High: {overall_high}")
    else:
        print("❌ No scan results available")
        sys.exit(1)
    
    print("\n✅ Scan complete!")


if __name__ == "__main__":
    main()
