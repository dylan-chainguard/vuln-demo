#!/usr/bin/env python3
"""
Vulnerability Scan Comparison Tool
Compares two JSON scan result files and shows vulnerability changes
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any, Tuple
from dataclasses import dataclass


@dataclass
class VulnChange:
    """Store vulnerability count changes"""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    negligible: int = 0
    unknown: int = 0

    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.negligible + self.unknown

    def has_remediations(self) -> bool:
        """Check if any vulnerabilities were remediated (negative values)"""
        return (
            self.critical < 0 or self.high < 0 or self.medium < 0 or
            self.low < 0 or self.negligible < 0 or self.unknown < 0
        )

    def has_new_vulns(self) -> bool:
        """Check if any new vulnerabilities were introduced (positive values)"""
        return (
            self.critical > 0 or self.high > 0 or self.medium > 0 or
            self.low > 0 or self.negligible > 0 or self.unknown > 0
        )


def load_scan_results(file_path: str) -> Dict[str, Any]:
    """Load vulnerability scan results from JSON file"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ Error: File not found: {file_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"❌ Error: Invalid JSON in file: {file_path}")
        sys.exit(1)


def calculate_diff(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate the difference between two scan results"""
    diff = {
        "previous_timestamp": previous.get("timestamp"),
        "current_timestamp": current.get("timestamp"),
        "images": [],
        "summary": {}
    }

    # Create lookup for previous images
    prev_images = {img["image"]: img for img in previous.get("images", [])}
    curr_images = {img["image"]: img for img in current.get("images", [])}

    # Compare each image
    all_images = set(prev_images.keys()) | set(curr_images.keys())

    for image in sorted(all_images):
        prev_img = prev_images.get(image)
        curr_img = curr_images.get(image)

        # Calculate changes for each category
        image_diff = {
            "image": image,
            "status": "unknown",
            "os_level_change": {},
            "app_level_change": {},
            "total_change": {}
        }

        if prev_img and curr_img:
            image_diff["status"] = "compared"
            
            # OS-level changes
            prev_os = prev_img.get("os_level", {})
            curr_os = curr_img.get("os_level", {})
            for severity in ["critical", "high", "medium", "low", "negligible", "unknown"]:
                diff_val = curr_os.get(severity, 0) - prev_os.get(severity, 0)
                image_diff["os_level_change"][severity] = diff_val

            # App-level changes
            prev_app = prev_img.get("app_level", {})
            curr_app = curr_img.get("app_level", {})
            for severity in ["critical", "high", "medium", "low", "negligible", "unknown"]:
                diff_val = curr_app.get(severity, 0) - prev_app.get(severity, 0)
                image_diff["app_level_change"][severity] = diff_val

            # Total changes
            prev_total = prev_img.get("total", {})
            curr_total = curr_img.get("total", {})
            for severity in ["critical", "high", "medium", "low", "negligible", "unknown"]:
                diff_val = curr_total.get(severity, 0) - prev_total.get(severity, 0)
                image_diff["total_change"][severity] = diff_val

        elif prev_img and not curr_img:
            image_diff["status"] = "removed"
        elif not prev_img and curr_img:
            image_diff["status"] = "new"

        diff["images"].append(image_diff)

    # Calculate summary changes
    prev_summary = previous.get("summary", {})
    curr_summary = current.get("summary", {})

    for category in ["os_level", "app_level", "total"]:
        diff["summary"][category] = {}
        prev_cat = prev_summary.get(category, {})
        curr_cat = curr_summary.get(category, {})
        
        for severity in ["critical", "high", "medium", "low", "negligible", "unknown"]:
            diff_val = curr_cat.get(severity, 0) - prev_cat.get(severity, 0)
            diff["summary"][category][severity] = diff_val

    return diff


def format_severity_row(severity: str, values: Dict[str, int]) -> str:
    """Format a severity row for display"""
    critical = values.get("critical", 0)
    high = values.get("high", 0)
    medium = values.get("medium", 0)
    low = values.get("low", 0)
    negligible = values.get("negligible", 0)

    # Format with + or - prefix
    def format_num(num):
        if num > 0:
            return f"+{num}"
        elif num < 0:
            return f"{num}"
        else:
            return "0"

    return (
        f"{severity:<15} | "
        f"{format_num(critical):<6} {format_num(high):<6} {format_num(medium):<6} "
        f"{format_num(low):<6} {format_num(negligible):<6}"
    )


def get_image_name(full_image: str) -> str:
    """Extract just the image name and tag from a full image path.
    
    Examples:
    - postgres:18 -> postgres:18
    - cgr.dev/dylans-donuts.com/postgres:18 -> postgres:18
    - node:24-dev -> node:24-dev
    """
    # Remove registry path, keep only the last part after the final /
    return full_image.split('/')[-1]


def generate_markdown_report(previous: Dict[str, Any], current: Dict[str, Any], output_file: str = "scan-comparison.md") -> str:
    """Generate a markdown report of vulnerability comparisons with before/after values"""
    markdown = []
    markdown.append("## 🔎 Vulnerability Summary\n")

    # Create lookup for previous and current images
    prev_images = {img["image"]: img for img in previous.get("images", [])}
    curr_images = {img["image"]: img for img in current.get("images", [])}
    
    # Create lookups by image name for matching across registries
    prev_by_name = {get_image_name(full_path): (img, full_path) for full_path, img in prev_images.items()}
    curr_by_name = {get_image_name(full_path): (img, full_path) for full_path, img in curr_images.items()}
    
    all_image_names = sorted(set(prev_by_name.keys()) | set(curr_by_name.keys()))

    # Summary table header
    markdown.append("| Image | Before | After | Change |")
    markdown.append("|---|---:|---:|---:|")

    # Summary table rows
    for image_name in all_image_names:
        prev_data = prev_by_name.get(image_name)
        curr_data = curr_by_name.get(image_name)

        if prev_data and curr_data:
            prev_img, prev_full_path = prev_data
            curr_img, curr_full_path = curr_data
            
            # Get totals
            before_total = prev_img.get("total", {}).get("total", 0)
            after_total = curr_img.get("total", {}).get("total", 0)
            change_total = after_total - before_total

            # Get severity breakdown for before
            prev_total = prev_img.get("total", {})
            curr_total = curr_img.get("total", {})
            
            c_before = prev_total.get("critical", 0)
            h_before = prev_total.get("high", 0)
            m_before = prev_total.get("medium", 0)
            l_before = prev_total.get("low", 0)
            
            c_after = curr_total.get("critical", 0)
            h_after = curr_total.get("high", 0)
            m_after = curr_total.get("medium", 0)
            l_after = curr_total.get("low", 0)
            
            c_change = c_after - c_before
            h_change = h_after - h_before
            m_change = m_after - m_before
            l_change = l_after - l_before

            # Format the row - show both old and new if they differ
            if prev_full_path != curr_full_path:
                image_display = f"`{prev_full_path}` → `{curr_full_path}`"
            else:
                image_display = f"`{curr_full_path}`"
            
            before_str = f"**{before_total} total** ({c_before}C / {h_before}H / {m_before}M / {l_before}L)"
            after_str = f"**{after_total} total** ({c_after}C / {h_after}H / {m_after}M / {l_after}L)"
            
            change_str = f"**{change_total:+d}** total"
            if c_change != 0 or h_change != 0 or m_change != 0 or l_change != 0:
                change_str += f" (**{c_change:+d}C / {h_change:+d}H / {m_change:+d}M / {l_change:+d}L**)"

            markdown.append(f"| {image_display} | {before_str} | {after_str} | {change_str} |")

    markdown.append("")
    markdown.append("### Breakdown by Severity\n")

    # Detailed breakdown for each image
    for image_name in all_image_names:
        prev_data = prev_by_name.get(image_name)
        curr_data = curr_by_name.get(image_name)

        if prev_data and curr_data:
            prev_img, prev_full_path = prev_data
            curr_img, curr_full_path = curr_data
            
            prev_total = prev_img.get("total", {})
            curr_total = curr_img.get("total", {})
            
            # Check if there are any changes for this image
            has_changes = False
            for severity in ["critical", "high", "medium", "low", "negligible"]:
                before = prev_total.get(severity, 0)
                after = curr_total.get(severity, 0)
                if before != after:
                    has_changes = True
                    break
            
            # Only output breakdown if there are changes
            if has_changes:
                # Show both old and new if they differ
                if prev_full_path != curr_full_path:
                    image_display = f"`{prev_full_path}` → `{curr_full_path}`"
                else:
                    image_display = f"`{curr_full_path}`"
                
                markdown.append(f"#### {image_display}")
                markdown.append("| Severity | Before | After | Delta |")
                markdown.append("|---|---:|---:|---:|")

                for severity in ["critical", "high", "medium", "low", "negligible"]:
                    before = prev_total.get(severity, 0)
                    after = curr_total.get(severity, 0)
                    delta = after - before
                    
                    markdown.append(f"| {severity.capitalize()} | {before} | {after} | **{delta:+d}** |")

                before_total = prev_total.get("total", 0)
                after_total = curr_total.get("total", 0)
                delta_total = after_total - before_total
                markdown.append(f"| **Total** | **{before_total}** | **{after_total}** | **{delta_total:+d}** |")
                markdown.append("")

    # Write to file
    report_content = "\n".join(markdown)
    with open(output_file, 'w') as f:
        f.write(report_content)
    
    return output_file


def print_comparison(diff: Dict[str, Any]):
    """Print a formatted comparison report"""
    print("\n" + "=" * 110)
    print("VULNERABILITY SCAN COMPARISON REPORT")
    print("=" * 110)

    print(f"\n📊 Previous Scan: {diff.get('previous_timestamp', 'Unknown')}")
    print(f"📊 Current Scan:  {diff.get('current_timestamp', 'Unknown')}")

    print("\n" + "=" * 110)
    print("OVERALL SUMMARY")
    print("=" * 110)

    summary = diff.get("summary", {})
    
    # OS-level summary
    print("\n🔧 OS/Container-Level Changes:")
    print("-" * 110)
    print(f"{'Severity':<15} | {'Critical':<6} {'High':<6} {'Medium':<6} {'Low':<6} {'Negligible':<6}")
    print("-" * 110)
    
    os_changes = summary.get("os_level", {})
    print(format_severity_row("Changes", os_changes))
    
    os_total = sum(v for v in os_changes.values())
    print(f"{'TOTAL':<15} | {os_total:+6d}")

    # App-level summary
    print("\n📦 Application-Level Changes:")
    print("-" * 110)
    print(f"{'Severity':<15} | {'Critical':<6} {'High':<6} {'Medium':<6} {'Low':<6} {'Negligible':<6}")
    print("-" * 110)
    
    app_changes = summary.get("app_level", {})
    print(format_severity_row("Changes", app_changes))
    
    app_total = sum(v for v in app_changes.values())
    print(f"{'TOTAL':<15} | {app_total:+6d}")

    # Overall summary
    print("\n📈 Overall Changes:")
    print("-" * 110)
    print(f"{'Severity':<15} | {'Critical':<6} {'High':<6} {'Medium':<6} {'Low':<6} {'Negligible':<6}")
    print("-" * 110)
    
    total_changes = summary.get("total", {})
    print(format_severity_row("Changes", total_changes))
    
    overall_total = sum(v for v in total_changes.values())
    print(f"{'TOTAL':<15} | {overall_total:+6d}")

    # Per-image details
    print("\n" + "=" * 110)
    print("PER-IMAGE CHANGES")
    print("=" * 110)

    for img_diff in diff.get("images", []):
        image = img_diff.get("image")
        status = img_diff.get("status")

        if status == "removed":
            print(f"\n❌ {image} (REMOVED)")
        elif status == "new":
            print(f"\n✨ {image} (NEW)")
        elif status == "compared":
            print(f"\n🔄 {image}")
            
            # OS-level changes
            os_change = img_diff.get("os_level_change", {})
            os_has_changes = any(v != 0 for v in os_change.values())
            
            if os_has_changes:
                print(f"   🔧 OS/Container-Level:")
                for sev in ["critical", "high", "medium", "low", "negligible"]:
                    val = os_change.get(sev, 0)
                    if val != 0:
                        symbol = "🚨" if val > 0 else "✅"
                        print(f"      {symbol} {sev:<12}: {val:+d}")

            # App-level changes
            app_change = img_diff.get("app_level_change", {})
            app_has_changes = any(v != 0 for v in app_change.values())
            
            if app_has_changes:
                print(f"   📦 Application-Level:")
                for sev in ["critical", "high", "medium", "low", "negligible"]:
                    val = app_change.get(sev, 0)
                    if val != 0:
                        symbol = "🚨" if val > 0 else "✅"
                        print(f"      {symbol} {sev:<12}: {val:+d}")

            if not os_has_changes and not app_has_changes:
                print(f"   ✅ No changes")

    # Key findings
    print("\n" + "=" * 110)
    print("KEY FINDINGS")
    print("=" * 110)

    critical_change = total_changes.get("critical", 0)
    high_change = total_changes.get("high", 0)
    
    if critical_change < 0:
        print(f"✅ Remediated {abs(critical_change)} Critical vulnerability(ies)")
    elif critical_change > 0:
        print(f"🚨 Introduced {critical_change} new Critical vulnerability(ies)")
    
    if high_change < 0:
        print(f"✅ Remediated {abs(high_change)} High vulnerability(ies)")
    elif high_change > 0:
        print(f"🚨 Introduced {high_change} new High vulnerability(ies)")

    if os_total < 0:
        print(f"✅ Remediated {abs(os_total)} OS/Container-level vulnerability(ies)")
    elif os_total > 0:
        print(f"🚨 Introduced {os_total} new OS/Container-level vulnerability(ies)")

    if app_total < 0:
        print(f"✅ Remediated {abs(app_total)} Application-level vulnerability(ies)")
    elif app_total > 0:
        print(f"🚨 Introduced {app_total} new Application-level vulnerability(ies)")

    if overall_total == 0:
        print("✅ No change in total vulnerability count")
    elif overall_total < 0:
        print(f"✅ Overall: {abs(overall_total)} vulnerability(ies) remediated")
    else:
        print(f"🚨 Overall: {overall_total} new vulnerability(ies) introduced")

    print()


def main():
    """Main function"""
    if len(sys.argv) < 3:
        print("Usage: python3 compare.py <previous_scan.json> <current_scan.json>")
        print("\nExample: python3 compare.py scan-results-old.json scan-results.json")
        sys.exit(1)

    previous_file = sys.argv[1]
    current_file = sys.argv[2]

    print("🔍 Loading scan results...")
    previous = load_scan_results(previous_file)
    current = load_scan_results(current_file)

    print("📊 Comparing scans...")
    diff = calculate_diff(previous, current)

    print_comparison(diff)
    
    # Generate markdown report
    md_file = generate_markdown_report(previous, current)
    print(f"📄 Markdown report saved to {md_file}")


if __name__ == "__main__":
    main()
