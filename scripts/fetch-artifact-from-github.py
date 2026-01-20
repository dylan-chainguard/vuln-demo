#!/usr/bin/env python3
"""
Fetch artifact from latest GitHub Actions workflow run
Downloads the vulnerability-scan-results artifact from the latest scan-images.yml workflow run
on the main branch of dylan-chainguard/vuln-demo
"""

# required GITHUB_TOKEN scope: actions:read

import os
import sys
import json
import requests
import zipfile
from pathlib import Path
from datetime import datetime

# GitHub configuration
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
REPO_OWNER = 'dylan-chainguard'
REPO_NAME = 'vuln-demo'
WORKFLOW_FILE = 'scan-images.yml'
ARTIFACT_NAME = 'vulnerability-scan-results'
JSON_FILE_NAME = 'scan-results.json'

# GitHub API base URL
GITHUB_API = 'https://api.github.com'

def get_headers():
    """Get authorization headers for GitHub API"""
    headers = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
    }
    if GITHUB_TOKEN:
        headers['Authorization'] = f'token {GITHUB_TOKEN}'
    return headers

def get_latest_workflow_run():
    """Get the latest workflow run on main branch"""
    print(f"🔍 Fetching latest workflow run for {WORKFLOW_FILE}...")
    
    url = f"{GITHUB_API}/repos/{REPO_OWNER}/{REPO_NAME}/actions/workflows/{WORKFLOW_FILE}/runs"
    params = {
        'branch': 'main',
        'status': 'completed',
        'per_page': 1
    }
    
    try:
        response = requests.get(url, headers=get_headers(), params=params)
        response.raise_for_status()
        
        data = response.json()
        runs = data.get('workflow_runs', [])
        
        if not runs:
            print(f"❌ No completed workflow runs found for {WORKFLOW_FILE} on main branch")
            return None
        
        run = runs[0]
        run_id = run['id']
        run_date = run['created_at']
        run_status = run['status']
        run_conclusion = run.get('conclusion', 'N/A')
        
        print(f"✓ Found workflow run #{run_id}")
        print(f"  Created: {run_date}")
        print(f"  Status: {run_status}")
        print(f"  Conclusion: {run_conclusion}")
        
        return run_id
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching workflow runs: {e}")
        return None

def get_artifact_id(run_id):
    """Get the artifact ID for the specified run"""
    print(f"\n🔍 Fetching artifacts for workflow run #{run_id}...")
    
    url = f"{GITHUB_API}/repos/{REPO_OWNER}/{REPO_NAME}/actions/runs/{run_id}/artifacts"
    
    try:
        response = requests.get(url, headers=get_headers())
        response.raise_for_status()
        
        data = response.json()
        artifacts = data.get('artifacts', [])
        
        if not artifacts:
            print(f"❌ No artifacts found for workflow run #{run_id}")
            return None
        
        # Find the artifact by name
        for artifact in artifacts:
            if artifact['name'] == ARTIFACT_NAME:
                artifact_id = artifact['id']
                size = artifact['size_in_bytes']
                print(f"✓ Found artifact: {ARTIFACT_NAME}")
                print(f"  ID: {artifact_id}")
                print(f"  Size: {size} bytes")
                return artifact_id
        
        print(f"❌ Artifact '{ARTIFACT_NAME}' not found in run #{run_id}")
        print(f"   Available artifacts: {[a['name'] for a in artifacts]}")
        return None
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching artifacts: {e}")
        return None

def download_artifact(artifact_id, output_path):
    """Download artifact and extract it"""
    print(f"\n📥 Downloading artifact #{artifact_id}...")
    
    url = f"{GITHUB_API}/repos/{REPO_OWNER}/{REPO_NAME}/actions/artifacts/{artifact_id}/zip"
    
    try:
        response = requests.get(url, headers=get_headers())
        response.raise_for_status()
        
        # Save zip file temporarily
        zip_path = output_path / 'temp-artifact.zip'
        with open(zip_path, 'wb') as f:
            f.write(response.content)
        
        print(f"✓ Downloaded {len(response.content)} bytes")
        
        # Extract zip file
        print(f"\n📦 Extracting artifact...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(output_path)
        
        print(f"✓ Extracted to {output_path}")
        
        # Find and verify the JSON file
        json_path = output_path / JSON_FILE_NAME
        if not json_path.exists():
            print(f"❌ JSON file '{JSON_FILE_NAME}' not found in artifact")
            print(f"   Available files: {list(output_path.glob('*'))}")
            return None
        
        # Clean up zip file
        zip_path.unlink()
        
        print(f"✓ Found JSON file: {JSON_FILE_NAME}")
        return json_path
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Error downloading artifact: {e}")
        return None
    except zipfile.BadZipFile as e:
        print(f"❌ Error extracting artifact: {e}")
        return None

def main():
    print("=" * 70)
    print("GitHub Actions Artifact Fetcher")
    print("=" * 70)
    print()
    
    if not GITHUB_TOKEN:
        print("⚠️  Warning: GITHUB_TOKEN not set. Using unauthenticated API requests.")
        print("   This may hit rate limits. Set GITHUB_TOKEN to continue.")
        print()
    
    # Create output directory
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    output_dir = project_root / 'downloaded-artifacts'
    output_dir.mkdir(exist_ok=True)
    
    print(f"📂 Output directory: {output_dir}")
    print()
    
    # Step 1: Get latest workflow run
    run_id = get_latest_workflow_run()
    if not run_id:
        sys.exit(1)
    
    # Step 2: Get artifact ID
    artifact_id = get_artifact_id(run_id)
    if not artifact_id:
        sys.exit(1)
    
    # Step 3: Download and extract artifact
    json_path = download_artifact(artifact_id, output_dir)
    if not json_path:
        sys.exit(1)
    
    # Verify JSON content
    try:
        with open(json_path) as f:
            data = json.load(f)
        
        print(f"\n✅ Successfully loaded JSON file")
        
        # Show summary
        if 'images' in data:
            image_count = len(data.get('images', []))
            print(f"   Images in artifact: {image_count}")
        if 'timestamp' in data:
            print(f"   Timestamp: {data['timestamp']}")
        
    except json.JSONDecodeError as e:
        print(f"❌ Error parsing JSON file: {e}")
        sys.exit(1)
    
    print()
    print("=" * 70)
    print("✅ Download Complete!")
    print("=" * 70)
    print()
    print(f"Artifact saved to: {json_path}")
    print()
    print("Next steps:")
    print(f"  1. Load into database: python3 scripts/load-artifact-to-database.py")
    print()

if __name__ == "__main__":
    main()
