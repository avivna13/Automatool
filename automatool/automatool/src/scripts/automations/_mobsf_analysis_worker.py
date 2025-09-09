#!/usr/bin/env python3
"""
MobSF Analysis Worker Process

This script runs as a separate background process to handle the entire MobSF analysis workflow:
1. Start MobSF container if needed
2. Get API key from container logs
3. Upload APK 
4. Start analysis scan
5. Monitor analysis progress
6. Download results

This follows the same pattern as other automatool background processes.
"""

import argparse
import os
import sys
import json
import time
import requests
from pathlib import Path
from resource_tracker import GlobalResourceTracker

# Import container management functions
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)
from launch_mobsf_container import (
    launch_mobsf_container, 
    is_mobsf_container_running, 
    get_mobsf_api_key,
    wait_for_mobsf_ready
)
from parse_mobsf_output import parse_mobsf_report_for_llm


def main():
    """Main worker process entry point."""
    parser = argparse.ArgumentParser(description="MobSF Analysis Worker")
    parser.add_argument("--apk-path", required=True, help="Path to APK file")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument("--port", type=int, default=8000, help="MobSF server port (default: 8000)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--quiet", action="store_true", help="Suppress output")
    
    args = parser.parse_args()
    verbose = args.verbose and not args.quiet
    
    # Initialize resource tracker
    try:
        tracker = GlobalResourceTracker()
        if verbose:
            print("[WORKER] 🔧 Resource tracker initialized")
    except Exception as e:
        if verbose:
            print(f"[WORKER] ⚠️  WARNING: Could not initialize resource tracker: {e}")
        tracker = None
    
    if verbose:
        print("[WORKER] Starting MobSF analysis worker...")
        print(f"[WORKER] APK: {args.apk_path}")
        print(f"[WORKER] Output: {args.output_dir}")
        print(f"[WORKER] Port: {args.port}")
    
    try:
        # 1. Ensure MobSF container is running
        if not ensure_container_running(args.port, verbose):
            sys.exit(1)
        
        # 2. Get API key
        api_key = get_api_key(args.port, verbose)
        if not api_key:
            sys.exit(2)
        
        # 3. Upload APK
        scan_hash = upload_apk(args.apk_path, api_key, args.port, verbose)
        if not scan_hash:
            sys.exit(3)
        
        # 4. Start analysis scan
        if not start_analysis(scan_hash, api_key, args.port, verbose):
            sys.exit(4)
        
        # 5. Wait for analysis completion  
        if not wait_for_analysis(scan_hash, api_key, args.port, verbose):
            sys.exit(5)
        
        # 6. Download results
        analysis_filepath, mobsf_output_dirpath = download_results(scan_hash, api_key, args.output_dir, args.port, verbose, tracker)
        if not analysis_filepath or not mobsf_output_dirpath:
            sys.exit(6)
            
        parse_mobsf_report_for_llm(analysis_filepath,mobsf_output_dirpath)
        
        if verbose:
            print("[WORKER] ✅ MobSF analysis completed successfully and resources tracked")
            
        sys.exit(0)  # Success
        
    except Exception as e:
        if verbose:
            print(f"[WORKER] ERROR: {e}")
        sys.exit(7)


def ensure_container_running(port=8000, verbose=False):
    """Ensure MobSF container is running and ready."""
    try:
        if verbose:
            print(f"[WORKER] Ensuring MobSF container is running on port {port}...")
        
        # Check if already running
        if is_mobsf_container_running(port, verbose):
            if verbose:
                print(f"[WORKER] Container already running on port {port}")
            return True
        
        # Launch container
        if verbose:
            print(f"[WORKER] Launching MobSF container on port {port}...")
            
        result = launch_mobsf_container(port, verbose)
        if result:
            if verbose:
                print("[WORKER] ✅ Container launched successfully")
            return True
        else:
            if verbose:
                print("[WORKER] ❌ Failed to launch container")
            return False
            
    except Exception as e:
        if verbose:
            print(f"[WORKER] Container error: {e}")
        return False


def get_api_key(port=8000, verbose=False):
    """Get API key from container logs."""
    try:
        if verbose:
            print(f"[WORKER] Retrieving API key for port {port}...")
            
        api_key = get_mobsf_api_key(port, verbose)
        if api_key:
            if verbose:
                print(f"[WORKER] ✅ API key retrieved: {api_key[:8]}... (length: {len(api_key)})")
            return api_key
        else:
            if verbose:
                print("[WORKER] ❌ Failed to retrieve API key")
            return None
            
    except Exception as e:
        if verbose:
            print(f"[WORKER] API key error: {e}")
        return None


def upload_apk(apk_path, api_key, port=8000, verbose=False):
    """Upload APK to MobSF and return scan hash."""
    try:
        if verbose:
            print(f"[WORKER] Uploading APK: {apk_path}")
            print(f"[WORKER] Using API key: {api_key[:8]}...{api_key[-8:]}")

        headers = {'Authorization': api_key}
        
        if verbose:
            print(f"[WORKER] Request URL: http://localhost:{port}/api/v1/upload")
            print(f"[WORKER] Headers: {headers}")
        
        with open(apk_path, 'rb') as f:
            files = {'file': (os.path.basename(apk_path), f, 'application/vnd.android.package-archive')}
            response = requests.post(
                f'http://localhost:{port}/api/v1/upload',
                files=files,
                headers=headers,
                timeout=600  # 10 minute timeout for large APKs
            )
        
        if verbose:
            print(f"[WORKER] Response status: {response.status_code}")
            if response.status_code != 200:
                print(f"[WORKER] Response: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            scan_hash = result.get('hash')
            if verbose:
                print(f"[WORKER] Upload successful, hash: {scan_hash}")
            return scan_hash
        else:
            if verbose:
                print(f"[WORKER] ❌ Upload failed. Status: {response.status_code}")
                print(f"[WORKER] Response: {response.text}")
            return None
                
    except Exception as e:
        if verbose:
            print(f"[WORKER] Upload error: {e}")
        return None


def start_analysis(scan_hash, api_key, port=8000, verbose=False):
    """Start MobSF analysis scan."""
    try:
        if verbose:
            print(f"[WORKER] Starting analysis for hash: {scan_hash}")
            
        data = {'hash': scan_hash}
        headers = {'Authorization': api_key}
        
        response = requests.post(
            f'http://localhost:{port}/api/v1/scan',
            data=data,
            headers=headers,
            timeout=60
        )
        
        if response.status_code == 200:
            if verbose:
                print(f"[WORKER] ✅ Analysis started successfully")
            return True
        else:
            if verbose:
                print(f"[WORKER] ❌ Analysis start failed: {response.status_code}")
                print(f"[WORKER] Response: {response.text}")
            return False
            
    except Exception as e:
        if verbose:
            print(f"[WORKER] Analysis start error: {e}")
        return False


def wait_for_analysis(scan_hash, api_key, port=8000, verbose=False, timeout=600):
    """Wait for analysis to complete."""
    try:
        if verbose:
            print(f"[WORKER] Waiting for analysis completion (timeout: {timeout}s)...")
            
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            # Check if analysis is complete by trying to get report
            if check_analysis_complete(scan_hash, api_key, port, verbose):
                if verbose:
                    print("[WORKER] ✅ Analysis completed")
                return True
            
            time.sleep(10)  # Check every 10 seconds
            
            if verbose:
                elapsed = int(time.time() - start_time)
                print(f"[WORKER] Analysis in progress... ({elapsed}/{timeout}s)")
        
        if verbose:
            print(f"[WORKER] ❌ Analysis timed out after {timeout}s")
        return False
        
    except Exception as e:
        if verbose:
            print(f"[WORKER] Analysis wait error: {e}")
        return False


def check_analysis_complete(scan_hash, api_key, port=8000, verbose=False):
    """Check if analysis is complete by attempting to get report."""
    try:
        data = {'hash': scan_hash}
        headers = {'Authorization': api_key}
        
        response = requests.post(
            f'http://localhost:{port}/api/v1/report_json',
            data=data,
            headers=headers,
            timeout=30
        )
        
        # Analysis is complete if we get a valid JSON report
        if response.status_code == 200:
            try:
                report = response.json()
                # Check if report contains actual analysis data
                if report and 'app_name' in report:
                    return True
            except json.JSONDecodeError:
                pass
        
        return False
        
    except Exception:
        return False


def download_results(scan_hash, api_key, output_dir, port=8000, verbose=False, tracker=None):
    """Download analysis results and save to output directory."""
    try:
        if verbose:
            print(f"[WORKER] Downloading results to: {output_dir}")
            
        # Create mobsf_results directory
        results_dir = os.path.join(output_dir, "mobsf_results")
        os.makedirs(results_dir, exist_ok=True)
        
        # Track the results directory
        if tracker:
            try:
                tracker.add_directory(results_dir)
                if verbose:
                    print(f"[WORKER] 📁 Tracked MobSF results directory: {results_dir}")
            except Exception as e:
                if verbose:
                    print(f"[WORKER] ⚠️  WARNING: Failed to track directory: {e}")
        
        # Download JSON report
        json_report = download_json_report(scan_hash, api_key, port, verbose)
        if json_report:
            json_path = os.path.join(results_dir, "analysis_report.json")
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(json_report, f, indent=2, ensure_ascii=False)
            
            # Track the JSON report file
            if tracker:
                try:
                    tracker.add_file(json_path)
                    if verbose:
                        print(f"[WORKER] 📄 Tracked JSON report: {json_path}")
                except Exception as e:
                    if verbose:
                        print(f"[WORKER] ⚠️  WARNING: Failed to track JSON file: {e}")
            
            if verbose:
                print(f"[WORKER] ✅ JSON report saved: {json_path}")
        
        # Create summary file
        if json_report:
            summary_path = os.path.join(results_dir, "mobsf_summary.txt")
            create_summary_file(json_report, summary_path, verbose, tracker)
        
        # Save scan metadata
        metadata_path = os.path.join(results_dir, "scan_info.txt")
        create_metadata_file(scan_hash, metadata_path, verbose, tracker)
        
        if verbose:
            print("[WORKER] ✅ Results download completed")
        return json_path, results_dir
        
    except Exception as e:
        if verbose:
            print(f"[WORKER] Results download error: {e}")
        return None, None


def download_json_report(scan_hash, api_key, port=8000, verbose=False):
    """Download JSON analysis report."""
    try:
        data = {'hash': scan_hash}
        headers = {'Authorization': api_key}
        
        response = requests.post(
            f'http://localhost:{port}/api/v1/report_json',
            data=data,
            headers=headers,
            timeout=180
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            if verbose:
                print(f"[WORKER] ❌ JSON report download failed: {response.status_code}")
            return None
            
    except Exception as e:
        if verbose:
            print(f"[WORKER] JSON report error: {e}")
        return None


def create_summary_file(json_report, summary_path, verbose=False, tracker=None):
    """Create human-readable summary from JSON report."""
    try:
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write("=== MobSF Analysis Summary ===\n\n")
            
            # Basic app info
            f.write(f"App Name: {json_report.get('app_name', 'N/A')}\n")
            f.write(f"Package: {json_report.get('packagename', 'N/A')}\n")
            f.write(f"Version: {json_report.get('version_name', 'N/A')}\n")
            f.write(f"File Name: {json_report.get('file_name', 'N/A')}\n")
            f.write(f"Hash: {json_report.get('hash', 'N/A')}\n\n")
            
            # Security score
            if 'security_score' in json_report:
                f.write(f"Security Score: {json_report['security_score']}/100\n\n")
            
            # Security issues summary
            if 'appsec' in json_report:
                appsec = json_report['appsec']
                f.write("=== Security Issues ===\n")
                f.write(f"High Risk Issues: {len(appsec.get('high', []))}\n")
                f.write(f"Warning Issues: {len(appsec.get('warning', []))}\n")
                f.write(f"Info Issues: {len(appsec.get('info', []))}\n")
                f.write(f"Secure Items: {len(appsec.get('secure', []))}\n\n")
            
            # Tracker information
            if 'trackers' in json_report:
                trackers = json_report['trackers']
                f.write("=== Privacy Trackers ===\n")
                f.write(f"Detected Trackers: {trackers.get('detected_trackers', 0)}\n")
                f.write(f"Total Trackers Checked: {trackers.get('total_trackers', 0)}\n\n")
            
            f.write("=== Full Report ===\n")
            f.write("See analysis_report.json for complete details\n")
        
        # Track the summary file
        if tracker:
            try:
                tracker.add_file(summary_path)
                if verbose:
                    print(f"[WORKER] 📄 Tracked summary file: {summary_path}")
            except Exception as e:
                if verbose:
                    print(f"[WORKER] ⚠️  WARNING: Failed to track summary file: {e}")
        
        if verbose:
            print(f"[WORKER] ✅ Summary created: {summary_path}")
            
    except Exception as e:
        if verbose:
            print(f"[WORKER] Summary creation error: {e}")


def create_metadata_file(scan_hash, metadata_path, verbose=False, tracker=None):
    """Create scan metadata file."""
    try:
        with open(metadata_path, 'w', encoding='utf-8') as f:
            f.write("=== MobSF Scan Information ===\n\n")
            f.write(f"Scan Hash: {scan_hash}\n")
            f.write(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"MobSF Version: Latest Docker Image\n")
            f.write(f"Analysis Type: Static Analysis\n")
        
        # Track the metadata file
        if tracker:
            try:
                tracker.add_file(metadata_path)
                if verbose:
                    print(f"[WORKER] 📄 Tracked metadata file: {metadata_path}")
            except Exception as e:
                if verbose:
                    print(f"[WORKER] ⚠️  WARNING: Failed to track metadata file: {e}")
        
        if verbose:
            print(f"[WORKER] ✅ Metadata created: {metadata_path}")
            
    except Exception as e:
        if verbose:
            print(f"[WORKER] Metadata creation error: {e}")


if __name__ == "__main__":
    main()