#!/usr/bin/env python3
"""
Debug MobSF Worker Script

This script runs the MobSF analysis worker directly with full verbose output
to debug what's happening during the APK upload process.
"""

import sys
import os
import tempfile
from pathlib import Path

# Add the automations scripts to path
current_dir = Path(__file__).parent
scripts_dir = current_dir.parent / "src" / "scripts" / "automations"
sys.path.insert(0, str(scripts_dir))

# Import MobSF modules
try:
    from launch_mobsf_container import (
        is_mobsf_container_running,
        get_mobsf_api_key,
        launch_mobsf_container
    )
    from _mobsf_analysis_worker import (
        ensure_container_running,
        get_api_key,
        upload_apk
    )
except ImportError as e:
    print(f"❌ ERROR: Failed to import MobSF modules: {e}")
    sys.exit(1)


def debug_worker_steps(apk_path, verbose=True):
    """Debug each step of the worker process."""
    print("🐛 DEBUG: Testing MobSF Worker Steps")
    print("=" * 50)
    
    # Step 1: Container check
    print("\n🐳 Step 1: Checking container status...")
    if is_mobsf_container_running(verbose=verbose):
        print("✅ Container is running")
    else:
        print("❌ Container not running, attempting to start...")
        if not launch_mobsf_container(verbose=verbose):
            print("❌ Failed to start container")
            return False
    
    # Step 2: API Key
    print("\n🔑 Step 2: Getting API key...")
    api_key = get_mobsf_api_key(verbose=verbose)
    if api_key:
        print(f"✅ API key: {api_key}")
    else:
        print("❌ Failed to get API key")
        return False
    
    # Step 3: Test upload directly
    print(f"\n📤 Step 3: Testing APK upload...")
    print(f"APK path: {apk_path}")
    print(f"APK exists: {os.path.exists(apk_path)}")
    if os.path.exists(apk_path):
        print(f"APK size: {os.path.getsize(apk_path)} bytes")
    
    scan_hash = upload_apk(apk_path, api_key, verbose=verbose)
    if scan_hash:
        print(f"✅ Upload successful, hash: {scan_hash}")
        return True
    else:
        print("❌ Upload failed - no scan hash returned")
        return False


def main():
    """Main debug execution."""
    if len(sys.argv) < 2:
        print("Usage: python debug_mobsf_worker.py <apk_path>")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    
    if not os.path.exists(apk_path):
        print(f"❌ APK file not found: {apk_path}")
        sys.exit(1)
    
    print(f"🎯 Testing with APK: {apk_path}")
    
    success = debug_worker_steps(apk_path, verbose=True)
    
    if success:
        print("\n✅ All steps completed successfully")
    else:
        print("\n❌ Debug test failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
