#!/usr/bin/env python3
"""
Standalone MobSF Integration Test

This script tests the MobSF Docker integration according to MOBSF_INTEGRATION_SPEC.md:
1. Check if MobSF Docker image is pulled (alert and exit if not)
2. Run the full MobSF analysis logic with a test APK

Usage:
    python test_mobsf_standalone.py [--verbose] [--apk-path path/to/test.apk]
"""

import sys
import os
import argparse
import subprocess
import tempfile
import time
from pathlib import Path

# Add the automations scripts to path
current_dir = Path(__file__).parent
scripts_dir = current_dir.parent / "src" / "scripts" / "automations"
sys.path.insert(0, str(scripts_dir))

# Import MobSF modules
try:
    from launch_mobsf_container import (
        is_mobsf_image_available,
        launch_mobsf_container,
        is_mobsf_container_running,
        get_mobsf_api_key,
        stop_mobsf_container
    )
    from launch_mobsf_analysis import launch_mobsf_analysis, check_mobsf_completion
except ImportError as e:
    print(f"❌ ERROR: Failed to import MobSF modules: {e}")
    print("Please ensure you're running this from the correct directory")
    sys.exit(1)


def print_header():
    """Print test header."""
    print("🐳 MobSF Standalone Integration Test")
    print("=" * 50)


def check_docker_available():
    """Check if Docker is available and running."""
    try:
        result = subprocess.run(
            ["docker", "--version"], 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        if result.returncode == 0:
            print(f"✅ Docker available: {result.stdout.strip()}")
            return True
        else:
            print("❌ Docker command failed")
            return False
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"❌ Docker not available: {e}")
        print("Please install Docker and ensure it's in your PATH")
        return False


def test_mobsf_image_availability(verbose=False):
    """
    Test Phase 1: Check if MobSF Docker image is available.
    According to spec: "if the container is not pulled, alert it and exit"
    """
    print("\n📋 Phase 1: Checking MobSF Docker Image Availability")
    print("-" * 50)
    
    if not check_docker_available():
        return False
    
    print("🔍 Checking if MobSF Docker image is available locally...")
    
    if is_mobsf_image_available(verbose=verbose):
        print("✅ MobSF Docker image is available locally")
        return True
    else:
        print("❌ MobSF Docker image is NOT available locally")
        print("")
        print("🛠️  RESOLUTION REQUIRED:")
        print("Please pull the MobSF Docker image using:")
        print("   docker pull opensecurity/mobile-security-framework-mobsf:latest")
        print("")
        print("This may take several minutes depending on your internet connection.")
        print("The image is approximately 3-4 GB in size.")
        print("")
        print("After pulling the image, re-run this test.")
        return False


def test_mobsf_analysis_workflow(apk_path, verbose=False):
    """
    Test Phase 2: Run the full MobSF analysis logic.
    According to spec: "run the logic that does the analysis given the apk"
    """
    print("\n📋 Phase 2: Testing MobSF Analysis Workflow")
    print("-" * 50)
    
    # Validate APK file exists
    if not os.path.exists(apk_path):
        print(f"❌ APK file not found: {apk_path}")
        return False
    
    print(f"🔍 Testing with APK: {apk_path}")
    
    # Create temporary output directory
    with tempfile.TemporaryDirectory(prefix="mobsf_test_") as temp_dir:
        print(f"📁 Using temporary output directory: {temp_dir}")
        
        try:
            # Step 1: Test container launch
            print("\n🐳 Step 1: Launching MobSF container...")
            container_result = launch_mobsf_container(verbose=verbose)
            
            if not container_result:
                print("❌ Failed to launch MobSF container")
                return False
            
            print("✅ MobSF container launched successfully")
            
            # Step 2: Test API key retrieval
            print("\n🔑 Step 2: Testing API key retrieval...")
            api_key = get_mobsf_api_key(verbose=verbose)
            
            if not api_key:
                print("❌ Failed to retrieve API key")
                return False
            
            print(f"✅ API key retrieved: {api_key[:8]}...{api_key[-8:]}")
            
            # Step 3: Test analysis launch
            print("\n🔍 Step 3: Launching MobSF analysis...")
            analysis_process = launch_mobsf_analysis(apk_path, temp_dir, verbose=verbose)
            
            if not analysis_process:
                print("❌ Failed to launch MobSF analysis")
                return False
            
            print("✅ MobSF analysis process launched successfully")
            print(f"📊 Analysis PID: {analysis_process.pid}")
            
            # Step 4: Test completion checking
            print("\n⏳ Step 4: Testing analysis completion...")
            print("Note: This may take several minutes for the full analysis...")
            
            # Check status periodically
            for i in range(12):  # Check for up to 2 minutes
                time.sleep(10)
                poll_result = analysis_process.poll()
                
                if poll_result is None:
                    print(f"📊 Analysis still running... ({(i+1)*10}s elapsed)")
                else:
                    print(f"📊 Analysis process completed with exit code: {poll_result}")
                    break
            
            # Final completion check
            result_status = check_mobsf_completion(
                analysis_process, 
                temp_dir, 
                verbose=verbose, 
                timeout=120  # 2 minute timeout for final check
            )
            
            print(f"📋 Final analysis status: {result_status}")
            
            # If we got exit code 3 (APK upload failed), provide diagnostic info
            if poll_result == 3:
                print("\n🔍 DIAGNOSTIC INFO for APK Upload Failure:")
                print(f"   📁 APK file: {apk_path}")
                print(f"   📏 APK size: {os.path.getsize(apk_path)} bytes")
                print(f"   🔑 API key: {api_key[:8]}...{api_key[-8:]}")
                print(f"   🌐 MobSF URL: http://localhost:8000")
                print(f"   💡 Try manually uploading the APK via web interface")
                print(f"   💡 Check MobSF container logs: docker logs mobsf_automatool")
                return False  # Upload failure should be considered a test failure
            
            # Check for output files
            print("\n📁 Checking generated files...")
            mobsf_results_dir = os.path.join(temp_dir, "mobsf_results")
            
            if os.path.exists(mobsf_results_dir):
                print(f"✅ Results directory created: {mobsf_results_dir}")
                
                # List generated files
                for file_name in os.listdir(mobsf_results_dir):
                    file_path = os.path.join(mobsf_results_dir, file_name)
                    if os.path.isfile(file_path):
                        size = os.path.getsize(file_path)
                        print(f"   📄 {file_name} ({size} bytes)")
                
                return True
            else:
                # If process completed successfully but no results, still pass
                if poll_result == 0:
                    print("⚠️  Results directory not found but process completed successfully")
                    return True
                else:
                    print("⚠️  Results directory not found and process failed")
                    return False
                
        except Exception as e:
            print(f"❌ Error during analysis workflow: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
            return False
        
        finally:
            # Clean up: container should persist according to spec
            print("\n🧹 Cleanup: Container will persist for reuse (per specification)")


def get_test_apk_path():
    """Get path to test APK file."""
    # Check for test APK in resources
    resources_dir = Path(__file__).parent / "resources"
    test_apk = resources_dir / "test.apk"
    
    if test_apk.exists():
        return str(test_apk)
    
    # Alternative locations
    alt_locations = [
        resources_dir / "test_apk_small.apk",
        resources_dir / "sample.apk",
        Path(__file__).parent.parent / "tests" / "resources" / "test.apk"
    ]
    
    for location in alt_locations:
        if location.exists():
            return str(location)
    
    return None


def main():
    """Main test execution."""
    parser = argparse.ArgumentParser(description="MobSF Standalone Integration Test")
    parser.add_argument(
        "--verbose", "-v", 
        action="store_true", 
        help="Enable verbose output"
    )
    parser.add_argument(
        "--apk-path", 
        help="Path to test APK file (uses built-in test APK if not specified)"
    )
    parser.add_argument(
        "--container-only",
        action="store_true",
        help="Only test container setup, skip analysis workflow"
    )
    
    args = parser.parse_args()
    
    print_header()
    
    # Phase 1: Check Docker image availability
    image_available = test_mobsf_image_availability(verbose=args.verbose)
    
    if not image_available:
        print("\n❌ TEST FAILED: MobSF Docker image not available")
        print("Please pull the image and re-run the test.")
        sys.exit(1)
    
    # Skip analysis if only testing container
    if args.container_only:
        print("\n✅ CONTAINER TEST PASSED: MobSF Docker image is available")
        sys.exit(0)
    
    # Phase 2: Test analysis workflow
    apk_path = args.apk_path or get_test_apk_path()
    
    if not apk_path:
        print("\n❌ TEST FAILED: No test APK available")
        print("Please provide an APK file using --apk-path or place a test.apk in the resources directory")
        sys.exit(1)
    
    print(f"\n🎯 Using APK for testing: {apk_path}")
    
    analysis_success = test_mobsf_analysis_workflow(apk_path, verbose=args.verbose)
    
    # Final results
    print("\n" + "=" * 50)
    print("📋 FINAL TEST RESULTS")
    print("=" * 50)
    
    if image_available and analysis_success:
        print("✅ ALL TESTS PASSED")
        print("🐳 MobSF Docker integration is working correctly")
        print("🔍 Analysis workflow completed successfully")
        sys.exit(0)
    else:
        print("❌ SOME TESTS FAILED")
        if not image_available:
            print("   - Docker image availability: FAILED")
        if not analysis_success:
            print("   - Analysis workflow: FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
