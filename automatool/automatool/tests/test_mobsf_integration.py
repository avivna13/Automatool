#!/usr/bin/env python3
"""
Test suite for MobSF integration standalone functionality.

This test suite verifies:
1. Container management (start, health check)
2. APK upload functionality  
3. End-to-end workflow with test.apk
4. Error handling and edge cases
"""

import pytest
import os
import sys
import time
import subprocess
import requests
from pathlib import Path

# Add the src directory to Python path for imports
test_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(test_dir, '..', 'src')
sys.path.insert(0, src_dir)

from scripts.automations.launch_mobsf_container import (
    launch_mobsf_container,
    is_mobsf_container_running,
    wait_for_mobsf_ready,
    stop_mobsf_container,
    is_mobsf_image_available
)
from scripts.automations.launch_mobsf_analysis import (
    launch_mobsf_analysis,
    check_mobsf_completion,
    get_mobsf_status
)

class TestMobSFContainerManagement:
    """Test MobSF container management functions."""
    
    def test_docker_image_availability(self):
        """Test MobSF Docker image availability check."""
        print("\n🐳 Testing MobSF Docker image availability...")
        
        image_available = is_mobsf_image_available(verbose=True)
        
        if not image_available:
            print("❌ MobSF Docker image not found locally.")
            print("📥 Please pull the MobSF image by running:")
            print("   docker pull opensecurity/mobile-security-framework-mobsf:latest")
            print("⏱️  This may take several minutes depending on your internet connection.")
            pytest.skip("MobSF Docker image not available locally. Please pull the image first.")
        
        print("✅ MobSF Docker image is available locally")
        assert image_available, "MobSF Docker image should be available"
    
    def test_container_status_check(self):
        """Test container status checking functionality."""
        # This should work regardless of container state
        status = is_mobsf_container_running(verbose=True)
        assert isinstance(status, bool)
    
    def test_container_launch_and_health_check(self):
        """Test container launch and health verification."""
        print("\n🐳 Testing MobSF container launch and health check...")
        
        # Launch container (or verify it's already running)
        container_result = launch_mobsf_container(verbose=True)
        
        # Should return process object or True (if already running)
        assert container_result is not False, "Container launch should succeed"
        
        # Verify container is now running
        assert is_mobsf_container_running(verbose=True), "Container should be running after launch"
        
        # Verify API health check
        api_ready = wait_for_mobsf_ready(timeout=30, verbose=True)
        assert api_ready, "MobSF API should be ready after container launch"
        
        print("✅ Container launch and health check passed!")

class TestMobSFAnalysisWorkflow:
    """Test the complete MobSF analysis workflow."""
    
    @pytest.fixture
    def test_apk_path(self):
        """Fixture to provide path to test APK."""
        test_dir = os.path.dirname(os.path.abspath(__file__))
        apk_path = os.path.join(test_dir, 'resources', 'test.apk')
        
        assert os.path.exists(apk_path), f"Test APK not found at {apk_path}"
        assert os.path.getsize(apk_path) > 0, "Test APK file should not be empty"
        
        return apk_path
    
    @pytest.fixture
    def test_output_dir(self, tmp_path):
        """Fixture to provide temporary output directory."""
        output_dir = tmp_path / "mobsf_test_output"
        output_dir.mkdir()
        return str(output_dir)
    
    def test_apk_upload_workflow(self, test_apk_path, test_output_dir):
        """Test the complete APK upload workflow using the worker script."""
        print(f"\n📱 Testing APK upload workflow with: {test_apk_path}")
        
        # Ensure container is running first
        container_result = launch_mobsf_container(verbose=True)
        assert container_result is not False, "Container must be running for upload test"
        
        # Wait for API to be ready
        api_ready = wait_for_mobsf_ready(timeout=60, verbose=True)
        assert api_ready, "API must be ready for upload test"
        
        # Run the worker script directly
        script_dir = os.path.join(os.path.dirname(__file__), '..', 'src', 'scripts', 'automations')
        worker_script = os.path.join(script_dir, '_mobsf_analysis_worker.py')
        
        assert os.path.exists(worker_script), f"Worker script not found at {worker_script}"
        
        # Execute worker script
        print("🔄 Running MobSF analysis worker...")
        result = subprocess.run([
            sys.executable, worker_script,
            "--apk-path", test_apk_path,
            "--output-dir", test_output_dir,
            "--verbose"
        ], capture_output=True, text=True, timeout=600)  # 10 minute timeout
        
        # Check worker script results
        print(f"Worker exit code: {result.returncode}")
        if result.stdout:
            print(f"Worker stdout: {result.stdout}")
        if result.stderr:
            print(f"Worker stderr: {result.stderr}")
        
        # Worker should complete successfully
        assert result.returncode == 0, f"Worker script should succeed, got exit code {result.returncode}"
        
        # Check that scan info file was created
        scan_info_path = os.path.join(test_output_dir, "mobsf_scan_info.txt")
        assert os.path.exists(scan_info_path), "Scan info file should be created"
        
        # Verify scan info content
        with open(scan_info_path, 'r') as f:
            scan_info_content = f.read()
        
        assert "Scan Hash:" in scan_info_content, "Scan info should contain scan hash"
        assert "http://localhost:8000" in scan_info_content, "Scan info should contain MobSF URL"
        assert "Upload Date:" in scan_info_content, "Scan info should contain upload date"
        
        print("✅ APK upload workflow completed successfully!")
        print(f"📄 Scan info saved to: {scan_info_path}")
    
    def test_process_coordination(self, test_apk_path, test_output_dir):
        """Test the process coordination layer (launch_mobsf_analysis.py)."""
        print(f"\n⚙️ Testing process coordination with: {test_apk_path}")
        
        # Launch analysis using the coordination layer
        process = launch_mobsf_analysis(test_apk_path, test_output_dir, verbose=True)
        
        # Should return a process object
        assert process is not False, "Analysis launch should succeed"
        assert hasattr(process, 'pid'), "Should return subprocess.Popen object"
        assert hasattr(process, 'poll'), "Should return subprocess.Popen object"
        
        print(f"✅ Analysis process launched with PID: {process.pid}")
        
        # Check initial status
        initial_status = get_mobsf_status(process, verbose=True)
        print(f"Initial status: {initial_status}")
        
        # Wait for completion
        print("⏳ Waiting for analysis to complete...")
        completion_result = check_mobsf_completion(process, test_output_dir, verbose=True, timeout=240)
        
        print(f"Completion result: {completion_result}")
        
        # Check final status
        final_status = get_mobsf_status(process, verbose=True)
        print(f"Final status: {final_status}")
        
        # Process should complete successfully
        assert "Success" in completion_result or "Completed" in final_status, "Analysis should complete successfully"
        
        # Verify output file exists
        scan_info_path = os.path.join(test_output_dir, "mobsf_scan_info.txt")
        assert os.path.exists(scan_info_path), "Scan info file should be created"
        
        print("✅ Process coordination test passed!")

class TestMobSFErrorHandling:
    """Test error handling and edge cases."""
    
    def test_invalid_apk_path(self, tmp_path):
        """Test handling of invalid APK path."""
        invalid_apk = str(tmp_path / "nonexistent.apk")
        output_dir = str(tmp_path / "output")
        os.makedirs(output_dir, exist_ok=True)
        
        # Should handle gracefully
        process = launch_mobsf_analysis(invalid_apk, output_dir, verbose=True)
        
        if process is not False:
            # If process launched, it should fail during execution
            result = check_mobsf_completion(process, output_dir, verbose=True, timeout=30)
            assert "Error" in result or "Failed" in result, "Should detect APK file error"
    
    def test_worker_script_validation(self):
        """Test that worker script exists and is executable."""
        script_dir = os.path.join(os.path.dirname(__file__), '..', 'src', 'scripts', 'automations')
        worker_script = os.path.join(script_dir, '_mobsf_analysis_worker.py')
        
        assert os.path.exists(worker_script), "Worker script should exist"
        assert os.access(worker_script, os.R_OK), "Worker script should be readable"

class TestMobSFAPIConnectivity:
    """Test MobSF API connectivity and health."""
    
    def test_api_endpoint_availability(self):
        """Test that MobSF API endpoints are reachable when container is running."""
        # Ensure container is running
        if not is_mobsf_container_running():
            container_result = launch_mobsf_container(verbose=True)
            assert container_result is not False, "Need container for API test"
        
        # Wait for API readiness
        api_ready = wait_for_mobsf_ready(timeout=120, verbose=True)
        assert api_ready, "API should be ready for connectivity test"
        
        # Test upload endpoint (should return 405 for GET request)
        try:
            response = requests.get("http://localhost:8000/api/v1/upload", timeout=10)
            # 405 Method Not Allowed is expected for GET request to upload endpoint
            assert response.status_code in [200, 405], f"Upload endpoint should be accessible, got {response.status_code}"
            print("✅ MobSF API upload endpoint is accessible")
        except requests.RequestException as e:
            pytest.fail(f"Could not reach MobSF API: {e}")

# Test execution helper functions
def print_test_separator(test_name):
    """Print a visual separator for test sections."""
    print(f"\n{'='*60}")
    print(f"🧪 {test_name}")
    print(f"{'='*60}")

# Pytest configuration
def pytest_configure(config):
    """Pytest configuration hook."""
    print("\n🔬 Starting MobSF Integration Tests")
    print("This will test container management, APK upload, and process coordination.")

def pytest_sessionfinish(session, exitstatus):
    """Pytest session finish hook."""
    print(f"\n✅ MobSF Integration Tests Complete (exit status: {exitstatus})")
    if exitstatus == 0:
        print("🎉 All tests passed! MobSF integration is working correctly.")
        print("🌐 You can now access MobSF at: http://localhost:8000")
    else:
        print("❌ Some tests failed. Check the output above for details.")

if __name__ == "__main__":
    """Allow running tests directly with python test_mobsf_integration.py"""
    pytest.main([__file__, "-v", "-s"])