#!/usr/bin/env python3
"""
MobSF Docker Container Management

This module handles launching and managing the MobSF Docker container
for APK static analysis integration with automatool.

Following the same patterns as launch_jadx.py and launch_vscode.py.
"""

import subprocess
import time
import requests


def launch_mobsf_container(port=8000, verbose=False):
    """
    Launch MobSF Docker container as a background process.
    
    Args:
        port (int): Port to bind MobSF container to (default: 8000)
        verbose (bool): Enable verbose output
        
    Returns:
        subprocess.Popen or bool: Process object if launch was successful, False otherwise
    """
    if verbose:
        print("[DEBUG] Launching MobSF Docker container...")
    
    try:
        # Check if container already running
        if is_mobsf_container_running(port, verbose):
            if verbose:
                print(f"[DEBUG] MobSF container already running on port {port}")
            print(f"✅ MobSF container already running on port {port}")
            return True
            
        # Launch MobSF container as background process
        if verbose:
            print(f"[DEBUG] Starting new MobSF container on port {port}...")
            
        container_name = f"mobsf_automatool_{port}"
        process = subprocess.Popen([
            "sudo", "docker", "run", "-d", 
            "--name", container_name,
            "-p", f"{port}:8000",
            "opensecurity/mobile-security-framework-mobsf:latest"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
        )
        
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            if verbose:
                print(f"[DEBUG] ❌ Docker run command failed with return code {process.returncode}")
                print(f"[DEBUG] stdout: {stdout.strip()}")
                print(f"[DEBUG] stderr: {stderr.strip()}")
            return False
        
        if verbose:
            print(f"[DEBUG] ✅ MobSF container launched with PID: {process.pid}")
            
        # Wait for container to be ready
        if verbose:
            print("[DEBUG] Waiting for MobSF container to become ready...")
            
        if wait_for_mobsf_ready(port, timeout=120, verbose=verbose):
            print(f"✅ MobSF container ready at http://localhost:{port}")
            return process
        else:
            print("❌ ERROR: MobSF container failed to become ready")
            return False
            
    except FileNotFoundError:
        print("❌ ERROR: 'docker' command not found.")
        print("Please ensure Docker is installed and in your system PATH.")
        if verbose:
            print("[DEBUG] You can download Docker from: https://docker.com/get-started")
        return False
        
    except Exception as e:
        print(f"❌ ERROR: Failed to launch MobSF container: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False



def is_mobsf_container_running(port=8000, verbose=False):
    """Check if MobSF container is already running by checking the port."""
    try:
        if verbose:
            print(f"[DEBUG] Checking if MobSF container is running on port {port}...")
            
        # Find container by port
        result = subprocess.run(
            ["sudo", "docker", "ps", "--filter", f"publish={port}", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10
        )
        
        container_name = result.stdout.strip()
        is_running = bool(container_name)
        
        if verbose:
            if is_running:
                print(f"[DEBUG] Found container '{container_name}' running on port {port}")
            else:
                print(f"[DEBUG] No container found running on port {port}")
            
        return is_running
        
    except Exception as e:
        if verbose:
            print(f"[DEBUG] Error checking container status: {e}")
        return False

def wait_for_mobsf_ready(port=8000, timeout=120, verbose=False):
    """Wait for MobSF API to become available with health checks."""
    start_time = time.time()
    
    if verbose:
        print(f"[DEBUG] Starting health check on port {port} with {timeout}s timeout...")
    
    while time.time() - start_time < timeout:
        try:
            # Health check: check base URL, no API key needed
            response = requests.get(
                f"http://localhost:{port}/", 
                timeout=5
            )
            # Expect 200 OK on the main page
            if response.status_code == 200:
                if verbose:
                    print(f"[DEBUG] Health check successful (status: {response.status_code})")
                return True
                
        except requests.RequestException as e:
            if verbose:
                print(f"[DEBUG] Health check failed: {e}")
            pass
        
        time.sleep(2)
        if verbose:
            elapsed = int(time.time() - start_time)
            print(f"[DEBUG] Waiting for MobSF... ({elapsed}/{timeout}s)")
    
    if verbose:
        print(f"[DEBUG] Health check timed out after {timeout}s")
    return False


def get_mobsf_api_key(port=8000, verbose=False):
    """Retrieve API key from MobSF container logs by checking the port."""
    try:
        if verbose:
            print(f"[DEBUG] Retrieving API key from container logs for port {port}...")
            
        # Find container by port
        result = subprocess.run(
            ["sudo", "docker", "ps", "--filter", f"publish={port}", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10
        )
        
        container_name = result.stdout.strip()
        
        if not container_name:
            if verbose:
                print(f"[DEBUG] No container found on port {port}")
            return None
            
        if verbose:
            print(f"[DEBUG] Found container '{container_name}' on port {port}")
            
        # Get API key from container logs
        result = subprocess.run(
            ["sudo", "docker", "logs", container_name],
            capture_output=True, text=True, timeout=30
        )
        
        if verbose:
            print("[DEBUG] Searching through container logs...")
        
        # Parse API key from logs - look for various patterns
        all_lines = result.stdout.splitlines() + result.stderr.splitlines()
        
        for line in all_lines:
            line = line.strip()
            if verbose and "API Key" in line:
                print(f"[DEBUG] Found API Key line: {line}")
            
            # Try different patterns for API key extraction
            if "API Key" in line:
                # Pattern 1: "REST API Key: XXXXX" or "API Key: XXXXX"
                if ":" in line:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        api_key = parts[1].strip()
                        if api_key and len(api_key) > 10:  # Ensure it's a reasonable length
                            # Strip ANSI color codes
                            import re
                            api_key_clean = re.sub(r'\x1b\[[0-9;]*m', '', api_key)
                            if verbose:
                                print(f"[DEBUG] Extracted API key: {api_key_clean[:8]}... (length: {len(api_key_clean)})")
                            return api_key_clean
                
                # Pattern 2: "API Key XXXXX" (space separated)
                parts = line.split()
                if len(parts) >= 3:
                    # Look for "API Key" or "REST API Key" patterns
                    if (parts[0] == "API" and parts[1] == "Key") or \
                       (parts[0] == "REST" and parts[1] == "API" and parts[2] == "Key"):
                        # Get the last part as the API key
                        api_key = parts[-1]
                        if api_key and len(api_key) > 10:
                            # Strip ANSI color codes
                            import re
                            api_key_clean = re.sub(r'\x1b\[[0-9;]*m', '', api_key)
                            if verbose:
                                print(f"[DEBUG] Extracted API key: {api_key_clean[:8]}... (length: {len(api_key_clean)})")
                            return api_key_clean
        
        if verbose:
            print("[DEBUG] API key not found in logs")
            print("[DEBUG] Sample log lines:")
            for i, line in enumerate(all_lines[-10:]):  # Show last 10 lines
                print(f"[DEBUG]   {i}: {line}")
        return None
        
    except Exception as e:
        if verbose:
            print(f"[DEBUG] Failed to retrieve API key: {e}")
        return None




def stop_mobsf_container(port=8000, verbose=False):
    """Stop and remove MobSF container for cleanup."""
    try:
        if verbose:
            print(f"[DEBUG] Stopping MobSF container on port {port}...")
            
        container_name = f"mobsf_automatool_{port}"
        
        # Stop container
        subprocess.run([
            "sudo", "docker", "stop", container_name
        ], capture_output=True, text=True, timeout=30)
        
        # Remove container
        subprocess.run([
            "sudo", "docker", "rm", container_name
        ], capture_output=True, text=True, timeout=30)
        
        if verbose:
            print("[DEBUG] MobSF container stopped and removed")
        return True
        
    except Exception as e:
        if verbose:
            print(f"[DEBUG] Error stopping container: {e}")
        return False


if __name__ == "__main__":
    # Simple test when run directly
    import sys
    
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    port = 8000
    
    # Check for port argument
    if "--port" in sys.argv:
        try:
            port_index = sys.argv.index("--port")
            if port_index + 1 < len(sys.argv):
                port = int(sys.argv[port_index + 1])
        except (ValueError, IndexError):
            print("❌ Invalid port argument")
            sys.exit(1)
    
    print(f"🐳 Testing MobSF Container Management on port {port}")
    
    # Test container launch
    result = launch_mobsf_container(port=port, verbose=verbose)
    if result:
        print("✅ Container launch test successful")
        
        # Test API key retrieval
        api_key = get_mobsf_api_key(port=port, verbose=verbose)
        if api_key:
            print(f"✅ API key retrieved: {api_key[:8]}...")
        else:
            print("❌ Failed to retrieve API key")
            
    else:
        print("❌ Container launch test failed")
        sys.exit(1)


def is_mobsf_image_available(verbose=False):
    """Check if MobSF Docker image is available locally."""
    try:
        if verbose:
            print("[DEBUG] Checking if MobSF Docker image is available...")
            
        result = subprocess.run([
            "sudo", "docker", "images", "--format", "{{.Repository}}:{{.Tag}}", 
            "opensecurity/mobile-security-framework-mobsf"
        ], capture_output=True, text=True, timeout=30)
        
        # Check if the image exists in the output
        image_found = "opensecurity/mobile-security-framework-mobsf:latest" in result.stdout
        
        if verbose:
            print(f"[DEBUG] MobSF image available: {image_found}")
            if not image_found:
                print("[DEBUG] Available images:")
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        print(f"[DEBUG]   - {line}")
                        
        return image_found
        
    except Exception as e:
        if verbose:
            print(f"[DEBUG] Error checking image availability: {e}")
        return False


def delete_mobsf_analysis(scan_hash, port=8000, verbose=False):
    """
    Delete MobSF analysis from server.
    
    Args:
        scan_hash (str): MobSF analysis hash to delete
        port (int): Port where MobSF server is running (default: 8000)
        verbose (bool): Enable verbose output
        
    Returns:
        bool: True if successfully deleted or not found, False on error
    """
    try:
        if verbose:
            print(f"[DEBUG] Deleting MobSF analysis: {scan_hash[:8]} on port {port}...")
            
        # Get current API key
        api_key = get_mobsf_api_key(port, verbose)
        if not api_key:
            if verbose:
                print("[DEBUG] Failed to get API key for deletion")
            return False
            
        # Try deletion with Authorization header (we know this works)
        headers = {'Authorization': api_key}
        response = requests.post(
            f'http://localhost:{port}/api/v1/delete_scan',
            data={'hash': scan_hash},
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            if verbose:
                print(f"[DEBUG] ✅ Successfully deleted analysis {scan_hash[:8]}")
            return True
        elif response.status_code == 404:
            if verbose:
                print(f"[DEBUG] ✅ Analysis {scan_hash[:8]} not found (already deleted)")
            return True
        else:
            if verbose:
                print(f"[DEBUG] ❌ Deletion failed: HTTP {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        if verbose:
            print("[DEBUG] ⚠️  MobSF server not accessible")
        return False
    except Exception as e:
        if verbose:
            print(f"[DEBUG] ❌ Deletion error: {e}")
        return False