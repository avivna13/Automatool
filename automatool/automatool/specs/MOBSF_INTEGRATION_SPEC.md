# 🐳 MobSF Docker Integration Specification

## **Overview**
Integrate MobSF (Mobile Security Framework) Docker container management and APK static analysis into the existing automatool workflow as a **background process** that starts immediately and runs in parallel with other automation tasks.

## **Purpose**
The MobSF integration will:
1. **Container Management**: Automatically start and manage MobSF Docker container
2. **Parallel Execution**: Run MobSF analysis as a separate background process from the beginning
3. **APK Analysis**: Upload APK to MobSF and retrieve comprehensive static analysis results
4. **Resource Tracking**: Full integration with existing GlobalResourceTracker system
5. **Non-Blocking**: Main workflow continues regardless of MobSF timing/status

## **Architecture Strategy**

### **Process-Based Execution (Not Threading)**
MobSF will use **subprocess.Popen** (following the same pattern as Jadx and VS Code) to run as completely separate background processes:

1. **Container Process**: Manages Docker container lifecycle
2. **Analysis Worker Process**: Coordinates APK upload, monitoring, and result collection

### **Early Start Integration** 
MobSF analysis starts **immediately after APK validation** (around line 103 in automatool.py), running in parallel with:
- Jadx GUI launch
- VS Code workspace setup
- Reviews scraping and parsing  
- Frida scripts preparation
- YARA analysis

## **File Structure**
```
automatool/automatool/src/scripts/automations/
├── launch_mobsf_container.py     # NEW: Docker container management
├── launch_mobsf_analysis.py      # NEW: Analysis process coordination  
└── _mobsf_analysis_worker.py     # NEW: Background analysis worker script
```

## **Implementation Details**

### **Phase 1: Container Management (`launch_mobsf_container.py`)**

Following the exact pattern from `launch_jadx.py` and `launch_vscode.py`:

```python
import subprocess
import time
import requests

def launch_mobsf_container(verbose=False):
    """
    Launch MobSF Docker container as a background process.
    
    Args:
        verbose (bool): Enable verbose output
        
    Returns:
        subprocess.Popen or bool: Process object if launch was successful, False otherwise
    """
    if verbose:
        print("[DEBUG] Launching MobSF Docker container...")
    
    try:
        # Check if container already running
        if is_mobsf_container_running(verbose):
            print("✅ MobSF container already running")
            return True
            
        # Launch MobSF container as background process
        process = subprocess.Popen([
            "docker", "run", "-d", 
            "--name", "mobsf_automatool",
            "-p", "8000:8000",
            "opensecurity/mobile-security-framework-mobsf:latest"
        ],
        stdout=subprocess.DEVNULL,  # Suppress stdout
        stderr=subprocess.DEVNULL,  # Suppress stderr  
        text=True
        )
        
        if verbose:
            print(f"[DEBUG] ✅ MobSF container launched with PID: {process.pid}")
            
        # Wait for container to be ready
        if wait_for_mobsf_ready(timeout=120, verbose=verbose):
            print("✅ MobSF container ready at http://localhost:8000")
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

def is_mobsf_container_running(verbose=False):
    """Check if MobSF container is already running."""
    try:
        result = subprocess.run([
            "docker", "ps", "--filter", "name=mobsf_automatool", 
            "--format", "{{.Names}}"
        ], capture_output=True, text=True, timeout=10)
        
        return "mobsf_automatool" in result.stdout
    except Exception:
        return False
    
def wait_for_mobsf_ready(timeout=120, verbose=False):
    """Wait for MobSF API to become available with health checks."""
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        try:
            # Simple health check to API endpoint
            response = requests.get(
                "http://localhost:8000/api/v1/upload", 
                timeout=5
            )
            if response.status_code in [200, 405]:  # 405 Method Not Allowed is expected for GET
                return True
        except requests.RequestException:
            pass
        
        time.sleep(2)
        if verbose:
            elapsed = int(time.time() - start_time)
            print(f"[DEBUG] Waiting for MobSF... ({elapsed}/{timeout}s)")
    
    return False

def get_mobsf_api_key(verbose=False):
    """Retrieve API key from MobSF container logs."""
    try:
        # Get API key from container logs
        result = subprocess.run([
            "docker", "logs", "mobsf_automatool"
        ], capture_output=True, text=True, timeout=30)
        
        # Parse API key from logs
        for line in result.stdout.splitlines() + result.stderr.splitlines():
            if "API Key" in line:
                # Extract key after "API Key:" 
                parts = line.split(":", 1)
                if len(parts) > 1:
                    api_key = parts[1].strip()
                    if verbose:
                        print(f"[DEBUG] Retrieved API key: {api_key[:8]}...")
                    return api_key
        
        if verbose:
            print("[DEBUG] API key not found in logs")
        return None
        
    except Exception as e:
        if verbose:
            print(f"[DEBUG] Failed to retrieve API key: {e}")
        return None
```

**Key Functions:**
- `launch_mobsf_container()` - Main container launch function
- `is_mobsf_container_running()` - Status check using docker ps
- `wait_for_mobsf_ready()` - Health check with HTTP requests
- `get_mobsf_api_key()` - Retrieve API key from container logs
- `stop_mobsf_container()` - Cleanup function

### **Phase 2: Analysis Coordination (`launch_mobsf_analysis.py`)**

Creates a coordination process that handles the entire APK analysis workflow:

```python
import subprocess
import os
import sys

def launch_mobsf_analysis(apk_path, output_directory, verbose=False):
    """
    Launch MobSF analysis as a background process.
    
    Args:
        apk_path (str): Path to the APK file
        output_directory (str): Directory to save results
        verbose (bool): Enable verbose output
        
    Returns:
        subprocess.Popen or bool: Process object if launch was successful, False otherwise
    """
    if verbose:
        print(f"[DEBUG] Launching MobSF analysis for: {apk_path}")
        print(f"[DEBUG] Output directory: {output_directory}")
    
    try:
        # Get the worker script path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        worker_script = os.path.join(script_dir, "_mobsf_analysis_worker.py")
        
        # Launch analysis worker as background process
        process = subprocess.Popen([
            sys.executable, worker_script,
            "--apk-path", apk_path,
            "--output-dir", output_directory,
            "--verbose" if verbose else "--quiet"
        ],
        stdout=subprocess.DEVNULL,  # Suppress stdout
        stderr=subprocess.DEVNULL,  # Suppress stderr
        text=True
        )
        
        if verbose:
            print(f"[DEBUG] ✅ MobSF analysis launched with PID: {process.pid}")
            
        print("🔍 MobSF analysis started in background...")
        return process
        
    except Exception as e:
        print(f"❌ ERROR: Failed to launch MobSF analysis: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False

def check_mobsf_completion(mobsf_process, output_directory, verbose=False, timeout=60):
    """Check if MobSF analysis has completed and collect results."""
    # Process status checking and result collection
```

**Key Functions:**
- `launch_mobsf_analysis()` - Main analysis launch function
- `check_mobsf_completion()` - Final result collection
- Error handling following existing patterns

### **Phase 3: Analysis Worker Script (`_mobsf_analysis_worker.py`)**

Separate Python script that runs as the background process:

```python
#!/usr/bin/env python3
"""
MobSF Analysis Worker Process

This script runs as a separate process to handle the entire MobSF analysis workflow:
1. Start MobSF container if needed
2. Upload APK 
3. Monitor analysis progress
4. Download results

This follows the same pattern as other automatool background processes.
"""

import argparse
import os
import sys
import json
import time
import requests
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="MobSF Analysis Worker")
    parser.add_argument("--apk-path", required=True, help="Path to APK file")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--quiet", action="store_true", help="Suppress output")
    
    args = parser.parse_args()
    verbose = args.verbose and not args.quiet
    
    try:
        # 1. Ensure MobSF container is running
        if not ensure_container_running(verbose):
            sys.exit(1)
        
        # 2. Get API key
        api_key = get_api_key(verbose)
        if not api_key:
            sys.exit(2)
        
        # 3. Upload APK
        scan_hash = upload_apk(args.apk_path, api_key, verbose)
        if not scan_hash:
            sys.exit(3)
        
        # 4. Start analysis scan
        if not start_analysis(scan_hash, api_key, verbose):
            sys.exit(4)
        
        # 5. Wait for analysis completion  
        if not wait_for_analysis(scan_hash, api_key, verbose):
            sys.exit(5)
        
        # 6. Download results
        if not download_results(scan_hash, api_key, args.output_dir, verbose):
            sys.exit(6)
            
        sys.exit(0)  # Success
        
    except Exception as e:
        if verbose:
            print(f"[WORKER] ERROR: {e}")
        sys.exit(5)

# Implementation of worker functions:
# - ensure_container_running()
# - get_api_key()
# - upload_apk() 
# - start_analysis()
# - wait_for_analysis()
# - download_results()

def upload_apk(apk_path, api_key, verbose=False):
    """Upload APK to MobSF and return scan hash."""
    try:
        with open(apk_path, 'rb') as f:
            files = {'file': f}
            headers = {'Authorization': api_key}
            
            response = requests.post(
                'http://localhost:8000/api/v1/upload',
                files=files,
                headers=headers,
                timeout=600  # 10 minute timeout for large APKs
            )
            
            if response.status_code == 200:
                result = response.json()
                scan_hash = result.get('hash')
                if verbose:
                    print(f"[WORKER] Upload successful, hash: {scan_hash}")
                return scan_hash
            else:
                if verbose:
                    print(f"[WORKER] Upload failed: {response.status_code}")
                return None
                
    except Exception as e:
        if verbose:
            print(f"[WORKER] Upload error: {e}")
        return None

def start_analysis(scan_hash, api_key, verbose=False):
    """Start MobSF analysis scan."""
    try:
        data = {'hash': scan_hash}
        headers = {'Authorization': api_key}
        
        response = requests.post(
            'http://localhost:8000/api/v1/scan',
            data=data,
            headers=headers,
            timeout=60
        )
        
        if response.status_code == 200:
            if verbose:
                print(f"[WORKER] Analysis started for hash: {scan_hash}")
            return True
        else:
            if verbose:
                print(f"[WORKER] Analysis start failed: {response.status_code}")
            return False
            
    except Exception as e:
        if verbose:
            print(f"[WORKER] Analysis start error: {e}")
        return False
```

**Exit Codes:**
- `0` - Success
- `1` - Container startup failed
- `2` - API key retrieval failed
- `3` - APK upload failed  
- `4` - Analysis start failed
- `5` - Analysis timeout/failed
- `6` - Results download failed
- `7` - Unexpected error

## **Integration with Main Workflow**

### **Command Line Arguments**
Add new optional flag to `automatool.py`:

```python
# In parse_arguments() function:
parser.add_argument(
    "--mobsf",
    action="store_true",
    help="Run MobSF static analysis on the APK in background process"
)
```

### **Main Workflow Integration**
```python
# In automatool.py main() function:

def main():
    # ... existing VPN and file validation ...
    
    # Extract package name from APK
    package_name = extract_package_name_with_fallback(apk_path, args.verbose)
    
    # Track package name and APK filename
    resource_tracker.set_package_name(package_name)
    resource_tracker.set_apk_filename(args.filename)
    
    # 🆕 Launch MobSF analysis EARLY (right after package extraction)
    mobsf_process = None
    if args.mobsf:
        mobsf_process = launch_mobsf_analysis(apk_path, args.directory, args.verbose)
        if mobsf_process:
            # Only track the analysis worker process, NOT the Docker container
            resource_tracker.add_process("mobsf_analysis", mobsf_process.pid)
    
    # Launch Jadx GUI for APK analysis (existing)
    jadx_process = launch_jadx_gui(apk_path, args.verbose)
    if jadx_process:
        resource_tracker.add_process("jadx", jadx_process.pid)
    
    # Launch VS Code workspace (existing)
    vscode_process = launch_vscode(args.directory, args.verbose)
    if vscode_process:
        resource_tracker.add_process("vscode", vscode_process.pid)
    
    # ... rest of workflow continues in parallel ...
    # - Run reviews scraping (threading)
    # - Copy Frida scripts
    # - Parse YARA results
    # - Generate research plan
    
    # 🆕 Check MobSF completion at the end
    if mobsf_process:
        mobsf_results = check_mobsf_completion(mobsf_process, args.directory, args.verbose)
        # Track MobSF results files if they exist
        mobsf_results_dir = os.path.join(args.directory, "mobsf_results")
        if os.path.exists(mobsf_results_dir):
            resource_tracker.add_directory(mobsf_results_dir)
```

## **Resource Management**

### **Process Tracking**
MobSF processes are tracked with **special handling for Docker containers**:

```python
# ❌ DO NOT track container process - containers should persist
# Container is managed separately and not killed during cleanup

# ✅ Track only the analysis worker process  
resource_tracker.add_process("mobsf_analysis", analysis_process.pid)

# ✅ Track results directory for cleanup
resource_tracker.add_directory(mobsf_results_dir)
```

**Container Persistence Strategy:**
- Docker containers are **NOT tracked** by GlobalResourceTracker
- Containers **persist across automation runs** for performance
- Manual container management via separate commands if needed

### **File Output Structure**
```
target_directory/
├── mobsf_results/
│   ├── analysis_report.json     # Main analysis report
│   ├── analysis_report.pdf      # PDF report (optional)
│   ├── scan_info.txt           # Scan metadata
│   └── mobsf_summary.txt       # Human-readable summary
├── reviews.json                 # Existing files
├── reviews_summary.txt
├── frida_scripts/
└── research_plan.txt
```

### **Container Lifecycle Management**
- **Startup**: Check if container exists, start if needed
- **Health Check**: Verify API accessibility before proceeding
- **Persistence**: Containers are **NOT cleaned up** automatically - they persist for reuse
- **Reuse**: Container can be reused for multiple analyses (performance benefit)
- **Manual Management**: Users can manually stop containers when no longer needed

## **MobSF API Integration**

### **API Endpoints Used**
```
POST /api/v1/upload           # Upload APK file
POST /api/v1/scan             # Start analysis with hash
GET  /api/v1/report_json      # Download JSON report
GET  /api/v1/report_pdf       # Download PDF report (optional)
```

### **API Authentication**
MobSF requires an API key for authentication. The API key is generated when the container starts and can be retrieved from container logs.

**API Key Retrieval Process:**
```bash
# Get API key from container logs
docker logs mobsf_automatool 2>&1 | grep "API Key" | tail -1 | cut -d: -f2 | tr -d ' '
```

**API Usage Examples:**
```bash
# Upload APK (using curl.exe for Windows PowerShell compatibility)
curl.exe -F "file=@/path/to/app.apk" http://localhost:8000/api/v1/upload -H "Authorization: API_KEY_HERE"

# Start analysis scan
curl.exe -X POST --url http://localhost:8000/api/v1/scan --data "hash=HASH_FROM_UPLOAD" -H "Authorization: API_KEY_HERE"

# Download JSON report
curl.exe -X POST --url http://localhost:8000/api/v1/report_json --data "hash=HASH_FROM_UPLOAD" -H "Authorization: API_KEY_HERE"
```

### **Docker Configuration**
```bash
# Container startup command
docker run -d --name mobsf_automatool -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

# Health check (API endpoint verification)
curl -f http://localhost:8000/api/v1/upload

# Container status check
docker ps --filter "name=mobsf_automatool" --format "{{.Names}}"

# Container logs (for API key retrieval)
docker logs mobsf_automatool
```

## **Error Handling Strategy**

### **Docker-Related Errors**
- **Docker not installed**: Clear error message with installation instructions
- **Docker daemon not running**: Instructions to start Docker service
- **Port 8000 already in use**: Suggest alternative ports or conflict resolution
- **Container fails to start**: Check Docker resources and permissions
- **Image pull failures**: Network connectivity and Docker Hub access

### **MobSF API Errors**
- **API timeout**: Retry mechanism with exponential backoff
- **Upload failure**: Validate APK file size, format, and network connectivity
- **Analysis failure**: Capture and display MobSF error messages
- **Download failure**: Retry with different formats, fallback to basic info

### **Process Management Errors**
- **Worker script not found**: Clear path validation and error messages
- **Process launch failure**: Fallback to manual instructions
- **Background process crash**: Continue workflow, provide status information
- **Resource tracking failure**: Log errors but don't halt main workflow

### **Graceful Degradation**
- **MobSF unavailable**: Main workflow continues without MobSF analysis
- **Container timeout**: Workflow completes, user gets manual instructions
- **Analysis timeout**: Background process continues, results available later
- **Results missing**: Warning message, workflow continues

## **Configuration Options**

### **Environment Variables**
```python
# Docker configuration
MOBSF_DOCKER_IMAGE = "opensecurity/mobile-security-framework-mobsf:latest"
MOBSF_CONTAINER_NAME = "mobsf_automatool"
MOBSF_PORT = 8000
MOBSF_API_BASE = f"http://localhost:{MOBSF_PORT}/api/v1"

# API endpoints
MOBSF_UPLOAD_ENDPOINT = f"{MOBSF_API_BASE}/upload"
MOBSF_SCAN_ENDPOINT = f"{MOBSF_API_BASE}/scan"
MOBSF_REPORT_JSON_ENDPOINT = f"{MOBSF_API_BASE}/report_json"
MOBSF_REPORT_PDF_ENDPOINT = f"{MOBSF_API_BASE}/report_pdf"

# Timeout configuration  
MOBSF_CONTAINER_TIMEOUT = 120  # Container startup (2 minutes)
MOBSF_API_KEY_TIMEOUT = 60     # API key retrieval (1 minute)
MOBSF_UPLOAD_TIMEOUT = 600     # APK upload timeout (10 minutes)
MOBSF_SCAN_START_TIMEOUT = 60  # Scan start timeout (1 minute)
MOBSF_ANALYSIS_TIMEOUT = 600   # APK analysis (10 minutes)
MOBSF_COLLECTION_TIMEOUT = 180 # Final result collection (3 minutes)
MOBSF_API_TIMEOUT = 60         # Individual API calls (1 minute)
```

### **API Key Management**
The API key is automatically retrieved from container logs and used for all API calls:
```python
# API key extraction pattern
API_KEY_PATTERN = r"API Key[:\s]+([a-f0-9]+)"

# API headers format
def get_api_headers(api_key):
    return {"Authorization": api_key}
```

### **Runtime Parameters**
- Custom Docker image/version
- Alternative port mapping  
- Analysis timeout configuration
- Report format selection (JSON/PDF/both)
- Container reuse vs fresh start

## **Progress Indicators**

### **Early Stage (Immediate)**
```
✅ VPN Status: Connected to United States
✅ APK validated: /path/to/app.apk
🐳 MobSF container ready at http://localhost:8000
🔍 MobSF analysis started in background...
✅ Jadx GUI launched successfully
✅ VS Code workspace opened: /path/to/directory
```

### **During Workflow**
```
📊 MobSF analysis in progress...
✅ Reviews scraper completed: reviews.json
✅ Frida scripts copied and configured
✅ YARA analysis complete: yara_summary.txt
```

### **End of Workflow**
```
⏳ Waiting for MobSF analysis to complete...
✅ MobSF analysis complete: mobsf_results/
--- APK Analysis Automation Complete ---
```

### **Alternative Scenarios**
```
⚠️  MobSF analysis still in progress - results will be available later
❌ MobSF analysis failed with exit code: 2
🐳 MobSF container starting (this may take a moment)...
```

## **Testing Strategy**

### **Unit Tests**
- Mock Docker commands for container management
- Mock HTTP requests for MobSF API calls  
- Test error scenarios (Docker unavailable, API failures)
- Validate file output generation and structure
- Test process lifecycle management

### **Integration Tests**
- Test full workflow with real MobSF container
- Validate file outputs and resource tracking
- Test cleanup on various failure scenarios
- Test parallel execution with other tools
- Performance testing for large APK files

### **Test Structure**
```
automatool/automatool/tests/
├── test_mobsf_container.py          # Container management tests
├── test_mobsf_analysis.py           # Analysis workflow tests  
├── test_mobsf_integration.py        # Full integration tests
└── resources/
    ├── sample_mobsf_response.json   # Mock API responses
    └── test_apk_small.apk          # Test APK file
```

## **Security Considerations**

### **Docker Security**
- Container runs with minimal privileges
- Network isolation (localhost only by default)
- No volume mounts to sensitive directories
- **Container persistence** - no auto-removal (performance optimization)
- Manual cleanup available when containers no longer needed

### **API Security**
- Local-only communication (no external exposure)
- Input validation for APK files
- Timeout protection against hanging requests
- Error message sanitization

### **File Permissions**
- Results directory created with appropriate permissions
- Temporary file cleanup
- APK file validation before upload

## **Performance Considerations**

### **Resource Usage**
- MobSF container memory requirements (~2GB RAM)
- Concurrent execution impact on system resources
- APK file size limitations and upload timeouts
- Analysis time scaling with APK complexity

### **Optimization Strategies**
- Container reuse across multiple analyses
- Parallel API calls where possible
- Incremental result downloading
- Background process monitoring and cleanup

## **User Experience**

### **Help and Documentation**
```bash
# Usage examples
automatool.py -d "/path/to/apk" -f "app.apk" --mobsf
automatool.py -d "/path/to/apk" -f "app.apk" --mobsf --verbose

# Manual container management (when needed)
docker ps --filter "name=mobsf_automatool"           # Check container status
docker logs mobsf_automatool | grep "API Key"        # Get API key
docker stop mobsf_automatool                        # Stop container
docker rm mobsf_automatool                          # Remove container
docker system prune                                 # Clean up unused containers

# Manual API testing
curl.exe -F "file=@app.apk" http://localhost:8000/api/v1/upload -H "Authorization: YOUR_API_KEY"
curl.exe -X POST --url http://localhost:8000/api/v1/scan --data "hash=HASH_FROM_UPLOAD" -H "Authorization: YOUR_API_KEY"
```

### **Error Messages with Solutions**
- Clear Docker installation instructions
- MobSF troubleshooting guide
- Port conflict resolution steps
- Manual analysis instructions as fallback

### **Status Reporting**
- Real-time progress indicators
- Clear completion messages
- Results location information
- Background process status updates

## **Implementation Phases**

### **Phase 1: Container Management**
1. Implement `launch_mobsf_container.py`
2. Docker integration and health checks
3. Basic error handling and validation
4. Unit tests for container functions

### **Phase 2: Analysis Worker** 
1. Implement `_mobsf_analysis_worker.py`
2. MobSF API integration
3. File output management
4. Worker process testing

### **Phase 3: Process Coordination**
1. Implement `launch_mobsf_analysis.py`  
2. Background process management
3. Result collection and validation
4. Integration with resource tracker

### **Phase 4: Main Workflow Integration**
1. Add command line arguments
2. Integrate with automatool.py main flow
3. Resource tracking integration
4. End-to-end testing

### **Phase 5: Documentation and Cleanup**
1. User documentation
2. Error handling refinement
3. Performance optimization
4. Final testing and validation

## **Key Benefits**

1. **Maximum Parallelism**: MobSF analysis (5-10 minutes) runs while other tools launch and work
2. **True Process Isolation**: Separate OS process provides resource isolation and crash protection  
3. **Non-Blocking Workflow**: Main automation continues regardless of MobSF timing
4. **Container Persistence**: Docker containers persist for reuse, improving subsequent analysis performance
5. **Consistent Patterns**: Uses same subprocess.Popen approach as Jadx and VS Code
6. **Comprehensive Analysis**: Adds professional-grade static analysis to the toolkit
7. **Graceful Degradation**: Workflow completes successfully even if MobSF fails
8. **Smart Resource Management**: Tracks analysis processes but preserves containers for efficiency
9. **User-Friendly**: Clear progress indicators and error messages

This specification provides a comprehensive, maintainable, and robust integration that follows established automatool patterns while adding powerful static analysis capabilities through MobSF's industry-standard analysis engine.
