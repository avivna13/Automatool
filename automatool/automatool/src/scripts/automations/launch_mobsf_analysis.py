import subprocess
import os
import sys

def launch_mobsf_analysis(apk_path, output_directory, verbose=False, port=8000):
    """
    Launch MobSF analysis as a background process.
    
    Args:
        apk_path (str): Path to the APK file
        output_directory (str): Directory to save results
        verbose (bool): Enable verbose output
        port (int): MobSF server port
        
    Returns:
        subprocess.Popen or bool: Process object if launch was successful, False otherwise
    """
    if verbose:
        print(f"[DEBUG] Launching MobSF analysis for: {apk_path}")
        print(f"[DEBUG] Output directory: {output_directory}")
        print(f"[DEBUG] MobSF Port: {port}")
    
    try:
        # Get the worker script path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        worker_script = os.path.join(script_dir, "_mobsf_analysis_worker.py")
        
        # Verify worker script exists
        if not os.path.exists(worker_script):
            print("❌ ERROR: MobSF analysis worker script not found.")
            if verbose:
                print(f"[DEBUG] Expected worker script at: {worker_script}")
            return False
        
        # Launch analysis worker as background process
        process = subprocess.Popen([
            sys.executable, worker_script,
            "--apk-path", apk_path,
            "--output-dir", output_directory,
            "--port", str(port),
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
        
    except FileNotFoundError:
        print("❌ ERROR: Python interpreter not found.")
        print("Please ensure Python is installed and in your system PATH.")
        if verbose:
            print(f"[DEBUG] Python executable: {sys.executable}")
        return False
        
    except Exception as e:
        print(f"❌ ERROR: Failed to launch MobSF analysis: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False

def check_mobsf_completion(mobsf_process, output_directory, verbose=False, timeout=180, port=8000):
    """
    Check if MobSF analysis has completed and collect results.
    
    Args:
        mobsf_process: subprocess.Popen object for the analysis process
        output_directory (str): Directory where results should be saved
        verbose (bool): Enable verbose output
        timeout (int): Maximum time to wait for completion (default: 3 minutes)
        port (int): MobSF server port
        
    Returns:
        str: Status message about the analysis results
    """
    if not mobsf_process:
        return "No MobSF analysis was started"
    
    if verbose:
        print("[DEBUG] Checking MobSF analysis completion...")
    
    # Check if process is still running
    poll_result = mobsf_process.poll()
    
    if poll_result is None:
        # Process still running
        if verbose:
            print(f"[DEBUG] MobSF analysis still running (PID: {mobsf_process.pid})")
        
        print("⏳ Waiting for MobSF analysis to complete...")
        
        try:
            # Wait with timeout
            mobsf_process.wait(timeout=timeout)
            poll_result = mobsf_process.poll()
        except subprocess.TimeoutExpired:
            print("⚠️  MobSF analysis still in progress - container and upload may still be running")
            print(f"🌐 You can check progress at: http://localhost:{port}")
            return "In Progress: MobSF analysis continuing in background"
    
    # Process completed, check results
    if poll_result == 0:
        # Success
        scan_info_file = os.path.join(output_directory, "mobsf_scan_info.txt")
        if os.path.exists(scan_info_file):
            print("✅ MobSF analysis setup complete")
            print(f"🌐 Access your analysis at: http://localhost:{port}")
            if verbose:
                print(f"[DEBUG] Scan info available: {scan_info_file}")
            return f"Success: MobSF analysis initiated - check {scan_info_file}"
        else:
            print("⚠️  MobSF analysis completed but no scan info found")
            print(f"🌐 Try accessing: http://localhost:{port}")
            return "Warning: MobSF analysis completed but no scan info file found"
    else:
        # Error
        error_messages = {
            1: "MobSF container failed to start",
            2: "API key retrieval failed",
            3: "APK upload failed", 
            4: "Analysis start failed",
            5: "Analysis timeout/failed",
            6: "Results download failed",
            7: "Unexpected error occurred"
        }
        
        error_msg = error_messages.get(poll_result, f"Unknown error (exit code: {poll_result})")
        print(f"❌ MobSF analysis failed: {error_msg}")
        
        if verbose:
            print(f"[DEBUG] Process exit code: {poll_result}")
            
        return f"Error: {error_msg}"

def get_mobsf_status(mobsf_process, verbose=False):
    """
    Get current status of MobSF analysis process without waiting.
    
    Args:
        mobsf_process: subprocess.Popen object for the analysis process
        verbose (bool): Enable verbose output
        
    Returns:
        str: Current status of the process
    """
    if not mobsf_process:
        return "No MobSF analysis process"
    
    poll_result = mobsf_process.poll()
    
    if poll_result is None:
        if verbose:
            print(f"[DEBUG] MobSF analysis running (PID: {mobsf_process.pid})")
        return "Running"
    elif poll_result == 0:
        if verbose:
            print("[DEBUG] MobSF analysis completed successfully")
        return "Completed Successfully"
    else:
        if verbose:
            print(f"[DEBUG] MobSF analysis failed (exit code: {poll_result})")
        return f"Failed (exit code: {poll_result})"
