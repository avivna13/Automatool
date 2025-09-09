#!/usr/bin/env python3
"""
Launch APK Assets Image Steganography Analysis

This script launches the assets image analysis as a background process
following the same pattern as launch_mobsf_analysis.py.
"""

import subprocess
import os
import sys

def launch_assets_analysis(apktool_output_path, target_directory, verbose=False, threshold_bytes=10):
    """
    Launch APK assets image analysis as a background process.
    
    Args:
        apktool_output_path (str): Path to the apktool decompilation output directory
        target_directory (str): Base target directory for saving analysis results
        verbose (bool): Enable verbose output
        threshold_bytes (int): Suspicious threshold for steganography detection
        
    Returns:
        subprocess.Popen or bool: Process object if launch was successful, False otherwise
    """
    if verbose:
        print(f"[DEBUG] Launching assets analysis for: {apktool_output_path}")
        print(f"[DEBUG] Output directory: {target_directory}")
        print(f"[DEBUG] Threshold: {threshold_bytes} bytes")
    
    try:
        # Get the worker script path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        worker_script = os.path.join(script_dir, "_assets_analysis_worker.py")
        
        # Verify worker script exists
        if not os.path.exists(worker_script):
            print("❌ ERROR: Assets analysis worker script not found.")
            if verbose:
                print(f"[DEBUG] Expected worker script at: {worker_script}")
            return False
        
        # Launch analysis worker as background process
        process = subprocess.Popen([
            sys.executable, worker_script,
            "--apktool-path", apktool_output_path,
            "--output-dir", target_directory,
            "--threshold", str(threshold_bytes),
            "--verbose" if verbose else "--quiet"
        ],
        stdout=subprocess.DEVNULL,  # Suppress stdout
        stderr=subprocess.DEVNULL,  # Suppress stderr
        text=True
        )
        
        if verbose:
            print(f"[DEBUG] ✅ Assets analysis launched with PID: {process.pid}")
            
        print("🖼️ APK assets image analysis started in background...")
        return process
        
    except FileNotFoundError:
        print("❌ ERROR: Python executable not found for worker process.")
        if verbose:
            print(f"[DEBUG] Python executable: {sys.executable}")
        return False
        
    except Exception as e:
        print(f"❌ ERROR: Failed to launch assets analysis: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False
