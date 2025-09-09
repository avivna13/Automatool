#!/usr/bin/env python3
"""
TTF Font Analysis Launch Module

This module provides the launch function for integrating TTF font steganography detection
into the automatool workflow. It launches the font analysis as a background process
and integrates with the existing resource tracking system.

Usage:
    from launch_font_analysis import launch_font_analysis
    
    font_process = launch_font_analysis(
        apktool_output_path, 
        target_directory, 
        verbose=False
    )
"""

import os
import sys
import subprocess
from pathlib import Path


def launch_font_analysis(apktool_output_path, target_directory, verbose=False):
    """
    Launch TTF font analysis as a background process.
    
    Args:
        apktool_output_path (str): Path to the apktool decompilation output directory
        target_directory (str): Base target directory for saving analysis results
        verbose (bool): Enable verbose output
        
    Returns:
        subprocess.Popen or bool: Process object if launch was successful, False otherwise
    """
    if verbose:
        print(f"[DEBUG] Launching TTF font analysis for: {apktool_output_path}")
        print(f"[DEBUG] Output directory: {target_directory}")
    
    try:
        # Get the worker script path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        worker_script = os.path.join(script_dir, "_font_analysis_worker.py")
        
        # Verify worker script exists
        if not os.path.exists(worker_script):
            print("❌ ERROR: Font analysis worker script not found.")
            if verbose:
                print(f"[DEBUG] Expected worker script at: {worker_script}")
            return False
        
        # Launch analysis worker as background process
        process = subprocess.Popen([
            sys.executable, worker_script,
            "--apktool-path", apktool_output_path,
            "--output-dir", target_directory,
            "--verbose" if verbose else "--quiet"
        ],
        stdout=subprocess.DEVNULL,  # Suppress stdout
        stderr=subprocess.DEVNULL,  # Suppress stderr
        text=True
        )
        
        if verbose:
            print(f"[DEBUG] ✅ TTF font analysis launched with PID: {process.pid}")
            
        print("🔤 TTF font analysis started in background...")
        return process
        
    except FileNotFoundError:
        print("❌ ERROR: Python executable not found for worker process.")
        if verbose:
            print(f"[DEBUG] Python executable: {sys.executable}")
        return False
        
    except Exception as e:
        print(f"❌ ERROR: Failed to launch font analysis: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False


def main():
    """Command line interface for testing the launch function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Launch TTF font analysis")
    parser.add_argument("--apktool-path", required=True, help="Path to apktool output directory")
    parser.add_argument("--output-dir", required=True, help="Target output directory")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    print("🔤 TTF Font Analysis Launcher")
    print("=" * 40)
    
    result = launch_font_analysis(args.apktool_path, args.output_dir, args.verbose)
    
    if result:
        print(f"✅ Font analysis launched successfully with PID: {result.pid}")
        return 0
    else:
        print("❌ Failed to launch font analysis")
        return 1


if __name__ == "__main__":
    sys.exit(main())
