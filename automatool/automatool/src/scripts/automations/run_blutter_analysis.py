#!/usr/bin/env python3
"""
Blutter Flutter Analysis Script with Resource Tracking
Decompiles Flutter libapp.so files using Blutter tool and tracks created resources for cleanup.
"""

import argparse
import os
import sys
import subprocess
from resource_tracker import GlobalResourceTracker

def run_blutter_analysis(output_dir, verbose=False):
    """
    Run Blutter analysis on libapp.so from APK decompilation output.
    
    Args:
        output_dir (str): Directory containing apktool_output with lib files
        verbose (bool): Enable verbose output
        
    Returns:
        dict: Results with success status and output paths
    """
    if verbose:
        print("🦋 Starting Blutter Flutter analysis...")
    
    # Initialize resource tracker
    tracker = None
    try:
        tracker = GlobalResourceTracker()
        if verbose:
            print("🔧 Resource tracker initialized")
    except Exception as e:
        print(f"⚠️  WARNING: Could not initialize resource tracker: {e}")
    
    # Build path to lib directory from apktool output
    lib_dir = os.path.join(output_dir, "apktool_output", "lib", "arm64-v8a")
    libapp_path = os.path.join(lib_dir, "libapp.so")
    
    # Check if libapp.so exists
    if not os.path.exists(libapp_path):
        if verbose:
            print(f"❌ libapp.so not found at: {libapp_path}")
            print("💡 This may not be a Flutter app or APK decompilation hasn't run yet")
        return {
            'success': False,
            'error': 'libapp.so not found - not a Flutter app or decompilation needed first',
            'output_dir': None
        }
    
    # Create Blutter output directory
    blutter_output_dir = os.path.join(output_dir, "blutter_output")
    os.makedirs(blutter_output_dir, exist_ok=True)
    
    # Track the output directory for cleanup
    if tracker:
        try:
            tracker.add_directory(blutter_output_dir)
            if verbose:
                print(f"📁 Tracked directory for cleanup: {blutter_output_dir}")
        except Exception as e:
            print(f"⚠️  WARNING: Failed to track directory: {e}")
    
    # Get Blutter script path (relative to current script location)
    current_dir = os.path.dirname(os.path.abspath(__file__))
    blutter_script = os.path.join(current_dir, "..", "..", "blutter", "blutter.py")
    
    if verbose:
        print(f"📁 Lib directory: {lib_dir}")
        print(f"📱 libapp.so found: {libapp_path}")
        print(f"📂 Output directory: {blutter_output_dir}")
        print(f"🔧 Blutter script: {blutter_script}")
    
    # Verify Blutter script exists
    if not os.path.exists(blutter_script):
        error_msg = f"Blutter script not found at: {blutter_script}"
        if verbose:
            print(f"❌ ERROR: {error_msg}")
        return {'success': False, 'error': error_msg, 'output_dir': None}
    
    # Run Blutter
    try:
        cmd = ["python3", blutter_script, lib_dir, blutter_output_dir]
        if verbose:
            print(f"[DEBUG] Running command: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            cwd=os.path.dirname(blutter_script)
        )
        
        if verbose:
            print("✅ Blutter completed successfully")
            if result.stdout.strip():
                print(f"[DEBUG] Blutter stdout: {result.stdout.strip()}")
        
        # Track individual output files for cleanup
        if tracker:
            try:
                # Track common Blutter output files
                output_files = [
                    os.path.join(blutter_output_dir, "blutter_frida.js"),
                    os.path.join(blutter_output_dir, "objs.txt"),
                    os.path.join(blutter_output_dir, "pp.txt")
                ]
                
                for file_path in output_files:
                    if os.path.exists(file_path):
                        tracker.add_file(file_path)
                        if verbose:
                            print(f"📄 Tracked file for cleanup: {os.path.basename(file_path)}")
                
                # Track asm directory if it exists
                asm_dir = os.path.join(blutter_output_dir, "asm")
                if os.path.exists(asm_dir):
                    tracker.add_directory(asm_dir)
                    if verbose:
                        print(f"📁 Tracked asm directory for cleanup")
                        
            except Exception as e:
                print(f"⚠️  WARNING: Failed to track output files: {e}")
        
        return {
            'success': True,
            'output_dir': blutter_output_dir,
            'lib_path': libapp_path
        }
        
    except FileNotFoundError:
        error_msg = "Blutter script not found or Python3 not available"
        if verbose:
            print(f"❌ ERROR: {error_msg}")
        return {'success': False, 'error': error_msg, 'output_dir': None}
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Blutter failed with exit code {e.returncode}"
        if verbose:
            print(f"❌ ERROR: {error_msg}")
            print(f"[DEBUG] Stderr: {e.stderr}")
        return {'success': False, 'error': error_msg, 'output_dir': None}

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Flutter Blutter Analysis with Resource Tracking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/output/dir
  %(prog)s /path/to/output/dir --verbose
        """
    )
    
    parser.add_argument(
        "output_dir",
        help="Output directory containing apktool_output with lib files"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    return parser.parse_args()

def main():
    """Main entry point for standalone execution."""
    args = parse_arguments()
    
    print("🦋 Starting Blutter Flutter Analysis")
    print(f"📁 Output directory: {args.output_dir}")
    
    if not os.path.exists(args.output_dir):
        print(f"❌ ERROR: Output directory not found: {args.output_dir}")
        sys.exit(1)
    
    try:
        result = run_blutter_analysis(args.output_dir, args.verbose)
        
        if result['success']:
            print(f"✅ Blutter analysis completed successfully")
            print(f"📂 Results saved to: {result['output_dir']}")
            print("🧹 Resources tracked for cleanup - use cleanup automation to remove later")
        else:
            print(f"❌ Blutter analysis failed: {result['error']}")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ ERROR: Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
