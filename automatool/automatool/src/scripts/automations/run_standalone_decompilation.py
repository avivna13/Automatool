#!/usr/bin/env python3
"""
Standalone APK Decompilation Script
Wrapper for run_apktool_decode.py to be used independently from main automatool flow.
"""

import argparse
import os
import sys
from run_apktool_decode import run_apktool_decode, get_decompilation_summary
from resource_tracker import GlobalResourceTracker

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Standalone APK decompilation using apktool + Jadx",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/app.apk /path/to/output/dir
  %(prog)s /path/to/app.apk /path/to/output/dir --verbose
        """
    )
   
    parser.add_argument(
        "apk_path",
        help="Path to the APK file to decompile"
    )
   
    parser.add_argument(
        "output_directory", 
        help="Output directory for decompilation results"
    )
   
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output for debugging"
    )
   
    return parser.parse_args()

def main():
    """Main entry point for standalone decompilation."""
    print("🔧 Starting standalone APK decompilation...")
   
    # Parse command line arguments
    args = parse_arguments()
    
    # Initialize resource tracker
    try:
        tracker = GlobalResourceTracker()
        if args.verbose:
            print("🔧 Resource tracker initialized")
    except Exception as e:
        print(f"⚠️  WARNING: Could not initialize resource tracker: {e}")
        tracker = None
   
    # Validate APK file exists
    if not os.path.exists(args.apk_path):
        print(f"❌ ERROR: APK file not found: {args.apk_path}")
        sys.exit(1)
   
    # Create output directory if it doesn't exist
    os.makedirs(args.output_directory, exist_ok=True)
   
    if args.verbose:
        print(f"[DEBUG] APK path: {args.apk_path}")
        print(f"[DEBUG] Output directory: {args.output_directory}")
   
    # Run decompilation
    try:
        results = run_apktool_decode(args.apk_path, args.output_directory, args.verbose)
        
        # Print summary
        if args.verbose:
            print("\n" + get_decompilation_summary(results))
        
        # Check results
        if results['success'] or (results['apktool_output'] or results['jadx_output']):
            # Track created directories
            if tracker:
                try:
                    if results['apktool_output']:
                        tracker.add_directory(results['apktool_output'])
                        if args.verbose:
                            print(f"📁 Tracked apktool directory: {results['apktool_output']}")
                    
                    if results['jadx_output']:
                        tracker.add_directory(results['jadx_output'])
                        if args.verbose:
                            print(f"📁 Tracked Jadx directory: {results['jadx_output']}")
                            
                except Exception as e:
                    print(f"⚠️  WARNING: Failed to track resources: {e}")
            
            print("✅ Decompilation completed successfully and resources tracked")
            
            if results['apktool_output']:
                print(f"📦 apktool output: {results['apktool_output']}")
            
            if results['jadx_output']:
                print(f"☕ Jadx output: {results['jadx_output']}")
                
            if results['errors']:
                print("⚠️ Some errors occurred:")
                for error in results['errors']:
                    print(f"  - {error}")
                    
            sys.exit(0)
        else:
            print("❌ Decompilation failed")
            if results['errors']:
                for error in results['errors']:
                    print(f"❌ {error}")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ ERROR: Decompilation failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
