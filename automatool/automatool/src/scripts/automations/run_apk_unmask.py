
import subprocess
import os
import sys
import argparse

# Import the filtering and file analysis functionality
from .apk_unmask_filter import ApkUnmaskFilter, ApkUnmaskParser
from .file_analyzer import FileAnalyzer, is_file_command_available
from .resource_tracker import GlobalResourceTracker

def run_apk_unmask(apk_path, output_dir, verbose=False, enable_filtering=True, enable_file_analysis=False, apktool_output_dir=None):
    """
    Runs the apk_unmask tool with optional false positive filtering and file type analysis.

    Args:
        apk_path (str): The absolute path to the APK file.
        output_dir (str): The directory to save the output file in.
        verbose (bool): Whether to print verbose output.
        enable_filtering (bool): Enable false positive filtering using ignore list.
        enable_file_analysis (bool): Run 'file' command on suspicious files for type analysis.
        apktool_output_dir (str, optional): Path to apktool decompiled output directory for file analysis.

    Returns:
        str: The path to the output file, or None if the operation failed.
    """
    # Initialize resource tracker
    try:
        tracker = GlobalResourceTracker()
        if verbose:
            print("🔧 Resource tracker initialized")
    except Exception as e:
        if verbose:
            print(f"⚠️  WARNING: Could not initialize resource tracker: {e}")
        tracker = None
    
    if verbose:
        print("🎭 Running apk_unmask analysis...")

    # Get the absolute path of the src directory to locate apk_unmask
    script_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    apk_unmask_path = os.path.join(script_dir, "apk_unmask")

    if not os.path.exists(apk_unmask_path):
        print(f"❌ ERROR: apk_unmask executable not found at {apk_unmask_path}")
        return None

    # Make sure it's executable
    if not os.access(apk_unmask_path, os.X_OK):
        print(f"❌ ERROR: apk_unmask is not executable. Please run 'chmod +x {apk_unmask_path}'")
        return None

    output_file_path = os.path.join(output_dir, "apk_unmask_output.txt")
    command = [apk_unmask_path, apk_path]

    try:
        if verbose:
            print(f"[DEBUG] Running command: {' '.join(command)}")
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )

        # Get the raw output from apk_unmask
        raw_output = result.stdout
        
        # Apply filtering if enabled
        if enable_filtering:
            if verbose:
                print("🔍 Applying false positive filtering...")
            
            try:
                filter_obj = ApkUnmaskFilter(verbose=verbose)
                filtered_output = filter_obj.filter_output(raw_output)
                
                # Save the filtered output
                with open(output_file_path, "w") as f:
                    f.write(filtered_output)
                
                # Track the output file
                if tracker:
                    try:
                        tracker.add_file(output_file_path)
                        if verbose:
                            print(f"📄 Tracked file: {output_file_path}")
                    except Exception as e:
                        if verbose:
                            print(f"⚠️  WARNING: Failed to track file: {e}")
                
                if verbose:
                    print(f"✅ Filtered apk_unmask output saved to {output_file_path}")
                    
            except Exception as e:
                if verbose:
                    print(f"⚠️  WARNING: Filtering failed, saving raw output: {e}")
                # Fallback to raw output if filtering fails
                with open(output_file_path, "w") as f:
                    f.write(raw_output)
                
                # Track the output file (fallback case)
                if tracker:
                    try:
                        tracker.add_file(output_file_path)
                        if verbose:
                            print(f"📄 Tracked file: {output_file_path}")
                    except Exception as e:
                        if verbose:
                            print(f"⚠️  WARNING: Failed to track file: {e}")
        else:
            # Save raw output without filtering
            with open(output_file_path, "w") as f:
                f.write(raw_output)
            
            # Track the output file (raw output case)
            if tracker:
                try:
                    tracker.add_file(output_file_path)
                    if verbose:
                        print(f"📄 Tracked file: {output_file_path}")
                except Exception as e:
                    if verbose:
                        print(f"⚠️  WARNING: Failed to track file: {e}")
            
            if verbose:
                print(f"✅ Raw apk_unmask output saved to {output_file_path}")

        # File analysis integration
        if enable_file_analysis:
            if verbose:
                print("🔬 Starting file type analysis...")
            
            # Check if file command is available
            if not is_file_command_available():
                if verbose:
                    print("⚠️  WARNING: 'file' command not available, skipping file analysis")
                return output_file_path
            
            # Check if apktool output directory is provided
            if not apktool_output_dir:
                if verbose:
                    print("⚠️  WARNING: apktool_output_dir not provided, skipping file analysis")
                return output_file_path
            
            if not os.path.exists(apktool_output_dir):
                if verbose:
                    print(f"⚠️  WARNING: apktool output directory not found: {apktool_output_dir}")
                return output_file_path
            
            try:
                # Create file analyzer
                analyzer = FileAnalyzer(apktool_output_dir, verbose=verbose)
                
                # Extract file paths from the filtered output
                filter_obj = ApkUnmaskFilter(verbose=False)  # Create a temporary filter for path extraction
                file_paths = filter_obj.extract_file_paths(filtered_output if enable_filtering else raw_output)
                
                if file_paths:
                    # Analyze the files
                    analysis_results = analyzer.analyze_multiple_files(file_paths)
                    
                    # Generate enhanced output with file type information
                    parser = ApkUnmaskParser()
                    enhanced_output = parser.generate_enhanced_output(
                        filtered_output if enable_filtering else raw_output,
                        analysis_results
                    )
                    
                    # Save enhanced output to a separate file
                    enhanced_output_path = output_file_path.replace('.txt', '_enhanced.txt')
                    with open(enhanced_output_path, "w") as f:
                        f.write(enhanced_output)
                    
                    # Track the enhanced output file
                    if tracker:
                        try:
                            tracker.add_file(enhanced_output_path)
                            if verbose:
                                print(f"📄 Tracked enhanced file: {enhanced_output_path}")
                        except Exception as e:
                            if verbose:
                                print(f"⚠️  WARNING: Failed to track enhanced file: {e}")
                    
                    if verbose:
                        successful_analyses = sum(1 for r in analysis_results.values() if r.get('analysis_success', False))
                        print(f"✅ File analysis complete: {successful_analyses}/{len(file_paths)} files analyzed")
                        print(f"📄 Enhanced output saved to {enhanced_output_path}")
                else:
                    if verbose:
                        print("ℹ️  No files to analyze in the output")
                        
            except Exception as e:
                if verbose:
                    print(f"⚠️  WARNING: File analysis failed: {e}")
                # Continue without file analysis

        return output_file_path

    except FileNotFoundError:
        print(f"❌ ERROR: apk_unmask not found. Make sure it is in the PATH or the path is correct.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"❌ ERROR: apk_unmask failed with exit code {e.returncode}")
        if verbose:
            print(f"[DEBUG] Stderr: {e.stderr}")
            print(f"[DEBUG] Stdout: {e.stdout}")
        
        # Try to apply filtering to stdout if it contains useful output
        error_output = "--- APK_UNMASK FAILED ---\n"
        error_output += f"Exit Code: {e.returncode}\n"
        error_output += "\n--- STDOUT ---\n"
        error_output += e.stdout
        error_output += "\n--- STDERR ---\n"
        error_output += e.stderr
        
        # If there's stdout content and filtering is enabled, try to filter it
        if enable_filtering and e.stdout and "[!] Detected potentially malicious files:" in e.stdout:
            if verbose:
                print("🔍 Attempting to filter partial output from failed run...")
            try:
                filter_obj = ApkUnmaskFilter(verbose=verbose)
                filtered_stdout = filter_obj.filter_output(e.stdout)
                
                # Replace stdout section with filtered version
                error_output = "--- APK_UNMASK FAILED (FILTERED OUTPUT) ---\n"
                error_output += f"Exit Code: {e.returncode}\n"
                error_output += "\n--- FILTERED STDOUT ---\n"
                error_output += filtered_stdout
                error_output += "\n--- STDERR ---\n"
                error_output += e.stderr
                
                if verbose:
                    print("✅ Applied filtering to partial output from failed run")
            except Exception as filter_error:
                if verbose:
                    print(f"⚠️  WARNING: Could not filter failed output: {filter_error}")
        
        with open(output_file_path, "w") as f:
            f.write(error_output)
        
        # Track the error output file
        if tracker:
            try:
                tracker.add_file(output_file_path)
                if verbose:
                    print(f"📄 Tracked error output file: {output_file_path}")
            except Exception as e:
                if verbose:
                    print(f"⚠️  WARNING: Failed to track error file: {e}")
        
        return output_file_path
    except Exception as e:
        print(f"❌ ERROR: An unexpected error occurred while running apk_unmask: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return None


def parse_arguments():
    """Parse command line arguments for standalone usage."""
    parser = argparse.ArgumentParser(
        description="APK Unmask analysis with false positive filtering and file type detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/app.apk /path/to/output
  %(prog)s /path/to/app.apk /path/to/output --enable-file-analysis --apktool-output /path/to/apktool_output
  %(prog)s /path/to/app.apk /path/to/output --disable-filtering --verbose
        """
    )
    
    parser.add_argument(
        "apk_path",
        help="Path to the APK file to analyze"
    )
    
    parser.add_argument(
        "output_dir", 
        help="Output directory for analysis results"
    )
    
    parser.add_argument(
        "--disable-filtering",
        action="store_true",
        help="Disable false positive filtering"
    )
    
    parser.add_argument(
        "--enable-file-analysis",
        action="store_true", 
        help="Enable file type analysis (requires apktool output)"
    )
    
    parser.add_argument(
        "--apktool-output",
        help="Path to apktool decompiled output directory for file analysis"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    return parser.parse_args()


def main():
    """Main entry point for standalone APK Unmask analysis."""
    args = parse_arguments()
    
    print("🎭 Starting Standalone APK Unmask Analysis")
    print(f"📱 APK: {args.apk_path}")
    print(f"📁 Output: {args.output_dir}")
    
    # Validate inputs
    if not os.path.exists(args.apk_path):
        print(f"❌ ERROR: APK file not found: {args.apk_path}")
        sys.exit(1)
    
    if not os.path.exists(args.output_dir):
        print(f"❌ ERROR: Output directory not found: {args.output_dir}")
        sys.exit(1)
    
    # Configuration
    enable_filtering = not args.disable_filtering
    enable_file_analysis = args.enable_file_analysis
    apktool_output_dir = args.apktool_output
    
    # Validate file analysis prerequisites
    if enable_file_analysis:
        if not apktool_output_dir:
            print("⚠️  WARNING: File analysis requested but no apktool output directory provided")
            print("            Disabling file analysis...")
            enable_file_analysis = False
        elif not os.path.exists(apktool_output_dir):
            print(f"⚠️  WARNING: Apktool output directory not found: {apktool_output_dir}")
            print("            Disabling file analysis...")
            enable_file_analysis = False
        elif not is_file_command_available():
            print("⚠️  WARNING: 'file' command not available on system")
            print("            Disabling file analysis...")
            enable_file_analysis = False
    
    # Display configuration
    print(f"🔍 False Positive Filtering: {'Enabled' if enable_filtering else 'Disabled'}")
    print(f"🔬 File Type Analysis: {'Enabled' if enable_file_analysis else 'Disabled'}")
    if enable_file_analysis:
        print(f"📂 Apktool Output: {apktool_output_dir}")
    
    try:
        # Run APK Unmask analysis
        output_path = run_apk_unmask(
            apk_path=args.apk_path,
            output_dir=args.output_dir,
            verbose=args.verbose,
            enable_filtering=enable_filtering,
            enable_file_analysis=enable_file_analysis,
            apktool_output_dir=apktool_output_dir
        )
        
        if output_path:
            print(f"✅ APK Unmask analysis completed successfully")
            print(f"📄 Output saved to: {output_path}")
            
            if enable_file_analysis:
                enhanced_path = output_path.replace('.txt', '_enhanced.txt')
                if os.path.exists(enhanced_path):
                    print(f"📄 Enhanced output with file types: {enhanced_path}")
        else:
            print("❌ APK Unmask analysis failed")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ ERROR: APK Unmask analysis failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
