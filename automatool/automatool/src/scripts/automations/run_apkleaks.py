import os
import subprocess
import argparse
from resource_tracker import GlobalResourceTracker

def run_apkleaks(apk_path, output_directory, verbose=False, custom_rules_path=None, json_output=False):
    """
    Runs apkleaks on the given APK and saves the output to a file.

    Args:
        apk_path (str): The absolute path to the APK file.
        output_directory (str): The directory to save the output file in.
        verbose (bool): Whether to print verbose output.
        custom_rules_path (str, optional): Path to custom rules JSON file for additional pattern matching.
        json_output (bool): Whether to output results in JSON format.

    Returns:
        str: The path to the output file, or None if the operation failed.
    """
    # Initialize resource tracker
    try:
        tracker = GlobalResourceTracker()
        if verbose:
            print("🔧 Resource tracker initialized for APKLeaks")
    except Exception as e:
        if verbose:
            print(f"⚠️  WARNING: Could not initialize resource tracker: {e}")
        tracker = None
    
    if verbose:
        print("💧 Running apkleaks analysis...")

    # Determine output file extension based on format
    file_extension = "json" if json_output else "txt"
    output_file_path = os.path.join(output_directory, f"apkleaks_report.{file_extension}")
    
    command = [
        "apkleaks",
        "-f", apk_path
    ]
    
    # Add custom rules if provided
    if custom_rules_path and os.path.exists(custom_rules_path):
        command.extend(["--pattern", custom_rules_path])
        if verbose:
            print(f"📋 Using custom rules from: {custom_rules_path}")
    elif custom_rules_path and verbose:
        print(f"⚠️  WARNING: Custom rules file not found: {custom_rules_path}")
    
    # Add JSON output flag if requested
    if json_output:
        command.extend(["--json", "-o", output_file_path])
        if verbose:
            print(f"📄 JSON output will be saved to: {output_file_path}")
    else:
        if verbose:
            print(f"📄 Text output will be captured to: {output_file_path}")

    try:
        if verbose:
            print(f"[DEBUG] Running command: {" ".join(command)}")
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )

        # Handle output based on whether JSON output with -o flag was used
        if json_output:
            # APKLeaks already wrote to the file with -o flag, just check if file exists
            if os.path.exists(output_file_path):
                if verbose:
                    print(f"✅ JSON output saved to {output_file_path}")
                # Print the output to be captured by the UI log
                print(result.stdout)
            else:
                if verbose:
                    print(f"⚠️  WARNING: Expected output file not found: {output_file_path}")
                # Fallback: write stdout to file
                with open(output_file_path, 'w', encoding='utf-8') as f:
                    f.write(result.stdout)
        else:
            # Write the output to the file for text format
            with open(output_file_path, 'w', encoding='utf-8') as f:
                f.write(result.stdout)
            if verbose:
                print(f"✅ Text output saved to {output_file_path}")
            # Print the output to be captured by the UI log
            print(result.stdout)

        # Track the output file
        if tracker:
            try:
                tracker.add_file(output_file_path)
                if verbose:
                    print(f"📄 Tracked APKLeaks report: {output_file_path}")
            except Exception as e:
                if verbose:
                    print(f"⚠️  WARNING: Failed to track output file: {e}")

        return output_file_path

    except FileNotFoundError:
        print(f"❌ ERROR: 'apkleaks' command not found. Please ensure apkleaks is installed and in your system's PATH.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"❌ ERROR: apkleaks failed with exit code {e.returncode}")
        if verbose:
            print(f"[DEBUG] Stderr: {e.stderr}")
            print(f"[DEBUG] Stdout: {e.stdout}")
        # Write error to a file for inspection
        error_log_path = os.path.join(output_directory, "apkleaks_error.log")
        with open(error_log_path, "w") as f:
            f.write(f"--- APKSLEAKS FAILED ---\nExit Code: {e.returncode}\n")
            f.write("\n--- STDOUT ---\n")
            f.write(e.stdout)
            f.write("\n--- STDERR ---")
            f.write(e.stderr)
        
        # Track the error log file
        if tracker:
            try:
                tracker.add_file(error_log_path)
                if verbose:
                    print(f"📄 Tracked APKLeaks error log: {error_log_path}")
            except Exception as e:
                if verbose:
                    print(f"⚠️  WARNING: Failed to track error log: {e}")
        
        return None
    except Exception as e:
        print(f"❌ ERROR: An unexpected error occurred while running apkleaks: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Run apkleaks to find secrets in an APK file.")
    parser.add_argument("-f", "--file", required=True, help="Path to the APK file.")
    parser.add_argument("-o", "--output", required=True, help="Directory to save the apkleaks report.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("--custom-rules", help="Path to custom rules JSON file for additional pattern matching.")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")
    args = parser.parse_args()

    run_apkleaks(args.file, args.output, args.verbose, args.custom_rules, args.json)
