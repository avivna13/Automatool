import os
import subprocess
import argparse
from resource_tracker import GlobalResourceTracker

def run_apkleaks(apk_path, output_directory, verbose=False):
    """
    Runs apkleaks on the given APK and saves the output to a JSON file.

    Args:
        apk_path (str): The absolute path to the APK file.
        output_directory (str): The directory to save the output file in.
        verbose (bool): Whether to print verbose output.

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

    output_file_path = os.path.join(output_directory, "apkleaks_report.txt")
    
    command = [
        "apkleaks",
        "-f", apk_path
    ]

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

        # Write the output to the file
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(result.stdout)

        # Track the output file
        if tracker:
            try:
                tracker.add_file(output_file_path)
                if verbose:
                    print(f"📄 Tracked APKLeaks report: {output_file_path}")
            except Exception as e:
                if verbose:
                    print(f"⚠️  WARNING: Failed to track output file: {e}")

        if verbose:
            print(f"✅ apkleaks output saved to {output_file_path}")

        # Print the output to be captured by the UI log
        print(result.stdout)

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
    args = parser.parse_args()

    run_apkleaks(args.file, args.output, args.verbose)
