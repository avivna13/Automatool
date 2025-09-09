import os
import subprocess
import argparse
from resource_tracker import GlobalResourceTracker

def find_so_files(directory, verbose=False):
    """Find all .so files in a directory."""
    so_files = set()
    # Look for .so files specifically in 'lib' directories, which is standard for APKs
    lib_dir = os.path.join(directory, 'lib')
    if os.path.isdir(lib_dir):
        for root, _, files in os.walk(lib_dir):
            for file in files:
                if file.endswith(".so"):
                    so_files.add(os.path.join(root, file))
    
    if not so_files: # Fallback to searching the whole directory if no 'lib' subdir
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".so"):
                    so_files.add(os.path.join(root, file))

    if verbose:
        print(f"[DEBUG] Found {len(so_files)} .so files.")
    return list(so_files)

def run_strings_on_so_files(apktool_output_path, output_directory, verbose=False):
    """
    Run 'strings' on all .so files found in the apktool output directory.
    Saves the output for each .so file into a structured directory.
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
    
    if not apktool_output_path or not os.path.isdir(apktool_output_path):
        if verbose:
            print(f"[DEBUG] apktool_output_path is invalid or does not exist: {apktool_output_path}")
        return None

    if verbose:
        print("🏃 Running strings analysis on .so files...")

    so_files = find_so_files(apktool_output_path, verbose)
    if not so_files:
        print("ℹ️ No .so files found, skipping strings analysis.")
        return None

    strings_output_dir = os.path.join(output_directory, "native_libs_strings")
    os.makedirs(strings_output_dir, exist_ok=True)
    
    # Track the output directory
    if tracker:
        try:
            tracker.add_directory(strings_output_dir)
            if verbose:
                print(f"📁 Tracked strings directory: {strings_output_dir}")
        except Exception as e:
            if verbose:
                print(f"⚠️  WARNING: Failed to track directory: {e}")

    if verbose:
        print(f"[DEBUG] Created strings output directory: {strings_output_dir}")

    for so_file_path in so_files:
        # Create a file name that reflects the library's path to avoid name collisions
        relative_path = os.path.relpath(so_file_path, apktool_output_path)
        sanitized_filename = relative_path.replace(os.path.sep, '_')
        output_file_path = os.path.join(strings_output_dir, f"{sanitized_filename}.txt")

        command = ["strings", so_file_path]

        try:
            if verbose:
                print(f"[DEBUG] Running command: {' '.join(command)}")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
                errors='ignore'  # Important for handling non-UTF8 characters in binary files
            )

            with open(output_file_path, "w", encoding='utf-8') as f:
                f.write(result.stdout)

            # Track individual output file
            if tracker:
                try:
                    tracker.add_file(output_file_path)
                    if verbose:
                        print(f"📄 Tracked file: {output_file_path}")
                except Exception as e:
                    if verbose:
                        print(f"⚠️  WARNING: Failed to track file: {e}")

            if verbose:
                print(f"✅ Strings output for {relative_path} saved to {output_file_path}")

        except FileNotFoundError:
            print("❌ ERROR: 'strings' command not found. Please ensure it is installed and in your system's PATH.")
            return None  # Abort if 'strings' is not available
        except subprocess.CalledProcessError as e:
            error_message = f"""--- STRINGS FAILED FOR {relative_path} ---
Exit Code: {e.returncode}
--- STDERR ---
{e.stderr}"""
            with open(output_file_path, "w", encoding='utf-8') as f:
                f.write(error_message)
            
            # Track error output file
            if tracker:
                try:
                    tracker.add_file(output_file_path)
                    if verbose:
                        print(f"📄 Tracked error file: {output_file_path}")
                except Exception as e:
                    if verbose:
                        print(f"⚠️  WARNING: Failed to track error file: {e}")
            
            if verbose:
                print(f"❌ ERROR: 'strings' failed for {so_file_path}. Details saved to {output_file_path}")
        except Exception as e:
            print(f"❌ ERROR: An unexpected error occurred while running strings on {so_file_path}: {e}")

    print(f"✅ Strings analysis complete and resources tracked. Output saved in: {strings_output_dir}")
    return strings_output_dir

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Run 'strings' on .so files from an apktool output directory.")
    parser.add_argument("apktool_path", help="Path to the apktool output directory.")
    parser.add_argument("output_dir", help="Directory to save the strings analysis output.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    args = parser.parse_args()

    run_strings_on_so_files(args.apktool_path, args.output_dir, args.verbose)
