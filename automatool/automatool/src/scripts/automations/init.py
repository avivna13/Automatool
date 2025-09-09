import os
import sys

def validate_files(directory, filename, verbose=False):
    """
    Validate that the target directory and APK file exist.
   
    Args:
        directory (str): Target directory path
        filename (str): APK filename
        verbose (bool): Enable verbose output
       
    Returns:
        str: Full APK path if validation passes
       
    Raises:
        SystemExit: If directory or APK file doesn't exist
    """
    if verbose:
        print("[DEBUG] Validating file paths...")
   
    # Check if target directory exists
    if not os.path.exists(directory):
        print(f"❌ ERROR: Target directory does not exist!")
        print(f"Directory: {directory}")
        print("Please verify the directory path and try again.")
        sys.exit(1)
   
    if not os.path.isdir(directory):
        print(f"❌ ERROR: Target path is not a directory!")
        print(f"Path: {directory}")
        print("Please provide a valid directory path.")
        sys.exit(1)
   
    # Construct and check APK file path
    apk_path = os.path.join(directory, filename)
   
    if not os.path.exists(apk_path):
        print(f"❌ ERROR: APK file does not exist!")
        print(f"Expected location: {apk_path}")
        print("Please verify the APK filename and try again.")
        sys.exit(1)
   
    if not os.path.isfile(apk_path):
        print(f"❌ ERROR: APK path is not a file!")
        print(f"Path: {apk_path}")
        print("Please provide a valid APK file.")
        sys.exit(1)
   
    # Optional: Check if file has .apk extension
    if not filename.lower().endswith('.apk'):
        print(f"⚠️  WARNING: File does not have .apk extension: {filename}")
        print("Continuing anyway, but this might not be an APK file.")
   
    if verbose:
        print(f"[DEBUG] ✅ Directory validated: {directory}")
        print(f"[DEBUG] ✅ APK file validated: {apk_path}")
   
    print(f"✅ File validation passed: {apk_path}")
    return apk_path

