import os
import subprocess



def run_reviews_scraper(package_name, output_directory, verbose=False):
    """
    Run the reviews scraper to collect app reviews with virtual environment activation.
   
    Args:
        package_name (str): Package name extracted from APK
        output_directory (str): Directory to save reviews file
        verbose (bool): Enable verbose output
       
    Returns:
        bool: True if scraper ran successfully, False otherwise
    """
    output_file = os.path.join(output_directory, "reviews.json")
   
    if verbose:
        print(f"[DEBUG] Running reviews scraper for package: {package_name}")
        print(f"[DEBUG] Output file: {output_file}")
   
    # Determine virtual environment Python executable (Kali Linux)
    venv_python = os.path.join("venv", "bin", "python")
   
    if os.path.exists(venv_python):
        if verbose:
            print(f"[DEBUG] Using virtual environment: {venv_python}")
    else:
        venv_python = "python3"  # Kali Linux default
        if verbose:
            print("[DEBUG] Virtual environment not found, using system Python3")
   
    try:
        # Run reviews scraper with virtual environment Python
        # Add --format=json because --output option requires it
        command = [venv_python, "reviews_scraper.py", "--format=json", "-o", output_file, package_name]
       
        if verbose:
            print(f"[DEBUG] Command: {' '.join(command)}")
            print(f"[DEBUG] Working directory: {os.getcwd()}")
       
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False  # Don't raise exception on non-zero exit
        )
       
        if result.returncode == 0:
            if verbose:
                print(f"[DEBUG] ✅ Reviews scraper completed successfully")
                if result.stdout.strip():
                    print(f"[DEBUG] Stdout: {result.stdout.strip()}")
            print(f"✅ Reviews scraper completed: {output_file}")
            return True
        else:
            print(f"⚠️  WARNING: Reviews scraper finished with warnings")
            print(f"Return code: {result.returncode}")
            if verbose:
                if result.stdout.strip():
                    print(f"[DEBUG] Stdout: {result.stdout.strip()}")
                if result.stderr.strip():
                    print(f"[DEBUG] Stderr: {result.stderr.strip()}")
            print(f"Output file may still be available: {output_file}")
            return False
       
    except FileNotFoundError:
        print("❌ ERROR: 'reviews_scraper.py' not found or Python not available.")
        print("Please ensure reviews_scraper.py is in the current directory.")
        print("Also check that the 'venv' virtual environment exists.")
        return False
       
    except Exception as e:
        print(f"❌ ERROR: Failed to run reviews scraper: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False
