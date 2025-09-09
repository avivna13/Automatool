import sys
import subprocess


def get_package_name(apk_path, verbose=False):
    """
    Extract package name from APK using aapt or fallback to pn command.
   
    Args:
        apk_path (str): Path to the APK file
        verbose (bool): Enable verbose output
       
    Returns:
        str or None: Package name if extraction succeeds, None otherwise
    """
    if verbose:
        print(f"[DEBUG] Extracting package name from: {apk_path}")
   
    # Try aapt first (standard Android SDK tool)
    try:
        if verbose:
            print("[DEBUG] Trying aapt command...")
        command = ['aapt', 'dump', 'badging', apk_path]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
       
        # Parse aapt output to find package name using the same logic as pn alias
        # Look for line like: package: name='com.example.app' versionCode='1' versionName='1.0'
        # Use the same parsing as: grep "package: name= " | cut -d "'" -f2
        for line in result.stdout.split('\n'):
            if 'package: name=' in line:
                # Extract package name between single quotes
                parts = line.split("'")
                if len(parts) >= 2:
                    package_name = parts[1]
                    if verbose:
                        print(f"[DEBUG] ✅ Package name extracted with aapt: {package_name}")
                    return package_name
       
        if verbose:
            print("[DEBUG] ❌ Could not parse package name from aapt output")
        return None
                       
    except FileNotFoundError:
        if verbose:
            print("[DEBUG] aapt command not found, trying pn fallback...")
       
        # Fallback to pn command (custom alias/function)
        try:
            command = ['pn', apk_path]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
           
            # The output contains the package name, get the first line and strip whitespace
            package_name = result.stdout.strip().split('\n')[0].strip()
           
            if package_name:
                if verbose:
                    print(f"[DEBUG] ✅ Package name extracted with pn: {package_name}")
                return package_name
            else:
                if verbose:
                    print("[DEBUG] ❌ Package name extraction returned empty result")
                return None
               
        except FileNotFoundError:
            print("❌ ERROR: Neither 'aapt' nor 'pn' command found.")
            print("Please ensure Android SDK build-tools are installed and in your PATH,")
            print("or set up the 'pn' alias/function in your shell.")
            return "unknown"
        except subprocess.CalledProcessError as e:
            print(f"❌ ERROR: Failed to extract package name with pn command.")
            print(f"Command failed: {' '.join(e.cmd)}")
            if verbose:
                print(f"[DEBUG] Return code: {e.returncode}")
                print(f"[DEBUG] Stderr: {e.stderr}")
            return "unknown"
           
    except subprocess.CalledProcessError as e:
        print(f"❌ ERROR: Failed to extract package name from APK.")
        print(f"Command failed: {' '.join(e.cmd)}")
        if verbose:
            print(f"[DEBUG] Return code: {e.returncode}")
            print(f"[DEBUG] Stderr: {e.stderr}")
        return "unknown"
    except Exception as e:
        print(f"❌ ERROR: Unexpected error during package name extraction: {e}")
        print(f"Command failed: {' '.join(e.cmd)}")
        if verbose:
            print(f"[DEBUG] Return code: {e.returncode}")
            print(f"[DEBUG] Stderr: {e.stderr}")
        return None


def extract_package_name_with_fallback(apk_path, verbose=False):
    """
    Extract package name from APK with error handling and user guidance.
   
    Args:
        apk_path (str): Path to the APK file
        verbose (bool): Enable verbose output
       
    Returns:
        str: Package name if successful
       
    Raises:
        SystemExit: If package name extraction fails
    """
    package_name = get_package_name(apk_path, verbose)
   
    if not package_name:
        print("❌ ERROR: Could not extract package name from APK!")
        print(f"APK: {apk_path}")
        print("\nTroubleshooting:")
        print("1. Verify the APK file is valid and not corrupted")
        print("2. Install Android SDK build-tools and ensure 'aapt' is in your PATH")
        print("3. Or set up 'pn' alias in your shell (see README for details)")
        print("4. Try extracting package name manually: aapt dump badging <apk_file>")
        return None
   
    print(f"✅ Package name extracted: {package_name}")
    return package_name

