import re
import sys
import subprocess


#### ADB ###

def check_adb_availability_and_devices(verbose=False):
    """
    Check if ADB is available and if any devices are connected.
   
    Args:
        verbose (bool): Enable verbose output
       
    Returns:
        tuple: (bool, list) - (adb_available, connected_devices_list)
               Returns (False, []) if ADB not available or no devices
    """
    try:
        # First check if adb is available
        adb_check = subprocess.run(
            ["adb", "version"],
            capture_output=True,
            text=True,
            check=False
        )
       
        if adb_check.returncode != 0:
            print("❌ ERROR: 'adb' command not found.")
            print("Please ensure Android SDK platform-tools are installed and in your PATH.")
            return False, []
       
        if verbose:
            print("[DEBUG] adb command found")
       
        # Check if any devices are connected
        devices_result = subprocess.run(
            ["adb", "devices"],
            capture_output=True,
            text=True,
            check=True
        )
       
        # Parse devices output to check for connected devices
        devices_lines = devices_result.stdout.strip().split('\n')[1:]  # Skip header
        connected_devices = [line for line in devices_lines if line.strip() and 'device' in line]
       
        if not connected_devices:
            print("⚠️  WARNING: No Android devices connected via ADB.")
            print("Please connect a device and enable USB debugging.")
            if verbose:
                print("[DEBUG] ADB devices output:")
                print(devices_result.stdout)
            return True, []  # ADB available but no devices
       
        if verbose:
            print(f"[DEBUG] Found {len(connected_devices)} connected device(s)")
            for device in connected_devices:
                print(f"[DEBUG] Device: {device.strip()}")
       
        return True, connected_devices
       
    except subprocess.CalledProcessError as e:
        print(f"❌ ERROR: ADB command failed: {e}")
        if verbose:
            print(f"[DEBUG] Command: {' '.join(e.cmd)}")
            print(f"[DEBUG] Return code: {e.returncode}")
            if e.stderr:
                print(f"[DEBUG] Stderr: {e.stderr}")
        return False, []
       
    except Exception as e:
        print(f"❌ ERROR: Unexpected error checking ADB: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False, []


#### VPN ###

def get_vpn_country():
    """
    Retrieves the connected VPN country from the 'nordvpn status' command.


    Returns:
        str or None: The country name if connected, otherwise None.
    """
    try:
        result = subprocess.run(
            ['nordvpn', 'status'],
            capture_output=True,
            text=True,
            check=False
        )
       
        # The output line we are looking for is typically "Country: United States"
        match = re.search(r'Country:\s+(.*)', result.stdout)
        if match:
            return match.group(1).strip()
           
    except FileNotFoundError:
        # nordvpn command not found
        return None
    except Exception:
        # Any other error occurred
        return None
       
    return None


def verify_vpn_connection(verbose=False):
    """
    Verify VPN connection is active and return country.
   
    Args:
        verbose (bool): Enable verbose output
       
    Returns:
        str: Country name if connected
       
    Raises:
        SystemExit: If VPN is not connected
    """
    if verbose:
        print("[DEBUG] Checking VPN status...")
       
    country = get_vpn_country()
   
    if not country:
        print("❌ ERROR: VPN connection required!")
        print("Please connect to your VPN and try again.")
        print("Expected: nordvpn status should show 'Country: <country_name>'")
        sys.exit(1)
   
    print(f"✅ VPN Status: Connected to {country}")
    return country



#### FRIDA ###




#### HTTPTOOLKIT ###

