import os
import sys
import argparse

# Fix path to allow imports from parent directories
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from scripts.utils.adb_controller import ADBController, DeviceStatus


def install_apk_on_device(apk_path: str, verbose: bool = False) -> bool:
    """
    Install APK on connected Android device using enhanced ADB controller.
    
    Args:
        apk_path: Path to the APK file to install
        verbose: Enable verbose output
        
    Returns:
        bool: True if installation was successful, False otherwise
    """
    if verbose:
        print(f"[DEBUG] Installing APK on device: {apk_path}")
    
    # Validate APK file exists before attempting installation
    if not os.path.exists(apk_path):
        print(f"❌ ERROR: APK file not found: {apk_path}")
        print("💡 Please verify the APK file path is correct")
        return False
    
    # Check APK file size to ensure it's not corrupted
    try:
        file_size = os.path.getsize(apk_path)
        if file_size == 0:
            print(f"❌ ERROR: APK file is empty: {apk_path}")
            return False
        if verbose:
            print(f"[DEBUG] APK file size: {file_size:,} bytes")
    except Exception as e:
        print(f"❌ ERROR: Cannot read APK file: {e}")
        return False
    
    try:
        # Initialize ADB controller
        adb_controller = ADBController()
        
        # Check ADB connection
        if not adb_controller.check_adb_connection():
            print("❌ ERROR: ADB not found or no devices connected.")
            print("Please ensure Android SDK platform-tools are installed and device is connected.")
            return False
        
        # Get device information
        authorized_devices = adb_controller.get_authorized_devices()
        all_devices = adb_controller.get_connected_devices()
        
        if verbose:
            print(f"[DEBUG] Found {len(all_devices)} total devices")
            for device in all_devices:
                print(f"[DEBUG] Device: {device.device_id} - Status: {device.status.value}")
                if device.product:
                    print(f"[DEBUG]   Product: {device.product}")
                if device.model:
                    print(f"[DEBUG]   Model: {device.model}")
        
        # Check for unauthorized devices
        unauthorized_devices = [d for d in all_devices if d.status == DeviceStatus.UNAUTHORIZED]
        if unauthorized_devices:
            print("⚠️  WARNING: Found unauthorized devices:")
            for device in unauthorized_devices:
                print(f"   • {device.device_id} - Please authorize this device for ADB access")
            print("💡 Solution: Check your device screen for ADB authorization dialog and tap 'Allow'")
        
        # Check for offline devices
        offline_devices = [d for d in all_devices if d.status == DeviceStatus.OFFLINE]
        if offline_devices:
            print("⚠️  WARNING: Found offline devices:")
            for device in offline_devices:
                print(f"   • {device.device_id} - Device is offline")
            print("💡 Solution: Check USB connection and ensure device is unlocked and awake")
        
        # Attempt installation
        if not authorized_devices:
            print("❌ ERROR: No authorized devices connected.")
            print("Please connect a device and authorize ADB access in developer options.")
            return False
        
        # Install on first authorized device
        target_device = authorized_devices[0]
        if verbose:
            print(f"[DEBUG] Installing on device: {target_device.device_id}")
            if target_device.product:
                print(f"[DEBUG] Device product: {target_device.product}")
        
        success = adb_controller.install_apk(apk_path, target_device.device_id)
        
        if success:
            print(f"✅ APK installed successfully on device: {target_device.device_id}")
            if verbose and target_device.product:
                print(f"[DEBUG] Device: {target_device.product}")
            return True
        else:
            print(f"❌ APK installation failed on device: {target_device.device_id}")
            
            # Get the last execution result for detailed error info
            last_result = adb_controller.get_last_result()
            if last_result and not last_result['success']:
                if last_result.get('stderr'):
                    print(f"💡 Error details: {last_result['stderr'].strip()}")
                if last_result.get('stdout'):
                    print(f"💡 ADB output: {last_result['stdout'].strip()}")
            
            print("💡 Common solutions:")
            print("   • Ensure device has sufficient storage space")
            print("   • Try uninstalling previous version of the app first")
            print("   • Check if APK is signed properly")
            print("   • Verify APK is compatible with device architecture")
            return False
            
    except Exception as e:
        print(f"❌ ERROR: Unexpected error during APK installation: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Install APK on a connected Android device.")
    parser.add_argument("apk_path", help="Path to the APK file to install.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for debugging.")
    args = parser.parse_args()
    
    if not install_apk_on_device(args.apk_path, args.verbose):
        sys.exit(1)  # Exit with a non-zero status code to indicate failure
