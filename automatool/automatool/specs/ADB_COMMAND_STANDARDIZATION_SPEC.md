# 🔧 ADB Command Standardization & Error Handling Enhancement Specification

## **Overview**
This specification addresses critical issues identified in the APK installation and cleanup processes within `automatool.py`. The current implementation has inconsistent ADB command execution patterns, insufficient error handling, and inadequate device validation that leads to failed installations and incomplete cleanup operations.

## **Current Issues Identified**

### **1. Inconsistent ADB Command Execution**
- **Installation**: Uses `subprocess.run()` with proper error handling
- **Cleanup**: Uses `os.system()` with basic error checking
- **Device validation**: Uses `subprocess.run()` but with inconsistent parsing
- **Impact**: Different failure modes and error reporting across modules

### **2. Insufficient Device Status Parsing**
- **Current Logic**: Only checks for 'device' keyword in ADB output
- **Missing States**: unauthorized, offline, disconnected, multiple devices
- **Impact**: False positives for device availability

### **3. Poor Error Handling and Propagation**
- **Installation Failures**: No retry mechanisms or detailed feedback
- **Device Issues**: No guidance for unauthorized/offline devices
- **Cleanup Failures**: Silent failures with no user feedback

### **4. Missing Device Authorization Validation**
- **No Authorization Check**: Doesn't verify devices are authorized for ADB
- **No Multi-Device Handling**: Assumes single device scenarios
- **No User Guidance**: No instructions for enabling USB debugging

## **Implementation Plan**

### **Phase 1: ADB Command Execution Standardization**

#### **1.1 Enhance Existing ADB Controller Module**
**File**: `scripts/utils/adb_controller.py` (enhance existing)

The existing `adb_controller.py` already provides good ADB command execution capabilities. We need to enhance it with:

1. **Device Status Parsing**: Add methods to parse device states properly
2. **APK Installation/Uninstallation**: Add specific methods for APK operations
3. **Device Authorization Validation**: Add methods to check device authorization status

```python
# Add to existing adb_controller.py

from enum import Enum
from dataclasses import dataclass
from typing import List, Optional

class DeviceStatus(Enum):
    """Enumeration of possible device states."""
    AUTHORIZED = "device"
    UNAUTHORIZED = "unauthorized"
    OFFLINE = "offline"
    DISCONNECTED = "disconnected"
    UNKNOWN = "unknown"

@dataclass
class DeviceInfo:
    """Device information structure."""
    device_id: str
    status: DeviceStatus
    product: Optional[str] = None
    model: Optional[str] = None
    android_version: Optional[str] = None

class ADBCommandError(Exception):
    """Custom exception for ADB command failures."""
    def __init__(self, command: str, return_code: int, stderr: str, stdout: str = ""):
        self.command = command
        self.return_code = return_code
        self.stderr = stderr
        self.stdout = stdout
        super().__init__(f"ADB command failed: {command} (return code: {return_code})")

# Add these methods to the existing ADBController class:

def get_connected_devices(self) -> List[DeviceInfo]:
    """
    Get list of connected devices with detailed status information.
    
    Returns:
        List of DeviceInfo objects representing connected devices
    """
    try:
        result = self.execute_command("adb devices -l")
        
        if not result['success']:
            logger.error("Failed to get device list")
            return []
        
        devices = []
        lines = result['stdout'].strip().split('\n')[1:]  # Skip header
        
        for line in lines:
            if not line.strip():
                continue
                
            # Parse device line: "device_id device product:product_name model:model_name"
            parts = line.strip().split()
            if len(parts) < 2:
                continue
                
            device_id = parts[0]
            status_str = parts[1]
            
            # Parse additional device information
            device_info = DeviceInfo(
                device_id=device_id,
                status=DeviceStatus(status_str)
            )
            
            # Extract product and model information
            for part in parts[2:]:
                if ':' in part:
                    key, value = part.split(':', 1)
                    if key == 'product':
                        device_info.product = value
                    elif key == 'model':
                        device_info.model = value
            
            devices.append(device_info)
        
        return devices
        
    except Exception as e:
        logger.error(f"Failed to get device list: {e}")
        return []

def get_authorized_devices(self) -> List[DeviceInfo]:
    """Get only authorized devices ready for ADB operations."""
    all_devices = self.get_connected_devices()
    return [device for device in all_devices if device.status == DeviceStatus.AUTHORIZED]

def install_apk(self, apk_path: str, device_id: Optional[str] = None) -> bool:
    """
    Install APK on device with comprehensive error handling.
    
    Args:
        apk_path: Path to APK file
        device_id: Specific device ID (if None, uses first authorized device)
        
    Returns:
        True if installation successful, False otherwise
    """
    try:
        import os
        
        # Validate APK file exists
        if not os.path.exists(apk_path):
            logger.error(f"APK file not found: {apk_path}")
            return False
        
        # Get authorized devices
        authorized_devices = self.get_authorized_devices()
        if not authorized_devices:
            logger.error("No authorized devices connected")
            return False
        
        # Select target device
        target_device = device_id or authorized_devices[0].device_id
        
        # Build install command
        install_cmd = f"adb install -r"
        if device_id:
            install_cmd += f" -s {device_id}"
        install_cmd += f" {apk_path}"
        
        # Execute installation
        result = self.execute_command(install_cmd)
        
        # Parse installation result
        if result['success'] and "Success" in result['stdout']:
            logger.info(f"APK installed successfully on device: {target_device}")
            return True
        else:
            logger.error(f"APK installation failed: {result.get('stderr', 'Unknown error')}")
            return False
            
    except Exception as e:
        logger.error(f"APK installation failed: {e}")
        return False

def uninstall_apk(self, package_name: str, device_id: Optional[str] = None) -> bool:
    """
    Uninstall APK from device with comprehensive error handling.
    
    Args:
        package_name: Package name to uninstall
        device_id: Specific device ID (if None, uses first authorized device)
        
    Returns:
        True if uninstallation successful, False otherwise
    """
    try:
        # Get authorized devices
        authorized_devices = self.get_authorized_devices()
        if not authorized_devices:
            logger.error("No authorized devices connected")
            return False
        
        # Select target device
        target_device = device_id or authorized_devices[0].device_id
        
        # Build uninstall command
        uninstall_cmd = f"adb uninstall"
        if device_id:
            uninstall_cmd += f" -s {device_id}"
        uninstall_cmd += f" {package_name}"
        
        # Execute uninstallation
        result = self.execute_command(uninstall_cmd)
        
        # Parse uninstallation result
        if result['success'] and "Success" in result['stdout']:
            logger.info(f"APK uninstalled successfully from device: {target_device}")
            return True
        else:
            logger.error(f"APK uninstallation failed: {result.get('stderr', 'Unknown error')}")
            return False
            
    except Exception as e:
        logger.error(f"APK uninstallation failed: {e}")
        return False
```

#### **1.2 Update Installation Module**
**File**: `scripts/automations/install_apk.py`

```python
import os
from ..utils.adb_controller import ADBController

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
        unauthorized_devices = [d for d in all_devices if d.status.value == "unauthorized"]
        if unauthorized_devices:
            print("⚠️  WARNING: Found unauthorized devices:")
            for device in unauthorized_devices:
                print(f"   • {device.device_id} - Please authorize this device for ADB access")
        
        # Check for offline devices
        offline_devices = [d for d in all_devices if d.status.value == "offline"]
        if offline_devices:
            print("⚠️  WARNING: Found offline devices:")
            for device in offline_devices:
                print(f"   • {device.device_id} - Device is offline")
        
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
            return False
            
    except Exception as e:
        print(f"❌ ERROR: Unexpected error during APK installation: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False
```

### **Phase 2: Enhanced Error Handling**

#### **2.1 Create Error Handling Utilities**
**File**: `scripts/utils/error_handlers.py`

```python
#!/usr/bin/env python3
"""
Enhanced Error Handling Utilities

This module provides standardized error handling patterns for ADB operations,
device management, and user feedback across all automation modules.
"""

import sys
from typing import Callable, Any, Optional, List
from functools import wraps
from .adb_controller import ADBController, DeviceInfo

class AutomationError(Exception):
    """Base exception for automation errors."""
    def __init__(self, message: str, error_code: Optional[str] = None, details: Optional[str] = None):
        self.message = message
        self.error_code = error_code
        self.details = details
        super().__init__(message)

class DeviceConnectionError(AutomationError):
    """Exception for device connection issues."""
    pass

class InstallationError(AutomationError):
    """Exception for APK installation issues."""
    pass

class CleanupError(AutomationError):
    """Exception for cleanup operation issues."""
    pass

def handle_adb_errors(func: Callable) -> Callable:
    """Decorator to handle ADB-related errors with user-friendly messages."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            error_str = str(e).lower()
            # Provide specific guidance based on error type
            if "unauthorized" in error_str:
                raise DeviceConnectionError(
                    message="Device not authorized for ADB access",
                    error_code="DEVICE_UNAUTHORIZED",
                    details="Please enable USB debugging and authorize this computer on your device."
                )
            elif "offline" in error_str:
                raise DeviceConnectionError(
                    message="Device is offline",
                    error_code="DEVICE_OFFLINE",
                    details="Please check your device connection and ensure it's not in sleep mode."
                )
            elif "device not found" in error_str or "no devices" in error_str:
                raise DeviceConnectionError(
                    message="No devices connected",
                    error_code="NO_DEVICES",
                    details="Please connect an Android device with USB debugging enabled."
                )
            else:
                raise AutomationError(
                    message=f"ADB operation failed: {e}",
                    error_code="ADB_ERROR",
                    details=str(e)
                )
    return wrapper

def provide_device_guidance(devices: List[DeviceInfo]) -> str:
    """Provide user guidance based on device status."""
    guidance = []
    
    authorized = [d for d in devices if d.status.value == "device"]
    unauthorized = [d for d in devices if d.status.value == "unauthorized"]
    offline = [d for d in devices if d.status.value == "offline"]
    
    if not devices:
        guidance.append("• No devices detected")
        guidance.append("• Connect your Android device via USB")
        guidance.append("• Enable USB debugging in Developer Options")
        guidance.append("• Install ADB drivers if needed")
    
    if unauthorized:
        guidance.append("• Unauthorized devices detected:")
        for device in unauthorized:
            guidance.append(f"  - {device.device_id}: Authorize this device for ADB access")
    
    if offline:
        guidance.append("• Offline devices detected:")
        for device in offline:
            guidance.append(f"  - {device.device_id}: Check device connection and wake device")
    
    if authorized:
        guidance.append(f"• {len(authorized)} authorized device(s) ready for operations")
    
    return "\n".join(guidance)

def retry_operation(operation: Callable, max_retries: int = 3, delay: float = 2.0) -> Callable:
    """Decorator to retry operations with exponential backoff."""
    @wraps(operation)
    def wrapper(*args, **kwargs):
        import time
        
        for attempt in range(max_retries):
            try:
                return operation(*args, **kwargs)
            except (DeviceConnectionError, InstallationError) as e:
                if attempt == max_retries - 1:
                    raise
                
                wait_time = delay * (2 ** attempt)
                print(f"⚠️  Operation failed (attempt {attempt + 1}/{max_retries}), retrying in {wait_time}s...")
                time.sleep(wait_time)
        
        return operation(*args, **kwargs)
    return wrapper
```

#### **2.2 Update Main Script Error Handling**
**File**: `automatool.py` (enhanced error handling)

```python
# Add to imports
from scripts.utils.error_handlers import (
    handle_adb_errors, 
    provide_device_guidance, 
    retry_operation,
    DeviceConnectionError,
    InstallationError,
    AutomationError
)

def main():
    """Main entry point for the APK analysis automation tool."""
    print("--- Starting APK Analysis Automation ---")
    
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        if args.verbose:
            print(f"[DEBUG] Target directory: {args.directory}")
            print(f"[DEBUG] APK filename: {args.filename}")
        
        # Initialize global resource tracker
        try:
            resource_tracker = GlobalResourceTracker()
            
            # Clean up all existing resources before starting new run
            print("🧹 Cleaning up previous resources before starting new analysis...")
            resource_tracker.cleanup_all()
            
            resource_tracker.start_new_run()
        except Exception as e:
            print(f"❌ ERROR: Failed to initialize resource tracker: {e}")
            if args.verbose:
                print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
            raise  # Stop automation on resource tracking failure
        
        # Verify VPN connection
        verify_vpn_connection(args.verbose)
        
        # Validate files and get full APK path
        apk_path = validate_files(args.directory, args.filename, args.verbose)
        
        # Extract package name from APK
        package_name = extract_package_name_with_fallback(apk_path, args.verbose)
        
        # Track package name and APK filename for current run
        try:
            resource_tracker.set_package_name(package_name)
            resource_tracker.set_apk_filename(args.filename)
        except Exception as e:
            print(f"❌ ERROR: Failed to track package information: {e}")
            if args.verbose:
                print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        
        # ... (existing automation steps) ...
        
        # Install APK on device if requested (enhanced error handling)
        if args.install:
            try:
                print("📱 Installing APK on connected device...")
                
                # Check device status first
                devices = ADBUtils.get_connected_devices()
                if not devices:
                    print("❌ ERROR: No devices connected")
                    print("\n📋 Device Connection Guide:")
                    print(provide_device_guidance([]))
                    return 1
                
                # Provide device status feedback
                print("\n📋 Device Status:")
                print(provide_device_guidance(devices))
                
                # Attempt installation with retry
                @retry_operation
                @handle_adb_errors
                def install_with_retry():
                    return install_apk_on_device(apk_path, args.verbose)
                
                install_success = install_with_retry()
                
                if install_success:
                    try:
                        resource_tracker.mark_apk_installed()
                        print("✅ APK installation tracked successfully")
                    except Exception as e:
                        print(f"❌ ERROR: Failed to track APK installation status: {e}")
                        if args.verbose:
                            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
                else:
                    print("❌ APK installation failed - continuing with analysis")
                    
            except DeviceConnectionError as e:
                print(f"❌ DEVICE ERROR: {e.message}")
                if e.details:
                    print(f"💡 {e.details}")
                print("\n📋 Troubleshooting Guide:")
                print(provide_device_guidance(ADBUtils.get_connected_devices()))
                return 1
                
            except InstallationError as e:
                print(f"❌ INSTALLATION ERROR: {e.message}")
                if e.details:
                    print(f"💡 {e.details}")
                return 1
                
            except AutomationError as e:
                print(f"❌ AUTOMATION ERROR: {e.message}")
                if e.details:
                    print(f"💡 {e.details}")
                return 1
        
        print("--- APK Analysis Automation Complete ---")
        return 0
        
    except Exception as e:
        print(f"❌ CRITICAL ERROR: {e}")
        if args.verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
```

### **Phase 3: Improved Cleanup Process**

#### **3.1 Update Resource Tracker Cleanup**
**File**: `scripts/automations/resource_tracker.py` (enhanced cleanup)

```python
# Add to imports
from ..utils.adb_utils import ADBUtils, ADBCommandError
from ..utils.error_handlers import handle_adb_errors, CleanupError

class GlobalResourceTracker:
    # ... (existing methods) ...
    
    @handle_adb_errors
    def _uninstall_apk(self, package_name: str) -> bool:
        """
        Uninstall APK from device using standardized ADB utilities.
        
        Args:
            package_name: Package name to uninstall
            
        Returns:
            bool: True if uninstallation successful, False otherwise
        """
        try:
            print(f"📱 Attempting to uninstall APK: {package_name}")
            
            # Check ADB availability
            if not ADBUtils.check_adb_availability():
                print(f"⚠️  ADB not found - cannot uninstall {package_name}")
                return False
            
            # Get device information
            authorized_devices = ADBUtils.get_authorized_devices()
            if not authorized_devices:
                print(f"⚠️  No authorized devices found - cannot uninstall {package_name}")
                return False
            
            # Attempt uninstallation on first authorized device
            target_device = authorized_devices[0]
            print(f"📱 Uninstalling from device: {target_device.device_id}")
            if target_device.product:
                print(f"📱 Device: {target_device.product}")
            
            success = ADBUtils.uninstall_apk(package_name, target_device.device_id)
            
            if success:
                print(f"✅ Successfully uninstalled APK: {package_name}")
                return True
            else:
                print(f"⚠️  Failed to uninstall APK: {package_name}")
                return False
                
        except ADBCommandError as e:
            print(f"❌ Error during APK uninstall for {package_name}: {e}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error during APK uninstall for {package_name}: {e}")
            return False
    
    def cleanup_all(self) -> dict:
        """
        Clean up all tracked resources with enhanced error handling.
        
        Returns:
            dict: Cleanup results summary
        """
        try:
            print("🧹 Starting cleanup of all tracked resources...")
            
            cleanup_results = {
                "processes_killed": 0,
                "files_deleted": 0,
                "directories_removed": 0,
                "apks_uninstalled": 0,
                "errors": [],
                "warnings": []
            }
            
            # Clean archived runs first
            try:
                archived_results = self.cleanup_archived_runs()
                for key in cleanup_results:
                    if key in archived_results:
                        cleanup_results[key] += archived_results[key]
            except Exception as e:
                error_msg = f"Failed to cleanup archived runs: {e}"
                print(f"❌ {error_msg}")
                cleanup_results["errors"].append(error_msg)
            
            # Clean current run
            try:
                current_results = self._cleanup_single_run(self.resources.get("current_run", {}))
                for key in cleanup_results:
                    if key in current_results:
                        cleanup_results[key] += current_results[key]
            except Exception as e:
                error_msg = f"Failed to cleanup current run: {e}"
                print(f"❌ {error_msg}")
                cleanup_results["errors"].append(error_msg)
            
            # Reset current run
            self.resources["current_run"] = {
                "timestamp": datetime.now().isoformat(),
                "package_name": None,
                "apk_filename": None,
                "apk_installed": False,
                "pid": {
                    "jadx": None,
                    "vscode": None
                },
                "files": [],
                "dirs": []
            }
            
            # Save the updated state
            self._save_resources()
            
            # Show cleanup summary
            self._show_cleanup_summary(cleanup_results)
            
            if cleanup_results["errors"]:
                print(f"\n⚠️  Cleanup completed with {len(cleanup_results['errors'])} errors")
                for error in cleanup_results["errors"]:
                    print(f"   • {error}")
            else:
                print("✅ Cleanup completed successfully")
            
            return cleanup_results
            
        except Exception as e:
            print(f"❌ ERROR: Failed to complete cleanup: {e}")
            raise CleanupError(
                message="Cleanup process failed",
                error_code="CLEANUP_FAILED",
                details=str(e)
            )
```

#### **3.2 Create Dedicated Cleanup Script**
**File**: `cleanup.py` (enhanced version)

```python
#!/usr/bin/env python3
"""
Enhanced APK Analysis Cleanup Tool

This script provides comprehensive cleanup of all resources tracked by automatool.py
with enhanced error handling, device validation, and user feedback.
"""

import argparse
import sys
import os
from scripts.automations.resource_tracker import GlobalResourceTracker
from scripts.utils.adb_utils import ADBUtils
from scripts.utils.error_handlers import (
    provide_device_guidance,
    DeviceConnectionError,
    CleanupError,
    AutomationError
)

def parse_arguments():
    """Parse command line arguments for enhanced cleanup script."""
    parser = argparse.ArgumentParser(
        description="Enhanced cleanup of all resources tracked by automatool.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Clean all resources with confirmation
  %(prog)s --verbose         # Verbose cleanup with detailed output
  %(prog)s --force           # Skip confirmation prompts
  %(prog)s --dry-run         # Show what would be cleaned without executing
  %(prog)s --current-only    # Clean only current run, not archived runs
  %(prog)s --device-status    # Show device status without cleaning
        """
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output for debugging"
    )
    
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Skip confirmation prompts (dangerous!)"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be cleaned without executing cleanup"
    )
    
    parser.add_argument(
        "--current-only",
        action="store_true",
        help="Clean only current run, not archived runs"
    )
    
    parser.add_argument(
        "--device-status",
        action="store_true",
        help="Show device status and exit without cleaning"
    )
    
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Show resource summary without cleaning"
    )
    
    return parser.parse_args()

def show_device_status():
    """Display current device status and provide guidance."""
    print("📱 Device Status Check")
    print("=" * 50)
    
    try:
        # Check ADB availability
        if not ADBUtils.check_adb_availability():
            print("❌ ADB not available")
            print("💡 Please install Android SDK platform-tools")
            return False
        
        # Get device information
        devices = ADBUtils.get_connected_devices()
        
        if not devices:
            print("❌ No devices detected")
            print("\n📋 Connection Guide:")
            print(provide_device_guidance([]))
            return False
        
        print(f"📱 Found {len(devices)} device(s):")
        print()
        
        for i, device in enumerate(devices, 1):
            status_icon = "✅" if device.status.value == "device" else "⚠️" if device.status.value == "unauthorized" else "❌"
            print(f"{i}. {status_icon} {device.device_id}")
            print(f"   Status: {device.status.value}")
            if device.product:
                print(f"   Product: {device.product}")
            if device.model:
                print(f"   Model: {device.model}")
            print()
        
        print("📋 Device Guidance:")
        print(provide_device_guidance(devices))
        
        return True
        
    except Exception as e:
        print(f"❌ Error checking device status: {e}")
        return False

def confirm_cleanup(force: bool, dry_run: bool) -> bool:
    """Get user confirmation for cleanup operation."""
    if force:
        return True
    
    if dry_run:
        print("🔍 DRY RUN MODE - No actual cleanup will be performed")
        return True
    
    print("\n⚠️  WARNING: This will permanently delete:")
    print("   • All tracked files and directories")
    print("   • Kill running processes (Jadx, VS Code)")
    print("   • Uninstall APKs from connected devices")
    print("   • Reset resource tracking")
    
    response = input("\n🤔 Are you sure you want to proceed? (yes/no): ").lower().strip()
    return response in ['yes', 'y']

def main():
    """Main entry point for enhanced cleanup script."""
    args = parse_arguments()
    
    try:
        # Initialize resource tracker
        tracker = GlobalResourceTracker()
        
        # Show device status if requested
        if args.device_status:
            show_device_status()
            return 0
        
        # Show resource summary if requested
        if args.summary_only:
            summary = tracker.get_resource_summary()
            print("📊 Resource Summary")
            print("=" * 50)
            print(f"📁 Total Files: {summary['files']}")
            print(f"📂 Total Directories: {summary['directories']}")
            print(f"⚙️  Total Processes: {summary['processes']}")
            print(f"🔄 Total Runs: {summary['total_runs']}")
            return 0
        
        # Show device status before cleanup
        print("📱 Checking device status before cleanup...")
        show_device_status()
        
        # Get user confirmation
        if not confirm_cleanup(args.force, args.dry_run):
            print("❌ Cleanup cancelled by user")
            return 1
        
        # Perform cleanup
        if args.dry_run:
            print("\n🔍 DRY RUN - Would perform the following cleanup:")
            # Show what would be cleaned (implementation needed)
            return 0
        
        if args.current_only:
            print("\n🧹 Cleaning current run only...")
            # Clean current run only (implementation needed)
        else:
            print("\n🧹 Cleaning all tracked resources...")
            cleanup_results = tracker.cleanup_all()
        
        print("✅ Cleanup completed successfully")
        return 0
        
    except DeviceConnectionError as e:
        print(f"❌ DEVICE ERROR: {e.message}")
        if e.details:
            print(f"💡 {e.details}")
        return 1
        
    except CleanupError as e:
        print(f"❌ CLEANUP ERROR: {e.message}")
        if e.details:
            print(f"💡 {e.details}")
        return 1
        
    except AutomationError as e:
        print(f"❌ AUTOMATION ERROR: {e.message}")
        if e.details:
            print(f"💡 {e.details}")
        return 1
        
    except Exception as e:
        print(f"❌ CRITICAL ERROR: {e}")
        if args.verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
```

## **Testing Strategy**

### **Unit Tests**
**File**: `tests/test_adb_utils.py`

```python
#!/usr/bin/env python3
"""
Unit tests for ADB utilities and error handling.
"""

import unittest
from unittest.mock import patch, MagicMock
from scripts.utils.adb_utils import ADBUtils, ADBCommandError, DeviceInfo, DeviceStatus
from scripts.utils.error_handlers import DeviceConnectionError, InstallationError

class TestADBUtils(unittest.TestCase):
    """Test cases for ADB utilities."""
    
    def test_check_adb_availability_success(self):
        """Test ADB availability check when ADB is available."""
        with patch.object(ADBUtils, 'execute_adb_command') as mock_execute:
            mock_execute.return_value = (0, "Android Debug Bridge version 1.0.41", "")
            result = ADBUtils.check_adb_availability()
            self.assertTrue(result)
    
    def test_check_adb_availability_failure(self):
        """Test ADB availability check when ADB is not available."""
        with patch.object(ADBUtils, 'execute_adb_command') as mock_execute:
            mock_execute.side_effect = ADBCommandError("adb version", -1, "command not found")
            result = ADBUtils.check_adb_availability()
            self.assertFalse(result)
    
    def test_get_connected_devices_success(self):
        """Test getting connected devices with valid output."""
        mock_output = """List of devices attached
emulator-5554    device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64
ABCD1234         unauthorized
"""
        with patch.object(ADBUtils, 'execute_adb_command') as mock_execute:
            mock_execute.return_value = (0, mock_output, "")
            devices = ADBUtils.get_connected_devices()
            
            self.assertEqual(len(devices), 2)
            self.assertEqual(devices[0].device_id, "emulator-5554")
            self.assertEqual(devices[0].status, DeviceStatus.AUTHORIZED)
            self.assertEqual(devices[1].device_id, "ABCD1234")
            self.assertEqual(devices[1].status, DeviceStatus.UNAUTHORIZED)
    
    def test_install_apk_success(self):
        """Test successful APK installation."""
        with patch.object(ADBUtils, 'check_adb_availability') as mock_check:
            with patch.object(ADBUtils, 'get_authorized_devices') as mock_devices:
                with patch.object(ADBUtils, 'execute_adb_command') as mock_execute:
                    mock_check.return_value = True
                    mock_devices.return_value = [DeviceInfo("emulator-5554", DeviceStatus.AUTHORIZED)]
                    mock_execute.return_value = (0, "Success", "")
                    
                    result = ADBUtils.install_apk("/path/to/app.apk")
                    self.assertTrue(result)

class TestErrorHandlers(unittest.TestCase):
    """Test cases for error handling utilities."""
    
    def test_handle_adb_errors_unauthorized(self):
        """Test handling of unauthorized device error."""
        @handle_adb_errors
        def test_function():
            raise ADBCommandError("adb devices", -1, "device unauthorized")
        
        with self.assertRaises(DeviceConnectionError) as context:
            test_function()
        
        self.assertEqual(context.exception.error_code, "DEVICE_UNAUTHORIZED")
        self.assertIn("authorize", context.exception.details)

if __name__ == "__main__":
    unittest.main()
```

## **Migration Plan**

### **Phase 1: Implementation (Week 1)**
1. Create `scripts/utils/adb_utils.py` with standardized ADB command execution
2. Create `scripts/utils/error_handlers.py` with enhanced error handling
3. Update `scripts/automations/install_apk.py` to use new utilities
4. Add unit tests for new utilities

### **Phase 2: Integration (Week 2)**
1. Update `automatool.py` to use enhanced error handling
2. Update `scripts/automations/resource_tracker.py` to use standardized ADB utilities
3. Create enhanced `cleanup.py` script
4. Add integration tests

### **Phase 3: Testing & Validation (Week 3)**
1. Comprehensive testing with various device scenarios
2. Error condition testing
3. Performance validation
4. User acceptance testing

### **Phase 4: Documentation & Deployment (Week 4)**
1. Update documentation
2. Create user guides for troubleshooting
3. Deploy to production
4. Monitor for issues

## **Success Metrics**

1. **Reliability**: 95%+ success rate for APK installations
2. **Error Handling**: Clear, actionable error messages for all failure scenarios
3. **User Experience**: Reduced user confusion and support requests
4. **Maintainability**: Consistent code patterns across all ADB-related modules
5. **Test Coverage**: 90%+ test coverage for new utilities

## **Risk Mitigation**

1. **Backward Compatibility**: Maintain existing function signatures where possible
2. **Gradual Rollout**: Implement changes incrementally with feature flags
3. **Comprehensive Testing**: Test all device states and error conditions
4. **User Feedback**: Collect feedback during testing phase
5. **Rollback Plan**: Maintain ability to revert to previous implementation

This specification provides a comprehensive solution to the identified issues while maintaining backward compatibility and ensuring robust error handling throughout the automation workflow.
