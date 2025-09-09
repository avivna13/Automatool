"""
ADB Controller for executing Android Debug Bridge commands.

This module provides a simple interface for executing ADB commands
and handling their results for the monitoring system.
"""

import subprocess
import logging
import os
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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


class ADBController:
    """Controls ADB command execution and result handling."""
    
    def __init__(self, timeout: int = 30):
        """
        Initialize ADB Controller.
        
        Args:
            timeout (int): Command timeout in seconds
        """
        self.timeout = timeout
        self.last_command = None
        self.last_result = None
        
        logger.info(f"ADB Controller initialized with {timeout}s timeout")
    
    def execute_command(self, cmd: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute an ADB command and return the result.
        
        Args:
            cmd (str): ADB command to execute
            timeout (int, optional): Override default timeout
            
        Returns:
            Dict containing command execution results
        """
        actual_timeout = timeout or self.timeout
        self.last_command = cmd
        
        logger.info(f"Executing ADB command: {cmd}")
        
        try:
            # Execute the command
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=actual_timeout
            )
            
            # Store the result
            self.last_result = {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'command': cmd,
                'timestamp': datetime.now().isoformat()
            }
            
            if result.returncode == 0:
                logger.info(f"Command executed successfully: {len(result.stdout)} chars output")
            else:
                logger.warning(f"Command failed with return code {result.returncode}")
                if result.stderr:
                    logger.warning(f"Error output: {result.stderr}")
            
            return self.last_result
            
        except subprocess.TimeoutExpired:
            error_msg = f"Command timed out after {actual_timeout}s"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg,
                'command': cmd,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Command execution failed: {str(e)}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg,
                'command': cmd,
                'timestamp': datetime.now().isoformat()
            }
    
    def check_adb_connection(self) -> bool:
        """
        Check if ADB is connected to a device.
        
        Returns:
            bool: True if device is connected, False otherwise
        """
        try:
            result = subprocess.run(
                "adb devices",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Check if there are any devices listed
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:  # First line is "List of devices attached"
                    device_lines = [line for line in lines[1:] if line.strip() and 'device' in line]
                    if device_lines:
                        logger.info(f"ADB connected to {len(device_lines)} device(s)")
                        return True
            
            logger.warning("No ADB devices found")
            return False
            
        except Exception as e:
            logger.error(f"Failed to check ADB connection: {str(e)}")
            return False

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
            
            # Build install command (device flag must come before install command)
            if device_id:
                install_cmd = f"adb -s {device_id} install -r \"{apk_path}\""
            else:
                install_cmd = f"adb install -r \"{apk_path}\""
            
            # Execute installation
            result = self.execute_command(install_cmd)
            
            # Parse installation result
            if result['success'] and "Success" in result['stdout']:
                logger.info(f"APK installed successfully on device: {target_device}")
                return True
            else:
                # Provide detailed error information
                error_msg = f"APK installation failed on device {target_device}"
                if result.get('stderr'):
                    error_msg += f"\nError: {result['stderr'].strip()}"
                if result.get('stdout'):
                    error_msg += f"\nOutput: {result['stdout'].strip()}"
                logger.error(error_msg)
                print(f"❌ {error_msg}")
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
            
            # Build uninstall command (device flag must come before uninstall command)
            if device_id:
                uninstall_cmd = f"adb -s {device_id} uninstall {package_name}"
            else:
                uninstall_cmd = f"adb uninstall {package_name}"
            
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
    
    def get_device_info(self) -> Dict[str, Any]:
        """
        Get basic device information.
        
        Returns:
            Dict containing device information
        """
        if not self.check_adb_connection():
            return {'error': 'No device connected'}
        
        try:
            # Get device model
            model_result = subprocess.run(
                "adb shell getprop ro.product.model",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Get Android version
            version_result = subprocess.run(
                "adb shell getprop ro.build.version.release",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return {
                'model': model_result.stdout.strip() if model_result.returncode == 0 else 'Unknown',
                'android_version': version_result.stdout.strip() if version_result.returncode == 0 else 'Unknown',
                'connected': True,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get device info: {str(e)}")
            return {'error': str(e)}
    
    def get_last_command(self) -> Optional[str]:
        """Get the last executed command."""
        return self.last_command
    
    def get_last_result(self) -> Optional[Dict[str, Any]]:
        """Get the last command result."""
        return self.last_result


# Convenience function for quick ADB command execution
def execute_adb_command(cmd: str, timeout: int = 30) -> Dict[str, Any]:
    """
    Quick function to execute an ADB command.
    
    Args:
        cmd (str): ADB command to execute
        timeout (int): Command timeout in seconds
        
    Returns:
        Dict containing command execution results
    """
    controller = ADBController(timeout=timeout)
    return controller.execute_command(cmd)


if __name__ == "__main__":
    # Test the ADB Controller
    print("Testing ADB Controller...")
    
    controller = ADBController()
    
    # Test ADB connection
    if controller.check_adb_connection():
        print("✅ ADB connection successful")
        
        # Test device info
        device_info = controller.get_device_info()
        print(f"📱 Device info: {device_info}")
        
        # Test command execution
        result = controller.execute_command("adb shell echo 'Hello from ADB'")
        print(f"🔧 Command result: {result['success']}")
        if result['success']:
            print(f"📝 Output: {result['stdout'].strip()}")
        
    else:
        print("❌ ADB connection failed")
        print("Make sure ADB is installed and device is connected")
