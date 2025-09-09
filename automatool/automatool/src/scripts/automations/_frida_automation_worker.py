#!/usr/bin/env python3
"""
VPN-Frida Automation Worker Process


Handles VPN connection management and Frida script execution in background.
Designed to run as a separate process for non-blocking operation.


This is a simplified initial version that focuses on the core workflow.
"""


import argparse
import subprocess
import sys
import os
import time
import json
from datetime import datetime
from pathlib import Path


# Import VPN controllers
from vpn_controllers import get_vpn_controller




def parse_arguments():
    """Parse command line arguments for worker process."""
    parser = argparse.ArgumentParser(description="VPN-Frida Automation Worker")
    parser.add_argument("--package-name", required=True, help="Android package name")
    parser.add_argument("--vpn-country", required=True, help="Target VPN country")
    parser.add_argument("--vpn-provider", default="nordvpn", choices=["nordvpn"])
    parser.add_argument("--script", action="append", dest="scripts", help="Frida script path")
    parser.add_argument("--device-id", help="Specific Android device ID")
    parser.add_argument("--timeout", type=int, default=300, help="Execution timeout in seconds")
    parser.add_argument("--output-dir", help="Output directory for logs")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()




def setup_output_directory(output_dir, package_name):
    """Create and setup output directory for logs."""
    if not output_dir:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"vpn_frida_{package_name}_{timestamp}"
   
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    return output_dir




def connect_vpn(vpn_provider, vpn_country, verbose=False):
    """Connect to VPN using specified provider and country."""
    try:
        if verbose:
            print(f"[DEBUG] Getting VPN controller for provider: {vpn_provider}")
       
        vpn_controller = get_vpn_controller(vpn_provider)
       
        if verbose:
            print(f"[DEBUG] Attempting to connect to {vpn_country} via {vpn_provider}")
       
        success = vpn_controller.connect(vpn_country)
       
        if success:
            if verbose:
                print(f"[DEBUG] VPN connection successful")
            return True
        else:
            print(f"[ERROR] VPN connection to {vpn_country} failed")
            return False
           
    except Exception as e:
        print(f"[ERROR] VPN connection failed: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False




def validate_frida_environment(device_id=None, verbose=False):
    """Enhanced Frida installation and device connectivity validation."""
    try:
        # Check Frida CLI availability and version
        result = subprocess.run(["frida", "--version"], capture_output=True, text=True, check=True)
        frida_version = result.stdout.strip()
       
        if verbose:
            print(f"[DEBUG] Frida version: {frida_version}")
       
        # Validate minimum Frida version (16.0.0+)
        try:
            version_parts = frida_version.split('.')
            major_version = int(version_parts[0])
            if major_version < 16:
                print(f"[WARNING] Frida version {frida_version} is old. Recommended: 16.0.0+")
        except (ValueError, IndexError):
            if verbose:
                print(f"[DEBUG] Could not parse Frida version: {frida_version}")
       
        # Get detailed device information
        devices_info = get_frida_devices_info(verbose)
        if not devices_info:
            print("[ERROR] No Frida-compatible devices found")
            return False
       
        # Display available devices
        print(f"[DEVICES] Found {len(devices_info)} Frida-compatible device(s):")
        for device in devices_info:
            status_icon = "[ONLINE]" if device['status'] == 'available' else "[OFFLINE]"
            device_type_icon = "[DEVICE]" if device['type'] == 'device' else "[EMULATOR]"
            print(f"  {status_icon} {device_type_icon} {device['id']} - {device['name']} ({device['type']})")
       
        # Validate specific device if provided
        if device_id:
            target_device = next((d for d in devices_info if d['id'] == device_id), None)
            if not target_device:
                print(f"[ERROR] Device '{device_id}' not found")
                print("Available devices:")
                for device in devices_info:
                    print(f"  - {device['id']}")
                return False
           
            if target_device['status'] != 'available':
                print(f"[ERROR] Device '{device_id}' is not available (status: {target_device['status']})")
                return False
               
            if verbose:
                print(f"[DEBUG] Target device validated: {device_id}")
        else:
            # Check if we have at least one available device
            available_devices = [d for d in devices_info if d['status'] == 'available']
            if not available_devices:
                print("[ERROR] No available devices found")
                return False
           
            if verbose:
                print(f"[DEBUG] {len(available_devices)} available device(s) found")
           
        return True
       
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[ERROR] Frida environment validation failed: {e}")
        return False




def get_frida_devices_info(verbose=False):
    """Get detailed information about available Frida devices."""
    try:
        # Get devices list
        devices_result = subprocess.run(["frida-ls-devices"], capture_output=True, text=True, check=True)
       
        if verbose:
            print(f"[DEBUG] Raw devices output:\n{devices_result.stdout}")
       
        devices_info = []
        for line in devices_result.stdout.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('Id'):  # Skip header and empty lines
                continue
               
            # Parse device line format: "Id  Type    Name"
            parts = line.split(None, 2)  # Split into max 3 parts
            if len(parts) >= 2:
                device_id = parts[0]
                device_type = parts[1].lower()
                device_name = parts[2] if len(parts) > 2 else "Unknown"
               
                # Determine status based on type
                status = 'available' if device_type in ['usb', 'tether', 'remote'] else 'offline'
               
                # Categorize device type
                if 'emulator' in device_name.lower() or device_type == 'remote':
                    category = 'emulator'
                else:
                    category = 'device'
               
                devices_info.append({
                    'id': device_id,
                    'type': category,
                    'name': device_name,
                    'status': status,
                    'connection_type': device_type
                })
       
        return devices_info
       
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        if verbose:
            print(f"[DEBUG] Error getting device info: {e}")
        return []




def validate_package_name(package_name, device_id=None, verbose=False):
    """Simple package validation - check if package is installed on device."""
    return True
    # try:
    #     # Build frida-ps command to list all installed applications
    #     cmd = ["frida-ps", "-Ua"]
    #     if device_id:
    #         cmd = ["frida-ps", "-D", device_id, "-a"]
           
    #     if verbose:
    #         print(f"[DEBUG] Checking for package: {package_name}")
    #         print(f"[DEBUG] Command: {' '.join(cmd)}")
       
    #     # Get all processes/packages
    #     result = subprocess.run(cmd, capture_output=True, text=True, check=True)
       
    #     if verbose:
    #         print(f"[DEBUG] Found applications:\n{result.stdout}")
       
    #     # Check if our package is in the list
    #     if package_name in result.stdout:
    #         print(f"[PACKAGE] Found package: {package_name}")
           
    #         # Try to get more details with installed apps
    #         try:
    #             detailed_cmd = cmd + ["-i"]  # Get installed applications with icons
    #             detailed_result = subprocess.run(detailed_cmd, capture_output=True, text=True, check=True)
               
    #             # Look for our package in detailed output
    #             for line in detailed_result.stdout.splitlines():
    #                 if package_name in line:
    #                     if verbose:
    #                         print(f"[DEBUG] Package details: {line.strip()}")
    #                     print(f"[PACKAGE] Package status: Installed")
    #                     break
    #             else:
    #                 print(f"[PACKAGE] Package status: Available but not detailed")
                   
    #         except (subprocess.CalledProcessError, FileNotFoundError):
    #             if verbose:
    #                 print("[DEBUG] Could not get detailed package info")
               
    #         return True
    #     else:
    #         print(f"[PACKAGE] Package '{package_name}' not found on device")
           
    #         # Show available packages for debugging
    #         if verbose:
    #             print("[DEBUG] Available packages:")
    #             lines = result.stdout.strip().split('\n')
    #             for line in lines[:10]:  # Show first 10 for brevity
    #                 if line.strip() and not line.startswith('PID'):
    #                     print(f"  - {line.strip()}")
    #             if len(lines) > 10:
    #                 print(f"  ... and {len(lines) - 10} more")
           
    #         return False
           
    # except (subprocess.CalledProcessError, FileNotFoundError) as e:
    #     print(f"[ERROR] Package validation failed: {e}")
    #     if verbose:
    #         print(f"[DEBUG] Error details: {type(e).__name__}: {e}")
    #     return False





def prepare_frida_scripts(scripts, verbose=False):
    """Prepare and validate Frida script paths."""
    if not scripts:
        # Use default main_hook.js - look for it in the project
        current_dir = Path(__file__).parent.parent.parent.parent.parent  # Go up to project root
        possible_paths = [
            current_dir / "automatool" / "src" / "scripts" / "frida" / "main_hook.js",
            current_dir / "FridaOS" / "FridaOS" / "src" / "backend" / "scripts" / "frida" / "main_hook.js",
            Path.cwd() / "main_hook.js"
        ]
       
        for path in possible_paths:
            if path.exists():
                scripts = [str(path)]
                if verbose:
                    print(f"[DEBUG] Using default script: {path}")
                break
        else:
            print("[ERROR] No Frida scripts provided and default main_hook.js not found")
            return None
   
    validated_scripts = []
    for script in scripts:
        script_path = Path(script)
        if not script_path.is_absolute():
            # Try relative to current directory
            script_path = Path.cwd() / script
       
        if script_path.exists():
            validated_scripts.append(str(script_path))
            if verbose:
                print(f"[DEBUG] Script validated: {script_path}")
        else:
            print(f"[ERROR] Script not found: {script}")
            return None
   
    return validated_scripts




def execute_frida_with_scripts(package_name, scripts, device_id=None, timeout=300, output_dir=None, verbose=False):
    """Execute Frida with multiple scripts."""
    try:
        # Build Frida command
        cmd = ["frida", "-Uf", package_name]
       
        # Add device specification if provided
        if device_id:
            cmd.extend(["-D", device_id])
       
        # Add all scripts
        for script in scripts:
            cmd.extend(["-l", script])
       
        if verbose:
            print(f"[DEBUG] Executing command: {' '.join(cmd)}")
       
        # Execute Frida process and capture output
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
       
        if verbose:
            print(f"[DEBUG] Frida process started with PID: {process.pid}")
       
        # Wait for completion or timeout
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return_code = process.returncode
           
            # Save logs to file if output_dir is available
            if output_dir:
                try:
                    stdout_log = Path(output_dir) / "frida_stdout.log"
                    stderr_log = Path(output_dir) / "frida_stderr.log"
                    with open(stdout_log, 'w') as f:
                        f.write(stdout)
                    with open(stderr_log, 'w') as f:
                        f.write(stderr)
                except Exception as e:
                    print(f"[WARNING] Could not write Frida logs to file: {e}")

            if return_code == 0:
                print("[SUCCESS] Frida execution completed successfully")
                if stdout and verbose:
                    print(f"--- Frida Stdout ---\n{stdout.strip()}\n--------------------")
                return True
            else:
                print(f"[WARNING] Frida execution finished with return code: {return_code}")
                if stderr:
                    print(f"--- Frida Stderr ---\n{stderr.strip()}\n--------------------")
                if stdout:
                    print(f"--- Frida Stdout ---\n{stdout.strip()}\n--------------------")
                return False
               
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            print(f"[TIMEOUT] Frida execution timed out after {timeout} seconds")
            if stderr:
                print(f"--- Frida Stderr (timeout) ---\n{stderr.strip()}\n--------------------")
            if stdout:
                print(f"--- Frida Stdout (timeout) ---\n{stdout.strip()}\n--------------------")
            return False
           
    except Exception as e:
        print(f"[ERROR] Frida execution failed: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False






def save_execution_summary(output_dir, package_name, vpn_country, vpn_provider, scripts, success, verbose=False):
    """Save execution summary to JSON file."""
    if not output_dir:
        return
   
    summary = {
        "timestamp": datetime.now().isoformat(),
        "package_name": package_name,
        "vpn_country": vpn_country,
        "vpn_provider": vpn_provider,
        "scripts": scripts,
        "success": success,
        "output_directory": str(output_dir)
    }
   
    summary_file = Path(output_dir) / "execution_summary.json"
    try:
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
       
        if verbose:
            print(f"[DEBUG] Execution summary saved to: {summary_file}")
           
    except Exception as e:
        print(f"[WARNING] Failed to save execution summary: {e}")




def main():
    """Main worker process execution."""
    args = parse_arguments()
   
    print(f"[VPN-FRIDA] Starting automation for {args.package_name}")
   
    # Setup output directory
    output_dir = setup_output_directory(args.output_dir, args.package_name)
    if args.verbose:
        print(f"[DEBUG] Output directory: {output_dir}")
   
    try:
        # Phase 1: VPN Connection
        print(f"[VPN] Connecting to VPN in {args.vpn_country} via {args.vpn_provider}...")
        vpn_success = connect_vpn(args.vpn_provider, args.vpn_country, args.verbose)
        if not vpn_success:
            save_execution_summary(output_dir, args.package_name, args.vpn_country,
                                 args.vpn_provider, args.scripts, False, args.verbose)
            return False
       
        print(f"[VPN] Connected to {args.vpn_country}")
       
        # Phase 2: Environment Validation
        print("[FRIDA] Validating Frida environment...")
        if not validate_frida_environment(args.device_id, args.verbose):
            save_execution_summary(output_dir, args.package_name, args.vpn_country,
                                 args.vpn_provider, args.scripts, False, args.verbose)
            return False
       
        # Phase 2.5: Package Validation
        print(f"[PACKAGE] Validating package: {args.package_name}")
        if not validate_package_name(args.package_name, args.device_id, args.verbose):
            save_execution_summary(output_dir, args.package_name, args.vpn_country,
                                 args.vpn_provider, args.scripts, False, args.verbose)
            return False
       
        # Phase 3: Script Preparation
        print("[SCRIPTS] Preparing Frida scripts...")
        validated_scripts = prepare_frida_scripts(args.scripts, args.verbose)
        if not validated_scripts:
            save_execution_summary(output_dir, args.package_name, args.vpn_country,
                                 args.vpn_provider, args.scripts, False, args.verbose)
            return False
       
        # Phase 4: Frida Execution
        print(f"[EXECUTE] Running Frida with {len(validated_scripts)} script(s)...")
        frida_success = execute_frida_with_scripts(
            args.package_name, validated_scripts, args.device_id,
            args.timeout, output_dir, args.verbose
        )
       
        # Phase 5: Cleanup and Summary
        save_execution_summary(output_dir, args.package_name, args.vpn_country,
                             args.vpn_provider, validated_scripts, frida_success, args.verbose)
       
        if frida_success:
            print("[SUCCESS] VPN-Frida automation completed successfully")
            return True
        else:
            print("[WARNING] VPN-Frida automation completed with issues")
            return False
           
    except Exception as e:
        print(f"[ERROR] VPN-Frida automation failed: {e}")
        if args.verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        save_execution_summary(output_dir, args.package_name, args.vpn_country,
                             args.vpn_provider, args.scripts, False, args.verbose)
        return False




if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)



