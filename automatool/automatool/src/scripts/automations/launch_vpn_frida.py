"""
VPN-Frida Automation Launcher

Launches VPN-controlled Frida automation as a background process.
Follows the same pattern as other automation launchers in this project.
"""

import subprocess
import os
import sys


def launch_vpn_frida(package_name, vpn_country, frida_scripts=None, vpn_provider="nordvpn", 
                    device_id=None, execution_timeout=300, output_directory=None, verbose=False):
    """
    Launch VPN-controlled Frida automation as a background process.
    
    Args:
        package_name (str): Android package name to hook
        vpn_country (str): Target country for VPN connection
        frida_scripts (list): List of Frida script paths (defaults to ['main_hook.js'])
        vpn_provider (str): VPN service provider ("nordvpn")
        device_id (str): Specific Android device ID (optional)
        execution_timeout (int): Maximum execution time in seconds
        output_directory (str): Directory to save logs and results
        verbose (bool): Enable verbose output
        
    Returns:
        subprocess.Popen or bool: Process object if launch was successful, False otherwise
    """
    if verbose:
        print(f"[DEBUG] Launching VPN-Frida automation for package: {package_name}")
        print(f"[DEBUG] Target VPN country: {vpn_country}")
        print(f"[DEBUG] VPN Provider: {vpn_provider}")
        print(f"[DEBUG] Frida scripts: {frida_scripts or ['main_hook.js (default)']}")
    
    try:
        # Get the worker script path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        worker_script = os.path.join(script_dir, "_vpn_frida_worker.py")
        
        # Verify worker script exists
        if not os.path.exists(worker_script):
            print("❌ ERROR: VPN-Frida worker script not found.")
            if verbose:
                print(f"[DEBUG] Expected worker script at: {worker_script}")
            return False
        
        # Prepare command arguments
        cmd_args = [
            sys.executable, worker_script,
            "--package-name", package_name,
            "--vpn-country", vpn_country,
            "--vpn-provider", vpn_provider,
            "--timeout", str(execution_timeout)
        ]
        
        # Add optional arguments
        if frida_scripts:
            for script in frida_scripts:
                cmd_args.extend(["--script", script])
        
        if device_id:
            cmd_args.extend(["--device-id", device_id])
            
        if output_directory:
            cmd_args.extend(["--output-dir", output_directory])
            
        if verbose:
            cmd_args.append("--verbose")
        
        if verbose:
            print(f"[DEBUG] Command to execute: {' '.join(cmd_args)}")
        
        # Launch worker as background process
        process = subprocess.Popen(
            cmd_args,
            stdout=subprocess.DEVNULL,  # Suppress stdout
            stderr=subprocess.DEVNULL,  # Suppress stderr
            text=True
        )
        
        if verbose:
            print(f"[DEBUG] ✅ VPN-Frida automation launched with PID: {process.pid}")
            
        print(f"🌐 VPN-Frida automation started for {package_name} in {vpn_country}...")
        return process
        
    except FileNotFoundError:
        print("❌ ERROR: Python executable not found for worker process.")
        if verbose:
            print(f"[DEBUG] Python executable: {sys.executable}")
        return False
        
    except Exception as e:
        print(f"❌ ERROR: Failed to launch VPN-Frida automation: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False


# For testing purposes - allow running this script directly
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Launch VPN-Frida Automation")
    parser.add_argument("package_name", help="Android package name")
    parser.add_argument("vpn_country", help="Target VPN country")
    parser.add_argument("--scripts", nargs="*", help="Frida script paths")
    parser.add_argument("--provider", default="nordvpn", help="VPN provider")
    parser.add_argument("--device-id", help="Specific device ID")
    parser.add_argument("--timeout", type=int, default=300, help="Execution timeout")
    parser.add_argument("--output-dir", help="Output directory")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    process = launch_vpn_frida(
        package_name=args.package_name,
        vpn_country=args.vpn_country,
        frida_scripts=args.scripts,
        vpn_provider=args.provider,
        device_id=args.device_id,
        execution_timeout=args.timeout,
        output_directory=args.output_dir,
        verbose=args.verbose
    )
    
    if process:
        print(f"✅ VPN-Frida automation launched successfully with PID: {process.pid}")
        print("Process is running in background...")
        
        # For testing, you can uncomment the line below to wait for completion
        # process.wait()
        
    else:
        print("❌ Failed to launch VPN-Frida automation")
        sys.exit(1)
