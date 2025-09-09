# utils/process_manager.py
import subprocess
import threading
import time
import os
from datetime import datetime
from config import Config


class ProcessManager:
    def __init__(self):
        self.current_process = None
        self.process_status = "ready"
        self.process_log = []
        self.automatool_path = "../automatool/automatool/src"  # Relative path to automatool
        self.default_timeout = Config.DEFAULT_TIMEOUT
   
    def execute_automatool(self, output_dir, apk_filename, verbose=True, install_apk=True):
        """Execute the main automatool.py process."""
        cmd = [
            'python', 'automatool.py',
            '-d', output_dir,
            '-f', apk_filename
        ]
        if verbose:
            cmd.append('--verbose')
        if install_apk:
            cmd.append('--install')
       
        return self._run_process(cmd, "Full Process", self.automatool_path, timeout=self.default_timeout)
   
    def execute_reviews_parsing(self, output_dir, verbose=True):
        """Execute reviews parsing using parse_reviews_summary.py."""
        # This function should be called from the automatool source directory
        script_path = os.path.join("scripts", "automations", "parse_reviews_summary.py")
        cmd = ['python', script_path, output_dir]
        if verbose:
            cmd.append('--verbose')
       
        return self._run_process(cmd, "Get Reviews", self.automatool_path)
   
    def execute_cleanup(self, verbose=True):
        """Execute cleanup process."""
        cmd = ['python', 'cleanup.py', '--force']
        if verbose:
            cmd.append('--verbose')
       
        return self._run_process(cmd, "Clean", self.automatool_path)
   
    def execute_mobsf_upload(self, apk_path, output_dir, verbose=True):
        """Execute MobSF upload using the worker script."""
        worker_script = os.path.join("scripts", "automations", "_mobsf_analysis_worker.py")
        cmd = [
            'python', worker_script,
            '--apk-path', apk_path,
            '--output-dir', output_dir
        ]
        if verbose:
            cmd.append('--verbose')
       
        return self._run_process(cmd, "Upload to MobSF", self.automatool_path, timeout=self.default_timeout)
   
    def execute_strings_on_so(self, apktool_output_path, output_directory, verbose=True):
        """Execute strings analysis on .so files."""
        script_path = os.path.join("scripts", "automations", "run_strings_on_so_files.py")
        cmd = [
            'python', script_path,
            apktool_output_path,
            output_directory
        ]
        if verbose:
            cmd.append('--verbose')
        
        return self._run_process(cmd, "Run Strings on .so", self.automatool_path, timeout=self.default_timeout)

    def execute_apkleaks(self, apk_path, output_dir, verbose=True):
        """Execute apkleaks scan."""
        script_path = os.path.join("scripts", "automations", "run_apkleaks.py")
        cmd = [
            'python', script_path,
            '-f', apk_path,
            '-o', output_dir
        ]
        if verbose:
            cmd.append('--verbose')
        
        return self._run_process(cmd, "Run APKLeaks", self.automatool_path, timeout=self.default_timeout)

    def execute_font_analysis(self, apktool_output_path, output_directory, verbose=True):
        """Execute TTF font steganography analysis."""
        script_path = os.path.join("scripts", "automations", "launch_font_analysis.py")
        cmd = [
            'python', script_path,
            '--apktool-path', apktool_output_path,
            '--output-dir', output_directory
        ]
        if verbose:
            cmd.append('--verbose')
        
        return self._run_process(cmd, "TTF Font Analysis", self.automatool_path, timeout=self.default_timeout)

    def execute_frida_fsmon_scan(self, output_dir, package_name):
        """Execute a combined Frida and F-Monitor scan."""
        # Define the individual commands
        frida_command = (
            f"frida -Uf {package_name} "
            f"-l frida_scripts/bypasses/liscencecheck.js "
            f"-l frida_scripts/info/crypto.js "
            f"-l frida_scripts/info/dex_load_tracer.js"
        )
        fsmon_command = f"fsmon {package_name}"

        # Check if fsmon is available before proceeding
        fsmon_check_command = "command -v fsmon"
        
        # Combine them to run in parallel, with output to both stdout (for logging) and files
        # The 'wait' command ensures the shell waits for both background jobs to finish.
        # First check if fsmon is available, then run both commands
        combined_command = (
            f"if {fsmon_check_command} >/dev/null 2>&1; then "
            f"(timeout 60 {frida_command} | tee frida_scan.txt) & "
            f"(timeout 60 {fsmon_command} | tee fsmon_scan.txt) & "
            f"wait; "
            f"else "
            f"echo 'Warning: fsmon not found in PATH, running Frida only'; "
            f"timeout 60 {frida_command} | tee frida_scan.txt; "
            f"touch fsmon_scan.txt && echo 'fsmon not available - please ensure fsmon is installed and in PATH' > fsmon_scan.txt; "
            f"fi"
        )

        # Try zsh first (where fsmon is available), fallback to bash
        # Check if zsh is available
        try:
            subprocess.run(['zsh', '--version'], capture_output=True, check=True)
            shell_cmd = ['zsh', '-c', combined_command]
        except (FileNotFoundError, subprocess.CalledProcessError):
            # Fallback to bash if zsh is not available
            shell_cmd = ['bash', '-c', combined_command]
            self.add_log("⚠️ zsh not available, using bash (fsmon may not work if not in bash PATH)")
        
        # We give the wrapper a slightly longer timeout as a safeguard.
        return self._run_process(shell_cmd, "Frida & F-Monitor Scan", working_dir=output_dir, timeout=70)

    def execute_manifest_analysis(self, apk_path, output_dir, verbose=True):
        """Execute AMAnDe manifest analysis."""
        # AMAnDe is located in the automatool src directory
        amande_path = os.path.join(self.automatool_path, "AMAnDe")
        main_script = "main.py"  # Use relative path for script executed from amande_path
        output_file = os.path.join(output_dir, "manifest_analysis.txt")
        
        # Command: python main.py -min 21 -max 33 test.apk > output.txt
        verbose_flag = '-v 0' if verbose else ''
        
        # Use shell redirection to capture output to file
        # This matches the exact command format requested
        shell_cmd = f"python {main_script} -min 21 -max 33 {verbose_flag} {apk_path} > {output_file}"
        
        return self._run_process(['bash', '-c', shell_cmd], "AMAnDe Manifest Analysis", amande_path, timeout=self.default_timeout)

    def execute_decompile_apk(self, apk_path, output_dir, verbose=True):
        """Execute standalone APK decompilation using apktool + Jadx."""
        script_path = os.path.join("scripts", "automations", "run_standalone_decompilation.py")
        cmd = [
            'python', script_path,
            apk_path,
            output_dir
        ]
        if verbose:
            cmd.append('--verbose')
        
        return self._run_process(cmd, "APK Decompilation", self.automatool_path, timeout=self.default_timeout)

    def execute_apk_unmask_analysis(self, apk_path, output_dir, enable_filtering=True, 
                                   enable_file_analysis=False, apktool_output_dir=None, verbose=True):
        """Execute standalone APK Unmask analysis with optional file type detection."""
        script_path = "scripts.automations.run_apk_unmask"
        cmd = [
            'python', '-m', script_path,
            apk_path,
            output_dir
        ]
        
        # Add options
        if not enable_filtering:
            cmd.append('--disable-filtering')
        
        if enable_file_analysis and apktool_output_dir:
            cmd.extend(['--enable-file-analysis', '--apktool-output', apktool_output_dir])
        
        if verbose:
            cmd.append('--verbose')
        
        return self._run_process(cmd, "APK Unmask Analysis", self.automatool_path, timeout=self.default_timeout)

    def _run_process(self, cmd, process_name, working_dir=None, timeout=None):
        """Run process in background thread."""
        if self.process_status == "running":
            self.add_log(f"❌ Cannot start {process_name}: Another process is already running")
            return False
       
        self.process_status = "running"
        self.add_log(f"🚀 Starting {process_name}...")
       
        final_cmd = cmd
        if timeout:
            final_cmd = ['timeout', str(timeout)] + cmd

        def run():
            try:
                # Set working directory if provided
                cwd = working_dir if working_dir else None
               
                # Ensure the working directory exists
                if cwd and not os.path.exists(cwd):
                    self.add_log(f"❌ Working directory does not exist: {cwd}")
                    self.process_status = "error"
                    return
               
                self.add_log(f"📂 Working directory: {cwd or 'current directory'}")
                self.add_log(f"🔧 Command: {' '.join(final_cmd)}")
               
                process = subprocess.Popen(
                    final_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd=cwd,
                    universal_newlines=True
                )
               
                self.current_process = {
                    'name': process_name,
                    'pid': process.pid,
                    'start_time': datetime.now(),
                    'process': process,
                    'command': ' '.join(final_cmd)
                }
               
                self.add_log(f"🔄 Process started with PID: {process.pid}")
               
                # Read output line by line
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        self.add_log(output.strip())
               
                # Wait for process to complete
                return_code = process.poll()
               
                if return_code == 124:
                    self.process_status = "error"
                    self.add_log(f"❌ {process_name} timed out and was terminated.")
                elif return_code == 0:
                    self.process_status = "completed"
                    self.add_log(f"✅ {process_name} completed successfully")
                else:
                    self.process_status = "error"
                    self.add_log(f"❌ {process_name} failed with exit code {return_code}")
               
            except FileNotFoundError as e:
                self.process_status = "error"
                if 'timeout' in str(e):
                    self.add_log(f"❌ Command 'timeout' not found. Please install it (e.g., 'sudo apt-get install coreutils').")
                elif 'zsh' in str(e):
                    self.add_log(f"❌ Shell 'zsh' not found. Falling back to bash or install zsh.")
                    self.add_log(f"💡 You can install zsh with: sudo apt-get install zsh")
                elif 'fsmon' in str(e):
                    self.add_log(f"❌ fsmon command not found in PATH.")
                    self.add_log(f"💡 Make sure fsmon is installed and available in your shell PATH")
                else:
                    self.add_log(f"❌ Command not found: {e}")
                self.add_log(f"💡 Make sure Python and required scripts are installed")
            except Exception as e:
                self.process_status = "error"
                self.add_log(f"❌ Error running {process_name}: {str(e)}")
           
            finally:
                self.current_process = None
       
        # Start the process in a daemon thread
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
       
        return True
   
    def add_log(self, message):
        """Add message to process log."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_entry = f"[{timestamp}] {message}"
        self.process_log.append(log_entry)
       
        # Keep only last 100 log entries to prevent memory issues
        if len(self.process_log) > 100:
            self.process_log = self.process_log[-100:]
       
        # Print to console for debugging (can be disabled in production)
        print(log_entry)
   
    def get_status(self):
        """Get current process status."""
        current_time = datetime.now()
       
        # Calculate duration if process is running
        duration = None
        if self.current_process and self.current_process.get('start_time'):
            duration_seconds = (current_time - self.current_process['start_time']).total_seconds()
            hours = int(duration_seconds // 3600)
            minutes = int((duration_seconds % 3600) // 60)
            seconds = int(duration_seconds % 60)
            duration = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
       
        # Prepare current process info
        current_process_info = None
        if self.current_process:
            current_process_info = {
                'name': self.current_process['name'],
                'pid': self.current_process['pid'],
                'start_time': self.current_process['start_time'].isoformat(),
                'duration': duration,
                'command': self.current_process.get('command', '')
            }
       
        return {
            'status': self.process_status,
            'current_process': current_process_info,
            'log': self.process_log[-10:] if self.process_log else [],  # Last 10 entries
            'full_log': self.process_log
        }
   
    def is_running(self):
        """Check if a process is currently running."""
        return self.process_status == "running"
   
    def kill_current_process(self):
        """Kill the currently running process."""
        if self.current_process and self.current_process.get('process'):
            try:
                process = self.current_process['process']
                process.terminate()
               
                # Wait a bit for graceful termination
                time.sleep(2)
               
                # Force kill if still running
                if process.poll() is None:
                    process.kill()
               
                self.add_log(f"🛑 Process {self.current_process['name']} terminated")
                self.process_status = "cancelled"
                self.current_process = None
                return True
               
            except Exception as e:
                self.add_log(f"❌ Error terminating process: {e}")
                return False
       
        return False
   
    def clear_log(self):
        """Clear the process log."""
        self.process_log = []
        self.add_log("📋 Log cleared")
   
    def get_log_summary(self):
        """Get a summary of recent log entries."""
        if not self.process_log:
            return "No log entries"
       
        recent_logs = self.process_log[-5:] if len(self.process_log) > 5 else self.process_log
        return "\n".join(recent_logs)
   
    # VPN-Frida Methods
   
    def start_vpn_frida(self, package_name: str, country: str, device_id: str = None, verbose: bool = True) -> bool:
        """Start VPN-Frida automation process."""
        try:
            if self.process_status == "running":
                self.add_log(f"❌ Cannot start VPN-Frida: Another process is already running")
                return False
           
            # Build the command to launch the VPN-Frida worker
            script_path_relative = os.path.join("scripts", "automations", "_vpn_frida_worker.py")
            worker_script_full = os.path.join(self.automatool_path, script_path_relative)

            if not os.path.exists(worker_script_full):
                self.add_log(f"❌ VPN-Frida worker script not found: {worker_script_full}")
                return False
           
            # Build command with arguments
            cmd = [
                'python', script_path_relative,
                '--package-name', package_name,
                '--vpn-country', country,
                '--vpn-provider', 'nordvpn'
            ]
           
            if device_id:
                cmd.extend(['--device-id', device_id])
           
            if verbose:
                cmd.append('--verbose')
           
            self.add_log(f"🚀 Starting VPN-Frida automation for {package_name} in {country}")
           
            # Run the process without timeout (VPN-Frida should run continuously)
            return self._run_process(cmd, f"VPN-Frida ({package_name})", self.automatool_path, timeout=None)
           
        except Exception as e:
            self.add_log(f"❌ Failed to start VPN-Frida: {e}")
            return False
   
    def change_vpn_region(self, new_country: str) -> bool:
        """Change VPN region during execution."""
        try:
            self.add_log(f"🔄 VPN region change requested to: {new_country}")
            
            # Import VPN controller to change region
            import sys
            import os
            
            # Add the automations directory to Python path
            automations_path = os.path.join(self.automatool_path, "scripts", "automations")
            if automations_path not in sys.path:
                sys.path.insert(0, automations_path)
            
            try:
                from vpn_controllers import get_vpn_controller
                
                # Get NordVPN controller and attempt to connect to new country
                vpn_controller = get_vpn_controller("nordvpn")
                
                self.add_log(f"🌐 Connecting to VPN in {new_country}...")
                success = vpn_controller.connect(new_country)
                
                if success:
                    self.add_log(f"✅ Successfully changed VPN region to {new_country}")
                    self.add_log(f"🔄 Restarting automation to run from new location...")
                    
                    # Store current process info before terminating
                    if self.current_process:
                        package_name = self._extract_package_name_from_process()
                        
                        # Terminate current process
                        self.add_log(f"🛑 Terminating current process...")
                        self.kill_current_process()
                        
                        # Wait a moment for cleanup
                        import time
                        time.sleep(2)
                        
                        # Restart with new country
                        if package_name:
                            self.add_log(f"🚀 Restarting VPN-Frida with {package_name} in {new_country}")
                            restart_success = self.start_vpn_frida(package_name, new_country)
                            if restart_success:
                                self.add_log(f"✅ Successfully restarted automation in {new_country}")
                                return True
                            else:
                                self.add_log(f"❌ Failed to restart automation")
                                return False
                        else:
                            self.add_log(f"❌ Could not extract package name for restart")
                            return False
                    else:
                        self.add_log(f"❌ No current process to restart")
                        return False
                else:
                    self.add_log(f"❌ Failed to connect to VPN in {new_country}")
                    self.add_log(f"ℹ️ The automation continues with the current VPN connection")
                    return False
                    
            except ImportError as e:
                self.add_log(f"❌ VPN controller import failed: {e}")
                self.add_log(f"ℹ️ Make sure VPN controllers are properly installed")
                return False
           
        except Exception as e:
            self.add_log(f"❌ Failed to change VPN region: {e}")
            return False

    def _extract_package_name_from_process(self) -> str:
        """Extract package name from current process command."""
        try:
            if self.current_process and 'command' in self.current_process:
                command = self.current_process['command']
                # Look for --package-name argument in the command
                parts = command.split()
                for i, part in enumerate(parts):
                    if part == '--package-name' and i + 1 < len(parts):
                        return parts[i + 1]
            return None
        except Exception as e:
            self.add_log(f"❌ Error extracting package name: {e}")
            return None

    def execute_blutter_analysis(self, output_dir, verbose=True):
        """Execute Blutter Flutter analysis on libapp.so files."""
        script_path = os.path.join("scripts", "automations", "run_blutter_analysis.py")
        cmd = [
            'python', script_path,
            output_dir
        ]
        
        if verbose:
            cmd.append('--verbose')
        
        return self._run_process(cmd, "Blutter Flutter Analysis", self.automatool_path, timeout=300)  # 5 min timeout