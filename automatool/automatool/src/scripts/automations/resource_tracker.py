#!/usr/bin/env python3
"""
Global Resource Tracker for APK Analysis Automation

This module tracks all resources created by automatool.py across all runs.
Resources are accumulated in a single JSON file and can be cleaned up completely.
"""

import os
import json
import shutil
import sys
from datetime import datetime
import psutil

class GlobalResourceTracker:
    def __init__(self):
        """Initialize the global resource tracker."""
        self.workspace_root = self._find_workspace_root()
        
        # Check if we're running in test environment
        if self._is_test_environment():
            # Use test resources file in tests/resources/ directory
            test_resources_dir = os.path.join(self.workspace_root, "tests", "resources")
            os.makedirs(test_resources_dir, exist_ok=True)
            self.resources_file = os.path.join(test_resources_dir, "automation_resources.json")
            print(f"[DEBUG] Test environment detected - using test resources file")
        else:
            # Use production resources file
            self.resources_file = os.path.join(self.workspace_root, "automation_resources.json")
        
        self.resources = self._load_or_create_resources()
        print(f"[DEBUG] Resource tracker initialized. Workspace: {self.workspace_root}")
        print(f"[DEBUG] Resources file: {self.resources_file}")
    
    def _is_test_environment(self):
        """Check if we're running in a test environment."""
        # Check if we're in a test directory or if pytest is running
        current_dir = os.getcwd()
        test_indicators = [
            "tests" in current_dir,
            "test_" in os.path.basename(current_dir),
            "pytest" in sys.modules,
            "PYTEST_CURRENT_TEST" in os.environ
        ]
        return any(test_indicators)
    
    def _find_workspace_root(self):
        """Find the workspace root directory (where automatool/ exists)."""
        current_dir = os.getcwd()
        while current_dir != os.path.dirname(current_dir):
            if os.path.exists(os.path.join(current_dir, "automatool")):
                return current_dir
            current_dir = os.path.dirname(current_dir)
        return os.getcwd()  # Fallback to current directory
    
    def _load_or_create_resources(self):
        """Load existing resources or create new structure."""
        if os.path.exists(self.resources_file):
            try:
                with open(self.resources_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, FileNotFoundError) as e:
                print(f"[DEBUG] Could not load existing resources: {e}")
        
        # Create new structure
        return {
            "runs": [],
            "current_run": {
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
        }
    
    def start_new_run(self):
        """Start tracking a new automation run."""
        try:
            print("[DEBUG] Starting new automation run tracking...")
            
            # Archive current run if it has resources
            if self._has_resources(self.resources["current_run"]):
                self.resources["runs"].append(self.resources["current_run"])
                print(f"[DEBUG] Archived previous run with resources")
            
            # Start fresh current run
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
            self._save_resources()
            print("[DEBUG] New run tracking started")
        except Exception as e:
            print(f"❌ ERROR: Failed to start new run: {e}")
            raise
    
    def add_process(self, process_type, pid):
        """Track a launched process."""
        if process_type in ["jadx", "vscode"]:
            try:
                self.resources["current_run"]["pid"][process_type] = pid
                self._save_resources()
                print(f"[DEBUG] Added {process_type} process with PID: {pid}")
            except Exception as e:
                print(f"❌ ERROR: Failed to track {process_type} process: {e}")
                raise
    
    def add_file(self, file_path):
        """Track a generated file (absolute path)."""
        try:
            abs_path = os.path.abspath(file_path)
            if abs_path not in self.resources["current_run"]["files"]:
                self.resources["current_run"]["files"].append(abs_path)
                self._save_resources()
                print(f"[DEBUG] Added file: {abs_path}")
        except Exception as e:
            print(f"❌ ERROR: Failed to track file {file_path}: {e}")
            raise
    
    def add_directory(self, dir_path):
        """Track a created directory (absolute path)."""
        try:
            abs_path = os.path.abspath(dir_path)
            if abs_path not in self.resources["current_run"]["dirs"]:
                self.resources["current_run"]["dirs"].append(abs_path)
                self._save_resources()
                print(f"[DEBUG] Added directory: {abs_path}")
        except Exception as e:
            print(f"❌ ERROR: Failed to track directory {dir_path}: {e}")
            raise
    
    def set_package_name(self, package_name):
        """Set the package name for the current run."""
        try:
            self.resources["current_run"]["package_name"] = package_name
            self._save_resources()
            print(f"[DEBUG] Set package name: {package_name}")
        except Exception as e:
            print(f"❌ ERROR: Failed to set package name: {e}")
            raise
    
    def set_apk_filename(self, apk_filename):
        """Set the APK filename for the current run."""
        try:
            self.resources["current_run"]["apk_filename"] = apk_filename
            self._save_resources()
            print(f"[DEBUG] Set APK filename: {apk_filename}")
        except Exception as e:
            print(f"❌ ERROR: Failed to set APK filename: {e}")
            raise
    
    def mark_apk_installed(self):
        """Mark that the APK was installed on the device."""
        try:
            self.resources["current_run"]["apk_installed"] = True
            self._save_resources()
            print(f"[DEBUG] Marked APK as installed")
        except Exception as e:
            print(f"❌ ERROR: Failed to mark APK as installed: {e}")
            raise
    
    def _save_resources(self):
        """Save resources to JSON file."""
        try:
            with open(self.resources_file, 'w') as f:
                json.dump(self.resources, f, indent=2)
        except Exception as e:
            print(f"⚠️  Warning: Could not save resource tracking: {e}")
    
    def _has_resources(self, run_data):
        """Check if a run has any resources to track."""
        try:
            return (run_data.get("pid", {}).get("jadx") is not None or 
                    run_data.get("pid", {}).get("vscode") is not None or
                    run_data.get("files") or 
                    run_data.get("dirs") or
                    run_data.get("package_name") or
                    run_data.get("apk_filename") or
                    run_data.get("apk_installed"))
        except Exception:
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
            raise
    
    def cleanup_archived_runs(self):
        """Clean up all archived runs and return summary."""
        try:
            print("🧹 Cleaning up archived runs...")
            
            cleanup_results = {
                "processes_killed": 0,
                "files_deleted": 0,
                "directories_removed": 0,
                "apks_uninstalled": 0,
                "errors": []
            }
            
            archived_runs = self.resources.get("runs", [])
            if not archived_runs:
                print("📭 No archived runs to clean")
                return cleanup_results
            
            print(f"📚 Found {len(archived_runs)} archived runs to clean")
            
            # Clean each archived run
            for i, run_data in enumerate(archived_runs, 1):
                try:
                    print(f"🧹 Cleaning archived run {i}/{len(archived_runs)}...")
                    run_results = self._cleanup_single_run(run_data)
                    
                    # Accumulate results
                    for key in cleanup_results:
                        if key in run_results:
                            cleanup_results[key] += run_results[key]
                            
                except Exception as e:
                    error_msg = f"Failed to clean archived run {i}: {e}"
                    print(f"❌ {error_msg}")
                    cleanup_results["errors"].append(error_msg)
                    continue
            
            # Clear archived runs after successful cleanup
            self.resources["runs"] = []
            print(f"✅ Archived runs cleanup completed")
            
            return cleanup_results
            
        except Exception as e:
            print(f"❌ ERROR: Failed to cleanup archived runs: {e}")
            raise
    
    def _cleanup_single_run(self, run_data):
        """Clean up resources from a single run and return results."""
        try:
            cleanup_results = {
                "processes_killed": 0,
                "files_deleted": 0,
                "directories_removed": 0,
                "apks_uninstalled": 0,
                "errors": []
            }
            
            # Kill processes
            if run_data.get("pid", {}).get("jadx"):
                if self._kill_process(run_data["pid"]["jadx"], "Jadx"):
                    cleanup_results["processes_killed"] += 1
            
            if run_data.get("pid", {}).get("vscode"):
                if self._kill_process(run_data["pid"]["vscode"], "VS Code"):
                    cleanup_results["processes_killed"] += 1
            
            # Delete files (excluding preserved files)
            for file_path in run_data.get("files", []):
                if self._should_preserve_file(file_path):
                    print(f"🔒 Preserving file: {file_path}")
                    continue
                if self._delete_file(file_path):
                    cleanup_results["files_deleted"] += 1
            
            # Remove directories
            for dir_path in run_data.get("dirs", []):
                if self._remove_directory(dir_path):
                    cleanup_results["directories_removed"] += 1
            
            # Uninstall APK if it was installed
            if run_data.get("apk_installed") and run_data.get("package_name"):
                if self._uninstall_apk(run_data["package_name"]):
                    cleanup_results["apks_uninstalled"] += 1
            
            return cleanup_results
            
        except Exception as e:
            error_msg = f"Failed to cleanup run: {e}"
            print(f"❌ {error_msg}")
            cleanup_results["errors"].append(error_msg)
            return cleanup_results
    
    def _show_cleanup_summary(self, cleanup_results):
        """Display detailed summary of cleanup results."""
        print("\n" + "="*50)
        print("🧹 CLEANUP SUMMARY")
        print("="*50)
        
        print(f"✅ Processes Terminated: {cleanup_results['processes_killed']}")
        print(f"✅ Files Deleted: {cleanup_results['files_deleted']}")
        print(f"✅ Directories Removed: {cleanup_results['directories_removed']}")
        print(f"✅ APKs Uninstalled: {cleanup_results['apks_uninstalled']}")
        
        if cleanup_results['errors']:
            print(f"\n⚠️  Errors Encountered: {len(cleanup_results['errors'])}")
            for error in cleanup_results['errors']:
                print(f"   • {error}")
        
        print("="*50)
    
    def cleanup_run(self, run_data):
        """Clean up resources from a specific run."""
        try:
            print(f"🧹 Cleaning up run from {run_data.get('timestamp', 'unknown time')}...")
            
            cleanup_results = self._cleanup_single_run(run_data)
            self._show_cleanup_summary(cleanup_results)
            
            print(f"✅ Run cleanup completed")
            return cleanup_results
            
        except Exception as e:
            print(f"❌ ERROR: Failed to cleanup run: {e}")
            raise
    
    def get_child_pids(self, parent_pid):
        """Get child PIDs from parent PID using psutil (from web search solution)."""
        if not psutil:
            return []
        try:
            parent = psutil.Process(parent_pid)
            children = parent.children(recursive=True)
            return [child.pid for child in children]
        except psutil.NoSuchProcess:
            return []
    
    def terminate_processes(self, pids):
        """Terminate multiple processes by PID (from web search solution)."""
        if not psutil:
            return False
        terminated_count = 0
        for pid in pids:
            try:
                process = psutil.Process(pid)
                process.terminate()
                terminated_count += 1
                print(f"💀 Terminated child process (PID: {pid})")
            except psutil.NoSuchProcess:
                continue
        return terminated_count > 0

    def _kill_process(self, pid, process_type):
        """Kill a process by PID with enhanced VS Code child process handling."""
        try:
            # For VS Code, use special handling since parent often exits quickly
            if process_type.lower() in ["vs code", "vscode"] and psutil:
                return self._kill_vscode_processes(pid)
            
            # For other processes, use normal termination
            if os.name == 'nt':  # Windows
                os.system(f'taskkill /PID {pid} /F >nul 2>&1')
            else:  # Linux/Mac
                os.kill(pid, 9)  # SIGKILL
            print(f"💀 Killed {process_type} process (PID: {pid})")
            return True # Indicate success
        except (ProcessLookupError, OSError):
            print(f"⚠️  Process {process_type} (PID: {pid}) already terminated")
            return False # Indicate failure
    
    def _kill_vscode_processes(self, original_pid):
        """
        Enhanced VS Code termination that handles the case where parent exits quickly.
        
        Strategy:
        1. Try to find children from the original PID
        2. If no children (parent exited), find VS Code processes by name
        3. Filter to only recent processes (to avoid killing unrelated VS Code)
        4. Terminate the found processes
        """
        if not psutil:
            # Fallback to normal kill if psutil unavailable
            try:
                if os.name == 'nt':
                    os.system(f'taskkill /PID {original_pid} /F >nul 2>&1')
                else:
                    os.kill(original_pid, 9)
                return True
            except:
                return False
        
        terminated_count = 0
        
        # First, try to find children from the original PID
        child_pids = self.get_child_pids(original_pid)
        if child_pids:
            print(f"🔍 Found {len(child_pids)} VS Code child processes from parent")
            if self.terminate_processes(child_pids):
                terminated_count += len(child_pids)
        else:
            print("🔍 No children found from parent PID (parent likely exited)")
            print("🔍 Searching for recent VS Code processes...")
            
            # Find VS Code processes by name, but only recent ones
            vscode_pids = self._find_recent_vscode_processes()
            if vscode_pids:
                print(f"🔍 Found {len(vscode_pids)} recent VS Code processes")
                if self.terminate_processes(vscode_pids):
                    terminated_count += len(vscode_pids)
        
        # Also try to kill the original PID if it still exists
        try:
            if os.name == 'nt':
                os.system(f'taskkill /PID {original_pid} /F >nul 2>&1')
            else:
                os.kill(original_pid, 9)
            print(f"💀 Also killed original VS Code PID: {original_pid}")
        except:
            pass  # Original PID already gone
        
        if terminated_count > 0:
            print(f"✅ Successfully terminated {terminated_count} VS Code processes")
            return True
        else:
            print("❌ No VS Code processes were terminated")
            return False
    
    def _find_recent_vscode_processes(self):
        """Find VS Code processes that were started recently (within last 30 seconds)."""
        if not psutil:
            return []
        
        import time
        current_time = time.time()
        recent_threshold = 30  # seconds
        vscode_pids = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'create_time']):
                try:
                    # Look for VS Code processes
                    if 'code' in proc.info['name'].lower():
                        # Check if process is recent (started within threshold)
                        process_age = current_time - proc.info['create_time']
                        if process_age <= recent_threshold:
                            vscode_pids.append(proc.info['pid'])
                            print(f"🕒 Found recent VS Code process: {proc.info['pid']} ({proc.info['name']}, age: {process_age:.1f}s)")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"⚠️  Error finding VS Code processes: {e}")
        
        return vscode_pids
    
    def _should_preserve_file(self, file_path):
        """Check if a file should be preserved during cleanup."""
        try:
            # Get the filename from the path
            filename = os.path.basename(file_path)
            
            preserved_files = ["yara.json", "reviews.json", "reviews_summary.txt", "yara_summary.txt"]
            return filename in preserved_files
        except Exception as e:
            print(f"⚠️  Error checking file preservation for {file_path}: {e}")
            return False
    
    def _delete_file(self, file_path):
        """Delete a tracked file."""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"🗑️  Deleted file: {file_path}")
                return True # Indicate success
            else:
                print(f"⚠️  File not found: {file_path}")
                return False # Indicate failure
        except Exception as e:
            print(f"❌ Failed to delete file {file_path}: {e}")
            return False # Indicate failure
    
    def _remove_directory(self, dir_path):
        """Remove a tracked directory and contents."""
        try:
            if os.path.exists(dir_path):
                shutil.rmtree(dir_path)
                print(f"🗑️  Removed directory: {dir_path}")
                return True # Indicate success
            else:
                print(f"⚠️  Directory not found: {dir_path}")
                return False # Indicate failure
        except Exception as e:
            print(f"❌ Failed to remove directory {dir_path}: {e}")
            return False # Indicate failure
    
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
            
            # Import ADB controller here to avoid circular imports
            from ..utils.adb_controller import ADBController
            
            # Initialize ADB controller
            adb_controller = ADBController()
            
            # Check ADB availability
            if not adb_controller.check_adb_connection():
                print(f"⚠️  ADB not found - cannot uninstall {package_name}")
                return False
            
            # Get device information
            authorized_devices = adb_controller.get_authorized_devices()
            if not authorized_devices:
                print(f"⚠️  No authorized devices found - cannot uninstall {package_name}")
                return False
            
            # Attempt uninstallation on first authorized device
            target_device = authorized_devices[0]
            print(f"📱 Uninstalling from device: {target_device.device_id}")
            if target_device.product:
                print(f"📱 Device: {target_device.product}")
            
            success = adb_controller.uninstall_apk(package_name, target_device.device_id)
            
            if success:
                print(f"✅ Successfully uninstalled APK: {package_name}")
                return True
            else:
                print(f"⚠️  Failed to uninstall APK: {package_name}")
                return False
                
        except Exception as e:
            print(f"❌ Error during APK uninstall for {package_name}: {e}")
            return False
    
    def get_resource_summary(self):
        """Get a summary of all tracked resources."""
        total_processes = 0
        total_files = 0
        total_dirs = 0
        
        # Count current run
        current = self.resources.get("current_run", {})
        total_processes += sum(1 for pid in current.get("pid", {}).values() if pid)
        total_files += len(current.get("files", []))
        total_dirs += len(current.get("dirs", []))
        
        # Count archived runs
        for run in self.resources.get("runs", []):
            total_processes += sum(1 for pid in run.get("pid", {}).values() if pid)
            total_files += len(run.get("files", []))
            total_dirs += len(run.get("dirs", []))
        
        return {
            "processes": total_processes,
            "files": total_files,
            "directories": total_dirs,
            "total_runs": len(self.resources.get("runs", [])) + 1
        }


class MockResourceTracker(GlobalResourceTracker):
    """Test-specific resource tracker that always uses test resources."""
    
    def __init__(self):
        """Initialize test resource tracker."""
        # Set up workspace root first
        self.workspace_root = self._find_workspace_root()
        
        # Override the resources file to always use test resources
        test_resources_dir = os.path.join(self.workspace_root, "tests", "resources")
        os.makedirs(test_resources_dir, exist_ok=True)
        self.resources_file = os.path.join(test_resources_dir, "automation_resources.json")
        
        # Load or create resources
        self.resources = self._load_or_create_resources()
        print(f"[DEBUG] Test resource tracker initialized. Workspace: {self.workspace_root}")
        print(f"[DEBUG] Test resources file: {self.resources_file}")
    
    def cleanup_test_resources(self):
        """Clean up test resources and reset to initial state."""
        print("[DEBUG] Cleaning up test resources...")
        # Reset to initial state
        self.resources = {
            "runs": [],
            "current_run": {
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
        }
        self._save_resources()
        print("[DEBUG] Test resources cleaned up")
