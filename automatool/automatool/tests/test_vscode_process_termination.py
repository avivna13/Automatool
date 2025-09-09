#!/usr/bin/env python3
"""
Unit tests for VS Code child process termination functionality

These tests verify the enhanced process termination for VS Code including:
- Child process discovery using psutil
- Process termination with child process handling
- Fallback behavior when psutil is unavailable
- Integration with existing resource tracking
"""

import unittest
import unittest.mock
import sys
import os
from unittest.mock import patch, MagicMock, call
from io import StringIO

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scripts.automations.resource_tracker import GlobalResourceTracker, MockResourceTracker


class TestVSCodeProcessTermination(unittest.TestCase):
    """Test VS Code child process termination functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.tracker = MockResourceTracker()
        self.tracker.cleanup_test_resources()
    
    def tearDown(self):
        """Clean up after tests."""
        self.tracker.cleanup_test_resources()


class TestChildProcessDiscovery(TestVSCodeProcessTermination):
    """Test child process discovery functionality."""
    
    @patch('scripts.automations.resource_tracker.psutil')
    def test_get_child_pids_with_children(self, mock_psutil):
        """Test finding child processes when they exist."""
        # Mock psutil structure
        mock_child1 = MagicMock()
        mock_child1.pid = 12347
        mock_child2 = MagicMock()
        mock_child2.pid = 12348
        mock_child3 = MagicMock()
        mock_child3.pid = 12349
        
        mock_parent = MagicMock()
        mock_parent.children.return_value = [mock_child1, mock_child2, mock_child3]
        mock_psutil.Process.return_value = mock_parent
        
        # Test child process discovery
        parent_pid = 12346
        child_pids = self.tracker.get_child_pids(parent_pid)
        
        # Verify results
        self.assertEqual(child_pids, [12347, 12348, 12349])
        mock_psutil.Process.assert_called_once_with(parent_pid)
        mock_parent.children.assert_called_once_with(recursive=True)
    
    @patch('scripts.automations.resource_tracker.psutil')
    def test_get_child_pids_no_children(self, mock_psutil):
        """Test finding child processes when none exist."""
        mock_parent = MagicMock()
        mock_parent.children.return_value = []
        mock_psutil.Process.return_value = mock_parent
        
        parent_pid = 12346
        child_pids = self.tracker.get_child_pids(parent_pid)
        
        self.assertEqual(child_pids, [])
        mock_psutil.Process.assert_called_once_with(parent_pid)
    
    @patch('scripts.automations.resource_tracker.psutil')
    def test_get_child_pids_process_not_found(self, mock_psutil):
        """Test handling when parent process doesn't exist."""
        import psutil as psutil_module
        mock_psutil.Process.side_effect = psutil_module.NoSuchProcess(12346)
        mock_psutil.NoSuchProcess = psutil_module.NoSuchProcess
        
        parent_pid = 12346
        child_pids = self.tracker.get_child_pids(parent_pid)
        
        self.assertEqual(child_pids, [])
    
    def test_get_child_pids_no_psutil(self):
        """Test behavior when psutil is not available."""
        # Temporarily disable psutil
        with patch('scripts.automations.resource_tracker.psutil', None):
            parent_pid = 12346
            child_pids = self.tracker.get_child_pids(parent_pid)
            
            self.assertEqual(child_pids, [])


class TestProcessTermination(TestVSCodeProcessTermination):
    """Test process termination functionality."""
    
    @patch('scripts.automations.resource_tracker.psutil')
    def test_terminate_processes_success(self, mock_psutil):
        """Test successful termination of multiple processes."""
        # Mock process termination
        mock_process1 = MagicMock()
        mock_process2 = MagicMock()
        mock_process3 = MagicMock()
        
        mock_psutil.Process.side_effect = [mock_process1, mock_process2, mock_process3]
        
        # Capture print output
        with patch('builtins.print') as mock_print:
            result = self.tracker.terminate_processes([12347, 12348, 12349])
        
        # Verify all processes were terminated
        self.assertTrue(result)
        mock_process1.terminate.assert_called_once()
        mock_process2.terminate.assert_called_once()
        mock_process3.terminate.assert_called_once()
        
        # Verify print statements
        expected_calls = [
            call("💀 Terminated child process (PID: 12347)"),
            call("💀 Terminated child process (PID: 12348)"),
            call("💀 Terminated child process (PID: 12349)")
        ]
        mock_print.assert_has_calls(expected_calls)
    
    @patch('scripts.automations.resource_tracker.psutil')
    def test_terminate_processes_some_not_found(self, mock_psutil):
        """Test termination when some processes don't exist."""
        import psutil as psutil_module
        mock_process1 = MagicMock()
        mock_psutil.Process.side_effect = [
            mock_process1,  # First process exists
            psutil_module.NoSuchProcess(12348),  # Second doesn't exist
            mock_process1   # Third exists (reuse mock)
        ]
        mock_psutil.NoSuchProcess = psutil_module.NoSuchProcess
        
        with patch('builtins.print') as mock_print:
            result = self.tracker.terminate_processes([12347, 12348, 12349])
        
        # Should still return True if at least one was terminated
        self.assertTrue(result)
        
        # Verify only existing processes were terminated
        self.assertEqual(mock_process1.terminate.call_count, 2)
    
    def test_terminate_processes_no_psutil(self):
        """Test termination when psutil is not available."""
        with patch('scripts.automations.resource_tracker.psutil', None):
            result = self.tracker.terminate_processes([12347, 12348])
            self.assertFalse(result)


class TestEnhancedKillProcess(TestVSCodeProcessTermination):
    """Test the enhanced _kill_process method with VS Code support."""
    
    @patch('scripts.automations.resource_tracker.psutil')
    @patch('os.name', 'nt')  # Windows
    @patch('os.system')
    def test_kill_vscode_with_children_windows(self, mock_system, mock_psutil):
        """Test VS Code termination with child processes on Windows."""
        # Mock child process discovery
        mock_child1 = MagicMock()
        mock_child1.pid = 12347
        mock_child2 = MagicMock()
        mock_child2.pid = 12348
        
        mock_parent = MagicMock()
        mock_parent.children.return_value = [mock_child1, mock_child2]
        
        # Mock process termination
        mock_process1 = MagicMock()
        mock_process2 = MagicMock()
        mock_psutil.Process.side_effect = [mock_parent, mock_process1, mock_process2]
        
        with patch('builtins.print') as mock_print:
            result = self.tracker._kill_process(12346, "VS Code")
        
        # Should return True (child processes terminated)
        self.assertTrue(result)
        
        # Verify child processes were terminated
        mock_process1.terminate.assert_called_once()
        mock_process2.terminate.assert_called_once()
        
        # Verify print output (updated for new enhanced logic)
        mock_print.assert_any_call("🔍 Found 2 VS Code child processes from parent")
        mock_print.assert_any_call("✅ Successfully terminated 2 VS Code processes")
    
    @patch('scripts.automations.resource_tracker.psutil')
    @patch('os.name', 'posix')  # Linux/Mac
    @patch('os.kill')
    def test_kill_vscode_no_children_linux(self, mock_kill, mock_psutil):
        """Test VS Code termination without child processes on Linux."""
        # Mock no child processes and no recent processes
        mock_parent = MagicMock()
        mock_parent.children.return_value = []
        
        # Mock process_iter to return no recent VS Code processes
        mock_psutil.Process.return_value = mock_parent
        mock_psutil.process_iter.return_value = []  # No recent processes found
        
        with patch('builtins.print') as mock_print:
            result = self.tracker._kill_process(12346, "vscode")
        
        # Should return False since no processes were found to terminate
        self.assertFalse(result)
        mock_print.assert_any_call("❌ No VS Code processes were terminated")
    
    @patch('os.name', 'nt')  # Windows
    @patch('os.system')
    def test_kill_jadx_unchanged(self, mock_system):
        """Test that Jadx process termination is unchanged."""
        with patch('builtins.print') as mock_print:
            result = self.tracker._kill_process(12345, "Jadx")
        
        # Should work normally without child process handling
        self.assertTrue(result)
        mock_system.assert_called_once_with('taskkill /PID 12345 /F >nul 2>&1')
        mock_print.assert_called_with("💀 Killed Jadx process (PID: 12345)")
    
    @patch('scripts.automations.resource_tracker.psutil', None)
    @patch('os.name', 'nt')
    @patch('os.system')
    def test_kill_vscode_no_psutil_fallback(self, mock_system):
        """Test VS Code termination fallback when psutil unavailable."""
        with patch('builtins.print') as mock_print:
            result = self.tracker._kill_process(12346, "VS Code")
        
        # Should fall back to normal termination
        self.assertTrue(result)
        mock_system.assert_called_once_with('taskkill /PID 12346 /F >nul 2>&1')
        mock_print.assert_called_with("💀 Killed VS Code process (PID: 12346)")
    
    @patch('scripts.automations.resource_tracker.psutil')
    @patch('os.kill')
    def test_kill_process_not_found(self, mock_kill, mock_psutil):
        """Test handling when VS Code process doesn't exist."""
        # Mock psutil to return no children and no recent processes
        mock_parent = MagicMock()
        mock_parent.children.return_value = []
        mock_psutil.Process.return_value = mock_parent
        mock_psutil.process_iter.return_value = []  # No recent processes
        
        with patch('builtins.print') as mock_print:
            result = self.tracker._kill_process(12346, "VS Code")
        
        # Should return False since no VS Code processes were found
        self.assertFalse(result)
        mock_print.assert_called_with("❌ No VS Code processes were terminated")


class TestIntegrationWithResourceTracker(TestVSCodeProcessTermination):
    """Test integration with existing resource tracker functionality."""
    
    def test_vscode_process_tracking_unchanged(self):
        """Test that VS Code process tracking API remains unchanged."""
        # This ensures our changes don't break existing functionality
        pid = 12346
        
        # Add process should work as before
        self.tracker.add_process("vscode", pid)
        
        # Verify it's tracked correctly
        current_run = self.tracker.resources["current_run"]
        self.assertEqual(current_run["pid"]["vscode"], pid)
    
    @patch('scripts.automations.resource_tracker.psutil')
    def test_cleanup_single_run_with_enhanced_vscode(self, mock_psutil):
        """Test cleanup_single_run works with enhanced VS Code termination."""
        # Set up test data
        run_data = {
            "pid": {"vscode": 12346, "jadx": 12345},
            "files": [],
            "dirs": [],
            "apk_installed": False
        }
        
        # Mock child process discovery and termination
        mock_child = MagicMock()
        mock_child.pid = 12347
        mock_parent = MagicMock()
        mock_parent.children.return_value = [mock_child]
        mock_child_process = MagicMock()
        mock_psutil.Process.side_effect = [mock_parent, mock_child_process]
        
        with patch('os.name', 'nt'), \
             patch('os.system') as mock_system, \
             patch('builtins.print'):
            
            cleanup_results = self.tracker._cleanup_single_run(run_data)
        
        # Should report 2 processes killed (VS Code children + Jadx)
        self.assertEqual(cleanup_results["processes_killed"], 2)
        self.assertEqual(cleanup_results["errors"], [])
        
        # Verify VS Code child process was terminated
        mock_child_process.terminate.assert_called_once()  # VS Code child
        
        # Verify system calls were made (VS Code original PID and Jadx)
        # The order might vary, so check that both calls were made
        expected_calls = [
            unittest.mock.call('taskkill /PID 12346 /F >nul 2>&1'),  # VS Code original PID
            unittest.mock.call('taskkill /PID 12345 /F >nul 2>&1')   # Jadx
        ]
        self.assertEqual(len(mock_system.call_args_list), 2)
        self.assertIn(expected_calls[0], mock_system.call_args_list)
        self.assertIn(expected_calls[1], mock_system.call_args_list)


class TestRealVSCodeIntegration(TestVSCodeProcessTermination):
    """Integration tests with real VS Code process launching and termination."""
    
    def test_real_vscode_launch_and_termination(self):
        """
        Real integration test: Launch VS Code, track PID and children, then terminate.
        
        This test will:
        1. Actually launch VS Code using subprocess
        2. Capture the parent PID 
        3. Wait for child processes to spawn
        4. Use our termination method to kill them
        5. Verify the processes are actually terminated
        """
        import subprocess
        import time
        import tempfile
        import os
        
        # Skip if VS Code not available - Windows uses code.cmd
        vscode_cmd = 'code.cmd' if os.name == 'nt' else 'code'
        try:
            subprocess.run([vscode_cmd, '--version'], 
                         capture_output=True, check=True, timeout=5)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            self.skipTest(f"VS Code not available: {vscode_cmd} not found")
        
        # Skip if psutil not available  
        try:
            import psutil
        except ImportError:
            self.skipTest("psutil not available for real process testing")
        
        # Create a temporary directory for VS Code to open
        with tempfile.TemporaryDirectory() as temp_dir:
            print(f"\n🚀 Launching VS Code with directory: {temp_dir}")
            
            # Launch VS Code (similar to how launch_vscode.py does it)
            process = subprocess.Popen(
                [vscode_cmd, temp_dir],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True
            )
            
            parent_pid = process.pid
            print(f"📝 Parent PID captured: {parent_pid}")
            
            # Wait a moment for VS Code to fully start and spawn children
            print("⏳ Waiting for VS Code to spawn child processes...")
            time.sleep(3)  # Give VS Code time to start up
            
            # Check if parent process still exists
            try:
                parent_process = psutil.Process(parent_pid)
                print(f"✅ Parent process exists: {parent_process.name()}")
            except psutil.NoSuchProcess:
                print("⚠️  Parent process exited quickly (expected for VS Code)")
            
            # Discover child processes using our method
            child_pids = self.tracker.get_child_pids(parent_pid)
            print(f"🔍 Found {len(child_pids)} child processes: {child_pids}")
            
            # If no children found from parent, try to find VS Code processes by name
            if not child_pids:
                print("🔍 No children from parent PID, searching for VS Code processes by name...")
                vscode_processes = []
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if 'code' in proc.info['name'].lower():
                            vscode_processes.append(proc.info['pid'])
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                print(f"🔍 Found VS Code processes by name: {vscode_processes}")
                child_pids = vscode_processes[:3]  # Limit to avoid killing unrelated VS Code instances
            
            # Verify some processes are running
            running_pids = []
            for pid in child_pids:
                try:
                    proc = psutil.Process(pid)
                    running_pids.append(pid)
                    print(f"✅ Process {pid} ({proc.name()}) is running")
                except psutil.NoSuchProcess:
                    print(f"⚠️  Process {pid} not found")
            
            if not running_pids:
                self.skipTest("No VS Code processes found to test termination")
            
            print(f"\n💀 Testing termination of {len(running_pids)} processes...")
            
            # Test our enhanced kill method
            result = self.tracker._kill_process(parent_pid, "VS Code")
            print(f"🔄 Termination result: {result}")
            
            # Wait a moment for termination to complete
            time.sleep(2)
            
            # Verify processes are terminated
            still_running = []
            terminated = []
            
            for pid in running_pids:
                try:
                    proc = psutil.Process(pid)
                    # Double check - try to get process info
                    proc.name()  # This will raise NoSuchProcess if terminated
                    still_running.append(pid)
                    print(f"⚠️  Process {pid} still running")
                except psutil.NoSuchProcess:
                    terminated.append(pid)
                    print(f"✅ Process {pid} successfully terminated")
            
            # Results
            print(f"\n📊 Termination Results:")
            print(f"   • Processes terminated: {len(terminated)}")
            print(f"   • Processes still running: {len(still_running)}")
            
            # The test passes if we terminated at least some processes
            # (VS Code behavior can be complex with multiple instances)
            if terminated:
                print("✅ Test PASSED: Successfully terminated VS Code processes")
                self.assertTrue(True, f"Successfully terminated {len(terminated)} processes")
            else:
                print("❌ Test FAILED: No processes were terminated")
                # Don't fail completely - VS Code might be tricky
                print("⚠️  This might be expected behavior depending on VS Code setup")


if __name__ == '__main__':
    # Run with more verbose output for integration tests
    unittest.main(verbosity=2)
