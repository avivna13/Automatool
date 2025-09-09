# test_process_manager.py - Tests for ProcessManager class
import pytest
import os
import time
import tempfile
from unittest.mock import patch, MagicMock

from utils.process_manager import ProcessManager


class TestProcessManager:
    """Test cases for ProcessManager class."""

    def test_init(self):
        """Test ProcessManager initialization."""
        manager = ProcessManager()
        assert manager.current_process is None
        assert manager.process_status == "ready"
        assert manager.process_log == []
        assert manager.automatool_path == "../automatool/automatool/src"

    def test_add_log(self):
        """Test log addition functionality."""
        manager = ProcessManager()
        
        # Add a log entry
        manager.add_log("Test message")
        
        assert len(manager.process_log) == 1
        assert "Test message" in manager.process_log[0]
        assert ":" in manager.process_log[0]  # Timestamp format

    def test_add_log_limit(self):
        """Test log entry limit (max 100 entries)."""
        manager = ProcessManager()
        
        # Add 150 log entries
        for i in range(150):
            manager.add_log(f"Message {i}")
        
        # Should only keep last 100
        assert len(manager.process_log) == 100
        assert "Message 149" in manager.process_log[-1]
        assert "Message 50" in manager.process_log[0]

    def test_get_status_initial(self):
        """Test get_status with initial state."""
        manager = ProcessManager()
        
        status = manager.get_status()
        
        assert status['status'] == 'ready'
        assert status['current_process'] is None
        assert status['log'] == []
        assert status['full_log'] == []

    def test_get_status_with_logs(self):
        """Test get_status with log entries."""
        manager = ProcessManager()
        
        # Add some log entries
        manager.add_log("Entry 1")
        manager.add_log("Entry 2")
        manager.add_log("Entry 3")
        
        status = manager.get_status()
        
        assert len(status['log']) == 3
        assert len(status['full_log']) == 3
        assert "Entry 3" in status['log'][-1]

    def test_is_running_initial(self):
        """Test is_running with initial state."""
        manager = ProcessManager()
        assert manager.is_running() is False

    def test_is_running_when_running(self):
        """Test is_running when process is running."""
        manager = ProcessManager()
        manager.process_status = "running"
        assert manager.is_running() is True

    def test_clear_log(self):
        """Test log clearing functionality."""
        manager = ProcessManager()
        
        # Add some logs
        manager.add_log("Test 1")
        manager.add_log("Test 2")
        
        # Clear logs
        manager.clear_log()
        
        # Should have only the "Log cleared" message
        assert len(manager.process_log) == 1
        assert "Log cleared" in manager.process_log[0]

    def test_get_log_summary_empty(self):
        """Test log summary with no logs."""
        manager = ProcessManager()
        summary = manager.get_log_summary()
        assert summary == "No log entries"

    def test_get_log_summary_few_entries(self):
        """Test log summary with few entries."""
        manager = ProcessManager()
        
        manager.add_log("Entry 1")
        manager.add_log("Entry 2")
        
        summary = manager.get_log_summary()
        assert "Entry 1" in summary
        assert "Entry 2" in summary

    def test_get_log_summary_many_entries(self):
        """Test log summary with many entries (should show last 5)."""
        manager = ProcessManager()
        
        # Add 10 entries
        for i in range(10):
            manager.add_log(f"Entry {i}")
        
        summary = manager.get_log_summary()
        
        # Should show last 5 entries
        assert "Entry 9" in summary
        assert "Entry 5" in summary
        assert "Entry 4" not in summary  # Should not include earlier entries

    @patch('subprocess.Popen')
    def test_run_process_success(self, mock_popen):
        """Test successful process execution."""
        manager = ProcessManager()
        
        # Mock successful process
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.stdout.readline.side_effect = [
            "Output line 1\n",
            "Output line 2\n",
            ""  # End of output
        ]
        mock_process.poll.side_effect = [None, None, 0]  # Still running, then completed
        mock_popen.return_value = mock_process
        
        # Test command execution
        result = manager._run_process(['echo', 'test'], "Test Process")
        
        assert result is True
        # Give a moment for the thread to start
        time.sleep(0.1)
        assert manager.process_status == "running" or manager.process_status == "completed"

    @patch('subprocess.Popen')
    def test_run_process_already_running(self, mock_popen):
        """Test process execution when another is already running."""
        manager = ProcessManager()
        manager.process_status = "running"
        
        result = manager._run_process(['echo', 'test'], "Test Process")
        
        assert result is False
        # Should not have called Popen
        mock_popen.assert_not_called()

    @patch('subprocess.Popen')
    def test_run_process_command_not_found(self, mock_popen):
        """Test process execution with command not found."""
        manager = ProcessManager()
        
        # Mock FileNotFoundError
        mock_popen.side_effect = FileNotFoundError("Command not found")
        
        result = manager._run_process(['nonexistent_command'], "Test Process")
        
        assert result is True  # Function returns True, but sets error status
        time.sleep(0.1)  # Give thread time to complete
        assert any("Command not found" in log for log in manager.process_log)

    def test_execute_automatool_prerequisites(self):
        """Test automatool execution method."""
        manager = ProcessManager()
        
        with patch.object(manager, '_run_process') as mock_run:
            mock_run.return_value = True
            
            result = manager.execute_automatool("/test/dir", "test.apk", verbose=True)
            
            assert result is True
            mock_run.assert_called_once()
            
            # Check command construction
            call_args = mock_run.call_args[0]
            cmd = call_args[0]
            process_name = call_args[1]
            
            assert 'python' in cmd
            assert 'automatool.py' in cmd
            assert '-d' in cmd
            assert '/test/dir' in cmd
            assert '-f' in cmd
            assert 'test.apk' in cmd
            assert '--verbose' in cmd
            assert process_name == "Full Process"

    def test_execute_reviews_parsing(self):
        """Test reviews parsing execution method."""
        manager = ProcessManager()
        
        with patch.object(manager, '_run_process') as mock_run:
            mock_run.return_value = True
            
            result = manager.execute_reviews_parsing("/test/dir", verbose=True)
            
            assert result is True
            mock_run.assert_called_once()

    def test_execute_cleanup(self):
        """Test cleanup execution method."""
        manager = ProcessManager()
        
        with patch.object(manager, '_run_process') as mock_run:
            mock_run.return_value = True
            
            result = manager.execute_cleanup(verbose=True)
            
            assert result is True
            mock_run.assert_called_once()
            
            # Check command construction
            call_args = mock_run.call_args[0]
            cmd = call_args[0]
            
            assert 'python' in cmd
            assert 'cleanup.py' in cmd
            assert '--force' in cmd
            assert '--verbose' in cmd

    def test_execute_mobsf_upload(self):
        """Test MobSF upload execution method."""
        manager = ProcessManager()
        
        with patch.object(manager, '_run_process') as mock_run:
            mock_run.return_value = True
            
            result = manager.execute_mobsf_upload("/path/to/app.apk", "/test/dir", verbose=True)
            
            assert result is True
            mock_run.assert_called_once()
            
            # Check command construction
            call_args = mock_run.call_args[0]
            cmd = call_args[0]
            
            assert 'python' in cmd
            assert '_mobsf_analysis_worker.py' in cmd
            assert '--apk-path' in cmd
            assert '/path/to/app.apk' in cmd
            assert '--output-dir' in cmd
            assert '/test/dir' in cmd
            assert '--verbose' in cmd

    def test_kill_current_process_no_process(self):
        """Test killing process when none is running."""
        manager = ProcessManager()
        
        result = manager.kill_current_process()
        assert result is False

    @patch('time.sleep')  # Speed up the test
    def test_kill_current_process_success(self, mock_sleep):
        """Test successful process termination."""
        manager = ProcessManager()
        
        # Mock current process
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Process is running
        mock_process.terminate = MagicMock()
        mock_process.kill = MagicMock()
        
        manager.current_process = {
            'name': 'Test Process',
            'process': mock_process
        }
        manager.process_status = "running"
        
        result = manager.kill_current_process()
        
        assert result is True
        mock_process.terminate.assert_called_once()
        assert manager.process_status == "cancelled"
        assert manager.current_process is None
