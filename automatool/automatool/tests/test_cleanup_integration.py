#!/usr/bin/env python3
"""
Integration tests for cleanup.py script

These tests verify the end-to-end cleanup workflow including:
- Full cleanup workflow
- Resource tracker integration
- File system operations
- Process management
"""

import unittest
import sys
import os
import tempfile
import shutil
import json
from unittest.mock import patch, MagicMock, mock_open
from io import StringIO

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scripts.automations.resource_tracker import GlobalResourceTracker, MockResourceTracker


class TestCleanupScriptEndToEnd(unittest.TestCase):
    """Test end-to-end cleanup workflow."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.tracker = MockResourceTracker()
        self.tracker.cleanup_test_resources()
        
        # Create test files and directories
        self.test_file1 = os.path.join(self.test_dir, "test_file1.txt")
        self.test_file2 = os.path.join(self.test_dir, "test_file2.txt")
        self.test_dir1 = os.path.join(self.test_dir, "test_dir1")
        self.test_dir2 = os.path.join(self.test_dir, "test_dir2")
        
        with open(self.test_file1, 'w') as f:
            f.write("test content 1")
        with open(self.test_file2, 'w') as f:
            f.write("test content 2")
        
        os.makedirs(self.test_dir1, exist_ok=True)
        os.makedirs(self.test_dir2, exist_ok=True)
        
        # Add test resources to tracker
        self.tracker.start_new_run()
        self.tracker.set_package_name("com.test.app")
        self.tracker.set_apk_filename("test.apk")
        self.tracker.add_process("jadx", 12345)
        self.tracker.add_process("vscode", 67890)
        self.tracker.add_file(self.test_file1)
        self.tracker.add_file(self.test_file2)
        self.tracker.add_directory(self.test_dir1)
        self.tracker.add_directory(self.test_dir2)
        self.tracker.mark_apk_installed()
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_full_cleanup_workflow(self):
        """Test complete cleanup workflow from start to finish."""
        from cleanup import execute_cleanup
        
        # Mock args for full cleanup
        args = MagicMock()
        args.verbose = True
        args.force = True
        args.dry_run = False
        args.summary_only = False
        args.current_only = False
        
        # Mock the cleanup functions to avoid actual deletion
        with patch('cleanup.cleanup_all_resources', return_value=True):
            result = execute_cleanup(self.tracker, args)
            self.assertTrue(result)
    
    def test_current_only_cleanup_workflow(self):
        """Test current-only cleanup workflow."""
        from cleanup import execute_cleanup
        
        # Mock args for current-only cleanup
        args = MagicMock()
        args.verbose = True
        args.force = True
        args.dry_run = False
        args.summary_only = False
        args.current_only = True
        
        # Mock the cleanup functions to avoid actual deletion
        with patch('cleanup.cleanup_current_run', return_value=True):
            result = execute_cleanup(self.tracker, args)
            self.assertTrue(result)
    
    def test_dry_run_workflow(self):
        """Test dry run workflow without actual cleanup."""
        from cleanup import execute_cleanup
        
        # Mock args for dry run
        args = MagicMock()
        args.verbose = True
        args.force = False
        args.dry_run = True
        args.summary_only = False
        args.current_only = False
        
        # Capture output
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            result = execute_cleanup(self.tracker, args)
            
            # Check return value
            self.assertTrue(result)
            
            # Check output contains expected content
            output = mock_stdout.getvalue()
            self.assertIn("DRY RUN MODE", output)
            self.assertIn("Current Run", output)
            self.assertIn("com.test.app", output)
            self.assertIn("test.apk", output)
            self.assertIn("12345", output)
            self.assertIn("67890", output)
            self.assertIn(self.test_file1, output)
            self.assertIn(self.test_file2, output)
            self.assertIn(self.test_dir1, output)
            self.assertIn(self.test_dir2, output)
    
    def test_summary_only_workflow(self):
        """Test summary-only workflow without cleanup."""
        from cleanup import execute_cleanup
        
        # Mock args for summary only
        args = MagicMock()
        args.verbose = True
        args.force = False
        args.dry_run = False
        args.summary_only = True
        args.current_only = False
        
        # Capture output
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            result = execute_cleanup(self.tracker, args)
            
            # Check return value
            self.assertTrue(result)
            
            # Check output contains expected content
            output = mock_stdout.getvalue()
            self.assertIn("RESOURCE SUMMARY", output)
            self.assertIn("Total Runs: 1", output)
            self.assertIn("Processes: 2", output)
            self.assertIn("Files: 2", output)
            self.assertIn("Directories: 2", output)


class TestCleanupScriptResourceTrackerIntegration(unittest.TestCase):
    """Test integration with resource tracker."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.tracker = MockResourceTracker()
        self.tracker.cleanup_test_resources()
    
    def test_tracker_initialization(self):
        """Test that resource tracker is properly initialized."""
        from cleanup import main
        
        # Mock GlobalResourceTracker
        mock_tracker = MagicMock()
        mock_tracker.resources_file = "/test/path/automation_resources.json"
        mock_tracker.get_resource_summary.return_value = {
            "total_runs": 1,
            "processes": 0,
            "files": 0,
            "directories": 0
        }
        
        # Mock the execute_cleanup function to actually call get_resource_summary
        with patch('cleanup.execute_cleanup') as mock_execute_cleanup:
            def side_effect(tracker, args):
                # Simulate what execute_cleanup would do
                if args.summary_only:
                    tracker.get_resource_summary()
                return True
            
            mock_execute_cleanup.side_effect = side_effect
            
            with patch('cleanup.GlobalResourceTracker', return_value=mock_tracker):
                with patch('sys.argv', ['cleanup.py', '--summary-only']):
                    with patch('sys.exit') as mock_exit:
                        main()
                        
                        # Check that get_resource_summary was called
                        mock_tracker.get_resource_summary.assert_called()
    
    def test_tracker_resource_access(self):
        """Test that cleanup script can access tracker resources."""
        from cleanup import execute_dry_run
        
        # Add test resources
        self.tracker.start_new_run()
        self.tracker.set_package_name("com.test.app")
        self.tracker.add_process("jadx", 12345)
        self.tracker.add_file("C:\\tmp\\test_file.txt")
        
        # Mock args
        args = MagicMock()
        args.verbose = False
        
        # Execute dry run
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            result = execute_dry_run(self.tracker, args)
            
            # Check return value
            self.assertTrue(result)
            
            # Check that resources were accessed
            output = mock_stdout.getvalue()
            self.assertIn("com.test.app", output)
            self.assertIn("12345", output)
            self.assertIn("C:\\tmp\\test_file.txt", output)
    
    def test_tracker_error_handling(self):
        """Test that tracker errors are properly handled."""
        from cleanup import main
        
        # Mock GlobalResourceTracker to raise an exception
        with patch('cleanup.GlobalResourceTracker', side_effect=Exception("Tracker failed")):
            with patch('sys.argv', ['cleanup.py']):
                with patch('sys.exit') as mock_exit:
                    main()
                    
                    # Check that sys.exit was called with error code
                    mock_exit.assert_called_with(1)


class TestCleanupScriptFileSystemOperations(unittest.TestCase):
    """Test file system operations during cleanup."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.tracker = MockResourceTracker()
        self.tracker.cleanup_test_resources()
        
        # Create test files and directories
        self.test_file = os.path.join(self.test_dir, "test_file.txt")
        self.test_subdir = os.path.join(self.test_dir, "test_subdir")
        self.test_subfile = os.path.join(self.test_subdir, "subfile.txt")
        
        with open(self.test_file, 'w') as f:
            f.write("test content")
        
        os.makedirs(self.test_subdir, exist_ok=True)
        with open(self.test_subfile, 'w') as f:
            f.write("subfile content")
        
        # Add to tracker
        self.tracker.start_new_run()
        self.tracker.add_file(self.test_file)
        self.tracker.add_directory(self.test_subdir)
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_file_existence_validation(self):
        """Test that file existence is properly validated."""
        from cleanup import show_run_resources
        
        # Get current run data
        current_run = self.tracker.resources["current_run"]
        
        # Capture output
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            show_run_resources("Test Run", current_run)
            
            output = mock_stdout.getvalue()
            self.assertIn(self.test_file, output)
            self.assertIn(self.test_subdir, output)
    
    def test_directory_structure_handling(self):
        """Test that directory structures are properly handled."""
        from cleanup import execute_dry_run
        
        # Mock args
        args = MagicMock()
        args.verbose = False
        
        # Execute dry run
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            result = execute_dry_run(self.tracker, args)
            
            # Check return value
            self.assertTrue(result)
            
            # Check that directory structure was displayed
            output = mock_stdout.getvalue()
            self.assertIn(self.test_subdir, output)
            self.assertIn(self.test_file, output)


class TestCleanupScriptProcessManagement(unittest.TestCase):
    """Test process management during cleanup."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.tracker = MockResourceTracker()
        self.tracker.cleanup_test_resources()
    
    def test_process_tracking_display(self):
        """Test that process tracking information is properly displayed."""
        from cleanup import show_run_resources
        
        # Add test processes
        self.tracker.start_new_run()
        self.tracker.add_process("jadx", 12345)
        self.tracker.add_process("vscode", 67890)
        
        # Get current run data
        current_run = self.tracker.resources["current_run"]
        
        # Capture output
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            show_run_resources("Test Run", current_run)
            
            output = mock_stdout.getvalue()
            self.assertIn("12345", output)
            self.assertIn("67890", output)
            self.assertIn("Jadx PID", output)
            self.assertIn("VS Code PID", output)
    
    def test_process_cleanup_preparation(self):
        """Test that process cleanup information is properly prepared."""
        from cleanup import confirm_cleanup
        
        # Add test processes
        self.tracker.start_new_run()
        self.tracker.add_process("jadx", 12345)
        self.tracker.add_process("vscode", 67890)
        
        # Mock user input for "yes" and "DELETE"
        with patch('builtins.input', side_effect=['yes', 'DELETE']):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                result = confirm_cleanup(self.tracker)
                
                # Check return value
                self.assertTrue(result)
                
                # Check that process count is displayed
                output = mock_stdout.getvalue()
                self.assertIn("2 running processes", output)


class TestCleanupScriptErrorScenarios(unittest.TestCase):
    """Test various error scenarios."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.tracker = MockResourceTracker()
        self.tracker.cleanup_test_resources()
    
    def test_missing_resource_files(self):
        """Test handling of missing resource files."""
        from cleanup import show_run_resources
        
        # Create run data with missing files
        run_data = {
            "timestamp": "2025-01-01T12:00:00",
            "package_name": "com.test.app",
            "apk_filename": "test.apk",
            "apk_installed": False,
            "pid": {"jadx": None, "vscode": None},
            "files": ["C:\\tmp\\nonexistent_file.txt"],
            "dirs": ["C:\\tmp\\nonexistent_dir"]
        }
        
        # Should not crash
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            show_run_resources("Test Run", run_data)
            
            output = mock_stdout.getvalue()
            self.assertIn("C:\\tmp\\nonexistent_file.txt", output)
            self.assertIn("C:\\tmp\\nonexistent_dir", output)
    
    def test_empty_resource_data(self):
        """Test handling of empty resource data."""
        from cleanup import show_run_resources
        
        # Create empty run data
        run_data = {
            "timestamp": "2025-01-01T12:00:00",
            "package_name": None,
            "apk_filename": None,
            "apk_installed": False,
            "pid": {"jadx": None, "vscode": None},
            "files": [],
            "dirs": []
        }
        
        # Should not crash
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            show_run_resources("Empty Run", run_data)
            
            output = mock_stdout.getvalue()
            self.assertIn("Empty Run", output)
            self.assertIn("None", output)
            self.assertIn("False", output)
    
    def test_malformed_resource_data(self):
        """Test handling of malformed resource data."""
        from cleanup import show_run_resources
        
        # Create malformed run data
        run_data = {
            "timestamp": "2025-01-01T12:00:00",
            # Missing required fields
        }
        
        # Should not crash
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            show_run_resources("Malformed Run", run_data)
            
            output = mock_stdout.getvalue()
            self.assertIn("Malformed Run", output)
            self.assertIn("2025-01-01T12:00:00", output)  # Actual timestamp is present


if __name__ == '__main__':
    unittest.main(verbosity=2)
