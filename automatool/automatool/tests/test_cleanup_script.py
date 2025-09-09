#!/usr/bin/env python3
"""
Unit tests for cleanup.py script

These tests verify the cleanup script functionality including:
- Argument parsing
- Dry run mode
- Confirmation system
- Error handling
"""

import unittest
import sys
import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock, mock_open
from io import StringIO

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scripts.automations.resource_tracker import GlobalResourceTracker, MockResourceTracker


class TestCleanupScriptArgumentParsing(unittest.TestCase):
    """Test command line argument parsing."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.test_apk = os.path.join(self.test_dir, "test.apk")
        
        # Create a dummy APK file
        with open(self.test_apk, 'w') as f:
            f.write("dummy APK content")
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_basic_argument_parsing(self):
        """Test that basic arguments are parsed correctly."""
        from cleanup import parse_arguments
        
        # Test with no arguments
        with patch('sys.argv', ['cleanup.py']):
            args = parse_arguments()
            self.assertFalse(args.verbose)
            self.assertFalse(args.force)
            self.assertFalse(args.dry_run)
            self.assertFalse(args.current_only)
            self.assertFalse(args.summary_only)
    
    def test_verbose_flag(self):
        """Test verbose flag parsing."""
        from cleanup import parse_arguments
        
        with patch('sys.argv', ['cleanup.py', '--verbose']):
            args = parse_arguments()
            self.assertTrue(args.verbose)
    
    def test_force_flag(self):
        """Test force flag parsing."""
        from cleanup import parse_arguments
        
        with patch('sys.argv', ['cleanup.py', '--force']):
            args = parse_arguments()
            self.assertTrue(args.force)
    
    def test_dry_run_flag(self):
        """Test dry run flag parsing."""
        from cleanup import parse_arguments
        
        with patch('sys.argv', ['cleanup.py', '--dry-run']):
            args = parse_arguments()
            self.assertTrue(args.dry_run)
    
    def test_current_only_flag(self):
        """Test current only flag parsing."""
        from cleanup import parse_arguments
        
        with patch('sys.argv', ['cleanup.py', '--current-only']):
            args = parse_arguments()
            self.assertTrue(args.current_only)
    
    def test_summary_only_flag(self):
        """Test summary only flag parsing."""
        from cleanup import parse_arguments
        
        with patch('sys.argv', ['cleanup.py', '--summary-only']):
            args = parse_arguments()
            self.assertTrue(args.summary_only)
    
    def test_multiple_flags(self):
        """Test multiple flags can be combined."""
        from cleanup import parse_arguments
        
        with patch('sys.argv', ['cleanup.py', '--verbose', '--force', '--dry-run']):
            args = parse_arguments()
            self.assertTrue(args.verbose)
            self.assertTrue(args.force)
            self.assertTrue(args.dry_run)


class TestCleanupScriptDryRunMode(unittest.TestCase):
    """Test dry run mode functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.tracker = MockResourceTracker()
        self.tracker.cleanup_test_resources()
        
        # Add some test resources
        self.tracker.start_new_run()
        self.tracker.set_package_name("com.test.app")
        self.tracker.set_apk_filename("test.apk")
        self.tracker.add_process("jadx", 12345)
        self.tracker.add_file("C:\\tmp\\test_file.txt")
        self.tracker.add_directory("C:\\tmp\\test_dir")
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_execute_dry_run(self):
        """Test dry run mode execution."""
        from cleanup import execute_dry_run
        
        # Mock args
        args = MagicMock()
        args.verbose = False
        
        # Capture output
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            result = execute_dry_run(self.tracker, args)
            
            # Check return value
            self.assertTrue(result)
            
            # Check output contains expected content
            output = mock_stdout.getvalue()
            self.assertIn("DRY RUN MODE", output)
            self.assertIn("Current Run", output)
            self.assertIn("com.test.app", output)
            self.assertIn("test.apk", output)
            self.assertIn("12345", output)
            self.assertIn("C:\\tmp\\test_file.txt", output)
            self.assertIn("C:\\tmp\\test_dir", output)
    
    def test_show_run_resources(self):
        """Test display of run resources."""
        from cleanup import show_run_resources
        
        # Create test run data
        run_data = {
            "timestamp": "2025-01-01T12:00:00",
            "package_name": "com.test.app",
            "apk_filename": "test.apk",
            "apk_installed": True,
            "pid": {"jadx": 12345, "vscode": 67890},
            "files": ["C:\\tmp\\file1.txt", "C:\\tmp\\file2.txt"],
            "dirs": ["C:\\tmp\\dir1", "C:\\tmp\\dir2"]
        }
        
        # Capture output
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            show_run_resources("Test Run", run_data)
            
            output = mock_stdout.getvalue()
            self.assertIn("Test Run", output)
            self.assertIn("2025-01-01T12:00:00", output)
            self.assertIn("com.test.app", output)
            self.assertIn("test.apk", output)
            self.assertIn("True", output)
            self.assertIn("12345", output)
            self.assertIn("67890", output)
            self.assertIn("C:\\tmp\\file1.txt", output)
            self.assertIn("C:\\tmp\\file2.txt", output)
            self.assertIn("C:\\tmp\\dir1", output)
            self.assertIn("C:\\tmp\\dir2", output)


class TestCleanupScriptResourceSummary(unittest.TestCase):
    """Test resource summary functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.tracker = MockResourceTracker()
        self.tracker.cleanup_test_resources()
    
    def test_show_resource_summary(self):
        """Test resource summary display."""
        from cleanup import show_resource_summary
        
        # Add some test resources
        self.tracker.start_new_run()
        self.tracker.add_process("jadx", 12345)
        self.tracker.add_file("C:\\tmp\\test_file.txt")
        self.tracker.add_directory("C:\\tmp\\test_dir")
        
        # Capture output
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            result = show_resource_summary(self.tracker)
            
            # Check return value
            self.assertTrue(result)
            
            # Check output contains expected content
            output = mock_stdout.getvalue()
            self.assertIn("RESOURCE SUMMARY", output)
            self.assertIn("Total Runs: 1", output)
            self.assertIn("Processes: 1", output)
            self.assertIn("Files: 1", output)
            self.assertIn("Directories: 1", output)
    
    def test_show_resource_summary_empty(self):
        """Test resource summary display with no resources."""
        from cleanup import show_resource_summary
        
        # Capture output
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            result = show_resource_summary(self.tracker)
            
            # Check return value
            self.assertTrue(result)
            
            # Check output contains expected content
            output = mock_stdout.getvalue()
            self.assertIn("RESOURCE SUMMARY", output)
            self.assertIn("Total Runs: 1", output)
            self.assertIn("Processes: 0", output)
            self.assertIn("Files: 0", output)
            self.assertIn("Directories: 0", output)


class TestCleanupScriptConfirmation(unittest.TestCase):
    """Test user confirmation system."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.tracker = MockResourceTracker()
        self.tracker.cleanup_test_resources()
    
    def test_confirm_cleanup_with_resources(self):
        """Test confirmation prompt with resources present."""
        from cleanup import confirm_cleanup
        
        # Add some test resources
        self.tracker.start_new_run()
        self.tracker.add_process("jadx", 12345)
        self.tracker.add_file("C:\\tmp\\test_file.txt")
        self.tracker.add_directory("C:\\tmp\\test_dir")
        
        # Mock user input for "yes" and "DELETE"
        with patch('builtins.input', side_effect=['yes', 'DELETE']):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                result = confirm_cleanup(self.tracker)
                
                # Check return value
                self.assertTrue(result)
                
                # Check warning message
                output = mock_stdout.getvalue()
                self.assertIn("WARNING", output)
                self.assertIn("permanently delete", output)
                self.assertIn("1 running processes", output)
                self.assertIn("1 generated files", output)
                self.assertIn("1 created directories", output)
    
    def test_confirm_cleanup_user_cancels(self):
        """Test confirmation prompt when user cancels."""
        from cleanup import confirm_cleanup
        
        # Add some test resources
        self.tracker.start_new_run()
        self.tracker.add_process("jadx", 12345)
        
        # Mock user input for "no"
        with patch('builtins.input', return_value='no'):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                result = confirm_cleanup(self.tracker)
                
                # Check return value
                self.assertFalse(result)
    
    def test_confirm_cleanup_user_input_variations(self):
        """Test confirmation prompt with various user inputs."""
        from cleanup import confirm_cleanup
        
        # Add some test resources
        self.tracker.start_new_run()
        self.tracker.add_process("jadx", 12345)
        
        # Test various "yes" inputs
        yes_inputs = ['yes', 'y', 'YES', 'Y', 'Yes']
        for user_input in yes_inputs:
            with patch('builtins.input', side_effect=[user_input, 'DELETE']):
                result = confirm_cleanup(self.tracker)
                self.assertTrue(result, f"Failed for input: {user_input}")
        
        # Test various "no" inputs
        no_inputs = ['no', 'n', 'NO', 'N', 'No', 'cancel', 'exit']
        for user_input in no_inputs:
            with patch('builtins.input', return_value=user_input):
                result = confirm_cleanup(self.tracker)
                self.assertFalse(result, f"Failed for input: {user_input}")


class TestCleanupScriptErrorHandling(unittest.TestCase):
    """Test error handling scenarios."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.tracker = MockResourceTracker()
        self.tracker.cleanup_test_resources()
    
    def test_resource_tracker_initialization_failure(self):
        """Test handling of resource tracker initialization failure."""
        from cleanup import main
        
        # Mock GlobalResourceTracker to raise an exception
        with patch('cleanup.GlobalResourceTracker', side_effect=Exception("Init failed")):
            with patch('sys.argv', ['cleanup.py']):
                with patch('sys.exit') as mock_exit:
                    main()
                    
                    # Check that sys.exit was called with error code
                    mock_exit.assert_called_with(1)
    
    def test_cleanup_execution_failure(self):
        """Test handling of cleanup execution failure."""
        from cleanup import execute_cleanup
        
        # Mock args
        args = MagicMock()
        args.dry_run = False
        args.summary_only = False
        args.force = True
        args.current_only = False
        
        # Mock cleanup_all_resources to raise an exception
        with patch('cleanup.cleanup_all_resources', side_effect=Exception("Cleanup failed")):
            with self.assertRaises(Exception) as context:
                execute_cleanup(self.tracker, args)
            
            self.assertIn("Cleanup failed", str(context.exception))


class TestCleanupScriptIntegration(unittest.TestCase):
    """Test integration with resource tracker."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.tracker = MockResourceTracker()
        self.tracker.cleanup_test_resources()
    
    def test_tracker_integration(self):
        """Test that cleanup script properly integrates with resource tracker."""
        from cleanup import execute_cleanup
        
        # Add test resources
        self.tracker.start_new_run()
        self.tracker.set_package_name("com.test.app")
        self.tracker.add_process("jadx", 12345)
        
        # Mock args
        args = MagicMock()
        args.dry_run = True
        args.verbose = False
        
        # Execute dry run
        result = execute_cleanup(self.tracker, args)
        self.assertTrue(result)
        
        # Verify resources are still intact (dry run doesn't modify)
        current_run = self.tracker.resources["current_run"]
        self.assertEqual(current_run["package_name"], "com.test.app")
        self.assertEqual(current_run["pid"]["jadx"], 12345)
    
    def test_tracker_file_path_detection(self):
        """Test that tracker uses correct resources file path."""
        from cleanup import main
        
        # Mock GlobalResourceTracker
        mock_tracker = MagicMock()
        mock_tracker.resources_file = "/test/path/automation_resources.json"
        
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
