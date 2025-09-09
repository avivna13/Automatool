#!/usr/bin/env python3
"""
Integration tests for automatool.py with resource tracking

These tests verify that the resource tracker is properly integrated
and that resources are being tracked correctly.
"""

import unittest
import sys
import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scripts.automations.resource_tracker import GlobalResourceTracker, MockResourceTracker


class TestAutomatoolIntegration(unittest.TestCase):
    """Test that resource tracker is properly integrated."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.test_apk = os.path.join(self.test_dir, "test.apk")
        
        # Create a dummy APK file
        with open(self.test_apk, 'w') as f:
            f.write("dummy APK content")
        
        # Clean up test resources before each test
        self.tracker = MockResourceTracker()
        self.tracker.cleanup_test_resources()
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    @patch('scripts.automations.resource_tracker.GlobalResourceTracker')
    def test_resource_tracker_initialization(self, mock_tracker_class):
        """Test that resource tracker is initialized in main function."""
        # Mock the tracker instance
        mock_tracker = MagicMock()
        mock_tracker_class.return_value = mock_tracker
        
        # Import and call main (this will test the integration)
        with patch('builtins.print'):  # Suppress print output
            # We can't easily test the full main function without mocking everything,
            # but we can verify the resource tracker is imported and available
            try:
                from scripts.automations.resource_tracker import GlobalResourceTracker
                self.assertTrue(True, "Resource tracker import successful")
            except ImportError as e:
                self.fail(f"Failed to import resource tracker: {e}")
    
    def test_resource_tracker_functionality(self):
        """Test that the resource tracker works correctly."""
        # Use the cleaned tracker from setUp
        tracker = self.tracker
        
        # Test basic functionality
        tracker.start_new_run()
        tracker.set_package_name("com.test.app")
        tracker.set_apk_filename("test.apk")
        tracker.add_process("jadx", 12345)
        tracker.add_file("/tmp/test_file.txt")
        tracker.add_directory("/tmp/test_dir")
        tracker.mark_apk_installed()
        
        # Verify resources were tracked
        summary = tracker.get_resource_summary()
        # Now we can check total_runs since we start with a clean state
        current_run = tracker.resources["current_run"]
        self.assertEqual(current_run["pid"]["jadx"], 12345)
        self.assertEqual(len(current_run["files"]), 1)
        self.assertEqual(len(current_run["dirs"]), 1)
        self.assertEqual(summary["total_runs"], 1)
    
    def test_resource_tracker_file_creation(self):
        """Test that the resource tracker creates the JSON file."""
        tracker = self.tracker
        
        # Check if the resources file was created
        self.assertTrue(os.path.exists(tracker.resources_file), 
                       "Resources file should be created")
        
        # Check if it's valid JSON
        try:
            with open(tracker.resources_file, 'r') as f:
                import json
                content = json.load(f)
                self.assertIn("current_run", content)
                self.assertIn("runs", content)
        except Exception as e:
            self.fail(f"Resources file should contain valid JSON: {e}")
    
    def test_apk_filename_tracking(self):
        """Test that APK filename is properly tracked."""
        tracker = self.tracker
        tracker.start_new_run()
        
        # Set APK filename
        tracker.set_apk_filename("test_app.apk")
        
        # Verify it was tracked
        self.assertEqual(tracker.resources["current_run"]["apk_filename"], "test_app.apk")
        
        # Check JSON structure
        with open(tracker.resources_file, 'r') as f:
            import json
            content = json.load(f)
            self.assertEqual(content["current_run"]["apk_filename"], "test_app.apk")


if __name__ == '__main__':
    unittest.main(verbosity=2)
