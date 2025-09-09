#!/usr/bin/env python3
"""
Tests for launch functions (launch_jadx and launch_vscode)

These tests verify that the launch functions:
1. Return process objects on success
2. Return False on failure
3. Maintain backward compatibility
4. Handle errors gracefully
"""

import unittest
import subprocess
import sys
import os
from unittest.mock import patch, MagicMock

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scripts.automations.launch_jadx import launch_jadx_gui
from scripts.automations.launch_vscode import launch_vscode


class TestLaunchJadx(unittest.TestCase):
    """Test cases for launch_jadx_gui function."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_apk_path = "/tmp/test.apk"
        self.verbose = True
    
    @patch('subprocess.Popen')
    def test_successful_launch_returns_process(self, mock_popen):
        """Test that successful launch returns subprocess.Popen object."""
        # Mock the process object
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_popen.return_value = mock_process
        
        # Call the function
        result = launch_jadx_gui(self.test_apk_path, self.verbose)
        
        # Verify the result is the process object
        self.assertIs(result, mock_process)
        self.assertEqual(result.pid, 12345)
        
        # Verify Popen was called correctly
        mock_popen.assert_called_once_with(
            ["jadx-gui", self.test_apk_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True
        )
    
    @patch('subprocess.Popen')
    def test_successful_launch_no_verbose(self, mock_popen):
        """Test successful launch without verbose output."""
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_popen.return_value = mock_process
        
        result = launch_jadx_gui(self.test_apk_path, verbose=False)
        
        self.assertIs(result, mock_process)
        self.assertEqual(result.pid, 12345)
    
    @patch('subprocess.Popen')
    def test_file_not_found_error(self, mock_popen):
        """Test that FileNotFoundError returns False."""
        mock_popen.side_effect = FileNotFoundError("jadx-gui not found")
        
        result = launch_jadx_gui(self.test_apk_path, self.verbose)
        
        self.assertFalse(result)
    
    @patch('subprocess.Popen')
    def test_generic_exception_returns_false(self, mock_popen):
        """Test that generic exceptions return False."""
        mock_popen.side_effect = Exception("Unexpected error")
        
        result = launch_jadx_gui(self.test_apk_path, self.verbose)
        
        self.assertFalse(result)
    
    def test_backward_compatibility_boolean_evaluation(self):
        """Test that the function maintains boolean-like behavior."""
        with patch('subprocess.Popen') as mock_popen:
            # Success case - should be truthy
            mock_process = MagicMock()
            mock_popen.return_value = mock_process
            
            result = launch_jadx_gui(self.test_apk_path, self.verbose)
            self.assertTrue(result)  # Process objects are truthy
        
        with patch('subprocess.Popen') as mock_popen:
            # Failure case - should be falsy
            mock_popen.side_effect = FileNotFoundError("jadx-gui not found")
            
            result = launch_jadx_gui(self.test_apk_path, self.verbose)
            self.assertFalse(result)  # False is falsy


class TestLaunchVSCode(unittest.TestCase):
    """Test cases for launch_vscode function."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_directory = "/tmp/test_dir"
        self.verbose = True
    
    @patch('subprocess.Popen')
    def test_successful_launch_returns_process(self, mock_popen):
        """Test that successful launch returns subprocess.Popen object."""
        # Mock the process object
        mock_process = MagicMock()
        mock_process.pid = 67890
        mock_popen.return_value = mock_process
        
        # Call the function
        result = launch_vscode(self.test_directory, self.verbose)
        
        # Verify the result is the process object
        self.assertIs(result, mock_process)
        self.assertEqual(result.pid, 67890)
        
        # Verify Popen was called correctly
        mock_popen.assert_called_once_with(
            ["code", self.test_directory],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True
        )
    
    @patch('subprocess.Popen')
    def test_successful_launch_no_verbose(self, mock_popen):
        """Test successful launch without verbose output."""
        mock_process = MagicMock()
        mock_process.pid = 67890
        mock_popen.return_value = mock_process
        
        result = launch_vscode(self.test_directory, verbose=False)
        
        self.assertIs(result, mock_process)
        self.assertEqual(result.pid, 67890)
    
    @patch('subprocess.Popen')
    def test_file_not_found_error(self, mock_popen):
        """Test that FileNotFoundError returns False."""
        mock_popen.side_effect = FileNotFoundError("code command not found")
        
        result = launch_vscode(self.test_directory, self.verbose)
        
        self.assertFalse(result)
    
    @patch('subprocess.Popen')
    def test_generic_exception_returns_false(self, mock_popen):
        """Test that generic exceptions return False."""
        mock_popen.side_effect = Exception("Unexpected error")
        
        result = launch_vscode(self.test_directory, self.verbose)
        
        self.assertFalse(result)
    
    def test_backward_compatibility_boolean_evaluation(self):
        """Test that the function maintains boolean-like behavior."""
        with patch('subprocess.Popen') as mock_popen:
            # Success case - should be truthy
            mock_process = MagicMock()
            mock_popen.return_value = mock_process
            
            result = launch_vscode(self.test_directory, self.verbose)
            self.assertTrue(result)  # Process objects are truthy
        
        with patch('subprocess.Popen') as mock_popen:
            # Failure case - should be falsy
            mock_popen.side_effect = FileNotFoundError("code command not found")
            
            result = launch_vscode(self.test_directory, self.verbose)
            self.assertFalse(result)  # False is falsy


class TestLaunchFunctionsIntegration(unittest.TestCase):
    """Integration tests for both launch functions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_apk_path = "/tmp/test.apk"
        self.test_directory = "/tmp/test_dir"
        self.verbose = True
    
    @patch('subprocess.Popen')
    def test_both_functions_return_process_objects(self, mock_popen):
        """Test that both functions return process objects on success."""
        # Mock process objects
        jadx_process = MagicMock()
        jadx_process.pid = 11111
        vscode_process = MagicMock()
        vscode_process.pid = 22222
        
        # Set up mock to return different processes for different calls
        mock_popen.side_effect = [jadx_process, vscode_process]
        
        # Test both functions
        jadx_result = launch_jadx_gui(self.test_apk_path, verbose=True)
        vscode_result = launch_vscode(self.test_directory, verbose=True)
        
        # Verify results
        self.assertIs(jadx_result, jadx_process)
        self.assertEqual(jadx_result.pid, 11111)
        self.assertIs(vscode_result, vscode_process)
        self.assertEqual(vscode_result.pid, 22222)
    
    @patch('subprocess.Popen')
    def test_process_pid_extraction(self, mock_popen):
        """Test that PIDs can be extracted from returned process objects."""
        # Mock process with PID
        mock_process = MagicMock()
        mock_process.pid = 99999
        mock_popen.return_value = mock_process
        
        # Test PID extraction
        result = launch_jadx_gui(self.test_apk_path, self.verbose)
        self.assertEqual(result.pid, 99999)
        
        # Test PID extraction from VS Code
        result = launch_vscode(self.test_directory, self.verbose)
        self.assertEqual(result.pid, 99999)


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)
