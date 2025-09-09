#!/usr/bin/env python3
"""
Tests for run_reviews_with_parsing.py threading fix.

Tests the timeout protection, fallback file creation, and thread management
features that prevent infinite blocking when reviews scraper fails.
"""

import os
import tempfile
import shutil
import time
import json
import threading
import unittest
from unittest.mock import patch, MagicMock, call
from datetime import datetime

# Add the src directory to the path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scripts.automations.run_reviews_with_parsing import (
    _create_fallback_reviews_file,
    _wait_and_parse,
    run_reviews_with_parsing,
    summary_result
)


class TestFallbackFileCreation(unittest.TestCase):
    """Test the fallback file creation functionality."""
    
    def setUp(self):
        """Set up test directory."""
        self.test_dir = tempfile.mkdtemp()
        self.reviews_file = os.path.join(self.test_dir, "reviews.json")
    
    def tearDown(self):
        """Clean up test directory."""
        shutil.rmtree(self.test_dir)
    
    def test_create_fallback_file_success(self):
        """Test successful fallback file creation."""
        _create_fallback_reviews_file(self.test_dir, verbose=False)
        
        # Check file exists
        self.assertTrue(os.path.exists(self.reviews_file))
        
        # Check file content
        with open(self.reviews_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Verify structure
        self.assertIn('reviews', data)
        self.assertIn('metadata', data)
        self.assertEqual(data['reviews'], [])
        self.assertEqual(data['metadata']['status'], 'no_reviews_found')
        self.assertEqual(data['metadata']['fallback'], True)
        self.assertIn('timestamp', data['metadata'])
        self.assertIn('message', data['metadata'])
    
    def test_create_fallback_file_with_verbose(self):
        """Test fallback file creation with verbose logging."""
        with patch('builtins.print') as mock_print:
            _create_fallback_reviews_file(self.test_dir, verbose=True)
            
            # Check that debug message was printed
            mock_print.assert_called_with(
                f"[DEBUG] Created fallback reviews file: {self.reviews_file}"
            )
    
    def test_fallback_file_metadata_content(self):
        """Test that fallback file contains correct metadata."""
        _create_fallback_reviews_file(self.test_dir, verbose=False)
        
        with open(self.reviews_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        metadata = data['metadata']
        self.assertEqual(metadata['status'], 'no_reviews_found')
        self.assertIn('Reviews scraper did not find any reviews', metadata['message'])
        self.assertTrue(metadata['fallback'])
        
        # Check timestamp is valid ISO format
        try:
            datetime.fromisoformat(metadata['timestamp'])
        except ValueError:
            self.fail("Timestamp is not in valid ISO format")


class TestWaitAndParseFunction(unittest.TestCase):
    """Test the _wait_and_parse function with timeout protection."""
    
    def setUp(self):
        """Set up test directory."""
        self.test_dir = tempfile.mkdtemp()
        self.reviews_file = os.path.join(self.test_dir, "reviews.json")
    
    def tearDown(self):
        """Clean up test directory."""
        shutil.rmtree(self.test_dir)
    
    @patch('scripts.automations.run_reviews_with_parsing.parse_reviews_to_summary')
    def test_wait_for_existing_file(self, mock_parse):
        """Test waiting for an existing file (normal case)."""
        # Create the file before calling the function
        with open(self.reviews_file, 'w') as f:
            json.dump({"reviews": [{"test": "data"}]}, f)
        
        mock_parse.return_value = "Test summary"
        
        # Reset global variable for test
        import scripts.automations.run_reviews_with_parsing as module
        module.summary_result = None
        
        # Call function with short timeout
        module._wait_and_parse(self.test_dir, verbose=False, timeout=1)
        
        # Verify parse was called
        mock_parse.assert_called_once_with(self.test_dir, False)
        
        # Verify global result was set
        self.assertEqual(module.summary_result, "Test summary")
    
    @patch('scripts.automations.run_reviews_with_parsing.parse_reviews_to_summary')
    @patch('scripts.automations.run_reviews_with_parsing._create_fallback_reviews_file')
    def test_timeout_creates_fallback(self, mock_create_fallback, mock_parse):
        """Test that timeout triggers fallback file creation."""
        mock_parse.return_value = "Fallback summary"
        
        # Call function with very short timeout
        import scripts.automations.run_reviews_with_parsing as module
        module._wait_and_parse(self.test_dir, verbose=False, timeout=0.1)
        
        # Verify fallback file was created
        mock_create_fallback.assert_called_once_with(self.test_dir, False)
        
        # Verify parse was called (with fallback file)
        mock_parse.assert_called_once_with(self.test_dir, False)
    
    @patch('scripts.automations.run_reviews_with_parsing.parse_reviews_to_summary')
    def test_parsing_error_handling(self, mock_parse):
        """Test error handling during parsing."""
        # Create a file to avoid timeout
        with open(self.reviews_file, 'w') as f:
            json.dump({"reviews": []}, f)
        
        # Make parse function raise an exception
        mock_parse.side_effect = Exception("Parse error")
        
        # Reset global variable for test
        import scripts.automations.run_reviews_with_parsing as module
        module.summary_result = None
        
        # Call function
        module._wait_and_parse(self.test_dir, verbose=False, timeout=1)
        
        # Verify global result contains error message
        self.assertEqual(module.summary_result, "Error: Failed to parse reviews")
    
    def test_timeout_logging(self):
        """Test verbose logging during timeout."""
        with patch('builtins.print') as mock_print:
            import scripts.automations.run_reviews_with_parsing as module
            module._wait_and_parse(self.test_dir, verbose=True, timeout=0.1)
            
            # Check that timeout messages were printed
            mock_print.assert_any_call(f"[DEBUG] Parser thread waiting for file: {self.reviews_file}")
            mock_print.assert_any_call("[DEBUG] Timeout set to: 0.1 seconds")
            
            # Check that timeout reached message was printed
            timeout_calls = [call for call in mock_print.call_args_list 
                           if "Timeout reached after" in str(call)]
            self.assertTrue(len(timeout_calls) > 0)


class TestRunReviewsWithParsing(unittest.TestCase):
    """Test the main run_reviews_with_parsing function."""
    
    def setUp(self):
        """Set up test directory."""
        self.test_dir = tempfile.mkdtemp()
        self.package_name = "com.test.app"
    
    def tearDown(self):
        """Clean up test directory."""
        shutil.rmtree(self.test_dir)
    
    @patch('scripts.automations.run_reviews_with_parsing.run_reviews_scraper')
    @patch('scripts.automations.run_reviews_with_parsing.parse_reviews_to_summary')
    def test_normal_operation(self, mock_parse, mock_scraper):
        """Test normal operation without timeout."""
        # Setup mocks
        mock_scraper.return_value = True
        mock_parse.return_value = "Normal summary"
        
        # Create reviews file to avoid timeout
        reviews_file = os.path.join(self.test_dir, "reviews.json")
        with open(reviews_file, 'w') as f:
            json.dump({"reviews": [{"test": "data"}]}, f)
        
        # Call function
        result = run_reviews_with_parsing(self.package_name, self.test_dir, verbose=False)
        
        # Verify result
        self.assertEqual(result, "Normal summary")
        
        # Verify scraper was called
        mock_scraper.assert_called_once_with(self.package_name, self.test_dir, False)
    
    @patch('scripts.automations.run_reviews_with_parsing.run_reviews_scraper')
    @patch('scripts.automations.run_reviews_with_parsing.parse_reviews_to_summary')
    @patch('scripts.automations.run_reviews_with_parsing._create_fallback_reviews_file')
    def test_thread_timeout_handling(self, mock_create_fallback, mock_parse, mock_scraper):
        """Test handling of thread timeout."""
        # Setup mocks
        mock_scraper.return_value = True
        mock_parse.return_value = "Fallback summary"
        
        # Mock the parser thread to simulate hanging
        with patch('threading.Thread') as mock_thread_class:
            mock_thread = MagicMock()
            mock_thread_class.return_value = mock_thread
            mock_thread.is_alive.return_value = True  # Thread is hanging
            
            # Call function with short timeout
            result = run_reviews_with_parsing(self.package_name, self.test_dir, verbose=False, timeout=0.1)
            
            # Verify fallback was created
            mock_create_fallback.assert_called_once_with(self.test_dir, False)
            
            # Verify parse was called with fallback
            mock_parse.assert_called_once_with(self.test_dir, False)
            
            # Verify result
            self.assertEqual(result, "Fallback summary")
    
    @patch('scripts.automations.run_reviews_with_parsing.run_reviews_scraper')
    @patch('scripts.automations.run_reviews_with_parsing.parse_reviews_to_summary')
    def test_fallback_parsing_error(self, mock_parse, mock_scraper):
        """Test error handling during fallback parsing."""
        # Setup mocks
        mock_scraper.return_value = True
        mock_parse.side_effect = Exception("Fallback parse error")
        
        # Mock the parser thread to simulate hanging
        with patch('threading.Thread') as mock_thread_class:
            mock_thread = MagicMock()
            mock_thread_class.return_value = mock_thread
            mock_thread.is_alive.return_value = True  # Thread is hanging
            
            # Call function
            result = run_reviews_with_parsing(self.package_name, self.test_dir, verbose=False, timeout=0.1)
            
            # Verify error result
            self.assertEqual(result, "Error: Failed to parse reviews (fallback)")
    
    def test_daemon_thread_creation(self):
        """Test that parser thread is created as daemon."""
        with patch('threading.Thread') as mock_thread_class:
            mock_thread = MagicMock()
            mock_thread_class.return_value = mock_thread
            
            # Mock the thread to complete quickly
            mock_thread.is_alive.return_value = False
            
            # Call function
            run_reviews_with_parsing(self.package_name, self.test_dir, verbose=False)
            
            # Find the call that creates the parser thread (with daemon=True)
            parser_thread_calls = [
                call for call in mock_thread_class.call_args_list
                if len(call[1]) > 0 and call[1].get('daemon') == True
            ]
            
            # Verify at least one daemon thread was created
            self.assertTrue(len(parser_thread_calls) > 0, "No daemon thread was created")
            
            # Verify the daemon thread has correct parameters
            parser_call = parser_thread_calls[0]
            self.assertEqual(parser_call[1]['daemon'], True)
    
    def test_timeout_configuration_logging(self):
        """Test verbose logging of timeout configuration."""
        with patch('builtins.print') as mock_print:
            with patch('threading.Thread') as mock_thread_class:
                mock_thread = MagicMock()
                mock_thread_class.return_value = mock_thread
                mock_thread.is_alive.return_value = False
                
                # Call function with verbose and custom timeout
                run_reviews_with_parsing(self.package_name, self.test_dir, verbose=True, timeout=30)
                
                # Check timeout configuration message
                mock_print.assert_any_call("[DEBUG] Timeout configuration: 30s for file wait, 35s for thread join")


class TestIntegrationScenarios(unittest.TestCase):
    """Test integration scenarios and edge cases."""
    
    def setUp(self):
        """Set up test directory."""
        self.test_dir = tempfile.mkdtemp()
        self.package_name = "com.test.app"
    
    def tearDown(self):
        """Clean up test directory."""
        shutil.rmtree(self.test_dir)
    
    def test_no_reviews_found_scenario(self):
        """Test the complete scenario when no reviews are found."""
        # This test simulates the real bug scenario
        with patch('scripts.automations.run_reviews_with_parsing.run_reviews_scraper') as mock_scraper:
            mock_scraper.return_value = True  # Scraper "succeeds" but doesn't create file
            
            # Call function with short timeout to simulate the issue
            result = run_reviews_with_parsing(self.package_name, self.test_dir, verbose=False, timeout=0.1)
            
            # Verify that a result was returned (no hanging)
            self.assertIsNotNone(result)
            
            # Verify fallback file was created
            reviews_file = os.path.join(self.test_dir, "reviews.json")
            self.assertTrue(os.path.exists(reviews_file))
            
            # Verify fallback file content
            with open(reviews_file, 'r') as f:
                data = json.load(f)
            self.assertEqual(data['reviews'], [])
            self.assertTrue(data['metadata']['fallback'])
    
    def test_network_failure_scenario(self):
        """Test scenario when network fails and scraper can't create file."""
        with patch('scripts.automations.run_reviews_with_parsing.run_reviews_scraper') as mock_scraper:
            mock_scraper.return_value = False  # Scraper fails
            
            # Call function
            result = run_reviews_with_parsing(self.package_name, self.test_dir, verbose=False, timeout=0.1)
            
            # Verify that function completes and returns a result
            self.assertIsNotNone(result)
            
            # Verify fallback file exists
            reviews_file = os.path.join(self.test_dir, "reviews.json")
            self.assertTrue(os.path.exists(reviews_file))
    
    def test_backward_compatibility(self):
        """Test that existing function calls still work."""
        with patch('scripts.automations.run_reviews_with_parsing.run_reviews_scraper') as mock_scraper:
            mock_scraper.return_value = True
            
            # Create a file to avoid timeout
            reviews_file = os.path.join(self.test_dir, "reviews.json")
            with open(reviews_file, 'w') as f:
                json.dump({"reviews": []}, f)
            
            # Call function without timeout parameter (should use default)
            result = run_reviews_with_parsing(self.package_name, self.test_dir, verbose=False)
            
            # Verify function works
            self.assertIsNotNone(result)


class TestThreadSafety(unittest.TestCase):
    """Test thread safety and race conditions."""
    
    def setUp(self):
        """Set up test directory."""
        self.test_dir = tempfile.mkdtemp()
        self.package_name = "com.test.app"
    
    def tearDown(self):
        """Clean up test directory."""
        shutil.rmtree(self.test_dir)
    
    def test_multiple_concurrent_calls(self):
        """Test multiple concurrent calls to the function."""
        results = []
        threads = []
        
        def run_function():
            with patch('scripts.automations.run_reviews_with_parsing.run_reviews_scraper') as mock_scraper:
                mock_scraper.return_value = True
                result = run_reviews_with_parsing(self.package_name, self.test_dir, verbose=False, timeout=0.1)
                results.append(result)
        
        # Start multiple threads
        for _ in range(3):
            thread = threading.Thread(target=run_function)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all calls completed
        self.assertEqual(len(results), 3)
        for result in results:
            self.assertIsNotNone(result)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
