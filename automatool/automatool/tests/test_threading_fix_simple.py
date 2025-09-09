#!/usr/bin/env python3
"""
Simple test for the threading fix to verify basic functionality.
"""

import os
import tempfile
import shutil
import json
import unittest
from unittest.mock import patch, MagicMock

# Add the src directory to the path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


class TestThreadingFixSimple(unittest.TestCase):
    """Simple tests for the threading fix."""
    
    def setUp(self):
        """Set up test directory."""
        self.test_dir = tempfile.mkdtemp()
        self.reviews_file = os.path.join(self.test_dir, "reviews.json")
    
    def tearDown(self):
        """Clean up test directory."""
        shutil.rmtree(self.test_dir)
    
    def test_fallback_file_creation(self):
        """Test that fallback file creation works."""
        from scripts.automations.run_reviews_with_parsing import _create_fallback_reviews_file
        
        # Create fallback file
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
        self.assertTrue(data['metadata']['fallback'])
    
    def test_timeout_functionality(self):
        """Test that timeout functionality works."""
        from scripts.automations.run_reviews_with_parsing import _wait_and_parse
        
        # Mock the parse function
        with patch('scripts.automations.run_reviews_with_parsing.parse_reviews_to_summary') as mock_parse:
            mock_parse.return_value = "Test result"
            
            # Reset global variable for test
            import scripts.automations.run_reviews_with_parsing as module
            module.summary_result = None
            
            # Call function with very short timeout (should create fallback)
            module._wait_and_parse(self.test_dir, verbose=False, timeout=0.1)
            
            # Verify fallback file was created
            self.assertTrue(os.path.exists(self.reviews_file))
            
            # Verify parse was called
            mock_parse.assert_called_once()
    
    def test_main_function_signature(self):
        """Test that main function has the expected signature."""
        from scripts.automations.run_reviews_with_parsing import run_reviews_with_parsing
        
        # Check that function exists and has timeout parameter
        import inspect
        sig = inspect.signature(run_reviews_with_parsing)
        params = list(sig.parameters.keys())
        
        self.assertIn('package_name', params)
        self.assertIn('output_directory', params)
        self.assertIn('verbose', params)
        self.assertIn('timeout', params)
        
        # Check default timeout value
        self.assertEqual(sig.parameters['timeout'].default, 60)


if __name__ == '__main__':
    unittest.main(verbosity=2)
