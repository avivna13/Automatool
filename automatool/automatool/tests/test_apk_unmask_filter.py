"""
Unit tests for APK Unmask Filter functionality.
"""

import unittest
import tempfile
import os
import sys
from unittest.mock import patch, mock_open

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scripts.automations.apk_unmask_filter import ApkUnmaskFilter, ApkUnmaskParser


class TestApkUnmaskFilter(unittest.TestCase):
    """Test cases for ApkUnmaskFilter class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.sample_ignore_list = """# APK Unmask Ignore List
# Format: regex_pattern:reason_code:comment

# Test patterns
.*NOTICES\.Z$:NOTICES_FILE:Android notices file
.*lowmcL[0-9]+\.bin\.properties$:CRYPTO_LIB:Bouncy Castle cryptographic library files
.*expo-root\.pem$:CERT_FILE:Expo root certificate file
"""
        
        self.sample_apk_unmask_output = """[!] Detected potentially malicious files:
\t-> org/bouncycastle/pqc/crypto/picnic/lowmcL1.bin.properties
\t   └─ File is out of place
\t   └─ File has a fake extension
\t-> assets/tcgetconfig.xml
\t   └─ File is out of place
\t   └─ File has a fake extension
\t   └─ File appears to be encrypted
\t-> com/e/d/a-
\t   └─ File is out of place
\t   └─ File has a fake extension
\t   └─ File appears to be encrypted
\t-> assets/NOTICES.Z
\t   └─ File is out of place
\t   └─ File has a fake extension
[*] Total: 4"""
    
    def test_parse_ignore_entry_valid(self):
        """Test parsing valid ignore list entries."""
        filter_obj = ApkUnmaskFilter(verbose=False)
        
        # Test valid entry with comment
        entry = filter_obj.parse_ignore_entry(".*test\.txt$:TEST_FILE:Test file comment")
        self.assertIsNotNone(entry)
        self.assertEqual(entry['pattern'], ".*test\.txt$")
        self.assertEqual(entry['reason'], "TEST_FILE")
        self.assertEqual(entry['comment'], "Test file comment")
        
        # Test valid entry without comment
        entry = filter_obj.parse_ignore_entry(".*test\.txt$:TEST_FILE")
        self.assertIsNotNone(entry)
        self.assertEqual(entry['pattern'], ".*test\.txt$")
        self.assertEqual(entry['reason'], "TEST_FILE")
        self.assertEqual(entry['comment'], "")
    
    def test_parse_ignore_entry_invalid(self):
        """Test parsing invalid ignore list entries."""
        filter_obj = ApkUnmaskFilter(verbose=False)
        
        # Test entry without reason code
        entry = filter_obj.parse_ignore_entry(".*test\.txt$")
        self.assertIsNone(entry)
        
        # Test entry with invalid regex
        entry = filter_obj.parse_ignore_entry("[invalid_regex:TEST_FILE:Comment")
        self.assertIsNone(entry)
        
        # Test empty entry
        entry = filter_obj.parse_ignore_entry("")
        self.assertIsNone(entry)
    
    def test_should_ignore_matching_patterns(self):
        """Test file path matching against ignore patterns."""
        with patch('builtins.open', mock_open(read_data=self.sample_ignore_list)):
            with patch('os.path.exists', return_value=True):
                filter_obj = ApkUnmaskFilter(verbose=False)
        
        # Test files that should be ignored
        should_ignore, reason = filter_obj.should_ignore("assets/NOTICES.Z")
        self.assertTrue(should_ignore)
        self.assertEqual(reason, "NOTICES_FILE")
        
        should_ignore, reason = filter_obj.should_ignore("org/bouncycastle/pqc/crypto/picnic/lowmcL1.bin.properties")
        self.assertTrue(should_ignore)
        self.assertEqual(reason, "CRYPTO_LIB")
        
        should_ignore, reason = filter_obj.should_ignore("path/to/expo-root.pem")
        self.assertTrue(should_ignore)
        self.assertEqual(reason, "CERT_FILE")
        
        # Test file that should NOT be ignored
        should_ignore, reason = filter_obj.should_ignore("assets/suspicious_file.exe")
        self.assertFalse(should_ignore)
        self.assertIsNone(reason)
    
    def test_extract_file_paths(self):
        """Test extraction of file paths from apk_unmask output."""
        filter_obj = ApkUnmaskFilter(verbose=False)
        
        file_paths = filter_obj.extract_file_paths(self.sample_apk_unmask_output)
        
        expected_paths = [
            "org/bouncycastle/pqc/crypto/picnic/lowmcL1.bin.properties",
            "assets/tcgetconfig.xml",
            "com/e/d/a-",
            "assets/NOTICES.Z"
        ]
        
        self.assertEqual(len(file_paths), 4)
        for expected_path in expected_paths:
            self.assertIn(expected_path, file_paths)
    
    def test_filter_output(self):
        """Test filtering of apk_unmask output."""
        with patch('builtins.open', mock_open(read_data=self.sample_ignore_list)):
            with patch('os.path.exists', return_value=True):
                filter_obj = ApkUnmaskFilter(verbose=False)
        
        filtered_output = filter_obj.filter_output(self.sample_apk_unmask_output)
        
        # Check that filtered files are removed
        self.assertNotIn("lowmcL1.bin.properties", filtered_output)
        self.assertNotIn("NOTICES.Z", filtered_output)
        
        # Check that non-filtered files remain
        self.assertIn("assets/tcgetconfig.xml", filtered_output)
        self.assertIn("com/e/d/a-", filtered_output)
        
        # Check that total count is updated
        self.assertIn("[*] Total: 2", filtered_output)
    
    def test_filter_output_no_patterns(self):
        """Test filtering when no ignore patterns are loaded."""
        with patch('os.path.exists', return_value=False):
            filter_obj = ApkUnmaskFilter(verbose=False)
        
        filtered_output = filter_obj.filter_output(self.sample_apk_unmask_output)
        
        # Should return original output unchanged
        self.assertEqual(filtered_output, self.sample_apk_unmask_output)
    
    def test_ignore_list_file_not_found(self):
        """Test behavior when ignore list file doesn't exist."""
        with patch('os.path.exists', return_value=False):
            filter_obj = ApkUnmaskFilter(verbose=False)
        
        # Should have no patterns loaded
        self.assertEqual(len(filter_obj.ignore_patterns), 0)
        
        # Should not ignore any files
        should_ignore, reason = filter_obj.should_ignore("any/file/path")
        self.assertFalse(should_ignore)
        self.assertIsNone(reason)
    
    def test_ignore_list_with_comments_and_empty_lines(self):
        """Test ignore list parsing with comments and empty lines."""
        ignore_list_with_comments = """# This is a comment
# Another comment

.*test\.txt$:TEST_FILE:Test file

# More comments
.*\.log$:LOG_FILE:Log files
"""
        
        with patch('builtins.open', mock_open(read_data=ignore_list_with_comments)):
            with patch('os.path.exists', return_value=True):
                filter_obj = ApkUnmaskFilter(verbose=False)
        
        # Should have loaded 2 patterns (ignoring comments and empty lines)
        self.assertEqual(len(filter_obj.ignore_patterns), 2)
        
        # Test that patterns work
        should_ignore, reason = filter_obj.should_ignore("path/test.txt")
        self.assertTrue(should_ignore)
        self.assertEqual(reason, "TEST_FILE")


class TestApkUnmaskParser(unittest.TestCase):
    """Test cases for ApkUnmaskParser class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.sample_output = """[!] Detected potentially malicious files:
\t-> assets/tcgetconfig.xml
\t   └─ File is out of place
\t   └─ File has a fake extension
\t   └─ File appears to be encrypted
\t-> com/e/d/a-
\t   └─ File is out of place
\t   └─ File has a fake extension
[*] Total: 2"""
        
        self.parser = ApkUnmaskParser()
    
    def test_parse_output(self):
        """Test parsing of apk_unmask output into structured format."""
        parsed = self.parser.parse_output(self.sample_output)
        
        # Check total count
        self.assertEqual(parsed['total_count'], 2)
        
        # Check file entries
        self.assertEqual(len(parsed['file_entries']), 2)
        
        # Check first file entry
        first_entry = parsed['file_entries'][0]
        self.assertEqual(first_entry['path'], "assets/tcgetconfig.xml")
        self.assertEqual(len(first_entry['reasons']), 3)
        self.assertIn("File is out of place", first_entry['reasons'])
        self.assertIn("File has a fake extension", first_entry['reasons'])
        self.assertIn("File appears to be encrypted", first_entry['reasons'])
        
        # Check second file entry
        second_entry = parsed['file_entries'][1]
        self.assertEqual(second_entry['path'], "com/e/d/a-")
        self.assertEqual(len(second_entry['reasons']), 2)
        self.assertIn("File is out of place", second_entry['reasons'])
        self.assertIn("File has a fake extension", second_entry['reasons'])
    
    def test_extract_file_entries(self):
        """Test extraction of file entries from output lines."""
        lines = self.sample_output.split('\n')
        entries = self.parser.extract_file_entries(lines)
        
        self.assertEqual(len(entries), 2)
        
        # Check first entry
        self.assertEqual(entries[0]['path'], "assets/tcgetconfig.xml")
        self.assertEqual(len(entries[0]['reasons']), 3)
        
        # Check second entry
        self.assertEqual(entries[1]['path'], "com/e/d/a-")
        self.assertEqual(len(entries[1]['reasons']), 2)
    
    def test_format_filtered_output(self):
        """Test formatting of filtered entries back to original format."""
        entries = [
            {
                'path': 'test/file1.txt',
                'reasons': ['Reason 1', 'Reason 2']
            },
            {
                'path': 'test/file2.txt',
                'reasons': ['Reason 3']
            }
        ]
        
        formatted = self.parser.format_filtered_output(entries)
        
        # Check that output contains expected elements
        self.assertIn("[!] Detected potentially malicious files:", formatted)
        self.assertIn("-> test/file1.txt", formatted)
        self.assertIn("-> test/file2.txt", formatted)
        self.assertIn("└─ Reason 1", formatted)
        self.assertIn("└─ Reason 2", formatted)
        self.assertIn("└─ Reason 3", formatted)
        self.assertIn("[*] Total: 2", formatted)
    
    def test_format_filtered_output_empty(self):
        """Test formatting when no entries remain after filtering."""
        formatted = self.parser.format_filtered_output([])
        self.assertEqual(formatted.strip(), "[*] Total: 0")


class TestIntegration(unittest.TestCase):
    """Integration tests for filter and parser working together."""
    
    def test_full_filtering_workflow(self):
        """Test complete filtering workflow from input to output."""
        ignore_list = """.*NOTICES\.Z$:NOTICES_FILE:Android notices file
.*lowmcL[0-9]+\.bin\.properties$:CRYPTO_LIB:Bouncy Castle files"""
        
        input_output = """[!] Detected potentially malicious files:
\t-> org/bouncycastle/pqc/crypto/picnic/lowmcL1.bin.properties
\t   └─ File is out of place
\t-> assets/tcgetconfig.xml
\t   └─ File is out of place
\t-> assets/NOTICES.Z
\t   └─ File is out of place
[*] Total: 3"""
        
        with patch('builtins.open', mock_open(read_data=ignore_list)):
            with patch('os.path.exists', return_value=True):
                filter_obj = ApkUnmaskFilter(verbose=False)
        
        filtered_output = filter_obj.filter_output(input_output)
        
        # Should have filtered out 2 files (lowmcL1.bin.properties and NOTICES.Z)
        self.assertNotIn("lowmcL1.bin.properties", filtered_output)
        self.assertNotIn("NOTICES.Z", filtered_output)
        self.assertIn("tcgetconfig.xml", filtered_output)
        self.assertIn("[*] Total: 1", filtered_output)


if __name__ == '__main__':
    unittest.main()
