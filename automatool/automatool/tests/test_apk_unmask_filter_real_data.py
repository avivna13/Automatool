"""
Additional unit tests for APK Unmask Filter using real data from apk_unmask_output.txt
"""

import unittest
import os
import sys
from unittest.mock import patch, mock_open

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scripts.automations.apk_unmask_filter import ApkUnmaskFilter, ApkUnmaskParser


class TestApkUnmaskFilterRealData(unittest.TestCase):
    """Test cases using real apk_unmask output data."""
    
    def setUp(self):
        """Set up test fixtures with real data."""
        # Load the real apk_unmask output
        test_resources_dir = os.path.join(os.path.dirname(__file__), 'resources')
        apk_unmask_output_file = os.path.join(test_resources_dir, 'apk_unmask_output.txt')
        
        with open(apk_unmask_output_file, 'r', encoding='utf-8') as f:
            self.real_apk_unmask_output = f.read()
        
        # Current ignore list from the utils directory
        self.current_ignore_list = """# APK Unmask Ignore List
# Format: regex_pattern:reason_code:comment

.*NOTICES\.Z$:NOTICES_FILE:Android notices file
.*lowmcL[0-9]+\.bin\.properties$:CRYPTO_LIB:Bouncy Castle cryptographic library files
.*expo-root\.pem$:CERT_FILE:Expo root certificate file"""
        
        # Extended ignore list for testing more patterns
        self.extended_ignore_list = """# APK Unmask Ignore List
# Format: regex_pattern:reason_code:comment

.*NOTICES\.Z$:NOTICES_FILE:Android notices file
.*lowmcL[0-9]+\.bin\.properties$:CRYPTO_LIB:Bouncy Castle cryptographic library files
.*expo-root\.pem$:CERT_FILE:Expo root certificate file
res/font/noto_sans_.*\.ttf$:SYSTEM_FONT:Google Noto system fonts
assets/CRT/.*/.*\.crt$:CERT_FILE:SSL certificate files
com/mastercard/terminalsdk/internal/.*-$:MASTERCARD_SDK:MasterCard SDK internal files"""
    
    def test_extract_file_paths_real_data(self):
        """Test file path extraction from real apk_unmask output."""
        filter_obj = ApkUnmaskFilter(verbose=False)
        
        file_paths = filter_obj.extract_file_paths(self.real_apk_unmask_output)
        
        # Should extract all 31 files mentioned in the output
        self.assertEqual(len(file_paths), 31)
        
        # Check for specific files we know should be in the output
        expected_files = [
            "org/bouncycastle/pqc/crypto/picnic/lowmcL1.bin.properties",
            "org/bouncycastle/pqc/crypto/picnic/lowmcL3.bin.properties", 
            "org/bouncycastle/pqc/crypto/picnic/lowmcL5.bin.properties",
            "assets/tcgetconfig.xml",
            "res/font/noto_sans_japanese.ttf",
            "res/font/noto_sans_korean.ttf",
            "assets/CRT/DEV/am.tapit.mx.crt",
            "com/mastercard/terminalsdk/internal/a-"
        ]
        
        for expected_file in expected_files:
            self.assertIn(expected_file, file_paths, f"Expected file {expected_file} not found in extracted paths")
    
    def test_current_ignore_list_filtering(self):
        """Test filtering with the current minimal ignore list."""
        with patch('builtins.open', mock_open(read_data=self.current_ignore_list)):
            with patch('os.path.exists', return_value=True):
                filter_obj = ApkUnmaskFilter(verbose=False)
        
        filtered_output = filter_obj.filter_output(self.real_apk_unmask_output)
        
        # Should filter out the 3 lowmcL*.bin.properties files
        self.assertNotIn("lowmcL1.bin.properties", filtered_output)
        self.assertNotIn("lowmcL3.bin.properties", filtered_output)
        self.assertNotIn("lowmcL5.bin.properties", filtered_output)
        
        # Should keep other files
        self.assertIn("assets/tcgetconfig.xml", filtered_output)
        self.assertIn("res/font/noto_sans_japanese.ttf", filtered_output)
        self.assertIn("assets/CRT/DEV/am.tapit.mx.crt", filtered_output)
        
        # Should update total count (31 - 3 = 28)
        self.assertIn("[*] Total: 28", filtered_output)
    
    def test_extended_ignore_list_filtering(self):
        """Test filtering with extended ignore list covering more patterns."""
        with patch('builtins.open', mock_open(read_data=self.extended_ignore_list)):
            with patch('os.path.exists', return_value=True):
                filter_obj = ApkUnmaskFilter(verbose=False)
        
        filtered_output = filter_obj.filter_output(self.real_apk_unmask_output)
        
        # Should filter out lowmcL files
        self.assertNotIn("lowmcL1.bin.properties", filtered_output)
        self.assertNotIn("lowmcL3.bin.properties", filtered_output)
        self.assertNotIn("lowmcL5.bin.properties", filtered_output)
        
        # Should filter out Noto fonts
        self.assertNotIn("noto_sans_japanese.ttf", filtered_output)
        self.assertNotIn("noto_sans_korean.ttf", filtered_output)
        self.assertNotIn("noto_sans_simplified_chinese.ttf", filtered_output)
        self.assertNotIn("noto_sans_traditional_chinese.ttf", filtered_output)
        
        # Should filter out CRT files
        self.assertNotIn("am.tapit.mx.crt", filtered_output)
        self.assertNotIn("api.tapit.mx.crt", filtered_output)
        
        # Should filter out MasterCard SDK files
        self.assertNotIn("com/mastercard/terminalsdk/internal/a-", filtered_output)
        self.assertNotIn("com/mastercard/terminalsdk/internal/b-", filtered_output)
        self.assertNotIn("com/mastercard/terminalsdk/internal/c-", filtered_output)
        self.assertNotIn("com/mastercard/terminalsdk/internal/d-", filtered_output)
        
        # Should keep other files
        self.assertIn("assets/tcgetconfig.xml", filtered_output)
        self.assertIn("com/e/d/a-", filtered_output)
        self.assertIn("assets/signature/DEV.txt", filtered_output)
        
        # Calculate expected remaining files
        # Original: 31 files
        # Filtered: 3 lowmcL + 4 noto fonts + 6 CRT files + 4 mastercard SDK = 17 files
        # Remaining: 31 - 17 = 14 files
        self.assertIn("[*] Total: 14", filtered_output)
    
    def test_pattern_matching_accuracy(self):
        """Test that patterns match exactly what we expect from real data."""
        with patch('builtins.open', mock_open(read_data=self.extended_ignore_list)):
            with patch('os.path.exists', return_value=True):
                filter_obj = ApkUnmaskFilter(verbose=False)
        
        # Test specific pattern matches
        test_cases = [
            # Should match
            ("org/bouncycastle/pqc/crypto/picnic/lowmcL1.bin.properties", True, "CRYPTO_LIB"),
            ("org/bouncycastle/pqc/crypto/picnic/lowmcL3.bin.properties", True, "CRYPTO_LIB"),
            ("org/bouncycastle/pqc/crypto/picnic/lowmcL5.bin.properties", True, "CRYPTO_LIB"),
            ("res/font/noto_sans_japanese.ttf", True, "SYSTEM_FONT"),
            ("res/font/noto_sans_korean.ttf", True, "SYSTEM_FONT"),
            ("assets/CRT/DEV/am.tapit.mx.crt", True, "CERT_FILE"),
            ("assets/CRT/PROD/api.tapit.mx.crt", True, "CERT_FILE"),
            ("com/mastercard/terminalsdk/internal/a-", True, "MASTERCARD_SDK"),
            ("com/mastercard/terminalsdk/internal/d-", True, "MASTERCARD_SDK"),
            
            # Should NOT match
            ("assets/tcgetconfig.xml", False, None),
            ("com/e/d/a-", False, None),
            ("assets/signature/DEV.txt", False, None),
            ("assets/ttp/mastercard/manifest.json", False, None),
        ]
        
        for file_path, should_match, expected_reason in test_cases:
            should_ignore, reason = filter_obj.should_ignore(file_path)
            self.assertEqual(should_ignore, should_match, 
                           f"Pattern matching failed for {file_path}: expected {should_match}, got {should_ignore}")
            if should_match:
                self.assertEqual(reason, expected_reason, 
                               f"Wrong reason for {file_path}: expected {expected_reason}, got {reason}")
    
    def test_parse_real_output_structure(self):
        """Test parsing of real apk_unmask output structure."""
        parser = ApkUnmaskParser()
        parsed = parser.parse_output(self.real_apk_unmask_output)
        
        # Check total count
        self.assertEqual(parsed['total_count'], 31)
        
        # Check number of file entries
        self.assertEqual(len(parsed['file_entries']), 31)
        
        # Check specific file entries
        file_paths = [entry['path'] for entry in parsed['file_entries']]
        
        # Verify specific files are parsed correctly
        self.assertIn("org/bouncycastle/pqc/crypto/picnic/lowmcL1.bin.properties", file_paths)
        self.assertIn("assets/tcgetconfig.xml", file_paths)
        self.assertIn("res/font/noto_sans_japanese.ttf", file_paths)
        
        # Check that files have correct number of reasons
        tcgetconfig_entry = next((entry for entry in parsed['file_entries'] 
                                if entry['path'] == "assets/tcgetconfig.xml"), None)
        self.assertIsNotNone(tcgetconfig_entry)
        self.assertEqual(len(tcgetconfig_entry['reasons']), 3)  # Should have 3 reasons
        
        # Check that font files have correct number of reasons
        font_entry = next((entry for entry in parsed['file_entries'] 
                          if entry['path'] == "res/font/noto_sans_japanese.ttf"), None)
        self.assertIsNotNone(font_entry)
        self.assertEqual(len(font_entry['reasons']), 2)  # Should have 2 reasons
    
    def test_filtering_preserves_output_format(self):
        """Test that filtering preserves the exact output format."""
        with patch('builtins.open', mock_open(read_data=self.current_ignore_list)):
            with patch('os.path.exists', return_value=True):
                filter_obj = ApkUnmaskFilter(verbose=False)
        
        filtered_output = filter_obj.filter_output(self.real_apk_unmask_output)
        
        # Should start with the detection header
        self.assertIn("[!] Detected potentially malicious files:", filtered_output)
        
        # Should end with total count
        self.assertTrue(filtered_output.strip().endswith("[*] Total: 28"))
        
        # Should maintain proper formatting for remaining files
        lines = filtered_output.split('\n')
        file_lines = [line for line in lines if line.strip().startswith('-> ')]
        reason_lines = [line for line in lines if line.strip().startswith('└─')]
        
        # Should have 28 file lines after filtering
        self.assertEqual(len(file_lines), 28)
        
        # Should have more reason lines than file lines (each file has multiple reasons)
        self.assertGreater(len(reason_lines), len(file_lines))
        
        # Check that each remaining file has proper indentation
        for line in file_lines:
            self.assertTrue(line.startswith('\t-> '), f"File line not properly formatted: {line}")
        
        for line in reason_lines:
            self.assertTrue(line.startswith('\t   └─'), f"Reason line not properly formatted: {line}")
    
    def test_no_filtering_returns_original(self):
        """Test that when no patterns match, original output is returned."""
        # Empty ignore list
        empty_ignore_list = """# APK Unmask Ignore List
# Format: regex_pattern:reason_code:comment

# No patterns defined"""
        
        with patch('builtins.open', mock_open(read_data=empty_ignore_list)):
            with patch('os.path.exists', return_value=True):
                filter_obj = ApkUnmaskFilter(verbose=False)
        
        filtered_output = filter_obj.filter_output(self.real_apk_unmask_output)
        
        # Should return original output with same total count
        self.assertIn("[*] Total: 31", filtered_output)
        
        # Should contain all original files
        self.assertIn("lowmcL1.bin.properties", filtered_output)
        self.assertIn("noto_sans_japanese.ttf", filtered_output)
        self.assertIn("assets/tcgetconfig.xml", filtered_output)
    
    def test_edge_case_patterns(self):
        """Test edge cases in pattern matching."""
        # Test patterns that might cause issues
        edge_case_patterns = """# Test edge cases
.*lowmcL[0-9]+\.bin\.properties$:CRYPTO_LIB:Exact match test
^res/font/.*:FONT_FILE:Start anchor test
.*\.ttf$:TTF_FILE:Extension only test"""
        
        with patch('builtins.open', mock_open(read_data=edge_case_patterns)):
            with patch('os.path.exists', return_value=True):
                filter_obj = ApkUnmaskFilter(verbose=False)
        
        # Test that patterns work as expected
        test_files = [
            ("org/bouncycastle/pqc/crypto/picnic/lowmcL1.bin.properties", True, "CRYPTO_LIB"),
            ("res/font/noto_sans_japanese.ttf", True, "FONT_FILE"),  # Should match first pattern
            ("some/other/file.ttf", True, "TTF_FILE"),  # Should match extension pattern
            ("assets/tcgetconfig.xml", False, None),  # Should not match any
        ]
        
        for file_path, should_match, expected_reason in test_files:
            should_ignore, reason = filter_obj.should_ignore(file_path)
            self.assertEqual(should_ignore, should_match, 
                           f"Edge case pattern failed for {file_path}")
            if should_match:
                # Note: When multiple patterns match, it returns the first match
                self.assertIsNotNone(reason)


if __name__ == '__main__':
    # Run with verbose output to see detailed test results
    unittest.main(verbosity=2)
