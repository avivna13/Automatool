import os
import tempfile
import shutil
import pytest
from unittest.mock import patch
import sys

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scripts.automations.parse_yara_results import parse_yara_to_summary, _clean_filename


class TestParseYaraResults:
    """Test suite for YARA results parsing automation."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def test_yara_json_path(self):
        """Get the path to the test yara.json file."""
        return os.path.join(os.path.dirname(__file__), 'resources', 'yara.json')
    
    def test_parse_yara_to_summary_success(self, temp_dir, test_yara_json_path):
        """Test successful parsing of YARA JSON to summary."""
        # Copy the test yara.json to temp directory
        temp_yara_path = os.path.join(temp_dir, 'yara.json')
        shutil.copy2(test_yara_json_path, temp_yara_path)
        
        # Run the parsing function
        result = parse_yara_to_summary(temp_dir, verbose=True)
        
        # Check that it returns the output file path (success)
        assert isinstance(result, str)
        assert result.endswith('yara_summary.txt')
        
        # Check that the output file was created
        output_file = os.path.join(temp_dir, 'yara_summary.txt')
        assert os.path.exists(output_file)
        
        # Read and verify the output content
        with open(output_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Verify basic structure
        assert "YARA Analysis Summary" in content
        assert "=" * 50 in content
        
        # Verify some specific file sections are present
        assert "=== ALL_DATA ===" in content
        assert "=== androidmanifest.xml ===" in content
        assert "=== classes.dex ===" in content
        assert "=== classes3.dex ===" in content
        
        # Verify some specific matches are present
        assert "NQ Shield" in content
        assert "Baidu" in content
        assert "The application have full_screen_intent permission" in content
        assert "Detect Uniapp (dcloud) applications" in content
        
        # Verify strings are cleaned and present
        assert "nqshield" in content
        assert "baiduprotect1.jar" in content
        assert "android.permission.USE_FULL_SCREEN_INTENT" in content
        assert "dcloud_uniplugins.json" in content
        
        # Verify summary section is preserved
        assert "Summary:" in content
        assert "=======  uni.app.UNIA804A35.apk  =======" in content
        assert "--packer--" in content
        assert "--heuristic--" in content
        assert "--technique--" in content
        assert "--obfuscator_protector--" in content
    
    def test_parse_yara_to_summary_no_file(self, temp_dir):
        """Test behavior when yara.json doesn't exist."""
        result = parse_yara_to_summary(temp_dir, verbose=True)
        
        # Should return None (file not found)
        assert result is None
        
        # Output file should not be created
        output_file = os.path.join(temp_dir, 'yara_summary.txt')
        assert not os.path.exists(output_file)
    
    def test_parse_yara_to_summary_invalid_json(self, temp_dir):
        """Test behavior with invalid JSON file."""
        # Create an invalid JSON file
        invalid_json_path = os.path.join(temp_dir, 'yara.json')
        with open(invalid_json_path, 'w') as f:
            f.write('{ invalid json content')
        
        result = parse_yara_to_summary(temp_dir, verbose=True)
        
        # Should return None (JSON parsing error)
        assert result is None
    
    def test_parse_yara_to_summary_empty_matches(self, temp_dir):
        """Test behavior with YARA file containing no matches."""
        # Create a minimal valid JSON with no matches
        empty_json_content = '''
{
    "files": [
        {
            "filename": "test.dex",
            "matches": []
        }
    ],
    "name": "test.apk"
}

Summary:

Test summary content
'''
        
        empty_json_path = os.path.join(temp_dir, 'yara.json')
        with open(empty_json_path, 'w', encoding='utf-8') as f:
            f.write(empty_json_content)
        
        result = parse_yara_to_summary(temp_dir, verbose=True)
        
        # Should still return the output file path (successful parsing)
        assert isinstance(result, str)
        assert result.endswith('yara_summary.txt')
        
        # Check that output file was created
        output_file = os.path.join(temp_dir, 'yara_summary.txt')
        assert os.path.exists(output_file)
        
        # Read and verify the output content
        with open(output_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Should still have basic structure
        assert "YARA Analysis Summary" in content
        # Should preserve summary
        assert "Test summary content" in content
    
    def test_parse_yara_to_summary_verbose_output(self, temp_dir, test_yara_json_path, capsys):
        """Test verbose output functionality."""
        # Copy the test yara.json to temp directory
        temp_yara_path = os.path.join(temp_dir, 'yara.json')
        shutil.copy2(test_yara_json_path, temp_yara_path)
        
        # Run with verbose=True
        result = parse_yara_to_summary(temp_dir, verbose=True)
        
        # Capture stdout
        captured = capsys.readouterr()
        
        assert isinstance(result, str)
        assert result.endswith('yara_summary.txt')
        assert "[DEBUG]" in captured.out
        assert "Looking for YARA results:" in captured.out
        assert "Successfully parsed YARA data" in captured.out
        assert "YARA summary written to:" in captured.out
    
    def test_parse_yara_to_summary_non_verbose(self, temp_dir, test_yara_json_path, capsys):
        """Test non-verbose output functionality."""
        # Copy the test yara.json to temp directory
        temp_yara_path = os.path.join(temp_dir, 'yara.json')
        shutil.copy2(test_yara_json_path, temp_yara_path)
        
        # Run with verbose=False
        result = parse_yara_to_summary(temp_dir, verbose=False)
        
        # Capture stdout
        captured = capsys.readouterr()
        
        assert isinstance(result, str)
        assert result.endswith('yara_summary.txt')
        assert "[DEBUG]" not in captured.out
        assert "✅ YARA summary created:" in captured.out
    
    def test_parse_yara_to_summary_with_empty_strings(self, temp_dir):
        """Test parsing with matches that have empty strings arrays."""
        json_with_empty_strings = '''
{
    "files": [
        {
            "filename": "test.dex",
            "matches": [
                {
                    "description": "Test rule with no strings",
                    "rule": "test_rule",
                    "strings": [],
                    "type": "heuristic"
                }
            ]
        }
    ],
    "name": "test.apk"
}

Summary:
Test summary
'''
        
        json_path = os.path.join(temp_dir, 'yara.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            f.write(json_with_empty_strings)
        
        result = parse_yara_to_summary(temp_dir, verbose=True)
        
        assert isinstance(result, str)
        assert result.endswith('yara_summary.txt')
        
        # Check output file content
        output_file = os.path.join(temp_dir, 'yara_summary.txt')
        with open(output_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        assert "Test rule with no strings" in content
        assert "- Strings: (none)" in content


class TestCleanFilename:
    """Test suite for the _clean_filename helper function."""
    
    def test_clean_filename_with_exclamation(self):
        """Test cleaning Windows path with APK extraction marker."""
        input_path = "C:\\Users\\New-P16v-002\\Desktop\\Day1\\Round3\\non-malicious\\uni.app.UNIA804A35\\uni.app.UNIA804A35.apk!classes.dex"
        expected = "classes.dex"
        result = _clean_filename(input_path)
        assert result == expected
    
    def test_clean_filename_with_nested_exclamation(self):
        """Test cleaning path with nested APK structure."""
        input_path = "C:\\Path\\to\\app.apk!lib/arm64-v8a/libtest.so"
        expected = "lib/arm64-v8a/libtest.so"
        result = _clean_filename(input_path)
        assert result == expected
    
    def test_clean_filename_with_backslash_only(self):
        """Test cleaning Windows path without exclamation."""
        input_path = "C:\\Users\\test\\file.dex"
        expected = "file.dex"
        result = _clean_filename(input_path)
        assert result == expected
    
    def test_clean_filename_with_forward_slash_only(self):
        """Test cleaning Unix-style path without exclamation."""
        input_path = "/home/user/analysis/file.dex"
        expected = "file.dex"
        result = _clean_filename(input_path)
        assert result == expected
    
    def test_clean_filename_simple_name(self):
        """Test with just a filename (no path)."""
        input_path = "classes.dex"
        expected = "classes.dex"
        result = _clean_filename(input_path)
        assert result == expected
    
    def test_clean_filename_all_data(self):
        """Test with special ALL_DATA filename."""
        input_path = "ALL_DATA"
        expected = "ALL_DATA"
        result = _clean_filename(input_path)
        assert result == expected


if __name__ == "__main__":
    # Run the tests when executed directly
    pytest.main([__file__, "-v"])
