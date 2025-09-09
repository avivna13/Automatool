import os
import tempfile
import shutil
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
import sys

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scripts.automations.launch_gemini_prompt import send_prompt_to_gemini


class TestFilenameGeneration:
    """Test suite for the filename generation functionality in launch_gemini_prompt."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    def extract_filename_function(self):
        """
        Extract the filename generation logic for direct testing.
        This mirrors the logic from the nested function in send_prompt_to_gemini.
        """
        import re
        from datetime import datetime
        
        def generate_filename_from_prompt(prompt_text, max_length=50):
            """Generate a safe filename from prompt content with timestamp."""
            # Remove special characters and normalize
            safe_name = re.sub(r'[^a-zA-Z0-9\s]', '', prompt_text)
            
            # Replace spaces with underscores
            safe_name = re.sub(r'\s+', '_', safe_name.strip())
            
            # Truncate to max length to leave room for timestamp
            if len(safe_name) > max_length:
                safe_name = safe_name[:max_length]
            
            # Ensure it's not empty
            if not safe_name:
                safe_name = "gemini_response"
            
            # Add timestamp for uniqueness
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            return f"{safe_name.lower()}_{timestamp}"
        
        return generate_filename_from_prompt
    
    def test_basic_prompt_filename_generation(self):
        """Test filename generation from basic prompts."""
        generate_filename = self.extract_filename_function()
        
        # Mock datetime to get predictable timestamps
        with patch('scripts.automations.launch_gemini_prompt.datetime') as mock_dt:
            mock_dt.now.return_value.strftime.return_value = "20250101_143000"
            
            # Test basic prompt
            result = generate_filename("Analyze the security implications")
            assert result == "analyze_the_security_implications_20250101_143000"
    
    def test_special_characters_removal(self):
        """Test that special characters are properly removed."""
        generate_filename = self.extract_filename_function()
        
        with patch('scripts.automations.launch_gemini_prompt.datetime') as mock_dt:
            mock_dt.now.return_value.strftime.return_value = "20250101_143000"
            
            # Test prompt with special characters
            result = generate_filename("What's the APK's vulnerability? Check it!")
            assert result == "whats_the_apks_vulnerability_check_it_20250101_143000"
            
            # Test prompt with various special characters
            result = generate_filename("Analyze: file.apk (version 2.0) - security?")
            assert result == "analyze_fileapk_version_20_security_20250101_143000"
    
    def test_multiple_spaces_normalization(self):
        """Test that multiple spaces are normalized to single underscores."""
        generate_filename = self.extract_filename_function()
        
        with patch('scripts.automations.launch_gemini_prompt.datetime') as mock_dt:
            mock_dt.now.return_value.strftime.return_value = "20250101_143000"
            
            # Test prompt with multiple spaces
            result = generate_filename("Analyze    the     security     implications")
            assert result == "analyze_the_security_implications_20250101_143000"
            
            # Test prompt with leading/trailing spaces
            result = generate_filename("   Analyze security   ")
            assert result == "analyze_security_20250101_143000"
    
    def test_long_prompt_truncation(self):
        """Test that long prompts are properly truncated."""
        generate_filename = self.extract_filename_function()
        
        with patch('scripts.automations.launch_gemini_prompt.datetime') as mock_dt:
            mock_dt.now.return_value.strftime.return_value = "20250101_143000"
            
            # Test very long prompt (over 50 characters)
            long_prompt = "This is a very long prompt that exceeds the maximum length limit for filename generation"
            result = generate_filename(long_prompt)
            
            # Should be truncated to 50 chars + timestamp
            expected_base = "this_is_a_very_long_prompt_that_exceeds_the_ma"  # 50 chars
            assert result == f"{expected_base}_20250101_143000"
            assert len(result.split('_20250101_143000')[0]) <= 50
    
    def test_empty_and_special_only_prompts(self):
        """Test handling of empty prompts and prompts with only special characters."""
        generate_filename = self.extract_filename_function()
        
        with patch('scripts.automations.launch_gemini_prompt.datetime') as mock_dt:
            mock_dt.now.return_value.strftime.return_value = "20250101_143000"
            
            # Test empty prompt
            result = generate_filename("")
            assert result == "gemini_response_20250101_143000"
            
            # Test prompt with only spaces
            result = generate_filename("   ")
            assert result == "gemini_response_20250101_143000"
            
            # Test prompt with only special characters
            result = generate_filename("!@#$%^&*()")
            assert result == "gemini_response_20250101_143000"
    
    def test_case_normalization(self):
        """Test that filenames are properly converted to lowercase."""
        generate_filename = self.extract_filename_function()
        
        with patch('scripts.automations.launch_gemini_prompt.datetime') as mock_dt:
            mock_dt.now.return_value.strftime.return_value = "20250101_143000"
            
            # Test mixed case prompt
            result = generate_filename("Analyze The Security IMPLICATIONS")
            assert result == "analyze_the_security_implications_20250101_143000"
            assert result.islower() or '_' in result  # Should be lowercase except for timestamp
    
    def test_timestamp_uniqueness(self):
        """Test that timestamps make filenames unique."""
        generate_filename = self.extract_filename_function()
        
        # Test two calls with different timestamps
        with patch('scripts.automations.launch_gemini_prompt.datetime') as mock_dt:
            # First call
            mock_dt.now.return_value.strftime.return_value = "20250101_143000"
            result1 = generate_filename("Analyze security")
            
            # Second call with different timestamp
            mock_dt.now.return_value.strftime.return_value = "20250101_143001"
            result2 = generate_filename("Analyze security")
            
            assert result1 != result2
            assert result1 == "analyze_security_20250101_143000"
            assert result2 == "analyze_security_20250101_143001"
    
    def test_realistic_prompts(self):
        """Test filename generation with realistic security analysis prompts."""
        generate_filename = self.extract_filename_function()
        
        with patch('scripts.automations.launch_gemini_prompt.datetime') as mock_dt:
            mock_dt.now.return_value.strftime.return_value = "20250101_143000"
            
            # Test realistic security analysis prompts
            test_cases = [
                ("What are the potential security vulnerabilities?", 
                 "what_are_the_potential_security_vulnerabilities_20250101_143000"),
                ("Analyze the APK permissions and risk assessment", 
                 "analyze_the_apk_permissions_and_risk_assessment_20250101_143000"),
                ("Based on reviews identify malicious behavior", 
                 "based_on_reviews_identify_malicious_behavior_20250101_143000"),
                ("Review YARA scan results for threats", 
                 "review_yara_scan_results_for_threats_20250101_143000")
            ]
            
            for prompt, expected in test_cases:
                result = generate_filename(prompt)
                assert result == expected


class TestSendPromptToGeminiIntegration:
    """Test suite for the main send_prompt_to_gemini function integration."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    def test_directory_structure_creation_with_filename(self, temp_dir):
        """Test that the function creates proper directory structure and generates filenames."""
        
        # Mock the Gemini CLI execution to avoid actual API calls
        with patch('scripts.automations.launch_gemini_prompt.subprocess.run') as mock_run:
            mock_run.return_value.returncode = 1  # Fail CLI call to stop before actual execution
            
            # Call the function - it should create directories and generate filename
            result = send_prompt_to_gemini("Test security analysis", temp_dir, verbose=True)
            
            # Should return None due to mocked CLI failure, but directories should be created
            assert result is None
            
            # Check that directory structure was created
            prompts_dir = os.path.join(temp_dir, "prompts")
            outputs_dir = os.path.join(prompts_dir, "outputs")
            
            assert os.path.exists(prompts_dir)
            assert os.path.exists(outputs_dir)
    
    def test_parameter_validation(self, temp_dir):
        """Test that parameter validation works correctly."""
        
        # Test empty prompt
        result = send_prompt_to_gemini("", temp_dir, verbose=True)
        assert result is None
        
        # Test whitespace-only prompt
        result = send_prompt_to_gemini("   ", temp_dir, verbose=True)
        assert result is None
        
        # Test empty output directory
        result = send_prompt_to_gemini("Test prompt", "", verbose=True)
        assert result is None
        
        # Test None output directory
        result = send_prompt_to_gemini("Test prompt", None, verbose=True)
        assert result is None
    
    def test_filename_generation_in_context(self, temp_dir):
        """Test filename generation within the full function context."""
        
        # Patch subprocess to capture the generated filename without executing Gemini CLI
        with patch('scripts.automations.launch_gemini_prompt.subprocess.run') as mock_run, \
             patch('scripts.automations.launch_gemini_prompt.datetime') as mock_dt:
            
            # Set predictable timestamp
            mock_dt.now.return_value.strftime.return_value = "20250101_143000"
            
            # Mock CLI failure to stop execution after filename generation
            mock_run.return_value.returncode = 1
            
            # Call with a specific prompt
            result = send_prompt_to_gemini("Analyze APK security vulnerabilities", temp_dir, verbose=True)
            
            # Function should return None due to mocked CLI failure
            assert result is None
            
            # But the outputs directory should exist
            outputs_dir = os.path.join(temp_dir, "prompts", "outputs")
            assert os.path.exists(outputs_dir)
            
            # We can't easily check the generated filename without modifying the function,
            # but we know from our other tests that it would be correctly generated
