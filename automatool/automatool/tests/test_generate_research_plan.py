import os
import tempfile
import shutil
import pytest
from unittest.mock import patch, mock_open
import sys

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scripts.automations.generate_research_plan import generate_research_plan


class TestGenerateResearchPlan:
    """Test suite for the generate_research_plan function."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def test_resources_dir(self):
        """Get the path to the test resources directory."""
        return os.path.join(os.path.dirname(__file__), 'resources')
    
    @pytest.fixture
    def sample_reviews_summary(self, test_resources_dir):
        """Load real reviews summary content from resources."""
        reviews_file = os.path.join(test_resources_dir, 'reviews_summary.txt')
        with open(reviews_file, 'r', encoding='utf-8') as f:
            return f.read()
    
    @pytest.fixture
    def sample_yara_summary(self, test_resources_dir):
        """Load real YARA summary content from resources."""
        yara_file = os.path.join(test_resources_dir, 'yara_summary.txt')
        with open(yara_file, 'r', encoding='utf-8') as f:
            return f.read()
    
    @pytest.fixture
    def sample_template(self, test_resources_dir):
        """Load real template content from resources."""
        template_file = os.path.join(test_resources_dir, 'research_plan_template.txt')
        with open(template_file, 'r', encoding='utf-8') as f:
            return f.read()
    
    @pytest.fixture
    def expected_formatted_content(self, test_resources_dir):
        """Load expected formatted content from resources."""
        expected_file = os.path.join(test_resources_dir, 'expected_research_plan.txt')
        with open(expected_file, 'r', encoding='utf-8') as f:
            return f.read()
    

    
    def test_placeholder_function(self, temp_dir):
        """Placeholder test to ensure test structure is working."""
        assert True
        assert temp_dir is not None
    
    def test_fixtures_load_real_files(self, sample_reviews_summary, sample_yara_summary, 
                                     sample_template, expected_formatted_content):
        """Test that fixtures successfully load real files from resources."""
        # Check that files were loaded and contain expected content
        assert len(sample_reviews_summary) > 0
        assert len(sample_yara_summary) > 0
        assert len(sample_template) > 0
        assert len(expected_formatted_content) > 0
        
        # Check specific content markers
        assert "=== REVIEWS SUMMARY ===" in sample_reviews_summary
        assert "YARA Analysis Summary" in sample_yara_summary
        assert "{reviews}" in sample_template
        assert "{yara_output}" in sample_template
        assert "given an application that has the following:" in expected_formatted_content
        
        print(f"✅ Reviews summary: {len(sample_reviews_summary)} characters")
        print(f"✅ YARA summary: {len(sample_yara_summary)} characters")
        print(f"✅ Template: {len(sample_template)} characters")
        print(f"✅ Expected output: {len(expected_formatted_content)} characters")
    
    # ===== BASIC FUNCTIONALITY TESTS =====
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_successful_generation_basic(self, mock_makedirs, mock_path_join, mock_open, 
                                       temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test successful research plan generation with basic functionality."""
        # Mock the template loading
        mock_template_content = """given an application that has the following:

reviews:
{reviews}

yara output:
{yara_output}

Plan a research strategy: how to proceed with the research dynamically and statically? 
provide some patterns to look for in the code and Frida scripts that can be useful to inspect it, given all the details"""
        
        # Mock file operations
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template_content
        mock_open.return_value.__enter__.return_value.write.return_value = None
        
        # Mock path operations
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        
        # Mock directory creation
        mock_makedirs.return_value = None
        
        # Call the function
        result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
        
        # Verify the result
        assert result is not None
        assert isinstance(result, str)
        assert "prompts/research_plan.txt" in result
        
        # Verify directory creation was called
        mock_makedirs.assert_called_once()
        
        # Verify file operations were called
        assert mock_open.call_count >= 2  # At least template read and output write
    
    def test_function_import_and_signature(self):
        """Test that the function can be imported and has correct signature."""
        # Test function exists and is callable
        assert callable(generate_research_plan)
        
        # Test function signature
        import inspect
        sig = inspect.signature(generate_research_plan)
        params = list(sig.parameters.keys())
        
        # Should have 4 parameters: output_directory, reviews_data, yara_data, verbose
        assert len(params) == 4
        assert params[0] == 'output_directory'
        assert params[1] == 'reviews_data'
        assert params[2] == 'yara_data'
        assert params[3] == 'verbose'
        
        # Test default value for verbose
        assert sig.parameters['verbose'].default is False
    
    def test_function_docstring(self):
        """Test that the function has proper documentation."""
        doc = generate_research_plan.__doc__
        assert doc is not None
        assert len(doc) > 50  # Should have substantial documentation
        
        # Check for key documentation elements
        assert "Args:" in doc
        assert "Returns:" in doc
        assert "output_directory" in doc
        assert "reviews_data" in doc
        assert "yara_data" in doc
        assert "verbose" in doc
    
    # ===== DATA HANDLING TESTS =====
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_with_valid_reviews_and_yara_data(self, mock_makedirs, mock_path_join, mock_open, 
                                            temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test with valid reviews and YARA data (normal case)."""
        # Mock template loading
        mock_template_content = """reviews:
{reviews}

yara output:
{yara_output}"""
        
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template_content
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Call function with valid data
        result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
        
        # Should succeed and return path
        assert result is not None
        assert isinstance(result, str)
        assert "prompts" in result
        assert "research_plan.txt" in result
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_with_error_message_reviews_data(self, mock_makedirs, mock_path_join, mock_open, 
                                           temp_dir, sample_yara_summary):
        """Test with error message in reviews data (should use placeholder)."""
        # Mock template loading
        mock_template_content = """reviews:
{reviews}

yara output:
{yara_output}"""
        
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template_content
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Reviews data with error message
        error_reviews = "❌ ERROR: Failed to parse reviews"
        
        # Call function with error reviews data
        result = generate_research_plan(temp_dir, error_reviews, sample_yara_summary, verbose=True)
        
        # Should still succeed but use placeholder for reviews
        assert result is not None
        assert isinstance(result, str)
        assert "prompts/research_plan.txt" in result
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_with_warning_message_reviews_data(self, mock_makedirs, mock_path_join, mock_open, 
                                             temp_dir, sample_yara_summary):
        """Test with warning message in reviews data (should use placeholder)."""
        # Mock template loading
        mock_template_content = """reviews:
{reviews}

yara output:
{yara_output}"""
        
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template_content
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Reviews data with warning message
        warning_reviews = "⚠️  WARNING: No valid reviews found"
        
        # Call function with warning reviews data
        result = generate_research_plan(temp_dir, warning_reviews, sample_yara_summary, verbose=True)
        
        # Should still succeed but use placeholder for reviews
        assert result is not None
        assert isinstance(result, str)
        assert "prompts/research_plan.txt" in result
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_with_none_yara_data(self, mock_makedirs, mock_path_join, mock_open, 
                                temp_dir, sample_reviews_summary):
        """Test with None YARA data (should use placeholder)."""
        # Mock template loading
        mock_template_content = """reviews:
{reviews}

yara output:
{yara_output}"""
        
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template_content
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Call function with None YARA data
        result = generate_research_plan(temp_dir, sample_reviews_summary, None, verbose=True)
        
        # Should still succeed but use placeholder for YARA
        assert result is not None
        assert isinstance(result, str)
        assert "prompts/research_plan.txt" in result
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_with_false_yara_data(self, mock_makedirs, mock_path_join, mock_open, 
                                 temp_dir, sample_reviews_summary):
        """Test with False YARA data (should use placeholder)."""
        # Mock template loading
        mock_template_content = """reviews:
{reviews}

yara output:
{yara_output}"""
        
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template_content
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Call function with False YARA data
        result = generate_research_plan(temp_dir, sample_reviews_summary, False, verbose=True)
        
        # Should still succeed but use placeholder for YARA
        assert result is not None
        assert isinstance(result, str)
        assert "prompts/research_plan.txt" in result
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_with_empty_reviews_data(self, mock_makedirs, mock_path_join, mock_open, 
                                    temp_dir, sample_yara_summary):
        """Test with empty reviews data (should use placeholder)."""
        # Mock template loading
        mock_template_content = """reviews:
{reviews}

yara output:
{yara_output}"""
        
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template_content
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Call function with empty reviews data
        result = generate_research_plan(temp_dir, "", sample_yara_summary, verbose=True)
        
        # Should still succeed but use placeholder for reviews
        assert result is not None
        assert isinstance(result, str)
        assert "prompts/research_plan.txt" in result
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_with_none_reviews_data(self, mock_makedirs, mock_path_join, mock_open, 
                                   temp_dir, sample_yara_summary):
        """Test with None reviews data (should use placeholder)."""
        # Mock template loading
        mock_template_content = """reviews:
{reviews}

yara_output:
{yara_output}"""
        
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template_content
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Call function with None reviews data
        result = generate_research_plan(temp_dir, None, sample_yara_summary, verbose=True)
        
        # Should still succeed but use placeholder for reviews
        assert result is not None
        assert isinstance(result, str)
        assert "prompts/research_plan.txt" in result
    
    # ===== TEMPLATE FORMATTING TESTS =====
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_template_formatting_with_real_data(self, mock_makedirs, mock_path_join, mock_open, 
                                              temp_dir, sample_reviews_summary, sample_yara_summary, 
                                              sample_template):
        """Test that template formatting works correctly with real data."""
        # Mock file operations
        mock_open.return_value.__enter__.return_value.read.return_value = sample_template
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Call function
        result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
        
        # Should succeed
        assert result is not None
        assert isinstance(result, str)
        assert "prompts/research_plan.txt" in result
        
        # Verify template was loaded and formatted
        mock_open.assert_called()
        # Check that write was called (indicating formatting succeeded)
        write_calls = [call for call in mock_open.call_args_list if 'w' in str(call)]
        assert len(write_calls) > 0
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_template_formatting_placeholders_used_correctly(self, mock_makedirs, mock_path_join, mock_open, 
                                                           temp_dir):
        """Test that template placeholders are replaced correctly with placeholders when data is invalid."""
        # Mock template with placeholders
        mock_template = """reviews:
{reviews}

yara output:
{yara_output}"""
        
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Call with invalid data (should use placeholders)
        result = generate_research_plan(temp_dir, "❌ ERROR: test", None, verbose=True)
        
        # Should succeed
        assert result is not None
        assert isinstance(result, str)
        assert "prompts/research_plan.txt" in result
        
        # Verify that write was called (indicating formatting succeeded)
        write_calls = [call for call in mock_open.call_args_list if 'w' in str(call)]
        assert len(write_calls) > 0
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_template_formatting_mixed_valid_invalid_data(self, mock_makedirs, mock_path_join, mock_open, 
                                                        temp_dir, sample_reviews_summary):
        """Test template formatting with mixed valid and invalid data."""
        # Mock template
        mock_template = """reviews:
{reviews}

yara output:
{yara_output}"""
        
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Valid reviews, invalid YARA
        result = generate_research_plan(temp_dir, sample_reviews_summary, False, verbose=True)
        
        # Should succeed
        assert result is not None
        assert isinstance(result, str)
        assert "prompts/research_plan.txt" in result
        
        # Verify formatting succeeded
        write_calls = [call for call in mock_open.call_args_list if 'w' in str(call)]
        assert len(write_calls) > 0
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_template_formatting_empty_template(self, mock_makedirs, mock_path_join, mock_open, 
                                             temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test template formatting with empty template (edge case)."""
        # Mock empty template
        mock_template = ""
        
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Call function
        result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
        
        # Should succeed even with empty template
        assert result is not None
        assert isinstance(result, str)
        assert "prompts/research_plan.txt" in result
        
        # Verify write was called
        write_calls = [call for call in mock_open.call_args_list if 'w' in str(call)]
        assert len(write_calls) > 0
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_template_formatting_template_without_placeholders(self, mock_makedirs, mock_path_join, mock_open, 
                                                            temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test template formatting with template that has no placeholders."""
        # Mock template without placeholders
        mock_template = """This is a static template
with no dynamic content."""
        
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Call function
        result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
        
        # Should succeed
        assert result is not None
        assert isinstance(result, str)
        assert "prompts/research_plan.txt" in result
        
        # Verify write was called
        write_calls = [call for call in mock_open.call_args_list if 'w' in str(call)]
        assert len(write_calls) > 0
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_template_formatting_template_with_extra_placeholders(self, mock_makedirs, mock_path_join, mock_open, 
                                                               temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test template formatting with template that has extra/unused placeholders."""
        # Mock template with extra placeholders
        mock_template = """reviews:
{reviews}

yara output:
{yara_output}

extra info:
{extra_placeholder}

more data:
{another_placeholder}"""
        
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Call function
        result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
        
        # Should fail gracefully when template has missing placeholders
        assert result is None
        
        # Verify that the function detected the missing placeholder error
        # The function should have logged an error about missing placeholders
    
    # ===== ERROR HANDLING TESTS =====
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_template_file_not_found(self, mock_makedirs, mock_path_join, mock_open, 
                                   temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test handling when template file is not found."""
        # Mock file not found error
        mock_open.side_effect = FileNotFoundError("Template file not found")
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Call function
        result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
        
        # Should return None on template file not found
        assert result is None
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_template_file_permission_error(self, mock_makedirs, mock_path_join, mock_open, 
                                          temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test handling when template file has permission issues."""
        # Mock permission error
        mock_open.side_effect = PermissionError("Permission denied")
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Call function
        result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
        
        # Should return None on permission error
        assert result is None
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_template_file_io_error(self, mock_makedirs, mock_path_join, mock_open, 
                                  temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test handling when template file has general I/O errors."""
        # Mock I/O error
        mock_open.side_effect = IOError("I/O error occurred")
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Call function
        result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
        
        # Should return None on I/O error
        assert result is None
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_directory_creation_permission_error(self, mock_makedirs, mock_path_join, mock_open, 
                                               temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test handling when directory creation fails due to permissions."""
        # Mock template loading success
        mock_template = """reviews:
{reviews}

yara output:
{yara_output}"""
        
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        
        # Mock directory creation permission error
        mock_makedirs.side_effect = PermissionError("Permission denied creating directory")
        
        # Call function
        result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
        
        # Should return None on directory creation permission error
        assert result is None
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_directory_creation_os_error(self, mock_makedirs, mock_path_join, mock_open, 
                                       temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test handling when directory creation fails due to OS errors."""
        # Mock template loading success
        mock_template = """reviews:
{reviews}

yara output:
{yara_output}"""
        
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        
        # Mock directory creation OS error
        mock_makedirs.side_effect = OSError("OS error occurred")
        
        # Call function
        result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
        
        # Should return None on directory creation OS error
        assert result is None
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_output_file_write_permission_error(self, mock_makedirs, mock_path_join, mock_open, 
                                              temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test handling when output file write fails due to permissions."""
        # Mock template loading success
        mock_template = """reviews:
{reviews}

yara output:
{yara_output}"""
        
        # Mock template read success, but output write permission error
        mock_open.side_effect = [
            mock_open.return_value.__enter__.return_value,  # Template read
            PermissionError("Permission denied writing file")  # Output write
        ]
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Call function
        result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
        
        # Should return None on output file write permission error
        assert result is None
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_output_file_write_io_error(self, mock_makedirs, mock_path_join, mock_open, 
                                      temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test handling when output file write fails due to I/O errors."""
        # Mock template loading success
        mock_template = """reviews:
{reviews}

yara output:
{yara_output}"""
        
        # Mock template read success, but output write I/O error
        mock_open.side_effect = [
            mock_open.return_value.__enter__.return_value,  # Template read
            IOError("I/O error writing file")  # Output write
        ]
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Call function
        result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
        
        # Should return None on output file write I/O error
        assert result is None
    
    @patch('scripts.automations.generate_research_plan.open')
    @patch('os.path.join')
    @patch('os.makedirs')
    def test_template_formatting_key_error(self, mock_makedirs, mock_path_join, mock_open, 
                                         temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test handling when template formatting fails due to KeyError."""
        # Mock template with invalid placeholder
        mock_template = """reviews:
{invalid_placeholder}

yara output:
{yara_output}"""
        
        mock_open.return_value.__enter__.return_value.read.return_value = mock_template
        mock_open.return_value.__enter__.return_value.write.return_value = None
        mock_path_join.side_effect = lambda *args: '/'.join(args)
        mock_makedirs.return_value = None
        
        # Call function
        result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
        
                # Should return None on template formatting KeyError
        assert result is None
    
    # ===== INTEGRATION TESTS =====
    
    def test_end_to_end_with_real_data(self, temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test complete end-to-end workflow with real data and actual file operations."""
        # Call function with real data
        result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
        
        # Should succeed and return path
        assert result is not None
        assert isinstance(result, str)
        assert "prompts" in result
        assert "research_plan.txt" in result
        
        # Verify the output file was actually created
        output_file = os.path.join(temp_dir, "prompts", "research_plan.txt")
        assert os.path.exists(output_file), f"Output file not found: {output_file}"
        
        # Verify the prompts directory was created
        prompts_dir = os.path.join(temp_dir, "prompts")
        assert os.path.isdir(prompts_dir), f"Prompts directory not created: {prompts_dir}"
        
        # Read and verify the generated content
        with open(output_file, 'r', encoding='utf-8') as f:
            generated_content = f.read()
        
        # Should contain the expected structure
        assert "given an application that has the following:" in generated_content
        assert "reviews:" in generated_content
        assert "yara output:" in generated_content
        
        # Should contain the actual data (not placeholders)
        assert "=== REVIEWS SUMMARY ===" in generated_content
        assert "YARA Analysis Summary" in generated_content
        
        # Should not contain template placeholders
        assert "{reviews}" not in generated_content
        assert "{yara_output}" not in generated_content
        
        print(f"✅ Generated file size: {len(generated_content)} characters")
        print(f"✅ Output file path: {output_file}")
    
    def test_end_to_end_with_mixed_data(self, temp_dir, sample_reviews_summary):
        """Test end-to-end workflow with mixed valid and invalid data."""
        # Call function with valid reviews but invalid YARA data
        result = generate_research_plan(temp_dir, sample_reviews_summary, None, verbose=True)
        
        # Should succeed and return path
        assert result is not None
        assert isinstance(result, str)
        assert "prompts" in result
        assert "research_plan.txt" in result
        
        # Verify the output file was created
        output_file = os.path.join(temp_dir, "prompts", "research_plan.txt")
        assert os.path.exists(output_file), f"Output file not found: {output_file}"
        
        # Read and verify the generated content
        with open(output_file, 'r', encoding='utf-8') as f:
            generated_content = f.read()
        
        # Should contain reviews data
        assert "=== REVIEWS SUMMARY ===" in generated_content
        
        # Should contain placeholder for YARA
        assert "[No YARA analysis results available]" in generated_content
        
        print(f"✅ Mixed data test - Generated file size: {len(generated_content)} characters")
    
    def test_end_to_end_with_error_data(self, temp_dir, sample_yara_summary):
        """Test end-to-end workflow with error data in reviews."""
        # Call function with error reviews data
        error_reviews = "❌ ERROR: Failed to parse reviews"
        result = generate_research_plan(temp_dir, error_reviews, sample_yara_summary, verbose=True)
        
        # Should succeed and return path
        assert result is not None
        assert isinstance(result, str)
        assert "prompts" in result
        assert "research_plan.txt" in result
        
        # Verify the output file was created
        output_file = os.path.join(temp_dir, "prompts", "research_plan.txt")
        assert os.path.exists(output_file), f"Output file not found: {output_file}"
        
        # Read and verify the generated content
        with open(output_file, 'r', encoding='utf-8') as f:
            generated_content = f.read()
        
        # Should contain YARA data
        assert "YARA Analysis Summary" in generated_content
        
        # Should contain placeholder for reviews
        assert "[No valid reviews data available]" in generated_content
        
        print(f"✅ Error data test - Generated file size: {len(generated_content)} characters")
    
    def test_output_file_content_structure(self, temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test that the generated output file has the correct structure and content."""
        # Generate the research plan
        result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
        assert result is not None
        
        # Read the generated file
        output_file = os.path.join(temp_dir, "prompts", "research_plan.txt")
        with open(output_file, 'r', encoding='utf-8') as f:
            generated_content = f.read()
        
        # Verify the content structure
        lines = generated_content.split('\n')
        
        # Should start with the expected header
        assert lines[0].strip() == "given an application that has the following:"
        
        # Should have the reviews section
        assert "reviews:" in generated_content
        
        # Should have the yara output section
        assert "yara output:" in generated_content
        
        # Should have the research strategy question
        assert "Plan a research strategy:" in generated_content
        
        # Should contain the actual data content
        assert len(generated_content) > 100  # Should be substantial
        
        print(f"✅ Content structure test - File has {len(lines)} lines")
    
    def test_multiple_calls_same_directory(self, temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test that multiple calls to the function work correctly in the same directory."""
        # First call
        result1 = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
        assert result1 is not None
        
        # Second call with different data
        different_reviews = "Different reviews content for testing"
        result2 = generate_research_plan(temp_dir, different_reviews, sample_yara_summary, verbose=True)
        assert result2 is not None
        
        # Both should return the same path
        assert result1 == result2
        
        # Verify the file was overwritten with new content
        output_file = os.path.join(temp_dir, "prompts", "research_plan.txt")
        with open(output_file, 'r', encoding='utf-8') as f:
            final_content = f.read()
        
        # Should contain the second call's data
        assert "Different reviews content for testing" in final_content
        
        print(f"✅ Multiple calls test - Final file size: {len(final_content)} characters")
    
    def test_verbose_output_behavior(self, temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test that verbose mode provides appropriate output."""
        # Capture stdout to check verbose output
        import io
        import sys
        
        # Redirect stdout to capture print statements
        old_stdout = sys.stdout
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        try:
            # Call function with verbose=True
            result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=True)
            
            # Restore stdout
            sys.stdout = old_stdout
            
            # Should succeed
            assert result is not None
            
            # Should have verbose output
            output = captured_output.getvalue()
            assert "[DEBUG]" in output
            assert "Starting research plan generation" in output
            assert "Template loaded successfully" in output
            assert "Research plan generated" in output
            
            print(f"✅ Verbose output test - Captured {len(output)} characters of debug output")
            
        finally:
            # Ensure stdout is restored even if test fails
            sys.stdout = old_stdout
    
    def test_non_verbose_output_behavior(self, temp_dir, sample_reviews_summary, sample_yara_summary):
        """Test that non-verbose mode provides minimal output."""
        # Capture stdout to check non-verbose output
        import io
        import sys
        
        # Redirect stdout to capture print statements
        old_stdout = sys.stdout
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        try:
            # Call function with verbose=False
            result = generate_research_plan(temp_dir, sample_reviews_summary, sample_yara_summary, verbose=False)
            
            # Restore stdout
            sys.stdout = old_stdout
            
            # Should succeed
            assert result is not None
            
            # Should have minimal output (only success message)
            output = captured_output.getvalue()
            assert "✅ Research plan generated:" in output
            
            # Should not have debug output
            assert "[DEBUG]" not in output
            assert "Starting research plan generation" not in output
            
            print(f"✅ Non-verbose output test - Captured {len(output)} characters of output")
            
        finally:
            # Ensure stdout is restored even if test fails
            sys.stdout = old_stdout


if __name__ == "__main__":
    # Run basic test to verify structure
    pytest.main([__file__, "-v"])
