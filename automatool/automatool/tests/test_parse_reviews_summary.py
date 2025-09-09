import os
import json
import tempfile
import shutil
import pytest
from io import StringIO
from unittest.mock import patch
import sys

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scripts.automations.parse_reviews_summary import parse_reviews_to_summary


class TestParseReviewsToSummary:
    """Test suite for the parse_reviews_to_summary function."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def sample_reviews_data(self):
        """Sample reviews data for testing."""
        return [
            {
                "review_id": "1",
                "user_name": "John Doe",
                "content": "Great app!",
                "score": 5,
                "translated_content": "Great app!",
                "country_code": "US"
            },
            {
                "review_id": "2",
                "user_name": "Jane Smith",
                "content": "Not working",
                "score": 1,
                "translated_content": "Not working",
                "country_code": "US"
            },
            {
                "review_id": "3",
                "user_name": "Pierre Dupont",
                "content": "Très bien",
                "score": 4,
                "translated_content": "Very good",
                "country_code": "FR"
            }
        ]
    
    @pytest.fixture
    def create_reviews_file(self, temp_dir, sample_reviews_data):
        """Create a reviews.json file in the temporary directory."""
        reviews_file = os.path.join(temp_dir, "reviews.json")
        with open(reviews_file, 'w', encoding='utf-8') as f:
            json.dump(sample_reviews_data, f, ensure_ascii=False, indent=2)
        return reviews_file
    
    def test_successful_parsing_normal_mode(self, temp_dir, create_reviews_file):
        """Test successful parsing of reviews in normal mode."""
        result = parse_reviews_to_summary(temp_dir, verbose=False)
        
        # Check that result is a string and contains expected content
        assert isinstance(result, str)
        assert "=== REVIEWS SUMMARY ===" in result
        assert "Most Reviews From: US (2 reviews)" in result
        assert "1. User: John Doe | Country: US" in result
        assert "   Review: Great app!" in result
        assert "2. User: Jane Smith | Country: US" in result
        assert "   Review: Not working" in result
        assert "3. User: Pierre Dupont | Country: FR" in result
        assert "   Review: Very good" in result
        
        # Check that summary file was created
        summary_file = os.path.join(temp_dir, "reviews_summary.txt")
        assert os.path.exists(summary_file)
        
        # Check file contents
        with open(summary_file, 'r', encoding='utf-8') as f:
            file_content = f.read()
        assert file_content == result
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_successful_parsing_verbose_mode(self, mock_stdout, temp_dir, create_reviews_file):
        """Test successful parsing of reviews in verbose mode."""
        result = parse_reviews_to_summary(temp_dir, verbose=True)
        
        # Check that result contains verbose information
        assert isinstance(result, str)
        assert "=== REVIEWS SUMMARY ===" in result
        assert "Most Reviews From: US (2 reviews - 66.7% of total)" in result
        assert "Country Distribution:" in result
        assert "- US: 2 reviews (66.7%)" in result
        assert "- FR: 1 reviews (33.3%)" in result
        
        # Check verbose output was printed
        output = mock_stdout.getvalue()
        assert "[DEBUG] Parsing reviews from:" in output
        assert "[DEBUG] Output summary to:" in output
        assert "[DEBUG] Loaded 3 reviews from JSON" in output
        assert "[DEBUG] Successfully processed 3 reviews" in output
        assert "[DEBUG] Most common country: US (2 reviews)" in output
        assert "[DEBUG] Total countries: 2" in output
        assert "[DEBUG] ✅ Summary written to" in output
        assert "✅ Reviews summary created:" in output
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_missing_reviews_file(self, mock_stdout, temp_dir):
        """Test behavior when reviews.json file is missing."""
        result = parse_reviews_to_summary(temp_dir, verbose=False)
        
        expected_error = f"❌ ERROR: reviews.json not found in {temp_dir}"
        assert result == expected_error
        
        # Check error was printed
        output = mock_stdout.getvalue()
        assert expected_error in output
    
    def test_invalid_json_file(self, temp_dir):
        """Test behavior when reviews.json contains invalid JSON."""
        # Create invalid JSON file
        invalid_json_file = os.path.join(temp_dir, "reviews.json")
        with open(invalid_json_file, 'w', encoding='utf-8') as f:
            f.write("{ invalid json content")
        
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = parse_reviews_to_summary(temp_dir, verbose=False)
        
        assert result.startswith("❌ ERROR: Invalid JSON in reviews file:")
        
        # Check error was printed
        output = mock_stdout.getvalue()
        assert "❌ ERROR: Invalid JSON in reviews file:" in output
    
    def test_empty_reviews_list(self, temp_dir):
        """Test behavior when reviews.json contains an empty list."""
        # Create empty reviews file
        reviews_file = os.path.join(temp_dir, "reviews.json")
        with open(reviews_file, 'w', encoding='utf-8') as f:
            json.dump([], f)
        
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = parse_reviews_to_summary(temp_dir, verbose=False)
        
        expected_warning = "⚠️  WARNING: No valid reviews found to process"
        assert result == expected_warning
        
        # Check warning was printed
        output = mock_stdout.getvalue()
        assert expected_warning in output
    
    def test_reviews_with_missing_required_fields(self, temp_dir):
        """Test behavior when some reviews have missing required fields."""
        incomplete_reviews = [
            {
                "review_id": "1",
                "user_name": "John Doe",
                "translated_content": "Great app!",
                "country_code": "US"
            },
            {
                "review_id": "2",
                "user_name": "Jane Smith",
                # Missing translated_content
                "country_code": "US"
            },
            {
                "review_id": "3",
                # Missing user_name
                "translated_content": "Good",
                "country_code": "FR"
            },
            {
                "review_id": "4",
                "user_name": "Valid User",
                "translated_content": "Valid review",
                "country_code": "DE"
            }
        ]
        
        reviews_file = os.path.join(temp_dir, "reviews.json")
        with open(reviews_file, 'w', encoding='utf-8') as f:
            json.dump(incomplete_reviews, f)
        
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = parse_reviews_to_summary(temp_dir, verbose=True)
        
        # Should only process reviews with all required fields
        assert "1. User: John Doe | Country: US" in result
        assert "2. User: Valid User | Country: DE" in result
        assert "Jane Smith" not in result  # Should be skipped
        
        # Check verbose output shows skipped reviews
        output = mock_stdout.getvalue()
        assert "[DEBUG] Skipping review with missing required fields: 2" in output
        assert "[DEBUG] Skipping review with missing required fields: 3" in output
        assert "[DEBUG] Successfully processed 2 reviews" in output
    
    def test_single_review_country_analysis(self, temp_dir):
        """Test country analysis with only one review."""
        single_review = [
            {
                "review_id": "1",
                "user_name": "Solo User",
                "translated_content": "Only review",
                "country_code": "JP"
            }
        ]
        
        reviews_file = os.path.join(temp_dir, "reviews.json")
        with open(reviews_file, 'w', encoding='utf-8') as f:
            json.dump(single_review, f)
        
        result = parse_reviews_to_summary(temp_dir, verbose=True)
        
        assert "Most Reviews From: JP (1 reviews - 100.0% of total)" in result
        assert "Country Distribution:" in result
        assert "- JP: 1 reviews (100.0%)" in result
    
    def test_multiple_countries_equal_distribution(self, temp_dir):
        """Test country analysis with equal distribution."""
        equal_distribution_reviews = [
            {
                "review_id": "1",
                "user_name": "User1",
                "translated_content": "Review1",
                "country_code": "US"
            },
            {
                "review_id": "2",
                "user_name": "User2",
                "translated_content": "Review2",
                "country_code": "FR"
            },
            {
                "review_id": "3",
                "user_name": "User3",
                "translated_content": "Review3",
                "country_code": "DE"
            }
        ]
        
        reviews_file = os.path.join(temp_dir, "reviews.json")
        with open(reviews_file, 'w', encoding='utf-8') as f:
            json.dump(equal_distribution_reviews, f)
        
        result = parse_reviews_to_summary(temp_dir, verbose=True)
        
        # Should pick first country alphabetically as most common when tied
        # Counter.most_common() returns in order of first occurrence when counts are equal
        assert "Most Reviews From: US (1 reviews - 33.3% of total)" in result
        assert "Country Distribution:" in result
        assert "- US: 1 reviews (33.3%)" in result
        assert "- FR: 1 reviews (33.3%)" in result
        assert "- DE: 1 reviews (33.3%)" in result
    
    def test_file_write_permission_error(self, temp_dir, create_reviews_file):
        """Test behavior when unable to write summary file due to permissions."""
        # Mock open to raise IOError when writing
        with patch('builtins.open', side_effect=[
            open(create_reviews_file, 'r', encoding='utf-8'),  # Reading reviews.json succeeds
            IOError("Permission denied")  # Writing summary file fails
        ]):
            with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
                result = parse_reviews_to_summary(temp_dir, verbose=False)
        
        expected_error = "❌ ERROR: Failed to write summary file: Permission denied"
        assert result == expected_error
        
        # Check error was printed
        output = mock_stdout.getvalue()
        assert expected_error in output
    
    def test_unexpected_exception_handling(self, temp_dir):
        """Test handling of unexpected exceptions."""
        # Create a valid reviews file first
        reviews_file = os.path.join(temp_dir, "reviews.json")
        with open(reviews_file, 'w', encoding='utf-8') as f:
            json.dump([{"user_name": "Test", "translated_content": "Test", "country_code": "US"}], f)
        
        # Mock json.load to raise an unexpected exception
        with patch('json.load', side_effect=RuntimeError("Unexpected error")):
            with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
                result = parse_reviews_to_summary(temp_dir, verbose=True)
        
        assert result.startswith("❌ ERROR: Failed to parse reviews: Unexpected error")
        
        # Check verbose error output
        output = mock_stdout.getvalue()
        assert "❌ ERROR: Failed to parse reviews: Unexpected error" in output
        assert "[DEBUG] Exception details: RuntimeError: Unexpected error" in output
    
    def test_unicode_content_handling(self, temp_dir):
        """Test handling of Unicode content in reviews."""
        unicode_reviews = [
            {
                "review_id": "1",
                "user_name": "用户名",
                "translated_content": "这是一个很好的应用程序",
                "country_code": "CN"
            },
            {
                "review_id": "2",
                "user_name": "مستخدم",
                "translated_content": "تطبيق رائع",
                "country_code": "AE"
            },
            {
                "review_id": "3",
                "user_name": "Пользователь",
                "translated_content": "Отличное приложение",
                "country_code": "RU"
            }
        ]
        
        reviews_file = os.path.join(temp_dir, "reviews.json")
        with open(reviews_file, 'w', encoding='utf-8') as f:
            json.dump(unicode_reviews, f, ensure_ascii=False)
        
        result = parse_reviews_to_summary(temp_dir, verbose=False)
        
        # Check Unicode content is preserved
        assert "1. User: 用户名 | Country: CN" in result
        assert "   Review: 这是一个很好的应用程序" in result
        assert "2. User: مستخدم | Country: AE" in result
        assert "   Review: تطبيق رائع" in result
        assert "3. User: Пользователь | Country: RU" in result
        assert "   Review: Отличное приложение" in result
        
        # Check that summary file was created with proper encoding
        summary_file = os.path.join(temp_dir, "reviews_summary.txt")
        assert os.path.exists(summary_file)
        
        with open(summary_file, 'r', encoding='utf-8') as f:
            file_content = f.read()
        assert "用户名" in file_content
        assert "مستخدم" in file_content
        assert "Пользователь" in file_content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
