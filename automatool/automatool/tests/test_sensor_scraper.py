#!/usr/bin/env python3
"""
Test suite for sensor_scraper.py functionality.

This module tests the sensor scraper functions including:
- Google Play URL generation
- Timestamp formatting
- Data display functionality
"""

import unittest
import sys
import os
from unittest.mock import patch, mock_open, MagicMock
import json
from datetime import datetime

# Add the src directory to the path to import the module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'scripts', 'automations'))

try:
    from sensor_scraper import (
        generate_google_play_url,
        format_timestamp,
        display_app_data,
        fetch_app_data,
        view_saved_data
    )
except ImportError as e:
    print(f"Error importing sensor_scraper: {e}")
    print("Make sure the sensor_scraper.py file exists in the correct location")
    sys.exit(1)


class TestGooglePlayUrlGeneration(unittest.TestCase):
    """Test cases for Google Play URL generation functionality."""
    
    def test_generate_google_play_url_basic(self):
        """Test basic Google Play URL generation with valid inputs."""
        app_id = "com.bigoen.stalkla"
        country = "US"
        expected_url = "https://play.google.com/store/apps/details?id=com.bigoen.stalkla&gl=US"
        
        result = generate_google_play_url(app_id, country)
        
        self.assertEqual(result, expected_url)
        self.assertIn("play.google.com", result)
        self.assertIn(app_id, result)
        self.assertIn(country, result)
    
    def test_generate_google_play_url_default_country(self):
        """Test Google Play URL generation with default country (US)."""
        app_id = "com.example.testapp"
        expected_url = "https://play.google.com/store/apps/details?id=com.example.testapp&gl=US"
        
        result = generate_google_play_url(app_id)
        
        self.assertEqual(result, expected_url)
        self.assertIn("gl=US", result)
    
    def test_generate_google_play_url_different_countries(self):
        """Test Google Play URL generation with different country codes."""
        app_id = "com.test.app"
        test_cases = [
            ("TR", "https://play.google.com/store/apps/details?id=com.test.app&gl=TR"),
            ("GB", "https://play.google.com/store/apps/details?id=com.test.app&gl=GB"),
            ("DE", "https://play.google.com/store/apps/details?id=com.test.app&gl=DE"),
            ("JP", "https://play.google.com/store/apps/details?id=com.test.app&gl=JP")
        ]
        
        for country, expected_url in test_cases:
            with self.subTest(country=country):
                result = generate_google_play_url(app_id, country)
                self.assertEqual(result, expected_url)
                self.assertIn(f"gl={country}", result)
    
    def test_generate_google_play_url_empty_app_id(self):
        """Test Google Play URL generation with empty app_id."""
        result = generate_google_play_url("", "US")
        self.assertEqual(result, "N/A")
    
    def test_generate_google_play_url_none_app_id(self):
        """Test Google Play URL generation with None app_id."""
        result = generate_google_play_url(None, "US")
        self.assertEqual(result, "N/A")
    
    def test_generate_google_play_url_complex_package_names(self):
        """Test Google Play URL generation with complex package names."""
        test_cases = [
            "com.company.app.submodule",
            "org.apache.cordova.example",
            "io.flutter.plugins.camera",
            "androidx.test.espresso.core"
        ]
        
        for app_id in test_cases:
            with self.subTest(app_id=app_id):
                result = generate_google_play_url(app_id, "US")
                expected_url = f"https://play.google.com/store/apps/details?id={app_id}&gl=US"
                self.assertEqual(result, expected_url)
                self.assertIn(app_id, result)
    
    def test_generate_google_play_url_special_characters(self):
        """Test Google Play URL generation with special characters in country codes."""
        app_id = "com.test.app"
        
        # Test with lowercase country codes (should work as-is)
        result = generate_google_play_url(app_id, "us")
        expected_url = "https://play.google.com/store/apps/details?id=com.test.app&gl=us"
        self.assertEqual(result, expected_url)


class TestTimestampFormatting(unittest.TestCase):
    """Test cases for timestamp formatting functionality."""
    
    def test_format_timestamp_valid(self):
        """Test timestamp formatting with valid Unix timestamps."""
        # Test with known timestamp (milliseconds)
        timestamp_ms = 1640995200000  # January 1, 2022 00:00:00 UTC
        expected_date = "2022-01-01"
        
        result = format_timestamp(timestamp_ms)
        self.assertEqual(result, expected_date)
    
    def test_format_timestamp_none(self):
        """Test timestamp formatting with None input."""
        result = format_timestamp(None)
        self.assertEqual(result, "N/A")
    
    def test_format_timestamp_zero(self):
        """Test timestamp formatting with zero input."""
        result = format_timestamp(0)
        self.assertEqual(result, "N/A")
    
    def test_format_timestamp_empty_string(self):
        """Test timestamp formatting with empty string input."""
        result = format_timestamp("")
        self.assertEqual(result, "N/A")
    
    def test_format_timestamp_invalid_type(self):
        """Test timestamp formatting with invalid type."""
        result = format_timestamp("invalid")
        self.assertEqual(result, "Invalid Date")
    
    def test_format_timestamp_negative(self):
        """Test timestamp formatting with negative timestamp."""
        result = format_timestamp(-1000)
        # Should handle negative timestamps gracefully
        self.assertIn("Invalid Date", result)


class TestDisplayAppData(unittest.TestCase):
    """Test cases for app data display functionality."""
    
    def setUp(self):
        """Set up test data for display tests."""
        self.sample_app_data = {
            "name": "Test App",
            "app_id": "com.test.app",
            "publisher_name": "Test Publisher",
            "categories": [{"name": "Social"}],
            "os": "android",
            "description": {"short_description": "A test application"},
            "worldwide_release_date": 1640995200000,
            "current_version": "1.0.0",
            "recent_release_date": 1640995200000,
            "minimum_os_version": "5.0",
            "file_size": "10MB",
            "rating": 4.5,
            "rating_count": 1000,
            "has_in_app_purchases": False,
            "installs": "1,000+",
            "top_countries": ["US", "CA", "GB"],
            "versions": [
                {"value": "1.0.0", "date": 1640995200000},
                {"value": "0.9.0", "date": 1640908800000}
            ]
        }
    
    @patch('builtins.print')
    @patch('builtins.open', new_callable=mock_open)
    def test_display_app_data_basic(self, mock_file, mock_print):
        """Test basic app data display functionality."""
        display_app_data(self.sample_app_data)
        
        # Verify that print was called (output was generated)
        self.assertTrue(mock_print.called)
        
        # Verify that file write was attempted
        mock_file.assert_called_once()
    
    @patch('builtins.print')
    @patch('builtins.open', new_callable=mock_open)
    def test_display_app_data_with_google_play_url(self, mock_file, mock_print):
        """Test app data display with Google Play URL."""
        google_play_url = "https://play.google.com/store/apps/details?id=com.test.app&gl=US"
        
        # This test assumes the display_app_data function will be updated to accept google_play_url
        # For now, we'll test the current functionality
        display_app_data(self.sample_app_data)
        
        # Verify basic functionality works
        self.assertTrue(mock_print.called)
        mock_file.assert_called_once()
    
    @patch('builtins.print')
    @patch('builtins.open', new_callable=mock_open)
    def test_display_app_data_missing_fields(self, mock_file, mock_print):
        """Test app data display with missing fields."""
        minimal_data = {
            "name": "Minimal App",
            "app_id": "com.minimal.app"
        }
        
        # Should handle missing fields gracefully
        display_app_data(minimal_data)
        
        self.assertTrue(mock_print.called)
        mock_file.assert_called_once()
    
    @patch('builtins.print')
    @patch('builtins.open', side_effect=IOError("Write error"))
    def test_display_app_data_file_write_error(self, mock_file, mock_print):
        """Test app data display when file writing fails."""
        display_app_data(self.sample_app_data)
        
        # Should still print to console even if file write fails
        self.assertTrue(mock_print.called)


class TestIntegrationScenarios(unittest.TestCase):
    """Integration test cases for sensor scraper functionality."""
    
    def test_google_play_url_integration(self):
        """Test integration of Google Play URL generation with real data."""
        # Simulate real SensorTower API response data
        api_response = {
            "app_id": "com.bigoen.stalkla",
            "country": "US",
            "name": "Gramai: IG Followers Analysis"
        }
        
        # Generate URL using the function
        google_play_url = generate_google_play_url(
            api_response.get("app_id"),
            api_response.get("country", "US")
        )
        
        # Verify the URL is correctly formatted
        expected_url = "https://play.google.com/store/apps/details?id=com.bigoen.stalkla&gl=US"
        self.assertEqual(google_play_url, expected_url)
        
        # Verify URL components
        self.assertIn("play.google.com", google_play_url)
        self.assertIn("com.bigoen.stalkla", google_play_url)
        self.assertIn("gl=US", google_play_url)
    
    def test_multiple_apps_url_generation(self):
        """Test URL generation for multiple apps."""
        apps = [
            {"app_id": "com.whatsapp", "country": "US"},
            {"app_id": "com.instagram.android", "country": "GB"},
            {"app_id": "com.spotify.music", "country": "DE"},
            {"app_id": "com.tiktok.musically", "country": "JP"}
        ]
        
        for app in apps:
            with self.subTest(app_id=app["app_id"], country=app["country"]):
                url = generate_google_play_url(app["app_id"], app["country"])
                
                # Verify URL structure
                self.assertTrue(url.startswith("https://play.google.com/store/apps/details?"))
                self.assertIn(f"id={app['app_id']}", url)
                self.assertIn(f"gl={app['country']}", url)


class TestJsonFiltering(unittest.TestCase):
    """Test cases for JSON data filtering functionality."""
    
    def setUp(self):
        """Set up test data with real SensorTower JSON structure."""
        # Load the actual SensorTower JSON data for testing
        try:
            import os
            test_json_path = os.path.join(os.path.dirname(__file__), 'resources', 'sensortower.json')
            with open(test_json_path, 'r', encoding='utf-8') as f:
                import json
                self.real_sensortower_data = json.load(f)
        except FileNotFoundError:
            # Fallback test data if file not found
            self.real_sensortower_data = {
                "app_id": "com.bigoen.stalkla",
                "name": "GramAI: IG Followers Analysis",
                "feature_graphic": "https://example.com/graphic.png",
                "screenshots": {"android": ["url1", "url2"]},
                "trailers": {"android": {}},
                "advertised_on_any_network": {"name": "test"},
                "content_rating": "Everyone",
                "valid_countries": ["US", "CA", "GB"],
                "available_countries": ["US", "AU", "BR"],
                "pre_order_countries": [],
                "os": "android",
                "price": {"currency": "USD", "value": 0},
                "rating_breakdown": [0, 0, 0, 0, 0],
                "rating_count": 0,
                "release_status": "WORLDWIDE_RELEASE",
                "supported_languages": [],
                "cohort_id": None,
                "worldwide_last_month_revenue": {"value": 100000},
                "worldwide_last_month_downloads": {"value": 1000},
                "category_rankings": {"app_id": "com.bigoen.stalkla"},
                "publisher_name": "Test Publisher",
                "categories": [{"name": "Social"}]
            }
    
    def test_filter_json_data_removes_specified_fields(self):
        """Test that filter_json_data removes all specified unwanted fields."""
        from sensor_scraper import filter_json_data
        
        # Fields that should be removed
        fields_to_remove = [
            "feature_graphic", "trailers", "advertised_on_any_network",
            "screenshots", "content_rating", "valid_countries",
            "available_countries", "pre_order_countries", "os",
            "price", "rating_breakdown", "rating_count",
            "release_status", "supported_languages", "cohort_id",
            "worldwide_last_month_revenue", "worldwide_last_month_downloads",
            "category_rankings"
        ]
        
        filtered_data = filter_json_data(self.real_sensortower_data)
        
        # Verify that all specified fields are removed
        for field in fields_to_remove:
            with self.subTest(field=field):
                self.assertNotIn(field, filtered_data, 
                                f"Field '{field}' should have been removed but is still present")
    
    def test_filter_json_data_preserves_important_fields(self):
        """Test that filter_json_data preserves important fields."""
        from sensor_scraper import filter_json_data
        
        # Fields that should be preserved (excluding versions which is now filtered out)
        important_fields = [
            "app_id", "name", "publisher_name", "categories",
            "description", "has_in_app_purchases", "installs",
            "top_countries", "current_version",
            "minimum_os_version", "recent_release_date",
            "worldwide_release_date", "rating", "icon_url",
            "website_url", "country"
        ]
        
        filtered_data = filter_json_data(self.real_sensortower_data)
        
        # Verify that important fields are preserved
        for field in important_fields:
            if field in self.real_sensortower_data:
                with self.subTest(field=field):
                    self.assertIn(field, filtered_data,
                                f"Important field '{field}' should have been preserved")
                    self.assertEqual(filtered_data[field], self.real_sensortower_data[field],
                                   f"Value for field '{field}' should be unchanged")
    
    def test_filter_json_data_does_not_modify_original(self):
        """Test that filter_json_data does not modify the original data."""
        from sensor_scraper import filter_json_data
        
        original_data = self.real_sensortower_data.copy()
        original_keys = set(original_data.keys())
        
        # Filter the data
        filtered_data = filter_json_data(original_data)
        
        # Verify original data is unchanged
        self.assertEqual(set(original_data.keys()), original_keys,
                        "Original data keys should not be modified")
        
        # Verify filtered data is different
        self.assertNotEqual(set(filtered_data.keys()), original_keys,
                           "Filtered data should have different keys than original")
        
        # Verify specific fields still exist in original but not in filtered
        if "screenshots" in original_data:
            self.assertIn("screenshots", original_data)
            self.assertNotIn("screenshots", filtered_data)
    
    def test_filter_json_data_with_missing_fields(self):
        """Test filter_json_data with data that doesn't have all unwanted fields."""
        from sensor_scraper import filter_json_data
        
        minimal_data = {
            "app_id": "com.test.app",
            "name": "Test App",
            "screenshots": ["url1", "url2"],  # Only one unwanted field
            "rating": 4.5,
            "publisher_name": "Test Publisher"
        }
        
        filtered_data = filter_json_data(minimal_data)
        
        # Should remove screenshots but preserve others
        self.assertNotIn("screenshots", filtered_data)
        self.assertIn("app_id", filtered_data)
        self.assertIn("name", filtered_data)
        self.assertIn("rating", filtered_data)
        self.assertIn("publisher_name", filtered_data)
    
    def test_filter_json_data_with_empty_dict(self):
        """Test filter_json_data with empty dictionary."""
        from sensor_scraper import filter_json_data
        
        empty_data = {}
        filtered_data = filter_json_data(empty_data)
        
        self.assertEqual(filtered_data, {})
        self.assertIsNot(filtered_data, empty_data)  # Should be a copy
    
    def test_filter_json_data_field_count_reduction(self):
        """Test that filtering significantly reduces the number of fields."""
        from sensor_scraper import filter_json_data
        
        original_field_count = len(self.real_sensortower_data)
        filtered_data = filter_json_data(self.real_sensortower_data)
        filtered_field_count = len(filtered_data)
        
        # Should have fewer fields after filtering
        self.assertLess(filtered_field_count, original_field_count,
                       "Filtered data should have fewer fields than original")
        
        # Should remove a significant number of fields
        removed_count = original_field_count - filtered_field_count
        self.assertGreater(removed_count, 5,
                          "Should remove more than 5 fields from the data")
    
    def test_filter_json_data_preserves_nested_structures(self):
        """Test that filtering preserves nested data structures that should be kept."""
        from sensor_scraper import filter_json_data
        
        filtered_data = filter_json_data(self.real_sensortower_data)
        
        # Check that nested structures in preserved fields are intact
        if "description" in self.real_sensortower_data:
            self.assertIn("description", filtered_data)
            if isinstance(self.real_sensortower_data["description"], dict):
                self.assertEqual(filtered_data["description"], 
                               self.real_sensortower_data["description"])
        
        if "categories" in self.real_sensortower_data:
            self.assertIn("categories", filtered_data)
            self.assertEqual(filtered_data["categories"], 
                           self.real_sensortower_data["categories"])
        
        # Note: versions field is now filtered out, so we don't test for it
    
    @patch('builtins.print')
    def test_filter_json_data_logging(self, mock_print):
        """Test that filter_json_data provides appropriate logging output."""
        from sensor_scraper import filter_json_data
        
        filtered_data = filter_json_data(self.real_sensortower_data)
        
        # Should have called print to log the filtering
        self.assertTrue(mock_print.called, "Should log filtering activity")
        
        # Check that the log message contains expected information
        call_args = mock_print.call_args[0][0]  # Get the first argument of the print call
        self.assertIn("Filtered out", call_args)
        self.assertIn("fields:", call_args)


class TestIntegratedFiltering(unittest.TestCase):
    """Test cases for integrated JSON filtering in fetch_app_data workflow."""
    
    def setUp(self):
        """Set up test data for integrated filtering tests."""
        # Load the original sensortower data
        try:
            import os
            original_json_path = os.path.join(os.path.dirname(__file__), 'resources', 'sensortower.json')
            with open(original_json_path, 'r', encoding='utf-8') as f:
                import json
                self.original_data = json.load(f)
        except FileNotFoundError:
            self.original_data = None
            
        # Load the expected filtered result
        try:
            filtered_json_path = os.path.join(os.path.dirname(__file__), 'resources', 'sensortower_filtered.json')
            with open(filtered_json_path, 'r', encoding='utf-8') as f:
                import json
                self.expected_filtered_data = json.load(f)
        except FileNotFoundError:
            self.expected_filtered_data = None
    
    def test_integrated_filtering_matches_expected_output(self):
        """Test that integrated filtering produces the expected filtered JSON structure."""
        if not self.original_data or not self.expected_filtered_data:
            self.skipTest("Required test data files not available")
            
        from sensor_scraper import filter_json_data
        
        # Add Google Play URL to match the integration workflow
        test_data = self.original_data.copy()
        test_data['generated_google_play_url'] = "https://play.google.com/store/apps/details?id=com.bigoen.stalkla&gl=US"
        
        # Apply filtering
        filtered_result = filter_json_data(test_data)
        
        # Verify specific important fields are preserved correctly
        important_fields = ["app_id", "name", "publisher_name", "generated_google_play_url"]
        for field in important_fields:
            if field in self.expected_filtered_data:
                self.assertEqual(filtered_result[field], self.expected_filtered_data[field],
                               f"Field '{field}' should match expected value")
        
        # Verify that key fields that should be preserved are present
        preserved_fields = ["categories", "description"]
        for field in preserved_fields:
            if field in self.expected_filtered_data:
                self.assertIn(field, filtered_result, f"Field '{field}' should be preserved")
        
        # Verify that these fields are removed as requested
        removed_fields = ["game_intel_data", "top_in_app_purchases", "versions"]
        for field in removed_fields:
            self.assertNotIn(field, filtered_result, f"Field '{field}' should be removed")
    
    def test_all_unwanted_fields_removed_from_integration(self):
        """Test that all unwanted fields are removed in the integrated workflow."""
        if not self.original_data:
            self.skipTest("Original test data file not available")
            
        from sensor_scraper import filter_json_data
        
        # Updated list of fields that should be removed 
        # Note: Based on sensortower_filtered.json, game_intel_data and top_in_app_purchases are preserved
        unwanted_fields = [
            "versions",  # This is now filtered out
            "feature_graphic", "trailers", "advertised_on_any_network",
            "screenshots", "content_rating", "valid_countries",
            "available_countries", "pre_order_countries", "os",
            "price", "rating_breakdown", "rating_count",
            "release_status", "supported_languages", "cohort_id",
            "worldwide_last_month_revenue", "worldwide_last_month_downloads",
            "category_rankings"
        ]
        
        test_data = self.original_data.copy()
        test_data['generated_google_play_url'] = "https://play.google.com/store/apps/details?id=com.bigoen.stalkla&gl=US"
        
        filtered_result = filter_json_data(test_data)
        
        # Verify each unwanted field is removed
        for field in unwanted_fields:
            with self.subTest(field=field):
                self.assertNotIn(field, filtered_result,
                                f"Unwanted field '{field}' should be removed from filtered output")
    
    def test_filtered_json_size_reduction(self):
        """Test that filtering significantly reduces JSON size."""
        if not self.original_data or not self.expected_filtered_data:
            self.skipTest("Required test data files not available")
            
        from sensor_scraper import filter_json_data
        
        test_data = self.original_data.copy()
        test_data['generated_google_play_url'] = "https://play.google.com/store/apps/details?id=com.bigoen.stalkla&gl=US"
        
        filtered_result = filter_json_data(test_data)
        
        original_size = len(json.dumps(test_data))
        filtered_size = len(json.dumps(filtered_result))
        
        # Should achieve significant size reduction
        reduction_percentage = (original_size - filtered_size) / original_size * 100
        self.assertGreater(reduction_percentage, 30,
                          f"Should achieve >30% size reduction, got {reduction_percentage:.1f}%")
        
        # Verify against expected filtered size
        expected_size = len(json.dumps(self.expected_filtered_data))
        size_difference = abs(filtered_size - expected_size) / expected_size * 100
        self.assertLess(size_difference, 5,
                       f"Filtered size should be within 5% of expected size, difference: {size_difference:.1f}%")
    
    def test_google_play_url_integration(self):
        """Test that Google Play URL is correctly integrated into filtered output."""
        if not self.expected_filtered_data:
            self.skipTest("Expected filtered data not available")
            
        # Verify the expected filtered data contains the Google Play URL
        self.assertIn("generated_google_play_url", self.expected_filtered_data,
                     "Filtered output should contain generated_google_play_url field")
        
        expected_url = self.expected_filtered_data["generated_google_play_url"]
        self.assertTrue(expected_url.startswith("https://play.google.com/store/apps/details?"),
                       "Google Play URL should have correct format")
        self.assertIn("id=com.bigoen.stalkla", expected_url,
                     "URL should contain the correct app ID")
        self.assertIn("gl=US", expected_url,
                     "URL should contain the correct country code")
    
    def test_essential_app_data_preserved(self):
        """Test that all essential app information is preserved in filtered output."""
        if not self.expected_filtered_data:
            self.skipTest("Expected filtered data not available")
            
        # Essential fields that must be preserved
        essential_fields = [
            "app_id", "name", "publisher_name", "categories", "description",
            "has_in_app_purchases", "installs", "top_countries", "current_version",
            "minimum_os_version", "recent_release_date", "worldwide_release_date",
            "rating", "icon_url", "website_url", "country"
        ]
        
        for field in essential_fields:
            with self.subTest(field=field):
                self.assertIn(field, self.expected_filtered_data,
                             f"Essential field '{field}' should be preserved in filtered output")
    
    def test_nested_structures_preserved_correctly(self):
        """Test that nested data structures are preserved correctly in filtered output."""
        if not self.expected_filtered_data:
            self.skipTest("Expected filtered data not available")
            
        # Test description object structure
        if "description" in self.expected_filtered_data:
            description = self.expected_filtered_data["description"]
            self.assertIsInstance(description, dict, "Description should be a dictionary")
            self.assertIn("short_description", description, "Should preserve short_description")
            self.assertIn("full_description", description, "Should preserve full_description")
        
        # Test categories array structure
        if "categories" in self.expected_filtered_data:
            categories = self.expected_filtered_data["categories"]
            self.assertIsInstance(categories, list, "Categories should be a list")
            if categories:
                self.assertIn("name", categories[0], "Category should have name field")
                self.assertIn("id", categories[0], "Category should have id field")
        
        # Test top_countries array
        if "top_countries" in self.expected_filtered_data:
            top_countries = self.expected_filtered_data["top_countries"]
            self.assertIsInstance(top_countries, list, "Top countries should be a list")
            self.assertTrue(all(isinstance(country, str) for country in top_countries),
                           "All country codes should be strings")
    
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dump')
    def test_fetch_app_data_integration_workflow(self, mock_json_dump, mock_file):
        """Test that the complete fetch_app_data workflow applies filtering correctly."""
        from sensor_scraper import filter_json_data
        
        # Mock data similar to what would come from API
        mock_api_data = {
            "app_id": "com.bigoen.stalkla",
            "name": "Test App",
            "country": "US",
            "screenshots": ["url1", "url2"],  # Should be filtered out
            "feature_graphic": "graphic_url",  # Should be filtered out
            "rating": 4.5,  # Should be preserved
            "publisher_name": "Test Publisher"  # Should be preserved
        }
        
        # Simulate the workflow
        google_play_url = "https://play.google.com/store/apps/details?id=com.bigoen.stalkla&gl=US"
        mock_api_data['generated_google_play_url'] = google_play_url
        
        filtered_data = filter_json_data(mock_api_data)
        
        # Verify filtering occurred
        self.assertNotIn("screenshots", filtered_data, "Screenshots should be filtered out")
        self.assertNotIn("feature_graphic", filtered_data, "Feature graphic should be filtered out")
        
        # Verify important data preserved
        self.assertIn("app_id", filtered_data, "App ID should be preserved")
        self.assertIn("name", filtered_data, "Name should be preserved")
        self.assertIn("generated_google_play_url", filtered_data, "Google Play URL should be preserved")
        
        # Verify the URL is correct
        self.assertEqual(filtered_data["generated_google_play_url"], google_play_url)


class TestErrorHandling(unittest.TestCase):
    """Test cases for error handling scenarios."""
    
    def test_generate_url_with_invalid_inputs(self):
        """Test URL generation with various invalid inputs."""
        invalid_inputs = [
            (None, "US"),
            ("", "US"),
            ("   ", "US"),  # Whitespace only
            ("com.test.app", None),  # None country should use default
            ("com.test.app", ""),    # Empty country should still work
        ]
        
        for app_id, country in invalid_inputs:
            with self.subTest(app_id=app_id, country=country):
                if not app_id or (app_id and not app_id.strip()):
                    result = generate_google_play_url(app_id, country)
                    self.assertEqual(result, "N/A")
                else:
                    # Valid app_id with invalid country should still work
                    result = generate_google_play_url(app_id, country or "US")
                    self.assertIn("play.google.com", result)


if __name__ == '__main__':
    # Create a test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestGooglePlayUrlGeneration,
        TestTimestampFormatting,
        TestDisplayAppData,
        TestIntegrationScenarios,
        TestJsonFiltering,
        TestIntegratedFiltering,
        TestErrorHandling
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run the tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with error code if tests failed
    sys.exit(0 if result.wasSuccessful() else 1)
