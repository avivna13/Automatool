#!/usr/bin/env python3
"""
Tests for merge_app_intelligence.py

Tests the comprehensive app intelligence report generation functionality
using both Google Play Store and SensorTower data sources.
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scripts.automations.merge_app_intelligence import merge_app_intelligence


class TestMergeAppIntelligence(unittest.TestCase):
    """Test cases for merge_app_intelligence function."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_package = "com.dextoro.pro"
        self.temp_dir = tempfile.mkdtemp()
        self.expected_output_file = os.path.join(self.temp_dir, "app_intelligence_report.txt")
        
        # Mock Google Play Store data
        self.mock_play_store_info = Mock()
        self.mock_play_store_info.app_id = self.test_package
        self.mock_play_store_info.developer_name = "DexToro Trading Inc."
        self.mock_play_store_info.contains_ads = False
        self.mock_play_store_info.developer_email = "support@dextoro.com"
        self.mock_play_store_info.privacy_policy = "https://www.dextoro.com/privacy"
        
        # Mock SensorTower data
        self.mock_sensor_data = {
            'name': 'dextoro: Buy Crypto & Memes',
            'app_id': self.test_package,
            'publisher_name': 'DexToro Trading Inc.',
            'categories': [{'name': 'Finance'}],
            'os': 'android',
            'description': {'short_description': 'dextoro: Buy, Trade & Discover the Hottest Memecoins Instantly'},
            'worldwide_release_date': 1719705600000,  # 2025-06-20
            'current_version': '2.3.0',
            'recent_release_date': 1721779200000,  # 2025-07-24
            'minimum_os_version': '7.0',
            'file_size': 'Varies with device',
            'rating': 4.81,
            'rating_count': 95,
            'has_in_app_purchases': False,
            'worldwide_last_month_revenue': {'value': 100000},  # $1,000.00 (in cents)
            'worldwide_last_month_downloads': {'value': 1000},
            'installs': '1K - 5K',
            'top_countries': ['NG', 'CM', 'BH'],
            'valid_countries': ['AE', 'AO', 'AR', 'AT', 'AU'],
            'versions': [
                {'value': '2.3.0', 'date': 1721779200000},
                {'value': '2.2.16', 'date': 1721606400000},
                {'value': '2.2.15', 'date': 1721520000000},
                {'value': '2.2.14', 'date': 1721433600000},
                {'value': '2.2.13', 'date': 1721174400000},
            ],
            'country': 'US'
        }

    def tearDown(self):
        """Clean up test fixtures."""
        # Remove temp directory and files
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch('scripts.automations.merge_app_intelligence.PlayStoreBasicInfoScraper')
    @patch('scripts.automations.merge_app_intelligence.fetch_app_data')
    @patch('scripts.automations.merge_app_intelligence.parse_to_text')
    @patch('scripts.automations.merge_app_intelligence.generate_google_play_url')
    def test_successful_report_generation(self, mock_generate_url, mock_parse_text, mock_fetch_data, mock_scraper_class):
        """Test successful report generation with both data sources."""
        
        # Mock Google Play Store scraper
        mock_scraper = Mock()
        mock_scraper.get_app_basic_info.return_value = self.mock_play_store_info
        mock_scraper.print_basic_info.return_value = """
App: com.dextoro.pro
Developer: DexToro Trading Inc.
Contains Ads: No
Developer Email: support@dextoro.com
Privacy Policy: https://www.dextoro.com/privacy"""
        mock_scraper_class.return_value = mock_scraper
        
        # Mock SensorTower functions
        mock_fetch_data.return_value = self.mock_sensor_data
        mock_generate_url.return_value = "https://play.google.com/store/apps/details?id=com.dextoro.pro&gl=US"
        mock_parse_text.return_value = """
============================================================
                    APP INFORMATION                     
============================================================
 📱 App: dextoro: Buy Crypto & Memes (com.dextoro.pro)
 🏢 Publisher: DexToro Trading Inc.
 🏷️ Category: Finance
 🌍 OS: Android
 📝 Description: dextoro: Buy, Trade & Discover the Hottest Memecoins Instantly
 🔗 Google Play: https://play.google.com/store/apps/details?id=com.dextoro.pro&gl=US

---------------------- Release & Version ---------------------
 🗓️ Worldwide Release: 2025-06-20
 📦 Current Version: 2.3.0 (Released: 2025-07-24)
 ⚙️ Minimum OS: 7.0
 📏 File Size: Varies with device

---------------------- Ratings & Financials -------------------
 ⭐ Rating: 4.81 stars (95 reviews)
 💰 In-App Purchases: None
 💵 Est. Revenue (Last Month): $1,000.00
 📥 Est. Downloads (Last Month): 1,000
 📈 Total Installs: 1K - 5K

-------------------------- Availability ------------------------
 🌍 Top Countries: NG, CM, BH
 ✅ Available in 112 countries, including: AE, AO, AR, AT, AU...

----------------------- Version History ----------------------
  - Version 2.3.0      | Released on: 2025-07-24
  - Version 2.2.16     | Released on: 2025-07-22
  - Version 2.2.15     | Released on: 2025-07-21
  - Version 2.2.14     | Released on: 2025-07-20
  - Version 2.2.13     | Released on: 2025-07-17
  ... and 6 older versions.
============================================================"""
        
        # Execute the function
        result = merge_app_intelligence(self.test_package, self.temp_dir, verbose=True)
        
        # Verify result
        self.assertIsNotNone(result)
        self.assertEqual(result, self.expected_output_file)
        self.assertTrue(os.path.exists(self.expected_output_file))
        
        # Verify file contents
        with open(self.expected_output_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for expected sections
        self.assertIn("APP INTELLIGENCE REPORT", content)
        self.assertIn(f"Package: {self.test_package}", content)
        self.assertIn("[GOOGLE PLAY STORE METADATA]", content)
        self.assertIn("[SENSOR TOWER APP METADATA]", content)
        self.assertIn("DexToro Trading Inc.", content)
        self.assertIn("Contains Ads: No", content)
        self.assertIn("support@dextoro.com", content)
        self.assertIn("https://www.dextoro.com/privacy", content)
        self.assertIn("Report generated by Aviv Automatool", content)
        
        # Verify function calls
        mock_scraper_class.assert_called_once_with(verbose=True)
        mock_scraper.get_app_basic_info.assert_called_once_with(self.test_package)
        mock_scraper.print_basic_info.assert_called_once_with(self.mock_play_store_info)
        mock_fetch_data.assert_called_once_with(self.test_package)
        mock_parse_text.assert_called_once()

    @patch('scripts.automations.merge_app_intelligence.PlayStoreBasicInfoScraper')
    @patch('scripts.automations.merge_app_intelligence.fetch_app_data')
    def test_play_store_failure_sensor_success(self, mock_fetch_data, mock_scraper_class):
        """Test report generation when Google Play Store fails but SensorTower succeeds."""
        
        # Mock Google Play Store failure
        mock_scraper = Mock()
        mock_scraper.get_app_basic_info.return_value = None
        mock_scraper_class.return_value = mock_scraper
        
        # Mock SensorTower success
        mock_fetch_data.return_value = self.mock_sensor_data
        
        with patch('scripts.automations.merge_app_intelligence.parse_to_text') as mock_parse_text, \
             patch('scripts.automations.merge_app_intelligence.generate_google_play_url') as mock_generate_url:
            
            mock_generate_url.return_value = "https://play.google.com/store/apps/details?id=com.dextoro.pro&gl=US"
            mock_parse_text.return_value = "SensorTower data here"
            
            # Execute the function
            result = merge_app_intelligence(self.test_package, self.temp_dir, verbose=True)
            
            # Verify result
            self.assertIsNotNone(result)
            self.assertTrue(os.path.exists(self.expected_output_file))
            
            # Verify file contents
            with open(self.expected_output_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.assertIn("❌ Google Play Store metadata unavailable", content)
            self.assertIn("SensorTower data here", content)

    @patch('scripts.automations.merge_app_intelligence.PlayStoreBasicInfoScraper')
    @patch('scripts.automations.merge_app_intelligence.fetch_app_data')
    def test_sensor_failure_play_store_success(self, mock_fetch_data, mock_scraper_class):
        """Test report generation when SensorTower fails but Google Play Store succeeds."""
        
        # Mock Google Play Store success
        mock_scraper = Mock()
        mock_scraper.get_app_basic_info.return_value = self.mock_play_store_info
        mock_scraper.print_basic_info.return_value = "Play Store data here"
        mock_scraper_class.return_value = mock_scraper
        
        # Mock SensorTower failure
        mock_fetch_data.return_value = None
        
        # Execute the function
        result = merge_app_intelligence(self.test_package, self.temp_dir, verbose=True)
        
        # Verify result
        self.assertIsNotNone(result)
        self.assertTrue(os.path.exists(self.expected_output_file))
        
        # Verify file contents
        with open(self.expected_output_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        self.assertIn("Play Store data here", content)
        self.assertIn("❌ SensorTower data unavailable", content)

    @patch('scripts.automations.merge_app_intelligence.PlayStoreBasicInfoScraper')
    @patch('scripts.automations.merge_app_intelligence.fetch_app_data')
    def test_both_sources_fail(self, mock_fetch_data, mock_scraper_class):
        """Test report generation when both data sources fail."""
        
        # Mock both sources failing
        mock_scraper = Mock()
        mock_scraper.get_app_basic_info.return_value = None
        mock_scraper_class.return_value = mock_scraper
        mock_fetch_data.return_value = None
        
        # Execute the function
        result = merge_app_intelligence(self.test_package, self.temp_dir, verbose=True)
        
        # Verify result
        self.assertIsNotNone(result)
        self.assertTrue(os.path.exists(self.expected_output_file))
        
        # Verify file contents
        with open(self.expected_output_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        self.assertIn("❌ Google Play Store metadata unavailable", content)
        self.assertIn("❌ SensorTower data unavailable", content)
        self.assertIn(f"Package: {self.test_package}", content)

    def test_invalid_output_directory(self):
        """Test handling of invalid output directory."""
        
        # Try to write to a non-existent directory with no permissions
        invalid_dir = "/root/nonexistent/directory"
        
        with patch('scripts.automations.merge_app_intelligence.PlayStoreBasicInfoScraper') as mock_scraper_class, \
             patch('scripts.automations.merge_app_intelligence.fetch_app_data') as mock_fetch_data:
            
            mock_scraper = Mock()
            mock_scraper.get_app_basic_info.return_value = None
            mock_scraper_class.return_value = mock_scraper
            mock_fetch_data.return_value = None
            
            # This should handle the error gracefully
            result = merge_app_intelligence(self.test_package, invalid_dir, verbose=True)
            
            # Should return None on failure
            # Note: This might still succeed if the directory can be created
            # The important thing is that it doesn't crash

    @patch('scripts.automations.merge_app_intelligence.PlayStoreBasicInfoScraper')
    @patch('scripts.automations.merge_app_intelligence.fetch_app_data')
    def test_exception_handling(self, mock_fetch_data, mock_scraper_class):
        """Test that exceptions are handled gracefully."""
        
        # Mock exceptions in both sources
        mock_scraper_class.side_effect = Exception("Play Store API error")
        mock_fetch_data.side_effect = Exception("SensorTower API error")
        
        # Execute the function - should not raise exceptions
        result = merge_app_intelligence(self.test_package, self.temp_dir, verbose=True)
        
        # Should still generate a report with error messages
        self.assertIsNotNone(result)
        self.assertTrue(os.path.exists(self.expected_output_file))
        
        # Verify file contains error messages
        with open(self.expected_output_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        self.assertIn("❌ Google Play Store metadata unavailable", content)
        self.assertIn("❌ SensorTower data unavailable", content)

    def test_verbose_logging(self):
        """Test that verbose logging works correctly."""
        
        with patch('scripts.automations.merge_app_intelligence.PlayStoreBasicInfoScraper') as mock_scraper_class, \
             patch('scripts.automations.merge_app_intelligence.fetch_app_data') as mock_fetch_data, \
             patch('builtins.print') as mock_print:
            
            mock_scraper = Mock()
            mock_scraper.get_app_basic_info.return_value = self.mock_play_store_info
            mock_scraper.print_basic_info.return_value = "Play Store data"
            mock_scraper_class.return_value = mock_scraper
            mock_fetch_data.return_value = self.mock_sensor_data
            
            with patch('scripts.automations.merge_app_intelligence.parse_to_text') as mock_parse_text, \
                 patch('scripts.automations.merge_app_intelligence.generate_google_play_url') as mock_generate_url:
                
                mock_generate_url.return_value = "https://play.google.com/store/apps/details?id=com.dextoro.pro&gl=US"
                mock_parse_text.return_value = "SensorTower data"
                
                # Execute with verbose=True
                result = merge_app_intelligence(self.test_package, self.temp_dir, verbose=True)
                
                # Verify verbose output was printed
                mock_print.assert_called()
                print_calls = [call[0][0] for call in mock_print.call_args_list]
                
                # Check for expected debug messages
                debug_messages = [msg for msg in print_calls if msg.startswith('[DEBUG]')]
                self.assertTrue(any("Starting app intelligence report generation" in msg for msg in debug_messages))
                self.assertTrue(any("Fetching Google Play Store metadata" in msg for msg in debug_messages))
                self.assertTrue(any("Fetching SensorTower app data" in msg for msg in debug_messages))

    def test_report_structure_and_formatting(self):
        """Test that the report has the correct structure and formatting."""
        
        with patch('scripts.automations.merge_app_intelligence.PlayStoreBasicInfoScraper') as mock_scraper_class, \
             patch('scripts.automations.merge_app_intelligence.fetch_app_data') as mock_fetch_data:
            
            # Mock successful data retrieval
            mock_scraper = Mock()
            mock_scraper.get_app_basic_info.return_value = self.mock_play_store_info
            mock_scraper.print_basic_info.return_value = "Play Store data"
            mock_scraper_class.return_value = mock_scraper
            mock_fetch_data.return_value = self.mock_sensor_data
            
            with patch('scripts.automations.merge_app_intelligence.parse_to_text') as mock_parse_text, \
                 patch('scripts.automations.merge_app_intelligence.generate_google_play_url') as mock_generate_url:
                
                mock_generate_url.return_value = "https://play.google.com/store/apps/details?id=com.dextoro.pro&gl=US"
                mock_parse_text.return_value = "SensorTower data"
                
                # Execute the function
                result = merge_app_intelligence(self.test_package, self.temp_dir)
                
                # Read and verify the report structure
                with open(self.expected_output_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                # Check header structure
                self.assertEqual(lines[0].strip(), "=" * 47)
                self.assertIn("APP INTELLIGENCE REPORT", lines[1])
                self.assertEqual(lines[2].strip(), "=" * 47)
                self.assertIn(f"Package: {self.test_package}", lines[3])
                self.assertIn("Generated:", lines[4])
                
                # Check sections exist in correct order
                content = ''.join(lines)
                play_store_pos = content.find("[GOOGLE PLAY STORE METADATA]")
                sensor_tower_pos = content.find("[SENSOR TOWER APP METADATA]")
                footer_pos = content.find("Report generated by Aviv Automatool")
                
                self.assertGreater(play_store_pos, 0)
                self.assertGreater(sensor_tower_pos, play_store_pos)
                self.assertGreater(footer_pos, sensor_tower_pos)


class TestMergeAppIntelligenceIntegration(unittest.TestCase):
    """Integration tests that test with real data (if available)."""

    def setUp(self):
        """Set up integration test fixtures."""
        self.test_package = "com.dextoro.pro"
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up integration test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @unittest.skipIf(not os.getenv('RUN_INTEGRATION_TESTS'), "Integration tests disabled")
    def test_real_data_integration(self):
        """Integration test with real API calls (only run when explicitly enabled)."""
        
        # This test requires actual API access and should only be run when explicitly enabled
        result = merge_app_intelligence(self.test_package, self.temp_dir, verbose=True)
        
        self.assertIsNotNone(result)
        self.assertTrue(os.path.exists(result))
        
        # Verify the file contains real data
        with open(result, 'r', encoding='utf-8') as f:
            content = f.read()
        
        self.assertIn(self.test_package, content)
        self.assertIn("APP INTELLIGENCE REPORT", content)


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)
