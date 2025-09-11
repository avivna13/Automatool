"""
Simple tests for parse_apkleaks_output.py module

Tests the parsing functionality with the actual APKLeaks report file.
"""

import json
import unittest
from pathlib import Path

# Add the src directory to the path so we can import the module
import sys
src_path = Path(__file__).parent.parent / 'src' / 'scripts' / 'automations'
sys.path.insert(0, str(src_path))

from parse_apkleaks_output import parse_apkleaks_json, get_keys_by_type


class TestParseAPKLeaksOutput(unittest.TestCase):
    """Test cases for APKLeaks output parsing functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_resources_dir = Path(__file__).parent / 'resources'
        self.apkleaks_report_path = self.test_resources_dir / 'apkleaks_report.json'
        self.custom_rules_path = Path(__file__).parent.parent / 'src' / 'scripts' / 'automations' / 'apkleaks_custom_rules.json'

    def test_apkleaks_report_exists(self):
        """Test that the APKLeaks report file exists."""
        self.assertTrue(self.apkleaks_report_path.exists(), 
                       f"APKLeaks report file not found: {self.apkleaks_report_path}")

    def test_custom_rules_exists(self):
        """Test that the custom rules file exists."""
        self.assertTrue(self.custom_rules_path.exists(),
                       f"Custom rules file not found: {self.custom_rules_path}")

    def test_parse_apkleaks_report(self):
        """Test parsing the actual APKLeaks report file."""
        result = parse_apkleaks_json(str(self.apkleaks_report_path))
        
        # Check that result is a dictionary
        self.assertIsInstance(result, dict)
        
        # Check that we have the expected keys from the report
        self.assertIn("appsflyer_api_keys", result)
        self.assertIn("onesignal_app_ids", result)
        
        # Check that values are sets
        self.assertIsInstance(result["appsflyer_api_keys"], set)
        self.assertIsInstance(result["onesignal_app_ids"], set)

    def test_appsflyer_keys_parsed(self):
        """Test that AppsFlyer API keys are correctly parsed."""
        result = parse_apkleaks_json(str(self.apkleaks_report_path))
        
        appsflyer_keys = result.get("appsflyer_api_keys", set())
        
        # Should have exactly 1 AppsFlyer key based on the report
        self.assertEqual(len(appsflyer_keys), 1)
        
        # Check the specific key value
        expected_key = "e44a8b69c7d76049d312caec6fb8a01b60982d8f"
        self.assertIn(expected_key, appsflyer_keys)

    def test_onesignal_ids_parsed(self):
        """Test that OneSignal App IDs are correctly parsed."""
        result = parse_apkleaks_json(str(self.apkleaks_report_path))
        
        onesignal_ids = result.get("onesignal_app_ids", set())
        
        # Should have exactly 9 OneSignal IDs based on the report
        self.assertEqual(len(onesignal_ids), 9)
        
        # Check some specific IDs
        expected_ids = {
            "00000000-0000-0000-0000-000000000000",
            "01528cc0-dd34-494d-9218-24af1317e1ee",
            "e4250327-8d3c-4d35-b9e8-3c1720a64b91"
        }
        
        for expected_id in expected_ids:
            self.assertIn(expected_id, onesignal_ids)

    def test_get_keys_by_type_function(self):
        """Test the get_keys_by_type utility function."""
        result = parse_apkleaks_json(str(self.apkleaks_report_path))
        
        # Test getting AppsFlyer keys
        appsflyer_keys = get_keys_by_type(result, "appsflyer_api_keys")
        self.assertEqual(len(appsflyer_keys), 1)
        
        # Test getting OneSignal IDs
        onesignal_ids = get_keys_by_type(result, "onesignal_app_ids")
        self.assertEqual(len(onesignal_ids), 9)
        
        # Test getting non-existent type
        non_existent = get_keys_by_type(result, "non_existent_type")
        self.assertEqual(len(non_existent), 0)
        self.assertIsInstance(non_existent, set)

    def test_custom_rules_format(self):
        """Test that custom rules file has correct format."""
        with open(self.custom_rules_path, 'r') as f:
            rules = json.load(f)
        
        # Check that it's a dictionary
        self.assertIsInstance(rules, dict)
        
        # Check that expected rule types exist
        expected_rule_types = [
            "firebase_api_keys",
            "appsflyer_api_keys", 
            "onesignal_app_ids",
            "google_maps_api_keys"
        ]
        
        for rule_type in expected_rule_types:
            self.assertIn(rule_type, rules, f"Missing rule type: {rule_type}")
            self.assertIsInstance(rules[rule_type], str, f"Rule {rule_type} should be a string pattern")

    def test_rule_coverage(self):
        """Test that our custom rules cover the keys found in the report."""
        # Parse the report
        result = parse_apkleaks_json(str(self.apkleaks_report_path))
        
        # Load custom rules
        with open(self.custom_rules_path, 'r') as f:
            rules = json.load(f)
        
        # Check that rules exist for the key types found in the report
        for key_type in result.keys():
            self.assertIn(key_type, rules, 
                         f"No custom rule defined for key type: {key_type}")

    def test_no_duplicates_in_parsed_results(self):
        """Test that parsed results don't contain duplicates."""
        result = parse_apkleaks_json(str(self.apkleaks_report_path))
        
        for key_type, keys in result.items():
            # Since we use sets, there should be no duplicates
            # Convert to list and back to set to verify
            keys_list = list(keys)
            unique_keys = set(keys_list)
            
            self.assertEqual(len(keys_list), len(unique_keys),
                           f"Duplicates found in {key_type}")


if __name__ == '__main__':
    unittest.main()
