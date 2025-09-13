"""
Comprehensive tests for analyze_developer_apk.py module

Tests the developer APK analysis automation functionality including:
- Input validation
- Database operations
- Error handling
- APKLeaks integration
- Result parsing and storage
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open, MagicMock
import shutil

# Add the src directory to the path so we can import the module
import sys
src_path = Path(__file__).parent.parent / 'src' / 'scripts' / 'automations'
sys.path.insert(0, str(src_path))

from analyze_developer_apk import (
    analyze_developer_apk,
    load_developers_database,
    save_developers_database,
    convert_sets_to_lists,
    validate_inputs,
    DeveloperAPKAnalysisError,
    DatabaseError,
    ValidationError,
    APKLeaksError,
    ParsingError
)


class TestDeveloperAPKAnalysisExceptions(unittest.TestCase):
    """Test custom exception classes."""
    
    def test_exception_hierarchy(self):
        """Test that custom exceptions inherit properly."""
        # Test base exception
        base_error = DeveloperAPKAnalysisError("Base error")
        self.assertIsInstance(base_error, Exception)
        
        # Test specific exceptions inherit from base
        db_error = DatabaseError("DB error")
        self.assertIsInstance(db_error, DeveloperAPKAnalysisError)
        
        validation_error = ValidationError("Validation error")
        self.assertIsInstance(validation_error, DeveloperAPKAnalysisError)
        
        apkleaks_error = APKLeaksError("APKLeaks error")
        self.assertIsInstance(apkleaks_error, DeveloperAPKAnalysisError)
        
        parsing_error = ParsingError("Parsing error")
        self.assertIsInstance(parsing_error, DeveloperAPKAnalysisError)


class TestLoadDevelopersDatabase(unittest.TestCase):
    """Test database loading functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.db_file = os.path.join(self.test_dir, "test_developers.json")
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_load_nonexistent_file(self):
        """Test loading non-existent database file returns empty dict."""
        result = load_developers_database(self.db_file)
        self.assertEqual(result, {})
    
    def test_load_empty_file(self):
        """Test loading empty database file returns empty dict."""
        # Create empty file
        with open(self.db_file, 'w') as f:
            f.write("")
        
        result = load_developers_database(self.db_file)
        self.assertEqual(result, {})
    
    def test_load_valid_database(self):
        """Test loading valid database file."""
        test_data = {
            "TestDev": {
                "firebase_api_keys": ["AIzaTest123"],
                "appsflyer_api_keys": ["abc123def456"]
            }
        }
        
        with open(self.db_file, 'w') as f:
            json.dump(test_data, f)
        
        result = load_developers_database(self.db_file)
        self.assertEqual(result, test_data)
    
    def test_load_invalid_json(self):
        """Test loading invalid JSON raises DatabaseError."""
        with open(self.db_file, 'w') as f:
            f.write("invalid json {")
        
        with self.assertRaises(DatabaseError) as cm:
            load_developers_database(self.db_file)
        
        self.assertIn("Invalid JSON format", str(cm.exception))
    
    def test_load_non_dict_json(self):
        """Test loading non-dictionary JSON raises DatabaseError."""
        with open(self.db_file, 'w') as f:
            json.dump(["not", "a", "dict"], f)
        
        with self.assertRaises(DatabaseError) as cm:
            load_developers_database(self.db_file)
        
        self.assertIn("Invalid database format", str(cm.exception))
    
    def test_load_permission_error(self):
        """Test loading with permission error raises DatabaseError."""
        # Create file first so it exists
        with open(self.db_file, 'w') as f:
            f.write("{}")
        
        # Now patch open to raise PermissionError when loading
        with patch('builtins.open', side_effect=PermissionError("Access denied")) as mock_open:
            with self.assertRaises(DatabaseError) as cm:
                load_developers_database(self.db_file)
        
        self.assertIn("Permission denied", str(cm.exception))


class TestSaveDevelopersDatabase(unittest.TestCase):
    """Test database saving functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.db_file = os.path.join(self.test_dir, "test_developers.json")
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_save_valid_database(self):
        """Test saving valid database."""
        test_data = {
            "TestDev": {
                "firebase_api_keys": ["AIzaTest123"],
                "appsflyer_api_keys": ["abc123def456"]
            }
        }
        
        save_developers_database(test_data, self.db_file)
        
        # Verify file was created and contains correct data
        self.assertTrue(os.path.exists(self.db_file))
        
        with open(self.db_file, 'r') as f:
            saved_data = json.load(f)
        
        self.assertEqual(saved_data, test_data)
    
    def test_save_creates_directory(self):
        """Test saving creates parent directories if they don't exist."""
        nested_dir = os.path.join(self.test_dir, "nested", "path")
        nested_file = os.path.join(nested_dir, "developers.json")
        
        test_data = {"TestDev": {}}
        save_developers_database(test_data, nested_file)
        
        self.assertTrue(os.path.exists(nested_file))
    
    def test_save_permission_error(self):
        """Test saving with permission error raises DatabaseError."""
        test_data = {"TestDev": {}}
        
        # Patch open to raise PermissionError when trying to save
        with patch('builtins.open', side_effect=PermissionError("Access denied")):
            with self.assertRaises(DatabaseError) as cm:
                save_developers_database(test_data, self.db_file)
        
        self.assertIn("Permission denied", str(cm.exception))


class TestConvertSetsToLists(unittest.TestCase):
    """Test set to list conversion functionality."""
    
    def test_convert_empty_dict(self):
        """Test converting empty dictionary."""
        result = convert_sets_to_lists({})
        self.assertEqual(result, {})
    
    def test_convert_sets_to_sorted_lists(self):
        """Test converting sets to sorted lists."""
        test_data = {
            "firebase_api_keys": {"key3", "key1", "key2"},
            "appsflyer_api_keys": {"keyB", "keyA"}
        }
        
        result = convert_sets_to_lists(test_data)
        
        expected = {
            "firebase_api_keys": ["key1", "key2", "key3"],
            "appsflyer_api_keys": ["keyA", "keyB"]
        }
        
        self.assertEqual(result, expected)
    
    def test_convert_maintains_structure(self):
        """Test that conversion maintains dictionary structure."""
        test_data = {
            "type1": {"single_key"},
            "type2": set(),
            "type3": {"z", "a", "m"}
        }
        
        result = convert_sets_to_lists(test_data)
        
        self.assertEqual(len(result), 3)
        self.assertEqual(result["type1"], ["single_key"])
        self.assertEqual(result["type2"], [])
        self.assertEqual(result["type3"], ["a", "m", "z"])


class TestValidateInputs(unittest.TestCase):
    """Test input validation functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.test_apk = os.path.join(self.test_dir, "test.apk")
        
        # Create a dummy APK file
        with open(self.test_apk, 'wb') as f:
            f.write(b"PK\x03\x04")  # ZIP file signature (APK is a ZIP)
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_validate_valid_inputs(self):
        """Test validation with valid inputs."""
        result = validate_inputs("TestDeveloper", self.test_apk, self.test_dir)
        self.assertTrue(result)
    
    def test_validate_empty_developer_name(self):
        """Test validation with empty developer name."""
        with self.assertRaises(ValidationError) as cm:
            validate_inputs("", self.test_apk, self.test_dir)
        
        self.assertIn("Developer name cannot be empty", str(cm.exception))
    
    def test_validate_whitespace_developer_name(self):
        """Test validation with whitespace-only developer name."""
        with self.assertRaises(ValidationError) as cm:
            validate_inputs("   ", self.test_apk, self.test_dir)
        
        self.assertIn("Developer name cannot be empty", str(cm.exception))
    
    def test_validate_invalid_characters_in_name(self):
        """Test validation with invalid characters in developer name."""
        invalid_names = ["Test/Dev", "Test\\Dev", "Test<Dev", "Test>Dev", 
                        "Test:Dev", 'Test"Dev', "Test|Dev", "Test?Dev", "Test*Dev"]
        
        for invalid_name in invalid_names:
            with self.assertRaises(ValidationError) as cm:
                validate_inputs(invalid_name, self.test_apk, self.test_dir)
            
            self.assertIn("invalid characters", str(cm.exception))
    
    def test_validate_nonexistent_apk(self):
        """Test validation with non-existent APK file."""
        fake_apk = os.path.join(self.test_dir, "nonexistent.apk")
        
        with self.assertRaises(ValidationError) as cm:
            validate_inputs("TestDev", fake_apk, self.test_dir)
        
        self.assertIn("APK file not found", str(cm.exception))
    
    def test_validate_apk_is_directory(self):
        """Test validation when APK path is a directory."""
        with self.assertRaises(ValidationError) as cm:
            validate_inputs("TestDev", self.test_dir, self.test_dir)
        
        self.assertIn("APK path is not a file", str(cm.exception))
    
    def test_validate_non_apk_extension(self):
        """Test validation with non-APK file extension."""
        txt_file = os.path.join(self.test_dir, "test.txt")
        with open(txt_file, 'w') as f:
            f.write("test")
        
        with self.assertRaises(ValidationError) as cm:
            validate_inputs("TestDev", txt_file, self.test_dir)
        
        self.assertIn("File is not an APK", str(cm.exception))
    
    def test_validate_creates_output_directory(self):
        """Test validation creates output directory if it doesn't exist."""
        new_dir = os.path.join(self.test_dir, "new_output")
        
        result = validate_inputs("TestDev", self.test_apk, new_dir)
        
        self.assertTrue(result)
        self.assertTrue(os.path.exists(new_dir))


class TestAnalyzeDeveloperAPK(unittest.TestCase):
    """Test main analysis functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.test_apk = os.path.join(self.test_dir, "test.apk")
        self.output_dir = os.path.join(self.test_dir, "output")
        
        # Create a dummy APK file
        with open(self.test_apk, 'wb') as f:
            f.write(b"PK\x03\x04")  # ZIP file signature
        
        # Create output directory
        os.makedirs(self.output_dir)
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('analyze_developer_apk.run_apkleaks')
    @patch('analyze_developer_apk.parse_apkleaks_json')
    def test_analyze_new_developer_success(self, mock_parse, mock_run_apkleaks):
        """Test successful analysis of new developer."""
        # Mock APKLeaks execution
        mock_output_file = os.path.join(self.test_dir, "apkleaks_output.json")
        with open(mock_output_file, 'w') as f:
            json.dump({"test": "data"}, f)
        
        mock_run_apkleaks.return_value = mock_output_file
        
        # Mock parsing results
        mock_parse.return_value = {
            "firebase_api_keys": {"AIzaTest123"},
            "appsflyer_api_keys": {"abc123def456"}
        }
        
        # Run analysis
        success, result = analyze_developer_apk(
            "TestDeveloper", 
            self.test_apk, 
            self.output_dir,
            verbose=True
        )
        
        # Verify success
        self.assertTrue(success)
        self.assertEqual(result["developer"], "TestDeveloper")
        self.assertEqual(result["status"], "completed")
        self.assertIn("results", result)
        
        # Verify database was created and updated
        db_file = os.path.join(self.output_dir, "developers.json")
        self.assertTrue(os.path.exists(db_file))
        
        with open(db_file, 'r') as f:
            db_data = json.load(f)
        
        self.assertIn("TestDeveloper", db_data)
        self.assertEqual(db_data["TestDeveloper"]["firebase_api_keys"], ["AIzaTest123"])
        self.assertEqual(db_data["TestDeveloper"]["appsflyer_api_keys"], ["abc123def456"])
    
    def test_analyze_existing_developer_without_force(self):
        """Test analysis of existing developer without force flag."""
        # Create existing database with developer
        db_file = os.path.join(self.output_dir, "developers.json")
        existing_data = {"TestDeveloper": {"existing": ["data"]}}
        
        with open(db_file, 'w') as f:
            json.dump(existing_data, f)
        
        # Run analysis
        success, result = analyze_developer_apk(
            "TestDeveloper", 
            self.test_apk, 
            self.output_dir
        )
        
        # Verify failure due to existing developer
        self.assertFalse(success)
        self.assertEqual(result["error"], "Developer already exists")
        self.assertEqual(result["developer"], "TestDeveloper")
    
    @patch('analyze_developer_apk.run_apkleaks')
    @patch('analyze_developer_apk.parse_apkleaks_json')
    def test_analyze_existing_developer_with_force(self, mock_parse, mock_run_apkleaks):
        """Test analysis of existing developer with force flag."""
        # Create existing database with developer
        db_file = os.path.join(self.output_dir, "developers.json")
        existing_data = {"TestDeveloper": {"existing": ["data"]}}
        
        with open(db_file, 'w') as f:
            json.dump(existing_data, f)
        
        # Mock APKLeaks execution
        mock_output_file = os.path.join(self.test_dir, "apkleaks_output.json")
        with open(mock_output_file, 'w') as f:
            json.dump({"test": "data"}, f)
        
        mock_run_apkleaks.return_value = mock_output_file
        mock_parse.return_value = {"new_keys": {"new_value"}}
        
        # Run analysis with force
        success, result = analyze_developer_apk(
            "TestDeveloper", 
            self.test_apk, 
            self.output_dir,
            force=True
        )
        
        # Verify success and overwrite
        self.assertTrue(success)
        
        # Verify database was overwritten
        with open(db_file, 'r') as f:
            db_data = json.load(f)
        
        self.assertEqual(db_data["TestDeveloper"]["new_keys"], ["new_value"])
        self.assertNotIn("existing", db_data["TestDeveloper"])
    
    def test_analyze_invalid_developer_name(self):
        """Test analysis with invalid developer name."""
        success, result = analyze_developer_apk(
            "Test/Invalid", 
            self.test_apk, 
            self.output_dir
        )
        
        self.assertFalse(success)
        self.assertEqual(result["error_type"], "ValidationError")
        self.assertIn("invalid characters", result["error"])
    
    def test_analyze_nonexistent_apk(self):
        """Test analysis with non-existent APK file."""
        fake_apk = os.path.join(self.test_dir, "nonexistent.apk")
        
        success, result = analyze_developer_apk(
            "TestDeveloper", 
            fake_apk, 
            self.output_dir
        )
        
        self.assertFalse(success)
        self.assertEqual(result["error_type"], "ValidationError")
        self.assertIn("APK file not found", result["error"])
    
    def test_analyze_missing_custom_rules(self):
        """Test analysis when custom rules file is missing."""
        # Mock the custom rules path to point to non-existent file
        with patch('analyze_developer_apk.os.path.join') as mock_join:
            mock_join.return_value = "/nonexistent/rules.json"
            
            success, result = analyze_developer_apk(
                "TestDeveloper", 
                self.test_apk, 
                self.output_dir
            )
            
            self.assertFalse(success)
            self.assertEqual(result["error_type"], "ValidationError")
            self.assertIn("Custom rules file not found", result["error"])
    
    @patch('analyze_developer_apk.run_apkleaks')
    def test_analyze_apkleaks_failure(self, mock_run_apkleaks):
        """Test analysis when APKLeaks fails."""
        mock_run_apkleaks.return_value = None
        
        success, result = analyze_developer_apk(
            "TestDeveloper", 
            self.test_apk, 
            self.output_dir
        )
        
        self.assertFalse(success)
        self.assertEqual(result["error_type"], "APKLeaksError")
        self.assertIn("failed to produce output file", result["error"])
    
    @patch('analyze_developer_apk.run_apkleaks')
    @patch('analyze_developer_apk.parse_apkleaks_json')
    def test_analyze_parsing_failure(self, mock_parse, mock_run_apkleaks):
        """Test analysis when result parsing fails."""
        # Mock APKLeaks success
        mock_output_file = os.path.join(self.test_dir, "apkleaks_output.json")
        with open(mock_output_file, 'w') as f:
            json.dump({"test": "data"}, f)
        
        mock_run_apkleaks.return_value = mock_output_file
        
        # Mock parsing failure
        mock_parse.side_effect = Exception("Parsing failed")
        
        success, result = analyze_developer_apk(
            "TestDeveloper", 
            self.test_apk, 
            self.output_dir
        )
        
        self.assertFalse(success)
        self.assertEqual(result["error_type"], "ParsingError")
        self.assertIn("Failed to parse APKLeaks results", result["error"])
    
    @patch('analyze_developer_apk.run_apkleaks')
    @patch('analyze_developer_apk.parse_apkleaks_json')
    @patch('analyze_developer_apk.save_developers_database')
    def test_analyze_database_save_failure(self, mock_save_db, mock_parse, mock_run_apkleaks):
        """Test analysis when database save fails."""
        # Mock APKLeaks execution success
        mock_output_file = os.path.join(self.test_dir, "apkleaks_output.json")
        with open(mock_output_file, 'w') as f:
            json.dump({"test": "data"}, f)
        
        mock_run_apkleaks.return_value = mock_output_file
        mock_parse.return_value = {"test_keys": {"test_value"}}
        
        # Mock database save failure
        mock_save_db.side_effect = DatabaseError("Permission denied saving database")
        
        success, result = analyze_developer_apk(
            "TestDeveloper", 
            self.test_apk, 
            self.output_dir
        )
        
        self.assertFalse(success)
        self.assertEqual(result["error_type"], "DatabaseError")
        self.assertIn("Permission denied", result["error"])


class TestIntegrationWithRealFiles(unittest.TestCase):
    """Integration tests using real test files."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_resources_dir = Path(__file__).parent / 'resources'
        self.test_apk = self.test_resources_dir / 'test.apk'
        self.test_dir = tempfile.mkdtemp()
        self.output_dir = os.path.join(self.test_dir, "output")
        os.makedirs(self.output_dir)
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @unittest.skipUnless(
        Path(__file__).parent.parent / 'src' / 'scripts' / 'automations' / 'apkleaks_custom_rules.json',
        "Custom rules file not found"
    )
    def test_validate_with_real_apk(self):
        """Test validation with real test APK file."""
        if self.test_apk.exists():
            result = validate_inputs("TestDeveloper", str(self.test_apk), self.output_dir)
            self.assertTrue(result)
        else:
            self.skipTest("Test APK file not found")
    
    def test_database_operations_with_real_data(self):
        """Test database operations with realistic data structure."""
        db_file = os.path.join(self.output_dir, "developers.json")
        
        # Test data matching the specification format
        test_data = {
            "MalwareDev": {
                "appsflyer_api_keys": [
                    "e44a8b69c7d76049d312caec6fb8a01b60982d8f"
                ],
                "onesignal_app_ids": [
                    "00000000-0000-0000-0000-000000000000",
                    "01528cc0-dd34-494d-9218-24af1317e1ee"
                ],
                "firebase_api_keys": [
                    "AIzaSyD4E5f6G7h8I9J0kLmN1oP2qR3sT4uV5wX"
                ]
            },
            "LegitimateApp": {
                "google_maps_api_keys": [
                    "AIzaSyBmaps123456789012345678901234567"
                ]
            }
        }
        
        # Save and load
        save_developers_database(test_data, db_file)
        loaded_data = load_developers_database(db_file)
        
        self.assertEqual(loaded_data, test_data)


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
