# test_file_handler.py - Tests for FileHandler class
import pytest
import os
import tempfile
from datetime import datetime
from io import BytesIO
from werkzeug.datastructures import FileStorage

from utils.file_handler import FileHandler


class TestFileHandler:
    """Test cases for FileHandler class."""

    def test_init(self, temp_dir):
        """Test FileHandler initialization."""
        handler = FileHandler(upload_dir=temp_dir)
        assert handler.upload_dir == temp_dir
        assert handler.max_size == 500 * 1024 * 1024  # 500MB
        assert handler.allowed_extensions == {'.apk', '.json'}

    def test_create_analysis_directory(self, file_handler):
        """Test analysis directory creation."""
        # Create directory
        dir_path = file_handler.create_analysis_directory()
        
        # Verify directory exists
        assert os.path.exists(dir_path)
        assert os.path.isdir(dir_path)
        
        # Verify naming convention (timestamp_analysis)
        dir_name = os.path.basename(dir_path)
        assert dir_name.endswith('_analysis')
        
        # Verify timestamp format (YYYYMMDD_HHMMSS)
        timestamp_part = dir_name.replace('_analysis', '')
        try:
            datetime.strptime(timestamp_part, '%Y%m%d_%H%M%S')
        except ValueError:
            pytest.fail("Directory name doesn't follow timestamp format")

    def test_create_multiple_analysis_directories(self, file_handler):
        """Test that multiple directories have unique names."""
        dir1 = file_handler.create_analysis_directory()
        dir2 = file_handler.create_analysis_directory()
        
        assert dir1 != dir2
        assert os.path.exists(dir1)
        assert os.path.exists(dir2)

    def test_validate_and_save_apk_success(self, file_handler, mock_apk_file, temp_dir):
        """Test successful APK file validation and saving."""
        output_dir = os.path.join(temp_dir, "output")
        os.makedirs(output_dir)
        
        filepath, error = file_handler.validate_and_save_apk(mock_apk_file, output_dir)
        
        assert error is None
        assert filepath is not None
        assert os.path.exists(filepath)
        assert filepath.endswith('.apk')
        assert os.path.basename(filepath) == "test_app.apk"

    def test_validate_and_save_apk_no_file(self, file_handler, temp_dir):
        """Test APK validation with no file provided."""
        output_dir = os.path.join(temp_dir, "output")
        os.makedirs(output_dir)
        
        filepath, error = file_handler.validate_and_save_apk(None, output_dir)
        
        assert filepath is None
        assert error == "No file provided"

    def test_validate_and_save_apk_empty_filename(self, file_handler, temp_dir):
        """Test APK validation with empty filename."""
        output_dir = os.path.join(temp_dir, "output")
        os.makedirs(output_dir)
        
        # Create file with empty filename
        empty_file = FileStorage(stream=BytesIO(b"content"), filename="")
        
        filepath, error = file_handler.validate_and_save_apk(empty_file, output_dir)
        
        assert filepath is None
        assert error == "No file provided"

    def test_validate_and_save_apk_wrong_extension(self, file_handler, mock_invalid_file, temp_dir):
        """Test APK validation with wrong file extension."""
        output_dir = os.path.join(temp_dir, "output")
        os.makedirs(output_dir)
        
        filepath, error = file_handler.validate_and_save_apk(mock_invalid_file, output_dir)
        
        assert filepath is None
        assert error == "File must be an APK"

    def test_validate_and_save_apk_too_large(self, file_handler, temp_dir):
        """Test APK validation with file too large."""
        output_dir = os.path.join(temp_dir, "output")
        os.makedirs(output_dir)
        
        # Create a file that's too large (simulate by setting smaller max_size)
        handler = FileHandler(upload_dir=temp_dir, max_size=1024)  # 1KB limit
        large_content = b"X" * 2048  # 2KB file
        large_file = FileStorage(
            stream=BytesIO(large_content),
            filename="large.apk"
        )
        
        filepath, error = handler.validate_and_save_apk(large_file, output_dir)
        
        assert filepath is None
        assert "File too large" in error

    def test_validate_and_save_yara_success(self, file_handler, mock_yara_file, temp_dir):
        """Test successful YARA file validation and saving."""
        output_dir = os.path.join(temp_dir, "output")
        os.makedirs(output_dir)
        
        filepath, error = file_handler.validate_and_save_yara(mock_yara_file, output_dir)
        
        assert error is None
        assert filepath is not None
        assert os.path.exists(filepath)
        assert os.path.basename(filepath) == "yara.json"

    def test_validate_and_save_yara_no_file(self, file_handler, temp_dir):
        """Test YARA validation with no file (should be allowed)."""
        output_dir = os.path.join(temp_dir, "output")
        os.makedirs(output_dir)
        
        filepath, error = file_handler.validate_and_save_yara(None, output_dir)
        
        assert filepath is None
        assert error is None  # YARA is optional

    def test_validate_and_save_yara_wrong_extension(self, file_handler, temp_dir):
        """Test YARA validation with wrong file extension."""
        output_dir = os.path.join(temp_dir, "output")
        os.makedirs(output_dir)
        
        # Create non-JSON file
        txt_file = FileStorage(
            stream=BytesIO(b"not json"),
            filename="rules.txt"
        )
        
        filepath, error = file_handler.validate_and_save_yara(txt_file, output_dir)
        
        assert filepath is None
        assert error == "YARA file must be JSON"

    def test_is_valid_extension(self, file_handler):
        """Test file extension validation."""
        assert file_handler.is_valid_extension("test.apk", ".apk")
        assert file_handler.is_valid_extension("test.APK", ".apk")  # Case insensitive
        assert file_handler.is_valid_extension("rules.json", ".json")
        assert not file_handler.is_valid_extension("test.txt", ".apk")
        assert not file_handler.is_valid_extension("test", ".apk")

    def test_get_file_size_mb(self, file_handler, temp_dir):
        """Test file size calculation."""
        # Create a test file
        test_file = os.path.join(temp_dir, "test.txt")
        content = b"X" * 1024  # 1KB
        with open(test_file, "wb") as f:
            f.write(content)
        
        size_mb = file_handler.get_file_size_mb(test_file)
        expected_size = 1024 / (1024 * 1024)  # Convert to MB
        assert abs(size_mb - expected_size) < 0.001  # Allow small floating point errors

    def test_get_file_size_mb_nonexistent(self, file_handler):
        """Test file size calculation for non-existent file."""
        size_mb = file_handler.get_file_size_mb("/non/existent/file.txt")
        assert size_mb == 0
