# test_path_validator.py - Tests for PathValidator class
import pytest
import os
import tempfile
import stat

from utils.path_validator import PathValidator


class TestPathValidator:
    """Test cases for PathValidator class."""

    def test_init(self):
        """Test PathValidator initialization."""
        validator = PathValidator()
        assert validator is not None

    def test_validate_directory_success(self, path_validator, temp_dir):
        """Test successful directory validation."""
        valid, result = path_validator.validate_directory(temp_dir)
        
        assert valid is True
        assert result == os.path.abspath(temp_dir)

    def test_validate_directory_empty_path(self, path_validator):
        """Test directory validation with empty path."""
        valid, result = path_validator.validate_directory("")
        
        assert valid is False
        assert "Directory path cannot be empty" in result

    def test_validate_directory_none_path(self, path_validator):
        """Test directory validation with None path."""
        valid, result = path_validator.validate_directory(None)
        
        assert valid is False
        assert "Directory path cannot be empty" in result

    def test_validate_directory_nonexistent(self, path_validator):
        """Test directory validation with non-existent directory."""
        nonexistent_path = "/absolutely/non/existent/path/12345"
        valid, result = path_validator.validate_directory(nonexistent_path)
        
        assert valid is False
        assert "Directory does not exist" in result

    def test_validate_directory_file_not_dir(self, path_validator, temp_dir):
        """Test directory validation when path points to a file."""
        # Create a file instead of directory
        file_path = os.path.join(temp_dir, "not_a_directory.txt")
        with open(file_path, "w") as f:
            f.write("test")
        
        valid, result = path_validator.validate_directory(file_path)
        
        assert valid is False
        assert "Path is not a directory" in result

    @pytest.mark.skipif(os.name == 'nt', reason="Permission tests are complex on Windows")
    def test_validate_directory_no_read_permission(self, path_validator, temp_dir):
        """Test directory validation with no read permission."""
        # Create a directory and remove read permission
        no_read_dir = os.path.join(temp_dir, "no_read")
        os.makedirs(no_read_dir)
        
        # Remove read permission
        os.chmod(no_read_dir, stat.S_IWUSR | stat.S_IXUSR)  # Write and execute only
        
        try:
            valid, result = path_validator.validate_directory(no_read_dir)
            assert valid is False
            assert "Directory is not readable" in result
        finally:
            # Restore permissions for cleanup
            os.chmod(no_read_dir, stat.S_IRWXU)

    @pytest.mark.skipif(os.name == 'nt', reason="Permission tests are complex on Windows")
    def test_validate_directory_no_write_permission(self, path_validator, temp_dir):
        """Test directory validation with no write permission."""
        # Create a directory and remove write permission
        no_write_dir = os.path.join(temp_dir, "no_write")
        os.makedirs(no_write_dir)
        
        # Remove write permission
        os.chmod(no_write_dir, stat.S_IRUSR | stat.S_IXUSR)  # Read and execute only
        
        try:
            valid, result = path_validator.validate_directory(no_write_dir)
            assert valid is False
            assert "Directory is not writable" in result
        finally:
            # Restore permissions for cleanup
            os.chmod(no_write_dir, stat.S_IRWXU)

    def test_validate_apk_file_success(self, path_validator, test_directory_with_apk):
        """Test successful APK file validation."""
        apk_filename = "test.apk"
        
        valid, result = path_validator.validate_apk_file(test_directory_with_apk, apk_filename)
        
        assert valid is True
        assert result.endswith("test.apk")
        assert os.path.exists(result)

    def test_validate_apk_file_empty_filename(self, path_validator, temp_dir):
        """Test APK file validation with empty filename."""
        valid, result = path_validator.validate_apk_file(temp_dir, "")
        
        assert valid is False
        assert "APK filename cannot be empty" in result

    def test_validate_apk_file_invalid_directory(self, path_validator):
        """Test APK file validation with invalid directory."""
        valid, result = path_validator.validate_apk_file("/non/existent", "test.apk")
        
        assert valid is False
        assert "Directory does not exist" in result

    def test_validate_apk_file_nonexistent_file(self, path_validator, temp_dir):
        """Test APK file validation with non-existent APK file."""
        valid, result = path_validator.validate_apk_file(temp_dir, "nonexistent.apk")
        
        assert valid is False
        assert "APK file does not exist" in result

    def test_validate_apk_file_wrong_extension(self, path_validator, temp_dir):
        """Test APK file validation with wrong extension."""
        # Create a file with wrong extension
        txt_file = os.path.join(temp_dir, "test.txt")
        with open(txt_file, "w") as f:
            f.write("test")
        
        valid, result = path_validator.validate_apk_file(temp_dir, "test.txt")
        
        assert valid is False
        assert "File must have .apk extension" in result

    def test_validate_apk_file_directory_not_file(self, path_validator, temp_dir):
        """Test APK file validation when APK path points to directory."""
        # Create a directory with .apk name
        apk_dir = os.path.join(temp_dir, "fake.apk")
        os.makedirs(apk_dir)
        
        valid, result = path_validator.validate_apk_file(temp_dir, "fake.apk")
        
        assert valid is False
        assert "APK path is not a file" in result

    @pytest.mark.skipif(os.name == 'nt', reason="Permission tests are complex on Windows")
    def test_validate_apk_file_no_read_permission(self, path_validator, temp_dir):
        """Test APK file validation with no read permission."""
        # Create APK file and remove read permission
        apk_file = os.path.join(temp_dir, "test.apk")
        with open(apk_file, "w") as f:
            f.write("test")
        
        # Remove read permission
        os.chmod(apk_file, stat.S_IWUSR)  # Write only
        
        try:
            valid, result = path_validator.validate_apk_file(temp_dir, "test.apk")
            assert valid is False
            assert "APK file is not readable" in result
        finally:
            # Restore permissions for cleanup
            os.chmod(apk_file, stat.S_IRWXU)

    def test_sanitize_path_normal(self, path_validator):
        """Test path sanitization with normal paths."""
        normal_path = "/home/user/documents"
        result = path_validator.sanitize_path(normal_path)
        
        assert ".." not in result
        assert os.path.isabs(result)

    def test_sanitize_path_traversal_attempts(self, path_validator):
        """Test path sanitization removes path traversal attempts."""
        malicious_paths = [
            "../../../etc/passwd",
            "/home/user/../../../etc/passwd",
            "folder/../../../sensitive",
            "/path//with//double//slashes"
        ]
        
        for malicious_path in malicious_paths:
            result = path_validator.sanitize_path(malicious_path)
            assert ".." not in result

    def test_sanitize_path_empty(self, path_validator):
        """Test path sanitization with empty path."""
        result = path_validator.sanitize_path("")
        assert result == ""

    def test_sanitize_path_none(self, path_validator):
        """Test path sanitization with None path."""
        result = path_validator.sanitize_path(None)
        assert result == ""

    def test_sanitize_path_windows_paths(self, path_validator):
        """Test path sanitization with Windows-style paths."""
        if os.name == 'nt':  # Only run on Windows
            windows_paths = [
                r"C:\Users\test\Documents",
                r"C:\Users\..\Windows\System32",
                r"C:\\Windows\\\\System32"
            ]
            
            for win_path in windows_paths:
                result = path_validator.sanitize_path(win_path)
                assert ".." not in result
                assert os.path.isabs(result)
