# conftest.py - pytest configuration and fixtures
import pytest
import os
import tempfile
import shutil
from io import BytesIO
from werkzeug.datastructures import FileStorage
import sys

# Add the parent directory to the path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.file_handler import FileHandler
from utils.path_validator import PathValidator


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    temp_path = tempfile.mkdtemp()
    yield temp_path
    # Cleanup after test
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def file_handler(temp_dir):
    """Create a FileHandler instance with temporary upload directory."""
    return FileHandler(upload_dir=temp_dir)


@pytest.fixture
def path_validator():
    """Create a PathValidator instance."""
    return PathValidator()


@pytest.fixture
def mock_apk_file():
    """Create a mock APK file for testing."""
    # Create a small file that mimics an APK
    content = b"PK\x03\x04" + b"Mock APK content for testing" * 100  # Small APK-like content
    file_obj = BytesIO(content)
    return FileStorage(
        stream=file_obj,
        filename="test_app.apk",
        content_type="application/vnd.android.package-archive"
    )


@pytest.fixture
def mock_large_apk_file():
    """Create a mock large APK file for testing size limits."""
    # Create a file larger than the limit (simulate 600MB)
    large_content = b"X" * (600 * 1024 * 1024)  # 600MB
    file_obj = BytesIO(large_content)
    return FileStorage(
        stream=file_obj,
        filename="large_app.apk",
        content_type="application/vnd.android.package-archive"
    )


@pytest.fixture
def mock_yara_file():
    """Create a mock YARA JSON file for testing."""
    json_content = b'{"rules": [{"name": "test_rule", "condition": "true"}]}'
    file_obj = BytesIO(json_content)
    return FileStorage(
        stream=file_obj,
        filename="yara_rules.json",
        content_type="application/json"
    )


@pytest.fixture
def mock_invalid_file():
    """Create a mock invalid file for testing."""
    content = b"This is not an APK file"
    file_obj = BytesIO(content)
    return FileStorage(
        stream=file_obj,
        filename="not_an_apk.txt",
        content_type="text/plain"
    )


@pytest.fixture
def test_apk_file(temp_dir):
    """Create a real test APK file on disk."""
    apk_path = os.path.join(temp_dir, "test.apk")
    with open(apk_path, "wb") as f:
        f.write(b"PK\x03\x04" + b"Mock APK content" * 50)
    return apk_path


@pytest.fixture
def test_directory_with_apk(temp_dir, test_apk_file):
    """Create a test directory containing an APK file."""
    return temp_dir
