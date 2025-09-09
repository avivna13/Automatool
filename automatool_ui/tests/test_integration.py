# test_integration.py - Integration tests for the complete workflow
import pytest
import json
import os
import tempfile
from io import BytesIO
import sys

# Add the parent directory to the path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, app_state
from utils.file_handler import FileHandler
from utils.path_validator import PathValidator


@pytest.fixture
def client():
    """Create a test client for the Flask application."""
    app.config['TESTING'] = True
    app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()
    
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture
def reset_app_state():
    """Reset the global app state before each test."""
    global app_state
    original_state = app_state.copy()
    app_state.update({
        'APK_FILENAME': None,
        'OUTPUT_DIR': None,
        'APK_PATH': None,
        'YARA_PATH': None,
        'setup_complete': False,
        'current_process': None
    })
    yield
    # Reset to original state
    app_state.update(original_state)


@pytest.mark.integration
class TestIntegrationWorkflow:
    """Integration tests for complete workflows."""

    def test_complete_lazy_mode_workflow(self, client, reset_app_state):
        """Test complete lazy mode workflow from upload to ready state."""
        # Step 1: Check initial state
        response = client.get('/api/status')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['state']['setup_complete'] is False

        # Step 2: Upload APK file
        apk_content = b"PK\x03\x04" + b"Mock APK content for integration test" * 20
        upload_response = client.post('/api/upload', data={
            'apk_file': (BytesIO(apk_content), 'integration_test.apk')
        })
        
        assert upload_response.status_code == 200
        upload_data = json.loads(upload_response.data)
        assert upload_data['success'] is True
        assert upload_data['state']['setup_complete'] is True
        
        # Step 3: Verify state persisted
        status_response = client.get('/api/status')
        status_data = json.loads(status_response.data)
        assert status_data['state']['APK_FILENAME'] == 'integration_test.apk'
        assert status_data['state']['OUTPUT_DIR'] is not None
        assert status_data['state']['APK_PATH'] is not None
        assert status_data['state']['setup_complete'] is True
        
        # Step 4: Verify files actually exist
        apk_path = status_data['state']['APK_PATH']
        output_dir = status_data['state']['OUTPUT_DIR']
        
        assert os.path.exists(apk_path)
        assert os.path.exists(output_dir)
        assert os.path.isfile(apk_path)
        assert os.path.isdir(output_dir)

    def test_complete_manual_mode_workflow(self, client, reset_app_state):
        """Test complete manual mode workflow."""
        # Step 1: Create test environment
        current_dir = os.getcwd()
        test_apk_name = "manual_integration_test.apk"
        test_apk_path = os.path.join(current_dir, test_apk_name)
        
        # Create test APK file
        with open(test_apk_path, "wb") as f:
            f.write(b"PK\x03\x04" + b"Manual mode test APK")
        
        try:
            # Step 2: Manual setup
            setup_response = client.post('/api/manual-setup', json={
                'directory_path': current_dir,
                'apk_filename': test_apk_name
            })
            
            assert setup_response.status_code == 200
            setup_data = json.loads(setup_response.data)
            assert setup_data['success'] is True
            assert setup_data['state']['setup_complete'] is True
            
            # Step 3: Verify state
            status_response = client.get('/api/status')
            status_data = json.loads(status_response.data)
            assert status_data['state']['APK_FILENAME'] == test_apk_name
            assert status_data['state']['OUTPUT_DIR'] == os.path.abspath(current_dir)
            assert status_data['state']['APK_PATH'] == test_apk_path
            
        finally:
            # Cleanup
            if os.path.exists(test_apk_path):
                os.remove(test_apk_path)

    def test_lazy_mode_with_yara_workflow(self, client, reset_app_state):
        """Test lazy mode workflow with both APK and YARA files."""
        # Create APK content
        apk_content = b"PK\x03\x04" + b"APK with YARA test" * 15
        
        # Create YARA content
        yara_content = json.dumps({
            "rules": [
                {"name": "test_rule_1", "condition": "true"},
                {"name": "test_rule_2", "condition": "false"}
            ]
        }).encode('utf-8')
        
        # Upload both files
        response = client.post('/api/upload', data={
            'apk_file': (BytesIO(apk_content), 'test_with_yara.apk'),
            'yara_file': (BytesIO(yara_content), 'rules.json')
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['state']['YARA_PATH'] is not None
        
        # Verify YARA file exists and contains correct content
        yara_path = data['state']['YARA_PATH']
        assert os.path.exists(yara_path)
        assert os.path.basename(yara_path) == "yara.json"
        
        with open(yara_path, 'r') as f:
            yara_data = json.load(f)
            assert "rules" in yara_data
            assert len(yara_data["rules"]) == 2

    def test_error_recovery_workflow(self, client, reset_app_state):
        """Test error recovery scenarios."""
        # Step 1: Try invalid upload
        invalid_response = client.post('/api/upload', data={
            'apk_file': (BytesIO(b'not an apk'), 'invalid.txt')
        })
        
        assert invalid_response.status_code == 200
        invalid_data = json.loads(invalid_response.data)
        assert invalid_data['success'] is False
        
        # Step 2: Verify state remains unchanged
        status_response = client.get('/api/status')
        status_data = json.loads(status_response.data)
        assert status_data['state']['setup_complete'] is False
        
        # Step 3: Now do successful upload
        apk_content = b"PK\x03\x04" + b"Recovery test APK" * 10
        success_response = client.post('/api/upload', data={
            'apk_file': (BytesIO(apk_content), 'recovery_test.apk')
        })
        
        assert success_response.status_code == 200
        success_data = json.loads(success_response.data)
        assert success_data['success'] is True
        assert success_data['state']['setup_complete'] is True

    def test_multiple_uploads_workflow(self, client, reset_app_state):
        """Test multiple uploads overwrite previous state."""
        # First upload
        apk1_content = b"PK\x03\x04" + b"First APK" * 10
        response1 = client.post('/api/upload', data={
            'apk_file': (BytesIO(apk1_content), 'first.apk')
        })
        
        data1 = json.loads(response1.data)
        first_output_dir = data1['state']['OUTPUT_DIR']
        
        # Second upload
        apk2_content = b"PK\x03\x04" + b"Second APK" * 10
        response2 = client.post('/api/upload', data={
            'apk_file': (BytesIO(apk2_content), 'second.apk')
        })
        
        data2 = json.loads(response2.data)
        second_output_dir = data2['state']['OUTPUT_DIR']
        
        # Verify state updated to second upload
        assert data2['state']['APK_FILENAME'] == 'second.apk'
        assert second_output_dir != first_output_dir
        
        # Verify both directories exist
        assert os.path.exists(first_output_dir)
        assert os.path.exists(second_output_dir)

    def test_state_consistency_across_requests(self, client, reset_app_state):
        """Test that state remains consistent across multiple requests."""
        # Upload file
        apk_content = b"PK\x03\x04" + b"Consistency test" * 10
        client.post('/api/upload', data={
            'apk_file': (BytesIO(apk_content), 'consistency.apk')
        })
        
        # Make multiple status requests
        responses = [client.get('/api/status') for _ in range(5)]
        
        # All responses should be identical
        first_data = json.loads(responses[0].data)
        for response in responses[1:]:
            assert response.status_code == 200
            current_data = json.loads(response.data)
            assert current_data['state'] == first_data['state']

    @pytest.mark.slow
    def test_large_file_handling(self, client, reset_app_state):
        """Test handling of larger APK files."""
        # Create a moderately large APK (1MB)
        large_content = b"PK\x03\x04" + b"X" * (1024 * 1024)
        
        response = client.post('/api/upload', data={
            'apk_file': (BytesIO(large_content), 'large_test.apk')
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        
        # Verify file was saved correctly
        apk_path = data['state']['APK_PATH']
        assert os.path.exists(apk_path)
        
        # Verify file size
        file_size = os.path.getsize(apk_path)
        expected_size = len(large_content)
        assert file_size == expected_size
