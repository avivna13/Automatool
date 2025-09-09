import os
import tempfile
import shutil
import pytest
from unittest.mock import patch
import sys

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scripts.automations.detect_image_steganography import (
    detect_image_steganography, 
    _analyze_image_file, 
    _detect_image_format,
    _generate_simple_report
)
from scripts.parsers.parse_steganography_results import (
    parse_steganography_results,
    generate_combined_summary
)


class TestSteganographyDetection:
    """Test suite for image steganography detection automation."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def test_clean_image_path(self):
        """Get the path to the test clean image file."""
        return os.path.join(os.path.dirname(__file__), 'resources', 'test_encrypted_image.png')
    
    @pytest.fixture
    def test_suspicious_image_path(self):
        """Get the path to the test suspicious image file."""
        return os.path.join(os.path.dirname(__file__), 'resources', 'test_suspicious_image.png')
    
    @pytest.fixture
    def test_resources_dir(self):
        """Get the path to test resources directory."""
        return os.path.join(os.path.dirname(__file__), 'resources')

    def test_clean_image_detection(self, temp_dir, test_clean_image_path):
        """Test detection of the clean image with no trailing data."""
        print(f"\n🧪 Testing clean image detection with: {test_clean_image_path}")
        
        # Verify the test image exists
        assert os.path.exists(test_clean_image_path), f"Test image not found: {test_clean_image_path}"
        
        # Run steganography detection with default threshold (10 bytes)
        result = detect_image_steganography(
            image_path=test_clean_image_path,
            output_directory=temp_dir,
            verbose=True,
            threshold_bytes=10
        )
        
        # Verify the function succeeded
        assert result is not None, "Detection function should return a result"
        
        # Verify the result structure
        assert isinstance(result, dict), "Result should be a dictionary"
        required_keys = ['image_path', 'image_format', 'image_size', 'legitimate_end_offset', 
                        'trailing_bytes', 'threshold_bytes', 'is_suspicious']
        for key in required_keys:
            assert key in result, f"Result should contain key: {key}"
        
        # Verify the image is detected as PNG
        assert result['image_format'] == 'PNG', "Test image should be detected as PNG format"
        
        # Verify the image is classified as clean (not suspicious)
        assert result['is_suspicious'] == False, "Clean image should not be classified as suspicious"
        
        # Verify trailing bytes are below threshold
        assert result['trailing_bytes'] < 10, f"Clean image should have < 10 trailing bytes, got {result['trailing_bytes']}"
        
        # Verify analysis directory was created
        analysis_dir = os.path.join(temp_dir, "steganography_analysis")
        assert os.path.exists(analysis_dir), "Analysis directory should be created"
        
        # Verify no suspicious report was generated for clean image
        assert 'report_file' not in result, "Clean image should not have a report file"
        
        print(f"✅ Image correctly classified as clean with {result['trailing_bytes']} trailing bytes")

    def test_suspicious_image_detection(self, temp_dir, test_suspicious_image_path):
        """Test detection of the suspicious image with trailing data."""
        print(f"\n🧪 Testing suspicious image detection with: {test_suspicious_image_path}")
        
        # Verify the test image exists
        assert os.path.exists(test_suspicious_image_path), f"Test image not found: {test_suspicious_image_path}"
        
        # Run steganography detection with default threshold (10 bytes)
        result = detect_image_steganography(
            image_path=test_suspicious_image_path,
            output_directory=temp_dir,
            verbose=True,
            threshold_bytes=10
        )
        
        # Verify the function succeeded
        assert result is not None, "Detection function should return a result"
        
        # Verify the result structure
        assert isinstance(result, dict), "Result should be a dictionary"
        required_keys = ['image_path', 'image_format', 'image_size', 'legitimate_end_offset', 
                        'trailing_bytes', 'threshold_bytes', 'is_suspicious']
        for key in required_keys:
            assert key in result, f"Result should contain key: {key}"
        
        # Verify the image is detected as PNG
        assert result['image_format'] == 'PNG', "Test image should be detected as PNG format"
        
        # Verify the image is classified as suspicious
        assert result['is_suspicious'] == True, "Test image should be classified as suspicious"
        
        # Verify trailing bytes exceed threshold
        assert result['trailing_bytes'] >= 10, f"Test image should have >= 10 trailing bytes, got {result['trailing_bytes']}"
        
        # Verify analysis directory was created
        analysis_dir = os.path.join(temp_dir, "steganography_analysis")
        assert os.path.exists(analysis_dir), "Analysis directory should be created"
        
        # Verify suspicious report was generated
        assert 'report_file' in result, "Suspicious image should have a report file"
        assert os.path.exists(result['report_file']), "Report file should exist"
        
        print(f"✅ Image classified as suspicious with {result['trailing_bytes']} trailing bytes")

    def test_threshold_behavior_with_suspicious_image(self, temp_dir, test_suspicious_image_path):
        """Test threshold behavior with suspicious image - high threshold should make it clean."""
        print(f"\n🧪 Testing threshold behavior with suspicious image")
        
        # First, get the actual trailing bytes count
        initial_result = detect_image_steganography(
            image_path=test_suspicious_image_path,
            output_directory=temp_dir,
            verbose=False,
            threshold_bytes=10
        )
        
        trailing_bytes = initial_result['trailing_bytes']
        high_threshold = trailing_bytes + 50  # Set threshold higher than actual trailing bytes
        
        # Clear the temp directory for clean test
        shutil.rmtree(temp_dir)
        os.makedirs(temp_dir)
        
        # Run detection with high threshold
        result = detect_image_steganography(
            image_path=test_suspicious_image_path,
            output_directory=temp_dir,
            verbose=True,
            threshold_bytes=high_threshold
        )
        
        # Verify the image is now classified as clean due to high threshold
        assert result['is_suspicious'] == False, f"Image should be clean with threshold {high_threshold}"
        assert result['trailing_bytes'] == trailing_bytes, "Trailing bytes count should be consistent"
        assert 'report_file' not in result, "Clean images should not generate reports"
        
        print(f"✅ Image classified as clean with threshold {high_threshold} (trailing bytes: {trailing_bytes})")

    def test_format_detection_png(self, test_clean_image_path):
        """Test PNG format detection specifically."""
        print(f"\n🧪 Testing PNG format detection")
        
        # Read the test image
        with open(test_clean_image_path, 'rb') as f:
            file_data = f.read()
        
        # Test format detection
        format_info = _detect_image_format(file_data, verbose=True)
        
        assert format_info is not None, "Format detection should succeed"
        assert format_info['format'] == 'PNG', "Should detect PNG format"
        assert 'end_offset' in format_info, "Should find end offset"
        assert 'marker_position' in format_info, "Should find IEND marker position"
        
        # Verify IEND marker was found
        iend_pos = format_info['marker_position']
        assert iend_pos > 0, "IEND marker should be found at valid position"
        
        # Verify PNG signature
        assert file_data.startswith(b'\x89PNG\r\n\x1a\n'), "File should have valid PNG signature"
        
        # Verify IEND marker exists at reported position
        assert file_data[iend_pos:iend_pos+4] == b'IEND', "IEND marker should be at reported position"
        
        print(f"✅ PNG format detected, IEND at offset {iend_pos}, legitimate end at {format_info['end_offset']}")

    def test_analyze_image_file_direct(self, temp_dir, test_suspicious_image_path):
        """Test the core analysis function directly."""
        print(f"\n🧪 Testing core analysis function")
        
        # Test with different thresholds
        thresholds_to_test = [1, 10, 100, 200]  # 200 > 130 trailing bytes
        
        for threshold in thresholds_to_test:
            result = _analyze_image_file(
                image_path=test_suspicious_image_path,
                results_dir=temp_dir,
                threshold_bytes=threshold,
                verbose=True
            )
            
            assert result is not None, f"Analysis should succeed with threshold {threshold}"
            assert result['threshold_bytes'] == threshold, f"Threshold should be set to {threshold}"
            
            # Determine expected classification
            expected_suspicious = result['trailing_bytes'] >= threshold
            assert result['is_suspicious'] == expected_suspicious, f"Classification should match threshold {threshold}"
            
            print(f"  ✓ Threshold {threshold}: {'SUSPICIOUS' if result['is_suspicious'] else 'CLEAN'}")

    def test_results_parsing(self, temp_dir, test_suspicious_image_path):
        """Test the results parsing functionality."""
        print(f"\n🧪 Testing results parsing")
        
        # First, run detection to generate results
        result = detect_image_steganography(
            image_path=test_suspicious_image_path,
            output_directory=temp_dir,
            verbose=True,
            threshold_bytes=10
        )
        
        assert result['is_suspicious'], "Image should be suspicious for this test"
        
        # Now test parsing the results
        summary = parse_steganography_results(
            results_directory=temp_dir,
            verbose=True
        )
        
        assert isinstance(summary, str), "Summary should be a string"
        assert "STEGANOGRAPHY ANALYSIS SUMMARY" in summary, "Summary should have proper header"
        assert "SUSPICIOUS ACTIVITY DETECTED" in summary, "Summary should indicate suspicious activity"
        assert "test_suspicious_image.png" in summary, "Summary should mention the test image"
        
        # Verify summary file was created
        summary_file = os.path.join(temp_dir, "steganography_analysis", "steganography_summary.txt")
        assert os.path.exists(summary_file), "Summary file should be created"
        
        print("✅ Results parsing successful")

    def test_combined_summary_generation(self, temp_dir, test_suspicious_image_path):
        """Test combined summary generation for multiple results."""
        print(f"\n🧪 Testing combined summary generation")
        
        # Generate multiple test results
        result1 = detect_image_steganography(
            image_path=test_suspicious_image_path,
            output_directory=temp_dir,
            verbose=False,
            threshold_bytes=10
        )
        
        # Create a mock clean result
        result2 = {
            'image_path': '/fake/clean_image.png',
            'image_format': 'PNG',
            'image_size': 1000,
            'legitimate_end_offset': 1000,
            'trailing_bytes': 0,
            'threshold_bytes': 10,
            'is_suspicious': False
        }
        
        # Generate combined summary
        combined_summary = generate_combined_summary(
            results_list=[result1, result2],
            output_dir=temp_dir,
            verbose=True
        )
        
        assert isinstance(combined_summary, str), "Combined summary should be a string"
        assert "COMBINED STEGANOGRAPHY ANALYSIS RESULTS" in combined_summary, "Should have proper header"
        assert "Total images analyzed: 2" in combined_summary, "Should show correct total count"
        assert "Suspicious images found: 1" in combined_summary, "Should show correct suspicious count"
        assert "test_suspicious_image.png" in combined_summary, "Should list the suspicious image"
        
        # Verify combined summary file was created
        combined_file = os.path.join(temp_dir, "steganography_combined_summary.txt")
        assert os.path.exists(combined_file), "Combined summary file should be created"
        
        print("✅ Combined summary generation successful")

    def test_report_generation(self, temp_dir, test_suspicious_image_path):
        """Test suspicious image report generation."""
        print(f"\n🧪 Testing report generation")
        
        # Run analysis to get result
        result = _analyze_image_file(
            image_path=test_suspicious_image_path,
            results_dir=temp_dir,
            threshold_bytes=10,
            verbose=True
        )
        
        assert result['is_suspicious'], "Image should be suspicious for this test"
        
        # Generate report
        report_file = _generate_simple_report(
            analysis_result=result,
            results_dir=temp_dir,
            verbose=True
        )
        
        assert os.path.exists(report_file), "Report file should be created"
        
        # Read and verify report content
        with open(report_file, 'r') as f:
            report_content = f.read()
        
        assert "SUSPICIOUS IMAGE DETECTED" in report_content, "Report should have proper header"
        assert "test_suspicious_image.png" in report_content, "Report should mention the image name"
        assert "PNG" in report_content, "Report should mention the format"
        assert "WARNING: Manual investigation required" in report_content, "Report should have recommendation"
        
        print("✅ Report generation successful")

    def test_error_handling_missing_file(self, temp_dir):
        """Test error handling for missing image file."""
        print(f"\n🧪 Testing error handling for missing file")
        
        fake_path = os.path.join(temp_dir, "nonexistent_image.png")
        
        result = detect_image_steganography(
            image_path=fake_path,
            output_directory=temp_dir,
            verbose=True,
            threshold_bytes=10
        )
        
        assert result is None, "Should return None for missing file"
        print("✅ Error handling for missing file successful")

    def test_error_handling_invalid_image(self, temp_dir):
        """Test error handling for invalid image file."""
        print(f"\n🧪 Testing error handling for invalid image")
        
        # Create a fake image file with invalid content
        fake_image = os.path.join(temp_dir, "fake_image.png")
        with open(fake_image, 'w') as f:
            f.write("This is not an image file")
        
        result = detect_image_steganography(
            image_path=fake_image,
            output_directory=temp_dir,
            verbose=True,
            threshold_bytes=10
        )
        
        assert result is None, "Should return None for invalid image format"
        print("✅ Error handling for invalid image successful")

    def test_threshold_edge_cases(self, temp_dir, test_suspicious_image_path):
        """Test edge cases with different threshold values."""
        print(f"\n🧪 Testing threshold edge cases")
        
        # First get actual trailing bytes
        result = _analyze_image_file(
            image_path=test_suspicious_image_path,
            results_dir=temp_dir,
            threshold_bytes=1,
            verbose=False
        )
        
        actual_trailing = result['trailing_bytes']
        print(f"Actual trailing bytes in test image: {actual_trailing}")
        
        # Test edge cases
        test_cases = [
            (0, True),  # 0 threshold - should be suspicious if any trailing data
            (actual_trailing - 1, True),  # Just below actual - should be suspicious
            (actual_trailing, True),  # Exactly equal - should be suspicious
            (actual_trailing + 1, False),  # Just above actual - should be clean
        ]
        
        for threshold, expected_suspicious in test_cases:
            if threshold < 0:
                continue
                
            result = _analyze_image_file(
                image_path=test_suspicious_image_path,
                results_dir=temp_dir,
                threshold_bytes=threshold,
                verbose=False
            )
            
            assert result['is_suspicious'] == expected_suspicious, \
                f"Threshold {threshold} should result in suspicious={expected_suspicious}"
            
            print(f"  ✓ Threshold {threshold}: {'SUSPICIOUS' if result['is_suspicious'] else 'CLEAN'} (expected: {expected_suspicious})")

    def test_verbose_output_capture(self, temp_dir, test_clean_image_path, capsys):
        """Test that verbose output is properly generated."""
        print(f"\n🧪 Testing verbose output")
        
        # Run with verbose=True
        result = detect_image_steganography(
            image_path=test_clean_image_path,
            output_directory=temp_dir,
            verbose=True,
            threshold_bytes=10
        )
        
        # Capture the output
        captured = capsys.readouterr()
        
        # Verify key debug messages are present
        assert "[DEBUG] Analyzing image for steganography" in captured.out, "Should show analysis start"
        assert "[DEBUG] Detected PNG format" in captured.out, "Should show format detection"
        assert "[DEBUG] Found IEND at offset" in captured.out, "Should show IEND detection"
        assert "[DEBUG] Trailing data size:" in captured.out, "Should show trailing data info"
        assert "[DEBUG] Classification:" in captured.out, "Should show classification"
        
        print("✅ Verbose output capture successful")

if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v", "-s"])
