#!/usr/bin/env python3
"""
Simple Test Suite for TTF Font Steganography Detection

Tests the detect_ttf_steganography module with the myfont.ttf file from resources.
This version focuses on core functionality without external dependencies.
"""

import os
import sys
import tempfile
import shutil
import unittest
from pathlib import Path

# Add the scripts directory to the path for imports
script_dir = Path(__file__).parent.parent / "src" / "scripts" / "automations"
sys.path.insert(0, str(script_dir))

# Import the module to test
from detect_ttf_steganography import detect_ttf_steganography


class TestTTFSteganographyDetectionSimple(unittest.TestCase):
    """Simple test suite for TTF font steganography detection."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create temporary directory for test outputs
        self.test_output_dir = tempfile.mkdtemp()
        
        # Path to the test font file
        self.test_font_path = Path(__file__).parent / "resources" / "myfont.ttf"
        
        # Expected threshold (150 KB)
        self.expected_threshold = 150 * 1024  # 150 KB
        
        print(f"\n🧪 Setting up TTF steganography detection tests...")
        print(f"📁 Test output directory: {self.test_output_dir}")
        print(f"🔤 Test font file: {self.test_font_path}")
        print(f"📏 Expected threshold: {self.expected_threshold} bytes ({self.expected_threshold/1024:.1f} KB)")
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.test_output_dir):
            shutil.rmtree(self.test_output_dir)
        print(f"🧹 Cleaned up test directory: {self.test_output_dir}")
    
    def test_01_myfont_ttf_detection(self):
        """Test detection against the actual myfont.ttf file (8.1 MB - should be suspicious)."""
        print(f"\n🧪 Testing myfont.ttf detection (8.1 MB file)")
        
        # Verify test file exists
        self.assertTrue(self.test_font_path.exists(), f"Test font file not found: {self.test_font_path}")
        
        # Get actual file size
        actual_size = os.path.getsize(self.test_font_path)
        print(f"📏 Actual file size: {actual_size} bytes ({actual_size/1024/1024:.1f} MB)")
        
        # This should definitely be above our 150 KB threshold
        self.assertGreater(actual_size, self.expected_threshold, 
                          f"Test font ({actual_size} bytes) should be above threshold ({self.expected_threshold} bytes)")
        
        # Run detection
        result = detect_ttf_steganography(str(self.test_font_path), self.test_output_dir, verbose=True)
        
        # Verify result
        self.assertIsNotNone(result, "Detection should return a result")
        self.assertEqual(result['font_path'], str(self.test_font_path))
        self.assertEqual(result['font_size'], actual_size)
        self.assertEqual(result['threshold_bytes'], self.expected_threshold)
        self.assertTrue(result['is_suspicious'], "8.1 MB font should be flagged as suspicious")
        self.assertIsNotNone(result['report_file'], "Suspicious font should generate a report")
        
        # Verify report file was created
        self.assertTrue(os.path.exists(result['report_file']), "Report file should be created")
        
        print(f"✅ myfont.ttf correctly detected as suspicious")
        print(f"📄 Report generated: {result['report_file']}")
    
    def test_02_report_content_validation(self):
        """Test that the generated report contains correct information."""
        print(f"\n🧪 Testing report content validation")
        
        # Run detection to generate report
        result = detect_ttf_steganography(str(self.test_font_path), self.test_output_dir, verbose=False)
        
        # Read and validate report content
        with open(result['report_file'], 'r') as f:
            report_content = f.read()
        
        # Check for key information
        self.assertIn("SUSPICIOUS TTF FONT DETECTED", report_content)
        self.assertIn("myfont.ttf", report_content)
        self.assertIn("150.0 KB", report_content)  # Threshold
        self.assertIn("WARNING: Manual investigation required", report_content)
        self.assertIn("Hidden data or steganographic payloads", report_content)
        
        print(f"✅ Report content validation passed")
    
    def test_03_threshold_calculation(self):
        """Test that the threshold is correctly calculated as 150 KB."""
        print(f"\n🧪 Testing threshold calculation")
        
        # Run detection
        result = detect_ttf_steganography(str(self.test_font_path), self.test_output_dir, verbose=False)
        
        # Verify threshold
        expected_threshold = 150 * 1024  # 150 KB
        self.assertEqual(result['threshold_bytes'], expected_threshold)
        self.assertEqual(result['threshold_bytes'], 153600)  # Exact bytes
        
        print(f"✅ Threshold calculation correct: {result['threshold_bytes']} bytes ({result['threshold_bytes']/1024:.1f} KB)")
    
    def test_04_file_validation(self):
        """Test file validation logic."""
        print(f"\n🧪 Testing file validation logic")
        
        # Test with non-existent file
        result = detect_ttf_steganography("/nonexistent/font.ttf", self.test_output_dir, verbose=False)
        self.assertIsNone(result, "Non-existent file should return None")
        
        # Test with non-TTF file (create a temporary text file)
        temp_text_file = os.path.join(self.test_output_dir, "test.txt")
        with open(temp_text_file, 'w') as f:
            f.write("This is not a TTF font")
        
        result = detect_ttf_steganography(temp_text_file, self.test_output_dir, verbose=False)
        self.assertIsNone(result, "Non-TTF file should return None")
        
        print(f"✅ File validation logic working correctly")
    
    def test_05_output_directory_creation(self):
        """Test that output directories are created correctly."""
        print(f"\n🧪 Testing output directory creation")
        
        # Run detection
        result = detect_ttf_steganography(str(self.test_font_path), self.test_output_dir, verbose=False)
        
        # Check that font_steganography_analysis directory was created
        expected_dir = os.path.join(self.test_output_dir, "font_steganography_analysis")
        self.assertTrue(os.path.exists(expected_dir), "Output directory should be created")
        
        # Check that it's a directory
        self.assertTrue(os.path.isdir(expected_dir), "Output should be a directory")
        
        print(f"✅ Output directory creation working correctly")
    
    def test_06_verbose_output(self):
        """Test verbose output functionality."""
        print(f"\n🧪 Testing verbose output functionality")
        
        # Capture stdout to check verbose output
        import io
        from contextlib import redirect_stdout
        
        # Test with verbose=True - fix the buffer handling
        buf = io.StringIO()
        with redirect_stdout(buf):
            result = detect_ttf_steganography(str(self.test_font_path), self.test_output_dir, verbose=True)
        
        verbose_output = buf.getvalue()
        buf.close()
        
        # Check for debug information
        self.assertIn("[DEBUG]", verbose_output)
        self.assertIn("Analyzing TTF font for steganography", verbose_output)
        self.assertIn("TTF file size:", verbose_output)
        self.assertIn("Threshold:", verbose_output)
        self.assertIn("Classification: SUSPICIOUS", verbose_output)
        
        print(f"✅ Verbose output working correctly")
    
    def test_07_performance_characteristics(self):
        """Test performance characteristics (should be fast)."""
        print(f"\n🧪 Testing performance characteristics")
        
        import time
        
        # Time the detection
        start_time = time.time()
        result = detect_ttf_steganography(str(self.test_font_path), self.test_output_dir, verbose=False)
        end_time = time.time()
        
        execution_time = end_time - start_time
        
        # Should be very fast (< 100ms for file size check)
        self.assertLess(execution_time, 0.1, f"Detection should be fast, took {execution_time:.3f}s")
        
        print(f"✅ Performance test passed: {execution_time:.3f}s (under 100ms threshold)")


def run_tests():
    """Run the test suite."""
    print("🧪 Starting TTF Font Steganography Detection Tests (Simple Version)")
    print("=" * 70)
    
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestTTFSteganographyDetectionSimple)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 70)
    print("📊 Test Results Summary")
    print(f"✅ Tests run: {result.testsRun}")
    print(f"❌ Failures: {len(result.failures)}")
    print(f"⚠️  Errors: {len(result.errors)}")
    
    if result.failures:
        print("\n❌ Test Failures:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback}")
    
    if result.errors:
        print("\n⚠️  Test Errors:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
