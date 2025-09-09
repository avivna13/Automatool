#!/usr/bin/env python3
"""
Enhanced Test Suite for Image Steganography Detection

This enhanced test suite covers:
1. Edge cases and error handling
2. Performance with large files
3. Memory usage optimization
4. Real-world APK analysis scenarios
5. Additional image format support
6. Robustness improvements
"""

import os
import sys
import tempfile
import shutil
import time
import pytest
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import psutil
import gc

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scripts.automations.detect_image_steganography import (
    detect_image_steganography, 
    _analyze_image_file, 
    _detect_image_format,
    _generate_simple_report
)


class TestSteganographyDetectionEnhanced(unittest.TestCase):
    """Enhanced test suite for image steganography detection automation."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create temporary directory for test outputs
        self.test_output_dir = tempfile.mkdtemp()
        
        # Path to test resources
        self.resources_dir = Path(__file__).parent / "resources"
        
        # Test image paths
        self.clean_image_path = self.resources_dir / "test_encrypted_image.png"
        self.suspicious_image_path = self.resources_dir / "test_suspicious_image.png"
        self.trailing_data_image_path = self.resources_dir / "test_image_with_trailing_data.png"
        
        print(f"\n🧪 Setting up enhanced steganography detection tests...")
        print(f"📁 Test output directory: {self.test_output_dir}")
        print(f"🔤 Test resources directory: {self.resources_dir}")
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.test_output_dir):
            shutil.rmtree(self.test_output_dir)
        print(f"🧹 Cleaned up test directory: {self.test_output_dir}")
    
    def test_01_basic_functionality_verification(self):
        """Test basic functionality with existing test images."""
        print(f"\n🧪 Testing basic functionality verification")
        
        # Test clean image
        result = detect_image_steganography(
            str(self.clean_image_path), 
            self.test_output_dir, 
            verbose=True
        )
        
        self.assertIsNotNone(result, "Clean image analysis should return result")
        self.assertIsInstance(result, dict, "Result should be a dictionary")
        self.assertIn('is_suspicious', result, "Result should contain suspicious flag")
        
        # Test suspicious image
        result = detect_image_steganography(
            str(self.suspicious_image_path), 
            self.test_output_dir, 
            verbose=True
        )
        
        self.assertIsNotNone(result, "Suspicious image analysis should return result")
        self.assertTrue(result['is_suspicious'], "Suspicious image should be flagged")
        
        print(f"✅ Basic functionality verification passed")
    
    def test_02_large_file_performance(self):
        """Test performance with large files to ensure scalability."""
        print(f"\n🧪 Testing large file performance")
        
        # Create a large test image (1MB) with trailing data
        large_image_path = os.path.join(self.test_output_dir, "large_test_image.png")
        
        # Create a large PNG file with trailing data
        self._create_large_test_image(large_image_path, size_mb=1, trailing_bytes=100)
        
        # Measure performance
        start_time = time.time()
        result = detect_image_steganography(
            large_image_path, 
            self.test_output_dir, 
            verbose=False
        )
        end_time = time.time()
        
        execution_time = end_time - start_time
        
        # Should complete within reasonable time (< 5 seconds for 1MB)
        self.assertLess(execution_time, 5.0, f"Large file analysis took too long: {execution_time:.2f}s")
        
        # Verify result
        self.assertIsNotNone(result, "Large file analysis should succeed")
        self.assertTrue(result['is_suspicious'], "Large file with trailing data should be suspicious")
        
        print(f"✅ Large file performance test passed: {execution_time:.3f}s (under 5s threshold)")
    
    def test_03_memory_usage_optimization(self):
        """Test memory usage to ensure no memory leaks."""
        print(f"\n🧪 Testing memory usage optimization")
        
        # Get initial memory usage
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        # Create and analyze multiple large images
        for i in range(5):
            large_image_path = os.path.join(self.test_output_dir, f"memory_test_{i}.png")
            self._create_large_test_image(large_image_path, size_mb=0.5, trailing_bytes=50)
            
            result = detect_image_steganography(
                large_image_path, 
                self.test_output_dir, 
                verbose=False
            )
            self.assertIsNotNone(result)
        
        # Force garbage collection
        gc.collect()
        
        # Get final memory usage
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be minimal (< 10MB)
        self.assertLess(memory_increase, 10 * 1024 * 1024, 
                       f"Memory increase should be minimal, increased by {memory_increase/1024/1024:.1f} MB")
        
        print(f"✅ Memory usage test passed: {memory_increase/1024/1024:.1f} MB increase (under 10MB threshold)")
    
    def test_04_edge_case_handling(self):
        """Test edge cases and error handling robustness."""
        print(f"\n🧪 Testing edge case handling")
        
        # Test with corrupted PNG header
        corrupted_png_path = os.path.join(self.test_output_dir, "corrupted.png")
        self._create_corrupted_png(corrupted_png_path)
        
        result = detect_image_steganography(
            corrupted_png_path, 
            self.test_output_dir, 
            verbose=True
        )
        
        # Should handle gracefully (return None or error result)
        if result is None:
            print("✅ Corrupted PNG handled gracefully (returned None)")
        else:
            # If it returns a result, it should indicate an error
            self.assertIn('error', result, "Corrupted file should indicate error")
        
        # Test with empty file
        empty_file_path = os.path.join(self.test_output_dir, "empty.png")
        with open(empty_file_path, 'wb') as f:
            pass  # Create empty file
        
        result = detect_image_steganography(
            empty_file_path, 
            self.test_output_dir, 
            verbose=True
        )
        
        # Should handle gracefully
        if result is None:
            print("✅ Empty file handled gracefully (returned None)")
        else:
            self.assertIn('error', result, "Empty file should indicate error")
        
        # Test with very small file
        tiny_file_path = os.path.join(self.test_output_dir, "tiny.png")
        with open(tiny_file_path, 'wb') as f:
            f.write(b'\x89PNG\r\n\x1a\n')  # Just PNG signature
        
        result = detect_image_steganography(
            tiny_file_path, 
            self.test_output_dir, 
            verbose=True
        )
        
        # Should handle gracefully
        if result is None:
            print("✅ Tiny file handled gracefully (returned None)")
        else:
            self.assertIn('error', result, "Tiny file should indicate error")
        
        print(f"✅ Edge case handling test passed")
    
    def test_05_format_detection_robustness(self):
        """Test format detection robustness with various scenarios."""
        print(f"\n🧪 Testing format detection robustness")
        
        # Test PNG with various IEND positions
        png_variants = [
            ("normal.png", b'\x89PNG\r\n\x1a\n\x00\x00\x00\x00IHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x01\x01\x01\x00\x18\xdd\x8d\xb0\x00\x00\x00\x00IEND\xaeB`\x82'),
            ("no_iend.png", b'\x89PNG\r\n\x1a\n\x00\x00\x00\x00IHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x01\x01\x01\x00\x18\xdd\x8d\xb0\x00\x00\x00\x00'),
            ("multiple_iend.png", b'\x89PNG\r\n\x1a\n\x00\x00\x00\x00IHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x01\x01\x01\x00\x18\xdd\x8d\xb0\x00\x00\x00\x00IEND\xaeB`\x82IEND\xaeB`\x82')
        ]
        
        for name, data in png_variants:
            test_file_path = os.path.join(self.test_output_dir, name)
            with open(test_file_path, 'wb') as f:
                f.write(data)
            
            # Test format detection directly
            format_info = _detect_image_format(data, verbose=True)
            
            if name == "normal.png":
                self.assertIsNotNone(format_info, f"{name} should be detected")
                self.assertEqual(format_info['format'], 'PNG', f"{name} should be PNG")
            elif name == "no_iend.png":
                # Should handle gracefully
                if format_info is None:
                    print(f"✅ {name} handled gracefully (no IEND)")
                else:
                    self.assertIn('error', format_info, f"{name} should indicate error")
            elif name == "multiple_iend.png":
                # Should find the last IEND
                self.assertIsNotNone(format_info, f"{name} should be detected")
                self.assertEqual(format_info['format'], 'PNG', f"{name} should be PNG")
        
        print(f"✅ Format detection robustness test passed")
    
    def test_06_threshold_edge_cases(self):
        """Test threshold behavior at boundary conditions."""
        print(f"\n🧪 Testing threshold edge cases")
        
        # Create test image with exactly threshold bytes
        exact_threshold_path = os.path.join(self.test_output_dir, "exact_threshold.png")
        self._create_test_image_with_trailing(exact_threshold_path, trailing_bytes=10)
        
        # Test with threshold = 10 (exact match)
        result = detect_image_steganography(
            exact_threshold_path, 
            self.test_output_dir, 
            verbose=True,
            threshold_bytes=10
        )
        
        self.assertIsNotNone(result, "Exact threshold image should be analyzed")
        self.assertEqual(result['trailing_bytes'], 10, "Should have exactly 10 trailing bytes")
        self.assertTrue(result['is_suspicious'], "Exact threshold should be suspicious")
        
        # Test with threshold = 9 (just below)
        result = detect_image_steganography(
            exact_threshold_path, 
            self.test_output_dir, 
            verbose=True,
            threshold_bytes=9
        )
        
        self.assertIsNotNone(result, "Below threshold image should be analyzed")
        self.assertEqual(result['trailing_bytes'], 10, "Should have exactly 10 trailing bytes")
        self.assertTrue(result['is_suspicious'], "Above threshold should be suspicious")
        
        # Test with threshold = 11 (just above)
        result = detect_image_steganography(
            exact_threshold_path, 
            self.test_output_dir, 
            verbose=True,
            threshold_bytes=11
        )
        
        self.assertIsNotNone(result, "Above threshold image should be analyzed")
        self.assertEqual(result['trailing_bytes'], 10, "Should have exactly 10 trailing bytes")
        self.assertFalse(result['is_suspicious'], "Below threshold should be clean")
        
        print(f"✅ Threshold edge cases test passed")
    
    def test_07_concurrent_analysis(self):
        """Test concurrent analysis to ensure thread safety."""
        print(f"\n🧪 Testing concurrent analysis")
        
        import threading
        import queue
        
        results_queue = queue.Queue()
        errors_queue = queue.Queue()
        
        def analyze_image(image_path, output_dir, thread_id):
            try:
                result = detect_image_steganography(
                    image_path, 
                    output_dir, 
                    verbose=False
                )
                results_queue.put((thread_id, result))
            except Exception as e:
                errors_queue.put((thread_id, e))
        
        # Create multiple test images
        test_images = []
        for i in range(5):
            image_path = os.path.join(self.test_output_dir, f"concurrent_test_{i}.png")
            self._create_test_image_with_trailing(image_path, trailing_bytes=20 + i)
            test_images.append(image_path)
        
        # Run concurrent analysis
        threads = []
        for i, image_path in enumerate(test_images):
            thread = threading.Thread(
                target=analyze_image,
                args=(image_path, self.test_output_dir, i)
            )
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Check results
        self.assertEqual(results_queue.qsize(), 5, "All threads should complete successfully")
        self.assertEqual(errors_queue.qsize(), 0, "No threads should encounter errors")
        
        # Verify all results are valid
        while not results_queue.empty():
            thread_id, result = results_queue.get()
            self.assertIsNotNone(result, f"Thread {thread_id} should return valid result")
            self.assertIsInstance(result, dict, f"Thread {thread_id} should return dictionary")
        
        print(f"✅ Concurrent analysis test passed")
    
    def test_08_real_world_scenarios(self):
        """Test real-world APK analysis scenarios."""
        print(f"\n🧪 Testing real-world APK scenarios")
        
        # Test with mixed image types (like in APK assets)
        mixed_images = [
            ("icon.png", self._create_png_icon),
            ("background.jpg", self._create_jpeg_background),
            ("animation.gif", self._create_gif_animation),
            ("logo.bmp", self._create_bmp_logo)
        ]
        
        analysis_results = []
        for name, creator_func in mixed_images:
            image_path = os.path.join(self.test_output_dir, name)
            creator_func(image_path)
            
            result = detect_image_steganography(
                image_path, 
                self.test_output_dir, 
                verbose=False
            )
            
            self.assertIsNotNone(result, f"{name} analysis should succeed")
            analysis_results.append(result)
        
        # Verify all formats were detected correctly
        expected_formats = ['PNG', 'JPEG', 'GIF', 'BMP']
        detected_formats = [result['image_format'] for result in analysis_results]
        
        for expected in expected_formats:
            self.assertIn(expected, detected_formats, f"Should detect {expected} format")
        
        print(f"✅ Real-world scenarios test passed")
    
    def test_09_error_recovery(self):
        """Test error recovery and graceful degradation."""
        print(f"\n🧪 Testing error recovery")
        
        # Test with file that becomes inaccessible during analysis
        inaccessible_path = os.path.join(self.test_output_dir, "inaccessible.png")
        self._create_test_image_with_trailing(inaccessible_path, trailing_bytes=15)
        
        # Make file inaccessible during analysis
        with patch('builtins.open', side_effect=PermissionError("Access denied")):
            result = detect_image_steganography(
                inaccessible_path, 
                self.test_output_dir, 
                verbose=True
            )
        
        # Should handle gracefully
        if result is None:
            print("✅ Permission error handled gracefully (returned None)")
        else:
            self.assertIn('error', result, "Permission error should indicate error")
        
        # Test with corrupted file during analysis
        corrupted_path = os.path.join(self.test_output_dir, "corrupted_during.png")
        self._create_test_image_with_trailing(corrupted_path, trailing_bytes=15)
        
        # Simulate corruption during analysis
        with patch('builtins.open', side_effect=OSError("File corrupted")):
            result = detect_image_steganography(
                corrupted_path, 
                self.test_output_dir, 
                verbose=True
            )
        
        # Should handle gracefully
        if result is None:
            print("✅ Corruption error handled gracefully (returned None)")
        else:
            self.assertIn('error', result, "Corruption error should indicate error")
        
        print(f"✅ Error recovery test passed")
    
    def test_10_performance_benchmarking(self):
        """Test performance benchmarking with various file sizes."""
        print(f"\n🧪 Testing performance benchmarking")
        
        # Test different file sizes
        file_sizes = [0.1, 0.5, 1.0, 2.0]  # MB
        performance_results = {}
        
        for size_mb in file_sizes:
            image_path = os.path.join(self.test_output_dir, f"benchmark_{size_mb}mb.png")
            self._create_large_test_image(image_path, size_mb=size_mb, trailing_bytes=100)
            
            # Measure performance
            start_time = time.time()
            result = detect_image_steganography(
                image_path, 
                self.test_output_dir, 
                verbose=False
            )
            end_time = time.time()
            
            execution_time = end_time - start_time
            performance_results[size_mb] = execution_time
            
            # Verify result
            self.assertIsNotNone(result, f"{size_mb}MB file analysis should succeed")
            self.assertTrue(result['is_suspicious'], f"{size_mb}MB file should be suspicious")
            
            # Performance should scale reasonably
            if size_mb <= 1.0:
                self.assertLess(execution_time, 2.0, f"{size_mb}MB file should complete in < 2s")
            else:
                self.assertLess(execution_time, 5.0, f"{size_mb}MB file should complete in < 5s")
        
        print(f"✅ Performance benchmarking results:")
        for size_mb, exec_time in performance_results.items():
            print(f"   {size_mb}MB: {exec_time:.3f}s")
    
    # Helper methods for creating test files
    
    def _create_large_test_image(self, file_path, size_mb=1, trailing_bytes=100):
        """Create a large test PNG image with trailing data."""
        # Create a minimal valid PNG
        png_data = (
            b'\x89PNG\r\n\x1a\n'  # PNG signature
            b'\x00\x00\x00\r'     # IHDR chunk length
            b'IHDR'                # IHDR chunk type
            b'\x00\x00\x00\x01'   # Width: 1 pixel
            b'\x00\x00\x00\x01'   # Height: 1 pixel
            b'\x08'                # Bit depth: 8
            b'\x02'                # Color type: RGB
            b'\x00'                # Compression: deflate
            b'\x00'                # Filter: none
            b'\x00'                # Interlace: none
            b'\x90wS\xde'         # IHDR CRC
            b'\x00\x00\x00\x0c'   # IDAT chunk length
            b'IDAT'                # IDAT chunk type
            b'x\x9cc\xf8\x0f\x00\x01\x01\x01\x00\x18\xdd\x8d\xb0'  # Minimal image data
            b'\x00\x00\x00\x00'   # IDAT CRC
            b'\x00\x00\x00\x00'   # IEND chunk length
            b'IEND'                # IEND chunk type
            b'\xaeB`\x82'         # IEND CRC
        )
        
        # Add padding to reach desired size
        target_size = int(size_mb * 1024 * 1024)
        padding_size = target_size - len(png_data) - trailing_bytes
        
        if padding_size > 0:
            # Add padding in IDAT chunk
            padding_data = b'\x00' * padding_size
            # Update IDAT chunk length and data
            idat_start = png_data.find(b'IDAT')
            idat_length_pos = idat_start - 4
            new_idat_length = len(png_data[idat_start+4:-12]) + padding_size
            png_data = (
                png_data[:idat_start-4] +
                new_idat_length.to_bytes(4, 'big') +
                png_data[idat_start:png_data.find(b'\x00\x00\x00\x00', idat_start)] +
                padding_data +
                png_data[png_data.find(b'\x00\x00\x00\x00', idat_start):]
            )
        
        # Add trailing data
        trailing_data = b'X' * trailing_bytes
        
        with open(file_path, 'wb') as f:
            f.write(png_data)
            f.write(trailing_data)
    
    def _create_test_image_with_trailing(self, file_path, trailing_bytes=20):
        """Create a test PNG image with specific trailing data size."""
        # Create minimal valid PNG
        png_data = (
            b'\x89PNG\r\n\x1a\n'  # PNG signature
            b'\x00\x00\x00\r'     # IHDR chunk length
            b'IHDR'                # IHDR chunk type
            b'\x00\x00\x00\x01'   # Width: 1 pixel
            b'\x00\x00\x00\x01'   # Height: 1 pixel
            b'\x08'                # Bit depth: 8
            b'\x02'                # Color type: RGB
            b'\x00'                # Compression: deflate
            b'\x00'                # Filter: none
            b'\x00'                # Interlace: none
            b'\x90wS\xde'         # IHDR CRC
            b'\x00\x00\x00\x0c'   # IDAT chunk length
            b'IDAT'                # IDAT chunk type
            b'x\x9cc\xf8\x0f\x00\x01\x01\x01\x00\x18\xdd\x8d\xb0'  # Minimal image data
            b'\x00\x00\x00\x00'   # IDAT CRC
            b'\x00\x00\x00\x00'   # IEND chunk length
            b'IEND'                # IEND chunk type
            b'\xaeB`\x82'         # IEND CRC
        )
        
        # Add trailing data
        trailing_data = b'X' * trailing_bytes
        
        with open(file_path, 'wb') as f:
            f.write(png_data)
            f.write(trailing_data)
    
    def _create_corrupted_png(self, file_path):
        """Create a corrupted PNG file."""
        corrupted_data = (
            b'\x89PNG\r\n\x1a\n'  # PNG signature
            b'\x00\x00\x00\r'     # IHDR chunk length
            b'IHDR'                # IHDR chunk type
            # Missing width/height data
            b'\x90wS\xde'         # Invalid CRC
        )
        
        with open(file_path, 'wb') as f:
            f.write(corrupted_data)
    
    def _create_png_icon(self, file_path):
        """Create a PNG icon file."""
        self._create_test_image_with_trailing(file_path, trailing_bytes=0)
    
    def _create_jpeg_background(self, file_path):
        """Create a JPEG background file."""
        # Create minimal valid JPEG
        jpeg_data = (
            b'\xff\xd8'           # SOI marker
            b'\xff\xe0'           # APP0 marker
            b'\x00\x10'           # APP0 length
            b'JFIF\x00\x01\x01'   # JFIF identifier
            b'\x00\x01'           # Version
            b'\x00\x01'           # Units
            b'\x00\x01'           # Density
            b'\x00\x01'           # Density
            b'\x00\x00'           # No thumbnail
            b'\xff\xc0'           # SOF0 marker
            b'\x00\x11'           # SOF0 length
            b'\x08'               # Precision
            b'\x00\x01'           # Height
            b'\x00\x01'           # Width
            b'\x03'               # Components
            b'\x01\x11\x00'       # Component 1
            b'\x02\x11\x01'       # Component 2
            b'\x03\x11\x01'       # Component 3
            b'\xff\xda'           # SOS marker
            b'\x00\x0c'           # SOS length
            b'\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00'  # Scan header
            b'\x00\x01\x01'       # Scan data
            b'\xff\xd9'           # EOI marker
        )
        
        with open(file_path, 'wb') as f:
            f.write(jpeg_data)
    
    def _create_gif_animation(self, file_path):
        """Create a GIF animation file."""
        # Create minimal valid GIF
        gif_data = (
            b'GIF89a'             # GIF signature
            b'\x01\x00'           # Width: 1
            b'\x01\x00'           # Height: 1
            b'\x91'               # Color table info
            b'\x00'               # Background color
            b'\x00'               # Aspect ratio
            b'\x00'               # Global color table
            b'\x00\x00\x00'       # Color 0: black
            b'\xff\xff\xff'       # Color 1: white
            b'\x21\xf9\x04\x00\x00\x00\x00\x00'  # Graphics control extension
            b'\x2c'               # Image descriptor
            b'\x00\x00\x00\x00\x01\x00\x01\x00\x00'  # Image info
            b'\x02'               # LZW minimum code size
            b'\x02'               # LZW data size
            b'\x44\x01\x00'       # LZW data
            b'\x00'               # Block terminator
            b'\x3b'               # GIF trailer
        )
        
        with open(file_path, 'wb') as f:
            f.write(gif_data)
    
    def _create_bmp_logo(self, file_path):
        """Create a BMP logo file."""
        # Create minimal valid BMP
        bmp_data = (
            b'BM'                 # BMP signature
            b'\x36\x00\x00\x00'   # File size: 54 bytes
            b'\x00\x00'           # Reserved
            b'\x00\x00'           # Reserved
            b'\x36\x00\x00\x00'   # Data offset: 54 bytes
            b'\x28\x00\x00\x00'   # Header size: 40 bytes
            b'\x01\x00\x00\x00'   # Width: 1
            b'\x01\x00\x00\x00'   # Height: 1
            b'\x01\x00'           # Planes: 1
            b'\x18\x00'           # Bits per pixel: 24
            b'\x00\x00\x00\x00'   # Compression: none
            b'\x00\x00\x00\x00'   # Image size: 0
            b'\x00\x00\x00\x00'   # Horizontal resolution
            b'\x00\x00\x00\x00'   # Vertical resolution
            b'\x00\x00\x00\x00'   # Colors in palette: 0
            b'\x00\x00\x00\x00'   # Important colors: 0
            b'\xff\x00\x00'       # Pixel data: red
        )
        
        with open(file_path, 'wb') as f:
            f.write(bmp_data)


def run_enhanced_tests():
    """Run the enhanced test suite."""
    print("🧪 Starting Enhanced Image Steganography Detection Tests")
    print("=" * 70)
    
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSteganographyDetectionEnhanced)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 70)
    print("📊 Enhanced Test Results Summary")
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
    success = run_enhanced_tests()
    sys.exit(0 if success else 1)
