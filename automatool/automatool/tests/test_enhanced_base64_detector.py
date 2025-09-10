#!/usr/bin/env python3
"""
Test script for the enhanced base64 detector integration.
This script tests the updated base64_scanner.py with the new analyze_base64 function.
"""

import pytest
import os
import sys
import tempfile

# Mark this test as local-only since it requires specific file paths
pytestmark = pytest.mark.local_only

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the enhanced base64 detector
import importlib.util

# Get the correct path to the base64 detector script
base_dir = os.path.dirname(os.path.abspath(__file__))
script_path = os.path.join(base_dir, "..", "src", "scripts", "automations", "base64-detector", "base-64-detector-script.py")

try:
    spec = importlib.util.spec_from_file_location(
        "base64_detector", 
        script_path
    )
    base64_detector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base64_detector)
    analyze_base64 = base64_detector.analyze_base64
except FileNotFoundError:
    print(f"Warning: Base64 detector script not found at {script_path}")
    # Create a mock function for testing
    def analyze_base64(file_path):
        return {"status": "mock", "file": file_path}

# Import the updated base64 scanner
from base64_scanner import Base64Scanner


def create_test_file():
    """Create a test file with some base64 content."""
    test_content = """
    // Test Java file with base64 strings
    public class TestClass {
        private static final String SMALL_B64 = "SGVsbG8gV29ybGQ=";  // "Hello World"
        private static final String LARGE_B64 = "VGhpcyBpcyBhIG11Y2ggbG9uZ2VyIGJhc2U2NCBzdHJpbmcgdGhhdCBjb250YWlucyBtdWx0aXBsZSBzZW50ZW5jZXMgYW5kIHNob3VsZCBiZSBkZXRlY3RlZCBhcyB0aGUgbG9uZ2VzdCBzdHJpbmcgaW4gdGhpcyBmaWxlLiBUaGlzIHN0cmluZyBpcyBkZWNvZGVkIGZyb20gYSBzYW1wbGUgdGV4dCB0aGF0IGlzIGJhc2U2NCBlbmNvZGVkIGFuZCBjb250YWlucyBzb21lIHNhbXBsZSBjb250ZW50IHRoYXQgc2hvdWxkIGJlIGRldGVjdGVkIGJ5IHRoZSBzY3JpcHQu";
        
        public void testMethod() {
            String anotherB64 = "QW5vdGhlciBiYXNlNjQgc3RyaW5n";
            System.out.println("Testing base64 detection");
        }
    }
    """
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
        f.write(test_content)
        return f.name


def test_enhanced_detector():
    """Test the enhanced base64 detector directly."""
    print("🧪 Testing Enhanced Base64 Detector")
    print("=" * 50)
    
    test_file = create_test_file()
    print(f"📁 Created test file: {test_file}")
    
    try:
        # Test the enhanced analyze_base64 function
        result = analyze_base64(test_file)
        
        print("✅ Enhanced detector result:")
        for key, value in result.items():
            if key == 'longest_string' and len(str(value)) > 100:
                print(f"  {key}: {str(value)[:100]}... (truncated)")
            elif key == 'longest_string_decoded' and len(str(value)) > 100:
                print(f"  {key}: {str(value)[:100]}... (truncated)")
            else:
                print(f"  {key}: {value}")
        
        # Verify the new structure
        expected_keys = ['file_path', 'strings_detected', 'longest_string', 
                        'longest_string_decoded', 'has_any_base64', 'has_large_blob', 
                        'has_lots_of_strings', 'error']
        
        missing_keys = [key for key in expected_keys if key not in result]
        if missing_keys:
            print(f"❌ Missing expected keys: {missing_keys}")
        else:
            print("✅ All expected keys present")
            
        if result['has_any_base64']:
            print(f"✅ Base64 strings detected: {result['strings_detected']}")
            print(f"✅ Longest string length: {len(result['longest_string'])}")
        else:
            print("❌ No base64 strings detected")
            
    except Exception as e:
        print(f"❌ Error testing enhanced detector: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Cleanup
        try:
            os.unlink(test_file)
            print(f"🧹 Cleaned up test file: {test_file}")
        except Exception as e:
            print(f"⚠️ Warning: Could not clean up test file: {e}")


def test_base64_scanner():
    """Test the updated base64 scanner."""
    print("\n🧪 Testing Updated Base64 Scanner")
    print("=" * 50)
    
    test_file = create_test_file()
    print(f"📁 Created test file: {test_file}")
    
    try:
        # Create a temporary directory for the scanner
        with tempfile.TemporaryDirectory() as temp_dir:
            # Copy test file to temp directory
            import shutil
            test_file_in_dir = os.path.join(temp_dir, "TestClass.java")
            shutil.copy2(test_file, test_file_in_dir)
            
            # Initialize scanner
            scanner = Base64Scanner()
            
            # Scan the file
            file_result = scanner.scan_java_file(test_file_in_dir)
            
            if file_result:
                print("✅ File scan result:")
                for key, value in file_result.items():
                    if key == 'longest_string' and len(str(value)) > 100:
                        print(f"  {key}: {str(value)[:100]}... (truncated)")
                    elif key == 'longest_string_decoded' and len(str(value)) > 100:
                        print(f"  {key}: {str(value)[:100]}... (truncated)")
                    else:
                        print(f"  {key}: {value}")
                
                # Verify the new structure
                expected_keys = ['file_path', 'strings_detected', 'longest_string', 
                               'longest_string_decoded', 'analysis_summary', 'scan_timestamp']
                
                missing_keys = [key for key in expected_keys if key not in file_result]
                if missing_keys:
                    print(f"❌ Missing expected keys: {missing_keys}")
                else:
                    print("✅ All expected keys present")
            else:
                print("❌ No scan result returned")
                
    except Exception as e:
        print(f"❌ Error testing base64 scanner: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Cleanup
        try:
            os.unlink(test_file)
            print(f"🧹 Cleaned up test file: {test_file}")
        except Exception as e:
            print(f"⚠️ Warning: Could not clean up test file: {e}")


if __name__ == "__main__":
    test_enhanced_detector()
    test_base64_scanner()
    print("\n🎉 Testing complete!")
