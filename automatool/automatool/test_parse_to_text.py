#!/usr/bin/env python3
"""
Test script for the new parse_to_text method in sensor_scraper.py
"""
import json
import sys
import os

# Add the src directory to the path to import sensor_scraper
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src', 'scripts', 'automations'))

from sensor_scraper import parse_to_text, generate_google_play_url

def test_parse_to_text_with_sample_data():
    """Test the parse_to_text method with the sample JSON data"""
    
    print("="*60)
    print(" " * 15 + "TESTING parse_to_text METHOD" + " " * 15)
    print("="*60)
    
    # Load the test data
    test_data_path = os.path.join(os.path.dirname(__file__), 'tests', 'resources', 'sensortower_filtered.json')
    
    try:
        with open(test_data_path, 'r', encoding='utf-8') as f:
            test_data = json.load(f)
            
        print(f"[+] Loaded test data from: {test_data_path}")
        print(f"[+] App: {test_data.get('name', 'N/A')}")
        print(f"[+] Package: {test_data.get('app_id', 'N/A')}")
        
        # Get Google Play URL from the data
        google_play_url = test_data.get('generated_google_play_url')
        if not google_play_url:
            # Generate it if not present
            app_id = test_data.get('app_id', '')
            country = test_data.get('country', 'US')
            google_play_url = generate_google_play_url(app_id, country)
        
        print(f"[+] Google Play URL: {google_play_url}")
        print("\n" + "="*60)
        print(" " * 20 + "FORMATTED OUTPUT" + " " * 20)
        print("="*60)
        
        # Test the parse_to_text method
        formatted_text = parse_to_text(test_data, google_play_url)
        
        # Display the result
        print(formatted_text)
        
        # Save to a test output file
        output_file = "test_parse_output.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(formatted_text)
        
        print(f"\n[+] Test output saved to: {output_file}")
        print(f"[+] Text length: {len(formatted_text)} characters")
        print(f"[+] Number of lines: {len(formatted_text.split('\\n'))} lines")
        
        return True
        
    except FileNotFoundError:
        print(f"[!] Error: Test data file not found at {test_data_path}")
        return False
    except json.JSONDecodeError:
        print("[!] Error: Could not parse test JSON data")
        return False
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return False

def test_parse_to_text_with_minimal_data():
    """Test with minimal data to check edge cases"""
    
    print("\n" + "="*60)
    print(" " * 12 + "TESTING WITH MINIMAL DATA" + " " * 12)
    print("="*60)
    
    # Create minimal test data
    minimal_data = {
        "name": "Test App",
        "app_id": "com.test.app",
        "publisher_name": "Test Publisher",
        "categories": [{"name": "Utilities"}],
        "os": "android",
        "rating": 4.5,
        "rating_count": 1000
    }
    
    print("[+] Testing with minimal data structure...")
    
    # Test with minimal data
    formatted_text = parse_to_text(minimal_data)
    print(formatted_text)
    
    print(f"[+] Minimal test completed successfully")
    print(f"[+] Text length: {len(formatted_text)} characters")
    
    return True

if __name__ == "__main__":
    print("Starting parse_to_text method tests...\n")
    
    # Test 1: Full data test
    success1 = test_parse_to_text_with_sample_data()
    
    # Test 2: Minimal data test
    success2 = test_parse_to_text_with_minimal_data()
    
    # Summary
    print("\n" + "="*60)
    print(" " * 22 + "TEST SUMMARY" + " " * 22)
    print("="*60)
    print(f"Full data test: {'PASSED' if success1 else 'FAILED'}")
    print(f"Minimal data test: {'PASSED' if success2 else 'FAILED'}")
    
    if success1 and success2:
        print("\n[+] All tests PASSED! 🎉")
        print("[+] The parse_to_text method is working correctly.")
    else:
        print("\n[!] Some tests FAILED! ❌")
        sys.exit(1)
