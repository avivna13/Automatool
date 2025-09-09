import re
import math
import os
from collections import Counter
import base64

def analyze_base64(file_path, min_length=20, blob_threshold=700, string_count_threshold=10):
    # Input validation
    if not file_path or not isinstance(file_path, str):
        raise ValueError("file_path must be a non-empty string")
    
    if min_length < 1:
        raise ValueError("min_length must be at least 1")
    
    if blob_threshold < 1:
        raise ValueError("blob_threshold must be at least 1")
    
    if string_count_threshold < 1:
        raise ValueError("string_count_threshold must be at least 1")
    
    # File existence and access check
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"Permission denied reading file: {file_path}")
    
    try:
        with open(file_path, 'rb') as file:
            content = file.read().decode('utf-8', errors='ignore')
    except UnicodeDecodeError as e:
        # Try with different encoding if UTF-8 fails
        try:
            with open(file_path, 'rb') as file:
                content = file.read().decode('latin-1', errors='ignore')
        except Exception as fallback_e:
            raise IOError(f"Failed to read file {file_path}: {e}. Fallback also failed: {fallback_e}")
    except Exception as e:
        raise IOError(f"Failed to read file {file_path}: {e}")
    
    def entropy(s):
        """Calculate Shannon entropy of a string."""
        if len(s) == 0:
            return 0
        try:
            p, lns = Counter(s), float(len(s))
            return -sum(count/lns * math.log(count/lns, 2) for count in p.values())
        except (ValueError, ZeroDivisionError):
            return 0
    
    def is_likely_base64(s):
        """Check if a string is likely to be valid base64."""
        if not s or len(s) < min_length:
            return False
        
        # Check if length is valid for base64 (must be multiple of 4)
        if len(s) % 4 != 0:
            return False
        
        # Check if string contains only valid base64 characters
        if not re.match(r'^[A-Za-z0-9+/]+={0,2}$', s):
            return False
        
        try:
            base64.b64decode(s, validate=True)
            return True
        except Exception:
            return False
    
    # Find potential base64 strings
    try:
        potential_b64_strings = re.findall(r'[A-Za-z0-9+/]{%d,}={0,2}' % min_length, content)
    except Exception as e:
        # Fallback to simpler pattern if regex fails
        potential_b64_strings = re.findall(r'[A-Za-z0-9+/]{20,}', content)
    
    # Filter and validate strings
    b64_strings = []
    for s in potential_b64_strings:
        try:
            if is_likely_base64(s) and ((3.0 < entropy(s) < 5) or len(s) >= blob_threshold):
                b64_strings.append(s)
        except Exception:
            # Skip strings that cause errors during analysis
            continue
    
    # Find the longest string if any exist
    longest_string = ""
    longest_string_decoded = ""
    decoding_error = None
    
    if b64_strings:
        try:
            # Sort by length to find the longest
            longest_string = max(b64_strings, key=len)
            
            # Try to decode the longest string
            try:
                decoded_bytes = base64.b64decode(longest_string, validate=True)
                
                # Try to convert to string if it's text, otherwise show as hex
                try:
                    longest_string_decoded = decoded_bytes.decode('utf-8', errors='ignore')
                    if not longest_string_decoded.isprintable():
                        longest_string_decoded = decoded_bytes.hex()
                except UnicodeDecodeError:
                    longest_string_decoded = decoded_bytes.hex()
                    
            except Exception as e:
                decoding_error = str(e)
                longest_string_decoded = f"Decoding error: {decoding_error}"
                
        except Exception as e:
            # Handle errors in finding longest string
            longest_string = b64_strings[0] if b64_strings else ""
            longest_string_decoded = f"Error finding longest string: {str(e)}"
    
    # Calculate flags with error handling
    try:
        has_any_b64 = len(b64_strings) > 0
        has_large_blob = any(len(s) >= blob_threshold for s in b64_strings)
        string_count = len(b64_strings)
        has_lots_of_strings = string_count > string_count_threshold
    except Exception:
        # Fallback values if calculation fails
        has_any_b64 = False
        has_large_blob = False
        string_count = 0
        has_lots_of_strings = False
    
    return {
        "file_path": file_path,
        "strings_detected": string_count,
        "longest_string": longest_string,
        "longest_string_decoded": longest_string_decoded,
        "has_any_base64": has_any_b64,
        "has_large_blob": has_large_blob,
        "has_lots_of_strings": has_lots_of_strings,
        "error": decoding_error if decoding_error else None
    }

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python base64_detector.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    result = analyze_base64(file_path)
    
    print("Base64 Detection Results")
    print("=" * 50)
    print(f"📁 File: {result['file_path']}")
    print(f"🔍 Strings Detected: {result['strings_detected']}")
    
    if result['has_any_base64']:
        print(f"📏 Longest String Length: {len(result['longest_string'])} characters")
        print(f"🔤 Longest String Preview: {result['longest_string'][:100]}{'...' if len(result['longest_string']) > 100 else ''}")
        
        # Display decoded content appropriately
        if result['longest_string_decoded'].startswith('Decoding error:'):
            print(f"❌ Decoding Error: {result['longest_string_decoded']}")
        elif len(result['longest_string_decoded']) > 200:
            print(f"📄 Decoded Content (truncated): {result['longest_string_decoded'][:200]}...")
        else:
            print(f"📄 Decoded Content: {result['longest_string_decoded']}")
        
        # Additional flags for context
        if result['has_large_blob']:
            print("⚠️  Large blob detected (potential binary data)")
        if result['has_lots_of_strings']:
            print("📊 Many strings found (high activity)")
    else:
        print("✅ No base64 strings detected in this file")
    
    print("=" * 50)
