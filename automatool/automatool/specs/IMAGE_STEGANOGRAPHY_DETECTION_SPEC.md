# 🖼️ Image Steganography Detection Specification

## **Overview**
Create a new automation that analyzes image files (particularly PNG format) to detect hidden/encrypted data appended after the official file format markers. This tool will specifically look for data hidden after PNG's IEND chunk marker, which is a common technique for concealing payloads like DEX files, encrypted data, or other malicious content in seemingly innocent image files.

## **Purpose**
The image steganography detection automation will:
1. **End Marker Detection**: Find image format end markers (PNG IEND, JPEG EOI, etc.)
2. **Trailing Data Detection**: Check for any data after the legitimate image content
3. **Threshold Classification**: Use configurable byte threshold to classify suspicious files
4. **Simple Reporting**: Generate basic alerts and summaries for suspicious images
5. **Integration**: Seamlessly integrate with existing automatool workflow and resource tracking

## **Technical Background**

### **Multi-Format Image Structure Analysis**

#### **PNG File Structure**
PNG files follow a specific format with chunks ending in an IEND chunk:
```
PNG Signature: 89 50 4E 47 0D 0A 1A 0A
... [PNG chunks] ...
IEND Chunk: [length:4][IEND:4][CRC:4] = 00 00 00 00 49 45 4E 44 AE 42 60 82
```

#### **JPEG File Structure**
JPEG files use marker segments with specific start/end markers:
```
JPEG Signature: FF D8 FF
... [JPEG segments] ...
End of Image (EOI): FF D9
```

#### **GIF File Structure**
GIF files have a clear trailer marker:
```
GIF Signature: 47 49 46 38 [37|39] 61 (GIF87a or GIF89a)
... [GIF data] ...
GIF Trailer: 3B (semicolon)
```

#### **BMP File Structure**
BMP files have a predictable size defined in the header:
```
BMP Signature: 42 4D (BM)
File Size: [4 bytes at offset 2-5]
... [BMP data with calculated end] ...
```

Any data appearing after these legitimate end markers could indicate:
- Appended DEX files (Android malware technique)
- Steganographic payloads
- Encrypted data containers
- Additional malware components

### **Simplified Detection Strategy**
1. **Format Detection**: Identify image format from file signature
2. **Locate End Marker**: Find format-specific end marker or calculate end position
3. **Calculate Trailing Size**: Count bytes after legitimate image content ends
4. **Threshold Check**: Compare trailing size against configurable threshold
5. **Classification**: Mark as suspicious if trailing data exceeds threshold
6. **Simple Reporting**: Generate basic alert with file info and trailing byte count

## **File Structure**
Following existing automatool organization patterns:
```
automatool/automatool/src/scripts/
├── automations/
│   └── detect_image_steganography.py    # NEW: Main detection automation
└── parsers/
    └── parse_steganography_results.py   # NEW: Results parsing and formatting
```

This follows the established pattern where:
- **automations/**: Contains the main detection/analysis functions
- **parsers/**: Contains result parsing and formatting functions

## **Implementation Details**

### **Phase 1: Core Detection Function (`automations/detect_image_steganography.py`)**

Following the exact pattern from existing automation scripts in the automations/ directory:

```python
import os
import struct
import binascii
from pathlib import Path

def detect_image_steganography(image_path, output_directory, verbose=False, threshold_bytes=10):
    """
    Analyze an image file for suspicious trailing data after format end markers.
    
    Args:
        image_path (str): Path to the image file to analyze
        output_directory (str): Directory to save analysis results
        verbose (bool): Enable verbose output
        threshold_bytes (int): Minimum trailing bytes to classify as suspicious (default: 10)
        
    Returns:
        dict: Simple analysis results with suspicious classification
        Returns None if analysis fails
    """
    if verbose:
        print(f"[DEBUG] Analyzing image for steganography: {image_path}")
        print(f"[DEBUG] Output directory: {output_directory}")
    
    try:
        # Validate input file
        if not os.path.exists(image_path):
            print(f"❌ ERROR: Image file does not exist: {image_path}")
            return None
            
        if not os.path.isfile(image_path):
            print(f"❌ ERROR: Path is not a file: {image_path}")
            return None
        
        # Create output directory for results
        results_dir = os.path.join(output_directory, "steganography_analysis")
        os.makedirs(results_dir, exist_ok=True)
        
        # Perform simplified analysis
        analysis_result = _analyze_image_file(image_path, results_dir, threshold_bytes, verbose)
        
        if analysis_result:
            if analysis_result.get('is_suspicious'):
                print(f"🚨 SUSPICIOUS: {os.path.basename(image_path)} has {analysis_result['trailing_bytes']} trailing bytes")
            else:
                print(f"✅ Clean: {os.path.basename(image_path)} - {analysis_result['trailing_bytes']} trailing bytes (below threshold)")
            
            return analysis_result
        else:
            print("❌ ERROR: Image analysis failed")
            return None
            
    except Exception as e:
        print(f"❌ ERROR: Failed to analyze image: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return None

def _analyze_image_file(image_path, results_dir, threshold_bytes, verbose=False):
    """Simplified analysis logic for detecting suspicious trailing data."""
    
    # Read file into memory
    with open(image_path, 'rb') as f:
        file_data = f.read()
    
    file_size = len(file_data)
    if verbose:
        print(f"[DEBUG] File size: {file_size} bytes")
        print(f"[DEBUG] Suspicious threshold: {threshold_bytes} bytes")
    
    # Detect file format and find end marker
    format_info = _detect_image_format(file_data, verbose)
    if not format_info:
        return None
    
    # Calculate trailing data size
    trailing_size = file_size - format_info['end_offset']
    
    if verbose:
        print(f"[DEBUG] Legitimate image ends at offset: {format_info['end_offset']}")
        print(f"[DEBUG] Trailing data size: {trailing_size} bytes")
    
    # Simple threshold-based classification
    is_suspicious = trailing_size >= threshold_bytes
    
    if verbose:
        print(f"[DEBUG] Suspicious classification: {is_suspicious}")
    
    # Prepare simple analysis results
    analysis_result = {
        'image_path': image_path,
        'image_format': format_info['format'],
        'image_size': file_size,
        'legitimate_end_offset': format_info['end_offset'],
        'trailing_bytes': trailing_size,
        'threshold_bytes': threshold_bytes,
        'is_suspicious': is_suspicious
    }
    
    # Generate simple report if suspicious
    if is_suspicious:
        report_file = _generate_simple_report(analysis_result, results_dir, verbose)
        analysis_result['report_file'] = report_file
    
    return analysis_result

def _detect_image_format(file_data, verbose=False):
    """Detect image format and find the end of legitimate content."""
    
    # PNG format detection
    if file_data.startswith(b'\x89PNG\r\n\x1a\n'):
        if verbose:
            print("[DEBUG] Detected PNG format")
        
        # Find IEND chunk
        iend_marker = b'IEND'
        iend_pos = file_data.find(iend_marker)
        
        if iend_pos == -1:
            if verbose:
                print("[DEBUG] Warning: IEND chunk not found in PNG")
            return None
        
        # IEND chunk structure: [length:4][IEND:4][CRC:4] = 12 bytes total
        # End of PNG is after the CRC (4 bytes after IEND marker)
        png_end_offset = iend_pos + 4 + 4  # IEND + CRC
        
        if verbose:
            print(f"[DEBUG] Found IEND at offset {iend_pos}")
            print(f"[DEBUG] PNG ends at offset {png_end_offset}")
        
        return {
            'format': 'PNG',
            'end_offset': png_end_offset,
            'marker_position': iend_pos
        }
    
    # JPEG format detection
    elif file_data.startswith(b'\xff\xd8'):
        if verbose:
            print("[DEBUG] Detected JPEG format")
        
        # Find End of Image marker (EOI)
        eoi_pos = file_data.rfind(b'\xff\xd9')  # Use rfind for last occurrence
        
        if eoi_pos == -1:
            if verbose:
                print("[DEBUG] Warning: EOI marker not found in JPEG")
            return None
        
        jpeg_end_offset = eoi_pos + 2  # EOI marker is 2 bytes
        
        if verbose:
            print(f"[DEBUG] Found EOI at offset {eoi_pos}")
            print(f"[DEBUG] JPEG ends at offset {jpeg_end_offset}")
        
        return {
            'format': 'JPEG',
            'end_offset': jpeg_end_offset,
            'marker_position': eoi_pos
        }
    
    # GIF format detection
    elif file_data.startswith(b'GIF87a') or file_data.startswith(b'GIF89a'):
        if verbose:
            print("[DEBUG] Detected GIF format")
        
        # Find GIF trailer (semicolon)
        trailer_pos = file_data.rfind(b';')  # Use rfind for last occurrence
        
        if trailer_pos == -1:
            if verbose:
                print("[DEBUG] Warning: GIF trailer not found")
            return None
        
        gif_end_offset = trailer_pos + 1  # Trailer is 1 byte
        
        if verbose:
            print(f"[DEBUG] Found GIF trailer at offset {trailer_pos}")
            print(f"[DEBUG] GIF ends at offset {gif_end_offset}")
        
        return {
            'format': 'GIF',
            'end_offset': gif_end_offset,
            'marker_position': trailer_pos
        }
    
    # BMP format detection
    elif file_data.startswith(b'BM'):
        if verbose:
            print("[DEBUG] Detected BMP format")
        
        # BMP file size is stored at offset 2-5 (4 bytes, little-endian)
        if len(file_data) < 6:
            if verbose:
                print("[DEBUG] Warning: BMP file too small to read header")
            return None
        
        file_size = struct.unpack('<I', file_data[2:6])[0]  # Little-endian unsigned int
        
        if verbose:
            print(f"[DEBUG] BMP declared file size: {file_size} bytes")
            print(f"[DEBUG] Actual file size: {len(file_data)} bytes")
        
        # Use the smaller of declared size or actual file size as the legitimate end
        bmp_end_offset = min(file_size, len(file_data))
        
        return {
            'format': 'BMP',
            'end_offset': bmp_end_offset,
            'marker_position': file_size,  # Store declared size for reference
            'declared_size': file_size
        }
    
    # WebP format detection
    elif file_data.startswith(b'RIFF') and file_data[8:12] == b'WEBP':
        if verbose:
            print("[DEBUG] Detected WebP format")
        
        # WebP file size is stored at offset 4-7 (4 bytes, little-endian)
        # Total file size = 8 bytes (RIFF + size) + declared size
        if len(file_data) < 12:
            if verbose:
                print("[DEBUG] Warning: WebP file too small to read header")
            return None
        
        chunk_size = struct.unpack('<I', file_data[4:8])[0]  # Little-endian unsigned int
        webp_end_offset = 8 + chunk_size  # 8 bytes header + chunk size
        
        if verbose:
            print(f"[DEBUG] WebP declared chunk size: {chunk_size} bytes")
            print(f"[DEBUG] WebP ends at offset {webp_end_offset}")
        
        return {
            'format': 'WebP',
            'end_offset': webp_end_offset,
            'marker_position': chunk_size,
            'declared_size': chunk_size
        }
    
    # TIFF format detection (basic)
    elif file_data.startswith(b'II*\x00') or file_data.startswith(b'MM\x00*'):
        if verbose:
            print("[DEBUG] Detected TIFF format")
        
        # TIFF is complex, we'll use a heuristic approach
        # Look for common end patterns or use file size
        # This is a simplified detection - TIFF can be complex
        
        # For now, assume the entire file is legitimate TIFF data
        # This could be enhanced with proper TIFF parsing
        tiff_end_offset = len(file_data)
        
        if verbose:
            print(f"[DEBUG] TIFF analysis using full file size: {tiff_end_offset}")
            print("[DEBUG] Note: TIFF format uses simplified detection")
        
        return {
            'format': 'TIFF',
            'end_offset': tiff_end_offset,
            'marker_position': len(file_data),
            'note': 'TIFF uses simplified detection - may have false negatives'
        }
    
    else:
        if verbose:
            print("[DEBUG] Unsupported image format or corrupted file")
            print(f"[DEBUG] File starts with: {file_data[:16].hex()}")
        return None

def _generate_simple_report(analysis_result, results_dir, verbose=False):
    """Generate simple report for suspicious images."""
    
    # Generate basic text report
    report_file = os.path.join(results_dir, "suspicious_image_report.txt")
    with open(report_file, 'w') as f:
        f.write("SUSPICIOUS IMAGE DETECTED\n")
        f.write("=" * 30 + "\n\n")
        
        f.write(f"Image File: {os.path.basename(analysis_result['image_path'])}\n")
        f.write(f"Format: {analysis_result['image_format']}\n")
        f.write(f"Total File Size: {analysis_result['image_size']} bytes\n")
        f.write(f"Legitimate Image Ends: {analysis_result['legitimate_end_offset']} bytes\n")
        f.write(f"Trailing Data Size: {analysis_result['trailing_bytes']} bytes\n")
        f.write(f"Threshold: {analysis_result['threshold_bytes']} bytes\n\n")
        
        f.write("🚨 SUSPICIOUS CLASSIFICATION\n")
        f.write(f"This image has {analysis_result['trailing_bytes']} bytes of data after the legitimate image content,\n")
        f.write(f"which exceeds the suspicious threshold of {analysis_result['threshold_bytes']} bytes.\n\n")
        f.write("⚠️  RECOMMENDATION: Manual investigation required\n")
        f.write("The trailing data could indicate steganography or malware.\n")
    
    if verbose:
        print(f"[DEBUG] Generated suspicious image report: {report_file}")
    
    return report_file
```

### **Phase 2: Results Parser (`parsers/parse_steganography_results.py`)**

Following the pattern for parser functions in the parsers/ directory:

```python
import os
import json

def parse_steganography_results(results_directory, verbose=False):
    """
    Parse steganography analysis results and generate summary.
    
    Args:
        results_directory (str): Directory containing analysis results
        verbose (bool): Enable verbose output
        
    Returns:
        str: Human-readable summary of findings
    """
    if verbose:
        print(f"[DEBUG] Parsing steganography results from: {results_directory}")
    
    try:
        # Look for analysis results
        analysis_dir = os.path.join(results_directory, "steganography_analysis")
        json_file = os.path.join(analysis_dir, "steganography_analysis.json")
        
        if not os.path.exists(json_file):
            return "No steganography analysis results found."
        
        # Load analysis results
        with open(json_file, 'r') as f:
            results = json.load(f)
        
        # Generate summary
        summary = _generate_summary(results, verbose)
        
        # Save summary to file
        summary_file = os.path.join(analysis_dir, "steganography_summary.txt")
        with open(summary_file, 'w') as f:
            f.write(summary)
        
        if verbose:
            print(f"[DEBUG] Generated summary: {summary_file}")
        
        return summary
        
    except Exception as e:
        error_msg = f"Failed to parse steganography results: {e}"
        if verbose:
            print(f"[DEBUG] {error_msg}")
        return error_msg

def _generate_summary(results, verbose=False):
    """Generate human-readable summary of analysis results."""
    
    summary_lines = []
    summary_lines.append("STEGANOGRAPHY ANALYSIS SUMMARY")
    summary_lines.append("=" * 35)
    summary_lines.append("")
    
    image_name = os.path.basename(results['image_path'])
    summary_lines.append(f"Image: {image_name}")
    summary_lines.append(f"Format: {results['image_format']}")
    summary_lines.append(f"Size: {results['image_size']} bytes")
    summary_lines.append("")
    
    if results['hidden_data_found']:
        summary_lines.append("🚨 HIDDEN DATA DETECTED!")
        summary_lines.append(f"Hidden payload size: {results['trailing_data_size']} bytes")
        summary_lines.append("")
        
        if results.get('payload_type') and results['payload_type'] != 'Unknown':
            summary_lines.append(f"Likely payload type: {results['payload_type']}")
        
        if results.get('potential_signatures'):
            summary_lines.append("Detected signatures:")
            for sig in results['potential_signatures']:
                summary_lines.append(f"  - {sig['type']}")
        
        if results.get('entropy_analysis'):
            entropy = results['entropy_analysis']
            summary_lines.append(f"Encryption likelihood: {'High' if entropy['likely_encrypted'] else 'Low'}")
        
        summary_lines.append("")
        summary_lines.append("⚠️  RECOMMENDATION: This image requires manual investigation")
        summary_lines.append("   The hidden data could be malicious (DEX files, backdoors, etc.)")
        
    else:
        summary_lines.append("✅ NO HIDDEN DATA FOUND")
        summary_lines.append("   Image appears clean and contains only legitimate image data")
    
    return "\n".join(summary_lines)
```

## **Integration with Main Workflow**

### **Command Line Arguments**
Add new optional flag to `automatool.py`:

```python
# In parse_arguments() function:
parser.add_argument(
    "--detect-steganography",
    action="store_true", 
    help="Analyze image files in the directory for hidden data/steganography"
)

parser.add_argument(
    "--image-extensions",
    default=".png,.jpg,.jpeg,.gif,.bmp,.webp,.tiff,.tif",
    help="Comma-separated list of image extensions to analyze (default: .png,.jpg,.jpeg,.gif,.bmp,.webp,.tiff,.tif)"
)
```

### **Main Workflow Integration**
```python
# In automatool.py main() function:

def main():
    # ... existing workflow ...
    
    # 🆕 Image Steganography Detection (after other analyses)
    if args.detect_steganography:
        print("\n" + "="*50)
        print("📸 RUNNING IMAGE STEGANOGRAPHY DETECTION")
        print("="*50)
        
        steganography_results = run_steganography_detection(
            args.directory, 
            args.image_extensions, 
            args.verbose
        )
        
        if steganography_results:
            # Track results directory
            stego_dir = os.path.join(args.directory, "steganography_analysis")
            if os.path.exists(stego_dir):
                resource_tracker.add_directory(stego_dir)
        
        print("✅ Image steganography detection complete")

def run_steganography_detection(target_directory, extensions, verbose=False):
    """Run steganography detection on all images in directory."""
    
    # Import detection and parsing functions from their respective directories
    from scripts.automations.detect_image_steganography import detect_image_steganography
    from scripts.parsers.parse_steganography_results import parse_steganography_results
    
    if verbose:
        print(f"[DEBUG] Scanning {target_directory} for images...")
    
    # Parse extension list
    ext_list = [ext.strip().lower() for ext in extensions.split(',')]
    if verbose:
        print(f"[DEBUG] Looking for extensions: {ext_list}")
    
    # Find all image files
    image_files = []
    for file in os.listdir(target_directory):
        file_path = os.path.join(target_directory, file)
        if os.path.isfile(file_path):
            _, ext = os.path.splitext(file.lower())
            if ext in ext_list:
                image_files.append(file_path)
    
    if not image_files:
        print("ℹ️  No image files found to analyze")
        return None
    
    print(f"📸 Found {len(image_files)} image file(s) to analyze")
    
    # Analyze each image
    all_results = []
    for image_path in image_files:
        if verbose:
            print(f"[DEBUG] Analyzing: {os.path.basename(image_path)}")
        
        result = detect_image_steganography(image_path, target_directory, verbose)
        if result:
            all_results.append(result)
    
    # Generate combined summary
    if all_results:
        summary = _generate_combined_summary(all_results, target_directory, verbose)
        return summary
    
    return None

def _generate_combined_summary(results_list, output_dir, verbose=False):
    """Generate a summary of all steganography analysis results."""
    
    summary_lines = []
    summary_lines.append("COMBINED STEGANOGRAPHY ANALYSIS RESULTS")
    summary_lines.append("=" * 45)
    summary_lines.append("")
    
    total_images = len(results_list)
    suspicious_images = sum(1 for r in results_list if r['hidden_data_found'])
    
    summary_lines.append(f"Total images analyzed: {total_images}")
    summary_lines.append(f"Images with hidden data: {suspicious_images}")
    summary_lines.append("")
    
    if suspicious_images > 0:
        summary_lines.append("🚨 SUSPICIOUS IMAGES DETECTED:")
        for result in results_list:
            if result['hidden_data_found']:
                image_name = os.path.basename(result['image_path'])
                payload_size = result['trailing_data_size']
                payload_type = result.get('payload_type', 'Unknown')
                summary_lines.append(f"  - {image_name}: {payload_size} bytes ({payload_type})")
        
        summary_lines.append("")
        summary_lines.append("⚠️  IMMEDIATE ACTION REQUIRED!")
        summary_lines.append("   These images contain hidden data and should be investigated")
        summary_lines.append("   Check individual analysis reports for detailed findings")
    else:
        summary_lines.append("✅ ALL IMAGES APPEAR CLEAN")
        summary_lines.append("   No hidden data detected in any analyzed images")
    
    # Save combined summary
    summary_text = "\n".join(summary_lines)
    summary_file = os.path.join(output_dir, "steganography_combined_summary.txt")
    with open(summary_file, 'w') as f:
        f.write(summary_text)
    
    if verbose:
        print(f"[DEBUG] Generated combined summary: {summary_file}")
    
    print("\n" + summary_text)
    return summary_text
```

## **Output Structure**
```
target_directory/
├── steganography_analysis/
│   ├── steganography_analysis.txt      # Human-readable detailed report
│   ├── steganography_analysis.json     # Machine-readable results
│   ├── steganography_summary.txt       # Brief summary
│   └── extracted_payload.bin           # Raw extracted payload (if found)
├── steganography_combined_summary.txt  # Summary of all analyzed images
├── reviews.json                        # Existing files...
└── ...
```

## **Resource Management**

### **File Tracking**
Following existing patterns:
```python
# Track analysis directory
stego_dir = os.path.join(args.directory, "steganography_analysis") 
if os.path.exists(stego_dir):
    resource_tracker.add_directory(stego_dir)

# Track summary file
summary_file = os.path.join(args.directory, "steganography_combined_summary.txt")
if os.path.exists(summary_file):
    resource_tracker.add_file(summary_file)
```

## **Error Handling Strategy**

### **Input Validation**
- Verify image file exists and is readable
- Check file format compatibility 
- Validate output directory permissions
- Handle corrupted or truncated image files

### **Analysis Errors**
- Graceful handling of unrecognized image formats
- Continue workflow if some images fail analysis
- Clear error messages for debugging
- Fallback to basic hex analysis if format detection fails

### **Performance Considerations**
- Memory-efficient processing for large images
- Timeout protection for very large files
- Progress indicators for multiple image analysis
- Skip analysis for extremely large files (>100MB) with warning

## **Security Considerations**

### **Safe Analysis**
- Read-only analysis (no file modification)
- Extracted payloads saved in secure directory
- No automatic execution of extracted content
- Clear warnings about manual investigation needs

### **Output Security**
- Sanitize file paths in reports
- Limit hex dump output size
- No sensitive information in verbose logs
- Safe handling of potentially malicious payloads

## **Testing Strategy**

### **Test Images**
Create test images with known hidden data for all supported formats:
```
tests/resources/steganography/
├── clean_images/
│   ├── clean_image.png          # Normal PNG with no hidden data
│   ├── clean_image.jpg          # Normal JPEG with no hidden data
│   ├── clean_image.gif          # Normal GIF with no hidden data
│   ├── clean_image.bmp          # Normal BMP with no hidden data
│   └── clean_image.webp         # Normal WebP with no hidden data
├── hidden_data/
│   ├── dex_hidden.png           # PNG with appended DEX file
│   ├── dex_hidden.jpg           # JPEG with appended DEX file
│   ├── zip_appended.gif         # GIF with ZIP archive
│   ├── encrypted_payload.bmp    # BMP with encrypted data
│   └── malware_payload.webp     # WebP with malware payload
├── corrupted/
│   ├── corrupted_iend.png       # PNG with corrupted IEND marker
│   ├── corrupted_eoi.jpg        # JPEG with corrupted EOI marker
│   └── truncated_gif.gif        # GIF missing trailer
└── edge_cases/
    ├── empty_trailing.png       # PNG with empty trailing data (0 bytes)
    ├── large_payload.jpg        # JPEG with very large hidden payload
    └── multiple_formats.bmp     # BMP with multiple hidden file types
```

### **Unit Tests**
- Test PNG IEND marker detection
- Test JPEG EOI marker detection  
- Test GIF trailer detection
- Test BMP file size calculation
- Test WebP RIFF chunk parsing
- Test TIFF format handling
- Test file signature recognition for all formats
- Test entropy calculation
- Test report generation
- Test error handling scenarios for each format

### **Integration Tests**
- Test full workflow with various image types
- Test resource tracking integration
- Test command line argument handling
- Test output file generation

## **Usage Examples**

### **Basic Usage**
```bash
# Analyze all supported image formats in APK directory
automatool.py -d "/path/to/apk" -f "app.apk" --detect-steganography

# Analyze only specific formats with verbose output
automatool.py -d "/path/to/apk" -f "app.apk" --detect-steganography --image-extensions ".png,.jpg,.jpeg" --verbose

# Analyze all formats including WebP and TIFF
automatool.py -d "/path/to/apk" -f "app.apk" --detect-steganography --image-extensions ".png,.jpg,.jpeg,.gif,.bmp,.webp,.tiff,.tif" --verbose

# Combine with other analyses
automatool.py -d "/path/to/apk" -f "app.apk" --detect-steganography --mobsf --verbose
```

### **Expected Output**
```
📸 RUNNING IMAGE STEGANOGRAPHY DETECTION
==================================================
📸 Found 5 image file(s) to analyze
[DEBUG] Analyzing: app_icon.png
[DEBUG] Detected PNG format
[DEBUG] Found IEND at offset 1024
[DEBUG] PNG ends at offset 1032
🚨 ALERT: Hidden data detected in app_icon.png
[DEBUG] Analyzing: background.jpg  
[DEBUG] Detected JPEG format
[DEBUG] Found EOI at offset 5420
[DEBUG] JPEG ends at offset 5422
✅ No hidden data found in background.jpg
[DEBUG] Analyzing: logo.gif
[DEBUG] Detected GIF format
[DEBUG] Found GIF trailer at offset 892
[DEBUG] GIF ends at offset 893
✅ No hidden data found in logo.gif
✅ Image steganography analysis complete

COMBINED STEGANOGRAPHY ANALYSIS RESULTS
=============================================

Total images analyzed: 5
Images with hidden data: 1

🚨 SUSPICIOUS IMAGES DETECTED:
  - app_icon.png: 2048 bytes (Android DEX)

⚠️  IMMEDIATE ACTION REQUIRED!
   These images contain hidden data and should be investigated
   Check individual analysis reports for detailed findings
```

## **Benefits and Value**

### **Security Enhancement**
- Detect sophisticated malware hiding techniques
- Identify steganographic payloads in APK resources
- Catch DEX files hidden in image assets
- Provide early warning of advanced threats

### **Forensic Capabilities**
- Extract hidden payloads for further analysis
- Document evidence of steganographic techniques
- Support incident response investigations  
- Enable malware family classification

### **Integration Benefits**
- Seamless integration with existing automatool workflow
- Consistent UI/UX with other automations
- Resource tracking for cleanup
- Parallel execution with other analyses

## **Implementation Phases**

### **Phase 1: Core Detection Engine**
1. Implement `automations/detect_image_steganography.py`
2. Multi-format detection (PNG, JPEG, GIF, BMP, WebP, TIFF)
3. Format-specific end marker detection
4. File signature recognition
5. Output file generation

### **Phase 2: Analysis Enhancement**
1. Entropy calculation for encryption detection
2. Enhanced signature database for malware types
3. Hex dump generation with formatting
4. Performance optimization for large files

### **Phase 3: Results Processing**
1. Implement `parsers/parse_steganography_results.py`
2. Format-aware summary generation
3. Combined reporting for multiple images
4. JSON output for automation and integration

### **Phase 4: Integration**
1. Add command line arguments
2. Integrate with main automatool workflow
3. Resource tracking integration
4. Error handling refinement

### **Phase 5: Testing and Documentation**
1. Create comprehensive test suite
2. Performance testing with large images
3. User documentation
4. Security validation

## **Success Criteria**
- [ ] Accurate detection of data after image format end markers (PNG IEND, JPEG EOI, GIF trailer, etc.)
- [ ] Multi-format support for all common image types (PNG, JPEG, GIF, BMP, WebP, TIFF)
- [ ] Recognition of common hidden file types (DEX, ZIP, ELF, etc.)
- [ ] Clear reporting of findings with actionable information
- [ ] Proper file organization: automation in `automations/`, parsing in `parsers/`
- [ ] Seamless integration with existing automatool workflow
- [ ] Comprehensive error handling and graceful degradation
- [ ] Resource tracking integration for cleanup
- [ ] Performance suitable for typical APK analysis workflows
- [ ] Security-conscious handling of potentially malicious payloads

## **Future Enhancements**
- Advanced entropy analysis and statistical tests
- Machine learning-based payload classification
- Integration with external malware analysis tools
- Automated payload extraction and sandboxing
- Support for more sophisticated steganographic techniques (LSB, frequency domain)
- Enhanced TIFF format parsing for better detection accuracy
- Support for RAW image formats (CR2, NEF, ARW)
- Detection of steganography within legitimate image data (not just appended)
- Integration with VirusTotal for payload analysis
- Support for detecting multiple hidden payloads in single images

This specification provides a comprehensive, maintainable, and secure solution for detecting image-based steganography that follows established automatool patterns while adding valuable security analysis capabilities to the mobile malware analysis toolkit.
