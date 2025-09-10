#!/usr/bin/env python3
"""
Image Steganography Detection Automation

This script analyzes image files to detect suspicious trailing data after legitimate image content.
It uses a simple byte threshold approach to classify potentially suspicious images.

Supports: PNG, JPEG, GIF, BMP, WebP formats
Threshold: 10 bytes (configurable) - based on security research for minimal false positives
"""

import os
import struct
import sys
import argparse


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
        print(f"[DEBUG] Suspicious threshold: {threshold_bytes} bytes")
    
    try:
        # Validate input file
        if not os.path.exists(image_path):
            print(f"ERROR: Image file does not exist: {image_path}")
            return None
            
        if not os.path.isfile(image_path):
            print(f"ERROR: Path is not a file: {image_path}")
            return None
        
        # Create output directory for results
        results_dir = os.path.join(output_directory, "steganography_analysis")
        os.makedirs(results_dir, exist_ok=True)
        
        # Perform simplified analysis
        analysis_result = _analyze_image_file(image_path, results_dir, threshold_bytes, verbose)
        
        if analysis_result:
            if analysis_result.get('is_suspicious'):
                print(f"SUSPICIOUS: {os.path.basename(image_path)} has {analysis_result['trailing_bytes']} trailing bytes")
            else:
                print(f"CLEAN: {os.path.basename(image_path)} - {analysis_result['trailing_bytes']} trailing bytes (below threshold)")
            
            return analysis_result
        else:
            print("ERROR: Image analysis failed")
            return None
            
    except Exception as e:
        print(f"ERROR: Failed to analyze image: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return None


def _analyze_image_file(image_path, results_dir, threshold_bytes, verbose=False):
    """
    Simplified analysis logic for detecting suspicious trailing data.
    
    This function:
    1. Reads the image file into memory
    2. Detects the image format and finds its legitimate end
    3. Calculates trailing data size
    4. Classifies as suspicious if trailing data >= threshold
    """
    
    # Read file into memory
    with open(image_path, 'rb') as f:
        file_data = f.read()
    
    file_size = len(file_data)
    if verbose:
        print(f"[DEBUG] File size: {file_size} bytes")
    
    # Detect file format and find end marker
    format_info = _detect_image_format(file_data, verbose)
    if not format_info:
        if verbose:
            print("[DEBUG] Unsupported or corrupted image format")
        return None
    
    # Calculate trailing data size
    trailing_size = file_size - format_info['end_offset']
    
    if verbose:
        print(f"[DEBUG] Legitimate {format_info['format']} ends at offset: {format_info['end_offset']}")
        print(f"[DEBUG] Trailing data size: {trailing_size} bytes")
    
    # Simple threshold-based classification
    is_suspicious = trailing_size >= threshold_bytes
    
    if verbose:
        classification = "SUSPICIOUS" if is_suspicious else "CLEAN"
        print(f"[DEBUG] Classification: {classification}")
    
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
    """
    Detect image format and find the end of legitimate content.
    
    This function checks file signatures and locates format-specific end markers:
    - PNG: IEND chunk marker
    - JPEG: End of Image (EOI) marker
    - GIF: Trailer semicolon
    - BMP: File size from header
    - WebP: RIFF chunk size
    """
    
    # PNG format detection
    if file_data.startswith(b'\x89PNG\r\n\x1a\n'):
        if verbose:
            print("[DEBUG] Detected PNG format")
        
        # Find IEND chunk marker
        iend_marker = b'IEND'
        iend_pos = file_data.find(iend_marker)
        
        if iend_pos == -1:
            if verbose:
                print("[DEBUG] Warning: IEND chunk not found in PNG")
            return None
        
        # IEND chunk structure: [length:4][IEND:4][CRC:4] = 12 bytes total
        # End of PNG is after the CRC (4 bytes after IEND marker)
        png_end_offset = iend_pos + 4 + 4  # IEND marker + CRC
        
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
        
        declared_size = struct.unpack('<I', file_data[2:6])[0]  # Little-endian unsigned int
        
        if verbose:
            print(f"[DEBUG] BMP declared file size: {declared_size} bytes")
            print(f"[DEBUG] Actual file size: {len(file_data)} bytes")
        
        # Use the smaller of declared size or actual file size as the legitimate end
        bmp_end_offset = min(declared_size, len(file_data))
        
        return {
            'format': 'BMP',
            'end_offset': bmp_end_offset,
            'marker_position': declared_size,
            'declared_size': declared_size
        }
    
    # WebP format detection
    elif file_data.startswith(b'RIFF') and len(file_data) >= 12 and file_data[8:12] == b'WEBP':
        if verbose:
            print("[DEBUG] Detected WebP format")
        
        # WebP file size is stored at offset 4-7 (4 bytes, little-endian)
        # Total file size = 8 bytes (RIFF + size) + declared size
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
    
    else:
        if verbose:
            print("[DEBUG] Unsupported image format or corrupted file")
            if len(file_data) >= 16:
                print(f"[DEBUG] File starts with: {file_data[:16].hex()}")
        return None


def _generate_simple_report(analysis_result, results_dir, verbose=False):
    """
    Generate simple report for suspicious images.
    
    Creates a basic text report with:
    - Image file info
    - Trailing data size vs threshold
    - Recommendation for manual investigation
    """
    
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
        
        f.write("*** SUSPICIOUS CLASSIFICATION ***\n")
        f.write(f"This image has {analysis_result['trailing_bytes']} bytes of data after the legitimate image content,\n")
        f.write(f"which exceeds the suspicious threshold of {analysis_result['threshold_bytes']} bytes.\n\n")
        f.write("WARNING: Manual investigation required\n")
        f.write("The trailing data could indicate steganography or malware.\n")
    
    if verbose:
        print(f"[DEBUG] Generated suspicious image report: {report_file}")
    
    return report_file


def parse_arguments():
    """Parse command line arguments for standalone usage."""
    parser = argparse.ArgumentParser(
        description="Image Steganography Detection - Analyze images for suspicious trailing data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/image.png /path/to/output
  %(prog)s /path/to/image.jpg /path/to/output --threshold 20 --verbose
        """
    )
    
    parser.add_argument(
        "image_path",
        help="Path to image file to analyze"
    )
    
    parser.add_argument(
        "output_directory", 
        help="Directory to save analysis results"
    )
    
    parser.add_argument(
        "--threshold",
        type=int,
        default=10,
        help="Minimum trailing bytes to classify as suspicious (default: 10)"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose debug output"
    )
    
    return parser.parse_args()


def main():
    """Main entry point for standalone execution."""
    args = parse_arguments()
    
    print("🖼️  Starting Image Steganography Detection")
    print(f"📁 Input: {args.image_path}")
    print(f"📁 Output: {args.output_directory}")
    print(f"🎯 Threshold: {args.threshold} bytes")
    
    # Validate inputs
    if not os.path.exists(args.image_path):
        print(f"❌ ERROR: Image file not found: {args.image_path}")
        sys.exit(1)
    
    if not os.path.exists(args.output_directory):
        print(f"❌ ERROR: Output directory not found: {args.output_directory}")
        sys.exit(1)
    
    try:
        # Call the main detection function
        result = detect_image_steganography(
            args.image_path,
            args.output_directory,
            verbose=args.verbose,
            threshold_bytes=args.threshold
        )
        
        if result:
            if result.get('is_suspicious'):
                print(f"🚨 SUSPICIOUS: Image has {result['trailing_bytes']} trailing bytes")
            else:
                print(f"✅ CLEAN: Image has {result['trailing_bytes']} trailing bytes (below threshold)")
            print(f"📄 Analysis complete!")
            sys.exit(0)
        else:
            print("❌ Image analysis failed")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ ERROR: Analysis failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
