#!/usr/bin/env python3
"""
TTF Font Steganography Detection Automation

This script analyzes TTF font files to detect suspicious data using a simple size-based threshold approach.
It uses a single threshold of 150 KB (based on web research showing standard TTF fonts are 50-100 KB).

Threshold: 150 KB (configurable) - based on security research for minimal false positives
"""

import os


def detect_ttf_steganography(font_path, output_directory, verbose=False):
    """
    Simple TTF font steganography detection using size threshold.
    
    Args:
        font_path (str): Path to the TTF font file to analyze
        output_directory (str): Directory to save analysis results
        verbose (bool): Enable verbose output
        
    Returns:
        dict: Simple analysis results with suspicious classification
        Returns None if analysis fails
    """
    if verbose:
        print(f"[DEBUG] Analyzing TTF font for steganography: {font_path}")
        print(f"[DEBUG] Output directory: {output_directory}")
    
    try:
        # Validate input file
        if not os.path.exists(font_path):
            print(f"ERROR: TTF font file does not exist: {font_path}")
            return None
            
        if not os.path.isfile(font_path):
            print(f"ERROR: Path is not a file: {font_path}")
            return None
        
        # Validate TTF extension
        if not font_path.lower().endswith('.ttf'):
            print(f"ERROR: File is not a TTF font: {font_path}")
            return None
        
        # Single threshold: 150 KB (standard font + 50% margin)
        THRESHOLD_BYTES = 150 * 1024  # 150 KB
        
        # Get file size
        file_size = os.path.getsize(font_path)
        
        # Simple classification
        is_suspicious = file_size > THRESHOLD_BYTES
        
        if verbose:
            print(f"[DEBUG] TTF file size: {file_size} bytes ({file_size/1024:.1f} KB)")
            print(f"[DEBUG] Threshold: {THRESHOLD_BYTES} bytes ({THRESHOLD_BYTES/1024:.1f} KB)")
            print(f"[DEBUG] Classification: {'SUSPICIOUS' if is_suspicious else 'CLEAN'}")
        
        # Generate report if suspicious
        report_file = None
        if is_suspicious:
            report_file = _generate_simple_font_report(
                font_path, file_size, THRESHOLD_BYTES, output_directory, verbose
            )
        
        return {
            'font_path': font_path,
            'font_size': file_size,
            'threshold_bytes': THRESHOLD_BYTES,
            'is_suspicious': is_suspicious,
            'report_file': report_file
        }
        
    except Exception as e:
        print(f"ERROR: Failed to analyze TTF font: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return None


def _generate_simple_font_report(font_path, file_size, threshold, output_dir, verbose=False):
    """
    Generate simple report for suspicious TTF fonts.
    
    Creates a basic text report with:
    - Font file info
    - Size vs threshold comparison
    - Recommendation for manual investigation
    """
    
    # Create output directory for results
    results_dir = os.path.join(output_dir, "font_steganography_analysis")
    os.makedirs(results_dir, exist_ok=True)
    
    # Generate basic text report
    report_file = os.path.join(results_dir, "suspicious_font_report.txt")
    with open(report_file, 'w') as f:
        f.write("SUSPICIOUS TTF FONT DETECTED\n")
        f.write("=" * 35 + "\n\n")
        
        f.write(f"Font File: {os.path.basename(font_path)}\n")
        f.write(f"File Size: {file_size} bytes ({file_size/1024:.1f} KB)\n")
        f.write(f"Threshold: {threshold} bytes ({threshold/1024:.1f} KB)\n\n")
        
        f.write("*** SUSPICIOUS CLASSIFICATION ***\n")
        f.write(f"This TTF font exceeds the standard size threshold of {threshold/1024:.1f} KB.\n")
        f.write(f"Standard TTF fonts typically range from 50-100 KB.\n\n")
        
        f.write("WARNING: Manual investigation required\n")
        f.write("The large size could indicate:\n")
        f.write("- Hidden data or steganographic payloads\n")
        f.write("- Malware or malicious code\n")
        f.write("- Extensive character sets (legitimate but rare)\n")
        f.write("- Corrupted or manipulated font files\n\n")
        
        f.write("RECOMMENDATION: Analyze the font file manually to determine\n")
        f.write("if the large size is legitimate or suspicious.\n")
    
    if verbose:
        print(f"[DEBUG] Generated suspicious font report: {report_file}")
    
    return report_file
