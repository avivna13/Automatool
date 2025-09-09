#!/usr/bin/env python3
"""
TTF Font Analysis Worker Script

This script performs the actual TTF font steganography detection work.
It's designed to run as a background process launched by launch_font_analysis.py.

The worker:
1. Finds fonts directory in APK decompilation
2. Discovers TTF fonts recursively
3. Analyzes each font using detect_ttf_steganography
4. Generates comprehensive reports and summaries

Usage:
    python _font_analysis_worker.py --apktool-path /path/to/apk --output-dir /path/to/output
"""

import os
import sys
import argparse
import json
import time
from pathlib import Path
from datetime import datetime
from resource_tracker import GlobalResourceTracker

# Add the scripts directory to the path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

# Import the detection module
from detect_ttf_steganography import detect_ttf_steganography


def find_fonts_directory(apktool_output_path, verbose=False):
    """
    Find the fonts directory in the APK decompilation output.
    
    Args:
        apktool_output_path (str): Path to apktool output directory
        verbose (bool): Enable verbose output
        
    Returns:
        str or None: Path to fonts directory if found, None otherwise
    """
    if verbose:
        print(f"[WORKER] Searching for fonts directory in: {apktool_output_path}")
    
    # Common locations for fonts in APK decompilation
    possible_font_dirs = [
        os.path.join(apktool_output_path, "assets", "fonts"),
        os.path.join(apktool_output_path, "assets", "font"),
        os.path.join(apktool_output_path, "res", "font"),
        os.path.join(apktool_output_path, "res", "fonts"),
        os.path.join(apktool_output_path, "fonts"),
    ]
    
    for font_dir in possible_font_dirs:
        if os.path.exists(font_dir) and os.path.isdir(font_dir):
            if verbose:
                print(f"[WORKER] Found fonts directory: {font_dir}")
            return font_dir
    
    # Search recursively for any directory containing TTF files
    if verbose:
        print(f"[WORKER] No standard fonts directory found, searching recursively...")
    
    for root, dirs, files in os.walk(apktool_output_path):
        for file in files:
            if file.lower().endswith('.ttf'):
                font_dir = os.path.dirname(os.path.join(root, file))
                if verbose:
                    print(f"[WORKER] Found TTF files in: {font_dir}")
                return font_dir
    
    if verbose:
        print(f"[WORKER] No fonts directory or TTF files found")
    return None


def discover_ttf_fonts(fonts_path, verbose=False):
    """
    Discover all TTF font files in the fonts directory.
    
    Args:
        fonts_path (str): Path to fonts directory
        verbose (bool): Enable verbose output
        
    Returns:
        list: List of full paths to TTF font files
    """
    if verbose:
        print(f"[WORKER] Discovering TTF fonts in: {fonts_path}")
    
    font_files = []
    
    # Search recursively for TTF files
    for root, dirs, files in os.walk(fonts_path):
        for file in files:
            if file.lower().endswith('.ttf'):
                font_path = os.path.join(root, file)
                font_files.append(font_path)
                if verbose:
                    print(f"[WORKER] Found TTF font: {file}")
    
    if verbose:
        print(f"[WORKER] Total TTF fonts discovered: {len(font_files)}")
    
    return font_files


def generate_font_analysis_summary(analysis_results, suspicious_count):
    """
    Generate a summary text for the font analysis results.
    
    Args:
        analysis_results (list): List of analysis result dictionaries
        suspicious_count (int): Count of suspicious fonts
        
    Returns:
        str: Formatted summary text
    """
    total_fonts = len(analysis_results)
    
    summary = f"TTF Font Steganography Analysis Summary\n"
    summary += f"=" * 45 + "\n\n"
    
    summary += f"Analysis completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    summary += f"Total fonts analyzed: {total_fonts}\n"
    summary += f"Suspicious fonts detected: {suspicious_count}\n"
    summary += f"Clean fonts: {total_fonts - suspicious_count}\n\n"
    
    if suspicious_count > 0:
        summary += f"⚠️  WARNING: {suspicious_count} suspicious font(s) detected!\n"
        summary += f"These fonts exceed the 150 KB threshold and may contain:\n"
        summary += f"- Hidden data or steganographic payloads\n"
        summary += f"- Malware or malicious code\n"
        summary += f"- Corrupted or manipulated content\n\n"
        
        summary += f"Detailed reports have been generated for each suspicious font.\n"
        summary += f"Manual investigation is recommended.\n\n"
    else:
        summary += f"✅ All fonts appear to be clean and within normal size ranges.\n\n"
    
    summary += f"Threshold used: 150 KB (153,600 bytes)\n"
    summary += f"Based on standard TTF font size research (50-100 KB average)\n"
    
    return summary


def analyze_apk_fonts_worker(apktool_output_path, target_directory, verbose=False, tracker=None):
    """
    Worker function that performs the actual font analysis.
    
    Args:
        apktool_output_path (str): Path to apktool output directory
        target_directory (str): Base target directory for results
        verbose (bool): Enable verbose output
        tracker (GlobalResourceTracker): Resource tracker instance
        
    Returns:
        dict: Analysis results
    """
    if verbose:
        print(f"[WORKER] Starting TTF font analysis...")
        print(f"[WORKER] APK path: {apktool_output_path}")
        print(f"[WORKER] Output directory: {target_directory}")
    
    # Step 1: Find fonts directory
    fonts_path = find_fonts_directory(apktool_output_path, verbose)
    if not fonts_path:
        return {
            'total_fonts_found': 0,
            'total_fonts_analyzed': 0,
            'suspicious_fonts_count': 0,
            'analysis_results': [],
            'summary_text': "No fonts directory found in decompiled APK.",
            'output_directory': None,
            'status': 'no_fonts'
        }
    
    # Step 2: Discover TTF fonts
    font_files = discover_ttf_fonts(fonts_path, verbose)
    if not font_files:
        return {
            'total_fonts_found': 0,
            'total_fonts_analyzed': 0,
            'suspicious_fonts_count': 0,
            'analysis_results': [],
            'summary_text': "No TTF font files found in fonts directory.",
            'output_directory': None,
            'status': 'no_fonts'
        }
    
    # Step 3: Analyze each font
    analysis_results = []
    suspicious_count = 0
    
    if verbose:
        print(f"[WORKER] Starting analysis of {len(font_files)} TTF fonts...")
    
    for i, font_path in enumerate(font_files, 1):
        if verbose:
            print(f"[WORKER] [{i}/{len(font_files)}] Analyzing {os.path.basename(font_path)}")
        
        try:
            result = detect_ttf_steganography(font_path, target_directory, verbose)
            if result:
                analysis_results.append(result)
                if result.get('is_suspicious'):
                    suspicious_count += 1
                    if verbose:
                        print(f"[WORKER] ⚠️  Suspicious font detected: {os.path.basename(font_path)}")
                        
        except Exception as e:
            if verbose:
                print(f"[WORKER] Error analyzing {font_path}: {e}")
    
    # Step 4: Generate summary
    summary_text = generate_font_analysis_summary(analysis_results, suspicious_count)
    
    # Step 5: Save summary to file
    output_dir = os.path.join(target_directory, "font_steganography_analysis")
    os.makedirs(output_dir, exist_ok=True)
    
    # Track the output directory
    if tracker:
        try:
            tracker.add_directory(output_dir)
            if verbose:
                print(f"[WORKER] 📁 Tracked font analysis directory: {output_dir}")
        except Exception as e:
            if verbose:
                print(f"[WORKER] ⚠️  WARNING: Failed to track directory: {e}")
    
    summary_file = os.path.join(output_dir, "analysis_summary.txt")
    with open(summary_file, 'w') as f:
        f.write(summary_text)
    
    # Track the summary file
    if tracker:
        try:
            tracker.add_file(summary_file)
            if verbose:
                print(f"[WORKER] 📄 Tracked summary file: {summary_file}")
        except Exception as e:
            if verbose:
                print(f"[WORKER] ⚠️  WARNING: Failed to track summary file: {e}")
    
    if verbose:
        print(f"[WORKER] Analysis summary saved to: {summary_file}")
    
    return {
        'total_fonts_found': len(font_files),
        'total_fonts_analyzed': len(analysis_results),
        'suspicious_fonts_count': suspicious_count,
        'analysis_results': analysis_results,
        'summary_text': summary_text,
        'output_directory': output_dir,
        'status': 'completed'
    }


def main():
    """Main entry point for the worker script."""
    parser = argparse.ArgumentParser(description="TTF Font Analysis Worker")
    parser.add_argument("--apktool-path", required=True, help="Path to apktool output directory")
    parser.add_argument("--output-dir", required=True, help="Target output directory")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--quiet", action="store_true", help="Suppress all output")
    
    args = parser.parse_args()
    
    # Initialize resource tracker
    try:
        tracker = GlobalResourceTracker()
        if not args.quiet:
            print("🔧 Resource tracker initialized")
    except Exception as e:
        if not args.quiet:
            print(f"⚠️  WARNING: Could not initialize resource tracker: {e}")
        tracker = None
    
    # Handle quiet mode
    if args.quiet:
        # Redirect stdout and stderr to /dev/null
        sys.stdout = open(os.devnull, 'w')
        sys.stderr = open(os.devnull, 'w')
    
    if not args.quiet:
        print("🔤 TTF Font Analysis Worker")
        print("=" * 40)
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
    
    try:
        # Perform the analysis
        start_time = time.time()
        results = analyze_apk_fonts_worker(args.apktool_path, args.output_dir, args.verbose, tracker)
        end_time = time.time()
        
        if not args.quiet:
            print(f"\n✅ Analysis completed in {end_time - start_time:.2f} seconds and resources tracked")
            print(f"📊 Results: {results['total_fonts_analyzed']} fonts analyzed, {results['suspicious_fonts_count']} suspicious")
            print(f"📁 Output directory: {results['output_directory']}")
        
        # Save results as JSON for programmatic access
        if results['output_directory']:
            json_file = os.path.join(results['output_directory'], "analysis_results.json")
            with open(json_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            # Track the JSON results file
            if tracker:
                try:
                    tracker.add_file(json_file)
                    if not args.quiet:
                        print(f"📄 Tracked JSON results: {json_file}")
                except Exception as e:
                    if not args.quiet:
                        print(f"⚠️  WARNING: Failed to track JSON file: {e}")
            
            if not args.quiet:
                print(f"📄 JSON results saved to: {json_file}")
        
        return 0
        
    except Exception as e:
        if not args.quiet:
            print(f"❌ ERROR: Font analysis failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
