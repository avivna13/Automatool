#!/usr/bin/env python3
"""
APK Assets Image Analysis Worker Process

This script runs as a separate background process to analyze all images
in the APK's assets directory for steganographic content.

Following the same pattern as _mobsf_analysis_worker.py.
"""

import argparse
import os
import sys
import json
import time
import shutil
from pathlib import Path

# Add script directory to path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

# Import analysis components
from detect_image_steganography import detect_image_steganography
sys.path.insert(0, os.path.join(script_dir, '..', 'parsers'))
from parse_steganography_results import generate_combined_summary


def main():
    """Main worker process entry point."""
    parser = argparse.ArgumentParser(description="Assets image analysis worker")
    parser.add_argument("--apktool-path", required=True, help="Path to apktool output directory")
    parser.add_argument("--output-dir", required=True, help="Output directory for results")
    parser.add_argument("--threshold", type=int, default=10, help="Suspicious threshold in bytes")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--quiet", action="store_true", help="Suppress output")
    
    args = parser.parse_args()
    verbose = args.verbose and not args.quiet
    
    if verbose:
        print(f"[WORKER] Starting assets analysis...")
        print(f"[WORKER] Apktool path: {args.apktool_path}")
        print(f"[WORKER] Output directory: {args.output_dir}")
        print(f"[WORKER] Threshold: {args.threshold} bytes")
    
    try:
        # Perform the complete analysis workflow
        results = analyze_apk_assets_images_worker(
            args.apktool_path,
            args.output_dir,
            verbose,
            args.threshold
        )
        
        # Save results summary to file for main process tracking
        save_worker_results(results, args.output_dir, verbose)
        
        if verbose:
            print("[WORKER] ✅ Assets analysis completed successfully")
            
    except Exception as e:
        error_msg = f"Assets analysis worker failed: {e}"
        if verbose:
            print(f"[WORKER] ❌ {error_msg}")
        
        # Save error status for main process
        save_worker_error(error_msg, args.output_dir, verbose)
        sys.exit(1)


def analyze_apk_assets_images_worker(apktool_output_path, target_directory, verbose=False, threshold_bytes=10):
    """
    Worker function that performs the actual assets analysis.
    
    Returns:
        dict: Analysis results
    """
    # Step 1: Find assets directory
    assets_path = find_assets_directory(apktool_output_path, verbose)
    if not assets_path:
        return {
            'total_images_found': 0,
            'total_images_analyzed': 0,
            'suspicious_images_count': 0,
            'analysis_results': [],
            'summary_text': "No assets directory found in decompiled APK.",
            'output_directory': None,
            'status': 'no_assets'
        }
    
    # Step 2: Discover images
    image_files = discover_images_in_assets(assets_path, verbose)
    if not image_files:
        return {
            'total_images_found': 0,
            'total_images_analyzed': 0,
            'suspicious_images_count': 0,
            'analysis_results': [],
            'summary_text': "No image files found in assets directory.",
            'output_directory': None,
            'status': 'no_images'
        }
    
    # Step 3: Create output directory
    output_directory = os.path.join(target_directory, "assets_steganography_analysis")
    os.makedirs(output_directory, exist_ok=True)
    
    # Create subdirectory for suspicious images
    suspicious_images_dir = os.path.join(output_directory, "suspicious_images")
    os.makedirs(suspicious_images_dir, exist_ok=True)
    
    # Step 4: Analyze each image
    analysis_results = analyze_discovered_images(image_files, output_directory, threshold_bytes, verbose)
    
    # Step 4.5: Copy suspicious images to analysis directory
    copy_suspicious_images(analysis_results, suspicious_images_dir, verbose)
    
    # Step 5: Generate summary
    summary_text = generate_assets_summary(analysis_results, output_directory, verbose)
    
    # Count suspicious images
    suspicious_count = sum(1 for result in analysis_results if result.get('is_suspicious', False))
    
    return {
        'total_images_found': len(image_files),
        'total_images_analyzed': len(analysis_results),
        'suspicious_images_count': suspicious_count,
        'analysis_results': analysis_results,
        'summary_text': summary_text,
        'output_directory': output_directory,
        'status': 'completed'
    }


def find_assets_directory(apktool_output_path, verbose=False):
    """
    Locate the assets or res directory within apktool output.
    
    Returns:
        str: Path to assets/res directory, or None if not found
    """
    # Check for assets directory first
    assets_path = os.path.join(apktool_output_path, "assets")
    if os.path.exists(assets_path) and os.path.isdir(assets_path):
        if verbose:
            print(f"[WORKER] Found assets directory: {assets_path}")
        return assets_path
    
    # Check for res directory (common in APK decompilation)
    res_path = os.path.join(apktool_output_path, "res")
    if os.path.exists(res_path) and os.path.isdir(res_path):
        if verbose:
            print(f"[WORKER] Found res directory: {res_path}")
        return res_path
    
    # If input path itself is a directory with images, use it directly
    if os.path.isdir(apktool_output_path):
        # Check if the path itself contains image files
        supported_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}
        has_images = False
        try:
            for file in os.listdir(apktool_output_path):
                if os.path.splitext(file.lower())[1] in supported_extensions:
                    has_images = True
                    break
        except (OSError, PermissionError):
            pass
        
        if has_images:
            if verbose:
                print(f"[WORKER] Using input directory directly: {apktool_output_path}")
            return apktool_output_path
    
    if verbose:
        print(f"[WORKER] No assets, res directory, or images found in: {apktool_output_path}")
    return None


def discover_images_in_assets(assets_path, verbose=False):
    """
    Recursively discover all image files in the assets directory.
    
    Returns:
        list: List of image file paths
    """
    supported_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}
    image_files = []
    
    if verbose:
        print(f"[WORKER] Scanning assets directory for images...")
    
    for root, dirs, files in os.walk(assets_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_extension = Path(file).suffix.lower()
            
            if file_extension in supported_extensions:
                image_files.append(file_path)
                if verbose:
                    relative_path = os.path.relpath(file_path, assets_path)
                    print(f"[WORKER] Found image: assets/{relative_path}")
    
    if verbose:
        print(f"[WORKER] Discovered {len(image_files)} image file(s) in assets directory")
    
    return image_files


def analyze_discovered_images(image_files, output_directory, threshold_bytes, verbose=False):
    """
    Analyze each discovered image using the existing steganography detection.
    
    Returns:
        list: List of analysis results from detect_image_steganography
    """
    analysis_results = []
    failed_analyses = []
    total_images = len(image_files)
    
    if verbose:
        print(f"[WORKER] Analyzing {total_images} image(s) for steganographic content...")
    
    for i, image_path in enumerate(image_files, 1):
        try:
            if verbose:
                print(f"[WORKER] [{i}/{total_images}] Analyzing {os.path.basename(image_path)}")
            
            # Use existing steganography detection
            result = detect_image_steganography(
                image_path, 
                output_directory, 
                verbose, 
                threshold_bytes
            )
            
            if result:
                analysis_results.append(result)
                # Show result summary
                if result.get('is_suspicious'):
                    print(f"[WORKER] 🚨 SUSPICIOUS: {os.path.basename(image_path)} has {result['trailing_bytes']} trailing bytes")
                else:
                    print(f"[WORKER] ✅ Clean: {os.path.basename(image_path)} - {result['trailing_bytes']} trailing bytes")
            else:
                failed_analyses.append(image_path)
                if verbose:
                    print(f"[WORKER] ❌ Failed to analyze: {os.path.basename(image_path)}")
                
        except Exception as e:
            if verbose:
                print(f"[WORKER] ❌ Failed to analyze {os.path.basename(image_path)}: {e}")
            failed_analyses.append(image_path)
    
    if failed_analyses and verbose:
        print(f"[WORKER] ⚠️  {len(failed_analyses)} image(s) failed to analyze")
    
    return analysis_results


def copy_suspicious_images(analysis_results, suspicious_images_dir, verbose=False):
    """
    Copy all suspicious images to the analysis directory for easy access.
    
    Args:
        analysis_results (list): List of analysis results
        suspicious_images_dir (str): Directory to copy suspicious images to
        verbose (bool): Enable verbose output
    """
    suspicious_images = [result for result in analysis_results if result.get('is_suspicious', False)]
    
    if not suspicious_images:
        if verbose:
            print(f"[WORKER] No suspicious images to copy")
        return
    
    if verbose:
        print(f"[WORKER] Copying {len(suspicious_images)} suspicious image(s) to analysis directory...")
    
    for result in suspicious_images:
        try:
            source_path = result.get('image_path')
            if not source_path or not os.path.exists(source_path):
                if verbose:
                    print(f"[WORKER] ⚠️  Source image not found: {source_path}")
                continue
            
            # Create a descriptive filename with trailing bytes info
            original_name = os.path.basename(source_path)
            name_parts = os.path.splitext(original_name)
            trailing_bytes = result.get('trailing_bytes', 0)
            
            # New filename: original_name_SUSPICIOUS_XXXbytes.ext
            new_filename = f"{name_parts[0]}_SUSPICIOUS_{trailing_bytes}bytes{name_parts[1]}"
            dest_path = os.path.join(suspicious_images_dir, new_filename)
            
            # Copy the suspicious image
            shutil.copy2(source_path, dest_path)
            
            if verbose:
                print(f"[WORKER] 📋 Copied suspicious image: {new_filename}")
        
        except Exception as e:
            if verbose:
                print(f"[WORKER] ❌ Failed to copy suspicious image {original_name}: {e}")
    
    print(f"[WORKER] 🚨 {len(suspicious_images)} suspicious image(s) copied to: {suspicious_images_dir}")


def generate_assets_summary(analysis_results, output_directory, verbose=False):
    """
    Generate comprehensive summary using existing parser infrastructure.
    
    Returns:
        str: Human-readable summary text
    """
    if verbose:
        print(f"[WORKER] Generating analysis summary...")
    
    # Use existing combined summary generator
    summary_text = generate_combined_summary(analysis_results, output_directory, verbose)
    
    # Save assets-specific summary
    summary_file = os.path.join(output_directory, "assets_steganography_summary.txt")
    with open(summary_file, 'w') as f:
        f.write("APK ASSETS IMAGE STEGANOGRAPHY ANALYSIS\n")
        f.write("=" * 45 + "\n\n")
        f.write(summary_text)
    
    if verbose:
        print(f"[WORKER] Summary saved to: {summary_file}")
    
    return summary_text


def save_worker_results(results, output_directory, verbose=False):
    """Save worker results to trackable files."""
    analysis_dir = os.path.join(output_directory, "assets_steganography_analysis")
    os.makedirs(analysis_dir, exist_ok=True)
    
    # Create status file for tracking
    status_file = os.path.join(analysis_dir, "analysis_status.json")
    with open(status_file, 'w') as f:
        json.dump({
            'status': results['status'],
            'total_images_found': results['total_images_found'],
            'total_images_analyzed': results['total_images_analyzed'],
            'suspicious_images_count': results['suspicious_images_count'],
            'timestamp': time.time(),
            'output_directory': results['output_directory']
        }, f, indent=2)
    
    if verbose:
        print(f"[WORKER] Results saved to trackable files in: {analysis_dir}")


def save_worker_error(error_msg, output_directory, verbose=False):
    """Save error status for main process tracking."""
    analysis_dir = os.path.join(output_directory, "assets_steganography_analysis")
    os.makedirs(analysis_dir, exist_ok=True)
    
    # Create error status file
    status_file = os.path.join(analysis_dir, "analysis_status.json")
    with open(status_file, 'w') as f:
        json.dump({
            'status': 'error',
            'error_message': error_msg,
            'timestamp': time.time(),
            'total_images_found': 0,
            'total_images_analyzed': 0,
            'suspicious_images_count': 0
        }, f, indent=2)
    
    if verbose:
        print(f"[WORKER] Error status saved to: {analysis_dir}")


if __name__ == "__main__":
    main()
