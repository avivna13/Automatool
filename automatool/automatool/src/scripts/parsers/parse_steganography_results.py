#!/usr/bin/env python3
"""
Steganography Results Parser

This script parses steganography analysis results and generates human-readable summaries.
It follows the same pattern as other parser functions in the parsers/ directory.

Processes results from detect_image_steganography.py and creates simple, actionable summaries.
"""

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
        # Look for analysis results directory
        analysis_dir = os.path.join(results_directory, "steganography_analysis")
        
        if not os.path.exists(analysis_dir):
            if verbose:
                print("[DEBUG] No steganography analysis directory found")
            return "No steganography analysis results found."
        
        # Look for suspicious image reports
        suspicious_reports = []
        for file in os.listdir(analysis_dir):
            if file == "suspicious_image_report.txt":
                report_path = os.path.join(analysis_dir, file)
                suspicious_reports.append(report_path)
        
        if verbose:
            print(f"[DEBUG] Found {len(suspicious_reports)} suspicious image report(s)")
        
        # Generate summary based on findings
        if suspicious_reports:
            summary = _generate_suspicious_summary(suspicious_reports, verbose)
        else:
            summary = _generate_clean_summary(analysis_dir, verbose)
        
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


def _generate_suspicious_summary(suspicious_reports, verbose=False):
    """
    Generate summary when suspicious images are found.
    
    Args:
        suspicious_reports (list): List of paths to suspicious image reports
        verbose (bool): Enable verbose output
        
    Returns:
        str: Formatted summary text
    """
    summary_lines = []
    summary_lines.append("STEGANOGRAPHY ANALYSIS SUMMARY")
    summary_lines.append("=" * 35)
    summary_lines.append("")
    summary_lines.append("*** SUSPICIOUS ACTIVITY DETECTED! ***")
    summary_lines.append("")
    
    # Process each suspicious report
    for i, report_path in enumerate(suspicious_reports, 1):
        if verbose:
            print(f"[DEBUG] Processing suspicious report: {report_path}")
        
        try:
            with open(report_path, 'r') as f:
                report_content = f.read()
            
            # Extract key information from the report
            report_info = _extract_report_info(report_content)
            
            summary_lines.append(f"Suspicious Image #{i}:")
            summary_lines.append(f"  File: {report_info.get('filename', 'Unknown')}")
            summary_lines.append(f"  Format: {report_info.get('format', 'Unknown')}")
            summary_lines.append(f"  Trailing Data: {report_info.get('trailing_bytes', 'Unknown')} bytes")
            summary_lines.append(f"  Threshold: {report_info.get('threshold', 'Unknown')} bytes")
            summary_lines.append("")
            
        except Exception as e:
            if verbose:
                print(f"[DEBUG] Error processing report {report_path}: {e}")
            summary_lines.append(f"Suspicious Image #{i}: Error reading report")
            summary_lines.append("")
    
    summary_lines.append("WARNING: IMMEDIATE ACTION REQUIRED!")
    summary_lines.append("   These images contain suspicious trailing data")
    summary_lines.append("   Manual investigation is recommended")
    summary_lines.append("   Check individual reports for detailed findings")
    
    return "\n".join(summary_lines)


def _generate_clean_summary(analysis_dir, verbose=False):
    """
    Generate summary when no suspicious images are found.
    
    Args:
        analysis_dir (str): Path to analysis directory
        verbose (bool): Enable verbose output
        
    Returns:
        str: Formatted summary text
    """
    summary_lines = []
    summary_lines.append("STEGANOGRAPHY ANALYSIS SUMMARY")
    summary_lines.append("=" * 35)
    summary_lines.append("")
    summary_lines.append("*** NO SUSPICIOUS ACTIVITY DETECTED ***")
    summary_lines.append("")
    summary_lines.append("All analyzed images appear clean.")
    summary_lines.append("No trailing data exceeding the threshold was found.")
    summary_lines.append("")
    summary_lines.append("Images appear to contain only legitimate image data.")
    
    if verbose:
        print("[DEBUG] Generated clean summary - no suspicious images found")
    
    return "\n".join(summary_lines)


def _extract_report_info(report_content):
    """
    Extract key information from a suspicious image report.
    
    Args:
        report_content (str): Content of the suspicious image report
        
    Returns:
        dict: Extracted information (filename, format, trailing_bytes, threshold)
    """
    info = {}
    
    try:
        lines = report_content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if line.startswith("Image File:"):
                info['filename'] = line.split(":", 1)[1].strip()
            elif line.startswith("Format:"):
                info['format'] = line.split(":", 1)[1].strip()
            elif line.startswith("Trailing Data Size:"):
                # Extract number from "Trailing Data Size: 2048 bytes"
                parts = line.split(":")
                if len(parts) > 1:
                    trailing_part = parts[1].strip()
                    # Extract just the number
                    trailing_bytes = trailing_part.split()[0]
                    info['trailing_bytes'] = trailing_bytes
            elif line.startswith("Threshold:"):
                # Extract number from "Threshold: 10 bytes"
                parts = line.split(":")
                if len(parts) > 1:
                    threshold_part = parts[1].strip()
                    # Extract just the number
                    threshold_bytes = threshold_part.split()[0]
                    info['threshold'] = threshold_bytes
    
    except Exception:
        # If parsing fails, return empty dict - calling function will handle gracefully
        pass
    
    return info


def generate_combined_summary(results_list, output_dir, verbose=False):
    """
    Generate a combined summary of multiple steganography analysis results.
    
    This function is used when analyzing multiple images in a directory.
    
    Args:
        results_list (list): List of analysis result dictionaries
        output_dir (str): Directory to save the combined summary
        verbose (bool): Enable verbose output
        
    Returns:
        str: Combined summary text
    """
    if verbose:
        print(f"[DEBUG] Generating combined summary for {len(results_list)} results")
    
    summary_lines = []
    summary_lines.append("COMBINED STEGANOGRAPHY ANALYSIS RESULTS")
    summary_lines.append("=" * 45)
    summary_lines.append("")
    
    # Count totals
    total_images = len(results_list)
    suspicious_images = sum(1 for r in results_list if r.get('is_suspicious', False))
    
    summary_lines.append(f"Total images analyzed: {total_images}")
    summary_lines.append(f"Suspicious images found: {suspicious_images}")
    summary_lines.append("")
    
    if suspicious_images > 0:
        summary_lines.append("*** SUSPICIOUS IMAGES DETECTED: ***")
        
        for result in results_list:
            if result.get('is_suspicious', False):
                image_name = os.path.basename(result.get('image_path', 'Unknown'))
                trailing_bytes = result.get('trailing_bytes', 'Unknown')
                image_format = result.get('image_format', 'Unknown')
                summary_lines.append(f"  - {image_name}: {trailing_bytes} bytes ({image_format})")
        
        summary_lines.append("")
        summary_lines.append("WARNING: IMMEDIATE ACTION REQUIRED!")
        summary_lines.append("   These images contain suspicious trailing data")
        summary_lines.append("   Check individual analysis reports for detailed findings")
        
    else:
        summary_lines.append("*** ALL IMAGES APPEAR CLEAN ***")
        summary_lines.append("   No suspicious trailing data detected in any analyzed images")
    
    # Save combined summary
    summary_text = "\n".join(summary_lines)
    summary_file = os.path.join(output_dir, "steganography_combined_summary.txt")
    
    try:
        with open(summary_file, 'w') as f:
            f.write(summary_text)
        
        if verbose:
            print(f"[DEBUG] Generated combined summary: {summary_file}")
    
    except Exception as e:
        if verbose:
            print(f"[DEBUG] Error writing combined summary: {e}")
    
    return summary_text
