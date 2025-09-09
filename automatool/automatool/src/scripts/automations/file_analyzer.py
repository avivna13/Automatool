"""
File Analyzer for APK Unmask Enhancement

This module provides file type analysis capabilities for suspicious files
found in APK packages by the apk_unmask tool using apktool decompiled output.
"""

import os
import subprocess
import logging
from typing import Dict, List, Optional


import glob

class FileAnalyzer:
    """Handles file type analysis for suspicious files using apktool decompiled output."""
    
    def __init__(self, apktool_output_dir: str, verbose: bool = False):
        """
        Initialize file analyzer with apktool decompiled output directory.
        
        Args:
            apktool_output_dir: Path to the apktool decompiled output directory
            verbose: Enable verbose output
        """
        self.apktool_output_dir = apktool_output_dir
        self.verbose = verbose
        self.logger = logging.getLogger(__name__)
        
        if verbose:
            print(f"🔬 FileAnalyzer initialized for apktool output: {apktool_output_dir}")
        
        # Verify the apktool output directory exists
        if not os.path.exists(apktool_output_dir):
            if verbose:
                print(f"⚠️  Apktool output directory not found: {apktool_output_dir}")
            self.logger.warning(f"Apktool output directory not found: {apktool_output_dir}")
    
    def build_file_path(self, apk_file_path: str) -> str:
        """
        Build the actual file system path from APK file path using apktool output.
        
        Args:
            apk_file_path: Path within APK (e.g., 'assets/config.xml')
            
        Returns:
            Actual file system path to the decompiled file
        """
        # Search for the file in the apktool_output_dir
        search_pattern = os.path.join(self.apktool_output_dir, "**", apk_file_path)
        if self.verbose:
            print(f"🔍 Searching for file with pattern: {search_pattern}")
        
        results = glob.glob(search_pattern, recursive=True)
        
        if results:
            if self.verbose:
                print(f"📁 Found file at: {results[0]}")
            return results[0]
        
        # If the file is not found, return the original path and let the analysis fail
        if self.verbose:
            print(f"⚠️  File not found in apktool output: {apk_file_path}")
        return os.path.join(self.apktool_output_dir, apk_file_path)
    
    def analyze_file_type(self, file_path: str) -> Dict[str, str]:
        """
        Run 'file' command on extracted file and return type information.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary with file analysis results
        """
        if not os.path.exists(file_path):
            return {
                'file_path': file_path,
                'file_type': 'File not found',
                'mime_info': 'unknown',
                'analysis_success': False,
                'error': 'File does not exist'
            }
        
        try:
            # Run file command with comprehensive options
            result = subprocess.run(
                ['file', '-b', '--mime-type', '--mime-encoding', file_path],
                capture_output=True, text=True, check=True, timeout=10
            )
            
            # Get human-readable description
            desc_result = subprocess.run(
                ['file', '-b', file_path],
                capture_output=True, text=True, check=True, timeout=10
            )
            
            if self.verbose:
                print(f"🔍 File analysis: {os.path.basename(file_path)} → {desc_result.stdout.strip()}")
            
            return {
                'file_path': file_path,
                'file_type': desc_result.stdout.strip(),
                'mime_info': result.stdout.strip(),
                'analysis_success': True
            }
            
        except subprocess.CalledProcessError as e:
            error_msg = f"File command failed: {e}"
            if self.verbose:
                print(f"❌ {error_msg}")
            
            return {
                'file_path': file_path,
                'file_type': 'Analysis failed',
                'mime_info': f'Error: {e}',
                'analysis_success': False,
                'error': error_msg
            }
        
        except subprocess.TimeoutExpired:
            error_msg = "File command timed out"
            if self.verbose:
                print(f"⏰ {error_msg}")
            
            return {
                'file_path': file_path,
                'file_type': 'Analysis timed out',
                'mime_info': 'timeout',
                'analysis_success': False,
                'error': error_msg
            }
        
        except FileNotFoundError:
            error_msg = "'file' command not found. Please install file utility."
            if self.verbose:
                print(f"❌ {error_msg}")
            
            return {
                'file_path': file_path,
                'file_type': 'File utility not available',
                'mime_info': 'unavailable',
                'analysis_success': False,
                'error': error_msg
            }
    
    def analyze_multiple_files(self, apk_file_paths: List[str]) -> Dict[str, Dict[str, str]]:
        """
        Analyze multiple files and return consolidated results.
        
        Args:
            apk_file_paths: List of file paths within the APK to analyze
            
        Returns:
            Dictionary mapping APK file paths to their analysis results
        """
        results = {}
        
        if self.verbose:
            print(f"🔬 Starting analysis of {len(apk_file_paths)} files...")
        
        for apk_file_path in apk_file_paths:
            if self.verbose:
                print(f"📋 Analyzing: {apk_file_path}")
            
            # Build the actual file system path
            actual_path = self.build_file_path(apk_file_path)
            
            # Analyze the file directly from apktool output
            analysis_result = self.analyze_file_type(actual_path)
            
            # Store with original APK path as key
            results[apk_file_path] = analysis_result
        
        if self.verbose:
            successful = sum(1 for r in results.values() if r.get('analysis_success', False))
            print(f"✅ Analysis complete: {successful}/{len(apk_file_paths)} files analyzed successfully")
        
        return results
    
    def analyze_single_file(self, apk_file_path: str) -> Dict[str, str]:
        """
        Analyze a single file and return results.
        
        Args:
            apk_file_path: File path within the APK to analyze
            
        Returns:
            Dictionary with analysis results
        """
        if self.verbose:
            print(f"📋 Analyzing single file: {apk_file_path}")
        
        # Build the actual file system path
        actual_path = self.build_file_path(apk_file_path)
        
        # Analyze the file directly from apktool output
        return self.analyze_file_type(actual_path)


def is_file_command_available() -> bool:
    """
    Check if the 'file' command is available on the system.
    
    Returns:
        True if file command is available, False otherwise
    """
    try:
        subprocess.run(['file', '--version'], 
                      capture_output=True, check=True, timeout=5)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


def get_file_command_info() -> Dict[str, str]:
    """
    Get information about the file command installation.
    
    Returns:
        Dictionary with file command information
    """
    try:
        result = subprocess.run(['file', '--version'], 
                              capture_output=True, text=True, check=True, timeout=5)
        return {
            'available': True,
            'version': result.stdout.strip(),
            'error': None
        }
    except FileNotFoundError:
        return {
            'available': False,
            'version': None,
            'error': "'file' command not found. Install with: apt-get install file (Linux) or brew install file (macOS)"
        }
    except subprocess.CalledProcessError as e:
        return {
            'available': False,
            'version': None,
            'error': f"'file' command error: {e}"
        }
    except subprocess.TimeoutExpired:
        return {
            'available': False,
            'version': None,
            'error': "'file' command timed out"
        }
