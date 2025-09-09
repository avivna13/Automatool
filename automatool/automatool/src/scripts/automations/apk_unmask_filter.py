"""
APK Unmask False Positive Filter

This module provides filtering capabilities for apk_unmask output to remove
known false positive detections based on regex patterns.
"""

import os
import re
import logging
from typing import List, Dict, Optional, Tuple


class ApkUnmaskFilter:
    """Handles false positive filtering for apk_unmask output."""
    
    def __init__(self, verbose: bool = False):
        """Initialize the filter with default ignore list from utils directory."""
        self.verbose = verbose
        self.ignore_patterns = []
        self.logger = logging.getLogger(__name__)
        
        # Load ignore list automatically
        self.load_ignore_list()
    
    def _get_ignore_list_path(self) -> str:
        """Get the path to the ignore list file in utils directory."""
        # Get the directory containing this script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        # Navigate to utils directory
        utils_dir = os.path.join(script_dir, '..', 'utils')
        ignore_list_path = os.path.join(utils_dir, 'apk_unmask_ignore_list.txt')
        return os.path.abspath(ignore_list_path)
    
    def load_ignore_list(self) -> None:
        """Load and parse ignore list file from utils directory."""
        ignore_list_path = self._get_ignore_list_path()
        
        if not os.path.exists(ignore_list_path):
            if self.verbose:
                print(f"[INFO] Ignore list file not found at {ignore_list_path}")
            self.logger.info(f"Ignore list file not found at {ignore_list_path}")
            return
        
        try:
            with open(ignore_list_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Parse ignore entry
                parsed_entry = self.parse_ignore_entry(line)
                if parsed_entry:
                    self.ignore_patterns.append(parsed_entry)
                else:
                    if self.verbose:
                        print(f"[WARNING] Invalid ignore list entry at line {line_num}: {line}")
                    self.logger.warning(f"Invalid ignore list entry at line {line_num}: {line}")
            
            if self.verbose:
                print(f"[INFO] Loaded {len(self.ignore_patterns)} ignore patterns from {ignore_list_path}")
            self.logger.info(f"Loaded {len(self.ignore_patterns)} ignore patterns")
            
        except Exception as e:
            if self.verbose:
                print(f"[ERROR] Failed to load ignore list: {e}")
            self.logger.error(f"Failed to load ignore list: {e}")
    
    def parse_ignore_entry(self, line: str) -> Optional[Dict[str, str]]:
        """
        Parse a single ignore list entry.
        
        Args:
            line: Line in format "regex_pattern:reason_code:comment"
            
        Returns:
            Dict with parsed entry or None if invalid
        """
        parts = line.split(':', 2)  # Split into max 3 parts
        
        if len(parts) < 2:
            return None
        
        regex_pattern = parts[0].strip()
        reason_code = parts[1].strip()
        comment = parts[2].strip() if len(parts) > 2 else ""
        
        # Validate regex pattern
        try:
            re.compile(regex_pattern)
        except re.error as e:
            if self.verbose:
                print(f"[ERROR] Invalid regex pattern '{regex_pattern}': {e}")
            self.logger.error(f"Invalid regex pattern '{regex_pattern}': {e}")
            return None
        
        return {
            'pattern': regex_pattern,
            'reason': reason_code,
            'comment': comment,
            'compiled_regex': re.compile(regex_pattern)
        }
    
    def should_ignore(self, file_path: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a file should be ignored based on regex patterns.
        
        Args:
            file_path: File path to check against ignore patterns
            
        Returns:
            Tuple of (should_ignore, reason) where reason is the reason code if ignored
        """
        for pattern_entry in self.ignore_patterns:
            if pattern_entry['compiled_regex'].match(file_path):
                if self.verbose:
                    print(f"[DEBUG] Ignoring file '{file_path}' - matches pattern '{pattern_entry['pattern']}' ({pattern_entry['reason']})")
                return True, pattern_entry['reason']
        
        return False, None
    
    def extract_file_paths(self, apk_unmask_output: str) -> List[str]:
        """
        Extract file paths from apk_unmask output.
        
        Args:
            apk_unmask_output: Raw output from apk_unmask tool
            
        Returns:
            List of file paths found in the output
        """
        file_paths = []
        lines = apk_unmask_output.split('\n')
        
        for line in lines:
            line = line.strip()
            # Look for lines that start with "-> " which indicate detected files
            if line.startswith('-> '):
                # Extract file path (remove the "-> " prefix)
                file_path = line[3:].strip()
                file_paths.append(file_path)
        
        return file_paths
    
    def filter_output(self, raw_output: str) -> str:
        """
        Filter apk_unmask output and return same format with filtered items removed.
        
        Args:
            raw_output: Raw output from apk_unmask tool
            
        Returns:
            Filtered output in the same format as original
        """
        if not self.ignore_patterns:
            if self.verbose:
                print("[INFO] No ignore patterns loaded, returning original output")
            return raw_output
        
        lines = raw_output.split('\n')
        filtered_lines = []
        current_file_block = []
        files_filtered = 0
        total_files = 0
        
        i = 0
        while i < len(lines):
            line = lines[i]
            
            # Check if this is a file detection line
            if line.strip().startswith('-> '):
                total_files += 1
                file_path = line.strip()[3:].strip()
                
                # Collect the entire block for this file (including reason lines)
                current_file_block = [line]
                i += 1
                
                # Collect all subsequent lines that are part of this file's description
                while i < len(lines) and lines[i].strip().startswith('└─'):
                    current_file_block.append(lines[i])
                    i += 1
                
                # Check if this file should be ignored
                should_ignore, reason = self.should_ignore(file_path)
                
                if should_ignore:
                    files_filtered += 1
                    if self.verbose:
                        print(f"[DEBUG] Filtered out: {file_path} (reason: {reason})")
                    # Skip this entire file block
                    continue
                else:
                    # Keep this file block
                    filtered_lines.extend(current_file_block)
                    continue
            else:
                # Keep non-file lines (headers, total count, etc.)
                filtered_lines.append(line)
                i += 1
        
        # Update the total count in the output
        filtered_output = '\n'.join(filtered_lines)
        remaining_files = total_files - files_filtered
        
        # Update the total count line
        filtered_output = re.sub(
            r'\[*\] Total: \d+',
            f'[*] Total: {remaining_files}',
            filtered_output
        )
        
        if self.verbose:
            print(f"[INFO] Filtered {files_filtered} files out of {total_files} total")
            print(f"[INFO] Remaining suspicious files: {remaining_files}")
        
        return filtered_output


class ApkUnmaskParser:
    """Parses apk_unmask output into structured data."""
    
    def __init__(self):
        """Initialize the parser."""
        pass
    
    def parse_output(self, raw_output: str) -> Dict:
        """
        Parse raw apk_unmask output into structured format.
        
        Args:
            raw_output: Raw output from apk_unmask tool
            
        Returns:
            Structured data with file entries and metadata
        """
        lines = raw_output.split('\n')
        file_entries = []
        total_count = 0
        
        current_file = None
        
        for line in lines:
            line_stripped = line.strip()
            
            # Extract total count
            if line_stripped.startswith('[*] Total:'):
                try:
                    total_count = int(line_stripped.split(':')[1].strip())
                except (ValueError, IndexError):
                    total_count = 0
            
            # Detect file entry
            elif line_stripped.startswith('-> '):
                if current_file:
                    file_entries.append(current_file)
                
                file_path = line_stripped[3:].strip()
                current_file = {
                    'path': file_path,
                    'reasons': []
                }
            
            # Detect reason lines
            elif line_stripped.startswith('└─') and current_file:
                reason = line_stripped[2:].strip()
                current_file['reasons'].append(reason)
        
        # Don't forget the last file
        if current_file:
            file_entries.append(current_file)
        
        return {
            'total_count': total_count,
            'file_entries': file_entries,
            'raw_output': raw_output
        }
    
    def extract_file_entries(self, output_lines: List[str]) -> List[Dict]:
        """
        Extract individual file entries with their reasons.
        
        Args:
            output_lines: List of output lines
            
        Returns:
            List of file entry dictionaries
        """
        entries = []
        current_entry = None
        
        for line in output_lines:
            line_stripped = line.strip()
            
            if line_stripped.startswith('-> '):
                # Save previous entry
                if current_entry:
                    entries.append(current_entry)
                
                # Start new entry
                file_path = line_stripped[3:].strip()
                current_entry = {
                    'path': file_path,
                    'reasons': []
                }
            
            elif line_stripped.startswith('└─') and current_entry:
                reason = line_stripped[2:].strip()
                current_entry['reasons'].append(reason)
        
        # Add last entry
        if current_entry:
            entries.append(current_entry)
        
        return entries
    
    def format_filtered_output(self, filtered_entries: List[Dict]) -> str:
        """
        Format filtered entries back to apk_unmask output format.
        
        Args:
            filtered_entries: List of file entry dictionaries
            
        Returns:
            Formatted output string
        """
        if not filtered_entries:
            return "[*] Total: 0\n"
        
        lines = ["[!] Detected potentially malicious files:"]
        
        for entry in filtered_entries:
            lines.append(f"\t-> {entry['path']}")
            for reason in entry['reasons']:
                lines.append(f"\t   └─ {reason}")
        
        lines.append(f"[*] Total: {len(filtered_entries)}")
        
        return '\n'.join(lines)
    
    def generate_enhanced_output(self, filtered_output: str, file_analysis_results: Dict) -> str:
        """
        Generate enhanced output with file type information.
        
        Args:
            filtered_output: Filtered apk_unmask output
            file_analysis_results: Dictionary of file analysis results
            
        Returns:
            Enhanced output string with file type information
        """
        if not file_analysis_results:
            return filtered_output
        
        lines = filtered_output.split('\n')
        enhanced_lines = []
        
        i = 0
        while i < len(lines):
            line = lines[i]
            enhanced_lines.append(line)
            
            # Check if this is a file detection line
            if line.strip().startswith('-> '):
                file_path = line.strip()[3:].strip()
                
                # Add all the original reason lines
                i += 1
                while i < len(lines) and lines[i].strip().startswith('└─'):
                    enhanced_lines.append(lines[i])
                    i += 1
                
                # Add file type information if available
                if file_path in file_analysis_results:
                    analysis = file_analysis_results[file_path]
                    if analysis.get('analysis_success', False):
                        file_type = analysis.get('file_type', 'Unknown')
                        enhanced_lines.append(f"\t   └─ File Type: {file_type}")
                    else:
                        error = analysis.get('error', 'Analysis failed')
                        enhanced_lines.append(f"\t   └─ File Type: Analysis failed ({error})")
                
                continue
            else:
                i += 1
        
        return '\n'.join(enhanced_lines)
