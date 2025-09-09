import os
import json
from pathlib import Path
from datetime import datetime
import sys

# Import the existing base64-detector package
base64_detector_path = os.path.join(os.path.dirname(__file__), 'base64-detector')
sys.path.insert(0, base64_detector_path)

# Import the analyze_base64 function from the base64-detector script
try:
    from base_64_detector_script import analyze_base64
except ImportError:
    # Fallback: try to import with different naming
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "base64_detector", 
        os.path.join(base64_detector_path, "base-64-detector-script.py")
    )
    base64_detector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base64_detector)
    analyze_base64 = base64_detector.analyze_base64

class Base64Scanner:
    """
    Professional base64 string scanner for decompiled APK directories.
    Uses the existing base64-detector package for accurate detection.
    """
    
    def __init__(self, min_string_length=20, min_decoded_size=100, max_strings_per_file=1000):
        """
        Initialize the Base64Scanner with configurable thresholds.
        
        Args:
            min_string_length (int): Minimum base64 string length to consider (default: 20)
            min_decoded_size (int): Minimum decoded size in bytes to consider (default: 100)
            max_strings_per_file (int): Maximum strings to analyze per file (default: 1000)
        """
        self.results = []
        self.scan_metadata = {}
        self.min_string_length = min_string_length
        self.min_decoded_size = min_decoded_size
        self.max_strings_per_file = max_strings_per_file
        
    def scan_decompiled_apk_directory(self, directory_path):
        """
        Scan decompiled APK directory for base64 strings
        
        Args:
            directory_path (str): Path to decompiled APK directory
            
        Returns:
            dict: Comprehensive scan results with metadata
            
        Raises:
            FileNotFoundError: If directory doesn't exist
            PermissionError: If directory access is denied
        """
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        if not os.access(directory_path, os.R_OK):
            raise PermissionError(f"Access denied to directory: {directory_path}")
        
        # Initialize scan metadata
        self.scan_metadata = {
            'scan_timestamp': datetime.now().isoformat(),
            'directory_path': directory_path,
            'total_files_scanned': 0,
            'total_strings_found': 0
        }
        
        # Find all Java files
        java_files = self.find_java_files(directory_path)
        self.scan_metadata['total_files_scanned'] = len(java_files)
        
        # Scan each Java file
        for java_file in java_files:
            file_results = self.scan_java_file(java_file)
            if file_results:
                self.results.append(file_results)
                self.scan_metadata['total_strings_found'] += file_results.get('strings_detected', 0)
        
        return self.generate_report()
    
    def find_java_files(self, directory_path):
        """
        Recursively find all Java files in directory and subdirectories.
        Optimized for Jadx output structure (looks in sources/ subdirectory first).
        If sources/ not found, recursively searches the entire decompiled APK.
        
        Args:
            directory_path (str): Root directory to search (Jadx output directory)
            
        Returns:
            list: List of Path objects for all Java files found
        """
        java_files = []
        
        try:
            # First check if this is a Jadx output directory with sources/ subdirectory
            sources_path = os.path.join(directory_path, 'sources')
            if os.path.exists(sources_path):
                # Jadx puts Java files in sources/ subdirectory
                print(f"🔍 Found Jadx sources directory: {sources_path}")
                search_path = sources_path
            else:
                # No sources/ directory found, search the entire decompiled APK recursively
                print(f"🔍 No sources/ directory found, searching entire decompiled APK: {directory_path}")
                search_path = directory_path
            
            # Recursively walk through the search path to find all Java files
            for root, dirs, files in os.walk(search_path):
                for file in files:
                    if file.endswith('.java'):
                        file_path = Path(root) / file
                        java_files.append(file_path)
                        
            print(f"📝 Found {len(java_files)} Java files in {search_path}")
                        
        except Exception as e:
            print(f"Error discovering Java files: {e}")
        
        return java_files
    
    def scan_java_file(self, file_path):
        """
        Scan individual Java file using enhanced base64-detector package
        
        Args:
            file_path (Path): Path to Java file to scan
            
        Returns:
            dict or None: File scan results if base64 strings found, None otherwise
        """
        try:
            # Use the enhanced base64-detector package for professional detection
            analysis_result = analyze_base64(str(file_path))
            
            # Check if base64 strings were found
            if analysis_result.get('has_any_base64', False):
                # The enhanced analyze_base64 now provides all the information we need
                return {
                    'file_path': str(file_path),
                    'strings_detected': analysis_result.get('strings_detected', 0),
                    'longest_string': analysis_result.get('longest_string', ''),
                    'longest_string_decoded': analysis_result.get('longest_string_decoded', ''),
                    'analysis_summary': analysis_result,
                    'scan_timestamp': datetime.now().isoformat()
                }
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
        
        return None
    

    
    def generate_report(self, output_directory=None, save_to_files=True):
        """
        Generate formatted results and optionally save to files
        
        Args:
            output_directory (str, optional): Directory to save output files
            save_to_files (bool): Whether to save results to files (default: True)
            
        Returns:
            dict: Structured report with scan results and metadata
        """
        report = {
            'scan_metadata': self.scan_metadata,
            'files_with_strings': self.results,
            'summary': {
                'total_files_scanned': self.scan_metadata['total_files_scanned'],
                'total_strings_found': self.scan_metadata['total_strings_found'],
                'files_with_strings_count': len(self.results)
            }
        }
        
        # Save results to files if requested and output directory provided
        if save_to_files and output_directory:
            self._save_results_to_files(report, output_directory)
        
        return report
    
    def _save_results_to_files(self, report, output_directory):
        """
        Save scan results to files in the output directory
        
        Args:
            report (dict): The scan report to save
            output_directory (str): Directory to save files
        """
        try:
            import json
            from datetime import datetime
            
            # Generate timestamp for filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Create results filename
            results_filename = f"base64_scan_results_{timestamp}.json"
            results_filepath = os.path.join(output_directory, results_filename)
            
            # Save JSON results to file
            with open(results_filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            # Create human-readable summary file
            summary_filename = f"base64_scan_summary_{timestamp}.txt"
            summary_filepath = os.path.join(output_directory, summary_filename)
            
            with open(summary_filepath, 'w', encoding='utf-8') as f:
                f.write(f"Base64 String Detection Results\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Directory Scanned: {self.scan_metadata['directory_path']}\n")
                f.write(f"=" * 60 + "\n\n")
                
                # Filter files to only show those with has_large_blob=True
                files_with_large_blob = [
                    file_result for file_result in report.get('files_with_strings', [])
                    if file_result.get('analysis_summary', {}).get('has_large_blob', False)
                ]
                
                if files_with_large_blob:
                    f.write(f"SCAN SUMMARY (Large Blob Files Only):\n")
                    f.write(f"  Files Scanned: {report['summary']['total_files_scanned']}\n")
                    f.write(f"  Total Strings Found: {report['summary']['total_strings_found']}\n")
                    f.write(f"  Files with Large Blobs: {len(files_with_large_blob)}\n\n")
                    
                    f.write(f"DETAILED RESULTS (Large Blob Files):\n")
                    for file_result in files_with_large_blob:
                        f.write(f"\n📁 File: {file_result['file_path']}\n")
                        f.write(f"   Strings Detected: {file_result.get('strings_detected', 0)}\n")
                        
                        # Display longest string information
                        if file_result.get('longest_string'):
                            f.write(f"\n   Longest String:\n")
                            f.write(f"     Length: {len(file_result['longest_string'])} characters\n")
                            f.write(f"     Preview: {file_result['longest_string'][:100]}{'...' if len(file_result['longest_string']) > 100 else ''}\n")
                            
                            # Display decoded content
                            decoded_content = file_result.get('longest_string_decoded', '')
                            if decoded_content.startswith('Decoding error:'):
                                f.write(f"     ❌ Decoding Error: {decoded_content}\n")
                            elif len(decoded_content) > 200:
                                f.write(f"     📄 Decoded Content (truncated): {decoded_content[:200]}...\n")
                            else:
                                f.write(f"     📄 Decoded Content: {decoded_content}\n")
                        
                        # Display analysis summary flags
                        analysis_summary = file_result.get('analysis_summary', {})
                        if analysis_summary.get('has_large_blob'):
                            f.write(f"     ⚠️  Large blob detected (potential binary data)\n")
                        if analysis_summary.get('has_lots_of_strings'):
                            f.write(f"     📊 Many strings found (high activity)\n")
                elif report.get('files_with_strings'):
                    f.write("No files with large blobs found in scanned files.\n")
                else:
                    f.write("No base64 strings found in scanned files.\n")
            
            # Add file paths to the report for reference
            report['output_files'] = {
                'json_results': results_filename,
                'text_summary': summary_filename
            }
            
            print(f"✅ Base64 scan results saved to:")
            print(f"   • {results_filename}")
            print(f"   • {summary_filename}")
            
        except Exception as e:
            print(f"❌ Error saving results to files: {e}")
            # Don't fail the entire operation if file saving fails
