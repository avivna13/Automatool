import argparse
import json
import sys
from pathlib import Path
import subprocess
import os

# Import our new Base64Scanner
from base64_scanner import Base64Scanner

def find_base64_strings_in_directory(directory_path, min_string_length=20, min_decoded_size=100, max_strings_per_file=1000):
    """
    Scans a decompiled APK directory for hardcoded Base64-encoded strings.
    
    Args:
        directory_path (str): Path to decompiled APK directory
        min_string_length (int): Minimum base64 string length to consider
        min_decoded_size (int): Minimum decoded size in bytes to consider
        max_strings_per_file (int): Maximum strings to analyze per file
        
    Returns:
        dict: Comprehensive scan results with metadata
    """
    try:
        # Initialize scanner with custom thresholds
        scanner = Base64Scanner(
            min_string_length=min_string_length,
            min_decoded_size=min_decoded_size,
            max_strings_per_file=max_strings_per_file
        )
        
        # Perform scan
        results = scanner.scan_decompiled_apk_directory(directory_path)
        
        return results
        
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def run_jni_extraction(apk_path, output_dir, project_root):
    """
    Runs the JNI extraction script.
    """
    try:
        python_executable = project_root / '.venv' / 'bin' / 'python'
        jni_script_path = project_root / 'automatool' / 'automatool' / 'src' / 'jni_helper' / 'extract_jni.py'
        output_file = output_dir / 'native-lib' / 'jni_results.json'

        output_file.parent.mkdir(parents=True, exist_ok=True)

        print(f"🔩 Running JNI extraction for: {apk_path}")
        command = [
            str(python_executable),
            str(jni_script_path),
            apk_path,
            '-o',
            str(output_file)
        ]
        
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"✅ JNI extraction successful. Results saved to {output_file}")
        else:
            print(f"❌ JNI extraction failed with return code {result.returncode}:")
            print(result.stderr)

    except FileNotFoundError:
        print(f"❌ Error: Python executable or JNI script not found. Make sure paths are correct.")
        print(f"   - Python: {python_executable}")
        print(f"   - JNI Script: {jni_script_path}")
    except subprocess.CalledProcessError as e:
        print(f"❌ An error occurred during JNI extraction:")
        print(e.stderr)
    except Exception as e:
        print(f"❌ An unexpected error occurred during JNI extraction: {e}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Scan decompiled APK directory for hardcoded base64 strings and optionally extract JNI information."
    )
    parser.add_argument(
        'directory_path', 
        type=str, 
        help='Path to decompiled APK directory'
    )
    parser.add_argument(
        '--apk-path',
        type=str,
        help='Path to the original APK file to run JNI extraction.'
    )
    parser.add_argument(
        '--output', 
        '-o', 
        type=str, 
        help='Output JSON file path for base64 scan (optional)'
    )
    parser.add_argument(
        '--verbose', 
        '-v', 
        action='store_true', 
        help='Enable verbose output'
    )
    parser.add_argument(
        '--min-length',
        type=int,
        default=20,
        help='Minimum base64 string length to consider (default: 20)'
    )
    parser.add_argument(
        '--min-size',
        type=int,
        default=100,
        help='Minimum decoded size in bytes to consider (default: 100)'
    )
    parser.add_argument(
        '--max-strings',
        type=int,
        default=1000,
        help='Maximum strings to analyze per file (default: 1000)'
    )
    
    args = parser.parse_args()
    
    # Determine project root. Assuming this script is in automatool/automatool/src/scripts/automations
    project_root = Path(__file__).resolve().parents[4]

    if args.apk_path:
        run_jni_extraction(args.apk_path, Path(args.directory_path), project_root)

    try:
        if args.verbose:
            print(f"🔍 Scanning directory for Base64 strings: {args.directory_path}")
        
        # Perform scan with custom thresholds
        results = find_base64_strings_in_directory(
            args.directory_path,
            min_string_length=args.min_length,
            min_decoded_size=args.min_size,
            max_strings_per_file=args.max_strings
        )
        
        if results is None:
            print("❌ Base64 scan failed")
            sys.exit(1)
        
        # Generate report with file output
        scanner = Base64Scanner(
            min_string_length=args.min_length,
            min_decoded_size=args.min_size,
            max_strings_per_file=args.max_strings
        )
        scanner.results = results['files_with_strings']
        scanner.scan_metadata = results['scan_metadata']
        
        # Save results to files in the scanned directory
        report = scanner.generate_report(
            output_directory=args.directory_path, 
            save_to_files=True
        )
        
        # Output summary
        summary = report['summary']
        print(f"✅ Base64 scan completed successfully!")
        print(f"📊 Scan Summary:")
        print(f"   • Files Scanned: {summary['total_files_scanned']}")
        print(f"   • Strings Found: {summary['total_strings_found']}")
        print(f"   • Files with Strings: {summary['files_with_strings_count']}")
        
        if 'output_files' in report:
            output_files = report['output_files']
            print(f"\n📁 Base64 results saved to:")
            print(f"   • {output_files['json_results']}")
            print(f"   • {output_files['text_summary']}")
            print(f"\nCheck the directory '{args.directory_path}' for detailed results.")
        
        # Also save to custom output file if specified
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n📄 Custom output also saved to: {args.output}")
            
    except Exception as e:
        print(f"❌ Error during Base64 scan: {e}", file=sys.stderr)
        sys.exit(1)
