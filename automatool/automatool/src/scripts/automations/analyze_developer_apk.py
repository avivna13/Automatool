#!/usr/bin/env python3
"""
Developer APK Analysis Automation

Analyzes APK files for developers, extracts API keys using custom APKLeaks rules,
and maintains a centralized developer database with parsed results.
"""

import json
import os
import argparse
import tempfile
from typing import Dict, Set, List, Tuple
from pathlib import Path

# Import existing modules
from run_apkleaks import run_apkleaks
from parse_apkleaks_output import parse_apkleaks_json

# Configuration constants
DEFAULT_CUSTOM_RULES = "apkleaks_custom_rules.json"
DEFAULT_DEVELOPERS_FILE = "developers.json"
TEMP_FILE_PREFIX = "apkleaks_temp_"

# Expected API types from specification
EXPECTED_API_TYPES = [
    "firebase_api_keys",
    "appsflyer_api_keys", 
    "onesignal_app_ids",
    "google_maps_api_keys",
    "appsflyer_dev_keys",
    "appsflyer_app_id"
]


# Custom Exception Classes for standardized error handling
class DeveloperAPKAnalysisError(Exception):
    """Base exception for Developer APK Analysis operations."""
    pass


class DatabaseError(DeveloperAPKAnalysisError):
    """Exception raised for database-related errors."""
    pass


class ValidationError(DeveloperAPKAnalysisError):
    """Exception raised for input validation errors."""
    pass


class APKLeaksError(DeveloperAPKAnalysisError):
    """Exception raised for APKLeaks execution errors."""
    pass


class ParsingError(DeveloperAPKAnalysisError):
    """Exception raised for result parsing errors."""
    pass


def load_developers_database(developers_file: str) -> dict:
    """
    Load existing developers.json or create empty structure.
    
    Args:
        developers_file (str): Path to the developers.json file
        
    Returns:
        dict: Developers database structure
        
    Raises:
        DatabaseError: If there are issues loading or parsing the database file
    """
    if not os.path.exists(developers_file):
        print(f"📄 Creating new developers database: {developers_file}")
        return {}
    
    try:
        with open(developers_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                print(f"📄 Empty developers database file, initializing: {developers_file}")
                return {}
            data = json.loads(content)
            
        if not isinstance(data, dict):
            raise DatabaseError(f"Invalid database format: expected dictionary, got {type(data).__name__}")
            
        print(f"📄 Loaded existing developers database: {developers_file}")
        return data
        
    except json.JSONDecodeError as e:
        raise DatabaseError(f"Invalid JSON format in database file '{developers_file}': {e}")
    except PermissionError as e:
        raise DatabaseError(f"Permission denied accessing database file '{developers_file}': {e}")
    except Exception as e:
        raise DatabaseError(f"Failed to load database file '{developers_file}': {e}")


def save_developers_database(developers_data: dict, developers_file: str) -> None:
    """
    Save developers database with proper formatting.
    
    Args:
        developers_data (dict): The developers database to save
        developers_file (str): Path where to save the database
        
    Raises:
        DatabaseError: If there are issues saving the database file
    """
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(developers_file), exist_ok=True)
        
        with open(developers_file, 'w', encoding='utf-8') as f:
            json.dump(developers_data, f, indent=2, ensure_ascii=False)
        print(f"✅ Developers database saved to: {developers_file}")
        
    except PermissionError as e:
        raise DatabaseError(f"Permission denied saving database file '{developers_file}': {e}")
    except OSError as e:
        raise DatabaseError(f"OS error saving database file '{developers_file}': {e}")
    except Exception as e:
        raise DatabaseError(f"Failed to save database file '{developers_file}': {e}")


def convert_sets_to_lists(parsed_data: Dict[str, Set[str]]) -> Dict[str, List[str]]:
    """
    Convert parse_apkleaks_json output to JSON-serializable format.
    
    Args:
        parsed_data (Dict[str, Set[str]]): Data with sets from parse_apkleaks_json
        
    Returns:
        Dict[str, List[str]]: Data with sorted lists for JSON serialization
    """
    return {
        api_type: sorted(list(keys)) for api_type, keys in parsed_data.items()
    }


def cleanup_temp_directory(temp_dir: str, verbose: bool = False) -> None:
    """
    Clean up temporary directory with error handling.
    
    Args:
        temp_dir (str): Path to temporary directory to clean up
        verbose (bool): Whether to print verbose messages
    """
    import shutil
    try:
        shutil.rmtree(temp_dir)
        if verbose:
            print(f"✅ Temporary directory cleaned up: {temp_dir}")
    except Exception as cleanup_error:
        if verbose:
            print(f"⚠️  Warning: Could not clean up temp directory: {cleanup_error}")


def create_error_info(error: Exception, developer_name: str, category: str = "standardized_error") -> dict:
    """
    Create standardized error information dictionary.
    
    Args:
        error (Exception): The exception that occurred
        developer_name (str): Developer identifier
        category (str): Error category ("standardized_error" or "unexpected_error")
        
    Returns:
        dict: Standardized error information
    """
    return {
        "error": str(error),
        "error_type": type(error).__name__,
        "developer": developer_name,
        "category": category
    }


def calculate_api_key_statistics(data: Dict[str, List[str]]) -> Tuple[int, int]:
    """
    Calculate API key statistics from parsed data.
    
    Args:
        data (Dict[str, List[str]]): Parsed API key data
        
    Returns:
        Tuple[int, int]: (total_keys, total_types)
    """
    total_keys = sum(len(keys) for keys in data.values())
    total_types = len(data)
    return total_keys, total_types


def print_verbose_parsing_summary(parsed_data: Dict[str, Set[str]], verbose: bool) -> None:
    """
    Print verbose summary of parsing results.
    
    Args:
        parsed_data (Dict[str, Set[str]]): Parsed data with sets
        verbose (bool): Whether to print verbose output
    """
    if verbose:
        total_keys = sum(len(keys) for keys in parsed_data.values())
        print(f"📊 Found {len(parsed_data)} API key types with {total_keys} total keys")
        for api_type, keys in parsed_data.items():
            print(f"  - {api_type}: {len(keys)} key(s)")


def print_verbose_final_summary(serializable_data: Dict[str, List[str]], developer_name: str, verbose: bool) -> None:
    """
    Print verbose final summary of analysis results.
    
    Args:
        serializable_data (Dict[str, List[str]]): Final serializable data
        developer_name (str): Developer identifier
        verbose (bool): Whether to print verbose output
    """
    print(f"\n🎉 Analysis completed successfully for developer: {developer_name}")
    if verbose:
        print("\n📋 Processing Summary:")
        for api_type, keys in serializable_data.items():
            print(f"   • {api_type}: {len(keys)} key(s)")
        total_keys, total_types = calculate_api_key_statistics(serializable_data)
        print(f"\n📊 Total: {total_keys} API keys across {total_types} categories")


def get_project_root() -> str:
    """
    Get the project root directory (where automation_resources.json and developers.json are located).
    
    Returns:
        str: Path to project root directory
    """
    # Navigate from the file location up to project root
    # Current file: automatool/automatool/src/scripts/automations/analyze_developer_apk.py
    # Need to go up: automations -> scripts -> src -> automatool -> automatool -> aviv_automatool (6 levels)
    current_file = __file__
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(current_file))))))


def validate_inputs(developer_name: str, apk_path: str, output_dir: str) -> bool:
    """
    Validate input parameters.
    
    Args:
        developer_name (str): Developer identifier
        apk_path (str): Path to APK file
        output_dir (str): Output directory path
        
    Returns:
        bool: True if all inputs are valid
        
    Raises:
        ValidationError: If any input is invalid
    """
    # Validate developer name
    if not developer_name or not developer_name.strip():
        raise ValidationError("Developer name cannot be empty")
    
    # Basic sanitization for developer name
    invalid_chars = ['/', '\\', '..', '<', '>', ':', '"', '|', '?', '*']
    if any(char in developer_name for char in invalid_chars):
        raise ValidationError(f"Developer name contains invalid characters: {invalid_chars}")
    
    # Validate APK file exists
    if not os.path.exists(apk_path):
        raise ValidationError(f"APK file not found: {apk_path}")
    
    if not os.path.isfile(apk_path):
        raise ValidationError(f"APK path is not a file: {apk_path}")
    
    # Validate APK file extension
    if not apk_path.lower().endswith('.apk'):
        raise ValidationError(f"File is not an APK: {apk_path}")
    
    # Validate/create output directory
    try:
        os.makedirs(output_dir, exist_ok=True)
    except PermissionError as e:
        raise ValidationError(f"Permission denied creating output directory '{output_dir}': {e}")
    except Exception as e:
        raise ValidationError(f"Cannot create output directory '{output_dir}': {e}")
    
    return True


def analyze_developer_apk(
    developer_name: str,
    apk_path: str,
    output_dir: str,
    verbose: bool = False,
    force: bool = False
) -> Tuple[bool, dict]:
    """
    Analyze APK for developer and store results in developers database.
    
    Args:
        developer_name: Unique identifier for the developer
        apk_path: Path to APK file to analyze
        output_dir: Directory for output files and developers.json
        verbose: Enable detailed logging
        force: Overwrite existing developer entry
        
    Returns:
        tuple[bool, dict]: (success, parsed_data or error_info)
    """
    if verbose:
        print(f"\n🔍 Starting analysis for developer: {developer_name}")
        print(f"📱 APK File: {apk_path}")
        print(f"📁 Output Directory: {output_dir}")
    
    try:
        # Step 1: Input validation
        validate_inputs(developer_name, apk_path, output_dir)
        if verbose:
            print("✅ Input validation passed")
        
        # Step 2: Load developers database
        # Use project root directory (same as automation_resources.json) for developers.json
        project_root = get_project_root()
        developers_file = os.path.join(project_root, DEFAULT_DEVELOPERS_FILE)
        developers_data = load_developers_database(developers_file)
        
        # Step 3: Check if developer already exists
        if developer_name in developers_data:
            if not force:
                print(f"⚠️  Developer '{developer_name}' already exists in database")
                print(f"📄 Use --force flag to overwrite existing entry")
                return False, {"error": "Developer already exists", "developer": developer_name}
            else:
                print(f"🔄 Overwriting existing entry for developer: {developer_name}")
        
        # Step 4: Developer is new or force overwrite - proceed with analysis
        print(f"✅ Proceeding with analysis for developer: {developer_name}")
        
        # Step 5: Run APKLeaks with custom rules
        if verbose:
            print("💧 Running APKLeaks analysis...")
        
        # Find custom rules file - it's in the automatool directory relative to project root
        project_root = get_project_root()
        custom_rules_path = os.path.join(project_root, "automatool", DEFAULT_CUSTOM_RULES)
        if not os.path.exists(custom_rules_path):
            raise ValidationError(f"Custom rules file not found: {custom_rules_path}")
        
        if verbose:
            print(f"📋 Using custom rules from: {custom_rules_path}")
        
        # Create temporary directory for APKLeaks output
        temp_dir = tempfile.mkdtemp(prefix=TEMP_FILE_PREFIX)
        if verbose:
            print(f"📁 Temporary directory: {temp_dir}")
        
        try:
            # Run APKLeaks with JSON output and custom rules
            apkleaks_output_file = run_apkleaks(
                apk_path=apk_path,
                output_directory=temp_dir,
                verbose=verbose,
                custom_rules_path=custom_rules_path,
                json_output=True
            )
            
            if not apkleaks_output_file or not os.path.exists(apkleaks_output_file):
                raise APKLeaksError("APKLeaks failed to produce output file")
            
            if verbose:
                print(f"✅ APKLeaks analysis completed")
                print(f"📄 Output file: {apkleaks_output_file}")
            
            # Step 6: Parse APKLeaks results
            if verbose:
                print("🔍 Parsing APKLeaks results...")
            
            try:
                # Parse the APKLeaks JSON output
                parsed_data = parse_apkleaks_json(apkleaks_output_file)
                
                # Print verbose parsing summary
                print_verbose_parsing_summary(parsed_data, verbose)
                
                # Convert sets to lists for JSON serialization
                serializable_data = convert_sets_to_lists(parsed_data)
                
                if verbose:
                    print("✅ Results parsing completed")
                
            except Exception as e:
                raise ParsingError(f"Failed to parse APKLeaks results: {e}")
            
            # Step 7: Update developers database (outside parsing try-catch)
            if verbose:
                print("📄 Updating developers database...")
            
            # Add developer entry to database with parsed results
            developers_data[developer_name] = serializable_data
            
            # Save updated database
            save_developers_database(developers_data, developers_file)
                
            if verbose:
                print(f"✅ Developer '{developer_name}' added to database")
                print(f"📄 Database location: {developers_file}")
            
            # Step 8: Cleanup and final summary
            if verbose:
                print("🧹 Cleaning up temporary files...")
            
            # Clean up temporary directory
            cleanup_temp_directory(temp_dir, verbose)
            
            # Final success summary
            print_verbose_final_summary(serializable_data, developer_name, verbose)
            
            # Return final success data
            total_keys, total_types = calculate_api_key_statistics(serializable_data)
            final_data = {
                "status": "completed",
                "developer": developer_name,
                "apk_path": apk_path,
                "results": serializable_data,
                "database_file": developers_file,
                "total_api_keys": total_keys,
                "api_key_types": list(serializable_data.keys())
            }
            
            return True, final_data
            
        except (APKLeaksError, ParsingError, DatabaseError):
            # Re-raise our custom exceptions
            # Cleanup temp directory on error
            cleanup_temp_directory(temp_dir, verbose=False)
            raise
        except Exception as e:
            # Cleanup temp directory on error
            cleanup_temp_directory(temp_dir, verbose=False)
            raise APKLeaksError(f"APKLeaks execution failed: {e}")
        
    except (ValidationError, DatabaseError, APKLeaksError, ParsingError) as e:
        error_info = create_error_info(e, developer_name, "standardized_error")
        print(f"❌ {type(e).__name__}: {e}")
        return False, error_info
    except Exception as e:
        error_info = create_error_info(e, developer_name, "unexpected_error")
        print(f"❌ UNEXPECTED ERROR: {e}")
        return False, error_info


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="🔍 Developer APK Analysis Tool - Extract hardcoded API keys using APKLeaks",
        epilog="""
📋 Examples:
  %(prog)s "MalwareDev" malware.apk ./output
  %(prog)s "TestApp" --verbose --force app.apk /tmp/analysis
  %(prog)s "NewDev" sample.apk . --verbose

📁 File Locations:
  • developers.json: Stored in project root (same as automation_resources.json)
  • Custom rules: automatool/apkleaks_custom_rules.json
  • Temporary files: System temp directory

🔑 Supported API Key Types:
  • Firebase API Keys
  • AppsFlyer API Keys & Dev Keys
  • OneSignal App IDs
  • Google Maps API Keys
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "developer_name", 
        help="🏷️  Unique identifier for the developer (alphanumeric, no special chars)"
    )
    parser.add_argument(
        "apk_path", 
        help="📱 Path to APK file to analyze (.apk extension required)"
    )
    parser.add_argument(
        "output_dir", 
        help="📁 Output directory for temporary files (developers.json stored in project root)"
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true", 
        help="🔊 Enable verbose output with detailed progress and statistics"
    )
    parser.add_argument(
        "--force", 
        action="store_true", 
        help="🔄 Overwrite existing developer entry in database"
    )
    parser.add_argument(
        "--version", 
        action="version", 
        version="Developer APK Analysis Tool v1.0.0"
    )
    
    args = parser.parse_args()
    
    # Print startup banner
    print("=" * 60)
    print("🔍 Developer APK Analysis Tool v1.0.0")
    print("=" * 60)
    print(f"🏷️  Developer: {args.developer_name}")
    print(f"📱 APK File: {args.apk_path}")
    print(f"📁 Output Directory: {args.output_dir}")
    print(f"🔊 Verbose Mode: {'Enabled' if args.verbose else 'Disabled'}")
    print(f"🔄 Force Overwrite: {'Enabled' if args.force else 'Disabled'}")
    print("=" * 60)
    
    # Run the analysis
    success, result = analyze_developer_apk(
        args.developer_name,
        args.apk_path,
        args.output_dir,
        args.verbose,
        args.force
    )
    
    # Enhanced output formatting
    print("=" * 60)
    if success:
        print("🎉 ANALYSIS COMPLETED SUCCESSFULLY")
        print("=" * 60)
        
        # Display results summary
        if 'results' in result:
            results = result['results']
            total_keys = result.get('total_api_keys', 0)
            
            print(f"📊 RESULTS SUMMARY:")
            print(f"   • Total API Keys Found: {total_keys}")
            print(f"   • API Key Categories: {len(results)}")
            print(f"   • Database Updated: ✅")
            
            if results:
                print(f"\n🔑 API KEYS BY TYPE:")
                for api_type, keys in results.items():
                    print(f"   • {api_type}: {len(keys)} key(s)")
            
            print(f"\n📄 Database Location: {result.get('database_file', 'N/A')}")
        
        if args.verbose and 'results' in result:
            print(f"\n📋 DETAILED RESULTS:")
            for api_type, keys in result['results'].items():
                if keys:
                    print(f"\n   {api_type}:")
                    for i, key in enumerate(keys, 1):
                        print(f"     {i}. {key}")
    else:
        print("💥 ANALYSIS FAILED")
        print("=" * 60)
        
        error_type = result.get('error_type', 'Unknown')
        error_msg = result.get('error', 'Unknown error')
        category = result.get('category', 'unknown')
        
        print(f"❌ Error Type: {error_type}")
        print(f"📝 Error Message: {error_msg}")
        
        if category == 'standardized_error':
            print("ℹ️  This is a known error type. Check your inputs and try again.")
        else:
            print("⚠️  This is an unexpected error. Please report this issue.")
        
        print("=" * 60)
        exit(1)
    
    print("=" * 60)
