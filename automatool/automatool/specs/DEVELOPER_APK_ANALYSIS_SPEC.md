# Developer APK Analysis Automation Specification

## Overview

This specification defines an automation system that processes APK files for developers, extracts API keys using custom APKLeaks rules, and maintains a centralized developer database with parsed results stored directly in JSON format.

## Purpose

Create a streamlined automation that:
- Analyzes APK files for hardcoded API keys (Firebase, AppsFlyer, Google, OneSignal)
- Maintains a developer database with direct data storage (not file paths)
- Prevents duplicate analysis of existing developers
- Provides easy access to extracted API keys for further analysis

## Requirements

### Functional Requirements

#### FR-1: Developer Existence Check
- **Requirement**: Check if developer already exists in the database before processing
- **Behavior**: If developer exists, skip analysis and return early
- **Rationale**: Avoid duplicate processing and maintain data integrity

#### FR-2: APKLeaks Integration
- **Requirement**: Execute APKLeaks with custom rules and JSON output
- **Input**: APK file path, custom rules file
- **Output**: Raw APKLeaks JSON results
- **Rules**: Use existing `apkleaks_custom_rules.json` for pattern matching

#### FR-3: Result Parsing
- **Requirement**: Parse APKLeaks output into structured data
- **Integration**: Use existing `parse_apkleaks_output.py` module
- **Data Structure**: Convert `Dict[str, Set[str]]` to `Dict[str, List[str]]` for JSON storage

#### FR-4: Direct Data Storage
- **Requirement**: Store parsed results directly in `developers.json`
- **Format**: `{developer_name: {api_type: [keys]}}`
- **Benefit**: Single source of truth, no file path management

#### FR-5: File Management
- **Requirement**: Handle output directory creation and file organization
- **Behavior**: Create directories if they don't exist
- **Cleanup**: Optionally save backup files for debugging

### Non-Functional Requirements

#### NFR-1: Performance
- **Requirement**: Process APK files efficiently without redundant operations
- **Implementation**: Early exit for existing developers, reuse existing modules

#### NFR-2: Reliability
- **Requirement**: Handle errors gracefully with clear error messages
- **Error Cases**: Missing files, APKLeaks failures, JSON parsing errors

#### NFR-3: Maintainability
- **Requirement**: Leverage existing codebase components
- **Dependencies**: `run_apkleaks.py`, `parse_apkleaks_output.py`, `apkleaks_custom_rules.json`

## Technical Specification

### Input Parameters

```python
def analyze_developer_apk(
    developer_name: str,    # Developer identifier
    apk_path: str,         # Path to APK file to analyze
    output_dir: str        # Directory for output files
) -> bool                  # Success indicator
```

### Data Structures

#### developers.json Format
```json
{
  "MalwareDev": {
    "appsflyer_api_keys": [
      "e44a8b69c7d76049d312caec6fb8a01b60982d8f"
    ],
    "onesignal_app_ids": [
      "00000000-0000-0000-0000-000000000000",
      "01528cc0-dd34-494d-9218-24af1317e1ee"
    ],
    "firebase_api_keys": [
      "AIzaSyD4E5f6G7h8I9J0kLmN1oP2qR3sT4uV5wX"
    ]
  },
  "LegitimateApp": {
    "google_maps_api_keys": [
      "AIzaSyBmaps123456789012345678901234567"
    ]
  }
}
```

#### Internal Data Flow
```
APK File → APKLeaks (JSON) → parse_apkleaks_json() → Dict[str, Set[str]] 
         → Convert to Dict[str, List[str]] → Store in developers.json
```

### Algorithm Design

#### Main Processing Flow
```
1. INPUT VALIDATION
   ├── Validate APK file exists
   ├── Validate output directory (create if needed)
   └── Load developers.json (create empty if missing)

2. DUPLICATE CHECK
   ├── Check if developer_name exists in developers.json
   └── If exists: Print message and return False

3. APKLEAKS EXECUTION
   ├── Generate temporary filenames
   ├── Execute run_apkleaks.py with:
   │   ├── --json flag for JSON output
   │   ├── --custom-rules for pattern matching
   │   └── Target output file
   └── Verify APKLeaks completed successfully

4. RESULT PARSING
   ├── Call parse_apkleaks_json() on APKLeaks output
   ├── Receive Dict[str, Set[str]] structure
   └── Convert sets to sorted lists for JSON serialization

5. DATABASE UPDATE
   ├── Add developer entry to developers.json structure
   ├── Write updated developers.json to disk
   └── Optionally save backup files

6. CLEANUP & RETURN
   ├── Remove temporary files (optional)
   ├── Print success summary
   └── Return True
```

#### Error Handling Strategy
```
┌── FileNotFoundError (APK missing)
├── subprocess.CalledProcessError (APKLeaks failure)  
├── json.JSONDecodeError (Invalid APKLeaks output)
├── ValueError (Unexpected data structure)
└── PermissionError (File write access)
    └── For each: Log error, cleanup temp files, return False
```

### File Organization

#### Output Directory Structure
```
output_dir/
├── developers.json                    # Main database (required)
├── temp/                             # Temporary APKLeaks files
│   ├── {developer}_raw_apkleaks.json # Raw APKLeaks output
│   └── {developer}_temp_parsed.json  # Intermediate parsed data
└── backups/ (optional)
    └── developers_backup_YYYYMMDD.json # Daily backups
```

#### File Naming Convention
- **Main database**: `developers.json`
- **Temporary files**: `{developer_name}_temp_*.json`
- **Backup files**: `developers_backup_{timestamp}.json`

### Integration Points

#### Existing Module Dependencies
```python
# Required imports
from run_apkleaks import run_apkleaks
from parse_apkleaks_output import parse_apkleaks_json, save_parsed_results
```

#### Custom Rules Integration
```python
# Rules file location
CUSTOM_RULES_PATH = "src/scripts/automations/apkleaks_custom_rules.json"

# Expected rule types
EXPECTED_API_TYPES = [
    "firebase_api_keys",
    "appsflyer_api_keys", 
    "onesignal_app_ids",
    "google_maps_api_keys",
    "appsflyer_dev_keys",
    "appsflyer_app_id"
]
```

## Implementation Details

### Main Function Signature
```python
def analyze_developer_apk(
    developer_name: str, 
    apk_path: str, 
    output_dir: str,
    verbose: bool = False,
    save_backups: bool = True
) -> tuple[bool, dict]:
    """
    Analyze APK for developer and store results in developers database.
    
    Args:
        developer_name: Unique identifier for the developer
        apk_path: Path to APK file to analyze
        output_dir: Directory for output files and developers.json
        verbose: Enable detailed logging
        save_backups: Save backup copies of raw/parsed data
        
    Returns:
        tuple[bool, dict]: (success, parsed_data or error_info)
    """
```

### Helper Functions
```python
def load_developers_database(developers_file: str) -> dict:
    """Load existing developers.json or create empty structure."""

def save_developers_database(developers_data: dict, developers_file: str) -> None:
    """Save developers database with proper formatting."""

def convert_sets_to_lists(parsed_data: Dict[str, Set[str]]) -> Dict[str, List[str]]:
    """Convert parse_apkleaks_json output to JSON-serializable format."""

def create_backup_files(developer_name: str, raw_data: str, parsed_data: dict, backup_dir: str) -> None:
    """Save backup copies for debugging and audit trail."""
```

### Command Line Interface
```python
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Analyze developer APK for hardcoded API keys"
    )
    parser.add_argument("developer_name", help="Developer identifier")
    parser.add_argument("apk_path", help="Path to APK file")
    parser.add_argument("output_dir", help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-backups", action="store_true", help="Skip backup file creation")
    parser.add_argument("--force", action="store_true", help="Overwrite existing developer")
```

### Expected Output Format
```bash
$ python analyze_developer_apk.py "MalwareDev" "/path/to/malware.apk" "/output/dir"

🔍 Analyzing APK for developer: MalwareDev
📱 APK: /path/to/malware.apk
📁 Output: /output/dir

💧 Running APKLeaks analysis...
📋 Using custom rules from: apkleaks_custom_rules.json
📄 JSON output will be saved to: /tmp/MalwareDev_raw_apkleaks.json

✅ APKLeaks analysis completed
🔍 Parsing results...
📊 Found 3 API key types with 12 total keys

📄 Updating developers database...
✅ Developer 'MalwareDev' added to database
📄 Results stored in: /output/dir/developers.json

📋 Summary:
  - AppsFlyer API Keys: 1
  - OneSignal App IDs: 9  
  - Firebase API Keys: 2
```

## Testing Strategy

### Unit Tests
```python
class TestDeveloperAPKAnalysis(unittest.TestCase):
    def test_new_developer_analysis(self):
        """Test analysis of new developer APK."""
        
    def test_existing_developer_skip(self):
        """Test skipping analysis for existing developer."""
        
    def test_invalid_apk_handling(self):
        """Test error handling for invalid APK files."""
        
    def test_apkleaks_failure_handling(self):
        """Test handling of APKLeaks execution failures."""
        
    def test_data_conversion(self):
        """Test conversion from sets to lists for JSON storage."""
        
    def test_developers_json_format(self):
        """Test developers.json structure and format."""
```

### Integration Tests
```python
def test_full_workflow_with_real_apk():
    """End-to-end test with actual APK file."""
    
def test_multiple_developers():
    """Test adding multiple developers to database."""
    
def test_backup_file_creation():
    """Test backup file generation and content."""
```

### Test Data
```
tests/resources/
├── sample_malware.apk           # Test APK with known API keys
├── developers_test.json         # Sample developers database
├── expected_results.json        # Expected parsing results
└── apkleaks_sample_output.json  # Sample APKLeaks output
```

## Security Considerations

### Data Handling
- **Sensitive Data**: API keys are stored in plain text for analysis purposes
- **File Permissions**: Ensure proper file permissions on developers.json
- **Backup Security**: Consider encryption for backup files containing API keys

### Input Validation
- **APK File Validation**: Verify file exists and is readable
- **Developer Name Sanitization**: Prevent path traversal in developer names
- **Output Directory**: Validate and sanitize output directory paths

## Configuration

### Default Settings
```python
# Configuration constants
DEFAULT_CUSTOM_RULES = "src/scripts/automations/apkleaks_custom_rules.json"
DEFAULT_DEVELOPERS_FILE = "developers.json"
TEMP_FILE_PREFIX = "apkleaks_temp_"
BACKUP_DIR_NAME = "backups"
MAX_BACKUP_FILES = 30  # Keep last 30 backups
```

### Environment Variables
```bash
# Optional environment overrides
APKLEAKS_CUSTOM_RULES=/path/to/custom/rules.json
DEVELOPERS_DATABASE_PATH=/path/to/developers.json
APKLEAKS_TIMEOUT=300  # Seconds
```

## Dependencies

### Required Python Packages
```
- json (built-in)
- os (built-in) 
- subprocess (built-in)
- argparse (built-in)
- typing (built-in)
- pathlib (built-in)
```

### External Dependencies
```
- APKLeaks tool (installed and in PATH)
- Java runtime (required by APKLeaks)
- Existing automatool modules:
  - run_apkleaks.py
  - parse_apkleaks_output.py
  - apkleaks_custom_rules.json
```

## Performance Considerations

### Optimization Strategies
- **Early Exit**: Skip processing for existing developers
- **Temporary Files**: Use system temp directory for intermediate files
- **Memory Management**: Process large APK files efficiently
- **Batch Processing**: Support for multiple APKs (future enhancement)

### Resource Usage
- **Disk Space**: Raw APKLeaks output + parsed results + backups
- **CPU**: APKLeaks analysis (Java process) + JSON parsing
- **Memory**: Hold developers.json in memory during updates

## Monitoring and Logging

### Log Levels
```python
import logging

# Log categories
logging.info("Processing new developer: {developer_name}")
logging.warning("Developer already exists: {developer_name}")  
logging.error("APKLeaks failed: {error_message}")
logging.debug("Parsed {count} API keys of type {api_type}")
```

### Metrics to Track
- **Success Rate**: Successful vs failed analyses
- **Processing Time**: Time per APK analysis
- **API Key Discovery**: Types and counts of keys found
- **Database Growth**: Number of developers over time

## Future Enhancements

### Planned Features
1. **Batch Processing**: Analyze multiple APKs for one developer
2. **Result Comparison**: Compare API keys across developer versions
3. **Export Formats**: CSV, XML export options
4. **Web Interface**: REST API for database queries
5. **Automated Reporting**: Generate summary reports

### Extensibility Points
- **Custom Rule Sets**: Support for multiple rule files
- **Plugin Architecture**: Custom post-processing plugins
- **Database Backends**: Support for SQL databases
- **Cloud Storage**: S3/Azure blob storage integration

## Conclusion

This specification provides a comprehensive framework for automated developer APK analysis with direct data storage in a centralized JSON database. The design leverages existing automatool components while providing a clean, maintainable interface for API key extraction and storage.

The implementation focuses on simplicity, reliability, and integration with existing workflows, making it easy to incorporate into larger malware analysis pipelines or security research workflows.
