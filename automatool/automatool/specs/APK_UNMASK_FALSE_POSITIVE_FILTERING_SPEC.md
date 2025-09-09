# APK Unmask False Positive Filtering Enhancement Specification

## Overview

This specification outlines the enhancement of the `run_apk_unmask.py` automation to include false positive (FP) filtering capabilities. The enhancement will allow users to maintain ignore lists for known false positives and display cleaner, more actionable output by filtering out benign detections.

## Problem Analysis

### Current State
- `apk_unmask` tool detects potentially malicious files in APK packages
- Output includes many false positives (legitimate files flagged as suspicious)
- No filtering mechanism exists to suppress known false positives
- Analysts must manually review and filter results each time

### Example False Positives from Output
Based on the provided example, common false positives include:
- **Bouncy Castle cryptographic library files**: `org/bouncycastle/pqc/crypto/picnic/*.bin.properties`
- **Font files**: `res/font/noto_sans_*.ttf`
- **Legitimate certificates**: `assets/CRT/*/*.crt`
- **Configuration files**: `assets/tcgetconfig.xml`
- **SDK components**: `com/mastercard/terminalsdk/internal/*-`

## Requirements

### Functional Requirements

#### FR1: Ignore List Management
- **FR1.1**: Support single global ignore list file
- **FR1.2**: Support regex matching patterns only
- **FR1.3**: Support reason codes for each ignore entry for documentation

#### FR2: Output Filtering
- **FR2.1**: Filter detected files based on ignore list and return same raw output format
- **FR2.2**: Maintain identical output format to original apk_unmask tool
- **FR2.3**: No additional summary or statistics in output

#### FR3: Configuration Management
- **FR3.1**: Fixed global ignore list location
- **FR3.2**: Support for comments in ignore list files
- **FR3.3**: Validation of ignore list syntax
- **FR3.4**: Auto-creation of default ignore list

#### FR4: Reporting Enhancement
- **FR4.1**: Generate filtered output with same format as original
- **FR4.2**: Extract file paths from filtered results and run `file` command analysis
- **FR4.3**: Generate enhanced output including file type information for each suspicious file
- **FR4.4**: Optional verbose mode for debugging filtering decisions

### Non-Functional Requirements

#### NFR1: Performance
- Filtering should add minimal overhead to analysis time
- Ignore list loading should be cached for multiple APK analysis

#### NFR2: Maintainability
- Clear separation between filtering logic and core apk_unmask execution
- Modular design allowing easy extension of matching patterns
- Comprehensive logging for debugging filtering issues

#### NFR3: Usability
- Backward compatibility - existing scripts should work unchanged
- Clear documentation and examples for ignore list creation
- Helpful error messages for invalid ignore list syntax

## Technical Specification

### 1. Enhanced Function Signature

```python
def run_apk_unmask(apk_path, output_dir, verbose=False, 
                   enable_filtering=True, enable_file_analysis=True):
    """
    Runs the apk_unmask tool with optional false positive filtering and file type analysis.

    Args:
        apk_path (str): The absolute path to the APK file.
        output_dir (str): The directory to save the output file in.
        verbose (bool): Whether to print verbose output.
        enable_filtering (bool): Enable false positive filtering.
        enable_file_analysis (bool): Run 'file' command on suspicious files for type analysis.

    Returns:
        str: The path to the output file, or None if the operation failed.
    """
```

### 2. Ignore List File Format

#### 2.1 File Structure
```ini
# APK Unmask Ignore List
# Format: regex_pattern:reason_code:comment

# Bouncy Castle cryptographic library files
org/bouncycastle/pqc/crypto/picnic/lowmc.*\.bin\.properties:CRYPTO_LIB:Bouncy Castle cryptographic library

# System fonts
res/font/noto_sans_.*\.ttf:SYSTEM_FONT:Google Noto system fonts
res/font/.*\.ttf:SYSTEM_FONT:System font files

# Certificate files
assets/CRT/.*/.*\.crt:CERT_FILE:SSL/TLS certificate files

# SDK components
com/mastercard/terminalsdk/internal/.*-:MASTERCARD_SDK:MasterCard SDK internal files
com/visa/vac/tc/.*-:VISA_SDK:Visa SDK components

# Obfuscated components
^com/[a-z]/[a-z]/[a-z]/[a-f0-9]+-$:OBFUSCATED_SDK:Obfuscated SDK components
^assets/com/[a-z]/[a-z]/[a-z]/[a-f0-9]+-$:OBFUSCATED_ASSETS:Obfuscated asset files

# Configuration files
assets/tcgetconfig\.xml:CONFIG_FILE:Terminal configuration
assets/ttp/mastercard/.*\.json:MASTERCARD_CONFIG:MasterCard configuration
```

#### 2.2 Ignore List Location
**Fixed Location**: `automatool/src/scripts/utils/apk_unmask_ignore_list.txt`
- Located within the project structure for consistency
- Automatically loaded by the automation
- Version controlled with the project
- No configuration required

### 3. New Classes and Modules

#### 3.1 ApkUnmaskFilter Class

```python
class ApkUnmaskFilter:
    """Handles false positive filtering for apk_unmask output."""
    
    def __init__(self, verbose=False):
        """Initialize the filter with default ignore list from utils directory."""
        
    def load_ignore_list(self):
        """Load and parse ignore list file from utils directory."""
        
    def _get_ignore_list_path(self):
        """Get the path to the ignore list file in utils directory."""
        import os
        # Get the directory containing this script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        # Navigate to utils directory
        utils_dir = os.path.join(script_dir, '..', 'utils')
        ignore_list_path = os.path.join(utils_dir, 'apk_unmask_ignore_list.txt')
        return os.path.abspath(ignore_list_path)
        
    def parse_ignore_entry(self, line):
        """Parse a single ignore list entry (regex:reason:comment)."""
        
    def should_ignore(self, file_path):
        """Check if a file should be ignored based on regex patterns."""
        
    def filter_output(self, raw_output):
        """Filter apk_unmask output and return same format with filtered items removed."""
        
    def extract_file_paths(self, filtered_output):
        """Extract file paths from filtered apk_unmask output for file analysis."""
```

#### 3.2 ApkUnmaskParser Class

```python
class ApkUnmaskParser:
    """Parses apk_unmask output into structured data."""
    
    def parse_output(self, raw_output):
        """Parse raw apk_unmask output into structured format."""
        
    def extract_file_entries(self, output_lines):
        """Extract individual file entries with their reasons."""
        
    def format_filtered_output(self, filtered_entries):
        """Format filtered entries back to apk_unmask output format."""
        
    def enhance_with_file_analysis(self, filtered_entries, file_analysis_results):
        """Enhance filtered output with file type analysis results."""
```

#### 3.3 FileAnalyzer Class

```python
class FileAnalyzer:
    """Handles file type analysis for suspicious files found in APK."""
    
    def __init__(self, apk_path, verbose=False):
        """Initialize file analyzer with APK path for file extraction."""
        
    def extract_file_from_apk(self, file_path):
        """Extract a specific file from APK for analysis."""
        
    def analyze_file_type(self, file_path):
        """Run 'file' command on extracted file and return type information."""
        
    def analyze_multiple_files(self, file_paths):
        """Analyze multiple files and return consolidated results."""
        
    def cleanup_extracted_files(self):
        """Clean up temporarily extracted files."""
```

#### 3.4 File Analysis Technical Details

##### 3.4.1 File Analysis Process
1. **Apktool Integration**: Use existing apktool decompiled output directory
2. **Path Construction**: Build file paths based on apktool output structure
3. **File Analysis**: Run `file` command on decompiled files directly
4. **No Cleanup**: Files already exist in apktool output directory

##### 3.4.2 File Command Integration
```python
def analyze_file_type(self, file_path):
    """
    Run 'file' command and parse output.
    
    Returns:
        dict: File analysis results with type, mime, encoding info
    """
    try:
        # Run file command with multiple options for comprehensive analysis
        result = subprocess.run(
            ['file', '-b', '--mime-type', '--mime-encoding', file_path],
            capture_output=True, text=True, check=True
        )
        
        # Get human-readable description
        desc_result = subprocess.run(
            ['file', '-b', file_path],
            capture_output=True, text=True, check=True
        )
        
        return {
            'file_path': file_path,
            'file_type': desc_result.stdout.strip(),
            'mime_info': result.stdout.strip(),
            'analysis_success': True
        }
        
    except subprocess.CalledProcessError as e:
        return {
            'file_path': file_path,
            'file_type': 'Analysis failed',
            'mime_info': f'Error: {e}',
            'analysis_success': False
        }
```

##### 3.4.3 Apktool Path Construction
```python
def build_file_path(self, apk_file_path, apktool_output_dir):
    """
    Build the actual file system path from APK file path using apktool output.
    
    Args:
        apk_file_path (str): Path within APK (e.g., 'assets/config.xml')
        apktool_output_dir (str): Base directory of apktool decompiled output
        
    Returns:
        str: Actual file system path to the decompiled file
    """
    import os
    
    # Construct the full path in apktool output directory
    full_path = os.path.join(apktool_output_dir, apk_file_path)
    
    # Normalize path separators for current OS
    normalized_path = os.path.normpath(full_path)
    
    return normalized_path
```

### 4. Output Structure

#### 4.1 Enhanced Output Structure

##### 4.1.1 Standard Filtered Output
- Filtered output saved to `apk_unmask_output.txt` (same filename as before)
- Identical format to original apk_unmask output
- Filtered entries are simply removed from the list
- Total count reflects remaining items after filtering

##### 4.1.2 Enhanced Output with File Analysis
- When `enable_file_analysis=True`, generates `apk_unmask_enhanced_output.txt`
- Contains original filtered output plus file type analysis
- Format preserves original structure with additional file type information

**Enhanced Output Format Example:**
```
[!] Detected potentially malicious files:
	-> assets/tcgetconfig.xml
	   └─ File is out of place
	   └─ File has a fake extension
	   └─ File appears to be encrypted
	   └─ File Type: XML 1.0 document, ASCII text
	-> com/e/d/a-
	   └─ File is out of place
	   └─ File has a fake extension
	   └─ File appears to be encrypted
	   └─ File Type: data (binary)
[*] Total: 2
```

### 5. Implementation Phases

#### Phase 1: Core Filtering Infrastructure
- Create `ApkUnmaskFilter` and `ApkUnmaskParser` classes
- Implement regex pattern matching
- Add automatic ignore list loading from utils directory
- Create default ignore list file in utils directory
- Create unit tests for filtering logic

#### Phase 2: Integration with run_apk_unmask.py
- Modify `run_apk_unmask()` function to support filtering parameters
- Add automatic ignore list loading from utils directory
- Implement output filtering while maintaining same format
- Maintain backward compatibility

#### Phase 3: File Analysis Integration
- Implement `FileAnalyzer` class for file type detection
- Add APK file extraction capabilities using `unzip` or `zipfile`
- Integrate file analysis with filtered output
- Add enhanced output generation with file type information

#### Phase 4: Advanced Features
- Implement ignore list validation
- Create default ignore list for common false positives
- Add comprehensive error handling
- Performance optimization

#### Phase 5: Documentation and Testing
- Create comprehensive documentation
- Add integration tests
- Performance testing and optimization
- User acceptance testing

### 6. Configuration Options

#### 6.1 Function Parameters
```python
# Direct parameters passed to run_apk_unmask() function
def run_apk_unmask(apk_path, output_dir, verbose=False, 
                   enable_filtering=True, enable_file_analysis=True):
    # Parameters control behavior directly
    # No environment variables needed
    # Ignore list automatically loaded from utils directory
```

#### 6.2 Ignore List Management
- **Fixed Path**: `automatool/src/scripts/utils/apk_unmask_ignore_list.txt`
- **Auto-Loading**: Automatically loaded by the automation
- **Version Control**: Maintained alongside the codebase
- **No Configuration**: No setup required, works out of the box

### 7. Default Ignore List Setup\n\n#### 7.1 Ignore List File Location\nThe ignore list file must be created at:\n```\nautomatool/src/scripts/utils/apk_unmask_ignore_list.txt\n```\n\n#### 7.2 File Creation Process\n1. Create the file in the utils directory alongside existing utility files\n2. Add regex patterns for common false positives\n3. Include reason codes and comments for maintainability\n4. Version control the file with the project\n\n### 7.3 Default Ignore Patterns

Based on the provided example and common false positive patterns:

```ini
# Cryptographic Libraries
org/bouncycastle/pqc/crypto/picnic/lowmc.*\.bin\.properties:CRYPTO_LIB:Bouncy Castle PQC

# System Fonts
res/font/noto_sans_.*\.ttf:SYSTEM_FONT:Google Noto fonts
res/font/.*\.ttf:SYSTEM_FONT:System font files

# Certificate Files
assets/CRT/.*/.*\.crt:CERT_FILE:SSL certificate files
assets/.*/certificate.*\.crt:CERT_FILE:Certificate files

# SDK Components
com/mastercard/terminalsdk/internal/.*-:MASTERCARD_SDK:MasterCard SDK
com/visa/vac/tc/.*-:VISA_SDK:Visa SDK components

# Configuration Files
assets/tcgetconfig\.xml:CONFIG_FILE:Terminal configuration
assets/ttp/mastercard/.*\.json:MASTERCARD_CONFIG:MasterCard configuration
assets/signature/.*\.txt:SIGNATURE_FILE:Signature files

# Obfuscated Components (common patterns)
^com/[a-z]/[a-z]/[a-z]/[a-f0-9]+-$:OBFUSCATED_SDK:Obfuscated SDK files
^assets/com/[a-z]/[a-z]/[a-z]/[a-f0-9]+-$:OBFUSCATED_ASSETS:Obfuscated assets
```

### 8. Error Handling

#### 8.1 Ignore List Errors
- Invalid syntax: Log warning and continue with valid entries
- Missing files: Log info message, continue without that list
- Permission errors: Log warning, fallback to other lists

#### 8.2 Filtering Errors
- Pattern compilation errors: Log error, skip invalid patterns
- Parsing errors: Fallback to unfiltered output with warning

### 9. Testing Strategy

#### 9.1 Unit Tests
- Pattern matching accuracy
- Ignore list parsing
- Output filtering logic
- Error handling scenarios

#### 9.2 Integration Tests
- End-to-end filtering with real apk_unmask output
- Global ignore list loading and parsing
- Performance with large outputs
- Backward compatibility

#### 9.3 Test Data
- Sample apk_unmask outputs with known false positives
- Global ignore list configurations
- Edge cases and malformed inputs

### 10. Usage Examples

#### 10.1 Basic Usage (Backward Compatible)
```python
# Existing code continues to work
output_path = run_apk_unmask(apk_path, output_dir, verbose=True)
```

#### 10.2 With Filtering Enabled
```python
# Enable filtering with global ignore list
output_path = run_apk_unmask(
    apk_path, output_dir, verbose=True,
    enable_filtering=True
)

# Output file contains filtered results in same format
if output_path:
    print(f"Filtered apk_unmask output saved to {output_path}")
```

#### 10.3 With File Analysis Enabled
```python
# Enable both filtering and file type analysis
output_path = run_apk_unmask(
    apk_path, output_dir, verbose=True,
    enable_filtering=True,
    enable_file_analysis=True
)

# Generates both standard and enhanced output files
if output_path:
    print(f"Filtered output: {output_path}")
    enhanced_path = output_path.replace('.txt', '_enhanced.txt')
    print(f"Enhanced output with file analysis: {enhanced_path}")
```

#### 10.4 File Analysis Only (No Filtering)
```python
# Run file analysis without filtering false positives
output_path = run_apk_unmask(
    apk_path, output_dir, verbose=True,
    enable_filtering=False,
    enable_file_analysis=True
)

# All detected files analyzed for type information
if output_path:
    print(f"Complete analysis with file types: {output_path}")
```

### 11. Migration Path

#### 11.1 Backward Compatibility
- All existing function calls work unchanged
- Filtering is enabled by default but can be disabled
- Existing output files remain unchanged
- No configuration required - works out of the box

#### 11.2 Simple Deployment
1. Add ignore list file to utils directory
2. Deploy enhanced run_apk_unmask.py
3. Filtering works automatically with default settings
4. Users can disable filtering if needed with `enable_filtering=False`

## Success Criteria

### Quantitative Metrics
- **Noise Reduction**: Reduce false positive alerts by >80% for common APK types
- **Performance**: Filtering adds <5% overhead to analysis time
- **Accuracy**: 0% false negatives (no actual threats filtered out)
- **Format Consistency**: 100% identical output format to original apk_unmask

### Qualitative Metrics
- **Usability**: Analysts can easily create and maintain ignore lists
- **Maintainability**: Code is modular and extensible
- **Reliability**: Robust error handling prevents analysis failures

## Risk Assessment

### High Risk
- **False Negatives**: Accidentally filtering real threats
  - *Mitigation*: Conservative default ignore lists, extensive testing
- **Performance Impact**: Slow filtering on large outputs
  - *Mitigation*: Efficient pattern matching, caching

### Medium Risk
- **Ignore List Maintenance**: List becomes outdated
  - *Mitigation*: Version control, community contributions
- **Complexity**: Feature creep making system too complex
  - *Mitigation*: Phased implementation, clear requirements

### Low Risk
- **Backward Compatibility**: Breaking existing integrations
  - *Mitigation*: Careful API design, thorough testing

## Future Enhancements

### Version 2.0 Features
- Machine learning-based false positive detection
- Integration with threat intelligence feeds
- Web-based ignore list management interface
- Collaborative ignore list sharing

### Integration Opportunities
- Integration with other analysis tools in the automation suite
- Export to SIEM/security platforms
- API for programmatic access to filtering results

## Conclusion

This enhancement will significantly improve the usability and effectiveness of apk_unmask analysis by reducing noise from false positives while maintaining the ability to detect genuine threats. The modular design ensures maintainability and allows for future enhancements while preserving backward compatibility with existing workflows.
