# 🔍 Base64 String Detection Automation Specification

## **Overview**
Refine the existing `find_base64_strings.py` automation to scan decompiled APK directories for hardcoded base64 encoded strings using the professional-grade `base64-detector` package, and integrate it as a standalone button in the `automatool_ui`.

## **Purpose**
The Base64 String Detection automation will:
1. **Directory Scanning**: Scan decompiled APK directories (not APK files) for Java source files
2. **Accurate Detection**: Use `base64-detector` package for professional-grade base64 string identification
3. **Comprehensive Results**: Provide file paths, line numbers, confidence scores, and entropy values
4. **UI Integration**: Seamlessly integrate with existing `automatool_ui` as a standalone button
5. **Error Handling**: Graceful handling of invalid paths and file access issues

## **Architecture Strategy**

### **File-Based Scanning (Not APK Parsing)**
Unlike the current implementation that uses `androguard` to parse APK files, this automation will:
1. **Input**: Accept path to decompiled APK directory
2. **Processing**: Recursively scan all `.java` files within the directory
3. **Detection**: Use `base64-detector` package for accurate string identification
4. **Output**: Generate comprehensive scan reports with confidence metrics

### **Professional Detection Engine**
Replace manual base64 validation with `base64-detector` package features:
- **Regex Pattern Matching**: Identify potential base64 strings
- **Entropy Calculation**: Filter out low-complexity data (reduce false positives)
- **Base64 Validation**: Confirm string validity through decoding
- **Large Blob Detection**: Identify substantial base64-encoded content
- **Confidence Scoring**: Provide reliability metrics for each detection

## **File Structure**
```
automatool/automatool/src/scripts/automations/
├── find_base64_strings.py          # REFINED: New directory scanning implementation
└── base64_scanner.py               # NEW: Core scanning logic using base64-detector

automatool_ui/
├── app.py                          # MODIFIED: Add new API endpoint
├── templates/index.html            # MODIFIED: Add new button
└── static/js/main.js              # MODIFIED: Add button handler
```

## **Implementation Details**

### **Phase 1: Dependencies and Setup**

#### 1.1 Install base64-detector Package
```bash
# Option 1: Clone and install from GitHub
git clone https://github.com/hackingbutlegal/base64-detector.git
cd base64-detector
pip install -e .

# Option 2: Add to requirements.txt
echo "base64-detector @ git+https://github.com/hackingbutlegal/base64-detector.git" >> requirements.txt
pip install -r requirements.txt
```

#### 1.2 Update Project Dependencies
```python
# requirements.txt
base64-detector @ git+https://github.com/hackingbutlegal/base64-detector.git
# ... existing dependencies
```

### **Phase 2: Core Implementation (`base64_scanner.py`)**

#### 2.1 Base64Scanner Class Structure
```python
import os
import json
from pathlib import Path
from base64_detector import Base64Detector  # or similar import
from datetime import datetime

class Base64Scanner:
    def __init__(self):
        self.detector = Base64Detector()
        self.results = []
        self.scan_metadata = {}
    
    def scan_decompiled_apk_directory(self, directory_path):
        """Main scanning function for decompiled APK directories"""
        pass
    
    def find_java_files(self, directory_path):
        """Recursively find all Java files in directory and subdirectories"""
        pass
    
    def scan_java_file(self, file_path):
        """Scan individual Java file using base64-detector package"""
        pass
    
    def generate_report(self):
        """Generate formatted results for UI consumption"""
        pass
```

#### 2.2 Directory Scanning Implementation
```python
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
            self.scan_metadata['total_strings_found'] += len(file_results['strings_found'])
    
    return self.generate_report()
```

#### 2.3 Java File Discovery
```python
def find_java_files(self, directory_path):
    """
    Recursively find all Java files in directory and subdirectories
    
    Args:
        directory_path (str): Root directory to search
        
    Returns:
        list: List of Path objects for all Java files found
    """
    java_files = []
    
    try:
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.endswith('.java'):
                    file_path = Path(root) / file
                    java_files.append(file_path)
    except Exception as e:
        print(f"Error discovering Java files: {e}")
    
    return java_files
```

#### 2.4 Individual File Scanning
```python
def scan_java_file(self, file_path):
    """
    Scan individual Java file using base64-detector package
    
    Args:
        file_path (Path): Path to Java file to scan
        
    Returns:
        dict or None: File scan results if base64 strings found, None otherwise
    """
    try:
        # Use base64-detector package for professional detection
        analysis = self.detector.analyze_file(str(file_path))
        
        if analysis.strings_found:
            return {
                'file_path': str(file_path),
                'strings_found': analysis.strings,
                'confidence_scores': analysis.confidence,
                'entropy_values': analysis.entropy,
                'decoded_sizes': analysis.decoded_sizes,
                'scan_timestamp': datetime.now().isoformat()
            }
    except Exception as e:
        print(f"Error scanning {file_path}: {e}")
    
    return None
```

#### 2.5 Report Generation
```python
def generate_report(self):
    """
    Generate formatted results for UI consumption
    
    Returns:
        dict: Structured report with scan results and metadata
    """
    return {
        'scan_metadata': self.scan_metadata,
        'files_with_strings': self.results,
        'summary': {
            'total_files_scanned': self.scan_metadata['total_files_scanned'],
            'total_strings_found': self.scan_metadata['total_strings_found'],
            'files_with_strings_count': len(self.results)
        }
    }
```

### **Phase 3: Refined Main Script (`find_base64_strings.py`)**

#### 3.1 Updated Main Script
```python
import argparse
import json
import sys
from pathlib import Path

# Import our new scanner
from base64_scanner import Base64Scanner

def main():
    """Main CLI function for standalone usage"""
    parser = argparse.ArgumentParser(
        description="Scan decompiled APK directory for hardcoded base64 strings"
    )
    parser.add_argument(
        'directory_path', 
        type=str, 
        help='Path to decompiled APK directory'
    )
    parser.add_argument(
        '--output', 
        '-o', 
        type=str, 
        help='Output JSON file path (optional)'
    )
    parser.add_argument(
        '--verbose', 
        '-v', 
        action='store_true', 
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize scanner
        scanner = Base64Scanner()
        
        if args.verbose:
            print(f"🔍 Scanning directory: {args.directory_path}")
        
        # Perform scan
        results = scanner.scan_decompiled_apk_directory(args.directory_path)
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"✅ Results saved to: {args.output}")
        else:
            print(json.dumps(results, indent=2))
            
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
```

### **Phase 4: UI Integration**

#### 4.1 Add New Button to `index.html`
```html
<!-- Add this button to the action-buttons section -->
<button class="btn btn-primary action-btn" data-action="scan-base64"
        {% if not state.setup_complete %}disabled{% endif %}>
    🔍 Scan for Base64 Strings
</button>
```

#### 4.2 Add New Route to `app.py`
```python
@app.route('/api/scan-base64', methods=['POST'])
def scan_base64_strings():
    """Scan decompiled APK directory for base64 strings"""
    try:
        if not app_state.get('OUTPUT_DIR'):
            return jsonify({
                'success': False,
                'message': 'No output directory configured'
            })
        
        # Initialize scanner
        scanner = Base64Scanner()
        
        # Scan the decompiled directory
        results = scanner.scan_decompiled_apk_directory(app_state['OUTPUT_DIR'])
        
        return jsonify({
            'success': True,
            'message': 'Base64 scan completed successfully',
            'results': results
        })
        
    except FileNotFoundError as e:
        return jsonify({
            'success': False,
            'message': f'Directory not found: {str(e)}',
            'error': 'DIRECTORY_NOT_FOUND'
        })
    except PermissionError as e:
        return jsonify({
            'success': False,
            'message': f'Access denied: {str(e)}',
            'error': 'ACCESS_DENIED'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Base64 scan failed: {str(e)}',
            'error': 'UNKNOWN_ERROR'
        })
```

#### 4.3 Add JavaScript Handler to `main.js`
```javascript
// Add to existing JavaScript
$('.action-btn[data-action="scan-base64"]').click(function() {
    const button = $(this);
    button.prop('disabled', true).text('🔍 Scanning...');
    
    $.post('/api/scan-base64')
        .done(function(response) {
            if (response.success) {
                showBase64Results(response.results);
            } else {
                showError('Base64 Scan Failed', response.message);
            }
        })
        .fail(function() {
            showError('Base64 Scan Failed', 'Network error occurred');
        })
        .always(function() {
            button.prop('disabled', false).text('🔍 Scan for Base64 Strings');
        });
});

function showBase64Results(results) {
    // Create and show results modal
    const modal = createBase64ResultsModal(results);
    $('body').append(modal);
    modal.modal('show');
}

function createBase64ResultsModal(results) {
    // Create modal HTML with results
    const modalHtml = `
        <div class="modal fade" id="base64-results-modal" tabindex="-1">
            <div class="modal-dialog modal-xl">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">🔍 Base64 Scan Results</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="scan-summary mb-3">
                            <div class="row">
                                <div class="col-md-3">
                                    <strong>Files Scanned:</strong> ${results.summary.total_files_scanned}
                                </div>
                                <div class="col-md-3">
                                    <strong>Strings Found:</strong> ${results.summary.total_strings_found}
                                </div>
                                <div class="col-md-3">
                                    <strong>Files with Strings:</strong> ${results.summary.files_with_strings_count}
                                </div>
                                <div class="col-md-3">
                                    <strong>Scan Time:</strong> ${new Date(results.scan_metadata.scan_timestamp).toLocaleString()}
                                </div>
                            </div>
                        </div>
                        <div class="results-list">
                            ${generateResultsList(results.files_with_strings)}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    return $(modalHtml);
}

function generateResultsList(filesWithStrings) {
    if (filesWithStrings.length === 0) {
        return '<div class="alert alert-info">No base64 strings found in scanned files.</div>';
    }
    
    let html = '';
    filesWithStrings.forEach(fileResult => {
        html += `
            <div class="card mb-3">
                <div class="card-header">
                    <strong>📁 ${fileResult.file_path.split('/').pop()}</strong>
                    <small class="text-muted">${fileResult.file_path}</small>
                </div>
                <div class="card-body">
                    ${generateStringsList(fileResult.strings_found)}
                </div>
            </div>
        `;
    });
    
    return html;
}

function generateStringsList(strings) {
    let html = '';
    strings.forEach((stringData, index) => {
        html += `
            <div class="string-item mb-2 p-2 border rounded">
                <div class="row">
                    <div class="col-md-8">
                        <strong>String ${index + 1}:</strong>
                        <div class="base64-string text-monospace small bg-light p-2 mt-1">
                            ${stringData.string.substring(0, 100)}${stringData.string.length > 100 ? '...' : ''}
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div><strong>Confidence:</strong> ${(stringData.confidence * 100).toFixed(1)}%</div>
                        <div><strong>Entropy:</strong> ${stringData.entropy.toFixed(2)}</div>
                        <div><strong>Decoded Size:</strong> ${stringData.decoded_size} bytes</div>
                    </div>
                </div>
            </div>
        `;
    });
    
    return html;
}
```

### **Phase 5: Results Display Modal**

#### 5.1 Create Results Modal Template
```html
<!-- Add to templates or create new modal -->
<div class="modal fade" id="base64-results-modal" tabindex="-1">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">🔍 Base64 Scan Results</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="scan-summary mb-3">
                    <div class="row">
                        <div class="col-md-3">
                            <strong>Files Scanned:</strong> <span id="files-scanned">0</span>
                        </div>
                        <div class="col-md-3">
                            <strong>Strings Found:</strong> <span id="strings-found">0</span>
                        </div>
                        <div class="col-md-3">
                            <strong>Files with Strings:</strong> <span id="files-with-strings">0</span>
                        </div>
                        <div class="col-md-3">
                            <strong>Scan Time:</strong> <span id="scan-time">-</span>
                        </div>
                    </div>
                </div>
                <div class="results-list" id="base64-results-list">
                    <!-- Results will be populated here -->
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <button type="button" class="btn btn-primary" id="export-results">Export Results</button>
            </div>
        </div>
    </div>
</div>
```

## **Expected Output Format**

### Success Response
```json
{
    "success": true,
    "message": "Base64 scan completed successfully",
    "results": {
        "scan_metadata": {
            "scan_timestamp": "2025-01-15T10:30:00Z",
            "directory_path": "/path/to/decompiled/apk",
            "total_files_scanned": 45,
            "total_strings_found": 12
        },
        "files_with_strings": [
            {
                "file_path": "/path/to/d1.java",
                "strings_found": [
                    {
                        "string": "UEsDBBQACAgIAFlwDFsAAAAAAAAAAAAAAAAJAAAAbGliZHBuLnNv...",
                        "confidence": 0.95,
                        "entropy": 5.8,
                        "decoded_size": 2048
                    }
                ],
                "scan_timestamp": "2025-01-15T10:30:00Z"
            }
        ],
        "summary": {
            "total_files_scanned": 45,
            "total_strings_found": 12,
            "files_with_strings_count": 3
        }
    }
}
```

### Error Response
```json
{
    "success": false,
    "message": "Failed to scan directory: Directory not found",
    "error": "DIRECTORY_NOT_FOUND"
}
```

## **Testing Requirements**

### 5.1 Unit Tests
- Test base64 detection logic with various string types
- Test file discovery functionality
- Test error handling for invalid paths
- Test report generation formatting

### 5.2 Integration Tests
- Test complete directory scanning workflow
- Test UI button functionality
- Test API endpoint responses
- Test results display modal

### 5.3 Sample Data Testing
- Use `d1.java` as primary test case
- Test with various Java file structures
- Validate base64 detection accuracy
- Test with large files and multiple strings

## **Success Criteria**

1. ✅ **Accurate Detection**: Successfully identifies base64 strings in Java files with high precision
2. ✅ **Directory Scanning**: Recursively scans decompiled APK directories for all Java files
3. ✅ **Professional Results**: Uses `base64-detector` package for enterprise-grade detection
4. ✅ **UI Integration**: Seamlessly integrates with existing `automatool_ui` as standalone button
5. ✅ **Error Handling**: Gracefully handles invalid paths, permission issues, and scanning errors
6. ✅ **Performance**: Efficiently processes large directories with minimal resource usage
7. ✅ **User Experience**: Clear, actionable results with confidence metrics and file locations

## **Timeline Estimate**

- **Phase 1**: 1-2 hours (dependencies + setup)
- **Phase 2**: 3-4 hours (core implementation)
- **Phase 3**: 1-2 hours (main script refinement)
- **Phase 4**: 3-4 hours (UI integration)
- **Phase 5**: 1-2 hours (results display)
- **Testing**: 2-3 hours (comprehensive testing)

**Total**: 11-17 hours for complete implementation

## **Dependencies**

- **base64-detector**: Professional base64 detection package
- **Standard Library**: `os`, `json`, `pathlib`, `datetime`
- **No External APK Parsing**: Removes `androguard` dependency
- **Python Compatibility**: 3.7+ compatible

## **Benefits of This Approach**

1. **Professional Detection**: Uses proven `base64-detector` algorithms instead of manual validation
2. **Higher Accuracy**: Entropy-based filtering reduces false positives significantly
3. **Better Performance**: Optimized for large file processing
4. **Seamless Integration**: Fits existing UI patterns and architecture
5. **Maintainable Code**: Clean separation of concerns and professional structure
6. **Scalable Solution**: Can handle large decompiled directories efficiently
7. **User-Friendly**: Clear results with confidence scores and detailed file information

This specification provides a comprehensive roadmap for implementing a robust, accurate base64 detection system that integrates seamlessly with your existing `automatool_ui` while leveraging professional-grade detection algorithms.
