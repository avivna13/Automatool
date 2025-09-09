# 🎭 APK Unmask Standalone Service Specification

## **Overview**

Extract the APK Unmask functionality from the main `automatool.py` execution flow and create it as a standalone service in the web UI. This addresses the dependency issue where APK Unmask requires decompiled output (apktool) that would slow down the main automation pipeline, while providing a focused, efficient standalone tool for malicious file detection with false positive filtering.

## **Problem Analysis**

### **Current Issues**
1. **Dependency Conflict**: APK Unmask with file analysis requires apktool decompilation output
2. **Performance Impact**: Adding decompilation to main `automatool.py` flow would significantly slow it down
3. **Workflow Mismatch**: Main automation is designed for speed, while APK Unmask analysis is more thorough
4. **Resource Efficiency**: Users often want APK Unmask analysis independently of the full automation pipeline

### **Current Implementation in automatool.py**
```python
# Lines 139-147 in automatool.py
apk_unmask_output_path = run_apk_unmask(apk_path, args.directory, args.verbose)
if apk_unmask_output_path:
    try:
        resource_tracker.add_file(apk_unmask_output_path)
    except Exception as e:
        print(f"❌ ERROR: Failed to track apk_unmask output file: {e}")
```

**Issues with Current Integration:**
- No decompilation support (file analysis disabled)
- Blocks main automation flow
- Limited functionality due to missing apktool output

## **Specification for Standalone APK Unmask Service**

### **1. UI Integration**

#### **Add New Action Button**
**File**: `automatool_ui/templates/index.html`
**Location**: In the "Analysis Actions" panel

```html
<button class="btn btn-warning action-btn" data-action="apk-unmask-analysis"
        {% if not state.setup_complete %}disabled{% endif %}>
    🎭 APK Unmask Analysis (with File Type Detection)
</button>
```

#### **Add Configuration Options**
**Location**: Add configuration panel in UI

```html
<div class="form-group">
    <label for="apk-unmask-options">APK Unmask Options:</label>
    <div class="form-check">
        <input class="form-check-input" type="checkbox" id="enable-filtering" checked>
        <label class="form-check-label" for="enable-filtering">
            Enable False Positive Filtering
        </label>
    </div>
    <div class="form-check">
        <input class="form-check-input" type="checkbox" id="enable-file-analysis" checked>
        <label class="form-check-label" for="enable-file-analysis">
            Enable File Type Analysis (requires decompilation)
        </label>
    </div>
    <div class="form-group mt-2">
        <label for="apktool-output-path">Apktool Output Directory (optional):</label>
        <input type="text" class="form-control" id="apktool-output-path" 
               placeholder="Path to apktool decompiled output for file analysis">
    </div>
</div>
```

### **2. Backend API Implementation**

#### **Add to Valid Actions**
**File**: `automatool_ui/app.py`
**Location**: Line 208 in `valid_actions` list

```python
valid_actions = ['full-process', 'get-reviews', 'clean', 'mobsf', 'native-strings-analysis', 
                 'apkleaks', 'scan-base64', 'font-analysis', 'frida-fsmon-scan', 
                 'manifest-analysis', 'decompile-apk', 'apk-unmask-analysis']
```

#### **Add Route Handler**
**File**: `automatool_ui/app.py`
**Location**: Around line 238, add to the action routing

```python
elif action_name == 'apk-unmask-analysis':
    return handle_apk_unmask_analysis()
```

#### **Handler Function**
**File**: `automatool_ui/app.py`
**Location**: Add new function around line 800

```python
def handle_apk_unmask_analysis():
    """Handle standalone APK Unmask analysis execution."""
    try:
        # Check prerequisites
        if not app_state.get('setup_complete') or not app_state.get('APK_PATH') or not app_state.get('OUTPUT_DIR'):
            return jsonify({
                'success': False,
                'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
            })
        
        # Get options from request
        data = request.get_json() or {}
        enable_filtering = data.get('enable_filtering', True)
        enable_file_analysis = data.get('enable_file_analysis', False)
        apktool_output_dir = data.get('apktool_output_dir', None)
        
        # Start APK Unmask analysis
        success = process_manager.execute_apk_unmask_analysis(
            app_state['APK_PATH'],
            app_state['OUTPUT_DIR'],
            enable_filtering=enable_filtering,
            enable_file_analysis=enable_file_analysis,
            apktool_output_dir=apktool_output_dir,
            verbose=True
        )
        
        if success:
            message = 'APK Unmask analysis started successfully'
            if enable_file_analysis and not apktool_output_dir:
                message += ' (File analysis disabled - no apktool output directory provided)'
            
            return jsonify({
                'success': True,
                'message': message,
                'action': 'apk-unmask-analysis'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to start APK Unmask analysis'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'APK Unmask analysis failed: {str(e)}'
        })
```

### **3. Process Manager Integration**

#### **Add New Method**
**File**: `automatool_ui/utils/process_manager.py`

```python
def execute_apk_unmask_analysis(self, apk_path, output_dir, enable_filtering=True, 
                               enable_file_analysis=False, apktool_output_dir=None, verbose=True):
    """Execute standalone APK Unmask analysis with optional file type detection."""
    script_path = os.path.join("scripts", "automations", "run_standalone_apk_unmask.py")
    cmd = [
        'python', script_path,
        apk_path,
        output_dir
    ]
    
    # Add options
    if not enable_filtering:
        cmd.append('--disable-filtering')
    
    if enable_file_analysis and apktool_output_dir:
        cmd.extend(['--enable-file-analysis', '--apktool-output', apktool_output_dir])
    
    if verbose:
        cmd.append('--verbose')
    
    return self._run_process(cmd, "APK Unmask Analysis", self.automatool_path, timeout=self.default_timeout)
```

### **4. Create Standalone Script**

#### **New Script File**
**File**: `automatool_ui/scripts/automations/run_standalone_apk_unmask.py`

```python
#!/usr/bin/env python3
"""
Standalone APK Unmask Analysis Tool

Runs APK Unmask analysis with false positive filtering and optional file type detection.
Designed to work independently of the main automatool pipeline.
"""

import argparse
import sys
import os

# Add the automatool src path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'automatool', 'automatool', 'src'))

from scripts.automations.run_apk_unmask import run_apk_unmask
from scripts.automations.file_analyzer import is_file_command_available

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Standalone APK Unmask analysis with false positive filtering and file type detection",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "apk_path",
        help="Path to the APK file to analyze"
    )
    
    parser.add_argument(
        "output_dir", 
        help="Output directory for analysis results"
    )
    
    parser.add_argument(
        "--disable-filtering",
        action="store_true",
        help="Disable false positive filtering"
    )
    
    parser.add_argument(
        "--enable-file-analysis",
        action="store_true", 
        help="Enable file type analysis (requires apktool output)"
    )
    
    parser.add_argument(
        "--apktool-output",
        help="Path to apktool decompiled output directory for file analysis"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    return parser.parse_args()

def main():
    """Main entry point for standalone APK Unmask analysis."""
    args = parse_arguments()
    
    print("🎭 Starting Standalone APK Unmask Analysis")
    print(f"📱 APK: {args.apk_path}")
    print(f"📁 Output: {args.output_dir}")
    
    # Validate inputs
    if not os.path.exists(args.apk_path):
        print(f"❌ ERROR: APK file not found: {args.apk_path}")
        sys.exit(1)
    
    if not os.path.exists(args.output_dir):
        print(f"❌ ERROR: Output directory not found: {args.output_dir}")
        sys.exit(1)
    
    # Configuration
    enable_filtering = not args.disable_filtering
    enable_file_analysis = args.enable_file_analysis
    apktool_output_dir = args.apktool_output
    
    # Validate file analysis prerequisites
    if enable_file_analysis:
        if not apktool_output_dir:
            print("⚠️  WARNING: File analysis requested but no apktool output directory provided")
            print("            Disabling file analysis...")
            enable_file_analysis = False
        elif not os.path.exists(apktool_output_dir):
            print(f"⚠️  WARNING: Apktool output directory not found: {apktool_output_dir}")
            print("            Disabling file analysis...")
            enable_file_analysis = False
        elif not is_file_command_available():
            print("⚠️  WARNING: 'file' command not available on system")
            print("            Disabling file analysis...")
            enable_file_analysis = False
    
    # Display configuration
    print(f"🔍 False Positive Filtering: {'Enabled' if enable_filtering else 'Disabled'}")
    print(f"🔬 File Type Analysis: {'Enabled' if enable_file_analysis else 'Disabled'}")
    if enable_file_analysis:
        print(f"📂 Apktool Output: {apktool_output_dir}")
    
    try:
        # Run APK Unmask analysis
        output_path = run_apk_unmask(
            apk_path=args.apk_path,
            output_dir=args.output_dir,
            verbose=args.verbose,
            enable_filtering=enable_filtering,
            enable_file_analysis=enable_file_analysis,
            apktool_output_dir=apktool_output_dir
        )
        
        if output_path:
            print(f"✅ APK Unmask analysis completed successfully")
            print(f"📄 Output saved to: {output_path}")
            
            if enable_file_analysis:
                enhanced_path = output_path.replace('.txt', '_enhanced.txt')
                if os.path.exists(enhanced_path):
                    print(f"📄 Enhanced output with file types: {enhanced_path}")
        else:
            print("❌ APK Unmask analysis failed")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ ERROR: APK Unmask analysis failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### **5. Copy Required Dependencies**

Since the standalone tool will be in the UI directory, we need to copy the APK Unmask functionality:

#### **Copy APK Unmask Files**
**Location**: `automatool_ui/scripts/automations/`

Files to copy:
- `run_apk_unmask.py` (enhanced version with filtering and file analysis)
- `apk_unmask_filter.py` (filtering classes)
- `file_analyzer.py` (file type analysis)

#### **Copy Utils**
**Location**: `automatool_ui/scripts/utils/`

Files to copy:
- `apk_unmask_ignore_list.txt` (ignore list)
- `README.md` (ignore list documentation)

### **6. Update Main automatool.py**

#### **Remove APK Unmask from Main Flow**
**File**: `automatool/automatool/src/automatool.py`
**Action**: Remove or comment out lines 139-147

```python
# # Run apk_unmask - MOVED TO STANDALONE UI SERVICE
# apk_unmask_output_path = run_apk_unmask(apk_path, args.directory, args.verbose)
# if apk_unmask_output_path:
#     try:
#         resource_tracker.add_file(apk_unmask_output_path)
#     except Exception as e:
#         print(f"❌ ERROR: Failed to track apk_unmask output file: {e}")
#         if args.verbose:
#             print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
```

#### **Add Optional Flag (Alternative)**
If you want to keep it optional in main flow:

```python
parser.add_argument(
    "--enable-apk-unmask",
    action="store_true",
    help="Enable APK Unmask analysis in main flow (slower, use standalone UI service instead)"
)

# In main():
if args.enable_apk_unmask:
    apk_unmask_output_path = run_apk_unmask(apk_path, args.directory, args.verbose)
    # ... rest of tracking code
else:
    print("⏭️ Skipping APK Unmask analysis (use standalone UI service for this feature)")
```

### **7. UI Enhancements**

#### **Results Display**
**File**: `automatool_ui/templates/index.html`
**Location**: Add results section

```html
<div id="apk-unmask-results" class="results-section" style="display: none;">
    <h4>🎭 APK Unmask Analysis Results</h4>
    <div class="row">
        <div class="col-md-6">
            <h5>Standard Output</h5>
            <pre id="apk-unmask-standard-output" class="bg-light p-3"></pre>
        </div>
        <div class="col-md-6" id="apk-unmask-enhanced-section" style="display: none;">
            <h5>Enhanced Output (with File Types)</h5>
            <pre id="apk-unmask-enhanced-output" class="bg-light p-3"></pre>
        </div>
    </div>
    <div class="mt-3">
        <button class="btn btn-sm btn-secondary" onclick="downloadApkUnmaskResults()">
            📥 Download Results
        </button>
    </div>
</div>
```

#### **JavaScript Integration**
**File**: `automatool_ui/static/js/main.js`

```javascript
function handleApkUnmaskAnalysis() {
    const enableFiltering = document.getElementById('enable-filtering').checked;
    const enableFileAnalysis = document.getElementById('enable-file-analysis').checked;
    const apktoolOutputPath = document.getElementById('apktool-output-path').value;
    
    const options = {
        enable_filtering: enableFiltering,
        enable_file_analysis: enableFileAnalysis,
        apktool_output_dir: apktoolOutputPath || null
    };
    
    executeAction('apk-unmask-analysis', options);
}

function displayApkUnmaskResults(outputDir) {
    // Load and display results
    fetch(`/api/get-file-content?path=${outputDir}/apk_unmask_output.txt`)
        .then(response => response.text())
        .then(content => {
            document.getElementById('apk-unmask-standard-output').textContent = content;
            document.getElementById('apk-unmask-results').style.display = 'block';
        });
    
    // Check for enhanced output
    fetch(`/api/get-file-content?path=${outputDir}/apk_unmask_enhanced_output.txt`)
        .then(response => {
            if (response.ok) {
                return response.text();
            }
            throw new Error('Enhanced output not available');
        })
        .then(content => {
            document.getElementById('apk-unmask-enhanced-output').textContent = content;
            document.getElementById('apk-unmask-enhanced-section').style.display = 'block';
        })
        .catch(() => {
            // Enhanced output not available, hide section
            document.getElementById('apk-unmask-enhanced-section').style.display = 'none';
        });
}
```

## **Benefits of Standalone Implementation**

### **1. Performance Optimization**
- **Main Flow Speed**: Removes APK Unmask from main automation, keeping it fast
- **Focused Analysis**: Users can run APK Unmask when specifically needed
- **Resource Efficiency**: No unnecessary decompilation in main flow

### **2. Enhanced Functionality**
- **Full Feature Set**: Supports both filtering and file analysis
- **Flexible Configuration**: Users can enable/disable features as needed
- **Better Integration**: Works seamlessly with apktool output when available

### **3. User Experience**
- **Clear Separation**: Distinct tool for malicious file detection
- **Progressive Enhancement**: Basic analysis without decompilation, enhanced with it
- **Immediate Feedback**: Real-time results display in UI

### **4. Maintainability**
- **Modular Design**: Standalone tool is easier to maintain and update
- **Independent Testing**: Can be tested separately from main automation
- **Flexible Deployment**: Can be used independently or as part of larger workflow

## **Implementation Phases**

### **Phase 1: Core Standalone Service**
1. Create standalone script with all APK Unmask functionality
2. Copy required dependencies to UI directory
3. Add basic UI integration (button, API endpoint)
4. Remove from main automatool.py flow

### **Phase 2: Enhanced UI Integration**
1. Add configuration options in UI
2. Implement results display
3. Add download functionality
4. Enhance error handling and user feedback

### **Phase 3: Advanced Features**
1. Integration with decompilation service
2. Batch analysis capabilities
3. Historical results tracking
4. Advanced filtering options

## **Testing Strategy**

### **1. Functional Testing**
- Test standalone script with various APK files
- Test with and without apktool output
- Test filtering and file analysis features
- Test error handling scenarios

### **2. Integration Testing**
- Test UI button and API endpoints
- Test process manager integration
- Test results display and download
- Test configuration options

### **3. Performance Testing**
- Compare main automation speed before/after removal
- Test standalone tool performance
- Test with large APK files
- Test concurrent execution

## **Migration Path**

### **1. Immediate Benefits**
- Remove APK Unmask from main flow → faster automation
- Provide standalone APK Unmask service → focused analysis
- Maintain all existing functionality → no feature loss

### **2. User Communication**
- Update documentation to reflect new workflow
- Provide migration guide for existing users
- Highlight benefits of standalone approach

### **3. Backward Compatibility**
- Keep option to enable APK Unmask in main flow (with warning)
- Provide clear migration path to standalone service
- Maintain same output format and functionality

## **Success Metrics**

### **Quantitative Metrics**
- **Main Automation Speed**: >30% faster execution time
- **Standalone Usage**: High adoption rate of standalone service
- **Feature Completeness**: 100% feature parity with enhanced capabilities

### **Qualitative Metrics**
- **User Satisfaction**: Positive feedback on focused tool approach
- **Maintainability**: Easier to maintain and update standalone service
- **Flexibility**: Users can choose when and how to run APK Unmask analysis

## **Conclusion**

Moving APK Unmask to a standalone service in the UI addresses the core dependency and performance issues while providing enhanced functionality. This approach:

1. **Solves the Problem**: Removes slow decompilation dependency from main flow
2. **Enhances Functionality**: Enables full file analysis capabilities when needed
3. **Improves User Experience**: Provides focused, configurable analysis tool
4. **Maintains Performance**: Keeps main automation fast and efficient

The standalone service follows established patterns in the UI and provides a foundation for future enhancements while maintaining backward compatibility and user expectations.
