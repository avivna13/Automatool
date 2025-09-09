# 🔧 APK Decompilation Standalone Service Specification

## **Overview**
Extract the APK decompilation functionality (apktool + Jadx) from the main `automatool.py` execution flow and create it as a standalone service in the web UI. This allows users to perform decompilation analysis independently without running the full automation pipeline.

## **Current State Analysis**

### **Current Implementation in automatool.py**
Currently, decompilation is embedded in the main execution flow:

```python
# Lines 151-179 in automatool.py
decompilation_results = run_apktool_decode(apk_path, args.directory, args.verbose)

# Track both output directories if available
apktool_output_path = None
jadx_output_path = None

if decompilation_results['apktool_output']:
    resource_tracker.add_directory(decompilation_results['apktool_output'])
    apktool_output_path = decompilation_results['apktool_output']

if decompilation_results['jadx_output']:
    resource_tracker.add_directory(decompilation_results['jadx_output'])
    jadx_output_path = decompilation_results['jadx_output']
```

### **Decompilation Function Details**
- **Script**: `automatool/automatool/src/scripts/automations/run_apktool_decode.py`
- **Function**: `run_apktool_decode(apk_path, output_directory, verbose=False)`
- **Tools**: Combined apktool + Jadx execution
- **Output Structure**:
  ```
  output_directory/
  ├── apktool_output/          # Resources, manifest, Smali
  │   ├── AndroidManifest.xml
  │   ├── assets/
  │   ├── res/
  │   └── smali/
  └── jadx_output/             # Java source code
      └── sources/
          └── com/
              └── example/
                  └── app/
                      ├── MainActivity.java
                      └── ...
  ```

## **Specification for Standalone Service**

### **1. UI Integration**

#### **Add New Action Button**
**File**: `automatool_ui/templates/index.html`
**Location**: In the "Analysis Actions" panel (around line 129)

```html
<button class="btn btn-primary action-btn" data-action="decompile-apk"
        {% if not state.setup_complete %}disabled{% endif %}>
    🔧 Decompile APK (apktool + Jadx)
</button>
```

### **2. Backend API Implementation**

#### **Add to Valid Actions**
**File**: `automatool_ui/app.py`
**Location**: Line 208 in `valid_actions` list

```python
valid_actions = ['full-process', 'get-reviews', 'clean', 'mobsf', 'native-strings-analysis', 
                 'apkleaks', 'scan-base64', 'font-analysis', 'frida-fsmon-scan', 
                 'manifest-analysis', 'decompile-apk']
```

#### **Add Route Handler**
**File**: `automatool_ui/app.py`
**Location**: Around line 235, add to the action routing

```python
elif action_name == 'decompile-apk':
    return handle_decompile_apk()
```

#### **Handler Function**
**File**: `automatool_ui/app.py`
**Location**: Add new function around line 633

```python
def handle_decompile_apk():
    """Handle standalone APK decompilation execution."""
    # Check prerequisites
    if not app_state.get('setup_complete') or not app_state.get('APK_PATH') or not app_state.get('OUTPUT_DIR'):
        return jsonify({
            'success': False,
            'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
        })
    
    # Start decompilation
    success = process_manager.execute_decompile_apk(
        app_state['APK_PATH'],
        app_state['OUTPUT_DIR'], 
        verbose=True
    )
    
    if success:
        return jsonify({
            'success': True,
            'message': 'APK decompilation started successfully',
            'action': 'decompile-apk'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Failed to start APK decompilation'
        })
```

### **3. Process Manager Integration**

#### **Add New Method**
**File**: `automatool_ui/utils/process_manager.py`
**Location**: Add new method around line 140

```python
def execute_decompile_apk(self, apk_path, output_dir, verbose=True):
    """Execute standalone APK decompilation using apktool + Jadx."""
    script_path = os.path.join("scripts", "automations", "run_apktool_decode.py")
    cmd = [
        'python', script_path,
        apk_path,
        output_dir
    ]
    if verbose:
        cmd.append('--verbose')
    
    return self._run_process(cmd, "APK Decompilation", self.automatool_path, timeout=self.default_timeout)
```

### **4. Standalone Script Wrapper**

#### **Create Standalone Script**
**File**: `automatool/automatool/src/scripts/automations/run_standalone_decompilation.py`

```python
#!/usr/bin/env python3
"""
Standalone APK Decompilation Script
Wrapper for run_apktool_decode.py to be used independently from main automatool flow.
"""

import argparse
import os
import sys
from run_apktool_decode import run_apktool_decode, get_decompilation_summary

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Standalone APK decompilation using apktool + Jadx",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/app.apk /path/to/output/dir
  %(prog)s /path/to/app.apk /path/to/output/dir --verbose
        """
    )
   
    parser.add_argument(
        "apk_path",
        help="Path to the APK file to decompile"
    )
   
    parser.add_argument(
        "output_directory", 
        help="Output directory for decompilation results"
    )
   
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output for debugging"
    )
   
    return parser.parse_args()

def main():
    """Main entry point for standalone decompilation."""
    print("🔧 Starting standalone APK decompilation...")
   
    # Parse command line arguments
    args = parse_arguments()
   
    # Validate APK file exists
    if not os.path.exists(args.apk_path):
        print(f"❌ ERROR: APK file not found: {args.apk_path}")
        sys.exit(1)
   
    # Create output directory if it doesn't exist
    os.makedirs(args.output_directory, exist_ok=True)
   
    if args.verbose:
        print(f"[DEBUG] APK path: {args.apk_path}")
        print(f"[DEBUG] Output directory: {args.output_directory}")
   
    # Run decompilation
    try:
        results = run_apktool_decode(args.apk_path, args.output_directory, args.verbose)
        
        # Print summary
        if args.verbose:
            print("\n" + get_decompilation_summary(results))
        
        # Check results
        if results['success'] or (results['apktool_output'] or results['jadx_output']):
            print("✅ Decompilation completed successfully")
            
            if results['apktool_output']:
                print(f"📦 apktool output: {results['apktool_output']}")
            
            if results['jadx_output']:
                print(f"☕ Jadx output: {results['jadx_output']}")
                
            if results['errors']:
                print("⚠️ Some errors occurred:")
                for error in results['errors']:
                    print(f"  - {error}")
                    
            sys.exit(0)
        else:
            print("❌ Decompilation failed")
            if results['errors']:
                for error in results['errors']:
                    print(f"❌ {error}")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ ERROR: Decompilation failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### **5. Update Process Manager to Use Standalone Script**

#### **Modify Process Manager Method**
**File**: `automatool_ui/utils/process_manager.py`

```python
def execute_decompile_apk(self, apk_path, output_dir, verbose=True):
    """Execute standalone APK decompilation using apktool + Jadx."""
    script_path = os.path.join("scripts", "automations", "run_standalone_decompilation.py")
    cmd = [
        'python', script_path,
        apk_path,
        output_dir
    ]
    if verbose:
        cmd.append('--verbose')
    
    return self._run_process(cmd, "APK Decompilation", self.automatool_path, timeout=self.default_timeout)
```

## **Benefits of Standalone Implementation**

### **1. Modularity**
- Decompilation can be run independently
- No need to run full automatool pipeline
- Faster execution for users who only need decompilation

### **2. Resource Efficiency**
- Doesn't launch Jadx GUI, VS Code, or other heavy tools
- Focused on just the decompilation task
- Lower resource consumption

### **3. Better User Experience**
- Clear, focused functionality
- Immediate feedback on decompilation results
- Can be used as a building block for other analyses

### **4. Consistency with Existing Patterns**
- Follows same UI patterns as other standalone features
- Uses existing process management infrastructure
- Consistent error handling and logging

## **Integration with Main automatool.py**

### **Remove from Main Flow (Optional)**
If desired, the decompilation can be removed from the main `automatool.py` execution and replaced with a call to the standalone service. This would require:

1. **Modify automatool.py**: Replace lines 151-179 with a conditional call
2. **Add flag**: `--skip-decompilation` to skip decompilation in main flow
3. **Update documentation**: Reflect that decompilation is now optional in main flow

### **Keep in Main Flow (Recommended)**
For backward compatibility and complete automation, keep decompilation in the main flow but also provide it as a standalone option.

## **Testing Strategy**

### **1. Unit Testing**
- Test standalone script with various APK files
- Test error handling for missing tools (apktool, jadx)
- Test output directory creation and permissions

### **2. Integration Testing**
- Test UI button functionality
- Test process manager integration
- Test API endpoint responses

### **3. End-to-End Testing**
- Upload APK via UI
- Click decompilation button
- Verify output directories are created
- Verify decompilation results are accessible

## **Implementation Priority**

### **Phase 1: Core Functionality**
1. Create standalone script
2. Add process manager method
3. Add UI button and API endpoint
4. Basic testing

### **Phase 2: Enhancement**
1. Add progress indicators
2. Enhance error handling
3. Add result preview in UI
4. Performance optimization

### **Phase 3: Integration**
1. Optional removal from main flow
2. Advanced configuration options
3. Integration with other standalone services
4. Comprehensive documentation

## **Dependencies**

### **System Requirements**
- `apktool` command-line tool installed
- `jadx` command-line tool installed
- Python 3.x with subprocess support

### **Python Dependencies**
- No additional Python packages required
- Uses existing automatool infrastructure

## **Error Handling**

### **Common Error Scenarios**
1. **Missing Tools**: apktool or jadx not installed
2. **Permission Issues**: Cannot write to output directory
3. **Corrupted APK**: Invalid or corrupted APK file
4. **Disk Space**: Insufficient disk space for output

### **Error Response Format**
```json
{
    "success": false,
    "message": "Decompilation failed: apktool command not found",
    "error": "TOOL_NOT_FOUND",
    "details": "Please install apktool and ensure it's in your system PATH"
}
```

## **Security Considerations**

### **Input Validation**
- Validate APK file paths to prevent directory traversal
- Sanitize output directory paths
- Verify APK file integrity before processing

### **Resource Limits**
- Set reasonable timeout values for decompilation
- Monitor disk space usage
- Limit concurrent decompilation processes

## **Future Enhancements**

### **Advanced Features**
1. **Selective Decompilation**: Choose apktool only, Jadx only, or both
2. **Custom Parameters**: Allow custom flags for apktool/Jadx
3. **Result Preview**: Show decompilation results in web UI
4. **Download Results**: Zip and download decompilation output
5. **Progress Tracking**: Real-time progress updates during decompilation

### **Integration Opportunities**
1. **With Base64 Scanner**: Auto-scan decompiled Java code
2. **With String Analysis**: Auto-analyze decompiled output
3. **With Code Review Tools**: Integration with static analysis
4. **With AI Analysis**: Send decompiled code to Gemini for analysis

This specification provides a complete roadmap for implementing APK decompilation as a standalone service while maintaining compatibility with the existing automatool ecosystem.
