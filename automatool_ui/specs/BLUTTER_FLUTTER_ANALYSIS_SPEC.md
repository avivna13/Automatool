# 🦋 Blutter Flutter Analysis Automation Specification

## **Overview**

Add Blutter automation to the AutomatoolUI for decompiling Flutter applications' `libapp.so` files. This automation automatically locates `libapp.so` files from previous APK decompilation, uses Blutter to extract Dart code and assemblies, generates Frida scripts, and integrates with the resource tracking system for proper cleanup management.

## **Background**

### **What is Blutter?**
Blutter is a Flutter Mobile Application Reverse Engineering Tool that compiles Dart AOT Runtime to analyze Flutter applications. It extracts:
- **Assembly files** with symbols from `libapp.so`
- **Frida script templates** for dynamic analysis
- **Object pool dumps** showing Dart objects
- **Complete nested dumps** of objects

### **Integration Context**
- **Prerequisites**: APK decompilation must run first to extract `libapp.so`
- **Target Files**: `output_directory/apktool_output/lib/arm64-v8a/libapp.so`
- **Output Location**: `output_directory/blutter_output/`
- **Resource Tracking**: All created files and directories are tracked for cleanup

## **Technical Requirements**

### **Dependencies**
- **Blutter Tool**: Located at `automatool/automatool/src/blutter/`
- **Python 3**: Required for Blutter execution
- **Native Libraries**: `libapp.so` from Flutter applications
- **Resource Tracker**: For cleanup integration

### **File Structure After Integration**
```
automatool_ui/
├── utils/process_manager.py          # Add execute_blutter_analysis()
├── app.py                           # Add handler and route
├── templates/index.html             # Add UI button
└── specs/BLUTTER_FLUTTER_ANALYSIS_SPEC.md

automatool/automatool/src/
├── blutter/                         # Existing Blutter tool
│   ├── blutter.py
│   └── README.md
└── scripts/automations/
    └── run_blutter_analysis.py     # New automation script
```

## **Implementation Specification**

### **Phase 1: Standalone Blutter Script with Resource Tracking**

**File**: `automatool/automatool/src/scripts/automations/run_blutter_analysis.py`

#### **Key Features**
- **Smart Detection**: Automatically finds `libapp.so` in expected location
- **Resource Tracking**: Integrates with `GlobalResourceTracker` for cleanup
- **Error Handling**: Clear messages for missing files or failures
- **Verbose Output**: Detailed logging for debugging

#### **Script Structure**
```python
#!/usr/bin/env python3
"""
Blutter Flutter Analysis Script with Resource Tracking
Decompiles Flutter libapp.so files using Blutter tool and tracks created resources for cleanup.
"""

import argparse
import os
import sys
import subprocess
from resource_tracker import GlobalResourceTracker

def run_blutter_analysis(output_dir, verbose=False):
    """
    Run Blutter analysis on libapp.so from APK decompilation output.
    
    Args:
        output_dir (str): Directory containing apktool_output with lib files
        verbose (bool): Enable verbose output
        
    Returns:
        dict: Results with success status and output paths
    """
    if verbose:
        print("🦋 Starting Blutter Flutter analysis...")
    
    # Initialize resource tracker
    tracker = None
    try:
        tracker = GlobalResourceTracker()
        if verbose:
            print("🔧 Resource tracker initialized")
    except Exception as e:
        print(f"⚠️  WARNING: Could not initialize resource tracker: {e}")
    
    # Build path to lib directory from apktool output
    lib_dir = os.path.join(output_dir, "apktool_output", "lib", "arm64-v8a")
    libapp_path = os.path.join(lib_dir, "libapp.so")
    
    # Check if libapp.so exists
    if not os.path.exists(libapp_path):
        if verbose:
            print(f"❌ libapp.so not found at: {libapp_path}")
            print("💡 This may not be a Flutter app or APK decompilation hasn't run yet")
        return {
            'success': False,
            'error': 'libapp.so not found - not a Flutter app or decompilation needed first',
            'output_dir': None
        }
    
    # Create Blutter output directory
    blutter_output_dir = os.path.join(output_dir, "blutter_output")
    os.makedirs(blutter_output_dir, exist_ok=True)
    
    # Track the output directory for cleanup
    if tracker:
        try:
            tracker.add_directory(blutter_output_dir)
            if verbose:
                print(f"📁 Tracked directory for cleanup: {blutter_output_dir}")
        except Exception as e:
            print(f"⚠️  WARNING: Failed to track directory: {e}")
    
    # Get Blutter script path (relative to current script location)
    current_dir = os.path.dirname(os.path.abspath(__file__))
    blutter_script = os.path.join(current_dir, "..", "..", "blutter", "blutter.py")
    
    if verbose:
        print(f"📁 Lib directory: {lib_dir}")
        print(f"📱 libapp.so found: {libapp_path}")
        print(f"📂 Output directory: {blutter_output_dir}")
        print(f"🔧 Blutter script: {blutter_script}")
    
    # Run Blutter
    try:
        cmd = ["python3", blutter_script, lib_dir, blutter_output_dir]
        if verbose:
            print(f"[DEBUG] Running command: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            cwd=os.path.dirname(blutter_script)
        )
        
        if verbose:
            print("✅ Blutter completed successfully")
            if result.stdout.strip():
                print(f"[DEBUG] Blutter stdout: {result.stdout.strip()}")
        
        # Track individual output files for cleanup
        if tracker:
            try:
                # Track common Blutter output files
                output_files = [
                    os.path.join(blutter_output_dir, "blutter_frida.js"),
                    os.path.join(blutter_output_dir, "objs.txt"),
                    os.path.join(blutter_output_dir, "pp.txt")
                ]
                
                for file_path in output_files:
                    if os.path.exists(file_path):
                        tracker.add_file(file_path)
                        if verbose:
                            print(f"📄 Tracked file for cleanup: {os.path.basename(file_path)}")
                
                # Track asm directory if it exists
                asm_dir = os.path.join(blutter_output_dir, "asm")
                if os.path.exists(asm_dir):
                    tracker.add_directory(asm_dir)
                    if verbose:
                        print(f"📁 Tracked asm directory for cleanup")
                        
            except Exception as e:
                print(f"⚠️  WARNING: Failed to track output files: {e}")
        
        return {
            'success': True,
            'output_dir': blutter_output_dir,
            'lib_path': libapp_path
        }
        
    except FileNotFoundError:
        error_msg = "Blutter script not found or Python3 not available"
        if verbose:
            print(f"❌ ERROR: {error_msg}")
        return {'success': False, 'error': error_msg, 'output_dir': None}
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Blutter failed with exit code {e.returncode}"
        if verbose:
            print(f"❌ ERROR: {error_msg}")
            print(f"[DEBUG] Stderr: {e.stderr}")
        return {'success': False, 'error': error_msg, 'output_dir': None}

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Flutter Blutter Analysis with Resource Tracking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/output/dir
  %(prog)s /path/to/output/dir --verbose
        """
    )
    
    parser.add_argument(
        "output_dir",
        help="Output directory containing apktool_output with lib files"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    return parser.parse_args()

def main():
    """Main entry point for standalone execution."""
    args = parse_arguments()
    
    print("🦋 Starting Blutter Flutter Analysis")
    print(f"📁 Output directory: {args.output_dir}")
    
    if not os.path.exists(args.output_dir):
        print(f"❌ ERROR: Output directory not found: {args.output_dir}")
        sys.exit(1)
    
    try:
        result = run_blutter_analysis(args.output_dir, args.verbose)
        
        if result['success']:
            print(f"✅ Blutter analysis completed successfully")
            print(f"📂 Results saved to: {result['output_dir']}")
            print("🧹 Resources tracked for cleanup - use cleanup automation to remove later")
        else:
            print(f"❌ Blutter analysis failed: {result['error']}")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ ERROR: Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### **Phase 2: Backend Integration**

#### **2.1 Process Manager Method**
**File**: `automatool_ui/utils/process_manager.py`
**Location**: Add after existing automation methods

```python
def execute_blutter_analysis(self, output_dir, verbose=True):
    """Execute Blutter Flutter analysis on libapp.so files."""
    script_path = os.path.join("scripts", "automations", "run_blutter_analysis.py")
    cmd = [
        'python', script_path,
        output_dir
    ]
    
    if verbose:
        cmd.append('--verbose')
    
    return self._run_process(cmd, "Blutter Flutter Analysis", self.automatool_path, timeout=300)  # 5 min timeout
```

#### **2.2 API Handler Integration**
**File**: `automatool_ui/app.py`

##### **Add to Valid Actions** (around line 208):
```python
valid_actions = ['full-process', 'get-reviews', 'clean', 'mobsf', 'native-strings-analysis', 
                 'apkleaks', 'scan-base64', 'font-analysis', 'frida-fsmon-scan', 
                 'manifest-analysis', 'decompile-apk', 'apk-unmask-analysis', 
                 'blutter-analysis']
```

##### **Add Route Handler** (around line 238):
```python
elif action_name == 'blutter-analysis':
    return handle_blutter_analysis()
```

##### **Add Handler Function** (around line 700+):
```python
def handle_blutter_analysis():
    """Handle Blutter Flutter analysis execution."""
    try:
        # Check prerequisites
        if not app_state.get('setup_complete') or not app_state.get('OUTPUT_DIR'):
            return jsonify({
                'success': False,
                'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
            })
        
        # Start Blutter analysis
        success = process_manager.execute_blutter_analysis(
            app_state['OUTPUT_DIR'],
            verbose=True
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Blutter Flutter analysis started successfully. Results will be tracked for cleanup.',
                'action': 'blutter-analysis',
                'cleanup_info': 'Output files and directories are automatically tracked and can be cleaned up using the cleanup automation.'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to start Blutter analysis'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Blutter analysis failed: {str(e)}'
        })
```

### **Phase 3: Frontend Integration**

#### **3.1 UI Button**
**File**: `automatool_ui/templates/index.html`
**Location**: Add in "Analysis Actions" section

```html
<button class="btn btn-info action-btn" data-action="blutter-analysis"
        {% if not state.setup_complete %}disabled{% endif %}
        title="Analyze Flutter libapp.so files - Results will be tracked for cleanup">
    🦋 Blutter Flutter Analysis
</button>
```

#### **3.2 JavaScript Integration**
The existing JavaScript automatically handles buttons with `action-btn` class. No special handling needed unless custom behavior is required.

## **Resource Tracking Integration**

### **How It Works**

#### **1. Automatic Resource Tracking**
- **Directory Tracking**: The main `blutter_output/` directory is tracked
- **File Tracking**: Individual output files (`blutter_frida.js`, `objs.txt`, `pp.txt`) are tracked
- **Subdirectory Tracking**: The `asm/` directory containing assembly files is tracked

#### **2. Resource Tracking Flow**
```
1. Blutter automation runs
   ↓
2. Creates blutter_output/ directory
   ↓
3. Tracks directory with resource_tracker.add_directory()
   ↓
4. Blutter generates files (frida script, assemblies, etc.)
   ↓
5. Tracks individual files with resource_tracker.add_file()
   ↓
6. Resources are stored in automation_resources.json
   ↓
7. Later: Cleanup automation can remove all tracked resources
```

#### **3. Tracked Resources**
- **Main Directory**: `output_directory/blutter_output/`
- **Assembly Directory**: `output_directory/blutter_output/asm/`
- **Frida Script**: `output_directory/blutter_output/blutter_frida.js`
- **Object Dumps**: `output_directory/blutter_output/objs.txt`
- **Dart Objects**: `output_directory/blutter_output/pp.txt`

#### **4. Cleanup Integration**
The existing cleanup automation will automatically handle Blutter resources:
- **Files**: Individual tracked files will be deleted
- **Directories**: The entire `blutter_output/` directory and subdirectories will be removed
- **Preservation**: Uses existing `_should_preserve_file()` logic if needed

## **Expected Output Structure**

### **Before Blutter Analysis**
```
output_directory/
├── apktool_output/          # From previous decompilation
│   ├── AndroidManifest.xml
│   ├── assets/
│   ├── res/
│   ├── smali/
│   └── lib/
│       └── arm64-v8a/
│           └── libapp.so    # Input file for Blutter
└── jadx_output/             # From previous decompilation
    └── sources/
```

### **After Blutter Analysis**
```
output_directory/
├── apktool_output/          # Existing
│   └── lib/arm64-v8a/
│       └── libapp.so        # Input file
├── jadx_output/             # Existing
└── blutter_output/          # New Blutter results
    ├── asm/                 # Assembly files with symbols
    │   ├── libapp_0x1000.s
    │   ├── libapp_0x2000.s
    │   └── ...
    ├── blutter_frida.js     # Generated Frida script template
    ├── objs.txt            # Complete object pool dump
    └── pp.txt              # Dart objects in object pool
```

## **User Workflow**

### **Complete Analysis Flow**
1. **Upload APK** and run initial setup
2. **Run APK Decompilation** (extracts `libapp.so`)
3. **Run Blutter Analysis** (analyzes Flutter components)
4. **Review Results** in `blutter_output/` directory
5. **Use Generated Frida Script** for dynamic analysis (optional)
6. **Run Cleanup** when analysis is complete

### **Prerequisites Check**
- ✅ APK uploaded and setup complete
- ✅ APK decompilation has run (creates `apktool_output/`)
- ✅ `libapp.so` exists in `lib/arm64-v8a/` directory
- ✅ Application is a Flutter app

## **Error Handling**

### **Common Error Scenarios**
| Error | Cause | Solution |
|-------|-------|----------|
| libapp.so not found | Not a Flutter app or decompilation not run | Run APK decompilation first |
| Blutter script not found | Blutter not properly installed | Check Blutter installation in src/blutter/ |
| Python3 not available | Missing Python 3 | Install Python 3 and ensure it's in PATH |
| Permission denied | File access issues | Check file permissions |
| Timeout | Large libapp.so file | Increase timeout in process_manager |

### **Error Messages**
- **Clear Feedback**: Descriptive error messages for each failure scenario
- **Actionable Guidance**: Suggestions for resolving issues
- **Debug Information**: Verbose output for troubleshooting

## **Testing Strategy**

### **Unit Testing**
```python
# test_blutter_analysis.py
import unittest
from unittest.mock import patch, MagicMock
from utils.process_manager import ProcessManager

class TestBlutterAnalysis(unittest.TestCase):
    def setUp(self):
        self.process_manager = ProcessManager()
    
    @patch('utils.process_manager.ProcessManager._run_process')
    def test_execute_blutter_analysis_success(self, mock_run):
        mock_run.return_value = True
        
        result = self.process_manager.execute_blutter_analysis(
            '/test/output',
            verbose=True
        )
        
        self.assertTrue(result)
        mock_run.assert_called_once()
```

### **Integration Testing**
1. **Manual UI Testing**: Test complete workflow through web interface
2. **API Testing**: Test endpoint with curl/Postman
3. **Standalone Testing**: Test script independently
4. **Resource Tracking Testing**: Verify cleanup integration

### **Test Cases**
- ✅ Flutter app with valid `libapp.so`
- ❌ Non-Flutter app (no `libapp.so`)
- ❌ Missing APK decompilation
- ❌ Blutter tool not available
- ✅ Resource tracking functionality
- ✅ Cleanup integration

## **Performance Considerations**

### **Execution Time**
- **Typical Duration**: 1-5 minutes depending on `libapp.so` size
- **Timeout Setting**: 5 minutes (300 seconds)
- **Resource Usage**: CPU-intensive during analysis

### **Storage Requirements**
- **Input**: `libapp.so` (varies, typically 10-100MB)
- **Output**: Assembly files, scripts, dumps (typically 50-200MB)
- **Cleanup**: All output tracked for removal

## **Security Considerations**

### **Input Validation**
- **Path Sanitization**: Prevent path traversal attacks
- **File Validation**: Verify `libapp.so` is valid binary
- **Command Injection**: Use parameterized commands

### **Resource Management**
- **Timeout Protection**: Prevent infinite execution
- **Disk Space**: Monitor output directory size
- **Process Isolation**: Run in controlled environment

## **Benefits and Use Cases**

### **Benefits**
- **Automated Flutter Analysis**: No manual Blutter setup required
- **Integrated Workflow**: Seamless integration with existing APK analysis
- **Resource Management**: Automatic tracking and cleanup
- **Frida Integration**: Generated scripts ready for dynamic analysis
- **Comprehensive Output**: Assembly, objects, and analysis data

### **Use Cases**
- **Flutter App Reverse Engineering**: Analyze Dart code and structure
- **Dynamic Analysis Preparation**: Generate Frida scripts for runtime analysis
- **Security Research**: Understand Flutter app internals
- **Malware Analysis**: Analyze malicious Flutter applications
- **Code Auditing**: Review Flutter application implementation

## **Future Enhancements**

### **Potential Improvements**
- **iOS Support**: Extend to analyze iOS Flutter binaries
- **Advanced Filtering**: Filter output based on analysis goals
- **Report Generation**: Create structured analysis reports
- **Integration with Other Tools**: Connect with additional reverse engineering tools
- **Batch Processing**: Analyze multiple Flutter apps simultaneously

### **Configuration Options**
- **Analysis Depth**: Configure level of analysis detail
- **Output Format**: Choose output formats (JSON, XML, etc.)
- **Custom Scripts**: Allow custom Blutter configurations

## **Conclusion**

This specification provides a comprehensive framework for integrating Blutter Flutter analysis into the AutomatoolUI. The implementation follows established patterns, includes proper resource tracking for cleanup, and provides a seamless user experience for Flutter application reverse engineering.

### **Key Takeaways**
1. **Simple Integration**: Follows existing automation patterns
2. **Resource Tracking**: Proper cleanup integration
3. **Error Handling**: Comprehensive error management
4. **User-Friendly**: Clear workflow and feedback
5. **Extensible**: Foundation for future enhancements

---

**Implementation Status**: ⏳ Specification Complete - Ready for Implementation
**Priority**: 🔥 High - Flutter analysis is increasingly important
**Complexity**: 🟡 Medium - Straightforward integration following existing patterns
