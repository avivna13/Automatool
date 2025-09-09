# 🧹 Standalone Resource Tracking Integration Specification

## **Overview**

This specification outlines the integration of resource tracking into standalone automations using the existing `GlobalResourceTracker` class. Instead of complex pattern-based discovery, each standalone automation will directly track its own resources as they are created, leveraging the existing global `automation_resources.json` file.

## **Problem Statement**

Currently, standalone automations run through `automatool_ui` generate resources that are **not tracked** by the `GlobalResourceTracker`, leading to:
- **Incomplete cleanup**: Resources accumulate over time without being cleaned up
- **Inconsistent behavior**: Full automation cleans up resources, standalone automations don't
- **Disk space waste**: Untracked resources consume disk space indefinitely

## **Solution Approach**

**Use the existing `GlobalResourceTracker` directly in each standalone automation** - this is the simplest and most reliable approach because:

1. ✅ **Already designed for this**: `GlobalResourceTracker` uses a global JSON file that any instance can read/write to
2. ✅ **Simpler implementation**: No complex pattern matching needed
3. ✅ **More reliable**: Direct tracking is more accurate than discovery
4. ✅ **Immediate tracking**: Resources tracked as they're created
5. ✅ **Existing cleanup works**: Current cleanup system will handle all tracked resources

## **How GlobalResourceTracker Works**

The `GlobalResourceTracker` is already designed for multiple instances:

```python
class GlobalResourceTracker:
    def __init__(self):
        # Uses a GLOBAL file: automation_resources.json
        self.resources_file = os.path.join(self.workspace_root, "automation_resources.json")
        self.resources = self._load_or_create_resources()  # Loads existing data
```

**Key Features:**
- **Shared JSON file**: All instances read/write to the same `automation_resources.json`
- **Automatic merging**: New instances load existing data and add to it
- **Thread-safe**: Each operation saves immediately with `_save_resources()`
- **Current run tracking**: Uses `current_run` to accumulate resources from multiple sources

## **Standalone Automations Requiring Integration**

### **High Priority** (Large resource footprint)

| Automation | Script | Resources Created | Priority |
|------------|--------|-------------------|----------|
| **APK Decompilation** | `run_standalone_decompilation.py` | `apktool_output/`, `jadx_output/` directories | 🔴 High |
| **APK Unmask Analysis** | `run_apk_unmask.py` | `apk_unmask_output.txt`, `apk_unmask_file_analysis.txt` | 🔴 High |
| **Native Strings Analysis** | `run_strings_on_so_files.py` | `native_libs_strings/` directory with `.txt` files | 🔴 High |
| **MobSF Analysis** | `_mobsf_analysis_worker.py` | `mobsf_results/` directory with analysis reports | 🔴 High |

### **Medium Priority**

| Automation | Script | Resources Created | Priority |
|------------|--------|-------------------|----------|
| **Font Analysis** | `_font_analysis_worker.py` | `font_analysis/` directory with analysis reports | 🟡 Medium |
| **Base64 Scanner** | Handled in `app.py` | `base64_scan_results_*.json`, `base64_scan_summary_*.txt` | 🟡 Medium |
| **APKLeaks** | `run_apkleaks.py` | APKLeaks output files | 🟡 Medium |

### **Low Priority** (Small files)

| Automation | Script | Resources Created | Priority |
|------------|--------|-------------------|----------|
| **Frida-FSMon Scan** | Handled in `ProcessManager` | `frida_scan.txt`, `fsmon_scan.txt` | 🟢 Low |
| **Manifest Analysis** | AMAnDe via `ProcessManager` | `manifest_analysis.txt` | 🟢 Low |

## **Implementation Pattern**

### **Standard Integration Pattern**

Each standalone automation follows this pattern:

```python
#!/usr/bin/env python3
"""
Standalone Automation with Resource Tracking
"""

import os
import sys
from scripts.automations.resource_tracker import GlobalResourceTracker

def run_standalone_automation(input_path, output_dir, verbose=False):
    """Main automation function with resource tracking."""
    
    # Initialize resource tracker (loads existing global state)
    tracker = GlobalResourceTracker()
    
    try:
        if verbose:
            print("🔧 Resource tracker initialized")
        
        # Perform automation work
        result_file = os.path.join(output_dir, "automation_output.txt")
        result_dir = os.path.join(output_dir, "automation_results")
        
        # ... automation logic here ...
        
        # Track resources as they are created
        if os.path.exists(result_file):
            tracker.add_file(result_file)
            if verbose:
                print(f"📄 Tracked file: {result_file}")
        
        if os.path.exists(result_dir):
            tracker.add_directory(result_dir)
            if verbose:
                print(f"📁 Tracked directory: {result_dir}")
        
        print("✅ Automation completed and resources tracked")
        return result_file
        
    except Exception as e:
        print(f"❌ Automation failed: {e}")
        if verbose:
            print(f"⚠️  Resources may have been partially tracked")
        raise

if __name__ == "__main__":
    # Command line interface
    import argparse
    parser = argparse.ArgumentParser(description="Standalone automation with resource tracking")
    parser.add_argument("input_path", help="Input file path")
    parser.add_argument("output_dir", help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    run_standalone_automation(args.input_path, args.output_dir, args.verbose)
```

## **Specific Implementation Examples**

### **1. APK Decompilation** (`run_standalone_decompilation.py`)

```python
def main():
    """Main entry point for standalone decompilation."""
    print("🔧 Starting standalone APK decompilation...")
   
    # Parse command line arguments
    args = parse_arguments()
    
    # Initialize resource tracker
    tracker = GlobalResourceTracker()
   
    # Validate APK file exists
    if not os.path.exists(args.apk_path):
        print(f"❌ ERROR: APK file not found: {args.apk_path}")
        sys.exit(1)
   
    # Create output directory if it doesn't exist
    os.makedirs(args.output_directory, exist_ok=True)
   
    if args.verbose:
        print(f"[DEBUG] APK path: {args.apk_path}")
        print(f"[DEBUG] Output directory: {args.output_directory}")
        print("🔧 Resource tracker initialized")
   
    # Run decompilation
    try:
        results = run_apktool_decode(args.apk_path, args.output_directory, args.verbose)
        
        # Track created directories
        if results['apktool_output']:
            tracker.add_directory(results['apktool_output'])
            if args.verbose:
                print(f"📁 Tracked apktool directory: {results['apktool_output']}")
        
        if results['jadx_output']:
            tracker.add_directory(results['jadx_output'])
            if args.verbose:
                print(f"📁 Tracked Jadx directory: {results['jadx_output']}")
        
        # Print summary
        if args.verbose:
            print("\n" + get_decompilation_summary(results))
        
        # Check results
        if results['success'] or (results['apktool_output'] or results['jadx_output']):
            print("✅ Decompilation completed successfully and resources tracked")
            # ... rest of success handling
        else:
            print("❌ Decompilation failed")
            # ... rest of error handling
            
    except Exception as e:
        print(f"❌ ERROR: Decompilation failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
```

### **2. APK Unmask Analysis** (`run_apk_unmask.py`)

```python
def run_apk_unmask(apk_path, output_dir, verbose=False, enable_filtering=True, enable_file_analysis=False, apktool_output_dir=None):
    """
    Runs the apk_unmask tool with resource tracking.
    """
    # Initialize resource tracker
    tracker = GlobalResourceTracker()
    
    if verbose:
        print("🎭 Running apk_unmask analysis...")
        print("🔧 Resource tracker initialized")

    # ... existing apk_unmask logic ...

    output_file_path = os.path.join(output_dir, "apk_unmask_output.txt")
    
    try:
        # ... existing command execution ...
        
        # Save output and track file
        with open(output_file_path, "w") as f:
            f.write(filtered_output if enable_filtering else raw_output)
        
        # Track the output file
        tracker.add_file(output_file_path)
        if verbose:
            print(f"📄 Tracked file: {output_file_path}")
        
        # File analysis integration
        if enable_file_analysis:
            file_analysis_path = os.path.join(output_dir, "apk_unmask_file_analysis.txt")
            # ... file analysis logic ...
            
            # Track file analysis output
            if os.path.exists(file_analysis_path):
                tracker.add_file(file_analysis_path)
                if verbose:
                    print(f"📄 Tracked file analysis: {file_analysis_path}")
        
        print("✅ APK Unmask analysis completed and resources tracked")
        return output_file_path
        
    except Exception as e:
        print(f"❌ ERROR: APK Unmask failed: {e}")
        raise
```

### **3. Native Strings Analysis** (`run_strings_on_so_files.py`)

```python
def run_strings_on_so_files(apktool_output_path, output_directory, verbose=False):
    """
    Run 'strings' on all .so files with resource tracking.
    """
    # Initialize resource tracker
    tracker = GlobalResourceTracker()
    
    if not apktool_output_path or not os.path.isdir(apktool_output_path):
        if verbose:
            print(f"[DEBUG] apktool_output_path is invalid: {apktool_output_path}")
        return None

    if verbose:
        print("🏃 Running strings analysis on .so files...")
        print("🔧 Resource tracker initialized")

    so_files = find_so_files(apktool_output_path, verbose)
    if not so_files:
        print("ℹ️ No .so files found, skipping strings analysis.")
        return None

    strings_output_dir = os.path.join(output_directory, "native_libs_strings")
    os.makedirs(strings_output_dir, exist_ok=True)
    
    # Track the output directory
    tracker.add_directory(strings_output_dir)
    if verbose:
        print(f"📁 Tracked strings directory: {strings_output_dir}")

    if verbose:
        print(f"[DEBUG] Created strings output directory: {strings_output_dir}")

    for so_file_path in so_files:
        # ... existing strings processing logic ...
        
        try:
            # ... command execution ...
            
            with open(output_file_path, "w", encoding='utf-8') as f:
                f.write(result.stdout)

            # Track individual output file
            tracker.add_file(output_file_path)
            if verbose:
                print(f"✅ Strings output for {relative_path} saved and tracked: {output_file_path}")

        except Exception as e:
            # ... error handling ...

    print(f"✅ Strings analysis complete and resources tracked. Output in: {strings_output_dir}")
    return strings_output_dir
```

### **4. Base64 Scanner** (in `app.py`)

```python
def handle_base64_scan():
    """Handle base64 string scanning execution with resource tracking."""
    # Check prerequisites
    if not app_state.get('setup_complete') or not app_state.get('OUTPUT_DIR'):
        return jsonify({
            'success': False,
            'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
        })
    
    try:
        # Import the Base64Scanner and resource tracker
        import sys
        automatool_src = os.path.join(os.path.dirname(__file__), '..', 'automatool', 'automatool', 'src')
        
        if not os.path.exists(automatool_src):
            return jsonify({
                'success': False,
                'message': 'Automatool source directory not found'
            })
        
        # Add to Python path
        sys.path.insert(0, automatool_src)
        
        # Import scanner and resource tracker
        from scripts.automations.base64_scanner import Base64Scanner
        from scripts.automations.resource_tracker import GlobalResourceTracker
        
        # Initialize scanner and resource tracker
        scanner = Base64Scanner()
        tracker = GlobalResourceTracker()
        
        # Scan the decompiled directory and save results to files
        results = scanner.scan_decompiled_apk_directory(app_state['OUTPUT_DIR'])
        
        # Generate report with file output
        report = scanner.generate_report(output_directory=app_state['OUTPUT_DIR'], save_to_files=True)
        
        # Track the generated files
        output_files = report.get('output_files', {})
        if 'json_results' in output_files:
            tracker.add_file(output_files['json_results'])
        if 'text_summary' in output_files:
            tracker.add_file(output_files['text_summary'])
        
        return jsonify({
            'success': True,
            'message': f'Base64 scan completed successfully and resources tracked. Results saved to output directory.',
            'action': 'scan-base64',
            'output_files': output_files,
            'summary': {
                'files_scanned': report['summary']['total_files_scanned'],
                'strings_found': report['summary']['total_strings_found'],
                'files_with_strings': report['summary']['files_with_strings_count']
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Base64 scan failed: {str(e)}',
            'error': 'UNKNOWN_ERROR'
        })
```

## **Implementation Benefits**

### **1. Simplicity**
- **Minimal code changes**: Just add 2-3 lines per automation
- **No ProcessManager changes**: Each automation handles its own tracking
- **No pattern matching**: Direct tracking is more reliable

### **2. Reliability**
- **Immediate tracking**: Resources tracked as they're created
- **Accurate tracking**: No guessing what files were created
- **Error resilience**: Partial tracking if automation fails partway

### **3. Integration**
- **Automatic cleanup**: Existing cleanup system handles all tracked resources
- **Global coordination**: All resources end up in the same JSON file
- **Consistent behavior**: Same tracking mechanism as full automation

### **4. Maintainability**
- **Standard pattern**: Same approach across all automations
- **Easy debugging**: Clear tracking messages in verbose mode
- **Future-proof**: Easy to add new automations

## **Implementation Phases**

### **Phase 1: High Priority Automations** (Week 1)
1. `run_standalone_decompilation.py` - Large directories
2. `run_apk_unmask.py` - Already partially integrated
3. `run_strings_on_so_files.py` - Many files
4. `_mobsf_analysis_worker.py` - Large directory

### **Phase 2: Medium Priority Automations** (Week 2)
5. `_font_analysis_worker.py` - Analysis directory
6. Base64 Scanner in `app.py` - Result files
7. `run_apkleaks.py` - Output files

### **Phase 3: Low Priority Automations** (Week 3)
8. Frida-FSMon Scan - Small log files
9. Manifest Analysis - Single text file

### **Phase 4: Testing and Validation** (Week 4)
- Integration testing
- Cleanup verification
- Performance validation
- Documentation updates

## **Testing Strategy**

### **Unit Tests**
```python
def test_standalone_automation_tracking():
    """Test that standalone automations track resources correctly."""
    # 1. Run standalone automation
    # 2. Check that resources are added to automation_resources.json
    # 3. Verify resource paths are correct
    # 4. Test cleanup removes tracked resources
    pass

def test_multiple_automation_tracking():
    """Test multiple automations adding to same current_run."""
    # 1. Run multiple standalone automations
    # 2. Verify all resources accumulated in current_run
    # 3. Test cleanup handles all resources
    pass
```

### **Integration Tests**
```python
def test_full_lifecycle_with_cleanup():
    """Test complete lifecycle from automation to cleanup."""
    # 1. Run standalone automation
    # 2. Verify resources created and tracked
    # 3. Run cleanup
    # 4. Verify all resources removed
    # 5. Verify user files preserved
    pass
```

## **Success Criteria**

1. ✅ **All high-priority standalone automations track their resources**
2. ✅ **Resources are immediately added to global `automation_resources.json`**
3. ✅ **Existing cleanup system removes all tracked resources**
4. ✅ **User-provided files (APK, YARA.json) are preserved**
5. ✅ **No performance impact during automation execution**
6. ✅ **Clear verbose logging shows resource tracking activity**

## **Risk Mitigation**

### **Backward Compatibility**
- No changes to existing automation interfaces
- Resource tracking is additive, doesn't affect core functionality
- Graceful handling if resource tracker initialization fails

### **Error Handling**
- Resource tracking failures don't stop automation execution
- Partial tracking if automation fails partway through
- Clear error messages for debugging

### **Performance**
- Minimal overhead (just file I/O for JSON updates)
- No impact on automation execution speed
- Efficient resource tracking operations

---

**This approach leverages the existing, well-tested `GlobalResourceTracker` infrastructure to solve the resource cleanup problem with minimal code changes and maximum reliability.**
