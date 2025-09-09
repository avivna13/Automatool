# AMAnDe Manifest Analysis Integration Specification

## Overview
Add AMAnDe (Android Manifest Anomaly Detector) as a new automation button in the UI to analyze Android manifest files and extract services, providers, notification listeners, and suspicious patterns.

## Current Integration Pattern Analysis

### Existing Pattern (from APKLeaks):
1. **Button in UI**: `index.html` has action button with `data-action="apkleaks"`
2. **API Endpoint**: `app.py` has `/api/action/apkleaks` route
3. **Handler Function**: `handle_apkleaks()` function in `app.py`
4. **Process Manager**: `execute_apkleaks()` method in `process_manager.py`
5. **Command Execution**: Uses `python` executable with script path

### Key Integration Points:
- Uses `self.automatool_path = "../automatool/automatool/src"` as working directory
- Commands run with `python` executable (not `python3`)
- Output goes to `app_state['OUTPUT_DIR']`
- Uses `_run_process()` method for background execution

## Specification

### 1. UI Changes (`index.html`)

**Add new button in the "Analysis Actions" section:**
```html
<button class="btn btn-primary action-btn" data-action="manifest-analysis"
        {% if not state.setup_complete %}disabled{% endif %}>
    📋 Manifest Analysis (AMAnDe)
</button>
```

**Location**: After the existing buttons, before the process control section

### 2. API Endpoint (`app.py`)

**Add to valid_actions list:**
```python
valid_actions = ['full-process', 'get-reviews', 'clean', 'mobsf', 'native-strings-analysis', 'apkleaks', 'scan-base64', 'font-analysis', 'frida-fsmon-scan', 'manifest-analysis']
```

**Add new handler function:**
```python
def handle_manifest_analysis():
    """Handle AMAnDe manifest analysis execution."""
    # Check prerequisites
    if not app_state.get('setup_complete') or not app_state.get('APK_PATH') or not app_state.get('OUTPUT_DIR'):
        return jsonify({
            'success': False,
            'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
        })
    
    # Start manifest analysis
    success = process_manager.execute_manifest_analysis(
        app_state['APK_PATH'],
        app_state['OUTPUT_DIR'], 
        verbose=True
    )
    
    if success:
        return jsonify({
            'success': True,
            'message': 'AMAnDe manifest analysis started successfully',
            'action': 'manifest-analysis'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Failed to start manifest analysis'
        })
```

**Add to action routing:**
```python
elif action_name == 'manifest-analysis':
    return handle_manifest_analysis()
```

### 3. Process Manager (`utils/process_manager.py`)

**Add new method:**
```python
def execute_manifest_analysis(self, apk_path, output_dir, verbose=True):
    """Execute AMAnDe manifest analysis."""
    # AMAnDe is located in the automatool src directory
    amande_path = os.path.join(self.automatool_path, "AMAnDe")
    main_script = os.path.join(amande_path, "main.py")
    output_file = os.path.join(output_dir, "manifest_analysis.txt")
    
    # Command: python main.py -min 21 -max 33 test.apk > output.txt
    cmd = [
        'python', main_script,
        '-min', '21',
        '-max', '33',
        apk_path
    ]
    
    if verbose:
        cmd.append('-v 0')  # INFO level logging
    
    # Use shell redirection to capture output to file
    # This matches the exact command format requested
    shell_cmd = f"python {main_script} -min 21 -max 33 {apk_path} > {output_file}"
    
    return self._run_process(['bash', '-c', shell_cmd], "AMAnDe Manifest Analysis", amande_path, timeout=self.default_timeout)
```

### 4. File Structure Assumptions

**AMAnDe Location**: `automatool/automatool/src/AMAnDe/`
- `main.py` - Main AMAnDe script
- `requirements.txt` - Dependencies
- `src/` - AMAnDe source code

### 5. Output Handling

**Output File**: `manifest_analysis.txt` in the analysis output directory
**Content**: Full AMAnDe analysis including:
- Services, providers, notification listeners
- Exported components
- Permissions analysis
- Suspicious patterns
- Security anomalies

### 6. Error Handling

**Prerequisites Check**:
- APK file must exist
- Setup must be complete
- AMAnDe directory must exist

**Execution Errors**:
- Python executable not found
- AMAnDe dependencies not installed
- APK file corrupted/invalid
- Output directory not writable

### 7. Integration Flow

1. User uploads APK file (existing flow)
2. User clicks "Manifest Analysis (AMAnDe)" button
3. UI sends POST to `/api/action/manifest-analysis`
4. `handle_manifest_analysis()` validates prerequisites
5. `execute_manifest_analysis()` runs AMAnDe command
6. Command executes: `python main.py -min 21 -max 33 test.apk > output.txt`
7. Results saved to `manifest_analysis.txt` in output directory
8. UI shows success/failure message

### 8. Dependencies

**AMAnDe Requirements**:
- Python 3.x
- `tabulate`, `termcolor`, `argparse`, `pyaxmlparser`, `requests`
- APK file for analysis

### 9. Testing Considerations

**Test Cases**:
- Valid APK file analysis
- Invalid APK file handling
- Missing AMAnDe directory
- Missing dependencies
- Output file creation
- Concurrent process handling

### 10. Future Enhancements

**Potential Improvements**:
- Configurable SDK version ranges
- JSON output option
- Real-time progress updates
- Integration with other analysis results
- Custom AMAnDe rule sets

## Summary

This specification follows the exact same pattern as APKLeaks integration:
- Same button structure and styling
- Same API endpoint pattern
- Same process manager execution method
- Same error handling approach
- Same output directory usage

The key difference is the command execution uses shell redirection (`> output.txt`) to match the exact format requested, while maintaining the same Python executable path resolution as APKLeaks.

## Implementation Checklist

- [ ] Add button to `index.html`
- [ ] Add action to valid_actions list in `app.py`
- [ ] Create `handle_manifest_analysis()` function in `app.py`
- [ ] Add action routing in `app.py`
- [ ] Create `execute_manifest_analysis()` method in `process_manager.py`
- [ ] Test AMAnDe installation and dependencies
- [ ] Test command execution with sample APK
- [ ] Verify output file creation
- [ ] Test error handling scenarios
- [ ] Update documentation
