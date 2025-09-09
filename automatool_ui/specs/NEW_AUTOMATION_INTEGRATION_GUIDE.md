# 🔧 New Automation Integration Guide

## **Overview**

This guide provides a comprehensive step-by-step process for integrating new automations into the AutomatoolUI web interface. It covers all necessary components from backend implementation to frontend integration, following established patterns and best practices.

## **Architecture Overview**

The AutomatoolUI follows a modular architecture with clear separation of concerns:

```
automatool_ui/
├── app.py                 # Flask application with API endpoints
├── utils/
│   └── process_manager.py # Process execution management
├── templates/
│   └── index.html         # Main UI interface
├── static/js/
│   └── main.js           # Frontend JavaScript logic
└── specs/                # Documentation and specifications
```

**Integration Flow:**
1. **Backend**: Process Manager → API Handler → Route Registration
2. **Frontend**: UI Button → JavaScript Event → API Call
3. **Execution**: Standalone Script → Process Management → User Feedback

## **Prerequisites**

### **Automation Script Requirements**
Your automation script must support standalone execution with:
- Command-line argument parsing (`argparse`)
- Proper input validation
- Clear success/error handling
- Verbose output options
- Exit codes (0 for success, 1+ for errors)

### **Location Requirements**
- **Main Script**: `automatool/automatool/src/scripts/automations/your_script.py`
- **Dependencies**: Within `automatool/automatool/src/` structure
- **Utils/Configs**: `automatool/automatool/src/scripts/utils/`

## **Step-by-Step Integration Process**

### **Phase 1: Prepare Automation Script**

#### **1.1 Ensure Standalone Capability**

Your script should have this structure:

```python
#!/usr/bin/env python3
"""
Your Automation Tool

Description of what your automation does.
"""

import argparse
import sys
import os

def your_main_function(param1, param2, verbose=False):
    """Main automation logic that can be imported."""
    # Your automation logic here
    pass

def parse_arguments():
    """Parse command line arguments for standalone usage."""
    parser = argparse.ArgumentParser(
        description="Your automation description",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/input /path/to/output
  %(prog)s /path/to/input /path/to/output --verbose
        """
    )
    
    parser.add_argument(
        "input_path",
        help="Path to input file/directory"
    )
    
    parser.add_argument(
        "output_path", 
        help="Path to output directory"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    # Add other options as needed
    
    return parser.parse_args()

def main():
    """Main entry point for standalone execution."""
    args = parse_arguments()
    
    print("🚀 Starting Your Automation")
    print(f"📁 Input: {args.input_path}")
    print(f"📁 Output: {args.output_path}")
    
    # Validate inputs
    if not os.path.exists(args.input_path):
        print(f"❌ ERROR: Input not found: {args.input_path}")
        sys.exit(1)
    
    if not os.path.exists(args.output_path):
        print(f"❌ ERROR: Output directory not found: {args.output_path}")
        sys.exit(1)
    
    try:
        # Call your main function
        result = your_main_function(
            args.input_path,
            args.output_path,
            verbose=args.verbose
        )
        
        if result:
            print(f"✅ Automation completed successfully")
            print(f"📄 Results saved to: {result}")
        else:
            print("❌ Automation failed")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ ERROR: Automation failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
```

#### **1.2 Test Standalone Execution**

```bash
cd automatool/automatool/src
python scripts/automations/your_script.py /test/input /test/output --verbose
```

### **Phase 2: Backend Integration**

#### **2.1 Add Process Manager Method**

**File**: `automatool_ui/utils/process_manager.py`

Add your method after existing automation methods:

```python
def execute_your_automation(self, input_path, output_dir, option1=True, verbose=True):
    """Execute your automation with specified options."""
    script_path = os.path.join("scripts", "automations", "your_script.py")
    cmd = [
        'python', script_path,
        input_path,
        output_dir
    ]
    
    # Add conditional options
    if option1:
        cmd.append('--option1')
    
    if verbose:
        cmd.append('--verbose')
    
    return self._run_process(cmd, "Your Automation Name", self.automatool_path, timeout=self.default_timeout)
```

**Key Points:**
- Use descriptive method name: `execute_[automation_name]`
- Follow parameter patterns: `(self, required_params, optional_params=default, verbose=True)`
- Use `os.path.join()` for script path
- Add conditional options based on parameters
- Use descriptive process name for logging
- Set appropriate timeout (use `self.default_timeout` unless special needs)

#### **2.2 Add API Handler**

**File**: `automatool_ui/app.py`

##### **2.2.1 Add to Valid Actions**

Find the `valid_actions` list (around line 208) and add your action:

```python
valid_actions = ['full-process', 'get-reviews', 'clean', 'mobsf', 'native-strings-analysis', 
                 'apkleaks', 'scan-base64', 'font-analysis', 'frida-fsmon-scan', 
                 'manifest-analysis', 'decompile-apk', 'apk-unmask-analysis', 
                 'your-automation-name']
```

##### **2.2.2 Add Route Handler**

Find the action routing section (around line 238) and add your handler:

```python
elif action_name == 'your-automation-name':
    return handle_your_automation()
```

##### **2.2.3 Create Handler Function**

Add your handler function after existing handlers (around line 700+):

```python
def handle_your_automation():
    """Handle your automation execution."""
    try:
        # Check prerequisites
        if not app_state.get('setup_complete') or not app_state.get('APK_PATH') or not app_state.get('OUTPUT_DIR'):
            return jsonify({
                'success': False,
                'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
            })
        
        # Get options from request (if needed)
        data = request.get_json() or {}
        option1 = data.get('option1', True)
        option2 = data.get('option2', False)
        
        # Start automation
        success = process_manager.execute_your_automation(
            app_state['APK_PATH'],  # or appropriate input
            app_state['OUTPUT_DIR'],
            option1=option1,
            option2=option2,
            verbose=True
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Your automation started successfully',
                'action': 'your-automation-name'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to start your automation'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Your automation failed: {str(e)}'
        })
```

**Handler Patterns:**
- Always check prerequisites first
- Use `app_state` for common paths (APK_PATH, OUTPUT_DIR)
- Parse options from JSON request data
- Provide clear success/error messages
- Include action name in success response
- Wrap in try-catch for error handling

### **Phase 3: Frontend Integration**

#### **3.1 Add UI Button**

**File**: `automatool_ui/templates/index.html`

Find the "Analysis Actions" section (around line 82) and add your button:

```html
<button class="btn btn-primary action-btn" data-action="your-automation-name"
        {% if not state.setup_complete %}disabled{% endif %}>
    🔧 Your Automation Name
</button>
```

**Button Guidelines:**
- Use appropriate Bootstrap class: `btn-primary` (blue), `btn-warning` (orange), `btn-success` (green)
- Always include `action-btn` class for JavaScript handling
- Set `data-action` to match your API action name
- Add emoji for visual identification
- Use conditional disabling: `{% if not state.setup_complete %}disabled{% endif %}`
- Keep button text concise but descriptive

#### **3.2 JavaScript Integration (Optional)**

**File**: `automatool_ui/static/js/main.js`

The existing JavaScript automatically handles buttons with `action-btn` class. However, if you need special handling, add it to the `executeAction` method:

```javascript
// In executeAction method, around line 196
if (result.success) {
    this.showMessage('success', `${action} completed successfully`);
    
    // Special handling for different actions
    if (action === 'your-automation-name') {
        this.updateStatus('Your automation started...');
        // Add any special UI updates
    }
}
```

### **Phase 4: Advanced Features (Optional)**

#### **4.1 Configuration Options**

If your automation needs user configuration, add options to the UI:

```html
<!-- Add to index.html before action buttons -->
<div class="form-group" id="your-automation-config" style="display: none;">
    <label>Your Automation Options:</label>
    <div class="form-check">
        <input class="form-check-input" type="checkbox" id="your-option1" checked>
        <label class="form-check-label" for="your-option1">
            Enable Option 1
        </label>
    </div>
    <div class="form-group mt-2">
        <label for="your-input">Custom Input:</label>
        <input type="text" class="form-control" id="your-input" 
               placeholder="Enter custom value">
    </div>
</div>
```

#### **4.2 Results Display**

Add a results section to display automation output:

```html
<!-- Add to index.html after action buttons -->
<div id="your-automation-results" class="results-section" style="display: none;">
    <h4>🔧 Your Automation Results</h4>
    <div class="row">
        <div class="col-md-12">
            <pre id="your-automation-output" class="bg-light p-3"></pre>
        </div>
    </div>
    <div class="mt-3">
        <button class="btn btn-sm btn-secondary" onclick="downloadYourResults()">
            📥 Download Results
        </button>
    </div>
</div>
```

#### **4.3 Custom JavaScript Functions**

Add specialized JavaScript functions if needed:

```javascript
// Add to main.js
function handleYourAutomation() {
    const option1 = document.getElementById('your-option1').checked;
    const customInput = document.getElementById('your-input').value;
    
    const options = {
        option1: option1,
        custom_input: customInput || null
    };
    
    executeAction('your-automation-name', options);
}

function displayYourResults(outputDir) {
    // Load and display results
    fetch(`/api/get-file-content?path=${outputDir}/your_output.txt`)
        .then(response => response.text())
        .then(content => {
            document.getElementById('your-automation-output').textContent = content;
            document.getElementById('your-automation-results').style.display = 'block';
        })
        .catch(error => {
            console.error('Error loading results:', error);
        });
}

function downloadYourResults() {
    // Implement download functionality
    const content = document.getElementById('your-automation-output').textContent;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'your_automation_results.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
```

### **Phase 5: Testing and Validation**

#### **5.1 Unit Testing**

Create test files in `automatool_ui/tests/`:

```python
# test_your_automation.py
import unittest
from unittest.mock import patch, MagicMock
from utils.process_manager import ProcessManager

class TestYourAutomation(unittest.TestCase):
    def setUp(self):
        self.process_manager = ProcessManager()
    
    @patch('utils.process_manager.ProcessManager._run_process')
    def test_execute_your_automation_success(self, mock_run):
        mock_run.return_value = True
        
        result = self.process_manager.execute_your_automation(
            '/test/input',
            '/test/output',
            verbose=True
        )
        
        self.assertTrue(result)
        mock_run.assert_called_once()
    
    def test_execute_your_automation_parameters(self):
        # Test parameter handling
        pass
```

#### **5.2 Integration Testing**

Test the complete flow:

1. **Manual UI Testing**:
   - Start the UI: `cd automatool_ui && python app.py`
   - Upload test APK or configure manual setup
   - Click your automation button
   - Verify process starts and completes
   - Check output files

2. **API Testing**:
   ```bash
   curl -X POST http://localhost:5000/api/action/your-automation-name \
        -H "Content-Type: application/json" \
        -d '{"option1": true}'
   ```

3. **Standalone Testing**:
   ```bash
   cd automatool/automatool/src
   python scripts/automations/your_script.py /test/input /test/output --verbose
   ```

#### **5.3 Error Handling Validation**

Test error scenarios:
- Missing input files
- Invalid parameters
- Process failures
- Timeout conditions
- Permission issues

## **Best Practices and Guidelines**

### **Naming Conventions**

- **Action Names**: Use kebab-case: `your-automation-name`
- **Function Names**: Use snake_case: `execute_your_automation`
- **File Names**: Use snake_case: `your_script.py`
- **CSS/HTML IDs**: Use kebab-case: `your-automation-results`

### **Error Handling**

```python
# Good error handling pattern
try:
    result = your_automation_function()
    if result:
        return jsonify({'success': True, 'message': 'Success'})
    else:
        return jsonify({'success': False, 'message': 'Operation failed'})
except FileNotFoundError as e:
    return jsonify({'success': False, 'message': f'File not found: {e}'})
except Exception as e:
    return jsonify({'success': False, 'message': f'Unexpected error: {e}'})
```

### **User Feedback**

- **Clear Messages**: Use descriptive success/error messages
- **Progress Indicators**: Show process status in UI
- **Visual Cues**: Use emojis and colors consistently
- **Logging**: Provide verbose output for debugging

### **Performance Considerations**

- **Timeouts**: Set appropriate timeouts for long-running processes
- **Resource Management**: Clean up temporary files and processes
- **Concurrent Execution**: Prevent multiple simultaneous executions
- **Memory Usage**: Monitor memory consumption for large operations

### **Security Guidelines**

- **Input Validation**: Always validate user inputs
- **Path Sanitization**: Prevent path traversal attacks
- **Command Injection**: Use parameterized commands, avoid shell=True
- **File Permissions**: Check file access permissions before operations

## **Common Integration Patterns**

### **Pattern 1: Simple Analysis Tool**
- Single input (APK)
- Single output file
- Basic configuration options
- Standard success/error handling

**Examples**: APKLeaks, String Analysis, Font Analysis

### **Pattern 2: Complex Analysis with Dependencies**
- Multiple inputs (APK + configuration)
- Multiple output files
- Advanced configuration options
- Dependency validation

**Examples**: APK Unmask with File Analysis, Manifest Analysis

### **Pattern 3: Interactive Service**
- Real-time communication
- Status updates
- User interaction during execution
- Progress monitoring

**Examples**: Frida Monitoring, VPN Integration

### **Pattern 4: Batch Processing**
- Multiple input files
- Parallel execution
- Result aggregation
- Progress tracking

**Examples**: Bulk APK Analysis, Report Generation

## **Troubleshooting Common Issues**

### **Backend Issues**

| Issue | Cause | Solution |
|-------|-------|----------|
| Action not found | Missing from valid_actions | Add to valid_actions list |
| Handler not called | Missing route mapping | Add elif clause in action routing |
| Process fails to start | Script path incorrect | Verify script path in process_manager |
| Timeout errors | Process runs too long | Increase timeout or optimize script |

### **Frontend Issues**

| Issue | Cause | Solution |
|-------|-------|----------|
| Button doesn't work | Missing action-btn class | Add action-btn class to button |
| Button always disabled | Missing setup check | Verify setup_complete state |
| No visual feedback | Missing JavaScript handling | Add special handling in executeAction |
| Results not displayed | Missing results section | Add results HTML section |

### **Script Issues**

| Issue | Cause | Solution |
|-------|-------|----------|
| Import errors | Wrong path structure | Fix sys.path or import statements |
| Permission denied | Script not executable | Check file permissions |
| Arguments not parsed | Missing argparse setup | Add parse_arguments function |
| No error handling | Missing try-catch | Add comprehensive error handling |

## **Example: Complete Integration**

Here's a complete example integrating a hypothetical "Hash Analysis" automation:

### **1. Script Structure**
```python
# automatool/automatool/src/scripts/automations/hash_analysis.py
#!/usr/bin/env python3
import argparse
import hashlib
import os
import sys

def analyze_hashes(apk_path, output_dir, verbose=False):
    """Analyze file hashes in APK."""
    if verbose:
        print("🔍 Starting hash analysis...")
    
    # Your analysis logic here
    output_file = os.path.join(output_dir, "hash_analysis.txt")
    with open(output_file, 'w') as f:
        f.write("Hash analysis results...\n")
    
    return output_file

def parse_arguments():
    parser = argparse.ArgumentParser(description="APK Hash Analysis")
    parser.add_argument("apk_path", help="Path to APK file")
    parser.add_argument("output_dir", help="Output directory")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    return parser.parse_args()

def main():
    args = parse_arguments()
    print("🔍 Starting Hash Analysis")
    
    if not os.path.exists(args.apk_path):
        print(f"❌ ERROR: APK not found: {args.apk_path}")
        sys.exit(1)
    
    try:
        result = analyze_hashes(args.apk_path, args.output_dir, args.verbose)
        print(f"✅ Analysis complete: {result}")
    except Exception as e:
        print(f"❌ ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### **2. Process Manager Method**
```python
# In automatool_ui/utils/process_manager.py
def execute_hash_analysis(self, apk_path, output_dir, verbose=True):
    """Execute hash analysis on APK file."""
    script_path = os.path.join("scripts", "automations", "hash_analysis.py")
    cmd = ['python', script_path, apk_path, output_dir]
    
    if verbose:
        cmd.append('--verbose')
    
    return self._run_process(cmd, "Hash Analysis", self.automatool_path, timeout=self.default_timeout)
```

### **3. API Handler**
```python
# In automatool_ui/app.py

# Add to valid_actions:
valid_actions = [..., 'hash-analysis']

# Add route:
elif action_name == 'hash-analysis':
    return handle_hash_analysis()

# Add handler:
def handle_hash_analysis():
    """Handle hash analysis execution."""
    try:
        if not app_state.get('setup_complete') or not app_state.get('APK_PATH') or not app_state.get('OUTPUT_DIR'):
            return jsonify({
                'success': False,
                'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
            })
        
        success = process_manager.execute_hash_analysis(
            app_state['APK_PATH'],
            app_state['OUTPUT_DIR'],
            verbose=True
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Hash analysis started successfully',
                'action': 'hash-analysis'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to start hash analysis'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Hash analysis failed: {str(e)}'
        })
```

### **4. UI Button**
```html
<!-- In automatool_ui/templates/index.html -->
<button class="btn btn-info action-btn" data-action="hash-analysis"
        {% if not state.setup_complete %}disabled{% endif %}>
    🔍 Hash Analysis
</button>
```

## **Conclusion**

This guide provides a comprehensive framework for integrating new automations into the AutomatoolUI. By following these patterns and best practices, you can ensure consistent, reliable, and user-friendly automation integration.

### **Key Takeaways**

1. **Follow Established Patterns**: Use existing implementations as templates
2. **Test Thoroughly**: Validate all components individually and together
3. **Handle Errors Gracefully**: Provide clear feedback for all scenarios
4. **Document Everything**: Update specs and add inline documentation
5. **Maintain Consistency**: Follow naming conventions and UI patterns

### **Next Steps**

After integration:
1. Update this guide with any new patterns discovered
2. Create automation-specific documentation
3. Add monitoring and metrics if needed
4. Consider performance optimizations
5. Plan for future enhancements

---

**Happy Automating!** 🚀
