# 🔍 Developer APK Analysis UI Integration Specification

## **Overview**

This specification defines the integration of the Developer APK Analysis automation into the AutomatoolUI web interface. The integration provides a dedicated page where users can input developer names and execute APK analysis to extract hardcoded API keys using APKLeaks with custom rules.

## **Purpose**

Create a user-friendly web interface for the Developer APK Analysis automation that:
- Provides a dedicated page for focused user interaction
- Allows users to input developer names and configure analysis options
- Executes the standalone `analyze_developer_apk.py` script
- Displays results in a structured format
- Maintains a centralized developer database

## **Architecture Overview**

### **Integration Approach: Dedicated Page Navigation**

**Selected Pattern**: Dedicated Page with Form Input
- **Rationale**: Clean separation, focused UI, extensible for future options
- **User Flow**: Main Page → Navigation Button → Dedicated Analysis Page → Results Display
- **Benefits**: Uncluttered main interface, clear workflow, easy to extend

### **System Components**

```
automatool_ui/
├── app.py                           # Flask routes and API handlers
├── utils/process_manager.py         # Process execution management
├── templates/
│   ├── index.html                  # Main UI with navigation button
│   └── developer_analysis.html     # Dedicated analysis page
├── static/
│   ├── js/main.js                  # Navigation and form handling
│   └── css/style.css               # Page-specific styling
└── specs/
    └── DEVELOPER_APK_ANALYSIS_INTEGRATION_SPEC.md  # This document
```

## **Technical Requirements**

### **Backend Requirements**

#### **BR-1: Process Manager Integration**
- **Requirement**: Execute `analyze_developer_apk.py` with user parameters
- **Method**: `execute_developer_apk_analysis(developer_name, apk_path, output_dir, force, verbose)`
- **Parameters**: Developer name, APK path, output directory, force flag, verbose flag
- **Timeout**: 300 seconds (5 minutes) for APKLeaks analysis

#### **BR-2: API Endpoint**
- **Route**: `POST /api/action/developer-apk-analysis`
- **Input**: JSON with developer_name and force flag
- **Output**: Standard success/error response format
- **Validation**: Check setup completion, APK path, output directory

#### **BR-3: Page Route**
- **Route**: `GET /developer-analysis`
- **Purpose**: Render dedicated analysis page
- **Template**: `developer_analysis.html`
- **State**: Pass current app_state for UI rendering

### **Frontend Requirements**

#### **FR-1: Navigation Integration**
- **Location**: Main page analysis actions section
- **Button**: "🔍 Developer APK Analysis"
- **Behavior**: Navigate to dedicated page
- **State**: Disabled if setup not complete

#### **FR-2: Dedicated Analysis Page**
- **Template**: `developer_analysis.html`
- **Components**: Input form, options, results display, navigation
- **Validation**: Client-side developer name validation
- **Feedback**: Progress indicators and result display

#### **FR-3: Form Handling**
- **Input Fields**: Developer name (required), force overwrite (checkbox)
- **Validation**: Alphanumeric characters, no special chars except underscore/hyphen
- **Submission**: AJAX POST to API endpoint
- **Results**: Display analysis results and download options

## **Implementation Details**

### **Phase 1: Backend Integration**

#### **1.1 Process Manager Method**

**File**: `automatool_ui/utils/process_manager.py`

```python
def execute_developer_apk_analysis(self, developer_name, apk_path, output_dir, force=False, verbose=True):
    """
    Execute developer APK analysis automation.
    
    Args:
        developer_name (str): Unique identifier for the developer
        apk_path (str): Path to APK file to analyze
        output_dir (str): Output directory for temporary files
        force (bool): Overwrite existing developer entry
        verbose (bool): Enable verbose output
        
    Returns:
        bool: True if process started successfully, False otherwise
    """
    script_path = os.path.join("scripts", "automations", "analyze_developer_apk.py")
    cmd = [
        'python', script_path,
        developer_name,
        apk_path,
        output_dir
    ]
    
    if force:
        cmd.append('--force')
    
    if verbose:
        cmd.append('--verbose')
    
    return self._run_process(
        cmd, 
        "Developer APK Analysis", 
        self.automatool_path, 
        timeout=300  # 5 minutes for APKLeaks analysis
    )
```

#### **1.2 API Handler Registration**

**File**: `automatool_ui/app.py`

**Add to valid_actions list** (around line 208):
```python
valid_actions = [
    'full-process', 'get-reviews', 'clean', 'mobsf', 'native-strings-analysis', 
    'apkleaks', 'scan-base64', 'font-analysis', 'frida-fsmon-scan', 
    'manifest-analysis', 'decompile-apk', 'apk-unmask-analysis',
    'developer-apk-analysis'  # Add this line
]
```

**Add route handler** (around line 238):
```python
elif action_name == 'developer-apk-analysis':
    return handle_developer_apk_analysis()
```

#### **1.3 API Handler Function**

**File**: `automatool_ui/app.py` (add after existing handlers)

```python
def handle_developer_apk_analysis():
    """Handle developer APK analysis execution."""
    try:
        # Check prerequisites
        if not app_state.get('setup_complete') or not app_state.get('APK_PATH') or not app_state.get('OUTPUT_DIR'):
            return jsonify({
                'success': False,
                'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
            })
        
        # Get parameters from request
        data = request.get_json() or {}
        developer_name = data.get('developer_name', '').strip()
        force = data.get('force', False)
        
        # Validate developer name
        if not developer_name:
            return jsonify({
                'success': False,
                'message': 'Developer name is required'
            })
        
        # Validate developer name format (alphanumeric, underscore, hyphen only)
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', developer_name):
            return jsonify({
                'success': False,
                'message': 'Developer name must contain only alphanumeric characters, underscores, and hyphens'
            })
        
        # Execute analysis
        success = process_manager.execute_developer_apk_analysis(
            developer_name,
            app_state['APK_PATH'],
            app_state['OUTPUT_DIR'],
            force=force,
            verbose=True
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Developer APK analysis started successfully for: {developer_name}',
                'action': 'developer-apk-analysis',
                'developer_name': developer_name
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to start developer APK analysis'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Developer APK analysis failed: {str(e)}'
        })
```

#### **1.4 Page Route Handler**

**File**: `automatool_ui/app.py` (add with other routes)

```python
@app.route('/developer-analysis')
def developer_analysis_page():
    """Render the developer APK analysis page."""
    return render_template('developer_analysis.html', state=app_state)
```

### **Phase 2: Frontend Implementation**

#### **2.1 Navigation Button Integration**

**File**: `automatool_ui/templates/index.html`

**Location**: Analysis Actions section (around line 82)

```html
<!-- Add after existing analysis buttons -->
<button class="btn btn-warning" onclick="navigateToDeveloperAnalysis()"
        {% if not state.setup_complete %}disabled{% endif %}>
    🔍 Developer APK Analysis
</button>
```

#### **2.2 Dedicated Analysis Page**

**File**: `automatool_ui/templates/developer_analysis.html` (new file)

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Developer APK Analysis - AutomatoolUI</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
    <div class="container mt-4">
        <!-- Header -->
        <div class="row mb-4">
            <div class="col-12">
                <h2>🔍 Developer APK Analysis</h2>
                <p class="text-muted">Extract hardcoded API keys from APK files and maintain a centralized developer database.</p>
            </div>
        </div>

        <!-- Status Alert -->
        <div id="status-alert" class="alert" style="display: none;" role="alert">
            <span id="status-message"></span>
        </div>

        <!-- Analysis Form -->
        <div class="card mb-4">
            <div class="card-header">
                <h5 class="mb-0">📋 Analysis Configuration</h5>
            </div>
            <div class="card-body">
                <!-- Current Setup Info -->
                <div class="row mb-3">
                    <div class="col-md-6">
                        <strong>📱 APK File:</strong>
                        <span class="text-muted">{{ state.APK_PATH or 'Not configured' }}</span>
                    </div>
                    <div class="col-md-6">
                        <strong>📁 Output Directory:</strong>
                        <span class="text-muted">{{ state.OUTPUT_DIR or 'Not configured' }}</span>
                    </div>
                </div>

                <hr>

                <!-- Input Form -->
                <form id="developer-analysis-form">
                    <div class="row">
                        <div class="col-md-8">
                            <div class="form-group mb-3">
                                <label for="developer-name" class="form-label">
                                    🏷️ Developer Name <span class="text-danger">*</span>
                                </label>
                                <input type="text" 
                                       class="form-control" 
                                       id="developer-name" 
                                       placeholder="Enter unique developer identifier (e.g., MalwareDev, TestApp)"
                                       pattern="[a-zA-Z0-9_-]+"
                                       title="Only alphanumeric characters, underscores, and hyphens allowed"
                                       required>
                                <div class="form-text">
                                    Use alphanumeric characters, underscores, and hyphens only. No spaces or special characters.
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="form-group mb-3">
                                <label class="form-label">&nbsp;</label>
                                <div class="form-check">
                                    <input class="form-check-input" 
                                           type="checkbox" 
                                           id="force-overwrite">
                                    <label class="form-check-label" for="force-overwrite">
                                        🔄 Force overwrite existing entry
                                    </label>
                                </div>
                                <div class="form-text">
                                    Check to overwrite if developer already exists in database.
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="row">
                        <div class="col-12">
                            <button type="submit" 
                                    class="btn btn-primary btn-lg"
                                    id="start-analysis-btn"
                                    {% if not state.setup_complete %}disabled{% endif %}>
                                🚀 Start Analysis
                            </button>
                            
                            {% if not state.setup_complete %}
                            <div class="text-danger mt-2">
                                ⚠️ Please complete setup (upload APK or configure manual setup) before running analysis.
                            </div>
                            {% endif %}
                        </div>
                    </div>
                </form>
            </div>
        </div>

        <!-- Progress Section -->
        <div id="progress-section" class="card mb-4" style="display: none;">
            <div class="card-header">
                <h5 class="mb-0">⏳ Analysis Progress</h5>
            </div>
            <div class="card-body">
                <div class="progress mb-3">
                    <div class="progress-bar progress-bar-striped progress-bar-animated" 
                         role="progressbar" 
                         style="width: 100%">
                        Analyzing...
                    </div>
                </div>
                <p class="mb-0" id="progress-message">Starting developer APK analysis...</p>
            </div>
        </div>

        <!-- Results Section -->
        <div id="results-section" class="card mb-4" style="display: none;">
            <div class="card-header">
                <h5 class="mb-0">📊 Analysis Results</h5>
            </div>
            <div class="card-body">
                <div id="results-content">
                    <!-- Results will be populated here -->
                </div>
            </div>
        </div>

        <!-- Navigation -->
        <div class="row">
            <div class="col-12">
                <button class="btn btn-secondary" onclick="goBackToMain()">
                    ← Back to Main Interface
                </button>
            </div>
        </div>
    </div>

    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Page-specific JavaScript
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.getElementById('developer-analysis-form');
            const developerNameInput = document.getElementById('developer-name');
            
            // Form validation
            developerNameInput.addEventListener('input', function() {
                const value = this.value;
                const isValid = /^[a-zA-Z0-9_-]*$/.test(value);
                
                if (!isValid && value) {
                    this.setCustomValidity('Only alphanumeric characters, underscores, and hyphens allowed');
                } else {
                    this.setCustomValidity('');
                }
            });
            
            // Form submission
            form.addEventListener('submit', function(e) {
                e.preventDefault();
                handleDeveloperAnalysis();
            });
        });

        function handleDeveloperAnalysis() {
            const developerName = document.getElementById('developer-name').value.trim();
            const force = document.getElementById('force-overwrite').checked;
            
            if (!developerName) {
                showAlert('danger', 'Please enter a developer name');
                return;
            }
            
            // Show progress
            document.getElementById('progress-section').style.display = 'block';
            document.getElementById('results-section').style.display = 'none';
            document.getElementById('start-analysis-btn').disabled = true;
            
            // Make API call
            fetch('/api/action/developer-apk-analysis', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    developer_name: developerName,
                    force: force
                })
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('progress-section').style.display = 'none';
                document.getElementById('start-analysis-btn').disabled = false;
                
                if (data.success) {
                    showAlert('success', data.message);
                    // Poll for results or show completion message
                    setTimeout(() => {
                        checkAnalysisResults(developerName);
                    }, 2000);
                } else {
                    showAlert('danger', data.message);
                }
            })
            .catch(error => {
                document.getElementById('progress-section').style.display = 'none';
                document.getElementById('start-analysis-btn').disabled = false;
                showAlert('danger', 'Network error: ' + error.message);
            });
        }

        function checkAnalysisResults(developerName) {
            // This would check for results file or database updates
            // For now, show a simple completion message
            document.getElementById('results-section').style.display = 'block';
            document.getElementById('results-content').innerHTML = `
                <div class="alert alert-success">
                    <h6>✅ Analysis Completed</h6>
                    <p>Developer APK analysis has been completed for: <strong>${developerName}</strong></p>
                    <p>Results have been saved to the developers database in the project root directory.</p>
                    <small class="text-muted">
                        Check the developers.json file for extracted API keys and analysis results.
                    </small>
                </div>
            `;
        }

        function showAlert(type, message) {
            const alertDiv = document.getElementById('status-alert');
            const messageSpan = document.getElementById('status-message');
            
            alertDiv.className = `alert alert-${type}`;
            messageSpan.textContent = message;
            alertDiv.style.display = 'block';
            
            // Auto-hide success messages
            if (type === 'success') {
                setTimeout(() => {
                    alertDiv.style.display = 'none';
                }, 5000);
            }
        }

        function navigateToDeveloperAnalysis() {
            window.location.href = '/developer-analysis';
        }

        function goBackToMain() {
            window.location.href = '/';
        }
    </script>
</body>
</html>
```

#### **2.3 JavaScript Integration**

**File**: `automatool_ui/static/js/main.js`

**Add navigation function**:

```javascript
// Add to existing functions
function navigateToDeveloperAnalysis() {
    window.location.href = '/developer-analysis';
}
```

### **Phase 3: Integration Points**

#### **3.1 Data Flow**

```
User Input → Form Validation → API Call → Process Manager → 
analyze_developer_apk.py → APKLeaks → Results → Database Update
```

#### **3.2 File Dependencies**

- **Script**: `automatool/automatool/src/scripts/automations/analyze_developer_apk.py`
- **Rules**: `automatool/apkleaks_custom_rules.json`
- **Database**: `developers.json` (project root)
- **Dependencies**: `run_apkleaks.py`, `parse_apkleaks_output.py`

#### **3.3 State Management**

- **Prerequisites**: `app_state['setup_complete']`, `app_state['APK_PATH']`, `app_state['OUTPUT_DIR']`
- **Validation**: APK file exists, output directory accessible
- **Results**: Database updated in project root

## **API Specification**

### **Request Format**

```json
POST /api/action/developer-apk-analysis
Content-Type: application/json

{
    "developer_name": "TestDeveloper",
    "force": false
}
```

### **Response Format**

**Success Response**:
```json
{
    "success": true,
    "message": "Developer APK analysis started successfully for: TestDeveloper",
    "action": "developer-apk-analysis",
    "developer_name": "TestDeveloper"
}
```

**Error Response**:
```json
{
    "success": false,
    "message": "Developer name must contain only alphanumeric characters, underscores, and hyphens"
}
```

## **Validation Rules**

### **Input Validation**

1. **Developer Name**:
   - Required field
   - Pattern: `^[a-zA-Z0-9_-]+$`
   - No spaces or special characters except underscore and hyphen
   - Minimum length: 1 character
   - Maximum length: 50 characters (recommended)

2. **Prerequisites**:
   - Setup must be complete (`setup_complete = true`)
   - APK file must be configured (`APK_PATH` exists)
   - Output directory must be configured (`OUTPUT_DIR` exists)

### **Business Logic Validation**

1. **Developer Existence**: 
   - Check if developer exists in database
   - Require force flag to overwrite existing entries

2. **File Access**:
   - Verify APK file is readable
   - Verify output directory is writable
   - Verify custom rules file exists

## **Error Handling**

### **Client-Side Errors**

| Error Type | Trigger | Message | Action |
|------------|---------|---------|---------|
| Validation | Invalid developer name | "Only alphanumeric characters, underscores, and hyphens allowed" | Show inline validation |
| Required Field | Empty developer name | "Please enter a developer name" | Focus input field |
| Network | API call fails | "Network error: [details]" | Show error alert |

### **Server-Side Errors**

| Error Type | Trigger | Message | HTTP Status |
|------------|---------|---------|-------------|
| Setup | Prerequisites not met | "Setup not complete. Please upload APK file or configure manual setup first." | 400 |
| Validation | Invalid developer name format | "Developer name must contain only alphanumeric characters, underscores, and hyphens" | 400 |
| Process | Script execution fails | "Failed to start developer APK analysis" | 500 |
| Exception | Unexpected error | "Developer APK analysis failed: [details]" | 500 |

## **Testing Strategy**

### **Unit Tests**

1. **Process Manager Tests**:
   - Test command construction
   - Test parameter handling
   - Test timeout configuration

2. **API Handler Tests**:
   - Test input validation
   - Test prerequisite checking
   - Test error responses

### **Integration Tests**

1. **End-to-End Flow**:
   - Navigate to page
   - Submit valid form
   - Verify API call
   - Check process execution

2. **Error Scenarios**:
   - Invalid developer names
   - Missing prerequisites
   - Process failures

### **Manual Testing Checklist**

- [ ] Navigation button works from main page
- [ ] Page loads with correct state information
- [ ] Form validation works for developer name input
- [ ] Force checkbox functions correctly
- [ ] Submit button disabled when setup incomplete
- [ ] API call executes successfully
- [ ] Progress indicators display correctly
- [ ] Results section shows completion message
- [ ] Back button returns to main page
- [ ] Error messages display appropriately

## **Performance Considerations**

### **Timeout Configuration**

- **API Timeout**: 300 seconds (5 minutes)
- **Rationale**: APKLeaks analysis can be time-intensive for large APKs
- **Fallback**: Process continues in background even if UI times out

### **Resource Management**

- **Memory**: Analysis runs in separate process
- **Disk**: Temporary files cleaned up automatically
- **CPU**: Single analysis at a time to prevent resource conflicts

## **Security Considerations**

### **Input Sanitization**

- Developer name validated with regex pattern
- No shell command injection possible (parameterized execution)
- Path traversal prevented by using absolute paths

### **File Access**

- Only configured APK and output directories accessible
- No arbitrary file system access
- Process runs with application permissions only

## **Future Enhancements**

### **Planned Features**

1. **Real-time Progress**: WebSocket integration for live progress updates
2. **Results Display**: Show extracted API keys directly in UI
3. **Batch Analysis**: Support multiple developers in single session
4. **Export Options**: Download results in various formats
5. **History View**: Show previous analysis results

### **Extensibility Points**

1. **Additional Options**: Easy to add more configuration options
2. **Custom Rules**: UI for managing custom APKLeaks rules
3. **Database Management**: Interface for viewing/managing developer database
4. **Integration**: Connect with other analysis tools

## **Conclusion**

This specification provides a comprehensive framework for integrating the Developer APK Analysis automation into the AutomatoolUI with a clean, dedicated page interface. The implementation follows established patterns while providing a focused user experience for this specific automation.

### **Key Benefits**

1. **User-Friendly**: Clean, focused interface for developer analysis
2. **Consistent**: Follows established UI patterns and API conventions
3. **Extensible**: Easy to add more features and options
4. **Robust**: Comprehensive error handling and validation
5. **Maintainable**: Clear separation of concerns and modular design

### **Implementation Priority**

1. **Phase 1**: Backend integration (Process Manager + API)
2. **Phase 2**: Basic frontend (Navigation + Form)
3. **Phase 3**: Enhanced UX (Progress + Results)
4. **Phase 4**: Advanced features (Real-time updates + Export)

---

**Ready for Implementation** 🚀
