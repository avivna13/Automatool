# 🤖 Gemini CLI Web Integration Specification

## **Overview**
Integrate the Gemini CLI automation into the automatool_ui web interface as a standalone feature, allowing users to send AI-powered prompts to analyze APK data through a simple web UI.

## **Purpose**
Add Gemini CLI functionality to the web interface with:
1. **Easy Access**: Navigation button from main page to dedicated Gemini page
2. **User-Friendly Interface**: Simple text field for custom prompts
3. **Predefined Prompts**: Quick-select buttons for common security analysis tasks
4. **Output Directory Integration**: Automatically uses existing APK analysis output directories
5. **Real-time Feedback**: Shows execution status and results

## **UI/UX Requirements**

### **Main Page Integration**
- **New Navigation Button**: Add "🤖 AI Analysis" button to existing action panel on index.html
- **Button Placement**: Include in the existing "Analysis Actions" panel alongside other automation buttons
- **Visual Design**: Follow existing button styling (`.btn .btn-primary`)

### **Dedicated Gemini Page (`/gemini`)**
- **Simple Layout**: Single panel design following existing patterns
- **Two Input Methods**:
  1. **Text Area**: Large text field for custom prompts
  2. **Predefined Prompts**: Quick-select buttons for common scenarios
- **Output Directory Selection**: Dropdown or input field to select analysis directory
- **Execution Controls**: Submit button and status display

## **Implementation Strategy**

### **Minimal Complexity Approach**
Following the existing automatool_ui patterns for simplicity:

1. **Single Route Addition**: Add `/gemini` route to app.py
2. **Single Template**: Create `templates/gemini.html`
3. **Single API Endpoint**: Add `/api/gemini/prompt` for prompt processing
4. **JavaScript Extension**: Extend existing AutomatoolUI class
5. **No Database**: Store results as files (following existing pattern)

## **Technical Architecture**

### **Backend Integration (Flask)**

#### **New Route in app.py**
```python
@app.route('/gemini')
def gemini_analysis():
    """Gemini CLI analysis page."""
    return render_template('gemini.html', state=app_state)

@app.route('/api/gemini/prompt', methods=['POST'])
def handle_gemini_prompt():
    """Handle Gemini prompt submission."""
    # Import and use the existing launch_gemini_prompt function
    # Return JSON response with success/error and file path
```

#### **Function Integration**
```python
# Import the automation function
from scripts.automations.launch_gemini_prompt import send_prompt_to_gemini

# Use in API endpoint
result_file = send_prompt_to_gemini(prompt, output_dir, verbose=True)
```

### **Frontend Implementation**

#### **Navigation Button (index.html)**
Add to existing Analysis Actions panel:
```html
<div class="panel">
    <h2>Analysis Actions</h2>
    <div class="action-buttons">
        <button class="btn btn-primary action-btn" data-action="full_process">🔄 Full Process</button>
        <button class="btn btn-primary action-btn" data-action="get_reviews">📱 Get Reviews</button>
        <!-- NEW BUTTON -->
        <button class="btn btn-primary" onclick="window.location.href='/gemini'">🤖 AI Analysis</button>
        <button class="btn btn-primary action-btn" data-action="clean">🧹 Clean</button>
        <button class="btn btn-primary action-btn" data-action="upload_mobsf">🔍 Upload to MobSF</button>
    </div>
</div>
```

#### **Gemini Page Template (gemini.html)**
```html
{% extends "base.html" %}

{% block content %}
<div class="panel">
    <h2>🤖 AI-Powered Security Analysis</h2>
    
    <!-- Output Directory Selection -->
    <div class="form-group">
        <label for="output-dir">Analysis Directory:</label>
        <input type="text" id="output-dir" placeholder="/path/to/analysis/directory" required>
    </div>
    
    <!-- Predefined Prompts -->
    <div class="form-group">
        <label>Quick Prompts:</label>
        <div class="prompt-buttons">
            <button class="btn btn-secondary prompt-btn" data-prompt="security-analysis">Security Analysis</button>
            <button class="btn btn-secondary prompt-btn" data-prompt="risk-assessment">Risk Assessment</button>
            <button class="btn btn-secondary prompt-btn" data-prompt="vulnerability-review">Vulnerability Review</button>
        </div>
    </div>
    
    <!-- Custom Prompt -->
    <div class="form-group">
        <label for="custom-prompt">Custom Prompt:</label>
        <textarea id="custom-prompt" rows="4" placeholder="Enter your analysis prompt..."></textarea>
    </div>
    
    <!-- Submit Button -->
    <button class="btn btn-primary" id="submit-prompt">🚀 Analyze</button>
    
    <!-- Status Display -->
    <div id="status-display" style="display: none;"></div>
    
    <!-- Results -->
    <div id="results-display" style="display: none;"></div>
</div>
{% endblock %}
```

### **JavaScript Integration (main.js)**

#### **Extend Existing AutomatoolUI Class**
```javascript
// Add to existing AutomatoolUI class
bindGeminiEvents() {
    // Predefined prompt buttons
    document.querySelectorAll('.prompt-btn').forEach(btn => {
        btn.addEventListener('click', this.selectPredefinedPrompt.bind(this));
    });
    
    // Submit button
    const submitBtn = document.getElementById('submit-prompt');
    if (submitBtn) {
        submitBtn.addEventListener('click', this.submitGeminiPrompt.bind(this));
    }
}

async submitGeminiPrompt() {
    const outputDir = document.getElementById('output-dir').value;
    const customPrompt = document.getElementById('custom-prompt').value;
    
    // Validate and submit
    // Show status, handle response
}
```

## **Predefined Prompts**

### **Security Analysis Templates**
Based on common APK analysis scenarios:

1. **Security Analysis**: 
   ```
   "Based on all analysis results in this directory including reviews, YARA scan results, and APK structure, provide a comprehensive security assessment highlighting potential threats and vulnerabilities."
   ```

2. **Risk Assessment**:
   ```
   "Analyze the risk level of this application based on user reviews, detected patterns, and static analysis results. Provide a risk score and recommendations."
   ```

3. **Vulnerability Review**:
   ```
   "Review the YARA scan results and APK analysis findings to identify specific vulnerabilities and provide remediation suggestions."
   ```

4. **User Feedback Analysis**:
   ```
   "Analyze the user reviews to identify potential security concerns, suspicious behavior reports, or malware indicators mentioned by users."
   ```

5. **Malware Detection Summary**:
   ```
   "Summarize all malware detection results from static analysis and provide a clear assessment of whether this APK contains malicious code."
   ```

## **User Workflow**

### **Simple 3-Step Process**
1. **Navigate**: Click "🤖 AI Analysis" from main page
2. **Configure**: 
   - Select or enter output directory path
   - Choose predefined prompt OR enter custom prompt
3. **Execute**: Click "🚀 Analyze" and view results

### **Directory Integration**
- **Auto-detection**: If user came from a completed analysis, auto-populate directory
- **Manual Input**: Allow manual directory path entry
- **Validation**: Verify directory exists and contains analysis files

## **File Structure**

### **New Files to Create**
```
automatool_ui/
├── templates/
│   └── gemini.html                    # NEW: Gemini analysis page
└── static/
    └── css/
        └── (extend existing style.css)  # Minor CSS additions if needed
```

### **Files to Modify**
```
automatool_ui/
├── app.py                             # Add routes and API endpoints
├── templates/
│   └── index.html                     # Add navigation button
└── static/js/
    └── main.js                        # Extend AutomatoolUI class
```

## **API Specification**

### **POST /api/gemini/prompt**
**Request:**
```json
{
    "prompt": "Analyze the security implications...",
    "output_directory": "/path/to/analysis/directory",
    "verbose": true
}
```

**Response (Success):**
```json
{
    "success": true,
    "message": "Analysis completed successfully",
    "result_file": "/path/to/analysis/directory/prompts/outputs/analyze_security_20250101_143000.txt",
    "execution_time": "45 seconds"
}
```

**Response (Error):**
```json
{
    "success": false,
    "error": "Gemini CLI not found. Please install: npm install -g @google-ai/generative-ai-cli",
    "details": "FileNotFoundError: gemini command not found"
}
```

## **Error Handling Strategy**

### **User-Friendly Error Messages**
1. **Missing Gemini CLI**: Clear installation instructions
2. **Invalid Directory**: Directory picker with validation
3. **Empty Prompt**: Prompt validation before submission
4. **Network Issues**: Retry suggestions and timeout handling
5. **Permission Errors**: Clear permission troubleshooting

### **Status Feedback**
1. **Submitting**: Show loading spinner
2. **Processing**: "Analyzing with Gemini AI..."
3. **Success**: Show result file link and preview
4. **Error**: Show error message and suggested actions

## **Integration Points**

### **With Existing Automatool Workflow**
- **Standalone Usage**: Can be used independently of other automations
- **Post-Analysis Usage**: Most effective after APK analysis is complete
- **File Integration**: Works with existing output directory structure
- **Resource Tracking**: Integrates with existing GlobalResourceTracker (if needed)

### **Configuration Requirements**
- **Gemini CLI**: Must be installed on the server
- **API Keys**: Gemini API keys must be configured
- **File Permissions**: Web server must have access to analysis directories

## **Security Considerations**

### **Input Validation**
- **Prompt Sanitization**: Validate and sanitize prompt content
- **Path Validation**: Ensure output directory paths are safe
- **File Access**: Restrict access to authorized directories only

### **API Security**
- **Rate Limiting**: Prevent abuse of Gemini API
- **Authentication**: Consider adding authentication for production use
- **Error Information**: Don't expose sensitive system information in errors

## **Testing Strategy**

### **Unit Tests**
- Test prompt validation logic
- Test directory path validation
- Mock Gemini CLI responses for testing

### **Integration Tests**
- Test full workflow with mock directories
- Test error handling scenarios
- Test API endpoint responses

### **User Testing**
- Test UI usability with different prompt types
- Test error message clarity
- Test workflow from main page to results

## **Future Enhancements**

1. **Prompt History**: Save and reuse previous prompts
2. **Batch Processing**: Multiple directories at once
3. **Result Export**: Download results in different formats
4. **Advanced Options**: Model selection, timeout configuration
5. **Real-time Streaming**: Show Gemini response as it generates

## **Success Criteria**

1. ✅ **Easy Navigation**: Single click from main page to Gemini analysis
2. ✅ **Intuitive Interface**: Simple form with clear options
3. ✅ **Quick Actions**: Predefined prompts work immediately
4. ✅ **Custom Flexibility**: Custom prompts work correctly
5. ✅ **Clear Feedback**: Status updates and error messages are helpful
6. ✅ **File Integration**: Results saved in expected directory structure
7. ✅ **Performance**: Analysis completes within reasonable time (< 5 minutes)

## **Implementation Priority**

### **Phase 1: Core Functionality**
1. Add navigation button to index.html
2. Create basic gemini.html template
3. Add /gemini route to app.py
4. Implement /api/gemini/prompt endpoint
5. Basic JavaScript integration

### **Phase 2: Polish & UX**
1. Add predefined prompt buttons
2. Improve status feedback
3. Add result display
4. Error handling improvements
5. CSS styling enhancements

### **Phase 3: Advanced Features**
1. Directory auto-detection
2. Prompt validation
3. Result previews
4. Performance optimizations

This specification provides a simple, clear implementation path that follows existing automatool_ui patterns while adding powerful Gemini CLI integration.
