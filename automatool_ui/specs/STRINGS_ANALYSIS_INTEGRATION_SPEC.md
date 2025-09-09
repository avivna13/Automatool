# Specification: Strings Analysis Integration for Automatool UI

## Overview
Integrate the `run_strings_on_so_files.py` functionality as a standalone button in the Automatool UI that allows users to run strings analysis on .so files from the currently analyzed APK.

## Current State Analysis
- The UI already has a `ProcessManager` class with a `execute_strings_on_so` method
- The UI supports multiple analysis actions (full-process, get-reviews, clean, mobsf)
- The UI maintains global state for APK analysis sessions
- The UI has a consistent pattern for action buttons and process management

## Requirements

### Functional Requirements
1. **Button Integration**: Add a "Run Strings Analysis" button to the Analysis Actions panel
2. **Prerequisites Check**: Button should be enabled only when an APK analysis is complete
3. **Execution**: Run strings analysis on .so files found in the apktool output directory
4. **Output Management**: Save results to the current analysis directory
5. **Status Updates**: Provide real-time feedback on execution progress
6. **Error Handling**: Graceful handling of failures and edge cases

### Technical Requirements
1. **Backend Integration**: Extend the existing action execution framework
2. **Process Management**: Integrate with existing `ProcessManager.execute_strings_on_so` method
3. **State Management**: Utilize existing global app state for APK and output directory
4. **UI Consistency**: Follow existing button styling and behavior patterns
5. **Logging**: Integrate with existing logging and status display system

## Implementation Plan

### 1. Backend Changes (app.py)

#### New Route
```python
@app.route('/api/action/strings-analysis', methods=['POST'])
def handle_strings_analysis():
    """Handle strings analysis execution on .so files."""
    # Check prerequisites
    if not app_state.get('setup_complete') or not app_state.get('OUTPUT_DIR'):
        return jsonify({
            'success': False,
            'message': 'Setup not complete. Please complete APK analysis first.'
        })
    
    # Start strings analysis
    success = process_manager.execute_strings_on_so(
        app_state['OUTPUT_DIR'],  # This should contain apktool output
        app_state['OUTPUT_DIR'],  # Output to same directory
        verbose=True
    )
    
    if success:
        return jsonify({
            'success': True,
            'message': 'Strings analysis started successfully',
            'action': 'strings-analysis'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Failed to start strings analysis'
        })
```

#### Update Action Validation
```python
# In execute_action function, update valid_actions:
valid_actions = ['full-process', 'get-reviews', 'clean', 'mobsf', 'strings-analysis']

# Add new handler:
elif action_name == 'strings-analysis':
    return handle_strings_analysis()
```

### 2. Frontend Changes (templates/index.html)

#### Add Button to Analysis Actions Panel
```html
<!-- Add this button to the action-buttons div -->
<button class="btn btn-primary action-btn" data-action="strings-analysis"
        {% if not state.setup_complete %}disabled{% endif %}>
    🔍 Run Strings Analysis
</button>
```

#### Update Button States
The button should follow the same pattern as other action buttons:
- **Disabled**: When no APK analysis is complete
- **Enabled**: When APK analysis is complete and apktool output exists
- **Loading**: During execution (following existing pattern)

### 3. JavaScript Integration (static/js/main.js)

#### Add Action Handler
```javascript
// Add to existing action button click handlers
if (action === 'strings-analysis') {
    executeStringsAnalysis();
}

function executeStringsAnalysis() {
    fetch('/api/action/strings-analysis', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showMessage('success', data.message);
            updateStatus('Strings analysis started...');
        } else {
            showMessage('error', data.message);
        }
    })
    .catch(error => {
        showMessage('error', 'Failed to start strings analysis: ' + error.message);
    });
}
```

### 4. Process Manager Integration

The existing `execute_strings_on_so` method in `ProcessManager` is already implemented and follows the established pattern. It will:
- Run the strings analysis script
- Handle process execution in background threads
- Provide real-time logging and status updates
- Integrate with existing process management system

## File Structure Changes

### New Files
None required - all functionality integrates with existing structure

### Modified Files
1. **`app.py`** - Add new route and action handler
2. **`templates/index.html`** - Add new button
3. **`static/js/main.js`** - Add JavaScript handler

## Prerequisites and Dependencies

### System Requirements
1. **`strings` command**: Must be available in system PATH (already handled by existing script)
2. **Python dependencies**: Already satisfied by existing requirements
3. **File permissions**: Read access to apktool output directory

### Analysis Prerequisites
1. **APK Analysis Complete**: User must have completed APK analysis (full-process or mobsf)
2. **Apktool Output**: The apktool output directory must exist and contain .so files
3. **Valid Output Directory**: Current analysis session must have a valid output directory

## User Experience Flow

### Normal Flow
1. User uploads APK and completes analysis
2. "Run Strings Analysis" button becomes enabled
3. User clicks button
4. System executes strings analysis on .so files
5. Results are saved to `native_libs_strings/` subdirectory
6. User receives success confirmation

### Edge Cases
1. **No .so files**: Inform user that no native libraries were found
2. **Strings command missing**: Clear error message about missing system dependency
3. **Permission issues**: Handle file access errors gracefully
4. **Process conflicts**: Prevent multiple simultaneous executions

## Output and Results

### File Structure
```
{analysis_directory}/
├── native_libs_strings/
│   ├── lib_libname.so.txt
│   ├── lib_another.so.txt
│   └── ...
├── mobsf_results/
├── other_analysis_results/
└── ...
```

### Result Format
- Each .so file gets its own `.txt` file
- Filename reflects the library path (sanitized for filesystem compatibility)
- Content contains all printable strings extracted from the binary

## Testing Strategy

### Unit Tests
1. **Route Testing**: Test new API endpoint with various states
2. **Prerequisites Testing**: Verify button state based on analysis completion
3. **Error Handling**: Test various failure scenarios

### Integration Tests
1. **End-to-End Flow**: Complete APK analysis → strings analysis → verify results
2. **Process Management**: Verify integration with existing process management
3. **UI State Management**: Test button states and user feedback

### Manual Testing
1. **Button States**: Verify button enables/disables correctly
2. **Execution Flow**: Test with real APK containing .so files
3. **Error Scenarios**: Test with missing dependencies or invalid states

## Security Considerations

1. **Path Validation**: Ensure all file paths are properly validated
2. **Process Isolation**: Strings analysis runs in isolated process
3. **File Access**: Limit access to analysis directories only
4. **Input Sanitization**: Validate all user inputs and file paths

## Performance Considerations

1. **Background Execution**: Strings analysis runs in background thread
2. **Progress Updates**: Real-time status updates during execution
3. **Resource Management**: Proper cleanup of temporary processes
4. **Memory Usage**: Handle large .so files efficiently

## Rollback Plan

If issues arise:
1. **Disable Button**: Temporarily disable the strings analysis button
2. **Process Cleanup**: Ensure any running processes are terminated
3. **State Reset**: Reset UI state to stable condition
4. **Logging**: Maintain detailed logs for debugging

## Success Criteria

1. ✅ Button appears in Analysis Actions panel
2. ✅ Button state correctly reflects analysis completion status
3. ✅ Clicking button executes strings analysis successfully
4. ✅ Results are saved to appropriate directory structure
5. ✅ User receives clear feedback on execution status
6. ✅ Integration with existing process management system
7. ✅ Error handling works for all edge cases
8. ✅ UI remains responsive during execution

## Future Enhancements

1. **Progress Bar**: Add progress indication for large .so files
2. **Result Preview**: Show extracted strings in UI
3. **Filtering**: Allow users to filter strings by type or content
4. **Export Options**: Additional export formats for results
5. **Batch Processing**: Support for multiple APK analysis

## Implementation Timeline

### Phase 1: Backend Integration (1-2 days)
- Add new API route
- Implement action handler
- Update action validation

### Phase 2: Frontend Integration (1-2 days)
- Add button to UI
- Implement JavaScript handler
- Update button states

### Phase 3: Testing & Validation (1-2 days)
- Unit testing
- Integration testing
- Manual testing

### Phase 4: Documentation & Deployment (0.5-1 day)
- Update documentation
- Deploy to development environment
- Final validation

## Dependencies

### Internal Dependencies
- Existing `ProcessManager.execute_strings_on_so` method
- Current UI action execution framework
- Global app state management system

### External Dependencies
- `strings` command availability in system PATH
- Python subprocess module
- Flask routing system

## Risk Assessment

### Low Risk
- UI integration (follows established patterns)
- Process management (uses existing infrastructure)
- Error handling (standard Flask error handling)

### Medium Risk
- File path validation (requires careful testing)
- Process execution (depends on system environment)
- State management (complexity in button states)

### Mitigation Strategies
- Comprehensive testing of file path scenarios
- Graceful fallback for missing system dependencies
- Clear user feedback for all error conditions

---

This specification provides a comprehensive plan for integrating the strings analysis functionality into the existing Automatool UI while maintaining consistency with current patterns and ensuring a smooth user experience. The implementation leverages existing infrastructure and follows established conventions for maintainability and reliability.
