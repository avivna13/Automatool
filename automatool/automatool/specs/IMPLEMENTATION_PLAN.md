# Resource Tracking Integration Implementation Plan

## Overview
Integrate the `GlobalResourceTracker` into the main `automatool.py` script to track all resources created during automation runs, including processes, files, directories, and APK installations.

## User Requirements Confirmed
1. ✅ **Launch Function Changes**: Yes - comfortable with changing return values from `bool` to `subprocess.Popen`
2. ✅ **Error Handling**: Yes - resource tracking failures should stop the automation (not just log warnings)
3. ✅ **File Tracking**: Only track dirs and files that appear in the main flow
4. ✅ **Testing Approach**: Yes - implement comprehensive unit and integration tests in `tests/` directory

## Current State Analysis
- **Resource Tracker**: ✅ Created and ready (`resource_tracker.py`)
- **Main Script**: Needs integration with resource tracker
- **Launch Functions**: Currently return `bool`, need to return `subprocess.Popen` objects for PID tracking
- **File Tracking**: Need to identify all generated files and directories from main flow only
- **Test Infrastructure**: Existing test files in `tests/` directory

## Implementation Plan

### Phase 1: Modify Launch Functions (Non-Breaking Changes)
**Goal**: Update launch functions to return process objects while maintaining backward compatibility.

#### 1.1 Update `launch_jadx.py`
- **Current**: Returns `bool` (True/False)
- **Change**: Return `subprocess.Popen` object on success, `False` on failure
- **Benefit**: Can extract PID for process tracking
- **Risk**: Low - existing code expecting boolean will still work

#### 1.2 Update `launch_vscode.py`
- **Current**: Returns `bool` (True/False)  
- **Change**: Return `subprocess.Popen` object on success, `False` on failure
- **Benefit**: Can extract PID for process tracking
- **Risk**: Low - existing code expecting boolean will still work

### Phase 2: Integrate Resource Tracker into Main Script
**Goal**: Add resource tracking calls throughout the automation workflow.

#### 2.1 Import and Initialize
- Add import: `from scripts.automations.resource_tracker import GlobalResourceTracker`
- Add import: `import os` (for path operations)
- Initialize tracker: `resource_tracker = GlobalResourceTracker()`
- Start new run: `resource_tracker.start_new_run()`

#### 2.2 Track Package Name
- **Location**: After `extract_package_name_with_fallback()`
- **Action**: `resource_tracker.set_package_name(package_name)`
- **Purpose**: Track which APK package is being analyzed

#### 2.3 Track Process Launches
- **Location**: After `launch_jadx_gui()` and `launch_vscode()`
- **Action**: Extract PID from returned process objects
- **Code Pattern**:
  ```python
  jadx_process = launch_jadx_gui(apk_path, args.verbose)
  if jadx_process:
      resource_tracker.add_process("jadx", jadx_process.pid)
  ```

#### 2.4 Track Generated Files (Main Flow Only)
- **Reviews**: Track `reviews.json` and `reviews_summary.txt`
- **YARA**: Track `yara.json` and `yara_summary.txt`  
- **Research Plan**: Track generated research plan file

#### 2.5 Track Generated Directories (Main Flow Only)
- **Frida Scripts**: Track `{target_dir}/frida_scripts/`
- **Prompts**: Track `{target_dir}/prompts/`

#### 2.6 Track APK Installation
- **Location**: After `install_apk_on_device()` call
- **Action**: `resource_tracker.mark_apk_installed()` if successful

### Phase 3: File and Directory Tracking Strategy
**Goal**: Ensure all resources created by automation are properly tracked.

#### 3.1 Files to Track (Main Flow Only)
- `reviews.json` - Raw reviews data
- `reviews_summary.txt` - Parsed reviews summary
- `yara.json` - YARA analysis results
- `yara_summary.txt` - YARA summary
- `research_plan.txt` - Generated research plan

#### 3.2 Directories to Track (Main Flow Only)
- `{target_dir}/frida_scripts/` - Copied Frida scripts
- `{target_dir}/prompts/` - Generated prompts

#### 3.3 Tracking Approach
- **Existence Check**: Only track files/dirs that actually exist
- **Absolute Paths**: Convert all paths to absolute for consistent tracking
- **Error Handling**: Resource tracking failures should STOP the automation (not just log warnings)

### Phase 4: Integration Points in Main Script
**Goal**: Map exactly where each tracking call should be inserted.

#### 4.1 Main Function Flow
```
1. Initialize resource tracker
2. Start new run
3. Extract package name → Track package name
4. Launch Jadx → Track Jadx PID
5. Launch VS Code → Track VS Code PID
6. Run reviews → Track reviews files
7. Copy Frida scripts → Track Frida scripts directory
8. Parse YARA → Track YARA files
9. Generate research plan → Track research plan file + prompts directory
10. Install APK → Track APK installation status
```

#### 4.2 Specific Code Changes
- **Line ~75**: Add tracker initialization
- **Line ~85**: Add package name tracking
- **Line ~88**: Modify Jadx launch and add PID tracking
- **Line ~92**: Modify VS Code launch and add PID tracking
- **Line ~95**: Add reviews file tracking
- **Line ~100**: Add Frida scripts directory tracking
- **Line ~105**: Add YARA file tracking
- **Line ~110**: Add research plan file and prompts directory tracking
- **Line ~115**: Add APK installation tracking

### Phase 5: Comprehensive Testing Strategy
**Goal**: Implement comprehensive unit and integration tests in `tests/` directory.

#### 5.1 Unit Tests
**File**: `test_resource_tracker.py`
- Test resource tracker initialization
- Test process tracking (add_process, get_resource_summary)
- Test file/directory tracking (add_file, add_directory)
- Test package name and APK installation tracking
- Test resource cleanup functionality
- Test JSON file creation and loading
- Test error handling scenarios

**File**: `test_launch_functions.py`
- Test modified launch functions return process objects
- Test PID extraction from returned processes
- Test backward compatibility (boolean-like behavior)
- Test error handling in launch functions

#### 5.2 Integration Tests
**File**: `test_automatool_integration.py`
- Test complete automation workflow with resource tracking
- Test `automation_resources.json` creation in workspace root
- Test all resources are properly tracked
- Test JSON structure is correct
- Test resource accumulation across multiple runs
- Test with and without `--install` flag

**File**: `test_file_tracking.py`
- Test tracking of all generated files from main flow
- Test tracking of all created directories from main flow
- Test absolute path conversion
- Test existence checking before tracking

#### 5.3 Test Resources
**Directory**: `tests/resources/`
- Create mock APK files for testing
- Create mock JSON files (reviews.json, yara.json)
- Create mock output directories
- Create expected resource tracking JSON files

#### 5.4 Test Scenarios
1. **Basic Resource Tracking**: Single automation run
2. **Multiple Runs**: Resource accumulation across runs
3. **Error Handling**: Resource tracking failures
4. **Process Management**: PID tracking and cleanup
5. **File Operations**: File/directory creation and tracking
6. **APK Installation**: Installation status tracking
7. **Cross-Platform**: Windows/Linux compatibility

### Phase 6: Error Handling and Validation
**Goal**: Implement robust error handling that stops automation on resource tracking failures.

#### 6.1 Error Handling Strategy
- **Resource Tracker Initialization**: Stop if tracker cannot be initialized
- **File Operations**: Stop if critical files cannot be tracked
- **Process Tracking**: Stop if process PIDs cannot be captured
- **JSON Operations**: Stop if resource file cannot be created/updated

#### 6.2 Validation Points
- Verify resource tracker initialization
- Verify process object returns from launch functions
- Verify file/directory existence before tracking
- Verify JSON file creation and updates
- Verify resource accumulation across runs

## Risk Assessment

### Low Risk
- **Launch function changes**: Return process objects instead of bool
- **Resource tracking**: Additive functionality, doesn't change core behavior
- **File operations**: Only read operations, no destructive changes

### Medium Risk
- **Import changes**: Adding new dependencies
- **Path operations**: Need to ensure cross-platform compatibility
- **Error handling**: Strict error handling may break existing workflows

### High Risk
- **Process management**: PID tracking and cleanup operations
- **File cleanup**: Automatic deletion of tracked resources

### Mitigation Strategies
- **Comprehensive testing**: Unit and integration tests for all components
- **Error logging**: Detailed error reporting for debugging
- **Fallback handling**: Graceful degradation where possible
- **Cross-platform testing**: Test on Windows, Linux, and Mac

## Expected Outcomes

### After Implementation
1. **Resource Tracking**: All automation resources properly tracked
2. **JSON File**: `automation_resources.json` created in workspace root
3. **Process Tracking**: Jadx and VS Code PIDs captured
4. **File Tracking**: All generated files logged with absolute paths
5. **Directory Tracking**: All created directories logged
6. **APK Tracking**: Package names and installation status tracked
7. **Comprehensive Tests**: Full test coverage for all functionality

### Benefits
1. **Complete Resource Visibility**: Know exactly what was created
2. **Automated Cleanup**: Enable `cleanup.py` to remove all resources
3. **Process Management**: Can kill tracked processes during cleanup
4. **APK Management**: Can uninstall tracked APKs during cleanup
5. **Cross-Run Tracking**: Accumulate resources across multiple automation runs
6. **Quality Assurance**: Comprehensive testing ensures reliability

## Implementation Order
1. **Phase 1**: Modify launch functions (return process objects)
2. **Phase 2**: Integrate resource tracker into main script
3. **Phase 3**: Implement file/directory tracking strategy
4. **Phase 4**: Complete main script integration
5. **Phase 5**: Implement comprehensive testing
6. **Phase 6**: Add error handling and validation

## Success Criteria
- [ ] All launch functions return process objects
- [ ] Resource tracker integrated into main script
- [ ] All main flow files and directories tracked
- [ ] Process PIDs captured and tracked
- [ ] APK installation status tracked
- [ ] `automation_resources.json` created in workspace root
- [ ] Comprehensive unit tests implemented
- [ ] Comprehensive integration tests implemented
- [ ] Error handling stops automation on failures
- [ ] Cross-platform compatibility verified

## Next Steps
1. Review and approve this implementation plan
2. Begin Phase 1: Modify launch functions
3. Implement each phase sequentially
4. Test thoroughly at each phase
5. Validate complete integration
6. Document any deviations or issues encountered
