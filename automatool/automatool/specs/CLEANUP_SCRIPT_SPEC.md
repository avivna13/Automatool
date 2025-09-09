# 🧹 Cleanup Script Implementation Specification

## **Overview**
Create a new standalone Python script `cleanup.py` in the same directory as `automatool.py` that will handle all cleanup operations for resources tracked by the APK analysis automation tool.

## **Purpose**
The cleanup script will:
1. Load the existing `automation_resources.json` file
2. Execute cleanup of all tracked resources (processes, files, directories, APK uninstall)
3. Archive the cleaned runs and reset the tracker
4. Provide detailed feedback on what was cleaned

## **File Structure**
```
automatool/automatool/src/
├── automatool.py          # Main automation script
├── cleanup.py             # NEW: Dedicated cleanup script
└── scripts/automations/
    └── resource_tracker.py # Enhanced with new cleanup methods
```

## **Phase 1: New Script Creation**

### **1.1 New File: `cleanup.py`**
- **Location**: `automatool/automatool/src/cleanup.py`
- **Purpose**: Dedicated cleanup script with its own command-line interface
- **Structure**: 
  - Command-line argument parsing
  - Main cleanup execution logic
  - Resource tracker integration
  - User feedback and reporting

### **1.2 Script Structure**
```python
#!/usr/bin/env python3
"""
APK Analysis Cleanup Tool

This script cleans up all resources tracked by automatool.py including:
- Running processes (Jadx, VS Code)
- Generated files and directories
- Installed APKs on connected devices
- Resource tracking JSON file

Usage:
  python cleanup.py [options]
"""

import argparse
import sys
from scripts.automations.resource_tracker import GlobalResourceTracker
```

## **Phase 2: Command Line Interface**

### **2.1 Argument Parser**
```python
def parse_arguments():
    """Parse command line arguments for cleanup script."""
    parser = argparse.ArgumentParser(
        description="Clean up all resources tracked by automatool.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Clean all resources
  %(prog)s --verbose         # Verbose cleanup with detailed output
  %(prog)s --force           # Skip confirmation prompts
  %(prog)s --dry-run         # Show what would be cleaned without executing
  %(prog)s --current-only    # Clean only current run, not archived runs
        """
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output for debugging"
    )
    
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Skip confirmation prompts (dangerous!)"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be cleaned without executing cleanup"
    )
    
    parser.add_argument(
        "--current-only",
        action="store_true",
        help="Clean only current run, not archived runs"
    )
    
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Show resource summary without cleaning"
    )
    
    return parser.parse_args()
```

## **Phase 3: Core Cleanup Logic**

### **3.1 Main Cleanup Function**
```python
def execute_cleanup(tracker, args):
    """Execute the main cleanup process."""
    print("🧹 Starting APK Analysis Cleanup...")
    
    if args.dry_run:
        return execute_dry_run(tracker, args)
    
    if args.summary_only:
        return show_resource_summary(tracker)
    
    # Confirm cleanup unless --force is used
    if not args.force:
        if not confirm_cleanup(tracker):
            print("❌ Cleanup cancelled by user")
            return False
    
    # Execute cleanup based on options
    if args.current_only:
        return cleanup_current_run(tracker, args)
    else:
        return cleanup_all_resources(tracker, args)
```

### **3.2 Cleanup Modes**
- **Full Cleanup**: Clean all archived runs + current run
- **Current Only**: Clean only current run
- **Dry Run**: Show what would be cleaned without executing
- **Summary Only**: Display resource summary without cleaning

## **Phase 4: Enhanced Resource Tracker Methods**

### **4.1 New Method: `cleanup_archived_runs()`**
- **File**: `automatool/automatool/src/scripts/automations/resource_tracker.py`
- **Purpose**: Clean up all archived runs
- **Features**:
  - Iterate through all archived runs
  - Clean each run individually
  - Remove cleaned runs from archive
  - Return summary of cleaned resources

### **4.2 Enhanced `cleanup_all()` Method**
- **File**: `automatool/automatool/src/scripts/automations/resource_tracker.py`
- **Purpose**: Improve current cleanup method
- **Enhancements**:
  - Better error handling for individual resource cleanup
  - Continue cleanup even if some resources fail
  - Return detailed summary of cleanup results

## **Phase 5: User Experience & Safety**

### **5.1 Confirmation System**
```python
def confirm_cleanup(tracker):
    """Get user confirmation for destructive cleanup operation."""
    summary = tracker.get_resource_summary()
    
    print("\n⚠️  WARNING: This will permanently delete the following resources:")
    print(f"   • {summary['processes']} running processes")
    print(f"   • {summary['files']} generated files")
    print(f"   • {summary['directories']} created directories")
    print(f"   • {summary['total_runs']} automation runs")
    
    response = input("\nAre you sure you want to continue? (yes/no): ").lower().strip()
    return response in ['yes', 'y']
```

### **5.2 Dry Run Mode**
```python
def execute_dry_run(tracker, args):
    """Show what would be cleaned without executing."""
    print("🔍 DRY RUN MODE - No resources will be deleted")
    
    # Show current run resources
    current = tracker.resources.get("current_run", {})
    show_run_resources("Current Run", current)
    
    # Show archived runs resources
    archived = tracker.resources.get("runs", [])
    for i, run in enumerate(archived, 1):
        show_run_resources(f"Archived Run {i}", run)
```

### **5.3 Progress Reporting**
- Real-time progress updates during cleanup
- Clear indication of what's being cleaned
- Error reporting for failed cleanup operations
- Summary of successful vs failed cleanups

## **Phase 6: Output & Reporting**

### **6.1 Cleanup Summary**
```python
def show_cleanup_summary(cleanup_results):
    """Display detailed summary of cleanup results."""
    print("\n" + "="*50)
    print("🧹 CLEANUP SUMMARY")
    print("="*50)
    
    print(f"✅ Processes Terminated: {cleanup_results['processes_killed']}")
    print(f"✅ Files Deleted: {cleanup_results['files_deleted']}")
    print(f"✅ Directories Removed: {cleanup_results['directories_removed']}")
    print(f"✅ APKs Uninstalled: {cleanup_results['apks_uninstalled']}")
    
    if cleanup_results['errors']:
        print(f"\n⚠️  Errors Encountered: {len(cleanup_results['errors'])}")
        for error in cleanup_results['errors']:
            print(f"   • {error}")
    
    print("="*50)
```

### **6.2 Verbose Mode Output**
- Detailed logging of each cleanup step
- File paths being processed
- Process IDs being terminated
- Error details and stack traces

## **Phase 7: Testing & Validation**

### **7.1 Unit Tests**
- **File**: `automatool/automatool/tests/test_cleanup_script.py`
- **Purpose**: Test cleanup script functionality
- **Test Cases**:
  - Argument parsing
  - Dry run mode
  - Confirmation system
  - Error handling

### **7.2 Integration Tests**
- **File**: `automatool/automatool/tests/test_cleanup_integration.py`
- **Purpose**: Test end-to-end cleanup workflow
- **Test Cases**:
  - Full cleanup workflow
  - Resource tracker integration
  - File system operations
  - Process management

## **Implementation Order**

1. **Phase 1**: Create `cleanup.py` script structure
2. **Phase 2**: Implement command-line argument parsing
3. **Phase 3**: Create core cleanup execution logic
4. **Phase 4**: Enhance resource tracker methods
5. **Phase 5**: Implement user experience features
6. **Phase 6**: Add output and reporting
7. **Phase 7**: Create comprehensive tests

## **Usage Examples**

```bash
# Basic cleanup with confirmation
python cleanup.py

# Verbose cleanup with detailed output
python cleanup.py --verbose

# Force cleanup without confirmation
python cleanup.py --force

# See what would be cleaned without executing
python cleanup.py --dry-run

# Clean only current run
python cleanup.py --current-only

# Show resource summary without cleaning
python cleanup.py --summary-only

# Combine options
python cleanup.py --verbose --current-only
```

## **Success Criteria**

- ✅ `cleanup.py` script is created and functional
- ✅ All cleanup modes work correctly
- ✅ User confirmation system prevents accidental cleanup
- ✅ Dry run mode shows what would be cleaned
- ✅ Comprehensive error handling and reporting
- ✅ Integration with existing resource tracker
- ✅ Full test coverage
- ✅ Clear documentation and help text

## **Risks & Considerations**

1. **Data Loss**: Cleanup is destructive - need clear warnings and confirmation
2. **Process Termination**: Killing processes may affect user experience
3. **File System Access**: Need proper permissions for file/directory removal
4. **ADB Dependencies**: APK uninstall requires ADB and connected device
5. **Cross-Platform**: Ensure Windows/Linux compatibility
6. **Resource Tracker State**: Ensure cleanup doesn't corrupt the JSON file

## **Dependencies**

- **Existing**: `GlobalResourceTracker` class from `resource_tracker.py`
- **New**: Enhanced cleanup methods in resource tracker
- **External**: ADB for APK uninstallation
- **System**: File system access, process management

## **Future Enhancements**

- **Selective Cleanup**: Clean specific resource types only
- **Backup Before Cleanup**: Create backup of resources before deletion
- **Scheduled Cleanup**: Automate cleanup at specific intervals
- **Cleanup History**: Track what was cleaned and when
- **Integration with CI/CD**: Automated cleanup in build pipelines

---

**Status**: Ready for Implementation Review
**Created**: 2025-01-01
**Author**: AI Assistant
**Review Required**: User approval before implementation
