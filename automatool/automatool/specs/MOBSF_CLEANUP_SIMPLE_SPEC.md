# 🧹 MobSF Cleanup Integration - Simple Specification

## **Overview**
Add MobSF analysis deletion to the existing cleanup system with minimal complexity.

## **Simple Strategy**

### **1. Store Hash in Resource Tracker**
Just add the scan hash to the existing resource structure:

```json
{
  "current_run": {
    "timestamp": "2025-01-15T10:30:00",
    "package_name": "com.example.app", 
    "apk_filename": "test.apk",
    "pid": {"jadx": 12345, "vscode": 67890},
    "files": ["path/to/file1"],
    "dirs": ["path/to/dir1"],
    "mobsf_hash": "71e562391bcee1a37d955159cf987dd7"
  }
}
```

### **2. Add Simple Deletion Function**
Create one simple function in the existing `launch_mobsf_container.py`:

```python
def delete_mobsf_analysis(scan_hash, verbose=False):
    """Delete MobSF analysis. Returns True if successful or already deleted."""
    try:
        # Get current API key
        api_key = get_mobsf_api_key(verbose)
        if not api_key:
            return False
            
        # Try to delete
        headers = {'Authorization': api_key}
        response = requests.post(
            'http://localhost:8000/api/v1/delete_scan',
            data={'hash': scan_hash},
            headers=headers,
            timeout=10
        )
        
        # Success if deleted or not found
        return response.status_code in [200, 404]
        
    except:
        return False  # Fail silently
```

### **3. Update Worker to Store Hash**
Add one line to `_mobsf_analysis_worker.py`:

```python
def download_results(scan_hash, api_key, output_dir, verbose=False):
    # ... existing code ...
    
    # Store hash in resource tracker
    store_mobsf_hash(scan_hash)
    
    return True

def store_mobsf_hash(scan_hash):
    """Store MobSF hash in resource tracker."""
    try:
        from resource_tracker import GlobalResourceTracker
        tracker = GlobalResourceTracker()
        tracker.resources["current_run"]["mobsf_hash"] = scan_hash
        tracker._save_resources()
    except:
        pass  # Fail silently
```

### **4. Update Cleanup Script**
Add MobSF cleanup to the existing cleanup functions:

```python
def cleanup_current_run(tracker, args):
    """Clean only current run."""
    # ... existing code before cleanup ...
    
    # Clean MobSF if hash exists
    cleanup_mobsf_hash(tracker.resources.get("current_run", {}), args.verbose)
    
    # ... rest of existing cleanup code ...

def cleanup_all_resources(tracker, args):
    """Clean all resources."""
    # ... existing code before cleanup ...
    
    # Clean all MobSF hashes
    current_run = tracker.resources.get("current_run", {})
    cleanup_mobsf_hash(current_run, args.verbose)
    
    for run in tracker.resources.get("runs", []):
        cleanup_mobsf_hash(run, args.verbose)
    
    # ... rest of existing cleanup code ...

def cleanup_mobsf_hash(run_data, verbose=False):
    """Clean single MobSF hash if it exists."""
    mobsf_hash = run_data.get("mobsf_hash")
    if not mobsf_hash:
        return
        
    if verbose:
        print(f"🗑️  Deleting MobSF analysis: {mobsf_hash[:8]}...")
    
    from scripts.automations.launch_mobsf_container import delete_mobsf_analysis
    
    if delete_mobsf_analysis(mobsf_hash, verbose):
        if verbose:
            print(f"   ✅ Deleted MobSF analysis")
    else:
        if verbose:
            print(f"   ⚠️  Failed to delete MobSF analysis (server may be down)")
```

## **Implementation Steps**

### **Step 1**: Add deletion function to `launch_mobsf_container.py`
- One simple function: `delete_mobsf_analysis(scan_hash, verbose=False)`

### **Step 2**: Update worker script 
- Add `store_mobsf_hash(scan_hash)` call after successful analysis
- Add the simple storage function

### **Step 3**: Update cleanup script
- Add `cleanup_mobsf_hash()` function
- Call it in existing cleanup functions

### **Step 4**: Update resource tracker
- Add `mobsf_hash` to resource summary display

## **Key Benefits of Simple Approach**

✅ **Minimal Code Changes**: Only ~20 lines of new code total
✅ **No New Files**: Uses existing files and patterns  
✅ **Fail-Safe**: All MobSF operations fail silently if server unavailable
✅ **One Hash Per Run**: Simple 1:1 relationship, no complex tracking
✅ **Backward Compatible**: Existing functionality unchanged
✅ **Easy to Test**: Simple functions, easy to verify

## **Limitations (Acceptable)**
- Only tracks the latest MobSF analysis per run (acceptable for most use cases)
- No retry logic (acceptable, cleanup will try again next time)
- No detailed error reporting (acceptable, cleanup continues regardless)

This approach gets 90% of the benefit with 10% of the complexity!
