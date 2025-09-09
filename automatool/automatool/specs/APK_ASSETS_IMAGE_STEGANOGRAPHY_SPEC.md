# 🖼️ APK Assets Image Steganography Analysis Specification

## **Overview**
Create a new standalone automation that analyzes all image files within the `assets/` directory of a decompiled APK to detect potential steganographic content. This automation integrates with the existing `apktool` decompilation workflow and leverages the established `detect_image_steganography.py` and `parse_steganography_results.py` components.

## **Purpose**
The APK assets image steganography automation will:
1. **Assets Directory Discovery**: Locate and analyze the `assets/` directory from apktool decompilation output
2. **Recursive Image Scanning**: Traverse all subdirectories within `assets/` to find image files
3. **Image Format Detection**: Identify supported image formats (PNG, JPEG, GIF, BMP, WebP)
4. **Steganography Analysis**: Use existing `detect_image_steganography.py` for each discovered image
5. **Results Aggregation**: Collect and parse all analysis results using `parse_steganography_results.py`
6. **Resource Tracking**: Integrate with `GlobalResourceTracker` for file and directory management
7. **Summary Generation**: Create comprehensive reports on all analyzed assets images

## **Technical Integration**

### **Apktool Integration Pattern**
Following the established pattern in `automatool.py`:
```python
# Current apktool integration (lines 136-145 in automatool.py)
apktool_output_path = run_apktool_decode(apk_path, args.directory, args.verbose)
if apktool_output_path:
    try:
        resource_tracker.add_directory(apktool_output_path)
    except Exception as e:
        # Error handling...
```

The new automation will receive the `apktool_output_path` and analyze its `assets/` subdirectory.

### **Assets Directory Structure**
After apktool decompilation, the typical structure is:
```
apktool_output/
├── AndroidManifest.xml
├── assets/                    # TARGET DIRECTORY
│   ├── images/
│   │   ├── logo.png          # Image to analyze
│   │   ├── background.jpg    # Image to analyze
│   │   └── icons/
│   │       └── icon.png      # Image to analyze (nested)
│   ├── data/
│   │   └── config.xml        # Skip - not an image
│   └── splash.png            # Image to analyze (root level)
├── res/
├── smali/
└── original/
```

## **Implementation Details**

### **Asynchronous Execution Pattern**

Following the established **subprocess pattern** from `launch_mobsf_analysis.py` and `_mobsf_analysis_worker.py`, the assets analysis will run as a separate background process to avoid blocking the main automation execution.

**Architecture:**
1. **Main Function**: `launch_assets_analysis.py` - Launches the background process
2. **Worker Process**: `_assets_analysis_worker.py` - Performs the actual analysis
3. **Resource Tracking**: Background process creates trackable output files
4. **Non-blocking**: Main execution continues while analysis runs in background

### **Main Launch Function: `launch_assets_analysis.py`**

Located at: `automatool/automatool/src/scripts/automations/launch_assets_analysis.py`

```python
#!/usr/bin/env python3
"""
Launch APK Assets Image Steganography Analysis

This script launches the assets image analysis as a background process
following the same pattern as launch_mobsf_analysis.py.
"""

import subprocess
import os
import sys

def launch_assets_analysis(apktool_output_path, target_directory, verbose=False, threshold_bytes=10):
    """
    Launch APK assets image analysis as a background process.
    
    Args:
        apktool_output_path (str): Path to the apktool decompilation output directory
        target_directory (str): Base target directory for saving analysis results
        verbose (bool): Enable verbose output
        threshold_bytes (int): Suspicious threshold for steganography detection
        
    Returns:
        subprocess.Popen or bool: Process object if launch was successful, False otherwise
    """
    if verbose:
        print(f"[DEBUG] Launching assets analysis for: {apktool_output_path}")
        print(f"[DEBUG] Output directory: {target_directory}")
        print(f"[DEBUG] Threshold: {threshold_bytes} bytes")
    
    try:
        # Get the worker script path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        worker_script = os.path.join(script_dir, "_assets_analysis_worker.py")
        
        # Verify worker script exists
        if not os.path.exists(worker_script):
            print("❌ ERROR: Assets analysis worker script not found.")
            if verbose:
                print(f"[DEBUG] Expected worker script at: {worker_script}")
            return False
        
        # Launch analysis worker as background process
        process = subprocess.Popen([
            sys.executable, worker_script,
            "--apktool-path", apktool_output_path,
            "--output-dir", target_directory,
            "--threshold", str(threshold_bytes),
            "--verbose" if verbose else "--quiet"
        ],
        stdout=subprocess.DEVNULL,  # Suppress stdout
        stderr=subprocess.DEVNULL,  # Suppress stderr
        text=True
        )
        
        if verbose:
            print(f"[DEBUG] ✅ Assets analysis launched with PID: {process.pid}")
            
        print("🖼️ APK assets image analysis started in background...")
        return process
        
    except FileNotFoundError:
        print("❌ ERROR: Python executable not found for worker process.")
        if verbose:
            print(f"[DEBUG] Python executable: {sys.executable}")
        return False
        
    except Exception as e:
        print(f"❌ ERROR: Failed to launch assets analysis: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False
```

### **Worker Process: `_assets_analysis_worker.py`**

Located at: `automatool/automatool/src/scripts/automations/_assets_analysis_worker.py`

```python
#!/usr/bin/env python3
"""
APK Assets Image Analysis Worker Process

This script runs as a separate background process to analyze all images
in the APK's assets directory for steganographic content.

Following the same pattern as _mobsf_analysis_worker.py.
"""

import argparse
import os
import sys
import json
import time
from pathlib import Path

# Add script directory to path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

# Import analysis components
from detect_image_steganography import detect_image_steganography
sys.path.insert(0, os.path.join(script_dir, '..', 'parsers'))
from parse_steganography_results import generate_combined_summary

def main():
    """Main worker process entry point."""
    parser = argparse.ArgumentParser(description="Assets image analysis worker")
    parser.add_argument("--apktool-path", required=True, help="Path to apktool output directory")
    parser.add_argument("--output-dir", required=True, help="Output directory for results")
    parser.add_argument("--threshold", type=int, default=10, help="Suspicious threshold in bytes")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--quiet", action="store_true", help="Suppress output")
    
    args = parser.parse_args()
    verbose = args.verbose and not args.quiet
    
    if verbose:
        print(f"[WORKER] Starting assets analysis...")
        print(f"[WORKER] Apktool path: {args.apktool_path}")
        print(f"[WORKER] Output directory: {args.output_dir}")
        print(f"[WORKER] Threshold: {args.threshold} bytes")
    
    try:
        # Perform the complete analysis workflow
        results = analyze_apk_assets_images_worker(
            args.apktool_path,
            args.output_dir,
            verbose,
            args.threshold
        )
        
        # Save results summary to file for main process tracking
        save_worker_results(results, args.output_dir, verbose)
        
        if verbose:
            print("[WORKER] ✅ Assets analysis completed successfully")
            
    except Exception as e:
        error_msg = f"Assets analysis worker failed: {e}"
        if verbose:
            print(f"[WORKER] ❌ {error_msg}")
        
        # Save error status for main process
        save_worker_error(error_msg, args.output_dir, verbose)
        sys.exit(1)

def analyze_apk_assets_images_worker(apktool_output_path, target_directory, verbose=False, threshold_bytes=10):
    """
    Worker function that performs the actual assets analysis.
    
    Returns:
        dict: Analysis results
    """
    # Step 1: Find assets directory
    assets_path = find_assets_directory(apktool_output_path, verbose)
    if not assets_path:
        return {
            'total_images_found': 0,
            'total_images_analyzed': 0,
            'suspicious_images_count': 0,
            'analysis_results': [],
            'summary_text': "No assets directory found in decompiled APK.",
            'output_directory': None,
            'status': 'no_assets'
        }
    
    # Step 2: Discover images
    image_files = discover_images_in_assets(assets_path, verbose)
    if not image_files:
        return {
            'total_images_found': 0,
            'total_images_analyzed': 0,
            'suspicious_images_count': 0,
            'analysis_results': [],
            'summary_text': "No image files found in assets directory.",
            'output_directory': None,
            'status': 'no_images'
        }
    
    # Step 3: Create output directory
    output_directory = os.path.join(target_directory, "assets_steganography_analysis")
    os.makedirs(output_directory, exist_ok=True)
    
    # Step 4: Analyze each image
    analysis_results = analyze_discovered_images(image_files, output_directory, threshold_bytes, verbose)
    
    # Step 5: Generate summary
    summary_text = generate_assets_summary(analysis_results, output_directory, verbose)
    
    # Count suspicious images
    suspicious_count = sum(1 for result in analysis_results if result.get('is_suspicious', False))
    
    return {
        'total_images_found': len(image_files),
        'total_images_analyzed': len(analysis_results),
        'suspicious_images_count': suspicious_count,
        'analysis_results': analysis_results,
        'summary_text': summary_text,
        'output_directory': output_directory,
        'status': 'completed'
    }
```

### **Integration Point in `automatool.py`**

Add the new automation after the apktool decode step (around line 146):

```python
# Import the new launch function
from scripts.automations.launch_assets_analysis import launch_assets_analysis

# Current code (lines 136-145)
apktool_output_path = run_apktool_decode(apk_path, args.directory, args.verbose)
if apktool_output_path:
    try:
        resource_tracker.add_directory(apktool_output_path)
    except Exception as e:
        # Error handling...

# NEW INTEGRATION POINT - Launch assets analysis in background
# Launch APK assets image steganography analysis (unless skipped)
if not args.skip_assets_analysis:
    assets_process = launch_assets_analysis(
        apktool_output_path, 
        args.directory, 
        args.verbose
    )
    
    if assets_process:
        try:
            # Track the assets analysis process (for cleanup)
            resource_tracker.add_process("assets_analysis", assets_process.pid)
            
            # The worker process will create trackable files asynchronously
            # These will be tracked via the resource monitoring system
            
        except Exception as e:
            print(f"❌ ERROR: Failed to track assets analysis process: {e}")
            if args.verbose:
                print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
            raise  # Stop automation on resource tracking failure
else:
    print("⏭️ Skipping APK assets image analysis (--skip-assets-analysis)")
```

## **Functional Workflow**

### **Step 1: Assets Directory Discovery**
```python
def _find_assets_directory(apktool_output_path, verbose=False):
    """
    Locate the assets directory within apktool output.
    
    Returns:
        str: Path to assets directory, or None if not found
    """
    assets_path = os.path.join(apktool_output_path, "assets")
    
    if os.path.exists(assets_path) and os.path.isdir(assets_path):
        if verbose:
            print(f"[DEBUG] Found assets directory: {assets_path}")
        return assets_path
    else:
        if verbose:
            print(f"[DEBUG] No assets directory found in: {apktool_output_path}")
        return None
```

### **Step 2: Recursive Image Discovery**
```python
def _discover_images_in_assets(assets_path, verbose=False):
    """
    Recursively discover all image files in the assets directory.
    
    Returns:
        list: List of image file paths
    """
    supported_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}
    image_files = []
    
    for root, dirs, files in os.walk(assets_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_extension = Path(file).suffix.lower()
            
            if file_extension in supported_extensions:
                image_files.append(file_path)
                if verbose:
                    relative_path = os.path.relpath(file_path, assets_path)
                    print(f"[DEBUG] Found image: assets/{relative_path}")
    
    return image_files
```

### **Step 3: Batch Image Analysis**
```python
def _analyze_discovered_images(image_files, output_directory, threshold_bytes, verbose=False):
    """
    Analyze each discovered image using the existing steganography detection.
    
    Returns:
        list: List of analysis results from detect_image_steganography
    """
    analysis_results = []
    
    for image_path in image_files:
        if verbose:
            print(f"[DEBUG] Analyzing image: {os.path.basename(image_path)}")
        
        # Use existing steganography detection
        result = detect_image_steganography(
            image_path, 
            output_directory, 
            verbose, 
            threshold_bytes
        )
        
        if result:
            analysis_results.append(result)
        else:
            if verbose:
                print(f"[DEBUG] Failed to analyze: {image_path}")
    
    return analysis_results
```

### **Step 4: Results Aggregation and Summary**
```python
def _generate_assets_summary(analysis_results, output_directory, verbose=False):
    """
    Generate comprehensive summary using existing parser infrastructure.
    
    Returns:
        str: Human-readable summary text
    """
    # Use existing combined summary generator
    summary_text = generate_combined_summary(analysis_results, output_directory, verbose)
    
    # Save assets-specific summary
    summary_file = os.path.join(output_directory, "assets_steganography_summary.txt")
    with open(summary_file, 'w') as f:
        f.write("APK ASSETS IMAGE STEGANOGRAPHY ANALYSIS\n")
        f.write("=" * 45 + "\n\n")
        f.write(summary_text)
    
    return summary_text
```

## **Output Structure**

The automation will create the following output structure:

```
target_directory/
├── assets_steganography_analysis/          # New output directory
│   ├── assets_steganography_summary.txt    # Main summary file
│   ├── steganography_combined_summary.txt  # Generated by existing parser
│   ├── suspicious_image_report.txt         # Per-image reports (if suspicious)
│   └── individual_analysis_results/        # Detailed per-image results
│       ├── image1_analysis.txt
│       ├── image2_analysis.txt
│       └── ...
└── (other existing automatool outputs)
```

## **Error Handling and Edge Cases**

### **No Assets Directory**
```python
if not assets_path:
    print("📁 No assets directory found in APK")
    return {
        'total_images_found': 0,
        'total_images_analyzed': 0,
        'suspicious_images_count': 0,
        'analysis_results': [],
        'summary_text': "No assets directory found in decompiled APK.",
        'output_directory': None
    }
```

### **No Images Found**
```python
if not image_files:
    print("🖼️ No image files found in assets directory")
    # Create minimal report and return appropriate structure
```

### **Analysis Failures**
Following the established pattern from existing automations:
```python
try:
    result = detect_image_steganography(image_path, output_directory, verbose, threshold_bytes)
    if result:
        analysis_results.append(result)
    else:
        failed_analyses.append(image_path)
except Exception as e:
    print(f"❌ ERROR: Failed to analyze {os.path.basename(image_path)}: {e}")
    if verbose:
        print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
    failed_analyses.append(image_path)
```

## **Resource Tracking Integration**

### **Process Tracking (Main Thread)**
Following the established pattern from `automatool.py`:

```python
# Track the background process for cleanup
if assets_process:
    resource_tracker.add_process("assets_analysis", assets_process.pid)
```

### **File Tracking (Background Process)**
The worker process creates trackable files that can be discovered by cleanup tools:

```python
def save_worker_results(results, output_directory, verbose=False):
    """Save worker results to trackable files."""
    analysis_dir = os.path.join(output_directory, "assets_steganography_analysis")
    os.makedirs(analysis_dir, exist_ok=True)
    
    # Create status file for tracking
    status_file = os.path.join(analysis_dir, "analysis_status.json")
    with open(status_file, 'w') as f:
        json.dump({
            'status': results['status'],
            'total_images_found': results['total_images_found'],
            'total_images_analyzed': results['total_images_analyzed'],
            'suspicious_images_count': results['suspicious_images_count'],
            'timestamp': time.time(),
            'output_directory': results['output_directory']
        }, f, indent=2)
    
    # Create summary file
    if results['summary_text']:
        summary_file = os.path.join(analysis_dir, "assets_steganography_summary.txt")
        with open(summary_file, 'w') as f:
            f.write(results['summary_text'])
    
    if verbose:
        print(f"[WORKER] Results saved to trackable files in: {analysis_dir}")
```

### **Cleanup Integration**
The background process and its output files will be automatically tracked by the resource system:

1. **Process Cleanup**: The worker process PID is tracked and will be terminated during cleanup
2. **File Cleanup**: All output files in `assets_steganography_analysis/` will be tracked and removed
3. **Graceful Termination**: The worker process handles termination signals gracefully

## **Testing Strategy**

### **Unit Tests**
Create `tests/test_analyze_apk_assets_images.py`:
```python
def test_analyze_assets_with_images():
    """Test analysis of assets directory containing images."""
    
def test_analyze_assets_no_images():
    """Test handling of assets directory with no images."""
    
def test_analyze_no_assets_directory():
    """Test handling when no assets directory exists."""
    
def test_nested_images_discovery():
    """Test recursive discovery of images in subdirectories."""
```

### **Integration Tests**
Extend existing integration tests to include the new automation in the full workflow.

## **CLI Integration**

Add new command line option to `automatool.py`:

```python
parser.add_argument(
    "--skip-assets-analysis",
    action="store_true",
    help="Skip APK assets image steganography analysis"
)
```

And conditional execution:
```python
# Analyze APK assets images for steganography (unless skipped)
if not args.skip_assets_analysis:
    assets_analysis_results = analyze_apk_assets_images(
        apktool_output_path, 
        args.directory, 
        args.verbose
    )
    # ... resource tracking ...
else:
    print("⏭️ Skipping APK assets image analysis (--skip-assets-analysis)")
```

## **Performance Considerations**

### **Asynchronous Execution Benefits**
- **Non-blocking**: Main automation continues while assets analysis runs in background
- **Parallel Processing**: Assets analysis runs alongside other automations (YARA, reviews, etc.)
- **Resource Isolation**: Analysis failures don't affect main automation flow
- **Memory Efficiency**: Worker process can be terminated to free memory after completion

### **Large Assets Directories**
- **Progress Indication**: Worker process shows progress without blocking main execution
- **Memory Management**: Worker process handles memory independently
- **Graceful Handling**: Long-running analysis doesn't delay other automation steps

### **Background Process Optimization**
```python
def analyze_discovered_images(image_files, output_directory, threshold_bytes, verbose=False):
    """Optimized for background execution with progress tracking."""
    total_images = len(image_files)
    analysis_results = []
    failed_analyses = []
    
    if verbose:
        print(f"[WORKER] Analyzing {total_images} image(s) for steganographic content...")
    
    for i, image_path in enumerate(image_files, 1):
        try:
            if verbose:
                print(f"[WORKER] [{i}/{total_images}] Analyzing {os.path.basename(image_path)}")
            
            # Process individual image with error isolation
            result = detect_image_steganography(
                image_path, 
                output_directory, 
                verbose, 
                threshold_bytes
            )
            
            if result:
                analysis_results.append(result)
                if result.get('is_suspicious'):
                    print(f"[WORKER] 🚨 SUSPICIOUS: {os.path.basename(image_path)} has {result['trailing_bytes']} trailing bytes")
                else:
                    print(f"[WORKER] ✅ Clean: {os.path.basename(image_path)} - {result['trailing_bytes']} trailing bytes")
            else:
                failed_analyses.append(image_path)
                
        except Exception as e:
            if verbose:
                print(f"[WORKER] ❌ Failed to analyze {os.path.basename(image_path)}: {e}")
            failed_analyses.append(image_path)
    
    if failed_analyses and verbose:
        print(f"[WORKER] ⚠️  {len(failed_analyses)} image(s) failed to analyze")
    
    return analysis_results

### **Resource Management**
- **Process Termination**: Worker process exits cleanly after completion
- **File Cleanup**: All output files are trackable for cleanup
- **Error Recovery**: Analysis failures don't crash the main automation
```

## **Security Considerations**

### **File Path Validation**
```python
def _validate_image_path(image_path, assets_path):
    """Ensure image path is within assets directory (prevent path traversal)."""
    try:
        assets_abs = os.path.abspath(assets_path)
        image_abs = os.path.abspath(image_path)
        return image_abs.startswith(assets_abs)
    except:
        return False
```

### **File Size Limits**
```python
def _check_image_size_limits(image_path, max_size_mb=100):
    """Check if image file size is reasonable for analysis."""
    try:
        size_bytes = os.path.getsize(image_path)
        size_mb = size_bytes / (1024 * 1024)
        return size_mb <= max_size_mb
    except:
        return False
```

## **Expected Output Examples**

### **Main Process Output (Non-blocking)**
```
🔧 Running apktool decode analysis...
✅ apktool decode completed successfully
📁 Output saved to: /path/to/output/apktool_output
🖼️ APK assets image analysis started in background...
🔧 Running apk_unmask analysis...
```

### **Worker Process Output (in background)**

**Successful Analysis (Clean Images):**
```
[WORKER] Starting assets analysis...
[WORKER] Apktool path: /path/to/output/apktool_output
[WORKER] Output directory: /path/to/output
[WORKER] Threshold: 10 bytes
[WORKER] Found assets directory: /path/to/output/apktool_output/assets
[WORKER] Discovered 5 image file(s) in assets directory
[WORKER] [1/5] Analyzing logo.png
[WORKER] ✅ Clean: logo.png - 0 trailing bytes (below threshold)
[WORKER] [2/5] Analyzing background.jpg  
[WORKER] ✅ Clean: background.jpg - 3 trailing bytes (below threshold)
[WORKER] [3/5] Analyzing icon.png
[WORKER] ✅ Clean: icon.png - 0 trailing bytes (below threshold)
[WORKER] [4/5] Analyzing splash.png
[WORKER] ✅ Clean: splash.png - 2 trailing bytes (below threshold)
[WORKER] [5/5] Analyzing button.png
[WORKER] ✅ Clean: button.png - 0 trailing bytes (below threshold)
[WORKER] ✅ Assets analysis completed successfully
[WORKER] 📄 Summary saved to: /path/to/output/assets_steganography_analysis/assets_steganography_summary.txt
```

**Suspicious Content Detected:**
```
[WORKER] Starting assets analysis...
[WORKER] Found assets directory: /path/to/output/apktool_output/assets
[WORKER] Discovered 3 image file(s) in assets directory
[WORKER] [1/3] Analyzing logo.png
[WORKER] ✅ Clean: logo.png - 0 trailing bytes (below threshold)
[WORKER] [2/3] Analyzing hidden_payload.png
[WORKER] 🚨 SUSPICIOUS: hidden_payload.png has 2048 trailing bytes
[WORKER] [3/3] Analyzing normal.jpg
[WORKER] ✅ Clean: normal.jpg - 1 trailing bytes (below threshold)
[WORKER] ⚠️  SUSPICIOUS CONTENT DETECTED!
[WORKER] 📄 Detailed analysis results saved to: /path/to/output/assets_steganography_analysis/
[WORKER] ✅ Assets analysis completed successfully
```

### **Results Detection (Optional Status Check)**
The main process can optionally check for completion:
```python
# Optional status check function (not blocking main execution)
def check_assets_analysis_status(output_directory, verbose=False):
    """Check if assets analysis has completed and what results are available."""
    status_file = os.path.join(output_directory, "assets_steganography_analysis", "analysis_status.json")
    if os.path.exists(status_file):
        with open(status_file, 'r') as f:
            status = json.load(f)
        return status
    return None
```

## **Documentation Updates**

### **README.md Updates**
Add section describing the new APK assets image analysis feature:

```markdown
### APK Assets Image Analysis
The tool now automatically analyzes all image files within the APK's `assets/` directory for potential steganographic content:

- **Automatic Discovery**: Recursively scans the `assets/` directory for images
- **Format Support**: PNG, JPEG, GIF, BMP, WebP
- **Steganography Detection**: Uses threshold-based analysis for suspicious trailing data
- **Comprehensive Reporting**: Generates detailed summaries and individual reports

To skip this analysis, use the `--skip-assets-analysis` flag.
```

### **Integration Documentation**
Update existing documentation to reflect the new workflow step and resource tracking.

## **Future Enhancement Possibilities**

1. **Additional Analysis Methods**: Integration with more sophisticated steganography detection tools
2. **Metadata Analysis**: Examine image metadata for suspicious entries
3. **Entropy Analysis**: Statistical analysis of image data for hidden content
4. **Format-Specific Checks**: Advanced checks for format-specific hiding techniques
5. **Performance Optimization**: Parallel processing for large assets directories

---

## **Summary: Asynchronous Implementation**

### **Key Design Decisions**
1. **Background Process**: Uses subprocess pattern (like MobSF analysis) instead of synchronous execution
2. **Non-blocking**: Main automation continues immediately after launching assets analysis  
3. **Resource Isolation**: Analysis failures don't affect main automation workflow
4. **Worker Architecture**: Dedicated worker script handles the complete analysis independently

### **Benefits of Asynchronous Approach**
- **Faster Overall Execution**: Assets analysis runs in parallel with other automations
- **Better Resource Management**: Worker process can be tracked and terminated cleanly
- **Improved Reliability**: Main automation isn't blocked by long-running image analysis
- **Scalability**: Pattern can be extended to other background analysis tasks

### **Implementation Files**
1. **`launch_assets_analysis.py`**: Main launcher (follows `launch_mobsf_analysis.py` pattern)
2. **`_assets_analysis_worker.py`**: Background worker (follows `_mobsf_analysis_worker.py` pattern)
3. **Integration**: Minimal changes to `automatool.py` (just add process launch + tracking)

This specification provides a comprehensive blueprint for implementing the APK assets image steganography analysis automation as a **non-blocking background process**, maintaining consistency with the existing automatool architecture and established asynchronous execution patterns.
