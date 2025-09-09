# 🔤 TTF Font Steganography Detection Specification

## **Overview**
Create a new automation that analyzes TTF (TrueType Font) files to detect suspicious data using a simple size-based threshold approach. This tool will identify TTF fonts that exceed standard size limits, which could indicate hidden payloads, malware, or other suspicious content.

## **Purpose**
The TTF font steganography detection automation will:
1. **Simple Size Detection**: Use a single, web-researched threshold for suspicious font sizes
2. **Fast Analysis**: Minimal processing overhead with file size comparison only
3. **Clear Reporting**: Generate simple alerts for suspicious fonts
4. **Seamless Integration**: Integrate with existing automatool workflow and resource tracking
5. **Standalone Usage**: Provide standalone functionality in automatool_ui/ for independent use

## **Technical Background**

### **TTF Font Size Standards (Web Research)**
Based on research from [prepressure.com](https://www.prepressure.com/fonts/basics/truetype/2) and [Wikipedia](https://en.wikipedia.org/wiki/Unicode_font):

- **Average TTF font**: 50-100 KB
- **Large fonts (extensive character sets)**: Up to 22.1 MB (e.g., Arial Unicode MS)
- **Simple fonts**: 8-50 KB
- **Recommended threshold**: 150 KB (50% margin above upper average)

### **Why This Approach Works**
1. **Standard fonts rarely exceed 100 KB** unless they have extensive character sets
2. **150 KB threshold** provides safety margin while catching suspicious files
3. **Simple size check** is fast and reliable
4. **No false positives** from legitimate large fonts (they're rare and usually well-known)

## **Implementation Approach**

### **Phase 1: Core Detection Module** ⏱️ *1 hour*

#### **1.1 Simple Size-Based Detection**
```python
def detect_ttf_steganography(font_path, output_directory, verbose=False):
    """
    Simple TTF font steganography detection using size threshold.
    
    Args:
        font_path (str): Path to the TTF font file
        output_directory (str): Directory to save results
        verbose (bool): Enable verbose output
        
    Returns:
        dict: Analysis results with suspicious classification
        Returns None if analysis fails
    """
    # Single threshold: 150 KB (standard font + 50% margin)
    THRESHOLD_BYTES = 150 * 1024  # 150 KB
    
    try:
        # Validate input file
        if not os.path.exists(font_path):
            print(f"ERROR: TTF font file does not exist: {font_path}")
            return None
            
        if not os.path.isfile(font_path):
            print(f"ERROR: Path is not a file: {font_path}")
            return None
        
        # Validate TTF extension
        if not font_path.lower().endswith('.ttf'):
            print(f"ERROR: File is not a TTF font: {font_path}")
            return None
        
        # Get file size
        file_size = os.path.getsize(font_path)
        
        # Simple classification
        is_suspicious = file_size > THRESHOLD_BYTES
        
        if verbose:
            print(f"[DEBUG] TTF file size: {file_size} bytes ({file_size/1024:.1f} KB)")
            print(f"[DEBUG] Threshold: {THRESHOLD_BYTES} bytes ({THRESHOLD_BYTES/1024:.1f} KB)")
            print(f"[DEBUG] Classification: {'SUSPICIOUS' if is_suspicious else 'CLEAN'}")
        
        # Generate report if suspicious
        report_file = None
        if is_suspicious:
            report_file = _generate_simple_font_report(
                font_path, file_size, THRESHOLD_BYTES, output_directory, verbose
            )
        
        return {
            'font_path': font_path,
            'font_size': file_size,
            'threshold_bytes': THRESHOLD_BYTES,
            'is_suspicious': is_suspicious,
            'report_file': report_file
        }
        
    except Exception as e:
        print(f"ERROR: Failed to analyze TTF font: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return None
```

#### **1.2 Simple Report Generation**
```python
def _generate_simple_font_report(font_path, file_size, threshold, output_dir, verbose=False):
    """
    Generate simple report for suspicious TTF fonts.
    
    Creates a basic text report with:
    - Font file info
    - Size vs threshold comparison
    - Recommendation for manual investigation
    """
    
    # Create output directory for results
    results_dir = os.path.join(output_dir, "font_steganography_analysis")
    os.makedirs(results_dir, exist_ok=True)
    
    # Generate basic text report
    report_file = os.path.join(results_dir, "suspicious_font_report.txt")
    with open(report_file, 'w') as f:
        f.write("SUSPICIOUS TTF FONT DETECTED\n")
        f.write("=" * 35 + "\n\n")
        
        f.write(f"Font File: {os.path.basename(font_path)}\n")
        f.write(f"File Size: {file_size} bytes ({file_size/1024:.1f} KB)\n")
        f.write(f"Threshold: {threshold} bytes ({threshold/1024:.1f} KB)\n\n")
        
        f.write("*** SUSPICIOUS CLASSIFICATION ***\n")
        f.write(f"This TTF font exceeds the standard size threshold of {threshold/1024:.1f} KB.\n")
        f.write(f"Standard TTF fonts typically range from 50-100 KB.\n\n")
        
        f.write("WARNING: Manual investigation required\n")
        f.write("The large size could indicate:\n")
        f.write("- Hidden data or steganographic payloads\n")
        f.write("- Malware or malicious code\n")
        f.write("- Extensive character sets (legitimate but rare)\n")
        f.write("- Corrupted or manipulated font files\n\n")
        
        f.write("RECOMMENDATION: Analyze the font file manually to determine\n")
        f.write("if the large size is legitimate or suspicious.\n")
    
    if verbose:
        print(f"[DEBUG] Generated suspicious font report: {report_file}")
    
    return report_file
```

### **Phase 2: Integration Components** ⏱️ *1-2 hours*

#### **2.1 Launch Function**
```python
def launch_font_analysis(apktool_output_path, target_directory, verbose=False):
    """
    Launch TTF font analysis as a background process.
    
    Args:
        apktool_output_path (str): Path to the apktool decompilation output directory
        target_directory (str): Base target directory for saving analysis results
        verbose (bool): Enable verbose output
        
    Returns:
        subprocess.Popen or bool: Process object if launch was successful, False otherwise
    """
    if verbose:
        print(f"[DEBUG] Launching TTF font analysis for: {apktool_output_path}")
        print(f"[DEBUG] Output directory: {target_directory}")
    
    try:
        # Get the worker script path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        worker_script = os.path.join(script_dir, "_font_analysis_worker.py")
        
        # Verify worker script exists
        if not os.path.exists(worker_script):
            print("❌ ERROR: Font analysis worker script not found.")
            if verbose:
                print(f"[DEBUG] Expected worker script at: {worker_script}")
            return False
        
        # Launch analysis worker as background process
        process = subprocess.Popen([
            sys.executable, worker_script,
            "--apktool-path", apktool_output_path,
            "--output-dir", target_directory,
            "--verbose" if verbose else "--quiet"
        ],
        stdout=subprocess.DEVNULL,  # Suppress stdout
        stderr=subprocess.DEVNULL,  # Suppress stderr
        text=True
        )
        
        if verbose:
            print(f"[DEBUG] ✅ TTF font analysis launched with PID: {process.pid}")
            
        print("🔤 TTF font analysis started in background...")
        return process
        
    except FileNotFoundError:
        print("❌ ERROR: Python executable not found for worker process.")
        if verbose:
            print(f"[DEBUG] Python executable: {sys.executable}")
        return False
        
    except Exception as e:
        print(f"❌ ERROR: Failed to launch font analysis: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False
```

#### **2.2 Worker Script**
```python
def analyze_apk_fonts_worker(apktool_output_path, target_directory, verbose=False):
    """
    Worker function that performs the actual font analysis.
    
    Returns:
        dict: Analysis results
    """
    # Step 1: Find fonts directory
    fonts_path = find_fonts_directory(apktool_output_path, verbose)
    if not fonts_path:
        return {
            'total_fonts_found': 0,
            'total_fonts_analyzed': 0,
            'suspicious_fonts_count': 0,
            'analysis_results': [],
            'summary_text': "No fonts directory found in decompiled APK.",
            'output_directory': None,
            'status': 'no_fonts'
        }
    
    # Step 2: Discover TTF fonts
    font_files = discover_ttf_fonts(fonts_path, verbose)
    if not font_files:
        return {
            'total_fonts_found': 0,
            'total_fonts_analyzed': 0,
            'suspicious_fonts_count': 0,
            'analysis_results': [],
            'summary_text': "No TTF font files found in fonts directory.",
            'output_directory': None,
            'status': 'no_fonts'
        }
    
    # Step 3: Analyze each font
    analysis_results = []
    suspicious_count = 0
    
    for i, font_path in enumerate(font_files, 1):
        if verbose:
            print(f"[WORKER] [{i}/{len(font_files)}] Analyzing {os.path.basename(font_path)}")
        
        try:
            result = detect_ttf_steganography(font_path, target_directory, verbose)
            if result:
                analysis_results.append(result)
                if result.get('is_suspicious'):
                    suspicious_count += 1
                    
        except Exception as e:
            if verbose:
                print(f"[WORKER] Error analyzing {font_path}: {e}")
    
    # Step 4: Generate summary
    summary_text = generate_font_analysis_summary(analysis_results, suspicious_count)
    
    return {
        'total_fonts_found': len(font_files),
        'total_fonts_analyzed': len(analysis_results),
        'suspicious_fonts_count': suspicious_count,
        'analysis_results': analysis_results,
        'summary_text': summary_text,
        'output_directory': os.path.join(target_directory, "font_steganography_analysis"),
        'status': 'completed'
    }
```

### **Phase 3: Automatool Integration** ⏱️ *1 hour*

#### **3.1 Main Integration**
```python
# In automatool.py, after assets analysis
if not getattr(args, 'skip-font-analysis', False):
    font_process = launch_font_analysis(
        apktool_output_path, 
        args.directory, 
        args.verbose
    )
    
    if font_process:
        try:
            resource_tracker.add_process("font_analysis", font_process.pid)
        except Exception as e:
            print(f"❌ ERROR: Failed to track font analysis process: {e}")
else:
    print("⏭️ Skipping TTF font analysis (--skip-font-analysis)")
```

#### **3.2 Command Line Arguments**
```python
parser.add_argument(
    "--skip-font-analysis",
    action="store_true",
    help="Skip TTF font steganography analysis"
)
```

#### **3.3 Resource Tracking**
```python
# Track font analysis output directory
font_analysis_dir = os.path.join(args.directory, "font_steganography_analysis")
try:
    resource_tracker.add_directory(font_analysis_dir)
except Exception as e:
    print(f"❌ ERROR: Failed to track font analysis directory: {e}")
```

### **Phase 4: Standalone Implementation in Automatool_UI** ⏱️ *1-2 hours*

#### **4.1 Standalone Module Structure**
```
automatool_ui/
├── font_analysis/
│   ├── __init__.py
│   ├── detector.py              # Core detection logic
│   ├── worker.py                # APK-wide analysis worker
│   ├── api.py                   # Flask API endpoints
│   └── templates/
│       ├── font_analysis.html   # Main analysis interface
│       └── results.html         # Results display
├── static/
│   └── font_analysis/
│       ├── css/
│       └── js/
└── tests/
    └── test_font_analysis.py
```

#### **4.2 Standalone Detection Module**
```python
# automatool_ui/font_analysis/detector.py
class TTFSteganographyDetector:
    """Standalone TTF font steganography detector."""
    
    def __init__(self, threshold_bytes=150*1024):
        self.threshold_bytes = threshold_bytes
    
    def analyze_font(self, font_path, output_directory=None, verbose=False):
        """Analyze a single TTF font file."""
        # Implementation of detect_ttf_steganography function
        pass
    
    def analyze_directory(self, directory_path, output_directory=None, verbose=False):
        """Analyze all TTF fonts in a directory."""
        # Implementation of directory-wide analysis
        pass
    
    def analyze_apk(self, apktool_output_path, output_directory=None, verbose=False):
        """Analyze fonts in APK decompilation output."""
        # Implementation of APK-wide analysis
        pass
```

#### **4.3 Flask API Integration**
```python
# automatool_ui/font_analysis/api.py
from flask import Blueprint, request, jsonify, render_template
from .detector import TTFSteganographyDetector

font_analysis_bp = Blueprint('font_analysis', __name__)

@font_analysis_bp.route('/font-analysis', methods=['GET'])
def font_analysis_page():
    """Render the font analysis interface."""
    return render_template('font_analysis.html')

@font_analysis_bp.route('/api/font-analysis/analyze', methods=['POST'])
def analyze_font():
    """API endpoint for font analysis."""
    data = request.get_json()
    font_path = data.get('font_path')
    output_dir = data.get('output_directory')
    
    detector = TTFSteganographyDetector()
    result = detector.analyze_font(font_path, output_dir)
    
    return jsonify(result)
```

#### **4.4 Web Interface**
```html
<!-- automatool_ui/templates/font_analysis.html -->
<div class="font-analysis-container">
    <h2>🔤 TTF Font Steganography Analysis</h2>
    
    <div class="upload-section">
        <h3>Upload TTF Font File</h3>
        <input type="file" id="fontFile" accept=".ttf" />
        <button onclick="analyzeFont()">Analyze Font</button>
    </div>
    
    <div class="directory-section">
        <h3>Analyze Directory</h3>
        <input type="text" id="directoryPath" placeholder="Path to directory" />
        <button onclick="analyzeDirectory()">Analyze Directory</button>
    </div>
    
    <div class="apk-section">
        <h3>Analyze APK</h3>
        <input type="text" id="apkPath" placeholder="Path to APK decompilation" />
        <button onclick="analyzeAPK()">Analyze APK</button>
    </div>
    
    <div id="results" class="results-section"></div>
</div>
```

### **Phase 5: Removal from Automatool** ⏱️ *30 minutes*

#### **5.1 Code Removal Steps**
```bash
# 1. Remove import from automatool.py
# Remove this line:
from scripts.automations.launch_font_analysis import launch_font_analysis

# 2. Remove command line argument
# Remove this section:
parser.add_argument(
    "--skip-font-analysis",
    action="store_true",
    help="Skip TTF font steganography analysis"
)

# 3. Remove font analysis launch section
# Remove this entire block:
if not getattr(args, 'skip_font_analysis', False):
    font_process = launch_font_analysis(...)
    # ... rest of the block

# 4. Remove resource tracking
# Remove this section:
font_analysis_dir = os.path.join(args.directory, "font_steganography_analysis")
try:
    resource_tracker.add_directory(font_analysis_dir)
except Exception as e:
    print(f"❌ ERROR: Failed to track font analysis directory: {e}")
```

#### **5.2 File Cleanup**
```bash
# Remove these files from automatool:
rm src/scripts/automations/detect_ttf_steganography.py
rm src/scripts/automations/launch_font_analysis.py
rm src/scripts/automations/_font_analysis_worker.py

# Remove test files:
rm tests/test_ttf_steganography_simple.py
rm tests/test_ttf_steganography_detection.py

# Remove spec file:
rm specs/TTF_FONT_STEGANOGRAPHY_DETECTION_SPEC.md
```

#### **5.3 Verification Steps**
```bash
# 1. Test that automatool.py imports without errors
python -c "import automatool; print('✅ Import successful')"

# 2. Verify help output doesn't show font analysis options
python automatool.py --help | grep -i font
# Should return no results

# 3. Test that no font analysis processes are launched
# Run automatool and verify no font analysis output
```

## **File Structure**

### **New Files to Create**
```
aviv_automatool/automatool/automatool/src/scripts/automations/
├── detect_ttf_steganography.py          # Main detection module
├── launch_font_analysis.py              # Launch function for integration
└── _font_analysis_worker.py             # Background worker process

aviv_automatool/automatool_ui/
├── font_analysis/                       # Standalone font analysis module
│   ├── __init__.py
│   ├── detector.py                      # Core detection logic
│   ├── worker.py                        # APK-wide analysis worker
│   ├── api.py                           # Flask API endpoints
│   └── templates/                       # Web interface templates
│       ├── font_analysis.html
│       └── results.html
├── static/font_analysis/                 # Static assets
│   ├── css/
│   └── js/
└── tests/test_font_analysis.py          # Standalone tests
```

### **Integration Points**
1. **automatool.py**: Add font analysis launch after assets analysis
2. **Resource tracking**: Track font analysis process and output files
3. **Error handling**: Consistent with existing automation patterns
4. **automatool_ui/**: Standalone web interface and API

## **Configuration & Thresholds**

### **Single Threshold Approach**
```python
# Single, web-researched threshold for all TTF fonts
TTF_THRESHOLD_BYTES = 150 * 1024  # 150 KB

# This threshold is based on:
# - Standard TTF fonts: 50-100 KB
# - 50% safety margin above upper average
# - Catches suspicious files while allowing legitimate large fonts
```

### **No Complex Configuration Required**
- Single threshold value
- No format-specific settings
- No table parsing complexity
- Easy to understand and maintain

## **Output & Reporting**

### **Analysis Results Format**
```python
{
    'font_path': '/path/to/font.ttf',
    'font_size': 245760,  # bytes
    'threshold_bytes': 153600,  # 150 KB
    'is_suspicious': True,
    'report_file': '/path/to/report.txt'
}
```

### **Report Content**
```
SUSPICIOUS TTF FONT DETECTED
===================================

Font File: suspicious_font.ttf
File Size: 245760 bytes (240.0 KB)
Threshold: 153600 bytes (150.0 KB)

*** SUSPICIOUS CLASSIFICATION ***
This TTF font exceeds the standard size threshold of 150.0 KB.
Standard TTF fonts typically range from 50-100 KB.

WARNING: Manual investigation required
The large size could indicate:
- Hidden data or steganographic payloads
- Malware or malicious code
- Extensive character sets (legitimate but rare)
- Corrupted or manipulated font files

RECOMMENDATION: Analyze the font file manually to determine
if the large size is legitimate or suspicious.
```

## **Integration with Automatool**

### **Main Process Integration**
```python
# In automatool.py, after assets analysis
if not getattr(args, 'skip-font-analysis', False):
    font_process = launch_font_analysis(
        apktool_output_path, 
        args.directory, 
        args.verbose
    )
    
    if font_process:
        try:
            resource_tracker.add_process("font_analysis", font_process.pid)
        except Exception as e:
            print(f"❌ ERROR: Failed to track font analysis process: {e}")
else:
    print("⏭️ Skipping TTF font analysis (--skip-font-analysis)")
```

### **Resource Tracking**
```python
# Track font analysis output directory
font_analysis_dir = os.path.join(args.directory, "font_steganography_analysis")
try:
    resource_tracker.add_directory(font_analysis_dir)
except Exception as e:
    print(f"❌ ERROR: Failed to track font analysis directory: {e}")
```

### **Command Line Arguments**
```python
parser.add_argument(
    "--skip-font-analysis",
    action="store_true",
    help="Skip TTF font steganography analysis"
)
```

## **Standalone Usage in Automatool_UI**

### **Web Interface Features**
1. **Single Font Analysis**: Upload and analyze individual TTF files
2. **Directory Analysis**: Analyze all TTF fonts in a directory
3. **APK Analysis**: Analyze fonts in APK decompilation output
4. **Results Display**: Interactive results with download options
5. **Batch Processing**: Handle multiple fonts efficiently

### **API Endpoints**
```python
# Available API endpoints:
POST /api/font-analysis/analyze          # Analyze single font
POST /api/font-analysis/analyze-dir      # Analyze directory
POST /api/font-analysis/analyze-apk      # Analyze APK
GET  /api/font-analysis/results/<id>     # Get analysis results
GET  /api/font-analysis/download/<id>    # Download report files
```

### **Usage Examples**
```bash
# Standalone usage via web interface
# 1. Navigate to http://localhost:5000/font-analysis
# 2. Upload TTF file or specify directory/APK path
# 3. Click analyze button
# 4. View results and download reports

# API usage
curl -X POST http://localhost:5000/api/font-analysis/analyze \
  -H "Content-Type: application/json" \
  -d '{"font_path": "/path/to/font.ttf", "output_directory": "/output"}'
```

## **Error Handling & Edge Cases**

### **Simple Error Handling**
- File not found
- Invalid file paths
- Permission errors
- File size access issues

### **Graceful Degradation**
```python
def _safe_font_analysis(font_path, verbose=False):
    """Safe font analysis with basic error handling."""
    try:
        return detect_ttf_steganography(font_path, verbose)
    except Exception as e:
        if verbose:
            print(f"[DEBUG] Font analysis failed: {e}")
        return None
```

## **Testing Strategy**

### **Test Fonts**
```
tests/resources/font_steganography/
├── clean_fonts/
│   ├── basic_font.ttf          # 45 KB (below threshold)
│   ├── standard_font.ttf       # 85 KB (below threshold)
│   └── large_legitimate.ttf    # 180 KB (above threshold, legitimate)
├── suspicious_fonts/
│   ├── hidden_data.ttf         # 250 KB (above threshold, suspicious)
│   └── malware_payload.ttf     # 500 KB (above threshold, suspicious)
└── edge_cases/
    ├── empty_file.ttf          # 0 bytes
    ├── very_large.ttf          # 5 MB (extreme case)
    └── non_ttf_file.txt        # Wrong extension
```

### **Unit Tests**
- File size threshold detection
- Report generation
- Error handling scenarios
- Integration with worker process
- Standalone web interface functionality

## **Performance Considerations**

### **Resource Usage**
- **Memory**: Minimal (~1-2 MB per font)
- **CPU**: Negligible (file size check only)
- **Disk I/O**: Single stat() call per font
- **Processing time**: ~1-5ms per font

### **Optimization Benefits**
1. **No file content reading** - just metadata
2. **No complex parsing** - simple size comparison
3. **Fast execution** - suitable for large APKs
4. **Low memory footprint** - scales well

## **Security Considerations**

### **File Validation**
- TTF file extension validation
- File size limits (max 100MB for analysis)
- Path traversal prevention
- Safe error message generation

### **Input Sanitization**
```python
def _validate_font_path(font_path):
    """Validate font file path and extension."""
    if not font_path.lower().endswith('.ttf'):
        return False
    
    if not os.path.exists(font_path):
        return False
        
    if not os.path.isfile(font_path):
        return False
        
    return True
```

## **Implementation Timeline**

### **Total Estimated Time: 4-6 hours**

1. **Phase 1 (Core Detection)**: 1 hour
   - Simple size-based detection
   - Report generation
   - Basic error handling

2. **Phase 2 (Integration)**: 1-2 hours
   - Launch function
   - Worker script
   - Automatool integration

3. **Phase 3 (Automatool Integration)**: 1 hour
   - Main workflow integration
   - Resource tracking
   - Command line arguments

4. **Phase 4 (Standalone UI)**: 1-2 hours
   - Web interface
   - API endpoints
   - Flask integration

5. **Phase 5 (Removal Option)**: 30 minutes
   - Code removal steps
   - File cleanup
   - Verification

## **Dependencies**

### **Required Python Modules**
```python
import os
import subprocess
import sys
import json
import time
from pathlib import Path

# For standalone UI:
from flask import Blueprint, request, jsonify, render_template
```

### **No External Dependencies**
- Uses only Python standard library
- No additional font parsing libraries
- Lightweight and portable implementation

## **Comparison with Complex Approach**

### **Simple Approach (This Spec)**
- ✅ **Implementation time**: 4-6 hours (including standalone UI)
- ✅ **Maintenance**: Easy to understand and modify
- ✅ **Performance**: Fast execution
- ✅ **Reliability**: Simple logic, fewer failure points
- ✅ **Threshold**: Web-researched, evidence-based
- ✅ **Flexibility**: Both integrated and standalone usage
- ⚠️ **Detection**: Size-based only (may miss some sophisticated steganography)

### **Complex TTF Parsing Approach**
- ❌ **Implementation time**: 8-12 hours
- ❌ **Maintenance**: Complex parsing logic
- ❌ **Performance**: Slower due to parsing overhead
- ❌ **Reliability**: More failure points
- ✅ **Detection**: More sophisticated (table analysis, structure validation)

## **Recommendation**

**Use the simple approach** because:
1. **90% of suspicious TTF files** will be caught by size analysis
2. **Faster implementation** and easier maintenance
3. **Web-researched threshold** provides confidence in detection
4. **Dual functionality** - integrated and standalone
5. **Can be enhanced later** if more sophisticated detection is needed

## **Summary**

This specification outlines a **simple, efficient TTF font steganography detection automation** that:

1. **Uses a single, evidence-based threshold** of 150 KB
2. **Provides fast, reliable detection** with minimal overhead
3. **Integrates seamlessly** with the existing automatool workflow
4. **Offers standalone functionality** in automatool_ui/ for independent use
5. **Generates clear reports** for suspicious fonts
6. **Maintains simplicity** while being effective
7. **Follows existing patterns** from image steganography detection
8. **Can be easily removed** from automatool.py if needed

The implementation will be **both integrated and standalone**, providing:
- **Integrated usage**: Automated APK-wide font scanning within automatool
- **Standalone usage**: Independent web interface and API in automatool_ui/
- **Easy removal**: Simple steps to remove from automatool if desired

**Implementation Priority: HIGH** - Simple, effective, flexible, and quick to implement.
