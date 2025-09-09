# 🔍 FSMON File System Monitoring Specification

## **Overview**
Develop an automation system that uses **fsmon** (https://github.com/nowsecure/fsmon) to continuously monitor an Android application's file system activity in real-time, detecting suspicious events such as `.dex` file extraction from cache, dropped payloads, and other malicious file operations.

## **Purpose**
The FSMON automation will:
1. **Continuous Monitoring**: Run fsmon in the background to monitor application file system activity
2. **Pattern Detection**: Use hardcoded patterns to identify suspicious file operations
3. **Real-time Alerting**: Detect and log suspicious activities as they occur
4. **Background Operation**: Run continuously until manually terminated
5. **Comprehensive Logging**: Record all detected events with full context and details

## **Architecture Strategy**

### **Standalone Tool Architecture**
The FSMON monitoring tool is designed as a completely independent tool:

1. **Main Launcher**: `launch_fsmon_monitoring.py` - CLI interface and process management
2. **Worker Process**: `_fsmon_monitoring_worker.py` - Background monitoring execution
3. **Pattern Engine**: `fsmon_patterns.py` - Suspicious activity detection patterns
4. **Background Operation**: Runs continuously until manually terminated

### **CLI Interface**
The tool provides a comprehensive command-line interface for easy standalone usage:

```bash
python launch_fsmon_monitoring.py --help
```

### **Integration Points**
- **Standalone Tool**: Independent execution separate from main automatool workflow
- **Web UI Integration**: Process management and termination via automatool_ui
- **Frida Automation**: Complementary to existing Frida monitoring
- **Manual Integration**: Can be run alongside other tools when needed

## **File Structure**
```
automatool/automatool/src/scripts/automations/
├── launch_fsmon_monitoring.py     # NEW: Standalone FSMON launcher with CLI
├── _fsmon_monitoring_worker.py    # NEW: Background monitoring worker
└── fsmon_patterns.py              # NEW: Suspicious activity patterns

automatool_ui/
├── app.py                         # Enhanced with FSMON management endpoints
├── templates/
│   ├── index.html                 # Enhanced with FSMON control panel
│   └── components/
│       └── fsmon_control.html     # NEW: FSMON monitoring control component
└── static/
    └── js/
        └── fsmon_control.js       # NEW: FSMON control JavaScript
```

### **Tool Independence**
- **No automatool.py dependency**: Can be run independently
- **Self-contained CLI**: Complete command-line interface
- **Standalone execution**: `python launch_fsmon_monitoring.py --help`
- **Web UI integration**: Process management via automatool_ui
- **Optional imports**: Can be imported into other tools if needed

## **Implementation Details**

### **Phase 1: FSMON Launcher (`launch_fsmon_monitoring.py`)**

Standalone CLI launcher with comprehensive argument parsing:

```python
def parse_arguments():
    """Parse command line arguments for standalone FSMON monitoring."""
    parser = argparse.ArgumentParser(
        description="FSMON Android File System Monitoring Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --package com.example.app
  %(prog)s --package com.example.app --output-dir ./logs --verbose
  %(prog)s --package com.example.app --paths /data/data/com.example.app/cache
        """
    )
    
    parser.add_argument(
        "--package", "--package-name",
        required=True,
        help="Android package name to monitor"
    )
    
    parser.add_argument(
        "--device-id",
        help="Specific Android device ID (optional)"
    )
    
    parser.add_argument(
        "--paths", "--monitoring-paths",
        nargs="+",
        help="Custom paths to monitor (defaults to app data directory)"
    )
    
    parser.add_argument(
        "--output-dir", "--output-directory",
        help="Directory to save logs and results"
    )
    
    parser.add_argument(
        "--patterns", "--patterns-file",
        help="Custom patterns file path (optional)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    return parser.parse_args()

def launch_fsmon_monitoring(package_name, device_id=None, 
                           monitoring_paths=None, output_directory=None, 
                           patterns_file=None, verbose=False):
    """
    Launch FSMON file system monitoring as a background process.
    
    Args:
        package_name (str): Android package name to monitor
        device_id (str): Specific Android device ID (optional)
        monitoring_paths (list): Custom paths to monitor (defaults to app data dir)
        output_directory (str): Directory to save logs and results
        patterns_file (str): Custom patterns file path (optional)
        verbose (bool): Enable verbose output
        
    Returns:
        subprocess.Popen or bool: Process object if launch was successful, False otherwise
    """

def get_fsmon_process_info():
    """Get information about currently running FSMON processes."""
    
def terminate_fsmon_process(process_id):
    """Terminate FSMON monitoring process by ID."""
    
def save_process_info(process_id, package_name, start_time, output_dir):
    """Save process information for web UI access."""
```

### **Phase 2: FSMON Worker (`_fsmon_monitoring_worker.py`)**

Core monitoring logic following the worker pattern:

```python
def setup_fsmon_monitoring(package_name, device_id=None, verbose=False):
    """Setup and validate FSMON environment."""
    
def start_fsmon_process(monitoring_paths, patterns, output_file, verbose=False):
    """Launch FSMON process with pattern filtering."""
    
def monitor_fsmon_output(output_file, patterns, verbose=False):
    """Monitor FSMON output for suspicious activities."""
    
def detect_suspicious_activity(line, patterns):
    """Apply pattern matching to detect suspicious file operations."""
```

### **Phase 3: Main Function Structure**

The launcher includes a main function for standalone execution:

```python
def main():
    """Main entry point for standalone FSMON monitoring."""
    print("🔍 FSMON Android File System Monitoring Tool")
    
    # Parse command line arguments
    args = parse_arguments()
    
    if args.verbose:
        print(f"[DEBUG] Package: {args.package}")
        print(f"[DEBUG] Device ID: {args.device_id}")
        print(f"[DEBUG] Output directory: {args.output_directory}")
    
    # Launch monitoring
    fsmon_process = launch_fsmon_monitoring(
        package_name=args.package,
        device_id=args.device_id,
        monitoring_paths=args.paths,
        output_directory=args.output_dir,
        patterns_file=args.patterns,
        verbose=args.verbose
    )
    
    if fsmon_process:
        print(f"✅ FSMON monitoring started for {args.package}")
        print(f"📊 Process ID: {fsmon_process.pid}")
        print("🔄 Monitoring in background. Press Ctrl+C to stop.")
        
        try:
            # Keep the main process alive
            fsmon_process.wait()
        except KeyboardInterrupt:
            print("\n🛑 Stopping FSMON monitoring...")
            fsmon_process.terminate()
            fsmon_process.wait()
            print("✅ FSMON monitoring stopped.")
    else:
        print("❌ Failed to start FSMON monitoring.")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### **Phase 4: Pattern Definitions (`fsmon_patterns.py`)**

Standalone pattern engine with hardcoded suspicious activity patterns:

```python
import re
from typing import Dict, List, Pattern

# Pre-compiled regex patterns for efficient matching
SUSPICIOUS_FILE_PATTERNS: Dict[str, List[Pattern]] = {
    "dex_extraction": [
        re.compile(r"\.dex$"),
        re.compile(r"secondary-dexes"),
        re.compile(r"\.dex\.\d+$")
    ],
    "dropped_payloads": [
        re.compile(r"\.apk$"),
        re.compile(r"\.jar$"),
        re.compile(r"\.so$"),
        re.compile(r"\.bin$")
    ],
    "cache_manipulation": [
        re.compile(r"cache/.*\.dex"),
        re.compile(r"cache/.*\.apk"),
        re.compile(r"cache/.*\.jar")
    ],
    "suspicious_locations": [
        re.compile(r"/data/data/.*/files/.*\.dex"),
        re.compile(r"/data/data/.*/cache/.*\.apk"),
        re.compile(r"/data/data/.*/lib/.*\.so")
    ]
}

SUSPICIOUS_OPERATIONS = [
    "CREATE",
    "WRITE",
    "RENAME",
    "LINK"
]

def load_custom_patterns(patterns_file: str) -> Dict[str, List[Pattern]]:
    """Load custom patterns from JSON file."""
    # Implementation for custom pattern loading
    pass

def get_default_patterns() -> Dict[str, List[Pattern]]:
    """Get default hardcoded patterns."""
    return SUSPICIOUS_FILE_PATTERNS
```

## **FSMON Integration Details**

### **Prerequisites**
- **Rooted Android Device**: Full access to application data directory required
- **FSMON Binary**: Downloaded and installed on Android device
- **ADB Connection**: Active ADB connection to target device

### **FSMON Setup Process**
1. **Binary Installation**:
   ```bash
   # Download fsmon binary
   wget https://github.com/nowsecure/fsmon/releases/latest/download/fsmon
   
   # Transfer to Android device
   adb push fsmon /data/local/tmp/
   
   # Set permissions
   adb shell chmod +x /data/local/tmp/fsmon
   ```

2. **Path Construction**:
   ```bash
   # Application data directory
   /data/data/{package_name}/
   
   # Cache directory
   /data/data/{package_name}/cache/
   
   # Files directory
   /data/data/{package_name}/files/
   ```

3. **FSMON Command Structure**:
   ```bash
   # Basic monitoring
   adb shell su -c "/data/local/tmp/fsmon /data/data/{package_name}/"
   
   # With pattern filtering
   adb shell su -c "/data/local/tmp/fsmon /data/data/{package_name}/ | grep -E '\.dex|\.apk|\.jar|\.so'"
   ```

### **Pattern Matching Strategy**

#### **File Type Detection**
- **DEX Files**: `.dex`, `secondary-dexes`, `.dex.1`, `.dex.2`
- **APK Files**: `.apk`, `.apk.tmp`, `.apk.download`
- **JAR Files**: `.jar`, `.jar.tmp`
- **Native Libraries**: `.so`, `.so.1`, `.so.2`

#### **Operation Type Detection**
- **File Creation**: New suspicious files appearing
- **File Modification**: Changes to existing files
- **File Movement**: Renaming or moving suspicious files
- **File Linking**: Symbolic links to suspicious files

#### **Location-Based Detection**
- **Cache Directory**: Unusual files in cache folders
- **Files Directory**: Suspicious files in app files
- **Lib Directory**: Unexpected native libraries
- **Temp Directories**: Temporary suspicious files

### **Logging and Output Format**

#### **Event Log Structure**
```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "event_type": "suspicious_file_creation",
  "package_name": "com.example.app",
  "file_path": "/data/data/com.example.app/cache/suspicious.dex",
  "operation": "CREATE",
  "file_size": 1024,
  "file_hash": "sha256:abc123...",
  "severity": "high",
  "pattern_matched": "dex_extraction",
  "details": "DEX file created in cache directory"
}
```

#### **Real-time Output Format**
```
[2024-01-15 10:30:45] 🚨 SUSPICIOUS ACTIVITY DETECTED
Package: com.example.app
Event: DEX file creation in cache
File: /data/data/com.example.app/cache/suspicious.dex
Operation: CREATE
Severity: HIGH
Pattern: dex_extraction
```

## **Usage Examples**

### **Basic Monitoring**
```bash
# Launch monitoring for specific package
python launch_fsmon_monitoring.py --package com.example.app

# With custom output directory
python launch_fsmon_monitoring.py --package com.example.app --output-dir ./fsmon_logs

# Verbose output
python launch_fsmon_monitoring.py --package com.example.app --verbose
```

### **Advanced Monitoring**
```bash
# Custom monitoring paths
python launch_fsmon_monitoring.py --package com.example.app --paths /data/data/com.example.app/cache,/data/data/com.example.app/files

# Custom patterns file
python launch_fsmon_monitoring.py --package com.example.app --patterns ./custom_patterns.json

# Device-specific monitoring
python launch_fsmon_monitoring.py --package com.example.app --device-id emulator-5554
```

## **Standalone Execution & Web UI Integration**

### **Independent Operation**
The FSMON monitoring tool operates independently from the main automatool workflow:

```python
# Direct execution without automatool.py
if __name__ == "__main__":
    main()
```

### **Web UI Integration**
The tool integrates with automatool_ui for process management and monitoring:

#### **API Endpoints**
```python
# Flask routes in automatool_ui/app.py
@app.route('/api/fsmon/start', methods=['POST'])
def start_fsmon_monitoring():
    """Start FSMON monitoring for specified package."""
    data = request.get_json()
    package_name = data.get('package_name')
    device_id = data.get('device_id')
    
    # Launch FSMON monitoring
    fsmon_process = launch_fsmon_monitoring(
        package_name=package_name,
        device_id=device_id,
        verbose=True
    )
    
    if fsmon_process:
        # Save process info for web UI access
        save_process_info(
            process_id=fsmon_process.pid,
            package_name=package_name,
            start_time=datetime.now().isoformat(),
            output_directory="./fsmon_logs"
        )
        return jsonify({"success": True, "process_id": fsmon_process.pid})
    else:
        return jsonify({"success": False, "error": "Failed to start monitoring"})

@app.route('/api/fsmon/stop', methods=['POST'])
def stop_fsmon_monitoring():
    """Stop active FSMON monitoring process."""
    data = request.get_json()
    process_id = data.get('process_id')
    
    if terminate_fsmon_process(process_id):
        return jsonify({"success": True, "message": "Monitoring stopped"})
    else:
        return jsonify({"success": False, "error": "Failed to stop monitoring"})

@app.route('/api/fsmon/status', methods=['GET'])
def get_fsmon_status():
    """Get current FSMON monitoring status."""
    processes = get_all_processes()
    return jsonify({"processes": processes})

@app.route('/api/fsmon/logs', methods=['GET'])
def get_fsmon_logs():
    """Get FSMON monitoring logs."""
    process_id = request.args.get('process_id')
    # Return logs for specific process or all processes
```

#### **Process Management**
- **Start Monitoring**: Launch FSMON process via web UI
- **Stop Monitoring**: Terminate active FSMON process
- **Status Monitoring**: Real-time process status and health
- **Log Access**: View monitoring logs through web interface

#### **Web UI Components**
```html
<!-- automatool_ui/templates/components/fsmon_control.html -->
<div class="fsmon-control-panel">
    <h3>🔍 FSMON File System Monitoring</h3>
    
    <!-- Start Monitoring Form -->
    <form id="fsmon-start-form">
        <input type="text" name="package_name" placeholder="Package name (e.g., com.example.app)" required>
        <input type="text" name="device_id" placeholder="Device ID (optional)">
        <button type="submit">Start Monitoring</button>
    </form>
    
    <!-- Status Display -->
    <div id="fsmon-status">
        <span class="status-indicator">●</span>
        <span class="status-text">Not Running</span>
    </div>
    
    <!-- Control Buttons -->
    <button id="fsmon-stop-btn" disabled>Stop Monitoring</button>
    <button id="fsmon-logs-btn">View Logs</button>
</div>
```

#### **JavaScript Control**
```javascript
// automatool_ui/static/js/fsmon_control.js
class FSMONController {
    constructor() {
        this.monitoring = false;
        this.processId = null;
        this.initEventListeners();
        this.statusInterval = null;
    }
    
    async startMonitoring(packageName, deviceId) {
        try {
            const response = await fetch('/api/fsmon/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ package_name: packageName, device_id: deviceId })
            });
            
            const result = await response.json();
            if (result.success) {
                this.processId = result.process_id;
                this.monitoring = true;
                this.updateUI();
                this.startStatusPolling();
            }
        } catch (error) {
            console.error('Failed to start monitoring:', error);
        }
    }
    
    async stopMonitoring() {
        if (!this.processId) return;
        
        try {
            const response = await fetch('/api/fsmon/stop', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ process_id: this.processId })
            });
            
            const result = await response.json();
            if (result.success) {
                this.monitoring = false;
                this.processId = null;
                this.updateUI();
                this.stopStatusPolling();
            }
        } catch (error) {
            console.error('Failed to stop monitoring:', error);
        }
    }
    
    async getStatus() {
        try {
            const response = await fetch('/api/fsmon/status');
            const result = await response.json();
            this.updateStatusDisplay(result.processes);
        } catch (error) {
            console.error('Failed to get status:', error);
        }
    }
    
    async getLogs() {
        try {
            const response = await fetch(`/api/fsmon/logs?process_id=${this.processId}`);
            const logs = await response.text();
            this.displayLogs(logs);
        } catch (error) {
            console.error('Failed to get logs:', error);
        }
    }
    
    startStatusPolling() {
        this.statusInterval = setInterval(() => this.getStatus(), 5000);
    }
    
    stopStatusPolling() {
        if (this.statusInterval) {
            clearInterval(this.statusInterval);
            this.statusInterval = null;
        }
    }
    
    updateUI() {
        // Update UI elements based on monitoring status
    }
}
```

### **Execution Workflow**
1. **CLI Parsing**: Parse command line arguments
2. **Environment Setup**: Validate ADB connection and device status
3. **FSMON Launch**: Start monitoring process in background
4. **Process Registration**: Register process with web UI management system
5. **Continuous Monitoring**: Run until manually terminated
6. **Graceful Shutdown**: Handle Ctrl+C, web UI stop, and cleanup resources

### **Dual Control Methods**
- **CLI Control**: Direct command-line execution and termination
- **Web UI Control**: Start/stop monitoring through automatool_ui interface
- **Process Persistence**: Process information stored for web UI access
- **Status Synchronization**: Real-time status updates between CLI and web UI

### **Manual Integration (Optional)**
When needed, the tool can be imported and used programmatically:

```python
# Optional programmatic usage
from scripts.automations.launch_fsmon_monitoring import launch_fsmon_monitoring

fsmon_process = launch_fsmon_monitoring(
    package_name="com.example.app",
    device_id="emulator-5554",
    output_directory="./fsmon_logs",
    verbose=True
)
```

### **Process Management**
The tool manages its own process lifecycle:
- **Startup**: Validate prerequisites and launch worker
- **Runtime**: Monitor worker process health
- **Shutdown**: Graceful termination and cleanup
- **Error Recovery**: Automatic restart on failures

### **Process Tracking for Web UI**
```python
# Process information storage for web UI access
FSMON_PROCESSES = {
    "process_id": {
        "package_name": "com.example.app",
        "start_time": "2024-01-15T10:30:45.123Z",
        "output_directory": "./fsmon_logs",
        "status": "running",
        "device_id": "emulator-5554",
        "monitoring_paths": ["/data/data/com.example.app/"],
        "log_file": "./fsmon_logs/monitoring.log"
    }
}

def update_process_status(process_id, status):
    """Update process status for web UI monitoring."""
    
def get_all_processes():
    """Get all FSMON processes for web UI display."""
```

## **Error Handling and Recovery**

### **Common Failure Scenarios**
1. **Device Not Rooted**: Graceful fallback with clear error message
2. **FSMON Binary Missing**: Automatic download and installation
3. **Permission Denied**: Clear instructions for manual setup
4. **Device Disconnection**: Automatic reconnection attempts
5. **Pattern File Errors**: Fallback to default patterns

### **Recovery Strategies**
```python
def handle_fsmon_failure(error_type, details):
    """Handle various FSMON failure scenarios."""
    
    if error_type == "not_rooted":
        print("❌ Device not rooted. FSMON requires root access.")
        print("💡 Please root your device or use alternative monitoring.")
        return False
        
    elif error_type == "binary_missing":
        print("📥 FSMON binary not found. Attempting download...")
        return download_fsmon_binary()
        
    elif error_type == "permission_denied":
        print("🔐 Permission denied. Checking device status...")
        return check_device_permissions()
```

## **Testing Strategy**

### **Unit Tests**
```python
# test_fsmon_monitoring.py
def test_pattern_matching():
    """Test suspicious activity pattern detection."""
    
def test_fsmon_output_parsing():
    """Test FSMON output parsing and event extraction."""
    
def test_logging_format():
    """Test log output format and structure."""
```

### **Integration Tests**
```python
# test_fsmon_integration.py
def test_fsmon_workflow():
    """Test complete FSMON monitoring workflow."""
    
def test_error_handling():
    """Test error handling and recovery scenarios."""
```

### **Test Resources**
```
automatool/automatool/tests/resources/
├── fsmon_sample_output.txt     # Sample FSMON output
├── suspicious_activity_log.json # Sample log file
└── test_patterns.json          # Test pattern definitions
```

## **Performance Considerations**

### **Resource Usage**
- **Memory**: Minimal memory footprint (~50MB)
- **CPU**: Low CPU usage during monitoring
- **Storage**: Log file growth based on activity level
- **Network**: Minimal network usage (local monitoring only)

### **Optimization Strategies**
- **Pattern Pre-compilation**: Compile regex patterns once
- **Efficient Logging**: Buffered logging for high-activity periods
- **Selective Monitoring**: Focus on high-risk directories
- **Log Rotation**: Automatic log file rotation to prevent disk space issues

## **Security Considerations**

### **Device Security**
- **Root Access Required**: FSMON needs elevated privileges
- **Local Monitoring Only**: No external data transmission
- **Secure Log Storage**: Logs stored locally with appropriate permissions
- **Pattern Validation**: Validate pattern files before execution

### **Privacy and Compliance**
- **Application-Specific**: Only monitor specified application
- **No Cross-App Access**: Cannot access other applications
- **Audit Trail**: Complete logging for compliance purposes
- **Data Retention**: Configurable log retention policies

## **Monitoring and Maintenance**

### **Health Checks**
```python
def check_fsmon_health():
    """Check FSMON monitoring process health."""
    
    # Check process status
    # Verify device connectivity
    # Validate log file access
    # Check pattern matching accuracy
```

### **Performance Metrics**
- **Events Detected**: Count of suspicious activities
- **False Positive Rate**: Accuracy of pattern matching
- **Response Time**: Time from event to detection
- **Resource Usage**: Memory and CPU consumption

### **Maintenance Tasks**
- **Pattern Updates**: Regular pattern file updates
- **Log Cleanup**: Periodic log file cleanup
- **Binary Updates**: FSMON binary version updates
- **Performance Tuning**: Optimization based on usage patterns

## **Future Enhancements**

### **Advanced Pattern Matching**
- **Machine Learning**: ML-based anomaly detection
- **Behavioral Analysis**: Pattern learning from normal operations
- **Custom Rules**: User-defined detection rules
- **Threat Intelligence**: Integration with threat feeds

### **Enhanced Logging**
- **Structured Logging**: JSON-based log format
- **Log Aggregation**: Centralized log collection
- **Real-time Alerts**: Immediate notification system
- **Dashboard Integration**: Web-based monitoring interface

### **Integration Extensions**
- **SIEM Integration**: Security information and event management
- **Incident Response**: Automated response to detected threats
- **Forensic Analysis**: Enhanced evidence collection
- **Compliance Reporting**: Automated compliance reports

## **Conclusion**

This specification provides a comprehensive framework for implementing a standalone Android file system monitoring tool using FSMON with dual control interfaces. The system follows existing project patterns while maintaining independence from the main automatool workflow, providing robust monitoring capabilities for detecting suspicious file system activities.

The implementation prioritizes:
1. **Simplicity**: Easy to use and maintain as a standalone tool
2. **Reliability**: Robust error handling and recovery
3. **Independence**: Self-contained operation without external dependencies
4. **Web UI Integration**: Process management and monitoring through automatool_ui
5. **Dual Control**: Both CLI and web interface for maximum flexibility
6. **Extensibility**: Future enhancement capabilities
7. **Security**: Secure and privacy-compliant operation

By following this specification, the standalone FSMON monitoring tool will provide valuable insights into application behavior and help identify potential security threats in real-time, while offering multiple control interfaces for different user preferences and integration scenarios.
