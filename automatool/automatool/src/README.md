# Automatool Core Source Directory

This directory contains the core implementation of the Automatool malware analysis automation suite. It houses the main automation engine, specialized analysis tools, and supporting utilities that power the APK analysis workflow.

## 🏗️ Directory Structure

```
src/
├── automatool.py                    # Main automation orchestrator
├── cleanup.py                      # Resource cleanup and management
├── play_app_metadata_scraper.py    # Google Play Store metadata extraction
├── sensor_scraper.py              # SensorTower data collection
├── reviews_scraper.py             # App reviews extraction
├── test_app_metadata_scraper.py   # Testing utilities
├── 
├── AMAnDe/                         # Android Manifest Analyzer
├── blutter/                        # Flutter/Dart analysis framework
├── jni_helper/                     # JNI analysis tools for multiple platforms
├── apk_unmask                      # APK obfuscation removal binary
├── 
├── scripts/                        # Automation scripts and utilities
│   ├── automations/               # Core automation workflows
│   ├── frida/                     # Frida hooking scripts
│   ├── monitoring/                # Real-time monitoring tools
│   ├── parsers/                   # Data parsing utilities
│   └── utils/                     # Common utilities and helpers
├── 
├── src/                           # Additional source modules
│   └── play_reviews_scraper/      # Modular reviews scraping system
├── 
└── Data Files:
    ├── reviews.json               # Sample reviews data
    ├── sensortower.json          # SensorTower API responses
    └── sensorShort.md            # SensorTower usage documentation
```

## 🚀 Core Components

### **Main Orchestrator**

#### `automatool.py` - Primary Automation Engine
The central command-line interface that orchestrates the complete APK analysis workflow:

**Key Features:**
- **VPN Verification**: Ensures secure analysis environment
- **Tool Integration**: Auto-launches Jadx GUI and VS Code workspace
- **APK Installation**: Installs APK on connected Android devices via ADB
- **Intelligence Gathering**: Scrapes app metadata and reviews
- **Frida Script Management**: Prepares and configures Frida hooks
- **Resource Tracking**: Monitors and tracks all created resources

**Usage:**
```bash
python automatool.py -d "/path/to/analysis" -f "app.apk" [options]
```

**Workflow:**
1. Validates input files and tools
2. Verifies VPN connection (optional)
3. Extracts package name from APK
4. Launches analysis tools (Jadx, VS Code)
5. Scrapes intelligence data (reviews, metadata)
6. Prepares Frida scripts with package names
7. Optionally installs APK on device
8. Generates research plan and summaries

### **Resource Management**

#### `cleanup.py` - Comprehensive Cleanup Tool
Manages and cleans up all resources created during analysis:

**Capabilities:**
- **Process Management**: Terminates running Jadx and VS Code instances
- **File Cleanup**: Removes generated files and directories
- **Device Management**: Uninstalls APKs from connected devices
- **Resource Tracking**: Maintains JSON-based resource inventory
- **Selective Cleanup**: Granular control over what gets cleaned

**Usage:**
```bash
python cleanup.py [--all|--processes|--files|--devices] [--force]
```

### **Intelligence Gathering**

#### `play_app_metadata_scraper.py` - Google Play Store Intelligence
Extracts essential metadata from Google Play Store applications:

**Extracted Data:**
- **Contains Ads**: Advertisement presence indicator
- **Developer Email**: Support/contact information
- **Privacy Policy**: Privacy policy URL
- **Developer Name**: Publisher information
- **Additional Metadata**: Version info, ratings, descriptions

**Features:**
- Lightweight and focused extraction
- Error handling for unavailable apps
- JSON output format
- Rich console output with progress indicators

#### `sensor_scraper.py` - SensorTower Market Intelligence
Collects market intelligence and app performance data from SensorTower:

**Data Points:**
- Download statistics
- Revenue estimates
- Market positioning
- Competitive analysis
- Historical performance data

#### `reviews_scraper.py` - User Reviews Analysis
Extracts and analyzes user reviews for behavioral insights:

**Capabilities:**
- Multi-language review extraction
- Sentiment analysis preparation
- Behavioral pattern identification
- Review summarization

## 🔧 Specialized Analysis Tools

### **AMAnDe** - Android Manifest Analyzer
Comprehensive Android Manifest analysis framework:

**Features:**
- **Accessibility Detection**: Identifies accessibility service abuse
- **Network Security**: Analyzes network security configurations
- **Permission Analysis**: Evaluates permission usage patterns
- **Component Analysis**: Examines activities, services, receivers

**Structure:**
- `main.py`: Entry point and CLI interface
- `src/analyzer.py`: Core analysis engine
- `src/apkParser.py`: APK parsing utilities
- `src/networkSecParser.py`: Network security analysis
- `examples/`: Sample manifest files for testing

### **Blutter** - Flutter/Dart Analysis Framework
Specialized tool for analyzing Flutter applications:

**Capabilities:**
- **Dart VM Analysis**: Extracts Dart VM information
- **Flutter Engine**: Analyzes Flutter engine components
- **Code Extraction**: Recovers Dart source code
- **Symbol Resolution**: Resolves Flutter symbols

**Components:**
- `blutter.py`: Main Python interface
- `dartvm_fetch_build.py`: Dart VM build fetcher
- `extract_dart_info.py`: Dart information extractor
- `blutter/src/`: C++ core implementation (43 files)

### **JNI Helper** - Multi-Platform JNI Analysis
Cross-platform JNI analysis supporting multiple reverse engineering tools:

**Supported Platforms:**
- **Binary Ninja**: `binary_ninja/jni_helper.py`
- **Ghidra**: `ghidra/jni_helper.py` + templates
- **IDA Pro**: `ida/jni_helper.py` (Python 2/3 versions)
- **Radare2**: `r2/jni_helper.py`

**Features:**
- JNI function identification
- Native method mapping
- Header file generation
- Cross-reference analysis

**Resources:**
- `headers/`: JNI header files (jni.h, art_method.h, dex.h)
- `demo_apk/`: Sample APK for testing JNI analysis
- `extract_jni.py`: Standalone JNI extraction utility

### **APK Unmask** - Deobfuscation Tool
Binary tool for removing APK obfuscation and revealing hidden components:

**Capabilities:**
- Code deobfuscation
- String decryption
- Resource extraction
- Anti-analysis bypass

## 📁 Scripts Directory

### **automations/** - Core Automation Workflows
The heart of the automation system containing workflow implementations:

**Key Automations:**
- `_assets_analysis_worker.py`: APK asset analysis
- `_font_analysis_worker.py`: Font steganography detection
- `_frida_automation_worker.py`: Frida script automation
- `_mobsf_analysis_worker.py`: MobSF integration
- `_vpn_frida_worker.py`: VPN-controlled Frida execution

**Analysis Tools:**
- `base64_scanner.py`: Base64 string detection
- `detect_image_steganography.py`: Image steganography analysis
- `detect_ttf_steganography.py`: Font steganography detection
- `file_analyzer.py`: Generic file analysis
- `apk_unmask_filter.py`: APK Unmask result filtering

**Workflow Management:**
- `launch_jadx.py`: Jadx GUI launcher
- `launch_vscode.py`: VS Code workspace setup
- `install_apk.py`: APK installation automation
- `copy_frida_scripts.py`: Frida script management
- `merge_app_intelligence.py`: Intelligence data aggregation

**VPN Controllers:**
- `vpn_controllers/nordvpn_controller.py`: NordVPN automation
- `vpn_controllers/expressvpn_controller.py`: ExpressVPN automation
- `vpn_controllers/surfshark_controller.py`: Surfshark automation
- `vpn_controllers/base_vpn_controller.py`: Base VPN interface

### **frida/** - Dynamic Analysis Scripts
Frida hooking scripts for runtime analysis:

**Categories:**
- `bypasses/`: Anti-analysis and protection bypasses
- `info/`: Information gathering hooks
- `templates/`: Reusable hook templates

**Key Scripts:**
- `main_hook_js.js`: Primary hooking framework
- `script.js`: General-purpose hooks
- `yairhook.js`: Advanced hooking utilities

### **monitoring/** - Real-Time Monitoring
Tools for real-time analysis and monitoring:

**Components:**
- `sms_call_monitor.py`: SMS/Call monitoring for toll fraud detection
- `fraud_detector.py`: Fraud pattern detection
- `notification_monitor.py`: Notification analysis

### **utils/** - Common Utilities
Shared utilities and helper functions:

**Core Utilities:**
- `utils.py`: General utility functions
- `adb_controller.py`: ADB device management
- `validators.py`: Input validation functions
- `error_handlers.py`: Error handling utilities

**Configuration:**
- `apk_unmask_ignore_list.txt`: APK Unmask filtering rules

### **parsers/** - Data Processing
Specialized parsers for analysis results:

**Parsers:**
- `parse_steganography_results.py`: Steganography result processing

## 🔍 Data Files and Examples

### **Sample Data**
- `reviews.json`: Example app reviews data structure
- `sensortower.json`: SensorTower API response examples
- `sensorShort.md`: SensorTower integration documentation

### **Testing**
- `test_app_metadata_scraper.py`: Unit tests for metadata scraping

## 🚀 Getting Started

### **Prerequisites**
- Python 3.8+
- Android SDK (ADB)
- Java Runtime Environment
- Required Python packages (see individual requirements.txt files)

### **Basic Usage**

1. **Full Analysis Workflow**:
   ```bash
   cd src/
   python automatool.py -d "/path/to/analysis" -f "app.apk" --verbose
   ```

2. **Specific Analysis Tasks**:
   ```bash
   # Metadata scraping only
   python play_app_metadata_scraper.py com.example.app
   
   # Manifest analysis
   cd AMAnDe/
   python main.py -f /path/to/AndroidManifest.xml
   
   # JNI analysis
   cd jni_helper/
   python extract_jni.py /path/to/app.apk
   ```

3. **Cleanup Resources**:
   ```bash
   python cleanup.py --all
   ```

### **Advanced Usage**

1. **VPN-Controlled Frida Analysis**:
   ```bash
   python scripts/automations/_vpn_frida_worker.py \
     --apk /path/to/app.apk \
     --package com.example.app \
     --vpn nordvpn \
     --locations US,UK,DE
   ```

2. **Steganography Detection**:
   ```bash
   python scripts/automations/detect_image_steganography.py /path/to/apk
   python scripts/automations/detect_ttf_steganography.py /path/to/apk
   ```

3. **Intelligence Gathering**:
   ```bash
   python scripts/automations/merge_app_intelligence.py \
     --package com.example.app \
     --output /path/to/intelligence.json
   ```

## 🔧 Development and Extension

### **Adding New Automations**
1. Create your automation script in `scripts/automations/`
2. Follow the established patterns for argument parsing and error handling
3. Add resource tracking if creating files or processes
4. Update the main `automatool.py` if integration is needed

### **Extending Analysis Tools**
1. **New Parsers**: Add to `scripts/parsers/`
2. **New Monitors**: Add to `scripts/monitoring/`
3. **New Utilities**: Add to `scripts/utils/`

### **Testing**
- Unit tests should be added alongside new components
- Integration tests should validate end-to-end workflows
- Use the provided test utilities and examples

## 🛡️ Security Considerations

### **VPN Usage**
- Always verify VPN connection before sensitive analysis
- Use different VPN locations for different analysis phases
- Monitor for IP leaks during dynamic analysis

### **Device Safety**
- Use dedicated analysis devices or emulators
- Regularly clean up installed APKs
- Monitor device state during analysis

### **Data Handling**
- Sanitize extracted data before storage
- Be cautious with sensitive information in logs
- Use secure channels for data transmission

## 📚 Documentation

### **Individual Tool Documentation**
- Each major tool has its own README.md
- Check `specs/` directory for detailed specifications
- See `examples/` directories for usage examples

### **API References**
- Function-level documentation in source code
- Type hints for better IDE support
- Comprehensive error handling documentation

## 🤝 Contributing

1. **Code Style**: Follow PEP 8 and existing patterns
2. **Documentation**: Update README files for new features
3. **Testing**: Add comprehensive test coverage
4. **Error Handling**: Implement robust error handling
5. **Resource Management**: Always clean up created resources

## 🔍 Troubleshooting

### **Common Issues**
- **Import Errors**: Check Python path and dependencies
- **Permission Denied**: Ensure proper file/device permissions
- **Tool Not Found**: Verify tool installations and PATH
- **VPN Issues**: Check VPN client installation and configuration

### **Debug Mode**
Enable verbose output for detailed debugging:
```bash
python automatool.py -d "/path" -f "app.apk" --verbose
```

### **Resource Tracking**
Monitor resource usage and cleanup:
```bash
python cleanup.py --summary-only
```

---

**Focus on the malware, not the setup. Let Automatool handle the automation.** 🚀
