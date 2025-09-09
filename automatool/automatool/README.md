# APK Analysis Automation Tool


A comprehensive automation tool that streamlines the APK analysis workflow by integrating VPN verification, package extraction, tool launching, reviews scraping, and Frida script preparation.


## Overview


This tool automates the complete APK analysis setup process:
1. **VPN Verification** - Ensures secure connection before analysis
2. **File Validation** - Validates APK and directory existence
3. **Package Extraction** - Extracts package name from APK
4. **Tool Integration** - Launches Jadx GUI and VS Code workspace
5. **Reviews Scraping** - Collects app reviews for analysis
6. **Frida Scripts Setup** - Copies and customizes Frida scripts with package name


## Requirements


### Dependencies
- **Python 3.x** - Main runtime
- **NordVPN CLI** - VPN status verification (`nordvpn`)
- **Jadx GUI** - APK analysis tool (`jadx-gui`)
- **VS Code** - Code editor (`code`)
- **Android SDK Build Tools** - Package name extraction (`aapt`)
- **Android SDK Platform Tools** - APK installation (`adb`) - *Optional*


### Required Files
- `reviews_scraper.py` - Must be in project root
- `venv/` - Virtual environment for reviews scraper (recommended)
- Frida scripts in `tool/` directory:
  - `native_hooks.js`
  - `frida_hooks.js`
  - `dex_loader_hooks.js`
  - `dex_load_tracer.js`


## Installation


### 1. Install External Tools


#### NordVPN CLI
Download from: https://nordvpn.com/download/
Ensure `nordvpn` command is in your PATH.


#### Jadx GUI
Download from: https://github.com/skylot/jadx/releases
Ensure `jadx-gui` command is in your PATH.


#### VS Code
Download from: https://code.visualstudio.com/
Ensure `code` command is in your PATH.


#### Android SDK Build Tools
Install Android SDK and ensure build-tools are in your PATH.
The tool will use `aapt` command (standard) or `pn` command (custom alias).


**Option 1: Use aapt (Recommended)**
Ensure `aapt` is in your PATH from Android SDK build-tools.


**Option 2: Set up pn alias**
Add to your shell profile (`.bashrc`, `.zshrc`, etc.):
```bash
# For aapt-based pn alias (exact command from your .zshrc)
alias pn='aapt dump badging "$1" | grep "package: name= " | cut -d "'" -f2'
```


### 2. Setup Project (Kali Linux)
```bash
# Ensure you're in the project root directory
cd /path/to/Automator


# Create and setup virtual environment for reviews scraper
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt  # Install reviews scraper dependencies


# Verify required files exist
ls reviews_scraper.py          # Should exist in root
ls venv/                       # Virtual environment directory
ls tool/apk_analyzer.py        # Main script
ls tool/*.js                   # Frida scripts
```


## Usage


### Basic Usage
```bash
python3 tool/apk_analyzer.py -d "/home/user/analysis/myapp" -f "myapp.apk"
```


### With Verbose Output
```bash
python3 tool/apk_analyzer.py -d "/home/user/analysis/myapp" -f "myapp.apk" --verbose
```


### Arguments
- `-d`, `--directory` - **Required**: Directory containing the APK file
- `-f`, `--filename` - **Required**: Name of the APK file to analyze
- `-v`, `--verbose` - **Optional**: Enable detailed debugging output
- `--install` - **Optional**: Install APK on connected Android device via ADB


### Examples (Kali Linux)
```bash
# Basic usage
python3 tool/apk_analyzer.py -d "/home/user/analysis/myapp" -f "app.apk"


# Different directory structure
python3 tool/apk_analyzer.py -d "/opt/apk-analysis/samples" -f "target.apk"


# Verbose mode for debugging
python3 tool/apk_analyzer.py -d "/home/user/Downloads" -f "malware.apk" -v


# Install APK on connected device
python3 tool/apk_analyzer.py -d "/home/user/Downloads" -f "app.apk" --install


# Full analysis with installation and verbose output
python3 tool/apk_analyzer.py -d "/opt/samples" -f "target.apk" --install --verbose
```


## Workflow


### 1. VPN Verification
- Checks VPN connection status using `nordvpn status`
- Extracts and displays connected country
- **Requirement**: Must be connected to VPN to proceed


### 2. File Validation
- Validates target directory exists
- Confirms APK file exists at specified location
- Warns if file doesn't have `.apk` extension


### 3. Package Name Extraction
- Uses `pn` command to extract package name from APK
- Package name is used for Frida script customization
- **Example**: `com.example.myapp`


### 4. Tool Integration
- **Jadx GUI**: Launches in background for APK analysis
- **VS Code**: Opens target directory as workspace
- Both tools run non-blocking (continue in background)


### 5. Reviews Scraping
- Activates virtual environment (`venv/`) if available
- Executes `reviews_scraper.py` with extracted package name and JSON format
- Command: `python3 reviews_scraper.py --format=json -o reviews.txt {package_name}`
- Saves reviews to `{target_directory}/reviews.txt` in JSON format
- **Blocking**: Waits for completion before continuing
- **Fallback**: Uses system Python if virtual environment not found


### 6. Frida Scripts Setup
- Copies Frida scripts from `tool/` to `{target_directory}/frida_scripts/`
- Updates scripts with extracted package name:
  - `native_hooks.js`: Replaces `"com.example.package"` → `{package_name}`
  - `dex_loader_hooks.js`: Replaces `"com.brick.bre.Brick"` → `{package_name}.PLACEHOLDER_CLASS`


### 7. APK Installation (Optional)
- **Triggered by**: `--install` flag
- **Requirements**: Connected Android device with USB debugging enabled
- **Process**: Uses `adb install -r` to install/reinstall APK on device
- **Validation**: Checks for ADB availability and connected devices


## Output Structure


After successful execution, your target directory will contain:
```
target_directory/
├── your_app.apk           # Original APK file
├── reviews.txt            # Scraped app reviews
└── frida_scripts/         # Customized Frida scripts
    ├── native_hooks.js    # Updated with package name
    ├── frida_hooks.js
    ├── dex_loader_hooks.js # Updated with placeholder class
    └── dex_load_tracer.js
```


## Example Output


### Successful Execution
```
--- Starting APK Analysis Automation ---
✅ VPN Status: Connected to United States
✅ File validation passed: C:\analysis\myapp\myapp.apk
✅ Package name extracted: com.example.myapp
✅ Jadx GUI launched successfully
✅ VS Code workspace opened: C:\analysis\myapp
✅ Reviews scraper completed: C:\analysis\myapp\reviews.txt
✅ Frida scripts copied: 4/4 files
✅ Frida scripts updated with package name: 2 files
--- APK Analysis Automation Complete ---
```


### Verbose Mode
```
--- Starting APK Analysis Automation ---
[DEBUG] Target directory: C:\analysis\myapp
[DEBUG] APK filename: myapp.apk
[DEBUG] Checking VPN status...
✅ VPN Status: Connected to United States
[DEBUG] Validating file paths...
[DEBUG] ✅ Directory validated: C:\analysis\myapp
[DEBUG] ✅ APK file validated: C:\analysis\myapp\myapp.apk
✅ File validation passed: C:\analysis\myapp\myapp.apk
[DEBUG] Extracting package name from: C:\analysis\myapp\myapp.apk
[DEBUG] ✅ Package name extracted: com.example.myapp
✅ Package name extracted: com.example.myapp
[DEBUG] Launching Jadx GUI for: C:\analysis\myapp\myapp.apk
[DEBUG] ✅ Jadx GUI launched with PID: 12345
✅ Jadx GUI launched successfully
[DEBUG] Launching VS Code for directory: C:\analysis\myapp
[DEBUG] ✅ VS Code launched with PID: 56789
✅ VS Code workspace opened: C:\analysis\myapp
[DEBUG] Running reviews scraper for package: com.example.myapp
[DEBUG] Output file: C:\analysis\myapp\reviews.txt
[DEBUG] Command: python reviews_scraper.py -o C:\analysis\myapp\reviews.txt com.example.myapp
[DEBUG] ✅ Reviews scraper completed successfully
✅ Reviews scraper completed: C:\analysis\myapp\reviews.txt
[DEBUG] Copying Frida scripts from tool directory to C:\analysis\myapp\frida_scripts
[DEBUG] Created directory: C:\analysis\myapp\frida_scripts
[DEBUG] ✅ Copied: native_hooks.js
[DEBUG] ✅ Copied: frida_hooks.js
[DEBUG] ✅ Copied: dex_loader_hooks.js
[DEBUG] ✅ Copied: dex_load_tracer.js
✅ Frida scripts copied: 4/4 files
[DEBUG] Updating Frida scripts with package name: com.example.myapp
[DEBUG] Scripts directory: C:\analysis\myapp\frida_scripts
[DEBUG] Updating script: native_hooks.js
[DEBUG] Replaced 'com.example.package' with 'com.example.myapp' in native_hooks.js
[DEBUG] ✅ Updated: native_hooks.js
[DEBUG] Updating script: dex_loader_hooks.js
[DEBUG] Replaced 'com.brick.bre.Brick' with 'com.example.myapp.PLACEHOLDER_CLASS' in dex_loader_hooks.js
[DEBUG] ✅ Updated: dex_loader_hooks.js
✅ Frida scripts updated with package name: 2 files
--- APK Analysis Automation Complete ---
```


## Error Handling


The tool provides comprehensive error handling with clear guidance:


### VPN Not Connected
```
❌ ERROR: VPN connection required!
Please connect to your VPN and try again.
Expected: nordvpn status should show 'Country: <country_name>'
```


### Missing APK File
```
❌ ERROR: APK file does not exist!
Expected location: C:\analysis\myapp\missing.apk
Please verify the APK filename and try again.
```


### Package Extraction Failed
```
❌ ERROR: Could not extract package name from APK!
APK: C:\analysis\myapp\myapp.apk


Troubleshooting:
1. Verify the APK file is valid and not corrupted
2. Install Android SDK build-tools and ensure 'aapt' is in your PATH
3. Or set up 'pn' alias in your shell (see README for details)
4. Try extracting package name manually: aapt dump badging <apk_file>
```


### Setting up pn alias (Kali Linux)
If you prefer using the `pn` shortcut, add this to your shell profile:
```bash
# Add to ~/.bashrc or ~/.zshrc
alias pn='aapt dump badging "$1" | grep "package: name= " | cut -d "'" -f2'


# Then reload your shell
source ~/.bashrc  # or source ~/.zshrc
```


### Missing Tools
```
❌ ERROR: 'jadx-gui' command not found.
Please ensure Jadx is installed and 'jadx-gui' is in your system PATH.
```


### APK Installation Issues
```
❌ ERROR: 'adb' command not found.
Please ensure Android SDK platform-tools are installed and in your PATH.


⚠️  WARNING: No Android devices connected via ADB.
Please connect a device and enable USB debugging.


❌ ERROR: Failed to install APK on device
Return code: 1
Error: INSTALL_FAILED_ALREADY_EXISTS
```


## Troubleshooting


### Common Issues


1. **VPN Connection**: Ensure NordVPN is connected and `nordvpn status` shows country
2. **Missing Tools**: Install and add all required tools to your system PATH
3. **File Permissions**: Ensure write permissions for target directory
4. **APK Validity**: Verify APK file is not corrupted
5. **Working Directory**: Run script from project root directory
6. **ADB Device Connection**: Ensure device is connected and USB debugging is enabled
7. **APK Installation**: Use `adb devices` to verify device connectivity


### Verbose Mode
Use `--verbose` flag for detailed debugging information:
```bash
python3 tool/apk_analyzer.py -d "/home/user/analysis" -f "app.apk" --verbose
```


## Support


For issues or questions:
1. Check error messages for specific guidance
2. Use verbose mode for detailed debugging
3. Verify all dependencies are installed and in PATH
4. Ensure you're running from the correct directory


## License


This tool is part of the APK Analysis Automation project.



