# 🌐 Automatool Web Interface Specification

Based on my analysis of the automatool project, I'll create a comprehensive specification for a Flask-based web interface that simplifies the APK analysis workflow.

## 📋 **Executive Summary**

The Automatool Web Interface will provide a user-friendly web-based frontend for the existing automatool.py command-line APK analysis toolkit. This interface will support both "lazy mode" (file uploads) and "manual mode" (path specification) while maintaining all existing functionality through a clean REST API architecture.

## 🏗️ **Architecture Overview**

### **Technology Stack**
- **Backend**: Flask (Python)
- **Frontend**: HTML5 + CSS3 + Vanilla JavaScript
- **File Handling**: Werkzeug for secure uploads
- **Process Management**: Python subprocess + threading
- **State Management**: Flask session + global variables
- **Styling**: Modern CSS with responsive design

### **Design Principles**
1. **Simplicity**: Clean, intuitive interface requiring minimal user interaction
2. **Flexibility**: Support both lazy mode (uploads) and manual mode (paths)
3. **Safety**: Secure file handling with validation and cleanup
4. **Transparency**: Real-time feedback and process status monitoring
5. **Maintainability**: Modular Flask application structure

## 📂 **Project Structure**

```
automatool_ui/
├── app.py                     # Main Flask application
├── config.py                  # Configuration settings
├── requirements.txt           # Python dependencies
├── static/
│   ├── css/
│   │   └── style.css         # Main stylesheet
│   ├── js/
│   │   └── main.js           # JavaScript functionality
│   └── uploads/              # Temporary upload directory
├── templates/
│   ├── base.html             # Base template
│   ├── index.html            # Main page
│   └── components/
│       ├── upload_form.html  # File upload component
│       ├── manual_form.html  # Manual path component
│       └── action_panel.html # Action buttons panel
├── utils/
│   ├── __init__.py
│   ├── file_handler.py       # File upload/validation utilities
│   ├── process_manager.py    # Process execution wrapper
│   └── path_validator.py     # Path validation utilities
└── logs/                     # Application logs
    └── app.log
```

## 🎨 **User Interface Design**

### **Main Page Layout**
```
┌─────────────────────────────────────────────────────────┐
│                    🔧 Automatool Web Interface                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─── Configuration Mode ─────────────────────────────┐ │
│  │  ○ Lazy Mode (Upload Files)                        │ │
│  │  ○ Manual Mode (Specify Paths)                     │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                         │
│  ┌─── Lazy Mode Panel ────────────────────────────────┐ │
│  │  📁 APK File:      [Choose File] [filename.apk]    │ │
│  │  📄 YARA JSON:     [Choose File] [yara.json]       │ │
│  │                                                     │ │
│  │  📂 Output Directory: /default/analysis/[auto-id]  │ │
│  │                                                     │ │
│  │                    [🚀 Launch Setup]               │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                         │
│  ┌─── Manual Mode Panel ──────────────────────────────┐ │
│  │  📂 Directory Path: [___________________________]  │ │
│  │  📁 APK Filename:   [___________________________]  │ │
│  │                                                     │ │
│  │                    [🚀 Launch Setup]               │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                         │
│  ┌─── Global Configuration ───────────────────────────┐ │
│  │  📱 APK_FILENAME:  [current-filename.apk]          │ │
│  │  📂 OUTPUT_DIR:    [/path/to/analysis/dir]         │ │
│  │  📍 APK_PATH:      [/path/to/analysis/file.apk]    │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                         │
│  ┌─── Analysis Actions ───────────────────────────────┐ │
│  │  [🔄 Full Process]  [📱 Get Reviews]               │ │
│  │  [🧹 Clean]         [🔍 Upload to MobSF]          │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                         │
│  ┌─── Process Status ─────────────────────────────────┐ │
│  │  🔄 Status: Ready                                   │ │
│  │  📊 Progress: [████████░░░░░░░░░░] 40%            │ │
│  │  📝 Log: Waiting for user action...                │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## 🔧 **Core Functionality**

### **1. Configuration Management**

#### **Lazy Mode (Default)**
- **APK Upload**: Secure file upload with validation (max 500MB, .apk extension)
- **YARA Upload**: Optional JSON file upload for YARA results
- **Auto Directory**: Server creates unique timestamped directory
- **Path Generation**: Automatically sets global variables after upload

#### **Manual Mode**
- **Directory Input**: User specifies existing directory containing APK
- **APK Filename**: User specifies APK filename within directory
- **Validation**: Server validates paths and file existence
- **Path Setting**: Updates global variables based on user input

### **2. Global Variable Management**

```python
# Global state variables
app_state = {
    'APK_FILENAME': None,    # e.g., "myapp.apk"
    'OUTPUT_DIR': None,      # e.g., "/path/to/analysis/20240115_143022_analysis"
    'APK_PATH': None,        # e.g., "/path/to/analysis/20240115_143022_analysis/myapp.apk"
    'YARA_PATH': None,       # e.g., "/path/to/analysis/20240115_143022_analysis/yara.json"
    'setup_complete': False, # Whether initial setup is done
    'current_process': None  # Currently running process info
}
```

### **3. Analysis Operations**

#### **Full Process** 
- **Command**: `python automatool.py -d {OUTPUT_DIR} -f {APK_FILENAME} --verbose`
- **Function**: Complete APK analysis workflow
- **Prerequisites**: APK_PATH, OUTPUT_DIR, APK_FILENAME must be set

#### **Get Reviews**
- **Command**: `python parse_reviews_summary.py {OUTPUT_DIR} --verbose`
- **Function**: Parse reviews.json and create summary
- **Prerequisites**: OUTPUT_DIR must be set and contain reviews.json

#### **Clean**
- **Command**: `python cleanup.py --verbose`
- **Function**: Clean up all tracked resources
- **Prerequisites**: None (can run anytime)

#### **Upload to MobSF**
- **Command**: `python _mobsf_analysis_worker.py --apk-path {APK_PATH} --output-dir {OUTPUT_DIR} --verbose`
- **Function**: Upload APK to MobSF for analysis
- **Prerequisites**: APK_PATH and OUTPUT_DIR must be set

## 🛠️ **Technical Implementation**

### **Flask Application Structure**

```python
# app.py - Main Flask Application
from flask import Flask, render_template, request, jsonify, session
import os
import subprocess
import threading
from datetime import datetime
from utils.file_handler import FileHandler
from utils.process_manager import ProcessManager
from utils.path_validator import PathValidator

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Global application state
app_state = {
    'APK_FILENAME': None,
    'OUTPUT_DIR': None, 
    'APK_PATH': None,
    'YARA_PATH': None,
    'setup_complete': False,
    'current_process': None
}

@app.route('/')
def index():
    """Main page with configuration and action panels."""
    return render_template('index.html', state=app_state)

@app.route('/api/upload', methods=['POST'])
def handle_upload():
    """Handle file uploads in lazy mode."""
    # File upload logic
    pass

@app.route('/api/manual-setup', methods=['POST'])
def handle_manual_setup():
    """Handle manual path configuration."""
    # Manual setup logic
    pass

@app.route('/api/action/<action_name>', methods=['POST'])
def execute_action(action_name):
    """Execute analysis actions (full-process, get-reviews, clean, mobsf)."""
    # Action execution logic
    pass

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current process status."""
    # Status checking logic
    pass
```

### **File Upload Handler**

```python
# utils/file_handler.py
import os
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename

class FileHandler:
    def __init__(self, upload_dir='static/uploads', max_size=500*1024*1024):
        self.upload_dir = upload_dir
        self.max_size = max_size
        self.allowed_extensions = {'.apk', '.json'}
    
    def create_analysis_directory(self):
        """Create timestamped analysis directory."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        dir_name = f"{timestamp}_analysis"
        full_path = os.path.join(self.upload_dir, dir_name)
        os.makedirs(full_path, exist_ok=True)
        return full_path
    
    def validate_and_save_apk(self, file, output_dir):
        """Validate and save uploaded APK file."""
        if not file or not file.filename:
            return None, "No file provided"
        
        if not file.filename.lower().endswith('.apk'):
            return None, "File must be an APK"
        
        if len(file.read()) > self.max_size:
            return None, f"File too large (max {self.max_size//1024//1024}MB)"
        
        file.seek(0)  # Reset file pointer
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(output_dir, filename)
        file.save(filepath)
        
        return filepath, None
    
    def validate_and_save_yara(self, file, output_dir):
        """Validate and save uploaded YARA JSON file."""
        if not file or not file.filename:
            return None, None  # YARA is optional
        
        if not file.filename.lower().endswith('.json'):
            return None, "YARA file must be JSON"
        
        filename = "yara.json"  # Standardize name
        filepath = os.path.join(output_dir, filename)
        file.save(filepath)
        
        return filepath, None
```

### **Process Manager**

```python
# utils/process_manager.py
import subprocess
import threading
import time
from datetime import datetime

class ProcessManager:
    def __init__(self):
        self.current_process = None
        self.process_status = "ready"
        self.process_log = []
    
    def execute_automatool(self, output_dir, apk_filename, verbose=True):
        """Execute the main automatool.py process."""
        cmd = [
            'python', 'automatool.py',
            '-d', output_dir,
            '-f', apk_filename
        ]
        if verbose:
            cmd.append('--verbose')
        
        return self._run_process(cmd, "Full Process")
    
    def execute_reviews_parsing(self, output_dir, verbose=True):
        """Execute reviews parsing."""
        cmd = ['python', 'parse_reviews_summary.py', output_dir]
        if verbose:
            cmd.append('--verbose')
        
        return self._run_process(cmd, "Get Reviews")
    
    def execute_cleanup(self, verbose=True):
        """Execute cleanup process."""
        cmd = ['python', 'cleanup.py', '--force']
        if verbose:
            cmd.append('--verbose')
        
        return self._run_process(cmd, "Clean")
    
    def execute_mobsf_upload(self, apk_path, output_dir, verbose=True):
        """Execute MobSF upload.""" 
        cmd = [
            'python', '_mobsf_analysis_worker.py',
            '--apk-path', apk_path,
            '--output-dir', output_dir
        ]
        if verbose:
            cmd.append('--verbose')
        
        return self._run_process(cmd, "Upload to MobSF")
    
    def _run_process(self, cmd, process_name):
        """Run process in background thread."""
        self.process_status = "running"
        self.add_log(f"Starting {process_name}...")
        
        def run():
            try:
                process = subprocess.Popen(
                    cmd, 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd='automatool/automatool/src'  # Set working directory
                )
                
                self.current_process = {
                    'name': process_name,
                    'pid': process.pid,
                    'start_time': datetime.now(),
                    'process': process
                }
                
                # Read output line by line
                for line in iter(process.stdout.readline, ''):
                    if line:
                        self.add_log(line.strip())
                
                process.wait()
                
                if process.returncode == 0:
                    self.process_status = "completed"
                    self.add_log(f"✅ {process_name} completed successfully")
                else:
                    self.process_status = "error"
                    self.add_log(f"❌ {process_name} failed with code {process.returncode}")
                
            except Exception as e:
                self.process_status = "error"
                self.add_log(f"❌ Error running {process_name}: {str(e)}")
            
            finally:
                self.current_process = None
        
        thread = threading.Thread(target=run)
        thread.daemon = True
        thread.start()
        
        return True
    
    def add_log(self, message):
        """Add message to process log."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.process_log.append(f"[{timestamp}] {message}")
        
        # Keep only last 100 log entries
        if len(self.process_log) > 100:
            self.process_log = self.process_log[-100:]
    
    def get_status(self):
        """Get current process status."""
        return {
            'status': self.process_status,
            'current_process': self.current_process,
            'log': self.process_log[-10:] if self.process_log else [],  # Last 10 entries
            'full_log': self.process_log
        }
```

### **API Endpoints**

#### **POST /api/upload** - Handle Lazy Mode Setup
```json
// Request: multipart/form-data
{
  "apk_file": "<file>",
  "yara_file": "<file>" // optional
}

// Response:
{
  "success": true,
  "message": "Files uploaded successfully",
  "state": {
    "APK_FILENAME": "myapp.apk",
    "OUTPUT_DIR": "/uploads/20240115_143022_analysis",
    "APK_PATH": "/uploads/20240115_143022_analysis/myapp.apk",
    "YARA_PATH": "/uploads/20240115_143022_analysis/yara.json",
    "setup_complete": true
  }
}
```

#### **POST /api/manual-setup** - Handle Manual Mode Setup
```json
// Request:
{
  "directory_path": "/path/to/analysis",
  "apk_filename": "myapp.apk"
}

// Response:
{
  "success": true,
  "message": "Manual setup completed",
  "state": {
    "APK_FILENAME": "myapp.apk",
    "OUTPUT_DIR": "/path/to/analysis", 
    "APK_PATH": "/path/to/analysis/myapp.apk",
    "setup_complete": true
  }
}
```

#### **POST /api/action/{action_name}** - Execute Analysis Actions
```json
// Supported actions: full-process, get-reviews, clean, mobsf

// Request: (no body needed)

// Response:
{
  "success": true,
  "message": "Action started successfully",
  "action": "full-process",
  "process_id": "12345"
}
```

#### **GET /api/status** - Get Current Status
```json
// Response:
{
  "status": "running", // ready, running, completed, error
  "current_process": {
    "name": "Full Process",
    "pid": 12345,
    "start_time": "2024-01-15T14:30:22",
    "duration": "00:02:15"
  },
  "log": [
    "[14:30:22] Starting Full Process...",
    "[14:30:25] ✅ VPN connection verified",
    "[14:30:30] 🔄 Launching Jadx GUI..."
  ],
  "state": {
    "APK_FILENAME": "myapp.apk",
    "OUTPUT_DIR": "/uploads/20240115_143022_analysis",
    "APK_PATH": "/uploads/20240115_143022_analysis/myapp.apk",
    "setup_complete": true
  }
}
```

## 🎯 **User Workflow**

### **Scenario 1: Lazy Mode (Recommended)**
1. User opens web interface
2. Selects "Lazy Mode" (default)
3. Uploads APK file (required)
4. Optionally uploads YARA JSON file
5. Clicks "Launch Setup"
6. System creates analysis directory and sets global variables
7. User sees updated global configuration
8. User clicks desired action button (Full Process, Get Reviews, etc.)
9. System executes command and shows real-time progress
10. User can monitor status and logs in real-time

### **Scenario 2: Manual Mode**
1. User opens web interface
2. Selects "Manual Mode"
3. Enters directory path containing APK
4. Enters APK filename
5. Clicks "Launch Setup"
6. System validates paths and sets global variables
7. User sees updated global configuration  
8. User proceeds with analysis actions as in Scenario 1

## 🔒 **Security & Validation**

### **File Upload Security**
- **Size Limits**: 500MB max for APK files
- **Extension Validation**: Only .apk and .json files allowed
- **Filename Sanitization**: Use Werkzeug's secure_filename()
- **Upload Directory**: Isolated upload area with proper permissions
- **Virus Scanning**: Optional integration with antivirus tools

### **Path Validation**
- **Directory Existence**: Verify paths exist and are accessible
- **File Permissions**: Check read/write permissions
- **Path Traversal Protection**: Prevent '../' attacks
- **APK Validation**: Verify APK file integrity with aapt

### **Process Security**
- **Command Injection Protection**: Use subprocess with argument lists
- **Working Directory**: Set proper CWD for all subprocess calls
- **Timeout Protection**: Kill processes that run too long
- **Resource Limits**: Monitor CPU and memory usage

## ⚡ **Performance Considerations**

### **File Handling**
- **Streaming Uploads**: Handle large APK files efficiently
- **Temporary Storage**: Clean up uploaded files after analysis
- **Async Operations**: Use threading for long-running processes
- **Progress Tracking**: Real-time feedback for file operations

### **Process Management**
- **Background Execution**: All analysis processes run in background
- **Resource Monitoring**: Track memory and CPU usage
- **Process Cleanup**: Ensure processes are properly terminated
- **Concurrent Limits**: Limit simultaneous analysis processes

## 🚀 **Deployment Guide**

### **Development Setup**
```bash
# Clone the repository
cd automatool_ui

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export FLASK_APP=app.py
export FLASK_ENV=development
export FLASK_DEBUG=1

# Create necessary directories
mkdir -p static/uploads logs

# Run the application
flask run --host=0.0.0.0 --port=5000
```

### **Production Setup**
```bash
# Use production WSGI server
pip install gunicorn

# Run with gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Or use Docker
docker build -t automatool-ui .
docker run -p 5000:5000 -v /path/to/automatool:/app/automatool automatool-ui
```

## 📋 **Configuration File**

```python
# config.py
import os
from datetime import timedelta

class Config:
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    FLASK_ENV = os.environ.get('FLASK_ENV') or 'development'
    
    # File Upload Configuration
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB max file size
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')
    ALLOWED_EXTENSIONS = {'.apk', '.json'}
    
    # Automatool Configuration
    AUTOMATOOL_PATH = os.environ.get('AUTOMATOOL_PATH') or 'automatool/automatool/src'
    DEFAULT_TIMEOUT = 3600  # 1 hour timeout for processes
    
    # Security Configuration
    SESSION_PERMANENT = False
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    
    # Logging Configuration
    LOG_LEVEL = 'INFO'
    LOG_FILE = 'logs/app.log'

class DevelopmentConfig(Config):
    DEBUG = True
    FLASK_ENV = 'development'

class ProductionConfig(Config):
    DEBUG = False
    FLASK_ENV = 'production'
    # Add production-specific settings

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
```

## 📝 **Requirements.txt**

```txt
Flask==2.3.3
Werkzeug==2.3.7
Jinja2==3.1.2
click==8.1.7
itsdangerous==2.1.2
MarkupSafe==2.1.3
gunicorn==21.2.0
python-dotenv==1.0.0
```

## 🎨 **Frontend Design**

### **Modern CSS Framework**
```css
/* static/css/style.css */
:root {
    --primary-color: #2563eb;
    --secondary-color: #64748b;
    --success-color: #059669;
    --error-color: #dc2626;
    --warning-color: #d97706;
    --background: #f8fafc;
    --surface: #ffffff;
    --border: #e2e8f0;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
}

.panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.btn {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.75rem 1.5rem;
    border: none;
    border-radius: 6px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
}

.btn-primary {
    background: var(--primary-color);
    color: white;
}

.btn-primary:hover {
    background: #1d4ed8;
}

.progress-bar {
    width: 100%;
    height: 8px;
    background: var(--border);
    border-radius: 4px;
    overflow: hidden;
}

.progress-fill {
    height: 100%;
    background: var(--primary-color);
    transition: width 0.3s ease;
}
```

### **JavaScript Functionality**
```javascript
// static/js/main.js
class AutomatoolUI {
    constructor() {
        this.state = null;
        this.statusInterval = null;
        this.init();
    }
    
    init() {
        this.bindEvents();
        this.updateStatus();
        this.startStatusPolling();
    }
    
    bindEvents() {
        // Mode switching
        document.querySelectorAll('input[name="mode"]').forEach(radio => {
            radio.addEventListener('change', this.toggleMode.bind(this));
        });
        
        // Form submissions
        document.getElementById('lazy-form').addEventListener('submit', this.handleLazyUpload.bind(this));
        document.getElementById('manual-form').addEventListener('submit', this.handleManualSetup.bind(this));
        
        // Action buttons
        document.querySelectorAll('.action-btn').forEach(btn => {
            btn.addEventListener('click', this.executeAction.bind(this));
        });
    }
    
    async handleLazyUpload(e) {
        e.preventDefault();
        const formData = new FormData(e.target);
        
        try {
            this.showLoading('Uploading files...');
            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.updateState(result.state);
                this.showSuccess(result.message);
            } else {
                this.showError(result.message);
            }
        } catch (error) {
            this.showError('Upload failed: ' + error.message);
        } finally {
            this.hideLoading();
        }
    }
    
    async executeAction(e) {
        const action = e.target.dataset.action;
        
        try {
            const response = await fetch(`/api/action/${action}`, {
                method: 'POST'
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.showSuccess(`${action} started successfully`);
            } else {
                this.showError(result.message);
            }
        } catch (error) {
            this.showError('Action failed: ' + error.message);
        }
    }
    
    async updateStatus() {
        try {
            const response = await fetch('/api/status');
            const status = await response.json();
            
            this.updateUI(status);
        } catch (error) {
            console.error('Status update failed:', error);
        }
    }
    
    startStatusPolling() {
        this.statusInterval = setInterval(() => {
            this.updateStatus();
        }, 2000); // Poll every 2 seconds
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new AutomatoolUI();
});
```

## 🔮 **Future Enhancements**

### **Phase 2 Features**
1. **Real-time Logs**: WebSocket integration for live log streaming
2. **Process Control**: Ability to pause/resume/cancel running processes
3. **Multiple Sessions**: Support for concurrent analysis sessions
4. **Results Viewer**: Built-in viewer for analysis results and reports
5. **Configuration Profiles**: Save and load analysis configurations

### **Phase 3 Features**
1. **API Authentication**: JWT-based authentication system
2. **Multi-user Support**: User accounts and session management
3. **Cloud Integration**: Support for cloud storage and remote analysis
4. **Advanced Analytics**: Dashboard with analysis statistics and trends
5. **Plugin System**: Extensible architecture for custom analysis modules

## 📊 **Benefits & Advantages**

### **User Experience**
- **Simplified Workflow**: No command-line knowledge required
- **Visual Feedback**: Real-time progress and status updates
- **Error Prevention**: Input validation and helpful error messages
- **Accessibility**: Works on any device with a web browser

### **Developer Benefits**
- **Modular Architecture**: Clean separation of concerns
- **Extensible Design**: Easy to add new features and analysis tools
- **Maintainable Code**: Well-structured Flask application
- **Documentation**: Comprehensive API and component documentation

### **Operational Advantages**
- **Remote Access**: Access analysis tools from anywhere
- **Resource Management**: Better control over system resources
- **Audit Trail**: Complete log of all analysis activities
- **Scalability**: Easy to deploy on multiple servers or containers

This specification provides a complete blueprint for implementing a user-friendly web interface for the automatool project while maintaining all existing functionality and adding significant usability improvements.
