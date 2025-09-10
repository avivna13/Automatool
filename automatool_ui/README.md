# Automatool UI

The web interface for the Automatool project provides a user-friendly platform for APK analysis and automation management. It offers drag-and-drop file uploads, one-click analysis execution, and comprehensive process management through a modern web interface.

## 🏗️ Architecture Overview

The AutomatoolUI follows a modular Flask-based architecture with clear separation of concerns:

```
automatool_ui/
├── app.py                    # Main Flask application and API endpoints
├── config.py                 # Configuration management
├── utils/
│   ├── process_manager.py    # Process execution and management
│   ├── file_handler.py       # File operations and validation
│   └── path_validator.py     # Path sanitization and validation
├── templates/
│   ├── base.html            # Base template with common layout
│   ├── index.html           # Main UI interface
│   ├── gemini.html          # AI analysis interface
│   └── monitoring_dashboard.html # Real-time monitoring
├── static/
│   ├── css/
│   │   └── style.css        # Application styling
│   ├── js/
│   │   └── main.js          # Frontend JavaScript logic
│   └── uploads/             # Temporary file storage
├── tests/                   # Unit and integration tests
└── specs/                   # Documentation and specifications
```

### Core Components

- **Flask Application (`app.py`)**: Handles HTTP requests, API endpoints, and application state management
- **Process Manager (`utils/process_manager.py`)**: Manages automation script execution, process monitoring, and resource cleanup
- **Frontend (`static/js/main.js`)**: Provides interactive UI, AJAX communication, and real-time status updates
- **Templates**: Jinja2 templates for server-side rendering with Bootstrap styling

### Integration Flow

1. **Frontend**: User interaction → JavaScript event → API call
2. **Backend**: API endpoint → Process Manager → Automation script
3. **Execution**: Standalone script → Process monitoring → Result handling
4. **Feedback**: Process status → API response → UI update

## 🚀 Features

- **Drag-and-Drop APK Upload**: Intuitive file handling with validation
- **One-Click Analysis**: Execute complex automation workflows with single button clicks
- **Real-Time Monitoring**: Live process status updates and progress tracking
- **MobSF Integration**: Containerized static/dynamic analysis with Docker
- **Gemini AI Integration**: Context-aware AI analysis of collected intelligence
- **Toll Fraud Monitoring**: Real-time SMS/call monitoring dashboard
- **Process Management**: Track, monitor, and manage running analysis tasks
- **Comprehensive Results**: Organized output with downloadable reports

## 🔧 Adding New Automations

The AutomatoolUI is designed for easy integration of new automation scripts. Follow this streamlined process to add your automation to the web interface.

### Quick Integration Steps

1. **Prepare Your Script** - Ensure your automation supports standalone execution with command-line arguments
2. **Backend Integration** - Add process manager method and API handler
3. **Frontend Integration** - Add UI button and optional configuration
4. **Testing** - Validate the complete integration flow

### 1. Script Requirements

Your automation script must be located in `automatool/automatool/src/scripts/automations/` and support:

```python
#!/usr/bin/env python3
import argparse
import sys
import os

def your_automation_function(input_path, output_dir, verbose=False):
    """Main automation logic."""
    # Your implementation here
    pass

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Your automation description")
    parser.add_argument("input_path", help="Path to input file/directory")
    parser.add_argument("output_dir", help="Path to output directory")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

def main():
    """Main entry point for standalone execution."""
    args = parse_arguments()
    
    # Validate inputs
    if not os.path.exists(args.input_path):
        print(f"❌ ERROR: Input not found: {args.input_path}")
        sys.exit(1)
    
    try:
        result = your_automation_function(args.input_path, args.output_dir, args.verbose)
        print(f"✅ Automation completed: {result}")
    except Exception as e:
        print(f"❌ ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### 2. Backend Integration

#### Add Process Manager Method (`utils/process_manager.py`):
```python
def execute_your_automation(self, input_path, output_dir, verbose=True):
    """Execute your automation with specified options."""
    script_path = os.path.join("scripts", "automations", "your_script.py")
    cmd = ['python', script_path, input_path, output_dir]
    
    if verbose:
        cmd.append('--verbose')
    
    return self._run_process(cmd, "Your Automation Name", self.automatool_path, timeout=self.default_timeout)
```

#### Add API Handler (`app.py`):
```python
# Add to valid_actions list:
valid_actions = [..., 'your-automation-name']

# Add route mapping:
elif action_name == 'your-automation-name':
    return handle_your_automation()

# Add handler function:
def handle_your_automation():
    """Handle your automation execution."""
    try:
        if not app_state.get('setup_complete') or not app_state.get('APK_PATH') or not app_state.get('OUTPUT_DIR'):
            return jsonify({
                'success': False,
                'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
            })
        
        success = process_manager.execute_your_automation(
            app_state['APK_PATH'],
            app_state['OUTPUT_DIR'],
            verbose=True
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Your automation started successfully',
                'action': 'your-automation-name'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to start your automation'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Your automation failed: {str(e)}'
        })
```

### 3. Frontend Integration

#### Add UI Button (`templates/index.html`):
```html
<button class="btn btn-primary action-btn" data-action="your-automation-name"
        {% if not state.setup_complete %}disabled{% endif %}>
    🔧 Your Automation Name
</button>
```

The existing JavaScript in `static/js/main.js` automatically handles buttons with the `action-btn` class.

### 4. Testing Your Integration

1. **Test Standalone Script**:
   ```bash
   cd automatool/automatool/src
   python scripts/automations/your_script.py /test/input /test/output --verbose
   ```

2. **Test Web Interface**:
   - Start the UI: `python app.py`
   - Upload test APK or configure manual setup
   - Click your automation button
   - Verify process starts and completes

3. **Test API Directly**:
   ```bash
   curl -X POST http://localhost:5000/api/action/your-automation-name \
        -H "Content-Type: application/json"
   ```

### Best Practices

- **Naming**: Use kebab-case for action names (`your-automation-name`)
- **Error Handling**: Provide clear success/error messages
- **Validation**: Always validate inputs and prerequisites
- **Feedback**: Use descriptive process names and verbose output
- **Testing**: Test both standalone and web integration thoroughly

### Complete Example

See `specs/NEW_AUTOMATION_INTEGRATION_GUIDE.md` for a comprehensive step-by-step guide with complete code examples, advanced features, troubleshooting, and best practices.

## MobSF Analysis Setup

Running the MobSF analysis requires Docker. By default, Docker commands need to be run with `sudo`, which can cause issues when triggering the analysis from a web application. This document explains how to configure your system to allow the Automatool UI to run MobSF analysis.

### The Problem

When the MobSF analysis is started from the web UI, it needs to run Docker commands to start the MobSF container. If the user running the web application does not have permission to run Docker commands, the analysis will fail with a "permission denied" error.

### The Solution

There are two ways to solve this problem. Choose the one that best suits your security needs.

#### Option 1: Add Your User to the `docker` Group (Recommended)

This is the simplest and most common way to grant a user permission to run Docker commands.

**1. Add your user to the `docker` group:**

Open a terminal and run the following command:

```bash
sudo usermod -aG docker $USER
```

**2. Log out and log back in:**

This is a crucial step. You must log out of your system and then log back in for the group membership change to take effect.

**Security Note:** Adding a user to the `docker` group gives them root-equivalent permissions on the host system. Be aware of the security implications of this choice.

#### Option 2: Configure Passwordless `sudo` for Docker (Advanced)

This method is more secure because it allows you to grant passwordless `sudo` access only for the `docker` command, without giving the user full root-equivalent permissions.

**1. Open the `sudoers` file for editing:**

Use the `visudo` command to safely edit the `/etc/sudoers` file.

```bash
sudo visudo
```

**2. Add the `NOPASSWD` rule:**

Scroll to the bottom of the file and add the following line. Replace `kali` with your username if it's different.

```
kali ALL=(ALL) NOPASSWD: /usr/bin/docker
```

**3. Save and exit the file.**

After making this change, the web application will be able to run `sudo docker` commands without a password prompt.

### Port Configuration

By default, the MobSF container is configured to run on port `8080`. If you need to change this, you can edit the `utils/process_manager.py` file.

In the `execute_mobsf_upload` function, you will find the `--port` argument. You can change the value of this argument to the desired port.

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Flask and dependencies (see `requirements.txt`)
- Docker (for MobSF analysis)
- Access to the main `automatool` directory for script execution

### Installation

1. **Install Dependencies**:
   ```bash
   cd automatool_ui
   pip install -r requirements.txt
   ```

2. **Configure Docker** (if using MobSF):
   - Follow the MobSF Analysis Setup section above
   - Ensure Docker is running and accessible

3. **Start the Application**:
   ```bash
   python app.py
   ```

4. **Access the Interface**:
   - Open your browser to `http://localhost:5000`
   - Upload an APK file or configure manual setup
   - Start running your automations!

### Development

#### Running Tests
```bash
# Run all tests
python -m pytest tests/

# Run specific test file
python -m pytest tests/test_integration.py

# Run with coverage
python -m pytest tests/ --cov=utils --cov-report=html
```

#### Project Structure for Developers

- **`app.py`**: Main Flask application - add new API endpoints here
- **`utils/process_manager.py`**: Core automation execution - add new automation methods here
- **`templates/index.html`**: Main UI - add new buttons and interface elements here
- **`static/js/main.js`**: Frontend logic - add custom JavaScript behavior here
- **`tests/`**: Unit and integration tests - add tests for new features here
- **`specs/`**: Documentation and specifications - add documentation for new features here

#### Adding New Features

1. **Create Specification**: Document your feature in `specs/`
2. **Implement Backend**: Add process manager methods and API handlers
3. **Implement Frontend**: Add UI elements and JavaScript handling
4. **Add Tests**: Create comprehensive test coverage
5. **Update Documentation**: Update README and relevant specs

### Troubleshooting

#### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Setup not complete" | No APK uploaded | Upload APK or configure manual setup |
| "Permission denied" Docker | User not in docker group | Follow MobSF setup instructions |
| Process timeout | Long-running automation | Increase timeout in process_manager.py |
| Import errors | Missing dependencies | Check requirements.txt and Python path |

#### Debug Mode

Enable debug mode for development:
```bash
export FLASK_ENV=development
python app.py
```

This enables:
- Auto-reload on code changes
- Detailed error messages
- Debug toolbar
- Verbose logging

### Contributing

1. Fork the repository
2. Create a feature branch
3. Add comprehensive tests
4. Update documentation
5. Submit a pull request

For detailed integration guidance, see `specs/NEW_AUTOMATION_INTEGRATION_GUIDE.md`.
