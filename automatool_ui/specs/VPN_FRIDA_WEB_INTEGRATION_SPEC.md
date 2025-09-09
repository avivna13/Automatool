# 🌐 VPN-Frida Web Integration Specification

## **Overview**
Integrate the standalone VPN-Frida automation into the `automatool_ui` web interface as a new section that automatically detects package names from uploaded APK files and provides an intuitive interface for VPN-controlled Frida script execution.

## **Goals**
- **Seamless Integration**: Connect VPN-Frida automation with existing APK upload workflow
- **Auto-Detection**: Automatically extract package names from uploaded APK files
- **Simple Interface**: One-click VPN region switching and Frida execution
- **Real-time Control**: Live status updates and region switching capabilities

## **User Workflow**

### **Simple 4-Step Process:**
1. **Upload APK** → User uploads APK file (existing functionality)
2. **Package Auto-Detected** → System extracts package name automatically
3. **Select Country** → User picks VPN country from dropdown
4. **Start Automation** → Click button to run VPN-Frida automation

### **Advanced Features:**
- **Region Switching**: Change VPN country while Frida is running
- **Live Status**: Real-time updates on VPN connection and Frida execution
- **Process Control**: Start, stop, and monitor automation progress

## **Technical Implementation**

### **1. Frontend Changes (HTML)**

#### **File:** `automatool_ui/templates/index.html`
**Location:** Add after existing action panels

```html
<!-- VPN-Frida Automation Panel -->
<div class="panel" id="vpn-frida-panel">
    <h2>🌐 VPN-Frida Automation</h2>
    
    <!-- Package Detection Section -->
    <div class="form-group">
        <label for="package-name">📱 Detected Package Name:</label>
        <input type="text" id="package-name" readonly 
               placeholder="Upload an APK file first..." 
               class="form-control readonly-input">
        <small class="form-text">Package name will be auto-detected from uploaded APK</small>
    </div>
    
    <!-- Country Selection -->
    <div class="form-group">
        <label for="vpn-country">🌍 Choose VPN Country:</label>
        <select id="vpn-country" class="form-control">
            <option value="">Select a country...</option>
            <option value="us">🇺🇸 United States</option>
            <option value="germany">🇩🇪 Germany</option>
            <option value="japan">🇯🇵 Japan</option>
            <option value="uk">🇬🇧 United Kingdom</option>
            <option value="canada">🇨🇦 Canada</option>
            <option value="australia">🇦🇺 Australia</option>
        </select>
    </div>
    
    <!-- Control Buttons -->
    <div class="button-group">
        <button id="start-vpn-frida" class="btn btn-primary" disabled>
            🚀 Start VPN-Frida
        </button>
        <button id="stop-vpn-frida" class="btn btn-secondary" disabled>
            ⏹️ Stop
        </button>
        <button id="change-country" class="btn btn-info" disabled>
            🔄 Change Country
        </button>
    </div>
    
    <!-- Status Display -->
    <div class="status-panel" id="vpn-frida-status">
        <div class="status-item">
            <strong>Status:</strong> 
            <span id="status-text" class="status-value">Waiting for APK upload...</span>
        </div>
        <div class="status-item">
            <strong>Country:</strong> 
            <span id="current-country" class="status-value">None</span>
        </div>
        <div class="status-item">
            <strong>App:</strong> 
            <span id="current-app" class="status-value">None</span>
        </div>
        <div class="status-item">
            <strong>Runtime:</strong> 
            <span id="runtime" class="status-value">0s</span>
        </div>
    </div>
</div>
```

### **2. Frontend JavaScript Extensions**

#### **File:** `automatool_ui/static/js/main.js`
**Location:** Add to existing AutomatoolUI class

```javascript
class AutomatoolUI {
    constructor() {
        this.state = null;
        this.statusInterval = null;
        this.vpnFridaStartTime = null; // Track start time for runtime display
        this.init();
    }
    
    // Extend existing init method
    init() {
        this.bindEvents();
        this.bindVPNFridaEvents(); // NEW: Add VPN-Frida event bindings
        this.updateStatus();
        this.startStatusPolling();
    }
    
    // NEW: Bind VPN-Frida specific events
    bindVPNFridaEvents() {
        // Start VPN-Frida button
        const startBtn = document.getElementById('start-vpn-frida');
        if (startBtn) {
            startBtn.addEventListener('click', this.startVPNFrida.bind(this));
        }
        
        // Stop VPN-Frida button
        const stopBtn = document.getElementById('stop-vpn-frida');
        if (stopBtn) {
            stopBtn.addEventListener('click', this.stopVPNFrida.bind(this));
        }
        
        // Change country button
        const changeBtn = document.getElementById('change-country');
        if (changeBtn) {
            changeBtn.addEventListener('click', this.changeVPNCountry.bind(this));
        }
    }
    
    // Extend existing updateStatus method
    async updateStatus() {
        try {
            const response = await fetch('/api/status');
            const data = await response.json();
            
            // Update existing status displays (keep existing code)
            this.updateExistingStatus(data);
            
            // NEW: Update VPN-Frida section when APK is uploaded
            if (data.state && data.state.APK_FILENAME && data.state.setup_complete) {
                await this.updatePackageNameFromAPK(data.state);
            }
            
            // Update runtime counter if VPN-Frida is running
            this.updateVPNFridaRuntime();
            
        } catch (error) {
            console.error('Status update failed:', error);
        }
    }
    
    // NEW: Auto-detect package name from uploaded APK
    async updatePackageNameFromAPK(state) {
        try {
            const packageInput = document.getElementById('package-name');
            
            // Skip if package already detected
            if (packageInput.value && packageInput.value !== 'Upload an APK file first...') {
                return;
            }
            
            const response = await fetch('/api/get-package-name', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    apk_path: state.APK_PATH
                })
            });
            
            const result = await response.json();
            
            if (result.success && result.package_name) {
                // Update package name field
                packageInput.value = result.package_name;
                
                // Enable start button
                document.getElementById('start-vpn-frida').disabled = false;
                
                // Update status
                document.getElementById('status-text').textContent = 'Ready - Package detected!';
                document.getElementById('current-app').textContent = result.package_name;
                
                this.showMessage(`Package detected: ${result.package_name}`, 'success');
            }
            
        } catch (error) {
            console.error('Failed to get package name:', error);
        }
    }
    
    // NEW: Start VPN-Frida automation
    async startVPNFrida() {
        const packageName = document.getElementById('package-name').value;
        const country = document.getElementById('vpn-country').value;
        
        // Validation
        if (!packageName || packageName === 'Upload an APK file first...') {
            this.showMessage('No package detected. Please upload an APK file first.', 'error');
            return;
        }
        
        if (!country) {
            this.showMessage('Please select a VPN country.', 'error');
            return;
        }
        
        try {
            const response = await fetch('/api/start-vpn-frida', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    package: packageName,
                    country: country
                })
            });
            
            const result = await response.json();
            
            if (result.success) {
                // Update UI for running state
                this.setVPNFridaUIState('running');
                this.vpnFridaStartTime = Date.now();
                
                // Update status display
                document.getElementById('status-text').textContent = 'Starting...';
                document.getElementById('current-country').textContent = country;
                
                this.showMessage(result.message, 'success');
            } else {
                this.showMessage(result.message, 'error');
            }
            
        } catch (error) {
            this.showMessage(`Error: ${error.message}`, 'error');
        }
    }
    
    // NEW: Stop VPN-Frida automation
    async stopVPNFrida() {
        try {
            const response = await fetch('/api/stop-vpn-frida', {
                method: 'POST'
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.setVPNFridaUIState('ready');
                this.vpnFridaStartTime = null;
                
                document.getElementById('status-text').textContent = 'Stopped';
                document.getElementById('runtime').textContent = '0s';
                
                this.showMessage('VPN-Frida automation stopped', 'success');
            } else {
                this.showMessage(result.message, 'error');
            }
            
        } catch (error) {
            this.showMessage(`Error: ${error.message}`, 'error');
        }
    }
    
    // NEW: Change VPN country
    async changeVPNCountry() {
        const newCountry = document.getElementById('vpn-country').value;
        
        if (!newCountry) {
            this.showMessage('Please select a new country.', 'error');
            return;
        }
        
        try {
            const response = await fetch('/api/change-vpn-country', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ country: newCountry })
            });
            
            const result = await response.json();
            
            if (result.success) {
                document.getElementById('status-text').textContent = 'Changing country...';
                document.getElementById('current-country').textContent = newCountry;
                
                this.showMessage(result.message, 'success');
            } else {
                this.showMessage(result.message, 'error');
            }
            
        } catch (error) {
            this.showMessage(`Error: ${error.message}`, 'error');
        }
    }
    
    // NEW: Update UI state for VPN-Frida controls
    setVPNFridaUIState(state) {
        const startBtn = document.getElementById('start-vpn-frida');
        const stopBtn = document.getElementById('stop-vpn-frida');
        const changeBtn = document.getElementById('change-country');
        
        if (state === 'running') {
            startBtn.disabled = true;
            stopBtn.disabled = false;
            changeBtn.disabled = false;
        } else { // 'ready'
            const packageName = document.getElementById('package-name').value;
            startBtn.disabled = !packageName || packageName === 'Upload an APK file first...';
            stopBtn.disabled = true;
            changeBtn.disabled = true;
        }
    }
    
    // NEW: Update runtime counter
    updateVPNFridaRuntime() {
        if (this.vpnFridaStartTime) {
            const elapsed = Math.floor((Date.now() - this.vpnFridaStartTime) / 1000);
            document.getElementById('runtime').textContent = `${elapsed}s`;
        }
    }
}
```

### **3. Backend API Extensions**

#### **File:** `automatool_ui/app.py`
**Location:** Add new routes after existing API endpoints

```python
# VPN-Frida API Endpoints

@app.route('/api/get-package-name', methods=['POST'])
def get_package_name():
    """Extract package name from uploaded APK file."""
    try:
        data = request.get_json()
        apk_path = data.get('apk_path')
        
        if not apk_path or not os.path.exists(apk_path):
            return jsonify({
                'success': False,
                'message': 'APK file not found'
            })
        
        # Use existing automatool package extraction
        package_name = extract_package_name_from_automatool(apk_path)
        
        if package_name and package_name != "unknown":
            return jsonify({
                'success': True,
                'package_name': package_name,
                'message': f'Package detected: {package_name}'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Could not extract package name from APK'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error extracting package name: {str(e)}'
        })

@app.route('/api/start-vpn-frida', methods=['POST'])
def start_vpn_frida():
    """Start VPN-Frida automation."""
    try:
        data = request.get_json()
        package = data.get('package')
        country = data.get('country')
        
        # Validation
        if not package or not country:
            return jsonify({
                'success': False,
                'message': 'Package name and country are required'
            })
        
        # Check if another process is running
        if process_manager.is_running():
            return jsonify({
                'success': False,
                'message': 'Another process is already running. Please stop it first.'
            })
        
        # Start VPN-Frida automation
        success = process_manager.start_vpn_frida(package, country)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'VPN-Frida automation started for {package} in {country}'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to start VPN-Frida automation'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        })

@app.route('/api/stop-vpn-frida', methods=['POST'])
def stop_vpn_frida():
    """Stop VPN-Frida automation."""
    try:
        success = process_manager.stop_current_process()
        
        return jsonify({
            'success': success,
            'message': 'VPN-Frida automation stopped' if success else 'Nothing to stop'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        })

@app.route('/api/change-vpn-country', methods=['POST'])
def change_vpn_country():
    """Change VPN country during execution."""
    try:
        data = request.get_json()
        new_country = data.get('country')
        
        if not new_country:
            return jsonify({
                'success': False,
                'message': 'New country is required'
            })
        
        # For now, this is a placeholder - actual implementation would
        # communicate with the running VPN-Frida process to change regions
        success = process_manager.change_vpn_region(new_country)
        
        return jsonify({
            'success': success,
            'message': f'Changing VPN region to {new_country}' if success else 'Failed to change region'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        })

# Helper function for package name extraction
def extract_package_name_from_automatool(apk_path):
    """Extract package name using automatool's existing functionality."""
    try:
        # Import existing automatool function
        import sys
        automatool_src = os.path.join(os.path.dirname(__file__), '..', 'automatool', 'automatool', 'src')
        sys.path.insert(0, automatool_src)
        
        from scripts.utils.utils import extract_package_name_with_fallback
        
        # Use existing function
        package_name = extract_package_name_with_fallback(apk_path, verbose=False)
        
        return package_name if package_name != "unknown" else None
        
    except Exception as e:
        print(f"Error extracting package name: {e}")
        return None
```

### **4. Process Manager Extensions**

#### **File:** `automatool_ui/utils/process_manager.py`
**Location:** Add methods to existing ProcessManager class

```python
class ProcessManager:
    # ... existing methods ...
    
    def start_vpn_frida(self, package_name, country):
        """Start VPN-Frida automation using the standalone launcher."""
        try:
            # Path to VPN-Frida launcher script
            vpn_frida_script = os.path.join(
                self.automatool_path, 
                "scripts", "automations", 
                "launch_vpn_frida.py"
            )
            
            # Verify script exists
            if not os.path.exists(vpn_frida_script):
                self.add_log(f"VPN-Frida script not found: {vpn_frida_script}")
                return False
            
            # Build command
            cmd = [
                'python', vpn_frida_script,
                package_name,           # Android package name
                country,               # VPN country
                '--verbose'            # Enable verbose output
            ]
            
            self.add_log(f"Starting VPN-Frida: {package_name} in {country}")
            
            # Execute using existing process management
            return self._run_process(cmd, f"VPN-Frida: {package_name} ({country})")
            
        except Exception as e:
            self.add_log(f"Error starting VPN-Frida: {e}")
            return False
    
    def change_vpn_region(self, new_region):
        """Change VPN region for running process."""
        try:
            # This is a placeholder implementation
            # In practice, this would require IPC with the running VPN-Frida process
            # or using the VPN controller directly
            
            self.add_log(f"Region change requested: {new_region}")
            
            # For now, just log the request
            # Future implementation could:
            # 1. Use signal/IPC to communicate with running process
            # 2. Call VPN controller directly
            # 3. Restart process with new region
            
            return True
            
        except Exception as e:
            self.add_log(f"Error changing VPN region: {e}")
            return False
    
    def get_vpn_frida_status(self):
        """Get detailed status of VPN-Frida process."""
        try:
            base_status = self.get_status()
            
            # Add VPN-Frida specific status information
            vpn_frida_status = {
                'is_vpn_frida': self.current_process_name and 'VPN-Frida' in self.current_process_name,
                'base_status': base_status
            }
            
            return vpn_frida_status
            
        except Exception as e:
            return {'error': str(e)}
```

### **5. CSS Styling**

#### **File:** `automatool_ui/static/css/style.css`
**Location:** Add at the end of existing styles

```css
/* VPN-Frida Panel Styling */
#vpn-frida-panel {
    margin-top: 1rem;
}

#vpn-frida-panel .form-group {
    margin-bottom: 1rem;
}

#vpn-frida-panel .readonly-input {
    background-color: #f8f9fa;
    border: 1px solid #dee2e6;
    color: #6c757d;
}

#vpn-frida-panel .button-group {
    display: flex;
    gap: 0.5rem;
    margin: 1.5rem 0;
    flex-wrap: wrap;
}

#vpn-frida-panel .button-group button {
    flex: 1;
    min-width: 120px;
}

/* Status Panel */
.status-panel {
    background-color: #f8f9fa;
    border: 1px solid #dee2e6;
    border-radius: 6px;
    padding: 1rem;
    margin-top: 1rem;
}

.status-item {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.5rem;
    padding: 0.25rem 0;
}

.status-item:last-child {
    margin-bottom: 0;
}

.status-item strong {
    color: var(--secondary-color);
    min-width: 80px;
}

.status-value {
    color: var(--primary-color);
    font-weight: 500;
}

/* Country select styling */
#vpn-country {
    background-color: white;
    border: 1px solid #ced4da;
    border-radius: 4px;
    padding: 0.5rem;
}

#vpn-country:focus {
    border-color: var(--primary-color);
    box-shadow: 0 0 0 0.2rem rgba(37, 99, 235, 0.25);
}

/* Responsive design for mobile */
@media (max-width: 768px) {
    #vpn-frida-panel .button-group {
        flex-direction: column;
    }
    
    #vpn-frida-panel .button-group button {
        width: 100%;
    }
    
    .status-item {
        flex-direction: column;
        align-items: flex-start;
    }
    
    .status-item strong {
        margin-bottom: 0.25rem;
    }
}
```

## **Implementation Steps**

### **Phase 1: Basic Integration (Week 1)**
1. ✅ Add VPN-Frida panel HTML to `index.html`
2. ✅ Implement package name auto-detection API
3. ✅ Add basic start/stop functionality
4. ✅ Integrate with existing process management

### **Phase 2: Enhanced Features (Week 2)**
1. **Real-time Status Updates**
   - Live runtime counter
   - VPN connection status
   - Frida execution progress

2. **Region Switching**
   - Dynamic country change during execution
   - VPN status validation
   - Error handling for connection failures

### **Phase 3: Polish & Testing (Week 3)**
1. **UI/UX Improvements**
   - Loading indicators
   - Better error messaging
   - Responsive design testing

2. **Integration Testing**
   - End-to-end workflow testing
   - Cross-browser compatibility
   - Mobile device testing

## **API Endpoints Summary**

| Endpoint | Method | Purpose | Parameters |
|----------|--------|---------|------------|
| `/api/get-package-name` | POST | Extract package from APK | `apk_path` |
| `/api/start-vpn-frida` | POST | Start VPN-Frida automation | `package`, `country` |
| `/api/stop-vpn-frida` | POST | Stop automation | None |
| `/api/change-vpn-country` | POST | Change VPN region | `country` |

## **File Modifications Summary**

| File | Changes | Purpose |
|------|---------|---------|
| `templates/index.html` | Add VPN-Frida panel | User interface |
| `static/js/main.js` | Add VPN-Frida controls | Frontend logic |
| `static/css/style.css` | Add VPN-Frida styling | Visual design |
| `app.py` | Add 4 new API routes | Backend endpoints |
| `utils/process_manager.py` | Add VPN-Frida methods | Process management |

## **User Experience Flow**

### **Happy Path:**
1. **User uploads APK** → Package name auto-appears
2. **User selects country** → Dropdown selection
3. **User clicks "Start"** → Automation begins
4. **Status updates live** → Real-time feedback
5. **User can switch regions** → Dynamic country changing
6. **User stops when done** → Clean shutdown

### **Error Handling:**
- **No APK uploaded** → Start button disabled, clear message
- **Invalid package** → Error message with guidance
- **VPN connection fails** → Retry options and error details
- **Process conflicts** → Clear messaging about stopping current process

## **Benefits**

### **For Users:**
- ✅ **No command line needed** → Pure web interface
- ✅ **Auto-detection** → No manual package name entry
- ✅ **Real-time control** → Live status and region switching
- ✅ **Integrated workflow** → Works with existing APK analysis

### **For Developers:**
- ✅ **Reuses existing code** → Leverages automatool VPN-Frida automation
- ✅ **Consistent patterns** → Follows existing web UI architecture
- ✅ **Modular design** → Easy to extend and maintain
- ✅ **Comprehensive testing** → Built-in error handling and validation

This specification provides a complete roadmap for integrating VPN-Frida automation into the web interface while maintaining simplicity and following existing architectural patterns.
