// static/js/main.js
class AutomatoolUI {
    constructor() {
        this.state = null;
        this.statusInterval = null;
        this.packageNameDetectionFailed = false;
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

        // Form submissions (if forms exist)
        const lazyForm = document.getElementById('lazy-form');
        if (lazyForm) {
            lazyForm.addEventListener('submit', this.handleLazyUpload.bind(this));
        }

        const manualForm = document.getElementById('manual-form');
        if (manualForm) {
            manualForm.addEventListener('submit', this.handleManualSetup.bind(this));
        }

        // Action buttons
        document.querySelectorAll('.action-btn').forEach(btn => {
            btn.addEventListener('click', this.executeAction.bind(this));
        });

        // Process control buttons
        const stopBtn = document.getElementById('stop-process-btn');
        if (stopBtn) {
            stopBtn.addEventListener('click', this.stopProcess.bind(this));
        }

        const clearLogsBtn = document.getElementById('clear-logs-btn');
        if (clearLogsBtn) {
            clearLogsBtn.addEventListener('click', this.clearLogs.bind(this));
        }

        // NEW: VPN-Frida button bindings
        const startVPNFridaBtn = document.getElementById('start-vpn-frida');
        if (startVPNFridaBtn) {
            startVPNFridaBtn.addEventListener('click', this.startVPNFrida.bind(this));
            console.log('[DEBUG] ✅ Start VPN-Frida button bound');
        }

        const stopVPNFridaBtn = document.getElementById('stop-vpn-frida');
        if (stopVPNFridaBtn) {
            stopVPNFridaBtn.addEventListener('click', this.stopVPNFrida.bind(this));
            console.log('[DEBUG] ✅ Stop VPN-Frida button bound');
        }

        const changeCountryBtn = document.getElementById('change-country');
        if (changeCountryBtn) {
            changeCountryBtn.addEventListener('click', this.changeVPNCountry.bind(this));
            console.log('[DEBUG] ✅ Change Country button bound');
        }

        // Gemini-specific event bindings
        this.bindGeminiEvents();
    }

    bindGeminiEvents() {
        // Only bind events if we're on the Gemini page
        const promptSelection = document.getElementById('prompt-selection');
        const customPrompt = document.getElementById('custom-prompt');
        const outputDir = document.getElementById('output-dir');
        const launchBtn = document.getElementById('launch-gemini');
        const clearBtn = document.getElementById('clear-form');

        if (!promptSelection) return; // Not on Gemini page

        // Prompt selection change handler
        promptSelection.addEventListener('change', this.handlePromptSelection.bind(this));
        
        // Input validation handlers
        if (customPrompt) {
            customPrompt.addEventListener('input', this.validateGeminiForm.bind(this));
        }
        if (outputDir) {
            outputDir.addEventListener('input', this.validateGeminiForm.bind(this));
        }

        // Button handlers
        if (launchBtn) {
            launchBtn.addEventListener('click', this.launchGeminiAnalysis.bind(this));
        }
        if (clearBtn) {
            clearBtn.addEventListener('click', this.clearGeminiForm.bind(this));
        }

        // Initial form validation
        this.validateGeminiForm();
        
        console.log('[DEBUG] ✅ Gemini events bound successfully');
    }

    toggleMode(e) {
        console.log('toggleMode called');
        const mode = e.target.value;
        console.log('Mode:', mode);
        const lazyPanel = document.getElementById('lazy-panel');
        const manualPanel = document.getElementById('manual-panel');

        if (mode === 'lazy') {
            lazyPanel.style.display = 'block';
            manualPanel.style.display = 'none';
        } else {
            lazyPanel.style.display = 'none';
            manualPanel.style.display = 'block';
        }
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
                this.showMessage('success', result.message);
            } else {
                this.showMessage('error', result.message);
            }
        } catch (error) {
            this.showMessage('error', 'Upload failed: ' + error.message);
        } finally {
            this.hideLoading();
        }
    }

    async handleManualSetup(e) {
        e.preventDefault();
        const formData = new FormData(e.target);
        const data = {
            directory_path: formData.get('directory_path'),
            apk_filename: formData.get('apk_filename')
        };

        try {
            this.showLoading('Setting up manual configuration...');
            const response = await fetch('/api/manual-setup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });

            const result = await response.json();

            if (result.success) {
                this.updateState(result.state);
                this.showMessage('success', result.message);
            } else {
                this.showMessage('error', result.message);
            }
        } catch (error) {
            this.showMessage('error', 'Manual setup failed: ' + error.message);
        } finally {
            this.hideLoading();
        }
    }

    async executeAction(e) {
        const action = e.target.dataset.action;

        try {
            // Prepare request body with configuration for specific actions
            let requestBody = {};
            
            if (action === 'image-steganography-analysis') {
                // Show configuration panel and get threshold value
                this.showImageStegoConfig(true);
                const threshold = parseInt(document.getElementById('stego-threshold').value) || 10;
                requestBody = { threshold_bytes: threshold };
            }

            this.showLoading(`Starting ${action}...`);
            const response = await fetch(`/api/action/${action}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(requestBody)
            });

            const result = await response.json();

            if (result.success) {
                this.showMessage('success', `${action} completed successfully`);
                
                // Special handling for different actions
                if (action === 'native-strings-analysis') {
                    this.updateStatus('Native strings analysis started...');
                } else if (action === 'scan-base64') {
                    // Show success message with file output info
                    this.showBase64SuccessMessage(result);
                } else if (action === 'font-analysis') {
                    this.updateStatus('TTF font analysis started...');
                } else if (action === 'image-steganography-analysis') {
                    this.updateStatus('Image steganography analysis started...');
                    this.showImageStegoConfig(false); // Hide config panel after starting
                }
            } else {
                this.showMessage('error', result.message);
            }
        } catch (error) {
            this.showMessage('error', 'Action failed: ' + error.message);
        } finally {
            this.hideLoading();
        }
    }

    async updateStatus() {
        try {
            const response = await fetch('/api/status');
            const status = await response.json();

            this.updateUI(status);

            // NEW: Update VPN-Frida section when APK is uploaded
            if (status.state && status.state.APK_FILENAME && status.state.setup_complete) {
                console.log('[DEBUG] 🔍 APK uploaded, checking for package name...');
                await this.updatePackageNameFromAPK(status.state);
            }

        } catch (error) {
            console.error('Status update failed:', error);
        }
    }

    updateUI(status) {
        // Update status display
        const statusDisplay = document.getElementById('status-display');
        if (statusDisplay) {
            statusDisplay.textContent = status.status || 'Ready';
        }

        // Update log display
        const logDisplay = document.getElementById('log-display');
        if (logDisplay && status.log) {
            logDisplay.textContent = status.log.join('');
            logDisplay.scrollTop = logDisplay.scrollHeight;
        }

        // Update state display
        if (status.state) {
            this.updateState(status.state);
        }

        // Update process control buttons
        this.updateProcessControls(status);
    }

    updateProcessControls(status) {
        const stopBtn = document.getElementById('stop-process-btn');
        const actionBtns = document.querySelectorAll('.action-btn');

        if (status.status === 'running') {
            // Show stop button when process is running
            if (stopBtn) {
                stopBtn.style.display = 'inline-flex';
            }

            // Disable action buttons when process is running
            actionBtns.forEach(btn => {
                btn.disabled = true;
            });
        } else {
            // Hide stop button when no process is running
            if (stopBtn) {
                stopBtn.style.display = 'none';
            }

            // Re-enable action buttons based on setup status
            actionBtns.forEach(btn => {
                if (btn.dataset.action === 'clean') {
                    btn.disabled = false; // Clean can always run
                } else {
                    btn.disabled = !this.state?.setup_complete;
                }
            });
        }
    }

    updateState(state) {
        this.state = state;

        // Update display elements
        const apkFilenameDisplay = document.getElementById('apk-filename-display');
        if (apkFilenameDisplay) {
            apkFilenameDisplay.textContent = state.APK_FILENAME || 'Not set';
        }

        const outputDirDisplay = document.getElementById('output-dir-display');
        if (outputDirDisplay) {
            outputDirDisplay.textContent = state.OUTPUT_DIR || 'Not set';
        }

        const apkPathDisplay = document.getElementById('apk-path-display');
        if (apkPathDisplay) {
            apkPathDisplay.textContent = state.APK_PATH || 'Not set';
        }

        // Enable/disable action buttons based on setup completion
        document.querySelectorAll('.action-btn').forEach(btn => {
            if (btn.dataset.action !== 'clean') {
                btn.disabled = !state.setup_complete;
            }
        });
    }

    showMessage(type, message) {
        const messageArea = document.getElementById('message-area');
        if (!messageArea) return;

        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}`;
        messageDiv.textContent = message;

        messageArea.appendChild(messageDiv);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (messageDiv.parentNode) {
                messageDiv.parentNode.removeChild(messageDiv);
            }
        }, 5000);
    }

    showLoading(message) {
        this.showMessage('warning', message);
    }

    hideLoading() {
        // Loading is handled by auto-removal of messages
    }

    showImageStegoConfig(show = true) {
        const configDiv = document.getElementById('image-stego-config');
        if (configDiv) {
            configDiv.style.display = show ? 'block' : 'none';
        }
    }

    async stopProcess() {
        try {
            this.showLoading('Stopping process...');
            const response = await fetch('/api/action/stop', {
                method: 'POST'
            });

            const result = await response.json();

            if (result.success) {
                this.showMessage('success', result.message);
            } else {
                this.showMessage('error', result.message);
            }
        } catch (error) {
            this.showMessage('error', 'Failed to stop process: ' + error.message);
        } finally {
            this.hideLoading();
        }
    }

    async clearLogs() {
        try {
            const response = await fetch('/api/logs/clear', {
                method: 'POST'
            });

            const result = await response.json();

            if (result.success) {
                this.showMessage('success', result.message);
                // Update status to refresh logs
                await this.updateStatus();
            } else {
                this.showMessage('error', result.message);
            }
        } catch (error) {
            this.showMessage('error', 'Failed to clear logs: ' + error.message);
        }
    }

    startStatusPolling() {
        this.statusInterval = setInterval(() => {
            this.updateStatus();
        }, 5000); // Poll every 2 seconds
    }

    // NEW: VPN-Frida Methods

    async updatePackageNameFromAPK(state) {
        if (this.packageNameDetectionFailed) {
            return;
        }
        try {
            console.log('[DEBUG] 🚀 Starting package name detection...');
            const packageInput = document.getElementById('package-name');

            if (!packageInput) {
                console.log('[DEBUG] ❌ Package name input not found in DOM');
                return;
            }

            // Skip if package already detected
            if (packageInput.value && packageInput.value !== 'Upload an APK file first...') {
                console.log('[DEBUG] ✅ Package already detected, skipping...');
                return;
            }

            console.log('[DEBUG] 📤 Calling /api/get-package-name with APK path:', state.APK_PATH);

            const response = await fetch('/api/get-package-name', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    apk_path: state.APK_PATH
                })
            });

            console.log('[DEBUG] 📥 Response received:', response.status);
            const result = await response.json();
            console.log('[DEBUG] 📦 Response data:', result);

            if (result.success && result.package_name) {
                console.log('[DEBUG] ✅ Package name detected:', result.package_name);

                // Update package name field
                packageInput.value = result.package_name;

                // Enable start button
                const startBtn = document.getElementById('start-vpn-frida');
                if (startBtn) {
                    startBtn.disabled = false;
                    console.log('[DEBUG] ✅ Start button enabled');
                }

                // Update status
                const statusText = document.getElementById('status-text');
                const currentApp = document.getElementById('current-app');

                if (statusText) statusText.textContent = 'Ready - Package detected!';
                if (currentApp) currentApp.textContent = result.package_name;

                this.showMessage('success', `Package detected: ${result.package_name}`);
            } else {
                console.log('[DEBUG] ❌ Package detection failed:', result.message);
                this.showMessage('error', `Package detection failed: ${result.message}`);
                this.packageNameDetectionFailed = true;
            }

        } catch (error) {
            console.error('[DEBUG] 💥 Error in updatePackageNameFromAPK:', error);
            this.showMessage('error', `Failed to detect package: ${error.message}`);
            this.packageNameDetectionFailed = true;
        }
    }

    async startVPNFrida() {
        console.log('[DEBUG] 🚀 Starting VPN-Frida automation...');
        const packageName = document.getElementById('package-name').value;
        const country = document.getElementById('vpn-country').value;

        console.log('[DEBUG] 📦 Package name:', packageName);
        console.log('[DEBUG] 🌍 Country:', country);

        // Validation
        if (!packageName || packageName === 'Upload an APK file first...') {
            this.showMessage('error', 'No package detected. Please upload an APK file first.');
            return;
        }

        if (!country) {
            this.showMessage('error', 'Please select a VPN country.');
            return;
        }

        try {
            console.log('[DEBUG] 📤 Calling /api/start-vpn-frida...');
            const response = await fetch('/api/start-vpn-frida', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    package: packageName,
                    country: country
                })
            });

            const result = await response.json();
            console.log('[DEBUG] 📥 Start response:', result);

            if (result.success) {
                // Update UI for running state
                this.setVPNFridaUIState('running');

                // Update status display
                const statusText = document.getElementById('status-text');
                const currentCountry = document.getElementById('current-country');

                if (statusText) statusText.textContent = 'Starting...';
                if (currentCountry) currentCountry.textContent = country;

                this.showMessage('success', result.message);
            } else {
                this.showMessage('error', result.message);
            }

        } catch (error) {
            console.error('[DEBUG] 💥 Error starting VPN-Frida:', error);
            this.showMessage('error', `Error: ${error.message}`);
        }
    }

    async stopVPNFrida() {
        console.log('[DEBUG] ⏹️ Stopping VPN-Frida automation...');
        try {
            const response = await fetch('/api/stop-vpn-frida', {
                method: 'POST'
            });

            const result = await response.json();
            console.log('[DEBUG] 📥 Stop response:', result);

            if (result.success) {
                this.setVPNFridaUIState('ready');

                const statusText = document.getElementById('status-text');
                const runtime = document.getElementById('runtime');

                if (statusText) statusText.textContent = 'Stopped';
                if (runtime) runtime.textContent = '0s';

                this.showMessage('success', 'VPN-Frida automation stopped');
            } else {
                this.showMessage('error', result.message);
            }

        } catch (error) {
            console.error('[DEBUG] 💥 Error stopping VPN-Frida:', error);
            this.showMessage('error', `Error: ${error.message}`);
        }
    }

    async changeVPNCountry() {
        console.log('[DEBUG] 🔄 Changing VPN country...');
        const newCountry = document.getElementById('vpn-country').value;

        if (!newCountry) {
            this.showMessage('error', 'Please select a new country.');
            return;
        }

        try {
            console.log('[DEBUG] 📤 Calling /api/change-vpn-country...');
            const response = await fetch('/api/change-vpn-country', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ country: newCountry })
            });

            const result = await response.json();
            console.log('[DEBUG] 📥 Change country response:', result);

            if (result.success) {
                const statusText = document.getElementById('status-text');
                const currentCountry = document.getElementById('current-country');

                if (statusText) statusText.textContent = 'Changing country...';
                if (currentCountry) currentCountry.textContent = newCountry;

                this.showMessage('success', result.message);
            } else {
                this.showMessage('error', result.message);
            }

        } catch (error) {
            console.error('[DEBUG] 💥 Error changing country:', error);
            this.showMessage('error', `Error: ${error.message}`);
        }
    }

    setVPNFridaUIState(state) {
        console.log('[DEBUG] 🎛️ Setting VPN-Frida UI state:', state);
        const startBtn = document.getElementById('start-vpn-frida');
        const stopBtn = document.getElementById('stop-vpn-frida');
        const changeBtn = document.getElementById('change-country');

        if (state === 'running') {
            if (startBtn) startBtn.disabled = true;
            if (stopBtn) stopBtn.disabled = false;
            if (changeBtn) changeBtn.disabled = false;
            console.log('[DEBUG] ✅ UI set to running state');
        } else { // 'ready'
            const packageName = document.getElementById('package-name').value;
            if (startBtn) {
                startBtn.disabled = !packageName || packageName === 'Upload an APK file first...';
            }
            if (stopBtn) stopBtn.disabled = true;
            if (changeBtn) changeBtn.disabled = true;
            console.log('[DEBUG] ✅ UI set to ready state');
        }
    }

    showBase64SuccessMessage(result) {
        console.log('[DEBUG] 🔍 Base64 scan completed:', result);
        
        // Show success message with summary
        const summary = result.summary || {};
        const outputFiles = result.output_files || {};
        
        let message = 'Base64 scan completed successfully!\n\n';
        message += `📊 Scan Summary:\n`;
        message += `• Files Scanned: ${summary.files_scanned || 0}\n`;
        message += `• Strings Found: ${summary.strings_found || 0}\n`;
        message += `• Files with Strings: ${summary.files_with_strings || 0}\n\n`;
        
        if (outputFiles.json_results && outputFiles.text_summary) {
            message += `📁 Results saved to:\n`;
            message += `• ${outputFiles.json_results}\n`;
            message += `• ${outputFiles.text_summary}\n\n`;
            message += `Check your output directory for detailed results.`;
        }
        
        this.showMessage('success', message);
    }

    // Gemini-specific methods
    handlePromptSelection(e) {
        const selectedValue = e.target.value;
        const customPrompt = document.getElementById('custom-prompt');
        
        if (selectedValue === 'custom') {
            // Show custom prompt field for editing
            customPrompt.style.display = 'block';
            customPrompt.focus();
        } else if (selectedValue) {
            // For predefined prompts, you can add logic here to populate with actual prompt text
            // For now, just show the selection and hide custom prompt if it was visible
            customPrompt.style.display = 'block';
            customPrompt.placeholder = `Selected: ${e.target.selectedOptions[0].text}`;
        }
        
        this.validateGeminiForm();
    }

    validateGeminiForm() {
        const promptSelection = document.getElementById('prompt-selection');
        const customPrompt = document.getElementById('custom-prompt');
        const outputDir = document.getElementById('output-dir');
        const launchBtn = document.getElementById('launch-gemini');

        if (!launchBtn) return;

        const hasPrompt = promptSelection.value || (customPrompt && customPrompt.value.trim());
        const hasOutputDir = outputDir && outputDir.value.trim();

        // Enable launch button only if both conditions are met
        launchBtn.disabled = !(hasPrompt && hasOutputDir);
        
        if (launchBtn.disabled) {
            launchBtn.title = "Please select a prompt and specify output directory";
        } else {
            launchBtn.title = "";
        }
    }

    async launchGeminiAnalysis(e) {
        e.preventDefault();
        
        const promptSelection = document.getElementById('prompt-selection');
        const customPrompt = document.getElementById('custom-prompt');
        const outputDir = document.getElementById('output-dir');
        
        // Determine the prompt to use
        let prompt = '';
        if (promptSelection.value === 'custom' || !promptSelection.value) {
            prompt = customPrompt.value.trim();
        } else {
            // For predefined prompts, you would map the selection to actual prompt text
            // For now, use a placeholder that indicates which option was selected
            prompt = `Predefined prompt: ${promptSelection.value}`;
        }

        const outputDirectory = outputDir.value.trim();

        if (!prompt) {
            this.showGeminiError('Please enter a prompt or select a predefined option');
            return;
        }

        if (!outputDirectory) {
            this.showGeminiError('Please specify an output directory');
            return;
        }

        try {
            // Show loading state
            this.showGeminiStatus('🤖 Launching Gemini analysis...', 'loading');
            
            // Disable the launch button during processing
            const launchBtn = document.getElementById('launch-gemini');
            launchBtn.disabled = true;
            
            console.log('[DEBUG] 🤖 Starting Gemini analysis...');
            console.log('[DEBUG] Prompt:', prompt);
            console.log('[DEBUG] Output Directory:', outputDirectory);

            const response = await fetch('/api/gemini/prompt', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    prompt: prompt,
                    output_directory: outputDirectory,
                    verbose: true
                })
            });

            const result = await response.json();

            if (result.success) {
                this.showGeminiSuccess(result.message, result.result_file, result.execution_time);
                console.log('[DEBUG] ✅ Gemini analysis completed successfully');
            } else {
                this.showGeminiError(result.error, result.details);
                console.log('[DEBUG] ❌ Gemini analysis failed:', result.error);
            }

        } catch (error) {
            this.showGeminiError('Network error: ' + error.message);
            console.error('[ERROR] 🤖 Gemini analysis network error:', error);
        } finally {
            // Re-enable the launch button
            const launchBtn = document.getElementById('launch-gemini');
            launchBtn.disabled = false;
            this.validateGeminiForm(); // Re-validate to ensure proper state
        }
    }

    clearGeminiForm() {
        const promptSelection = document.getElementById('prompt-selection');
        const customPrompt = document.getElementById('custom-prompt');
        
        if (promptSelection) promptSelection.value = '';
        if (customPrompt) {
            customPrompt.value = '';
            customPrompt.placeholder = 'Enter your custom analysis prompt here...';
        }
        // Note: We don't clear output-dir as it's often reused
        
        this.hideGeminiPanels();
        this.validateGeminiForm();
        
        console.log('[DEBUG] 🗑️ Gemini form cleared');
    }

    showGeminiStatus(message, type = 'loading') {
        const statusPanel = document.getElementById('status-display');
        const statusText = statusPanel.querySelector('.status-text');
        const statusIcon = statusPanel.querySelector('.status-icon');
        
        if (statusPanel && statusText && statusIcon) {
            statusText.textContent = message;
            statusIcon.textContent = type === 'loading' ? '⏳' : '🤖';
            statusPanel.style.display = 'block';
        }
        
        this.hideGeminiPanels(['status']);
    }

    showGeminiSuccess(message, resultFile, executionTime) {
        const resultsPanel = document.getElementById('results-display');
        const resultContent = document.getElementById('result-content');
        const resultFilename = document.getElementById('result-filename');
        
        if (resultsPanel) {
            resultsPanel.style.display = 'block';
            
            if (resultFilename) {
                resultFilename.textContent = resultFile.split('/').pop() || 'result.txt';
            }
            
            if (resultContent) {
                resultContent.textContent = `Analysis completed successfully!\n\nFile: ${resultFile}\nExecution Time: ${executionTime}\n\n${message}`;
            }
        }
        
        this.hideGeminiPanels(['results']);
    }

    showGeminiError(error, details = null) {
        const errorPanel = document.getElementById('error-display');
        const errorText = document.getElementById('error-text');
        const errorDetails = document.getElementById('error-details');
        
        if (errorPanel && errorText) {
            errorText.textContent = error;
            errorPanel.style.display = 'block';
            
            if (errorDetails && details) {
                errorDetails.textContent = details;
                errorDetails.style.display = 'block';
            } else if (errorDetails) {
                errorDetails.style.display = 'none';
            }
        }
        
        this.hideGeminiPanels(['error']);
    }

    hideGeminiPanels(except = []) {
        const panels = ['status-display', 'results-display', 'error-display'];
        
        panels.forEach(panelId => {
            if (!except.includes(panelId.replace('-display', ''))) {
                const panel = document.getElementById(panelId);
                if (panel) {
                    panel.style.display = 'none';
                }
            }
        });
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new AutomatoolUI();
});
