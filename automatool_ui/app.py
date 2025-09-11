# app.py - Main Flask Application
from flask import Flask, render_template, request, jsonify
import os
import subprocess
from config import config
from utils.file_handler import FileHandler
from utils.path_validator import PathValidator
from utils.process_manager import ProcessManager

# Initialize Flask app
app = Flask(__name__)

# Load configuration
config_name = os.environ.get('FLASK_ENV') or 'development'
app.config.from_object(config[config_name])

# Initialize utilities
file_handler = FileHandler(upload_dir=app.config['UPLOAD_FOLDER'])
path_validator = PathValidator()
process_manager = ProcessManager()

# Import monitoring modules
import sys
import os
# Correct path to include the 'src' directory, not 'src/scripts'
automatool_src_path = os.path.join(os.path.dirname(__file__), '..', 'automatool', 'automatool', 'src')
if automatool_src_path not in sys.path:
    sys.path.append(automatool_src_path)

try:
    # Corrected imports to be relative to the 'src' directory
    from scripts.monitoring import NotificationMonitor, DataCollector
    from scripts.utils.adb_controller import ADBController
    from scripts.automations.launch_gemini_prompt import send_prompt_to_gemini
    monitoring_available = True
    gemini_available = True
except ImportError as e:
    print(f"Warning: Monitoring modules not available: {e}")
    monitoring_available = False
    gemini_available = False

# Global application state (as specified in the documentation)
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

@app.route('/monitoring')
def monitoring_dashboard():
    """Toll fraud monitoring dashboard."""
    return render_template('monitoring_dashboard.html', state=app_state)

@app.route('/gemini')
def gemini_analysis():
    """Gemini AI analysis page."""
    return render_template('gemini.html', state=app_state)

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current process status."""
    process_status = process_manager.get_status()
    
    return jsonify({
        'status': process_status['status'],
        'current_process': process_status['current_process'],
        'log': process_status['log'],
        'state': app_state
    })

@app.route('/api/upload', methods=['POST'])
def handle_upload():
    """Handle file uploads in lazy mode."""
    try:
        # Check if files are in request
        if 'apk_file' not in request.files:
            return jsonify({
                'success': False,
                'message': 'No APK file provided'
            })
        
        apk_file = request.files['apk_file']
        yara_file = request.files.get('yara_file')  # Optional
        
        # Validate APK file
        if apk_file.filename == '':
            return jsonify({
                'success': False,
                'message': 'No APK file selected'
            })
        
        # Create analysis directory
        output_dir = file_handler.create_analysis_directory()
        
        # Save APK file
        apk_path, apk_error = file_handler.validate_and_save_apk(apk_file, output_dir)
        if apk_error:
            return jsonify({
                'success': False,
                'message': f'APK upload failed: {apk_error}'
            })
        
        # Save YARA file if provided
        yara_path = None
        if yara_file and yara_file.filename:
            yara_path, yara_error = file_handler.validate_and_save_yara(yara_file, output_dir)
            if yara_error:
                return jsonify({
                    'success': False,
                    'message': f'YARA upload failed: {yara_error}'
                })
        
        # Update global state
        app_state['APK_FILENAME'] = os.path.basename(apk_path)
        app_state['OUTPUT_DIR'] = output_dir
        app_state['APK_PATH'] = apk_path
        app_state['YARA_PATH'] = yara_path
        app_state['setup_complete'] = True
        
        return jsonify({
            'success': True,
            'message': 'Files uploaded successfully',
            'state': app_state.copy()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Upload failed: {str(e)}'
        })

@app.route('/api/manual-setup', methods=['POST'])
def handle_manual_setup():
    """Handle manual path configuration."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'message': 'No data provided'
            })
        
        directory_path = data.get('directory_path', '').strip()
        apk_filename = data.get('apk_filename', '').strip()
        
        if not directory_path or not apk_filename:
            return jsonify({
                'success': False,
                'message': 'Both directory path and APK filename are required'
            })
        
        # Validate directory
        dir_valid, dir_result = path_validator.validate_directory(directory_path)
        if not dir_valid:
            return jsonify({
                'success': False,
                'message': dir_result
            })
        
        # Validate APK file
        apk_valid, apk_result = path_validator.validate_apk_file(directory_path, apk_filename)
        if not apk_valid:
            return jsonify({
                'success': False,
                'message': apk_result
            })
        
        # Update global state
        app_state['APK_FILENAME'] = apk_filename
        app_state['OUTPUT_DIR'] = dir_result
        app_state['APK_PATH'] = apk_result
        app_state['YARA_PATH'] = None  # Not provided in manual mode
        app_state['setup_complete'] = True
        
        return jsonify({
            'success': True,
            'message': 'Manual setup completed successfully',
            'state': app_state.copy()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Manual setup failed: {str(e)}'
        })

@app.route('/api/action/<action_name>', methods=['POST'])
def execute_action(action_name):
    """Execute analysis actions (full-process, get-reviews, clean, mobsf)."""
    try:
        # Check if another process is already running
        if process_manager.is_running():
            return jsonify({
                'success': False,
                'message': 'Another process is already running. Please wait for it to complete.'
            })
        
        # Validate action name
        valid_actions = ['full-process', 'get-reviews', 'clean', 'mobsf', 'native-strings-analysis', 'apkleaks', 'scan-base64', 'font-analysis', 'frida-fsmon-scan', 'manifest-analysis', 'decompile-apk', 'apk-unmask-analysis', 'blutter-analysis', 'image-steganography-analysis']
        if action_name not in valid_actions:
            return jsonify({
                'success': False,
                'message': f'Invalid action: {action_name}. Valid actions: {", ".join(valid_actions)}'
            })
        
        # Execute the appropriate action
        if action_name == 'full-process':
            return handle_full_process()
        elif action_name == 'get-reviews':
            return handle_get_reviews()
        elif action_name == 'clean':
            return handle_clean()
        elif action_name == 'mobsf':
            return handle_mobsf_upload()
        elif action_name == 'native-strings-analysis':
            return handle_strings_analysis()
        elif action_name == 'apkleaks':
            return handle_apkleaks()
        elif action_name == 'scan-base64':
            return handle_base64_scan()
        elif action_name == 'font-analysis':
            return handle_font_analysis()
        elif action_name == 'frida-fsmon-scan':
            return handle_frida_fsmon_scan()
        elif action_name == 'manifest-analysis':
            return handle_manifest_analysis()
        elif action_name == 'decompile-apk':
            return handle_decompile_apk()
        elif action_name == 'apk-unmask-analysis':
            return handle_apk_unmask_analysis()
        elif action_name == 'blutter-analysis':
            return handle_blutter_analysis()
        elif action_name == 'image-steganography-analysis':
            return handle_image_steganography_analysis()
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Action execution failed: {str(e)}'
        })


def handle_full_process():
    """Handle full process execution."""
    # Check prerequisites
    if not app_state.get('setup_complete') or not app_state.get('APK_FILENAME') or not app_state.get('OUTPUT_DIR'):
        return jsonify({
            'success': False,
            'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
        })
    
    # Start the full process
    success = process_manager.execute_automatool(
        app_state['OUTPUT_DIR'], 
        app_state['APK_FILENAME'], 
        verbose=True
    )
    
    if success:
        return jsonify({
            'success': True,
            'message': 'Full analysis process started successfully',
            'action': 'full-process'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Failed to start full analysis process'
        })


def handle_get_reviews():
    """Handle reviews parsing execution."""
    # Check prerequisites
    if not app_state.get('OUTPUT_DIR'):
        return jsonify({
            'success': False,
            'message': 'Output directory not set. Please complete setup first.'
        })
    
    # Start reviews parsing
    success = process_manager.execute_reviews_parsing(
        app_state['OUTPUT_DIR'], 
        verbose=True
    )
    
    if success:
        return jsonify({
            'success': True,
            'message': 'Reviews parsing started successfully',
            'action': 'get-reviews'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Failed to start reviews parsing'
        })


def handle_clean():
    """Handle cleanup execution."""
    # Cleanup can run anytime, no prerequisites needed
    success = process_manager.execute_cleanup(verbose=True)
    
    if success:
        # Reset app state after cleanup
        app_state.update({
            'APK_FILENAME': None,
            'OUTPUT_DIR': None,
            'APK_PATH': None,
            'YARA_PATH': None,
            'setup_complete': False,
            'current_process': None
        })
        
        return jsonify({
            'success': True,
            'message': 'Cleanup started successfully',
            'action': 'clean'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Failed to start cleanup'
        })


def handle_mobsf_upload():
    """Handle MobSF upload execution."""
    # Check prerequisites
    if not app_state.get('setup_complete') or not app_state.get('APK_PATH') or not app_state.get('OUTPUT_DIR'):
        return jsonify({
            'success': False,
            'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
        })
    
    # Start MobSF upload
    success = process_manager.execute_mobsf_upload(
        app_state['APK_PATH'],
        app_state['OUTPUT_DIR'], 
        verbose=True
    )
    
    if success:
        return jsonify({
            'success': True,
            'message': 'MobSF upload started successfully',
            'action': 'mobsf'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Failed to start MobSF upload'
        })


def handle_strings_analysis():
    """Handle strings analysis execution on .so files."""
    # Check prerequisites
    if not app_state.get('setup_complete') or not app_state.get('OUTPUT_DIR'):
        return jsonify({
            'success': False,
            'message': 'Setup not complete. Please complete APK analysis first.'
        })
    
    # --- JNI Extraction (Synchronous) ---
    apk_path = app_state.get('APK_PATH')
    if apk_path and os.path.exists(apk_path):
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        python_executable = os.path.join(project_root, '.venv', 'bin', 'python')
        automatool_src_path = os.path.join(project_root, 'automatool', 'automatool', 'src')
        jni_script_path = os.path.join(automatool_src_path, 'jni_helper', 'extract_jni.py')
        
        output_dir = app_state['OUTPUT_DIR']
        native_lib_dir = os.path.join(output_dir, 'native-lib')
        os.makedirs(native_lib_dir, exist_ok=True)
        output_file = os.path.join(native_lib_dir, 'jni_results.json')

        command = [
            python_executable,
            jni_script_path,
            apk_path,
            '-o',
            output_file
        ]
        
        try:
            # Run synchronously and set the correct working directory
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                cwd=automatool_src_path  # Set the working directory here
            )
            print(f"JNI extraction successful. Results saved to {output_file}")
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"JNI extraction failed: {e.stderr}")
            # Stop if JNI extraction fails
            return jsonify({'success': False, 'message': f'JNI extraction failed: {e.stderr}'})

    # --- Strings Analysis (Asynchronous) ---
    success = process_manager.execute_strings_on_so(
        app_state['OUTPUT_DIR'],
        app_state['OUTPUT_DIR'],
        verbose=True
    )
    
    if success:
        return jsonify({
            'success': True,
            'message': 'JNI extraction completed and strings analysis started successfully',
            'action': 'native-strings-analysis'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'JNI extraction completed, but failed to start strings analysis'
        })

def handle_apkleaks():
    """Handle apkleaks execution."""
    # Check prerequisites
    if not app_state.get('setup_complete') or not app_state.get('APK_PATH') or not app_state.get('OUTPUT_DIR'):
        return jsonify({
            'success': False,
            'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
        })
    
    # Start apkleaks
    success = process_manager.execute_apkleaks(
        app_state['APK_PATH'],
        app_state['OUTPUT_DIR'], 
        verbose=True
    )
    
    if success:
        return jsonify({
            'success': True,
            'message': 'APKLeaks scan started successfully',
            'action': 'apkleaks'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Failed to start APKLeaks scan'
        })


def handle_base64_scan():
    """Handle base64 string scanning execution."""
    # Check prerequisites
    if not app_state.get('setup_complete') or not app_state.get('OUTPUT_DIR'):
        return jsonify({
            'success': False,
            'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
        })
    
    try:
        # Import the Base64Scanner from automatool
        import sys
        automatool_src = os.path.join(os.path.dirname(__file__), '..', 'automatool', 'automatool', 'src')
        
        if not os.path.exists(automatool_src):
            return jsonify({
                'success': False,
                'message': 'Automatool source directory not found'
            })
        
        # Add to Python path
        sys.path.insert(0, automatool_src)
        
        # Import Base64Scanner and GlobalResourceTracker
        from scripts.automations.base64_scanner import Base64Scanner
        from scripts.automations.resource_tracker import GlobalResourceTracker
        
        # Initialize resource tracker
        try:
            tracker = GlobalResourceTracker()
            print("🔧 Resource tracker initialized for Base64 scan")
        except Exception as e:
            print(f"⚠️  WARNING: Could not initialize resource tracker: {e}")
            tracker = None
        
        # Initialize scanner with default thresholds
        scanner = Base64Scanner()
        
        # Scan the decompiled directory and save results to files
        results = scanner.scan_decompiled_apk_directory(app_state['OUTPUT_DIR'])
        
        # Generate report with file output
        report = scanner.generate_report(output_directory=app_state['OUTPUT_DIR'], save_to_files=True)
        
        # Get the output file names for the response
        output_files = report.get('output_files', {})
        
        # Track the generated files
        if tracker and output_files:
            try:
                output_dir = app_state['OUTPUT_DIR']
                
                # Track JSON results file
                if 'json_results' in output_files:
                    json_file_path = os.path.join(output_dir, output_files['json_results'])
                    tracker.add_file(json_file_path)
                    print(f"📄 Tracked Base64 JSON results: {json_file_path}")
                
                # Track text summary file
                if 'text_summary' in output_files:
                    summary_file_path = os.path.join(output_dir, output_files['text_summary'])
                    tracker.add_file(summary_file_path)
                    print(f"📄 Tracked Base64 summary: {summary_file_path}")
                    
            except Exception as e:
                print(f"⚠️  WARNING: Failed to track Base64 scan files: {e}")
        
        return jsonify({
            'success': True,
            'message': f'Base64 scan completed successfully and resources tracked. Results saved to output directory.',
            'action': 'scan-base64',
            'output_files': output_files,
            'summary': {
                'files_scanned': report['summary']['total_files_scanned'],
                'strings_found': report['summary']['total_strings_found'],
                'files_with_strings': report['summary']['files_with_strings_count']
            }
        })
        
    except FileNotFoundError as e:
        return jsonify({
            'success': False,
            'message': f'Directory not found: {str(e)}',
            'error': 'DIRECTORY_NOT_FOUND'
        })
    except PermissionError as e:
        return jsonify({
            'success': False,
            'message': f'Access denied: {str(e)}',
            'error': 'ACCESS_DENIED'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Base64 scan failed: {str(e)}',
            'error': 'UNKNOWN_ERROR'
        })


def handle_font_analysis():
    """Handle TTF font steganography analysis execution."""
    # Check prerequisites
    if not app_state.get('setup_complete') or not app_state.get('OUTPUT_DIR'):
        return jsonify({
            'success': False,
            'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
        })
    
    try:
        # Use the process manager to execute font analysis
        success = process_manager.execute_font_analysis(
            app_state['OUTPUT_DIR'],  # Use output directory as source
            app_state['OUTPUT_DIR'],  # Use output directory for results
            verbose=True
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': 'TTF font steganography analysis started successfully in background',
                'action': 'font-analysis'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to start font analysis process'
            })
        
    except FileNotFoundError as e:
        return jsonify({
            'success': False,
            'message': f'Directory not found: {str(e)}',
            'error': 'DIRECTORY_NOT_FOUND'
        })
    except PermissionError as e:
        return jsonify({
            'success': False,
            'message': f'Access denied: {str(e)}',
            'error': 'ACCESS_DENIED'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Font analysis failed: {str(e)}',
            'error': 'UNKNOWN_ERROR'
        })


def handle_image_steganography_analysis():
    """Handle image steganography detection analysis execution."""
    try:
        # Check prerequisites
        if not app_state.get('setup_complete') or not app_state.get('OUTPUT_DIR'):
            return jsonify({
                'success': False,
                'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
            })
        
        # Get configuration options from request
        data = request.get_json() or {}
        threshold_bytes = data.get('threshold_bytes', 10)
        
        # Validate threshold
        if not isinstance(threshold_bytes, int) or threshold_bytes < 1 or threshold_bytes > 1000:
            return jsonify({
                'success': False,
                'message': 'Invalid threshold value. Must be an integer between 1 and 1000.'
            })
        
        # Determine input path - look for extracted APK assets (images)
        apktool_output = os.path.join(app_state['OUTPUT_DIR'], 'apktool_output')
        assets_path = os.path.join(apktool_output, 'res')
        
        # Check if APK assets exist (from decompilation)
        if not os.path.exists(assets_path):
            return jsonify({
                'success': False,
                'message': 'APK assets not found. Please run APK decompilation first to extract images.',
                'error': 'ASSETS_NOT_FOUND'
            })
        
        # Start image steganography analysis
        success = process_manager.execute_image_steganography_analysis(
            assets_path,
            app_state['OUTPUT_DIR'],
            threshold_bytes=threshold_bytes,
            verbose=True
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Image steganography analysis started successfully (threshold: {threshold_bytes} bytes)',
                'action': 'image-steganography-analysis',
                'config': {
                    'threshold_bytes': threshold_bytes,
                    'input_path': assets_path
                }
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to start image steganography analysis process'
            })
            
    except FileNotFoundError as e:
        return jsonify({
            'success': False,
            'message': f'Directory not found: {str(e)}',
            'error': 'DIRECTORY_NOT_FOUND'
        })
    except PermissionError as e:
        return jsonify({
            'success': False,
            'message': f'Access denied: {str(e)}',
            'error': 'ACCESS_DENIED'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Image steganography analysis failed: {str(e)}',
            'error': 'UNKNOWN_ERROR'
        })


def handle_frida_fsmon_scan():
    """Handle combined Frida and F-Monitor scan execution."""
    # Check prerequisites
    if not app_state.get('setup_complete') or not app_state.get('APK_PATH') or not app_state.get('OUTPUT_DIR'):
        return jsonify({
            'success': False,
            'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
        })

    try:
        # Initialize resource tracker
        import sys
        automatool_src = os.path.join(os.path.dirname(__file__), '..', 'automatool', 'automatool', 'src')
        sys.path.insert(0, automatool_src)
        from scripts.automations.resource_tracker import GlobalResourceTracker
        
        try:
            tracker = GlobalResourceTracker()
            print("🔧 Resource tracker initialized for Frida-FSMon scan")
        except Exception as e:
            print(f"⚠️  WARNING: Could not initialize resource tracker: {e}")
            tracker = None

        # Extract package name
        package_name = extract_package_name_from_automatool(app_state['APK_PATH'])
        if not package_name or package_name == "unknown":
            return jsonify({
                'success': False,
                'message': 'Could not extract package name from APK.'
            })

        # Start the combined scan
        success = process_manager.execute_frida_fsmon_scan(
            app_state['OUTPUT_DIR'],
            package_name
        )

        if success:
            # Track the output files that are created by the scan
            if tracker:
                try:
                    output_dir = app_state['OUTPUT_DIR']
                    
                    # Track Frida scan output file
                    frida_file_path = os.path.join(output_dir, "frida_scan.txt")
                    if os.path.exists(frida_file_path):
                        tracker.add_file(frida_file_path)
                        print(f"📄 Tracked Frida scan output: {frida_file_path}")
                    
                    # Track FSMon scan output file
                    fsmon_file_path = os.path.join(output_dir, "fsmon_scan.txt")
                    if os.path.exists(fsmon_file_path):
                        tracker.add_file(fsmon_file_path)
                        print(f"📄 Tracked FSMon scan output: {fsmon_file_path}")
                        
                except Exception as e:
                    print(f"⚠️  WARNING: Failed to track Frida-FSMon scan files: {e}")
            
            return jsonify({
                'success': True,
                'message': 'Frida & F-Monitor scan completed successfully and resources tracked',
                'action': 'frida-fsmon-scan'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to start Frida & F-Monitor scan'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Frida-FSMon scan failed: {str(e)}'
        })


def handle_manifest_analysis():
    """Handle AMAnDe manifest analysis execution."""
    # Check prerequisites
    if not app_state.get('setup_complete') or not app_state.get('APK_PATH') or not app_state.get('OUTPUT_DIR'):
        return jsonify({
            'success': False,
            'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
        })
    
    # Start manifest analysis
    success = process_manager.execute_manifest_analysis(
        app_state['APK_PATH'],
        app_state['OUTPUT_DIR'], 
        verbose=True
    )
    
    if success:
        return jsonify({
            'success': True,
            'message': 'AMAnDe manifest analysis started successfully',
            'action': 'manifest-analysis'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Failed to start manifest analysis'
        })


def handle_decompile_apk():
    """Handle standalone APK decompilation execution."""
    # Check prerequisites
    if not app_state.get('setup_complete') or not app_state.get('APK_PATH') or not app_state.get('OUTPUT_DIR'):
        return jsonify({
            'success': False,
            'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
        })
    
    # Start decompilation
    success = process_manager.execute_decompile_apk(
        app_state['APK_PATH'],
        app_state['OUTPUT_DIR'], 
        verbose=True
    )
    
    if success:
        return jsonify({
            'success': True,
            'message': 'APK decompilation started successfully',
            'action': 'decompile-apk'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Failed to start APK decompilation'
        })


def handle_apk_unmask_analysis():
    """Handle standalone APK Unmask analysis execution."""
    try:
        # Check prerequisites
        if not app_state.get('setup_complete') or not app_state.get('APK_PATH') or not app_state.get('OUTPUT_DIR'):
            return jsonify({
                'success': False,
                'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
            })
        
        # Get options from request (simple version for now)
        data = request.get_json() or {}
        enable_filtering = data.get('enable_filtering', True)
        enable_file_analysis = True  # Always enable file analysis
        apktool_output_dir = os.path.join(app_state.get('OUTPUT_DIR'), 'apktool_output') # Use the output directory from the app state
        
        # Start APK Unmask analysis
        success = process_manager.execute_apk_unmask_analysis(
            app_state['APK_PATH'],
            app_state['OUTPUT_DIR'],
            enable_filtering=enable_filtering,
            enable_file_analysis=enable_file_analysis,
            apktool_output_dir=apktool_output_dir,
            verbose=True
        )
        
        if success:
            message = 'APK Unmask analysis started successfully'
            if enable_file_analysis and not apktool_output_dir:
                message += ' (File analysis disabled - no apktool output directory provided)'
            
            return jsonify({
                'success': True,
                'message': message,
                'action': 'apk-unmask-analysis'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to start APK Unmask analysis'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'APK Unmask analysis failed: {str(e)}'
        })


def handle_blutter_analysis():
    """Handle Blutter Flutter analysis execution."""
    try:
        # Check prerequisites
        if not app_state.get('setup_complete') or not app_state.get('OUTPUT_DIR'):
            return jsonify({
                'success': False,
                'message': 'Setup not complete. Please upload APK file or configure manual setup first.'
            })
        
        # Start Blutter analysis
        success = process_manager.execute_blutter_analysis(
            app_state['OUTPUT_DIR'],
            verbose=True
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Blutter Flutter analysis started successfully. Results will be tracked for cleanup.',
                'action': 'blutter-analysis',
                'cleanup_info': 'Output files and directories are automatically tracked and can be cleaned up using the cleanup automation.'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to start Blutter analysis'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Blutter analysis failed: {str(e)}'
        })


@app.route('/api/action/stop', methods=['POST'])
def stop_process():
    """Stop the currently running process."""
    try:
        if not process_manager.is_running():
            return jsonify({
                'success': False,
                'message': 'No process is currently running'
            })
        
        success = process_manager.kill_current_process()
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Process stopped successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to stop process'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error stopping process: {str(e)}'
        })


@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    """Clear the process logs."""
    try:
        process_manager.clear_log()
        return jsonify({
            'success': True,
            'message': 'Logs cleared successfully'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error clearing logs: {str(e)}'
        })


# VPN-Frida API Endpoints

@app.route('/api/get-package-name', methods=['POST'])
def get_package_name():
    """Extract package name from uploaded APK file."""
    print(f"[DEBUG] 🔍 Starting package name extraction...")
    
    try:
        data = request.get_json()
        print(f"[DEBUG] 📥 Received request data: {data}")
        
        apk_path = data.get('apk_path')
        print(f"[DEBUG] 📁 APK path from request: {apk_path}")
        
        if not apk_path:
            print(f"[DEBUG] ❌ No APK path provided in request")
            return jsonify({
                'success': False,
                'message': 'No APK path provided'
            })
        
        if not os.path.exists(apk_path):
            print(f"[DEBUG] ❌ APK file not found at path: {apk_path}")
            return jsonify({
                'success': False,
                'message': f'APK file not found at: {apk_path}'
            })
        
        print(f"[DEBUG] ✅ APK file exists at: {apk_path}")
        print(f"[DEBUG] 📊 File size: {os.path.getsize(apk_path)} bytes")
        
        # Use existing automatool package extraction
        print(f"[DEBUG] 🚀 Calling automatool package extraction...")
        package_name = extract_package_name_from_automatool(apk_path)
        print(f"[DEBUG] 📦 Package extraction result: {package_name}")
        
        if package_name and package_name != "unknown":
            print(f"[DEBUG] ✅ Successfully extracted package name: {package_name}")
            return jsonify({
                'success': True,
                'package_name': package_name,
                'message': f'Package detected: {package_name}'
            })
        else:
            print(f"[DEBUG] ❌ Failed to extract package name - result: {package_name}")
            return jsonify({
                'success': False,
                'message': 'Could not extract package name from APK'
            })
            
    except Exception as e:
        print(f"[DEBUG] 💥 Exception during package extraction: {type(e).__name__}: {e}")
        import traceback
        print(f"[DEBUG] 📚 Full traceback:")
        traceback.print_exc()
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

        # Install the APK before starting Frida
        if not app_state.get('APK_PATH'):
            return jsonify({
                'success': False,
                'message': 'APK path not found in app state. Please upload APK first.'
            })

        apk_path = app_state['APK_PATH']
        
        # Add automatool src to path to import install_apk
        import sys
        automatool_src = os.path.join(os.path.dirname(__file__), '..', 'automatool', 'automatool', 'src')
        if automatool_src not in sys.path:
            sys.path.insert(0, automatool_src)
            
        try:
            from scripts.automations.install_apk import install_apk_on_device
            print(f"⚙️ Installing APK from: {apk_path}")
            install_success = install_apk_on_device(apk_path, verbose=True)
            if not install_success:
                error_msg = 'Failed to install APK on the device. Please check ADB connection and logs.'
                print(f"❌ {error_msg}")
                return jsonify({
                    'success': False,
                    'message': error_msg
                })
            print("✅ APK installed successfully.")
        except ImportError as e:
            error_msg = f'Internal server error: could not load APK installation module. Details: {e}'
            print(f"❌ {error_msg}")
            return jsonify({
                'success': False,
                'message': error_msg
            })
        except Exception as e:
            error_msg = f'An error occurred during APK installation: {e}'
            print(f"❌ {error_msg}")
            return jsonify({
                'success': False,
                'message': error_msg
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
        success = process_manager.kill_current_process()
        
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


def extract_package_name_from_automatool(apk_path: str) -> str:
    """
    Extract package name using automatool's existing functionality.
    Web-friendly version that doesn't call sys.exit() on failure.
    
    Args:
        apk_path (str): Path to the APK file
        
    Returns:
        str: Package name if successful, "unknown" if failed
    """
    print(f"[DEBUG] 🔧 extract_package_name_from_automatool called with: {apk_path}")
    
    try:
        # Import existing automatool function
        import sys
        print(f"[DEBUG] 📂 Current working directory: {os.getcwd()}")
        print(f"[DEBUG] 📂 Current file location: {__file__}")
        
        automatool_src = os.path.join(os.path.dirname(__file__), '..', 'automatool', 'automatool', 'src')
        print(f"[DEBUG] 🎯 Automatool source path: {automatool_src}")
        
        if not os.path.exists(automatool_src):
            print(f"[DEBUG] ❌ Automatool source directory not found: {automatool_src}")
            return "unknown"
        
        print(f"[DEBUG] ✅ Automatool source directory exists")
        print(f"[DEBUG] 📁 Contents of automatool_src:")
        try:
            for item in os.listdir(automatool_src):
                print(f"[DEBUG]   - {item}")
        except Exception as list_e:
            print(f"[DEBUG] ❌ Could not list directory contents: {list_e}")
        
        # Add to Python path
        print(f"[DEBUG] 🔧 Adding to Python path: {automatool_src}")
        sys.path.insert(0, automatool_src)
        print(f"[DEBUG] 📋 Current Python path:")
        for i, path in enumerate(sys.path[:5]):  # Show first 5 paths
            print(f"[DEBUG]   {i}: {path}")
        
        # Try to import the utils module
        print(f"[DEBUG] 📦 Attempting to import scripts.utils.utils...")
        try:
            from scripts.utils.utils import get_package_name
            print(f"[DEBUG] ✅ Successfully imported get_package_name function")
        except ImportError as import_e:
            print(f"[DEBUG] ❌ Import failed: {import_e}")
            print(f"[DEBUG] 📚 Available modules in automatool_src:")
            try:
                import scripts.utils.utils
                print(f"[DEBUG] ✅ scripts.utils.utils module exists")
                print(f"[DEBUG] 📋 Available attributes:")
                for attr in dir(scripts.utils.utils):
                    if not attr.startswith('_'):
                        print(f"[DEBUG]   - {attr}")
            except Exception as module_e:
                print(f"[DEBUG] ❌ Module inspection failed: {module_e}")
            return "unknown"
        
        # Use the base function that doesn't call sys.exit()
        print(f"[DEBUG] 🚀 Calling get_package_name with verbose=True for debugging...")
        package_name = get_package_name(apk_path, verbose=True)
        print(f"[DEBUG] 📦 get_package_name returned: {package_name}")
        
        result = package_name if package_name else "unknown"
        print(f"[DEBUG] 🎯 Final result: {result}")
        return result
        
    except Exception as e:
        print(f"[DEBUG] 💥 Exception in extract_package_name_from_automatool: {type(e).__name__}: {e}")
        import traceback
        print(f"[DEBUG] 📚 Full traceback:")
        traceback.print_exc()
        return "unknown"


# ============================================================================
# MONITORING ENDPOINTS
# ============================================================================

@app.route('/api/monitoring/status', methods=['GET'])
def monitoring_status():
    """Get monitoring system status and availability."""
    if not monitoring_available:
        return jsonify({
            'available': False,
            'message': 'Monitoring modules not available',
            'error': 'Import failed'
        })
    
    try:
        # Test ADB connection
        adb_controller = ADBController()
        adb_connected = adb_controller.check_adb_connection()
        
        return jsonify({
            'available': True,
            'adb_connected': adb_connected,
            'message': 'Monitoring system ready' if adb_connected else 'ADB not connected'
        })
    except Exception as e:
        return jsonify({
            'available': True,
            'adb_connected': False,
            'message': f'Monitoring system error: {str(e)}'
        })


@app.route('/api/monitoring/notifications', methods=['GET'])
def get_notifications():
    """Get notifications from a target app."""
    if not monitoring_available:
        return jsonify({
            'success': False,
            'message': 'Monitoring modules not available'
        }), 503
    
    try:
        # Get target package from query parameters
        target_package = request.args.get('package')
        if not target_package:
            return jsonify({
                'success': False,
                'message': 'Target package name required (use ?package=com.example.app)'
            }), 400
        
        # Create notification monitor
        monitor = NotificationMonitor(target_package)
        
        # Get notifications
        result = monitor.get_notifications()
        
        return jsonify({
            'success': True,
            'data': result
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error monitoring notifications: {str(e)}'
        }), 500


@app.route('/api/monitoring/collect-data', methods=['GET'])
def collect_notification_data():
    """Collect raw notification data from a target app."""
    if not monitoring_available:
        return jsonify({
            'success': False,
            'message': 'Monitoring modules not available'
        }), 500
        
    try:
        # Get target package from query parameters
        target_package = request.args.get('package')
        if not target_package:
            return jsonify({
                'success': False,
                'message': 'Target package name required (use ?package=com.example.app)'
            }), 400
        
        # Create notification monitor and data collector
        monitor = NotificationMonitor(target_package)
        collector = DataCollector(target_package)
        
        # Get notifications first
        notifications = monitor.get_notifications()
        
        # Collect and format the data
        collected_data = collector.collect_notifications(notifications)
        
        return jsonify({
            'success': True,
            'data': collected_data
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error collecting data: {str(e)}'
        }), 500


@app.route('/api/monitoring/device-info', methods=['GET'])
def get_device_info():
    """Get connected Android device information."""
    if not monitoring_available:
        return jsonify({
            'success': False,
            'message': 'Monitoring modules not available'
        }), 500
        
    try:
        adb_controller = ADBController()
        device_info = adb_controller.get_device_info()
        
        return jsonify({
            'success': True,
            'data': device_info
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error getting device info: {str(e)}'
        }), 500


@app.route('/api/gemini/prompt', methods=['POST'])
def handle_gemini_prompt():
    """Handle Gemini AI prompt requests."""
    try:
        # Check if Gemini is available
        if not gemini_available:
            return jsonify({
                'success': False,
                'error': 'Gemini integration not available. Please check if the automation module is installed.',
                'details': 'launch_gemini_prompt module could not be imported'
            })
        
        # Get request data
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            })
        
        # Extract parameters
        prompt = data.get('prompt', '').strip()
        output_directory = data.get('output_directory', '').strip()
        verbose = data.get('verbose', True)
        
        # Validate required parameters
        if not prompt:
            return jsonify({
                'success': False,
                'error': 'Prompt cannot be empty'
            })
        
        if not output_directory:
            return jsonify({
                'success': False,
                'error': 'Output directory must be specified'
            })
        
        # Validate output directory exists
        if not os.path.exists(output_directory):
            return jsonify({
                'success': False,
                'error': f'Output directory does not exist: {output_directory}'
            })
        
        # Execute Gemini prompt
        print(f"[DEBUG] 🤖 Starting Gemini analysis...")
        print(f"[DEBUG] Directory: {output_directory}")
        print(f"[DEBUG] Prompt: {prompt[:100]}..." if len(prompt) > 100 else f"[DEBUG] Prompt: {prompt}")
        
        import time
        start_time = time.time()
        
        result_file = send_prompt_to_gemini(prompt, output_directory, verbose)
        
        execution_time = round(time.time() - start_time, 1)
        
        if result_file:
            # Success response
            return jsonify({
                'success': True,
                'message': 'Gemini analysis completed successfully',
                'result_file': result_file,
                'execution_time': f"{execution_time} seconds"
            })
        else:
            # Failed response
            return jsonify({
                'success': False,
                'error': 'Gemini analysis failed to complete',
                'details': 'Check server logs for more details'
            })
            
    except Exception as e:
        print(f"[ERROR] 🤖 Gemini API error: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Gemini analysis failed: {str(e)}',
            'details': f'Exception: {type(e).__name__}'
        })


if __name__ == '__main__':
    # Create necessary directories if they don't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    # Run the application
    app.run(host='0.0.0.0', port=5000, debug=True)
