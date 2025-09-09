import subprocess
import os
import shutil


def run_apktool_decode(apk_path, output_directory, verbose=False):
    """
    Decompile APK using both apktool (resources) and Jadx (Java source code).
    
    This function provides comprehensive APK analysis:
    - apktool: Extracts resources, manifest, and disassembles bytecode
    - Jadx: Decompiles Java bytecode to readable source code
    
    Args:
        apk_path (str): Absolute path to the APK file
        output_directory (str): Directory where output should be saved
        verbose (bool): Enable verbose output
        
    Returns:
        dict: Dictionary containing paths to both outputs and status information
    """
    if verbose:
        print("🔧 Running comprehensive APK decompilation analysis...")
    
    # Create output directories
    apktool_output_dir = os.path.join(output_directory, "apktool_output")
    jadx_output_dir = os.path.join(output_directory, "jadx_output")
    
    results = {
        'apktool_output': None,
        'jadx_output': None,
        'success': False,
        'errors': []
    }
    
    # Step 1: Run apktool for resource extraction and disassembly
    if verbose:
        print("📦 Step 1: Running apktool for resource extraction...")
    
    apktool_success = _run_apktool(apk_path, apktool_output_dir, verbose)
    if apktool_success:
        results['apktool_output'] = apktool_output_dir
        if verbose:
            print(f"✅ apktool completed successfully: {apktool_output_dir}")
    else:
        error_msg = "apktool failed to extract resources"
        results['errors'].append(error_msg)
        if verbose:
            print(f"❌ {error_msg}")
    
    # Step 2: Run Jadx for Java decompilation
    if verbose:
        print("☕ Step 2: Running Jadx for Java decompilation...")
    
    jadx_success = _run_jadx(apk_path, jadx_output_dir, verbose)
    if jadx_success:
        results['jadx_output'] = jadx_output_dir
        if verbose:
            print(f"✅ Jadx completed successfully: {jadx_output_dir}")
    else:
        error_msg = "Jadx failed to decompile Java code"
        results['errors'].append(error_msg)
        if verbose:
            print(f"❌ {error_msg}")
    
    # Determine overall success
    results['success'] = apktool_success or jadx_success
    
    if results['success']:
        print("✅ APK decompilation completed successfully!")
        if results['apktool_output']:
            print(f"📁 Resources extracted to: {results['apktool_output']}")
        if results['jadx_output']:
            print(f"☕ Java source code to: {results['jadx_output']}")
    else:
        print("❌ APK decompilation failed completely")
        for error in results['errors']:
            print(f"   • {error}")
    
    return results


def _run_apktool(apk_path, output_directory, verbose=False):
    """
    Run apktool to extract resources and disassemble APK.
    
    Args:
        apk_path (str): Path to APK file
        output_directory (str): Output directory for apktool
        verbose (bool): Enable verbose output
        
    Returns:
        bool: True if successful, False otherwise
    """
    # Command: apktool d <apk_path> -o <output_path> -f
    # -f flag forces overwrite of existing output
    command = ["apktool", "d", apk_path, "-o", output_directory, "-f"]
    
    try:
        if verbose:
            print(f"[DEBUG] Running apktool command: {' '.join(command)}")
            print(f"[DEBUG] Output directory: {output_directory}")
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        
        if verbose:
            print(f"[DEBUG] ✅ apktool completed successfully")
            if result.stdout.strip():
                print(f"[DEBUG] apktool stdout: {result.stdout.strip()}")
        
        return True
        
    except FileNotFoundError:
        if verbose:
            print("❌ ERROR: 'apktool' command not found.")
            print("Please ensure apktool is installed and available in your system PATH.")
            print("You can install apktool from: https://ibotpeaches.github.io/Apktool/")
        return False
        
    except subprocess.CalledProcessError as e:
        if verbose:
            print(f"❌ ERROR: apktool failed with exit code {e.returncode}")
            print(f"[DEBUG] Command: {' '.join(e.cmd)}")
            print(f"[DEBUG] Stderr: {e.stderr}")
            print(f"[DEBUG] Stdout: {e.stdout}")
        return False
        
    except Exception as e:
        if verbose:
            print(f"❌ ERROR: Unexpected error during apktool execution: {e}")
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False


def _run_jadx(apk_path, output_directory, verbose=False):
    """
    Run Jadx command-line to decompile Java bytecode to source code.
    
    Args:
        apk_path (str): Path to APK file
        output_directory (str): Output directory for Jadx
        verbose (bool): Enable verbose output
        
    Returns:
        bool: True if successful, False otherwise
    """
    # Command: jadx -d <output_path> <apk_path>
    # -d specifies output directory
    command = ["jadx", "-d", output_directory, apk_path]
    
    try:
        if verbose:
            print(f"[DEBUG] Running Jadx command: {' '.join(command)}")
            print(f"[DEBUG] Output directory: {output_directory}")
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        
        if verbose:
            print(f"[DEBUG] ✅ Jadx completed successfully")
            if result.stdout.strip():
                print(f"[DEBUG] Jadx stdout: {result.stdout.strip()}")
        
        return True
        
    except FileNotFoundError:
        if verbose:
            print("❌ ERROR: 'jadx' command not found.")
            print("Please ensure Jadx is installed and available in your system PATH.")
            print("You can download Jadx from: https://github.com/skylot/jadx/releases")
            print("Note: You need the 'jadx' command-line tool, not just 'jadx-gui'")
        return False
        
    except subprocess.CalledProcessError as e:
        if verbose:
            print(f"❌ ERROR: Jadx failed with exit code {e.returncode}")
            print(f"[DEBUG] Command: {' '.join(e.cmd)}")
            print(f"[DEBUG] Stderr: {e.stderr}")
            print(f"[DEBUG] Stdout: {e.stdout}")
        return False
        
    except Exception as e:
        if verbose:
            print(f"❌ ERROR: Unexpected error during Jadx execution: {e}")
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False


def get_java_files_count(output_directory):
    """
    Count the number of Java files in the Jadx output directory.
    
    Args:
        output_directory (str): Path to Jadx output directory
        
    Returns:
        int: Number of Java files found, 0 if directory doesn't exist
    """
    if not output_directory or not os.path.exists(output_directory):
        return 0
    
    java_count = 0
    try:
        for root, dirs, files in os.walk(output_directory):
            for file in files:
                if file.endswith('.java'):
                    java_count += 1
    except Exception:
        pass
    
    return java_count


def get_decompilation_summary(results):
    """
    Generate a summary of the decompilation results.
    
    Args:
        results (dict): Results from run_apktool_decode
        
    Returns:
        str: Formatted summary string
    """
    summary_lines = []
    summary_lines.append("📊 APK Decompilation Summary")
    summary_lines.append("=" * 40)
    
    if results['apktool_output']:
        summary_lines.append(f"✅ Resources extracted: {results['apktool_output']}")
        # Count files in apktool output
        try:
            if os.path.exists(results['apktool_output']):
                file_count = len([f for f in os.listdir(results['apktool_output']) 
                                if os.path.isfile(os.path.join(results['apktool_output'], f))])
                summary_lines.append(f"   📁 Files extracted: {file_count}")
        except Exception:
            pass
    
    if results['jadx_output']:
        summary_lines.append(f"☕ Java source code: {results['jadx_output']}")
        # Count Java files
        java_count = get_java_files_count(results['jadx_output'])
        summary_lines.append(f"   📝 Java files: {java_count}")
    
    if results['errors']:
        summary_lines.append(f"❌ Errors encountered: {len(results['errors'])}")
        for error in results['errors']:
            summary_lines.append(f"   • {error}")
    
    summary_lines.append(f"🎯 Overall status: {'✅ Success' if results['success'] else '❌ Failed'}")
    
    return "\n".join(summary_lines)
