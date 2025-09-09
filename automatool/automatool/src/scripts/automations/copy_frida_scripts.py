import os
import shutil

FRIDA_SCRIPTS_TO_COPY = [
    "../frida/bypasses/install_referrer.js",
    "../frida/bypasses/liscencecheck.js",
    "../frida/bypasses/network_checks.js",
    "../frida/bypasses/restriction_bypass.js",
    "../frida/bypasses/root.js",
    "../frida/bypasses/system_properties.js",
    "../frida/bypasses/VPN.js",
    "../frida/info/cookie_exfiltration_detection.js",
    "../frida/info/crypto.js",
    "../frida/info/dex_load_tracer.js",
    "../frida/info/logs.js",
    "../frida/info/ssl_unpinning.js",
    "../frida/templates/dex_load.js",
    "../frida/templates/native.js",
    "../main_hook.js",
    "../frida/script.js",
    "../frida/yairhook.js",
]


def copy_frida_scripts(output_directory, verbose=False):
    """
    Copy Frida scripts from Automator/ directory to target directory.
   
    Args:
        output_directory (str): Directory to copy scripts to
        verbose (bool): Enable verbose output
       
    Returns:
        bool: True if copy was successful, False otherwise
    """
    # Define source and destination paths
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    source_dir = os.path.join(script_dir, "../frida")  # Scripts are in the same directory as this script
    dest_dir = os.path.join(output_directory, "frida_scripts")
   
    if verbose:
        print(f"[DEBUG] Copying Frida scripts from {source_dir} to {dest_dir}")
   
    try:
        shutil.copytree(source_dir, dest_dir)
           
    except PermissionError as e:
        print(f"❌ ERROR: Permission denied when copying Frida scripts: {e}")
        print("Please check directory permissions.")
        return False
       
    except Exception as e:
        print(f"❌ ERROR: Failed to copy Frida scripts: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False


def get_frida_script_replacements(package_name):
    """
    Get the replacement mappings for Frida scripts.
   
    Args:
        package_name (str): Package name to inject into scripts
       
    Returns:
        dict: Mapping of script names to their replacement patterns
    """
    return {
        "native_hooks.js": [
            ("com.example.package", package_name)
        ],
        "dex_loader_hooks.js": [
            ("com.brick.bre.Brick", f"{package_name}.PLACEHOLDER_CLASS")
        ]
    }


def apply_replacements_to_content(content, replacements, script_name, verbose=False):
    """
    Apply text replacements to script content.
   
    Args:
        content (str): Original script content
        replacements (list): List of (old_text, new_text) tuples
        script_name (str): Name of the script (for logging)
        verbose (bool): Enable verbose output
       
    Returns:
        str: Updated content with replacements applied
    """
    updated_content = content
   
    for old_text, new_text in replacements:
        if old_text in updated_content:
            updated_content = updated_content.replace(old_text, new_text)
            if verbose:
                print(f"[DEBUG] Replaced '{old_text}' with '{new_text}' in {script_name}")
        else:
            if verbose:
                print(f"[DEBUG] Pattern '{old_text}' not found in {script_name}")
   
    return updated_content


def update_single_frida_script(script_path, script_name, replacements, verbose=False):
    """
    Update a single Frida script file with package name replacements.
   
    Args:
        script_path (str): Full path to the script file
        script_name (str): Name of the script file
        replacements (list): List of replacement patterns
        verbose (bool): Enable verbose output
       
    Returns:
        bool: True if script was updated, False if no changes or error
    """
    if not os.path.exists(script_path):
        print(f"⚠️  WARNING: Script not found for update: {script_path}")
        if verbose:
            print(f"[DEBUG] ❌ Skipped: {script_name}")
        return False
   
    if verbose:
        print(f"[DEBUG] Updating script: {script_name}")
   
    try:
        # Read the script file
        with open(script_path, 'r', encoding='utf-8') as f:
            original_content = f.read()
       
        # Apply replacements
        updated_content = apply_replacements_to_content(
            original_content, replacements, script_name, verbose
        )
       
        # Write updated content back if changes were made
        if updated_content != original_content:
            with open(script_path, 'w', encoding='utf-8') as f:
                f.write(updated_content)
            if verbose:
                print(f"[DEBUG] ✅ Updated: {script_name}")
            return True
        else:
            if verbose:
                print(f"[DEBUG] No changes needed for: {script_name}")
            return False
           
    except UnicodeDecodeError as e:
        print(f"❌ ERROR: Failed to read {script_name} (encoding issue): {e}")
        return False
       
    except PermissionError as e:
        print(f"❌ ERROR: Permission denied when updating {script_name}: {e}")
        return False
       
    except Exception as e:
        print(f"❌ ERROR: Failed to update {script_name}: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False


def update_frida_scripts_with_package_name(output_directory, package_name, verbose=False):
    """
    Update Frida scripts with the extracted package name.
   
    Args:
        output_directory (str): Directory containing the copied Frida scripts
        package_name (str): Package name to inject into scripts
        verbose (bool): Enable verbose output
       
    Returns:
        bool: True if updates were successful, False otherwise
    """
    frida_scripts_dir = os.path.join(output_directory, "frida_scripts")
   
    if verbose:
        print(f"[DEBUG] Updating Frida scripts with package name: {package_name}")
        print(f"[DEBUG] Scripts directory: {frida_scripts_dir}")
   
    # Get replacement mappings
    replacements = get_frida_script_replacements(package_name)
   
    # Update each script
    updated_files = []
    for script_name, script_replacements in replacements.items():
        script_path = os.path.join(frida_scripts_dir, script_name)
       
        if update_single_frida_script(script_path, script_name, script_replacements, verbose):
            updated_files.append(script_name)
   
    # Report results
    if updated_files:
        print(f"✅ Frida scripts updated with package name: {len(updated_files)} files")
        if verbose:
            print(f"[DEBUG] Updated files: {', '.join(updated_files)}")
    else:
        print("⚠️  No Frida scripts were updated (no matching patterns found)")
   
    return True

