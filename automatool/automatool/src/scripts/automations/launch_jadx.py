
import subprocess

def launch_jadx_gui(apk_path, verbose=False):
    """
    Launch Jadx GUI to analyze the APK in the background.
   
    Args:
        apk_path (str): Path to the APK file
        verbose (bool): Enable verbose output
       
    Returns:
        subprocess.Popen or bool: Process object if launch was successful, False otherwise
    """
    if verbose:
        print(f"[DEBUG] Launching Jadx GUI for: {apk_path}")
   
    try:
        # Launch jadx-gui as a background process
        process = subprocess.Popen(
            ["jadx-gui", apk_path],
            stdout=subprocess.DEVNULL,  # Suppress stdout
            stderr=subprocess.DEVNULL,  # Suppress stderr
            text=True
        )
       
        if verbose:
            print(f"[DEBUG] ✅ Jadx GUI launched with PID: {process.pid}")
       
        print(f"✅ Jadx GUI launched successfully")
        return process
       
    except FileNotFoundError:
        print("❌ ERROR: 'jadx-gui' command not found.")
        print("Please ensure Jadx is installed and 'jadx-gui' is in your system PATH.")
        if verbose:
            print("[DEBUG] You can download Jadx from: https://github.com/skylot/jadx/releases")
        return False
       
    except Exception as e:
        print(f"❌ ERROR: Failed to launch Jadx GUI: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False
