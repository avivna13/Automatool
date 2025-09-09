
import subprocess 

def launch_vscode(directory, verbose=False):
    """
    Launch Visual Studio Code to open the target directory.
   
    Args:
        directory (str): Directory path to open in VS Code
        verbose (bool): Enable verbose output
       
    Returns:
        subprocess.Popen or bool: Process object if launch was successful, False otherwise
    """
    if verbose:
        print(f"[DEBUG] Launching VS Code for directory: {directory}")
   
    try:
        # Launch VS Code as a background process
        process = subprocess.Popen(
            ["code", directory],
            stdout=subprocess.DEVNULL,  # Suppress stdout
            stderr=subprocess.DEVNULL,  # Suppress stderr
            text=True
        )
       
        if verbose:
            print(f"[DEBUG] ✅ VS Code launched with PID: {process.pid}")
       
        print(f"✅ VS Code workspace opened: {directory}")
        return process
       
    except FileNotFoundError:
        print("❌ ERROR: 'code' command not found.")
        print("Please ensure Visual Studio Code is installed and 'code' is in your system PATH.")
        if verbose:
            print("[DEBUG] You can download VS Code from: https://code.visualstudio.com/")
        return False
       
    except Exception as e:
        print(f"❌ ERROR: Failed to launch VS Code: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False

