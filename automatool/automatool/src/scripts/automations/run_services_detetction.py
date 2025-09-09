import frida
import subprocess
import sys
import time
import os
from datetime import datetime

PACKAGE = "com.suspicious.app"
HOOK_SCRIPT = "automatool/automatool/src/scripts/frida/info/hook_services.js"
LOG_DIR = "logs"
DUMP_INTERVAL = 10   # seconds between dumpsys snapshots
RUN_TIME = 60        # total monitoring time in seconds

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

def run_dumpsys():
    """Run adb dumpsys and save output with timestamp"""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(LOG_DIR, f"services_{ts}.txt")
    with open(out_file, "w") as f:
        subprocess.run(
            ["adb", "shell", "dumpsys", "activity", "services"],
            stdout=f, stderr=subprocess.STDOUT
        )
    print(f"[ADB] Services dumped to {out_file}")
    return out_file

def on_message(msg, data):
    """Handle messages from Frida script"""
    if msg["type"] == "send":
        print("[Frida]", msg["payload"])
    elif msg["type"] == "error":
        print("[Frida ERROR]", msg)

def main():
    device = frida.get_usb_device()
    pid = device.spawn([PACKAGE])
    session = device.attach(pid)

    with open(HOOK_SCRIPT) as f:
        script = session.create_script(f.read())
    script.on("message", on_message)
    script.load()

    device.resume(pid)
    print(f"[*] App {PACKAGE} started with Frida PID {pid}")

    start = time.time()
    while time.time() - start < RUN_TIME:
        run_dumpsys()
        time.sleep(DUMP_INTERVAL)

    print("[*] Monitoring complete. Check logs/ for dumpsys outputs.")

if __name__ == "__main__":
    main()
