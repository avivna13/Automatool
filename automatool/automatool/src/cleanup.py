#!/usr/bin/env python3
"""
APK Analysis Cleanup Tool

This script cleans up all resources tracked by automatool.py including:
- Running processes (Jadx, VS Code)
- Generated files and directories
- Installed APKs on connected devices
- Resource tracking JSON file

Usage:
  python cleanup.py [options]
"""

import argparse
import sys
import os

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scripts.automations.resource_tracker import GlobalResourceTracker


def main():
    """Main entry point for enhanced cleanup script."""
    args = parse_arguments()
    
    try:
        # Initialize resource tracker
        tracker = GlobalResourceTracker()
        
        # Show device status if requested
        if args.device_status:
            show_device_status()
            return 0
        
        # Show resource summary if requested
        if args.summary_only:
            summary = tracker.get_resource_summary()
            print("📊 Resource Summary")
            print("=" * 50)
            print(f"📁 Total Files: {summary['files']}")
            print(f"📂 Total Directories: {summary['directories']}")
            print(f"⚙️  Total Processes: {summary['processes']}")
            print(f"🔄 Total Runs: {summary['total_runs']}")
            return 0
        
        # Show device status before cleanup
        print("📱 Checking device status before cleanup...")
        show_device_status()
        
        # Execute cleanup based on arguments
        success = execute_cleanup(tracker, args)
        if success:
            print("✅ Cleanup completed successfully")
            return 0
        else:
            print("❌ Cleanup failed or was cancelled")
            return 1
            
    except Exception as e:
        print(f"❌ CRITICAL ERROR: {e}")
        if args.verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return 1


def parse_arguments():
    """Parse command line arguments for enhanced cleanup script."""
    parser = argparse.ArgumentParser(
        description="Enhanced cleanup of all resources tracked by automatool.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Clean all resources with confirmation
  %(prog)s --verbose         # Verbose cleanup with detailed output
  %(prog)s --force           # Skip confirmation prompts
  %(prog)s --dry-run         # Show what would be cleaned without executing
  %(prog)s --current-only    # Clean only current run, not archived runs
  %(prog)s --device-status    # Show device status without cleaning
        """
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output for debugging"
    )
    
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Skip confirmation prompts (dangerous!)"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be cleaned without executing cleanup"
    )
    
    parser.add_argument(
        "--current-only",
        action="store_true",
        help="Clean only current run, not archived runs"
    )
    
    parser.add_argument(
        "--device-status",
        action="store_true",
        help="Show device status and exit without cleaning"
    )
    
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Show resource summary without cleaning"
    )
    
    return parser.parse_args()


def confirm_cleanup(tracker):
    """Get user confirmation for destructive cleanup operation."""
    summary = tracker.get_resource_summary()
    
    print("\n" + "="*60)
    print("⚠️  WARNING: DESTRUCTIVE CLEANUP OPERATION")
    print("="*60)
    
    print("This will permanently delete the following resources:")
    print(f"   • {summary['processes']} running processes (Jadx, VS Code)")
    print(f"   • {summary['files']} generated files")
    print(f"   • {summary['directories']} created directories")
    print(f"   • {summary['total_runs']} automation runs")
    
    print("\n🔒 SAFETY CHECKS:")
    print("   • All running processes will be terminated")
    print("   • All tracked files will be permanently deleted")
    print("   • All tracked directories will be removed")
    print("   • APKs will be uninstalled from connected devices")
    
    print("\n💡 TIP: Use --dry-run to see what would be cleaned first")
    print("="*60)
    
    # Double confirmation for safety
    response1 = input("\nAre you absolutely sure you want to continue? (yes/no): ").lower().strip()
    if response1 not in ['yes', 'y']:
        return False
    
    response2 = input("Type 'DELETE' to confirm final deletion: ").strip()
    return response2 == 'DELETE'


def show_progress(message, current, total=None):
    """Show progress indicator for cleanup operations."""
    if total:
        percentage = (current / total) * 100
        print(f"🔄 {message} [{current}/{total}] ({percentage:.1f}%)")
    else:
        print(f"🔄 {message}...")


def show_device_status():
    """Display current device status and provide guidance."""
    print("📱 Device Status Check")
    print("=" * 50)
    
    try:
        # Import ADB controller here to avoid circular imports
        from scripts.utils.adb_controller import ADBController
        
        # Initialize ADB controller
        adb_controller = ADBController()
        
        # Check ADB availability
        if not adb_controller.check_adb_connection():
            print("❌ ADB not available")
            print("💡 Please install Android SDK platform-tools")
            return False
        
        # Get device information
        devices = adb_controller.get_connected_devices()
        
        if not devices:
            print("❌ No devices detected")
            print("\n📋 Connection Guide:")
            print("• Connect your Android device via USB")
            print("• Enable USB debugging in Developer Options")
            print("• Install ADB drivers if needed")
            return False
        
        print(f"📱 Found {len(devices)} device(s):")
        print()
        
        for i, device in enumerate(devices, 1):
            status_icon = "✅" if device.status.value == "device" else "⚠️" if device.status.value == "unauthorized" else "❌"
            print(f"{i}. {status_icon} {device.device_id}")
            print(f"   Status: {device.status.value}")
            if device.product:
                print(f"   Product: {device.product}")
            if device.model:
                print(f"   Model: {device.model}")
            print()
        
        print("📋 Device Guidance:")
        authorized = [d for d in devices if d.status.value == "device"]
        unauthorized = [d for d in devices if d.status.value == "unauthorized"]
        offline = [d for d in devices if d.status.value == "offline"]
        
        if not devices:
            print("• No devices detected")
            print("• Connect your Android device via USB")
            print("• Enable USB debugging in Developer Options")
            print("• Install ADB drivers if needed")
        
        if unauthorized:
            print("• Unauthorized devices detected:")
            for device in unauthorized:
                print(f"  - {device.device_id}: Authorize this device for ADB access")
        
        if offline:
            print("• Offline devices detected:")
            for device in offline:
                print(f"  - {device.device_id}: Check device connection and wake device")
        
        if authorized:
            print(f"• {len(authorized)} authorized device(s) ready for operations")
        
        return True
        
    except Exception as e:
        print(f"❌ Error checking device status: {e}")
        return False

def execute_cleanup(tracker, args):
    """Execute the main cleanup process."""
    print("🧹 Starting APK Analysis Cleanup...")
    
    if args.dry_run:
        return execute_dry_run(tracker, args)

    if args.summary_only:
        return show_resource_summary(tracker)

    if args.device_status:
        return show_device_status()

    # Confirm cleanup unless --force is used
    if not args.force:
        if not confirm_cleanup(tracker):
            print("❌ Cleanup cancelled by user")
            return False
    
    print("\n🚀 Starting cleanup execution...")
    
    # Show device status before cleanup
    print("📱 Checking device status before cleanup...")
    show_device_status()
    
    # Execute cleanup based on options
    if args.current_only:
        return cleanup_current_run(tracker, args)
    else:
        return cleanup_all_resources(tracker, args)


def execute_dry_run(tracker, args):
    """Show what would be cleaned without executing."""
    print("🔍 DRY RUN MODE - No resources will be deleted")
    print("=" * 50)
    
    # Show current run resources
    current = tracker.resources.get("current_run", {})
    if tracker._has_resources(current):
        show_run_resources("Current Run", current)
    else:
        print("\n📭 Current Run: No resources to clean")
    
    # Show archived runs resources
    archived = tracker.resources.get("runs", [])
    if archived:
        print(f"\n📚 Archived Runs ({len(archived)}):")
        for i, run in enumerate(archived, 1):
            show_run_resources(f"Archived Run {i}", run)
    else:
        print("\n📭 Archived Runs: No archived runs to clean")
    
    # Show summary
    summary = tracker.get_resource_summary()
    print("\n" + "=" * 50)
    print("📊 DRY RUN SUMMARY")
    print("=" * 50)
    print(f"Total Resources That Would Be Cleaned:")
    print(f"   • {summary['processes']} Processes")
    print(f"   • {summary['files']} Files")
    print(f"   • {summary['directories']} Directories")
    print(f"   • {summary['total_runs']} Total Runs")
    print("=" * 50)
    
    return True


def show_resource_summary(tracker):
    """Show resource summary without cleaning."""
    summary = tracker.get_resource_summary()
    
    print("\n" + "=" * 50)
    print("📊 RESOURCE SUMMARY")
    print("=" * 50)
    
    # Current run details
    current = tracker.resources.get("current_run", {})
    print(f"🔄 Current Run:")
    print(f"   • Timestamp: {current.get('timestamp', 'Unknown')}")
    print(f"   • Package: {current.get('package_name', 'None')}")
    print(f"   • APK File: {current.get('apk_filename', 'None')}")
    print(f"   • Installed: {current.get('apk_installed', False)}")
    
    # Process details
    pids = current.get("pid", {})
    if pids.get("jadx") or pids.get("vscode"):
        print(f"   • Processes:")
        if pids.get("jadx"):
            print(f"     - Jadx: PID {pids['jadx']}")
        if pids.get("vscode"):
            print(f"     - VS Code: PID {pids['vscode']}")
    
    # File and directory counts
    files = current.get("files", [])
    dirs = current.get("dirs", [])
    print(f"   • Files: {len(files)}")
    print(f"   • Directories: {len(dirs)}")
    
    # Archived runs summary
    archived = tracker.resources.get("runs", [])
    if archived:
        print(f"\n📚 Archived Runs ({len(archived)}):")
        total_archived_processes = 0
        total_archived_files = 0
        total_archived_dirs = 0
        
        for i, run in enumerate(archived, 1):
            run_pids = run.get("pid", {})
            run_files = run.get("files", [])
            run_dirs = run.get("dirs", [])
            
            total_archived_processes += sum(1 for pid in run_pids.values() if pid)
            total_archived_files += len(run_files)
            total_archived_dirs += len(run_dirs)
            
            print(f"   • Run {i}: {len(run_files)} files, {len(run_dirs)} dirs")
        
        print(f"\n📊 Archived Totals:")
        print(f"   • Processes: {total_archived_processes}")
        print(f"   • Files: {total_archived_files}")
        print(f"   • Directories: {total_archived_dirs}")
    
    # Overall summary
    print("\n" + "=" * 50)
    print(f"🔄 Total Runs: {summary['total_runs']}")
    print(f"💻 Total Processes: {summary['processes']}")
    print(f"📄 Total Files: {summary['files']}")
    print(f"📁 Total Directories: {summary['directories']}")
    print("=" * 50)
    
    return True


def show_run_resources(run_name, run_data):
    """Display resources for a specific run."""
    print(f"\n{run_name}:")
    print(f"  📅 Timestamp: {run_data.get('timestamp', 'Unknown')}")
    print(f"  📱 Package: {run_data.get('package_name', 'None')}")
    print(f"  📦 APK File: {run_data.get('apk_filename', 'None')}")
    print(f"  💾 Installed: {run_data.get('apk_installed', False)}")

    # Show PIDs
    pids = run_data.get('pid', {})
    if pids.get('jadx') or pids.get('vscode'):
        print(f"  💻 Processes:")
        if pids.get('jadx'):
            print(f"    • Jadx PID: {pids['jadx']}")
        if pids.get('vscode'):
            print(f"    • VS Code PID: {pids['vscode']}")

    # Show files
    files = run_data.get('files', [])
    if files:
        print(f"  📄 Files ({len(files)}):")
        for file_path in files:
            print(f"    • {file_path}")

    # Show directories
    dirs = run_data.get('dirs', [])
    if dirs:
        print(f"  📁 Directories ({len(dirs)}):")
        for dir_path in dirs:
            print(f"    • {dir_path}")


def cleanup_current_run(tracker, args):
    """Clean only current run."""
    print("🧹 Cleaning current run only...")
    
    try:
        # Get current run data
        current_run = tracker.resources.get("current_run", {})
        
        if not tracker._has_resources(current_run):
            print("📭 No resources in current run to clean")
            return True
        
        # Show what will be cleaned
        print("\n📋 Current Run Resources to Clean:")
        if current_run.get("pid", {}).get("jadx"):
            print(f"   • Jadx Process (PID: {current_run['pid']['jadx']})")
        if current_run.get("pid", {}).get("vscode"):
            print(f"   • VS Code Process (PID: {current_run['pid']['vscode']})")
        
        files = current_run.get("files", [])
        if files:
            print(f"   • {len(files)} Files")
            if args.verbose:
                for file_path in files:
                    print(f"     - {file_path}")
        
        dirs = current_run.get("dirs", [])
        if dirs:
            print(f"   • {len(dirs)} Directories")
            if args.verbose:
                for dir_path in dirs:
                    print(f"     - {dir_path}")
        
        if current_run.get("apk_installed") and current_run.get("package_name"):
            print(f"   • APK Package: {current_run['package_name']}")
        
        print()  # Empty line for readability
        
        # Clean current run using the enhanced method
        cleanup_results = tracker._cleanup_single_run(current_run)
        
        # Show cleanup summary
        tracker._show_cleanup_summary(cleanup_results)
        
        # Reset current run
        tracker.resources["current_run"] = {
            "timestamp": tracker.resources["current_run"]["timestamp"],  # Keep timestamp
            "package_name": None,
            "apk_filename": None,
            "apk_installed": False,
            "pid": {"jadx": None, "vscode": None},
            "files": [],
            "dirs": []
        }
        
        # Save the updated state
        tracker._save_resources()
        
        print("✅ Current run cleanup completed successfully")
        return True
        
    except Exception as e:
        print(f"❌ ERROR: Failed to cleanup current run: {e}")
        if args.verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False


def cleanup_all_resources(tracker, args):
    """Clean all resources (archived runs + current run)."""
    print("🧹 Cleaning all resources...")
    
    try:
        # Show summary of what will be cleaned
        summary = tracker.get_resource_summary()
        print(f"\n📊 Total Resources to Clean:")
        print(f"   • {summary['processes']} Processes")
        print(f"   • {summary['files']} Files")
        print(f"   • {summary['directories']} Directories")
        print(f"   • {summary['total_runs']} Runs (including archived)")
        
        if args.verbose:
            # Show detailed breakdown
            current_run = tracker.resources.get("current_run", {})
            archived_runs = tracker.resources.get("runs", [])
            
            if tracker._has_resources(current_run):
                print(f"\n📋 Current Run Resources:")
                show_run_resources("Current Run", current_run)
            
            if archived_runs:
                print(f"\n📚 Archived Runs ({len(archived_runs)}):")
                for i, run in enumerate(archived_runs, 1):
                    show_run_resources(f"Archived Run {i}", run)
        
        print()  # Empty line for readability
        
        # Use the enhanced cleanup_all method
        cleanup_results = tracker.cleanup_all()
        
        print("✅ All resources cleanup completed successfully")
        return True
        
    except Exception as e:
        print(f"❌ ERROR: Failed to cleanup all resources: {e}")
        if args.verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return False


if __name__ == "__main__":
    main()
