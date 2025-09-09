#!/usr/bin/env python3
"""
APK Analysis Automation Tool


This tool automates the APK analysis workflow including:
- VPN verification
- Tool validation  
- Jadx GUI launch
- VS Code workspace setup
- Reviews scraping
- APK assets image steganography analysis
- Frida scripts preparation with package name injection


Author: Generated for APK Analysis Automation
"""


import argparse
import os

### UTILS IMPORTS ###
from scripts.utils.validators import verify_vpn_connection
from scripts.utils.utils import extract_package_name_with_fallback

### AUTOMATIONS IMPORTS ###
from scripts.automations.init import validate_files
from scripts.automations.launch_jadx import launch_jadx_gui
from scripts.automations.launch_vscode import launch_vscode
from scripts.automations.run_reviews_with_parsing import run_reviews_with_parsing
from scripts.automations.merge_app_intelligence import merge_app_intelligence
from scripts.automations.copy_frida_scripts import copy_frida_scripts, update_frida_scripts_with_package_name
from scripts.automations.install_apk import install_apk_on_device
from scripts.automations.parse_yara_results import parse_yara_to_summary
from scripts.automations.generate_research_plan import generate_research_plan
from scripts.automations.resource_tracker import GlobalResourceTracker


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Automate APK analysis workflow with VPN verification, tool integration, and Frida script preparation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d "/home/user/analysis/myapp" -f "myapp.apk"
  %(prog)s -d "/opt/apk-samples" -f "target.apk" --verbose
  %(prog)s -d "/home/user/Downloads" -f "app.apk" --install
        """
    )
   
    parser.add_argument(
        "-d", "--directory",
        required=True,
        help="Target directory containing the APK file"
    )
   
    parser.add_argument(
        "-f", "--filename",
        required=True,
        help="Filename of the APK to analyze"
    )
   
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output for debugging"
    )
   
    parser.add_argument(
        "--install",
        action="store_true",
        help="Install APK on connected Android device via ADB"
    )
   
    parser.add_argument(
        "--skip-assets-analysis",
        action="store_true",
        help="Skip APK assets image steganography analysis"
    )
   
    parser.add_argument(
        "--skip-font-analysis",
        action="store_true",
        help="Skip TTF font steganography analysis"
    )
   
    return parser.parse_args()


def main():
    """Main entry point for the APK analysis automation tool."""
    print("--- Starting APK Analysis Automation ---")
   
    # Parse command line arguments
    args = parse_arguments()
   
    if args.verbose:
        print(f"[DEBUG] Target directory: {args.directory}")
        print(f"[DEBUG] APK filename: {args.filename}")
   
    # Initialize global resource tracker
    try:
        resource_tracker = GlobalResourceTracker()
        
        # Clean up all existing resources before starting new run
        print("🧹 Cleaning up previous resources before starting new analysis...")
        resource_tracker.cleanup_all()
        
        resource_tracker.start_new_run()
    except Exception as e:
        print(f"❌ ERROR: Failed to initialize resource tracker: {e}")
        if args.verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        raise  # Stop automation on resource tracking failure
   
    # Verify VPN connection
    verify_vpn_connection(args.verbose)
   
    # Validate files and get full APK path
    apk_path = validate_files(args.directory, args.filename, args.verbose)

   
    # Extract package name from APK
    package_name = extract_package_name_with_fallback(apk_path, args.verbose)
    
    # Track package name and APK filename for current run
    try:
        resource_tracker.set_package_name(package_name)
        resource_tracker.set_apk_filename(args.filename)
    except Exception as e:
        print(f"❌ ERROR: Failed to track package information: {e}")
        if args.verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
   
    # APK Unmask analysis moved to standalone UI service for better performance
    print("⏭️ Skipping APK Unmask analysis (use standalone UI service for this feature)")
   
    # Launch APK assets image steganography analysis (unless skipped)
    if not getattr(args, 'skip_assets_analysis', False):
        print("⏭️ Skipping assets analysis - requires decompilation (use standalone service first)")
    else:
        print("⏭️ Skipping APK assets image analysis (--skip-assets-analysis)")
   
    # Launch Jadx GUI for APK analysis
    jadx_process = launch_jadx_gui(apk_path, args.verbose)
    if jadx_process:
        try:
            resource_tracker.add_process("jadx", jadx_process.pid)
        except Exception as e:
            print(f"❌ ERROR: Failed to track Jadx process: {e}")
            if args.verbose:
                print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
   
    # Launch VS Code workspace
    vscode_process = launch_vscode(args.directory, args.verbose)
    if vscode_process:
        try:
            resource_tracker.add_process("vscode", vscode_process.pid)
        except Exception as e:
            print(f"❌ ERROR: Failed to track VS Code process: {e}")
            if args.verbose:
                print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
   
    # Run reviews scraper and parser with threading
    reviews = run_reviews_with_parsing(package_name, args.directory, args.verbose)
    
    # Track reviews files
    reviews_json_path = os.path.join(args.directory, "reviews.json")
    reviews_summary_path = os.path.join(args.directory, "reviews_summary.txt")
    
    # Track reviews files with error handling
    try:
        if os.path.exists(reviews_json_path):
            resource_tracker.add_file(reviews_json_path)
        if os.path.exists(reviews_summary_path):
            resource_tracker.add_file(reviews_summary_path)
    except Exception as e:
        print(f"❌ ERROR: Failed to track reviews files: {e}")
        if args.verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
   
    # Copy Frida scripts to target directory
    copy_frida_scripts(args.directory, args.verbose)
    
    # Track Frida scripts directory
    frida_scripts_dir = os.path.join(args.directory, "frida_scripts")
    try:
        resource_tracker.add_directory(frida_scripts_dir)
    except Exception as e:
        print(f"❌ ERROR: Failed to track Frida scripts directory: {e}")
        if args.verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
   
    # Update Frida scripts with extracted package name
    update_frida_scripts_with_package_name(args.directory, package_name, args.verbose)
   
    # Parse YARA results if available
    yara_summary = parse_yara_to_summary(args.directory, args.verbose)
    
    # Track YARA files
    yara_json_path = os.path.join(args.directory, "yara.json")
    yara_summary_path = os.path.join(args.directory, "yara_summary.txt")
    
    # Track YARA files with error handling
    try:
        if os.path.exists(yara_json_path):
            resource_tracker.add_file(yara_json_path)
        if os.path.exists(yara_summary_path):
            resource_tracker.add_file(yara_summary_path)
    except Exception as e:
        print(f"❌ ERROR: Failed to track YARA files: {e}")
        if args.verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
    
    # Generate research plan from summaries
    research_plan_path = generate_research_plan(args.directory, reviews, yara_summary, args.verbose)
    if research_plan_path:
        try:
            resource_tracker.add_file(research_plan_path)
            # Track prompts directory
            prompts_dir = os.path.join(args.directory, "prompts")
            resource_tracker.add_directory(prompts_dir)
        except Exception as e:
            print(f"❌ ERROR: Failed to track research plan resources: {e}")
            if args.verbose:
                print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
    
    # Install APK on device if requested
    if args.install:
        install_success = install_apk_on_device(apk_path, args.verbose)
        if install_success:
            try:
                resource_tracker.mark_apk_installed()
            except Exception as e:
                print(f"❌ ERROR: Failed to track APK installation status: {e}")
                if args.verbose:
                    print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
   
    print("--- APK Analysis Automation Complete ---")


if __name__ == "__main__":
    main()
