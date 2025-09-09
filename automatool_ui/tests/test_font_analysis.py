#!/usr/bin/env python3
"""
Test script for font analysis integration in automatool_ui.
This script tests the font analysis functionality without running the full UI.
"""

import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.process_manager import ProcessManager


def test_font_analysis():
    """Test the font analysis functionality."""
    print("🧪 Testing Font Analysis Integration")
    print("=" * 50)
    
    # Initialize process manager
    process_manager = ProcessManager()
    
    # Test directory (create a temporary one)
    test_output_dir = os.path.join(os.path.dirname(__file__), "test_font_analysis")
    os.makedirs(test_output_dir, exist_ok=True)
    
    print(f"📁 Test output directory: {test_output_dir}")
    
    # Test font analysis execution
    try:
        print("🔤 Executing font analysis...")
        success = process_manager.execute_font_analysis(
            test_output_dir,  # Use test directory as both source and output
            test_output_dir,
            verbose=True
        )
        
        if success:
            print("✅ Font analysis started successfully!")
            print("📊 Process status:", process_manager.get_status())
        else:
            print("❌ Font analysis failed to start")
            
    except Exception as e:
        print(f"❌ Error during font analysis: {e}")
        import traceback
        traceback.print_exc()
    
    # Cleanup
    try:
        import shutil
        shutil.rmtree(test_output_dir)
        print(f"🧹 Cleaned up test directory: {test_output_dir}")
    except Exception as e:
        print(f"⚠️ Warning: Could not clean up test directory: {e}")


if __name__ == "__main__":
    test_font_analysis()
