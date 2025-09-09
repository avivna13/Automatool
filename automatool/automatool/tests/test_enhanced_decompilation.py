#!/usr/bin/env python3
"""
Test script for enhanced APK decompilation functionality.

This script demonstrates the new comprehensive APK decompilation
that combines apktool (resources) and Jadx (Java source code).
"""

import os
import sys

# Add the parent directory to the path to import the module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from run_apktool_decode import (
    run_apktool_decode, 
    get_decompilation_summary,
    get_java_files_count
)


def test_enhanced_decompilation():
    """Test the enhanced APK decompilation functionality."""
    
    # Example usage - replace with actual APK path
    apk_path = input("Enter the path to your APK file: ").strip()
    
    if not apk_path or not os.path.exists(apk_path):
        print("❌ Invalid APK path provided")
        return
    
    # Create output directory
    output_dir = os.path.join(os.path.dirname(apk_path), "decompilation_test")
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"🔧 Testing enhanced APK decompilation...")
    print(f"📁 APK: {apk_path}")
    print(f"📁 Output: {output_dir}")
    print("=" * 60)
    
    # Run the enhanced decompilation
    results = run_apktool_decode(apk_path, output_dir, verbose=True)
    
    print("\n" + "=" * 60)
    print("📊 FINAL RESULTS")
    print("=" * 60)
    
    # Display detailed summary
    summary = get_decompilation_summary(results)
    print(summary)
    
    # Additional analysis
    if results['jadx_output']:
        java_count = get_java_files_count(results['jadx_output'])
        print(f"\n🔍 Java Source Code Analysis:")
        print(f"   📝 Total Java files: {java_count}")
        
        if java_count > 0:
            print(f"   📁 Java source location: {results['jadx_output']}")
            print(f"   💡 You can now analyze the Java source code for:")
            print(f"      • Base64 strings detection")
            print(f"      • Code analysis")
            print(f"      • Security review")
    
    if results['apktool_output']:
        print(f"\n📦 Resource Analysis:")
        print(f"   📁 Resources location: {results['apktool_output']}")
        print(f"   💡 You can now analyze:")
        print(f"      • AndroidManifest.xml")
        print(f"      • Assets and resources")
        print(f"      • Native libraries (.so files)")
        print(f"      • Image files for steganography")
    
    print(f"\n🎯 Next Steps:")
    if results['success']:
        print(f"   ✅ Decompilation successful! You can now:")
        print(f"      1. Use the Java source code for analysis")
        print(f"      2. Analyze resources and assets")
        print(f"      3. Run your existing automations on the output")
    else:
        print(f"   ❌ Decompilation had issues. Check the errors above.")
    
    return results


if __name__ == "__main__":
    try:
        test_enhanced_decompilation()
    except KeyboardInterrupt:
        print("\n\n⏹️ Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
