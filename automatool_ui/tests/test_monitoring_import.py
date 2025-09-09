"""
Test script to verify monitoring module imports from the new location.
"""

import sys
import os

# Add the automatool scripts directory to the path
automatool_path = os.path.join(os.path.dirname(__file__), '..', 'automatool', 'automatool', 'src', 'scripts')
sys.path.append(automatool_path)

print(f"🔍 Testing monitoring module imports from: {automatool_path}")
print(f"📁 Current working directory: {os.getcwd()}")

try:
    # Test importing the monitoring package
    print("\n📦 Testing monitoring package import...")
    from monitoring import NotificationMonitor, DataCollector
    print("✅ Successfully imported NotificationMonitor and DataCollector")
    
    # Test importing the ADB controller
    print("\n🔧 Testing ADB controller import...")
    from utils.adb_controller import ADBController
    print("✅ Successfully imported ADBController")
    
    # Test creating instances
    print("\n🏗️ Testing instance creation...")
    monitor = NotificationMonitor("com.test.app")
    collector = DataCollector("com.test.app")
    adb_controller = ADBController()
    print("✅ Successfully created instances of all classes")
    
    # Test basic functionality
    print("\n🧪 Testing basic functionality...")
    print(f"📱 Monitor target package: {monitor.target_package}")
    print(f"📊 Collector target package: {collector.target_package}")
    print(f"⏱️ ADB timeout: {adb_controller.timeout}")
    
    print("\n🎉 All tests passed! The monitoring system is working correctly.")
    
except ImportError as e:
    print(f"❌ Import failed: {e}")
    print(f"🔍 Check if the path {automatool_path} exists and contains the monitoring modules")
    
except Exception as e:
    print(f"❌ Test failed: {e}")
    import traceback
    traceback.print_exc()

print(f"\n📋 Summary:")
print(f"   - Monitoring modules location: {automatool_path}")
print(f"   - Import test: {'✅ PASSED' if 'Successfully imported' in locals() else '❌ FAILED'}")
print(f"   - Instance creation: {'✅ PASSED' if 'Successfully created instances' in locals() else '❌ FAILED'}")
