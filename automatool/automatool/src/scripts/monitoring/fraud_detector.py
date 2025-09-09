"""
Simple Data Collector for Toll Fraud Detection System

This module simply collects and outputs notification data from the target app
without analysis - you can analyze the raw data later as needed.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import sys
import os

# Add the utils directory to the path to import ADBController
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'utils'))
from adb_controller import ADBController

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DataCollector:
    """Simple collector that gathers notification data without analysis."""
    
    def __init__(self, target_package: str, timeout: int = 30):
        """
        Initialize Data Collector.
        
        Args:
            target_package (str): Package name of the target app to monitor
            timeout (int): ADB command timeout in seconds
        """
        self.target_package = target_package
        self.adb_controller = ADBController(timeout=timeout)
        logger.info(f"Data Collector initialized for package: {target_package}")
    
    def collect_notifications(self, notification_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simply collect and format notification data without analysis.
        
        Args:
            notification_data (Dict): Notification data from NotificationMonitor
            
        Returns:
            Dict containing collected notification data
        """
        if not notification_data or 'target_app_notifications' not in notification_data:
            logger.warning("No notification data provided for collection")
            return self._create_empty_collection()
        
        notifications = notification_data.get('target_app_notifications', [])
        target_app = notification_data.get('target_app', self.target_package)
        
        logger.info(f"Collected {len(notifications)} notifications from {target_app}")
        
        # Simple collection without analysis
        response = {
            'timestamp': datetime.now().isoformat(),
            'target_app': target_app,
            'total_notifications': len(notifications),
            'raw_notifications': notifications,
            'collection_summary': {
                'lines_collected': len(notifications),
                'collection_time': datetime.now().isoformat()
            }
        }
        
        return response
    
    def _create_empty_collection(self) -> Dict[str, Any]:
        """Create an empty collection response."""
        return {
            'timestamp': datetime.now().isoformat(),
            'target_app': self.target_package,
            'total_notifications': 0,
            'raw_notifications': [],
            'collection_summary': {
                'lines_collected': 0,
                'collection_time': datetime.now().isoformat()
            }
        }
    
    def is_connected(self) -> bool:
        """Check if ADB is connected to a device."""
        return self.adb_controller.check_adb_connection()


# Convenience function for quick data collection
def collect_target_app_data(target_package: str, notification_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Quick function to collect notification data from target app.
    
    Args:
        target_package (str): Package name of the target app
        notification_data (Dict): Notification data to collect
        
    Returns:
        Dict containing collected data
    """
    collector = DataCollector(target_package)
    return collector.collect_notifications(notification_data)


if __name__ == "__main__":
    # Test the Data Collector
    print("Testing Data Collector...")
    
    # Test with sample notification data
    test_package = "com.example.app"
    test_notifications = {
        'target_app': test_package,
        'target_app_notifications': [
            {
                'line': 'android:title=Premium Service Subscription',
                'pattern': 'premium',
                'listener_activity': 'notification_listener'
            },
            {
                'line': 'android:text=Your account will be charged $9.99',
                'pattern': 'charged',
                'listener_activity': 'notification_listener'
            }
        ]
    }
    
    collector = DataCollector(test_package)
    
    if collector.is_connected():
        print("✅ ADB connection successful")
        
        # Test data collection
        result = collector.collect_notifications(test_notifications)
        print(f"📊 Collection result: {result['total_notifications']} notifications")
        print(f"📝 Raw data: {result['raw_notifications']}")
        
    else:
        print("❌ ADB connection failed")
        print("Make sure ADB is installed and device is connected")
