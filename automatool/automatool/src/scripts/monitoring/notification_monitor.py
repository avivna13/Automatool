"""
Notification Monitor for Toll Fraud Detection System

This module monitors notification listener traffic specifically from the target app
to detect suspicious patterns related to toll fraud activities.
"""

import re
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


class NotificationMonitor:
    """Monitors target app notification listener traffic for toll fraud detection."""
    
    def __init__(self, target_package: str, timeout: int = 30):
        """
        Initialize Notification Monitor.
        
        Args:
            target_package (str): Package name of the target app to monitor
            timeout (int): ADB command timeout in seconds
        """
        self.target_package = target_package
        self.adb_controller = ADBController(timeout=timeout)
        
        # Detection patterns for toll fraud
        self.fraud_patterns = {
            'premium': ['premium', 'subscription', 'billing', 'charged', 'toll', 'fraud'],
            'notification_listener': ['notification_listener', 'listener', 'notification'],
            'package_activity': ['package', 'activity', 'service'],
            'listener_events': ['listener', 'event', 'callback'],
            'listener_behavior': ['behavior', 'pattern', 'action'],
            'notification_metadata': ['metadata', 'attribute', 'property']
        }
        
        logger.info(f"Notification Monitor initialized for package: {target_package}")
    
    def get_notifications(self, package_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Get raw notification data from the target app using ADB commands.
        This method returns the raw stdout of the command without analysis.
        
        Args:
            package_name (str, optional): Override target package name
            
        Returns:
            Dict containing raw notification data
        """
        target_pkg = package_name or self.target_package
        
        logger.info(f"Fetching raw notification listeners for package: {target_pkg}")
        
        cmd = f"adb shell dumpsys notification --listeners | grep '{target_pkg}'"
        
        logger.info("="*80)
        logger.info(f"[NOTIFICATION_MONITOR] EXECUTING COMMAND FOR RAW OUTPUT: {cmd}")
        logger.info("="*80)

        result = self.adb_controller.execute_command(cmd)
        
        response = {
            'timestamp': datetime.now().isoformat(),
            'target_app': target_pkg,
            'raw_output': None,
            'error': None
        }

        if not result['success']:
            logger.error(f"Failed to get notifications: {result.get('error', 'Unknown error')}")
            response['error'] = result.get('error', 'Failed to execute ADB command')
        else:
            response['raw_output'] = result['stdout']
        
        return response
    
    def get_comprehensive_notifications(self, package_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Get comprehensive notification data including listener traffic.
        
        Args:
            package_name (str, optional): Override target package name
            
        Returns:
            Dict containing comprehensive notification analysis
        """
        target_pkg = package_name or self.target_package
        
        logger.info(f"Fetching comprehensive notifications for package: {target_pkg}")
        
        # Get basic notifications
        basic_result = self.get_notifications(target_pkg)
        
        # Get listener-specific data
        listener_cmd = f"adb shell dumpsys notification --listeners | grep '{target_pkg}'"
        listener_result = self.adb_controller.execute_command(listener_cmd)
        
        # Get package activity data
        package_cmd = f"adb shell dumpsys notification | grep -E '({target_pkg}|package|activity)' | grep '{target_pkg}'"
        package_result = self.adb_controller.execute_command(package_cmd)
        
        # Combine all results
        combined_data = basic_result['stdout'] if 'stdout' in basic_result else ""
        if listener_result['success']:
            combined_data += "\n" + listener_result['stdout']
        if package_result['success']:
            combined_data += "\n" + package_result['stdout']
        
        return self.analyze_notifications(combined_data, target_pkg)
    
    def analyze_notifications(self, raw_data: str, target_package: str) -> Dict[str, Any]:
        """
        Analyze raw notification data for suspicious patterns.
        
        Args:
            raw_data (str): Raw notification data from ADB
            target_package (str): Target package name
            
        Returns:
            Dict containing analyzed notification data
        """
        if not raw_data.strip():
            logger.warning(f"No notification data found for package: {target_package}")
            return self._create_empty_response(target_package)
        
        logger.info(f"Analyzing {len(raw_data.split(chr(10)))} lines of notification data")
        
        # Parse notifications line by line
        notifications = []
        listener_activities = 0
        package_activities = 0
        
        for line in raw_data.split(chr(10)):
            line = line.strip()
            # Explicitly filter out the raw list of all listeners
            
            # Analyze each line for patterns
            analysis = self._analyze_line(line)
            if analysis:
                notifications.append(analysis)
                
                # Count different types of activities
                if analysis['listener_activity'] in ['notification_listener', 'listener_events', 'listener_behavior']:
                    listener_activities += 1
                elif analysis['listener_activity'] in ['package_activity', 'notification_metadata']:
                    package_activities += 1
        
        # Create response
        response = {
            'timestamp': datetime.now().isoformat(),
            'target_app': target_package,
            'target_app_notifications': notifications,
            'target_app_traffic_summary': {
                'total_target_notifications': len(notifications),
                'listener_activities': listener_activities,
                'package_activities': package_activities
            }
        }
        
        logger.info(f"Analysis complete: {len(notifications)} notifications found")
        return response
    
    def _analyze_line(self, line: str) -> Optional[Dict[str, str]]:
        """
        Analyze a single line for suspicious patterns.
        
        Args:
            line (str): Single line of notification data
            
        Returns:
            Dict containing pattern analysis or None if no patterns found
        """
        line_lower = line.lower()
        
        # Check for fraud patterns
        for pattern_type, patterns in self.fraud_patterns.items():
            for pattern in patterns:
                if pattern in line_lower:
                    return {
                        'line': line,
                        'pattern': pattern,
                        'listener_activity': pattern_type
                    }
        
        # Check for general notification listener activity
        if any(keyword in line_lower for keyword in ['listener', 'notification', 'service']):
            return {
                'line': line,
                'pattern': 'general_activity',
                'listener_activity': 'notification_listener'
            }
        
        return None
    
    def _create_empty_response(self, target_package: str) -> Dict[str, Any]:
        """Create an empty response when no data is found."""
        return {
            'timestamp': datetime.now().isoformat(),
            'target_app': target_package,
            'target_app_notifications': [],
            'target_app_traffic_summary': {
                'total_target_notifications': 0,
                'listener_activities': 0,
                'package_activities': 0
            }
        }
    
    def get_suspicious_notifications(self, package_name: Optional[str] = None) -> List[Dict[str, str]]:
        """
        Get only suspicious notifications (those matching fraud patterns).
        
        Args:
            package_name (str, optional): Override target package name
            
        Returns:
            List of suspicious notifications
        """
        all_notifications = self.get_notifications(package_name)
        suspicious = []
        
        for notification in all_notifications.get('target_app_notifications', []):
            if notification['pattern'] in self.fraud_patterns['premium']:
                suspicious.append(notification)
        
        return suspicious
    
    def get_traffic_summary(self, package_name: Optional[str] = None) -> Dict[str, int]:
        """
        Get a summary of notification traffic for the target app.
        
        Args:
            package_name (str, optional): Override target package name
            
        Returns:
            Dict containing traffic summary
        """
        notifications = self.get_notifications(package_name)
        return notifications.get('target_app_traffic_summary', {})
    
    def is_connected(self) -> bool:
        """Check if ADB is connected to a device."""
        return self.adb_controller.check_adb_connection()


# Convenience function for quick notification monitoring
def monitor_target_app_notifications(target_package: str) -> Dict[str, Any]:
    """
    Quick function to monitor notifications for a target app.
    
    Args:
        target_package (str): Package name of the target app
        
    Returns:
        Dict containing notification analysis
    """
    monitor = NotificationMonitor(target_package)
    return monitor.get_notifications()


if __name__ == "__main__":
    # Test the Notification Monitor
    print("Testing Notification Monitor...")
    
    # Test with a sample package name
    test_package = "com.example.app"
    monitor = NotificationMonitor(test_package)
    
    if monitor.is_connected():
        print("✅ ADB connection successful")
        
        # Test basic notification monitoring
        result = monitor.get_notifications()
        print(f"📱 Basic monitoring result: {result['target_app_traffic_summary']}")
        
        # Test comprehensive monitoring
        comprehensive = monitor.get_comprehensive_notifications()
        print(f"🔍 Comprehensive monitoring result: {comprehensive['target_app_traffic_summary']}")
        
        # Test suspicious notifications
        suspicious = monitor.get_suspicious_notifications()
        print(f"⚠️ Suspicious notifications found: {len(suspicious)}")
        
    else:
        print("❌ ADB connection failed")
        print("Make sure ADB is installed and device is connected")
