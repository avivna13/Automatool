"""
SMS/Call Monitor for Toll Fraud Detection System

This module monitors SMS and call activities specifically from the target app
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


class SMSCallMonitor:
    """Monitors target app SMS and call activities for toll fraud detection."""
    
    def __init__(self, target_package: str, timeout: int = 30):
        """
        Initialize SMS/Call Monitor.
        
        Args:
            target_package (str): Package name of the target app to monitor
            timeout (int): ADB command timeout in seconds
        """
        self.target_package = target_package
        self.adb_controller = ADBController(timeout=timeout)
        
        # Detection patterns for toll fraud
        self.sms_patterns = ['subscribed', 'premium', 'service', 'charge', 'billing']
        self.call_patterns = ['short_duration_premium']  # Calls under 30 seconds to premium numbers
        
        # Premium number patterns (common toll fraud numbers)
        self.premium_number_patterns = [
            r'\+1[0-9]{10}',  # US premium numbers
            r'\+44[0-9]{10}', # UK premium numbers
            r'\+49[0-9]{10}', # German premium numbers
            r'\+33[0-9]{9}',  # French premium numbers
        ]
        
        logger.info(f"SMS/Call Monitor initialized for package: {target_package}")
    
    def get_sms_logs(self, package_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Get SMS logs from the target app using ADB commands.
        
        Args:
            package_name (str, optional): Override target package name
            
        Returns:
            Dict containing SMS data and analysis
        """
        target_pkg = package_name or self.target_package
        
        logger.info(f"Fetching SMS logs for package: {target_pkg}")
        
        # Execute ADB command to get SMS logs
        cmd = f"adb shell dumpsys telephony.registry | grep '{target_pkg}'"
        result = self.adb_controller.execute_command(cmd)
        
        if not result['success']:
            logger.error(f"Failed to get SMS logs: {result.get('error', 'Unknown error')}")
            return {
                'timestamp': datetime.now().isoformat(),
                'target_app': target_pkg,
                'error': result.get('error', 'Failed to execute ADB command'),
                'target_app_sms': []
            }
        
        # Analyze the SMS data
        return self.analyze_sms_data(result['stdout'], target_pkg)
    
    def get_call_logs(self, package_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Get call logs from the target app using ADB commands.
        
        Args:
            package_name (str, optional): Override target package name
            
        Returns:
            Dict containing call data and analysis
        """
        target_pkg = package_name or self.target_package
        
        logger.info(f"Fetching call logs for package: {target_pkg}")
        
        # Execute ADB command to get call logs
        cmd = f"adb shell dumpsys telephony.registry | grep '{target_pkg}'"
        result = self.adb_controller.execute_command(cmd)
        
        if not result['success']:
            logger.error(f"Failed to get call logs: {result.get('error', 'Unknown error')}")
            return {
                'timestamp': datetime.now().isoformat(),
                'target_app': target_pkg,
                'error': result.get('error', 'Failed to execute ADB command'),
                'target_app_calls': []
            }
        
        # Analyze the call data
        return self.analyze_call_data(result['stdout'], target_pkg)
    
    def get_telephony_data(self, package_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Get comprehensive telephony data (SMS and calls) from the target app.
        
        Args:
            package_name (str, optional): Override target package name
            
        Returns:
            Dict containing comprehensive telephony analysis
        """
        target_pkg = package_name or self.target_package
        
        logger.info(f"Fetching comprehensive telephony data for package: {target_pkg}")
        
        # Get SMS data
        sms_data = self.get_sms_logs(target_pkg)
        
        # Get call data
        call_data = self.get_call_logs(target_pkg)
        
        # Combine results
        combined_result = {
            'timestamp': datetime.now().isoformat(),
            'target_app': target_pkg,
            'target_app_sms': sms_data.get('target_app_sms', []),
            'target_app_calls': call_data.get('target_app_calls', [])
        }
        
        return combined_result
    
    def analyze_sms_data(self, raw_data: str, target_package: str) -> Dict[str, Any]:
        """
        Analyze raw SMS data for suspicious patterns.
        
        Args:
            raw_data (str): Raw SMS data from ADB
            target_package (str): Target package name
            
        Returns:
            Dict containing analyzed SMS data
        """
        if not raw_data.strip():
            logger.warning(f"No SMS data found for package: {target_package}")
            return {
                'timestamp': datetime.now().isoformat(),
                'target_app': target_package,
                'target_app_sms': []
            }
        
        logger.info(f"Analyzing SMS data for package: {target_package}")
        
        # Parse SMS data line by line
        sms_entries = []
        
        for line in raw_data.split(chr(10)):
            line = line.strip()
            if not line:
                continue
            
            # Analyze each line for SMS patterns
            analysis = self._analyze_sms_line(line)
            if analysis:
                sms_entries.append(analysis)
        
        # Create response
        response = {
            'timestamp': datetime.now().isoformat(),
            'target_app': target_package,
            'target_app_sms': sms_entries
        }
        
        logger.info(f"SMS analysis complete: {len(sms_entries)} entries found")
        return response
    
    def analyze_call_data(self, raw_data: str, target_package: str) -> Dict[str, Any]:
        """
        Analyze raw call data for suspicious patterns.
        
        Args:
            raw_data (str): Raw call data from ADB
            target_package (str): Target package name
            
        Returns:
            Dict containing analyzed call data
        """
        if not raw_data.strip():
            logger.warning(f"No call data found for package: {target_package}")
            return {
                'timestamp': datetime.now().isoformat(),
                'target_app': target_package,
                'target_app_calls': []
            }
        
        logger.info(f"Analyzing call data for package: {target_package}")
        
        # Parse call data line by line
        call_entries = []
        
        for line in raw_data.split(chr(10)):
            line = line.strip()
            if not line:
                continue
            
            # Analyze each line for call patterns
            analysis = self._analyze_call_line(line)
            if analysis:
                call_entries.append(analysis)
        
        # Create response
        response = {
            'timestamp': datetime.now().isoformat(),
            'target_app': target_package,
            'target_app_calls': call_entries
        }
        
        logger.info(f"Call analysis complete: {len(call_entries)} entries found")
        return response
    
    def _analyze_sms_line(self, line: str) -> Optional[Dict[str, str]]:
        """
        Analyze a single SMS line for suspicious patterns.
        
        Args:
            line (str): Single line of SMS data
            
        Returns:
            Dict containing SMS analysis or None if no patterns found
        """
        line_lower = line.lower()
        
        # Check for SMS fraud patterns
        for pattern in self.sms_patterns:
            if pattern in line_lower:
                # Extract phone number if present
                phone_number = self._extract_phone_number(line)
                
                return {
                    'number': phone_number or 'Unknown',
                    'message': line[:100] + '...' if len(line) > 100 else line,
                    'pattern': pattern
                }
        
        # Check for premium number patterns
        for pattern in self.premium_number_patterns:
            if re.search(pattern, line):
                phone_number = re.search(pattern, line).group()
                return {
                    'number': phone_number,
                    'message': line[:100] + '...' if len(line) > 100 else line,
                    'pattern': 'premium_number'
                }
        
        return None
    
    def _analyze_call_line(self, line: str) -> Optional[Dict[str, str]]:
        """
        Analyze a single call line for suspicious patterns.
        
        Args:
            line (str): Single line of call data
            
        Returns:
            Dict containing call analysis or None if no patterns found
        """
        line_lower = line.lower()
        
        # Check for call fraud patterns
        for pattern in self.call_patterns:
            if pattern in line_lower:
                # Extract phone number if present
                phone_number = self._extract_phone_number(line)
                
                # Extract duration if present
                duration = self._extract_call_duration(line)
                
                return {
                    'number': phone_number or 'Unknown',
                    'duration': duration or 'Unknown',
                    'pattern': pattern
                }
        
        # Check for premium number patterns
        for pattern in self.premium_number_patterns:
            if re.search(pattern, line):
                phone_number = re.search(pattern, line).group()
                duration = self._extract_call_duration(line)
                
                return {
                    'number': phone_number,
                    'duration': duration or 'Unknown',
                    'pattern': 'premium_number_call'
                }
        
        return None
    
    def _extract_phone_number(self, line: str) -> Optional[str]:
        """
        Extract phone number from a line of text.
        
        Args:
            line (str): Line of text to search
            
        Returns:
            Phone number if found, None otherwise
        """
        # Look for common phone number patterns
        phone_patterns = [
            r'\+?[0-9]{10,15}',  # International format
            r'[0-9]{3}-[0-9]{3}-[0-9]{4}',  # US format
            r'[0-9]{10}',  # 10-digit format
        ]
        
        for pattern in phone_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group()
        
        return None
    
    def _extract_call_duration(self, line: str) -> Optional[str]:
        """
        Extract call duration from a line of text.
        
        Args:
            line (str): Line of text to search
            
        Returns:
            Call duration if found, None otherwise
        """
        # Look for duration patterns (e.g., "00:00:15", "15s", "15 seconds")
        duration_patterns = [
            r'([0-9]{2}):([0-9]{2}):([0-9]{2})',  # HH:MM:SS format
            r'([0-9]+)s',  # Seconds format
            r'([0-9]+)\s*seconds',  # "seconds" format
        ]
        
        for pattern in duration_patterns:
            match = re.search(pattern, line)
            if match:
                if ':' in pattern:
                    return f"{match.group(1)}:{match.group(2)}:{match.group(3)}"
                else:
                    return f"00:00:{match.group(1)}"
        
        return None
    
    def get_suspicious_sms(self, package_name: Optional[str] = None) -> List[Dict[str, str]]:
        """
        Get only suspicious SMS entries (those matching fraud patterns).
        
        Args:
            package_name (str, optional): Override target package name
            
        Returns:
            List of suspicious SMS entries
        """
        sms_data = self.get_sms_logs(package_name)
        suspicious = []
        
        for sms in sms_data.get('target_app_sms', []):
            if sms['pattern'] in self.sms_patterns or sms['pattern'] == 'premium_number':
                suspicious.append(sms)
        
        return suspicious
    
    def get_suspicious_calls(self, package_name: Optional[str] = None) -> List[Dict[str, str]]:
        """
        Get only suspicious call entries (those matching fraud patterns).
        
        Args:
            package_name (str, optional): Override target package name
            
        Returns:
            List of suspicious call entries
        """
        call_data = self.get_call_logs(package_name)
        suspicious = []
        
        for call in call_data.get('target_app_calls', []):
            if call['pattern'] in self.call_patterns or call['pattern'] == 'premium_number_call':
                suspicious.append(call)
        
        return suspicious
    
    def is_connected(self) -> bool:
        """Check if ADB is connected to a device."""
        return self.adb_controller.check_adb_connection()


# Convenience function for quick SMS/Call monitoring
def monitor_target_app_telephony(target_package: str) -> Dict[str, Any]:
    """
    Quick function to monitor SMS and calls for a target app.
    
    Args:
        target_package (str): Package name of the target app
        
    Returns:
        Dict containing telephony analysis
    """
    monitor = SMSCallMonitor(target_package)
    return monitor.get_telephony_data()


if __name__ == "__main__":
    # Test the SMS/Call Monitor
    print("Testing SMS/Call Monitor...")
    
    # Test with a sample package name
    test_package = "com.example.app"
    monitor = SMSCallMonitor(test_package)
    
    if monitor.is_connected():
        print("✅ ADB connection successful")
        
        # Test SMS monitoring
        sms_result = monitor.get_sms_logs()
        print(f"📱 SMS monitoring result: {len(sms_result.get('target_app_sms', []))} entries")
        
        # Test call monitoring
        call_result = monitor.get_call_logs()
        print(f"📞 Call monitoring result: {len(call_result.get('target_app_calls', []))} entries")
        
        # Test comprehensive telephony monitoring
        telephony_result = monitor.get_telephony_data()
        print(f"🔍 Comprehensive telephony result: {len(telephony_result.get('target_app_sms', []))} SMS, {len(telephony_result.get('target_app_calls', []))} calls")
        
        # Test suspicious entries
        suspicious_sms = monitor.get_suspicious_sms()
        suspicious_calls = monitor.get_suspicious_calls()
        print(f"⚠️ Suspicious SMS: {len(suspicious_sms)}, Suspicious calls: {len(suspicious_calls)}")
        
    else:
        print("❌ ADB connection failed")
        print("Make sure ADB is installed and device is connected")
