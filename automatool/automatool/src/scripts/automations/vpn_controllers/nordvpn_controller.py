"""
NordVPN implementation of VPN controller.

Wraps the existing NordVpn class from VPNSwitcher.py to provide
a standardized interface for VPN operations.
"""

from typing import Optional, List
from .base import VPNController
from .vpn_switcher import NordVpn


class NordVPNController(VPNController):
    """NordVPN implementation of VPN controller."""
    
    def connect(self, country: str) -> bool:
        """Connect to NordVPN in specified country."""
        try:
            result = NordVpn.change_vpn_country(country)
            # Check if result indicates success
            if isinstance(result, str) and "Successfully connected" in result:
                return True
            elif isinstance(result, str) and "Already connected" in result:
                return True
            else:
                print(f"NordVPN connection failed: {result}")
                return False
        except Exception as e:
            print(f"NordVPN connection error: {e}")
            return False
    
    def get_current_country(self) -> Optional[str]:
        """Get current NordVPN country."""
        try:
            result = NordVpn.get_current_country()
            # Handle error strings returned by the original implementation
            if isinstance(result, str) and ("error occurred" in result.lower() or "subprocess error" in result.lower()):
                print(f"NordVPN status error: {result}")
                return None
            return result
        except Exception as e:
            print(f"NordVPN status error: {e}")
            return None
    
    def is_connected(self) -> bool:
        """Check if NordVPN is connected."""
        current = self.get_current_country()
        return current is not None and current != "" and not isinstance(current, str) or not current.startswith("error") if isinstance(current, str) else True
    
    def get_available_countries(self) -> Optional[List[str]]:
        """Get available NordVPN countries."""
        try:
            result = NordVpn.get_available_countries()
            # Handle error strings returned by the original implementation
            if isinstance(result, str) and "error occurred" in result.lower():
                print(f"NordVPN countries error: {result}")
                return None
            return result
        except Exception as e:
            print(f"NordVPN countries error: {e}")
            return None
