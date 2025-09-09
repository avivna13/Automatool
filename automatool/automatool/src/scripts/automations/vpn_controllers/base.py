"""
Abstract base interface for VPN controllers.

Defines the common interface that all VPN provider implementations must follow.
"""

from abc import ABC, abstractmethod
from typing import Optional, List


class VPNController(ABC):
    """Abstract interface for VPN providers."""
    
    @abstractmethod
    def connect(self, country: str) -> bool:
        """
        Connect to VPN in specified country.
        
        Args:
            country: Target country code or name
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        pass
    
    @abstractmethod
    def get_current_country(self) -> Optional[str]:
        """
        Get current VPN country.
        
        Returns:
            str: Current country code/name or None if not connected
        """
        pass
    
    @abstractmethod
    def is_connected(self) -> bool:
        """
        Check if VPN is connected.
        
        Returns:
            bool: True if connected, False otherwise
        """
        pass
    
    @abstractmethod
    def get_available_countries(self) -> Optional[List[str]]:
        """
        Get list of available countries.
        
        Returns:
            List[str]: Available country codes/names or None on error
        """
        pass
