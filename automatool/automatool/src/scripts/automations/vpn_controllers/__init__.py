"""
VPN Controllers Module

Provides abstract interface and implementations for VPN providers.
Currently supports NordVPN for geographic location control.
"""

from .base import VPNController
from .nordvpn_controller import NordVPNController

def get_vpn_controller(provider: str) -> VPNController:
    """
    Factory function to get VPN controller instance.
    
    Args:
        provider: VPN provider name ("nordvpn")
        
    Returns:
        VPNController: Appropriate controller instance
        
    Raises:
        ValueError: If provider is not supported
    """
    providers = {
        "nordvpn": NordVPNController,
    }
    
    if provider.lower() not in providers:
        raise ValueError(f"Unsupported VPN provider: {provider}. "
                        f"Supported providers: {list(providers.keys())}")
    
    return providers[provider.lower()]()

__all__ = ['VPNController', 'NordVPNController', 'get_vpn_controller']
