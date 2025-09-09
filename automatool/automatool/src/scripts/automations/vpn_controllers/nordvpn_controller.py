"""
NordVPN implementation of VPN controller.

Wraps the existing NordVpn class from VPNSwitcher.py to provide
a standardized interface for VPN operations.
"""

from typing import Optional, List, Dict
from .base import VPNController
from .vpn_switcher import NordVpn


class NordVPNController(VPNController):
    """NordVPN implementation of VPN controller."""
    
    # Mapping from user-friendly country names to NordVPN country names
    COUNTRY_MAPPING: Dict[str, str] = {
        'costarica': 'Costa_Rica',
        'costa rica': 'Costa_Rica',
        'southafrica': 'South_Africa',
        'south africa': 'South_Africa',
        'united states': 'United_States',
        'unitedstates': 'United_States',
        'usa': 'United_States',
        'united kingdom': 'United_Kingdom',
        'unitedkingdom': 'United_Kingdom',
        'uk': 'United_Kingdom',
        'czech republic': 'Czech_Republic',
        'czechrepublic': 'Czech_Republic',
        'dominican republic': 'Dominican_Republic',
        'dominicanrepublic': 'Dominican_Republic',
        'el salvador': 'El_Salvador',
        'elsalvador': 'El_Salvador',
        'hong kong': 'Hong_Kong',
        'hongkong': 'Hong_Kong',
        'new zealand': 'New_Zealand',
        'newzealand': 'New_Zealand',
        'south korea': 'South_Korea',
        'southkorea': 'South_Korea',
        'united arab emirates': 'United_Arab_Emirates',
        'unitedarabemirates': 'United_Arab_Emirates',
        'uae': 'United_Arab_Emirates',
        'bosnia and herzegovina': 'Bosnia_And_Herzegovina',
        'bosniaandherzegovina': 'Bosnia_And_Herzegovina',
        'trinidad and tobago': 'Trinidad_And_Tobago',
        'trinidadandtobago': 'Trinidad_And_Tobago',
        'lao peoples democratic republic': 'Lao_Peoples_Democratic_Republic',
        'laos': 'Lao_Peoples_Democratic_Republic',
        'brunei darussalam': 'Brunei_Darussalam',
        'brunei': 'Brunei_Darussalam',
        'cayman islands': 'Cayman_Islands',
        'caymanislands': 'Cayman_Islands',
        'isle of man': 'Isle_Of_Man',
        'isleofman': 'Isle_Of_Man',
        'libyan arab jamahiriya': 'Libyan_Arab_Jamahiriya',
        'libya': 'Libyan_Arab_Jamahiriya',
        'north macedonia': 'North_Macedonia',
        'northmacedonia': 'North_Macedonia',
        'macedonia': 'North_Macedonia',
        'papua new guinea': 'Papua_New_Guinea',
        'papuanewguinea': 'Papua_New_Guinea',
        'puerto rico': 'Puerto_Rico',
        'puertorico': 'Puerto_Rico',
    }
    
    def _normalize_country_name(self, country: str) -> str:
        """
        Normalize country name to match NordVPN's expected format.
        
        Args:
            country: Input country name (user-friendly format)
            
        Returns:
            str: NordVPN-compatible country name
        """
        if not country:
            return country
            
        # Convert to lowercase for mapping lookup
        country_lower = country.lower().strip()
        
        # Check if there's a direct mapping
        if country_lower in self.COUNTRY_MAPPING:
            return self.COUNTRY_MAPPING[country_lower]
        
        # Try to match against available countries (case-insensitive)
        available_countries = self.get_available_countries()
        if available_countries:
            for available_country in available_countries:
                if available_country.lower() == country_lower:
                    return available_country
                # Also check if the user input matches when we replace underscores with spaces
                if available_country.lower().replace('_', ' ') == country_lower:
                    return available_country
        
        # If no mapping found, return original (might work or fail gracefully)
        return country
    
    def _suggest_country_alternatives(self, original_country: str, normalized_country: str) -> None:
        """
        Suggest alternative country names when connection fails.
        
        Args:
            original_country: The original country name provided by user
            normalized_country: The normalized country name that was attempted
        """
        available_countries = self.get_available_countries()
        if not available_countries:
            return
            
        # Find similar country names
        original_lower = original_country.lower()
        suggestions = []
        
        for country in available_countries:
            country_lower = country.lower()
            # Exact match (shouldn't happen if we got here, but just in case)
            if country_lower == original_lower:
                suggestions.append(country)
                continue
            # Contains the original name
            if original_lower in country_lower or country_lower in original_lower:
                suggestions.append(country)
                continue
            # Similar when replacing underscores with spaces
            country_spaced = country_lower.replace('_', ' ')
            if original_lower in country_spaced or country_spaced in original_lower:
                suggestions.append(country)
        
        if suggestions:
            print(f"[SUGGESTION] Did you mean one of these countries?")
            for suggestion in suggestions[:5]:  # Limit to 5 suggestions
                print(f"  - {suggestion}")
        else:
            print(f"[INFO] Available countries include: {', '.join(available_countries[:10])}...")
            if len(available_countries) > 10:
                print(f"[INFO] And {len(available_countries) - 10} more. Use get_available_countries() for full list.")
    
    def connect(self, country: str) -> bool:
        """Connect to NordVPN in specified country."""
        try:
            # Normalize the country name to match NordVPN's expected format
            normalized_country = self._normalize_country_name(country)
            
            if normalized_country != country:
                print(f"[DEBUG] Normalized country name: '{country}' -> '{normalized_country}'")
            
            result = NordVpn.change_vpn_country(normalized_country)
            # Check if result indicates success
            if isinstance(result, str) and "Successfully connected" in result:
                return True
            elif isinstance(result, str) and "Already connected" in result:
                return True
            else:
                print(f"NordVPN connection failed: {result}")
                # If connection failed, suggest alternatives
                self._suggest_country_alternatives(country, normalized_country)
                return False
        except Exception as e:
            print(f"NordVPN connection error: {e}")
            self._suggest_country_alternatives(country, normalized_country)
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
