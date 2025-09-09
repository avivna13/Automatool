"""
Google Play App Metadata Scraper

A lightweight scraper that extracts specific metadata from Google Play Store applications.
Focuses on extracting only the essential information needed for app analysis.

Target Information:
1. Contains Ads - Boolean indicating if the app contains advertisements
2. Developer Email - Support/contact email for the developer
3. Privacy Policy Link - URL to the app's privacy policy
4. Developer Name - Name of the app developer/company
"""

import json
import logging
import sys
from dataclasses import dataclass
from typing import Optional

from google_play_scraper import app
from rich.console import Console


@dataclass
class AppBasicInfo:
    """Minimal data model for specific Google Play Store app metadata."""
    
    app_id: str                          # Package name (e.g., 'com.whatsapp')
    contains_ads: bool                   # True if app contains ads
    developer_email: Optional[str]       # Developer support email
    privacy_policy: Optional[str]        # Privacy policy URL
    developer_name: str                  # Developer/company name
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON output."""
        return {
            'app_id': self.app_id,
            'contains_ads': self.contains_ads,
            'developer_email': self.developer_email,
            'privacy_policy': self.privacy_policy,
            'developer_name': self.developer_name
        }


class PlayStoreBasicInfoScraper:
    """
    Minimal scraper for extracting specific Google Play Store app metadata.
    
    Extracts ONLY:
    - Contains ads (boolean)
    - Developer email (string)
    - Privacy policy link (string)  
    - Developer name (string)
    """
    
    def __init__(self, verbose: bool = False):
        """Initialize the basic info scraper."""
        self.console = Console()
        self.logger = logging.getLogger(__name__)
        if verbose:
            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    
    def get_app_basic_info(self, package_name: str) -> Optional[AppBasicInfo]:
        """
        Extract basic info for a single app.
        
        Args:
            package_name: Google Play package name (e.g., 'com.whatsapp')
            
        Returns:
            AppBasicInfo object or None if failed
        """
        try:
            self.logger.debug(f"Fetching app data for: {package_name}")
            
            # Fetch app data using google-play-scraper
            raw_data = app(package_name)
            
            self.logger.debug(f"Successfully fetched data for {package_name}")
            
            # Extract only the 4 fields specified
            basic_info = AppBasicInfo(
                app_id=package_name,
                contains_ads=raw_data.get('containsAds', False),
                developer_email=raw_data.get('developerEmail'),
                privacy_policy=raw_data.get('privacyPolicy'),
                developer_name=raw_data.get('developer', 'Unknown')
            )
            
            return basic_info
            
        except Exception as e:
            self.logger.error(f"Failed to scrape {package_name}: {e}")
            return None
    
    def print_basic_info(self, info: AppBasicInfo) -> str:
        """Print the basic info in a readable format and return the formatted string."""
        # Create the formatted text string
        formatted_text = f"""
App: {info.app_id}
Developer: {info.developer_name}
Contains Ads: {'Yes' if info.contains_ads else 'No'}
Developer Email: {info.developer_email or 'Not available'}
Privacy Policy: {info.privacy_policy or 'Not available'}"""
        
        # Print with rich formatting
        self.console.print(f"\n[bold]App: {info.app_id}[/bold]")
        self.console.print(f"Developer: {info.developer_name}")
        self.console.print(f"Contains Ads: {'Yes' if info.contains_ads else 'No'}")
        self.console.print(f"Developer Email: {info.developer_email or 'Not available'}")
        self.console.print(f"Privacy Policy: {info.privacy_policy or 'Not available'}")
        
        # Return the plain text version
        return formatted_text


# Example usage and command line interface
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python play_app_metadata_scraper.py <package_name>")
        print("Example: python play_app_metadata_scraper.py com.whatsapp")
        sys.exit(1)
    
    package_name = sys.argv[1]
    scraper = PlayStoreBasicInfoScraper(verbose=True)
    info = scraper.get_app_basic_info(package_name)
    
    if info:
        # Print and get the formatted string
        formatted_string = scraper.print_basic_info(info)
        
        print("\nJSON format:")
        print(json.dumps(info.to_dict(), indent=2))
        
        print("\nFormatted text string:")
        print(repr(formatted_string))  # Show the string representation
    else:
        print(f"Failed to scrape {package_name}")
        sys.exit(1)
