# 📱 Google Play App Metadata Scraper Specification

## **Overview**
A lightweight scraper that extracts specific metadata from Google Play Store applications using the `google-play-scraper` library. Focuses on extracting only the essential information needed for app analysis.

## **Target Information**
The scraper extracts exactly **4 data points**:
1. **Contains Ads** - Boolean indicating if the app contains advertisements
2. **Developer Email** - Support/contact email for the developer
3. **Privacy Policy Link** - URL to the app's privacy policy
4. **Developer Name** - Name of the app developer/company

## **File Structure**
```
automatool/automatool/src/
├── play_app_metadata_scraper.py    # Single file implementation
```

## **Core Implementation**

### **Data Model**
```python
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
```

### **Main Scraper Class**
```python
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
            logging.basicConfig(level=logging.DEBUG)
    
    def get_app_basic_info(self, package_name: str) -> Optional[AppBasicInfo]:
        """
        Extract basic info for a single app.
        
        Args:
            package_name: Google Play package name (e.g., 'com.whatsapp')
            
        Returns:
            AppBasicInfo object or None if failed
        """
        try:
            # Fetch app data using google-play-scraper
            raw_data = app(package_name)
            
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
    
    def print_basic_info(self, info: AppBasicInfo) -> None:
        """Print the basic info in a readable format."""
        self.console.print(f"\n[bold]App: {info.app_id}[/bold]")
        self.console.print(f"Developer: {info.developer_name}")
        self.console.print(f"Contains Ads: {'Yes' if info.contains_ads else 'No'}")
        self.console.print(f"Developer Email: {info.developer_email or 'Not available'}")
        self.console.print(f"Privacy Policy: {info.privacy_policy or 'Not available'}")
```

## **Google Play Scraper Field Mapping**

| Target Field | Google Play Scraper Field | Type | Description |
|--------------|---------------------------|------|-------------|
| `contains_ads` | `containsAds` | boolean | Indicates if app contains advertisements |
| `developer_email` | `developerEmail` | string | Developer contact email |
| `privacy_policy` | `privacyPolicy` | string | URL to privacy policy |
| `developer_name` | `developer` | string | Developer/company name |

## **Usage Examples**

### **Basic Usage**
```python
from play_app_metadata_scraper import PlayStoreBasicInfoScraper

# Initialize scraper
scraper = PlayStoreBasicInfoScraper(verbose=True)

# Get basic info for an app
info = scraper.get_app_basic_info('com.whatsapp')

if info:
    # Access the 4 specific fields
    print(f"Contains ads: {info.contains_ads}")
    print(f"Support email: {info.developer_email}")
    print(f"Privacy policy: {info.privacy_policy}")
    print(f"Developer: {info.developer_name}")
```

### **Multiple Apps**
```python
apps = ['com.whatsapp', 'com.instagram.android', 'com.tiktok']
results = []

for app_id in apps:
    info = scraper.get_app_basic_info(app_id)
    if info:
        results.append(info.to_dict())

# Output as JSON
import json
print(json.dumps(results, indent=2))
```

### **Command Line Usage**
```python
# Example usage in __main__
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python play_app_metadata_scraper.py <package_name>")
        sys.exit(1)
    
    package_name = sys.argv[1]
    scraper = PlayStoreBasicInfoScraper(verbose=True)
    info = scraper.get_app_basic_info(package_name)
    
    if info:
        scraper.print_basic_info(info)
        print("\nJSON format:")
        print(json.dumps(info.to_dict(), indent=2))
    else:
        print(f"Failed to scrape {package_name}")
```

## **Expected Output Formats**

### **Rich Console Output**
```
App: com.whatsapp
Developer: WhatsApp LLC
Contains Ads: No
Developer Email: android-support@whatsapp.com
Privacy Policy: https://www.whatsapp.com/legal/privacy-policy
```

### **JSON Output**
```json
{
  "app_id": "com.whatsapp",
  "contains_ads": false,
  "developer_email": "android-support@whatsapp.com", 
  "privacy_policy": "https://www.whatsapp.com/legal/privacy-policy",
  "developer_name": "WhatsApp LLC"
}
```

## **Dependencies**
- `google-play-scraper` - For fetching app metadata from Google Play Store
- `rich` - For formatted console output
- `dataclasses` - For data model structure
- `typing` - For type hints
- `logging` - For error handling and debugging

## **Error Handling Strategy**
- **Graceful Failures**: Returns `None` if scraping fails, logs error details
- **Missing Fields**: Uses sensible defaults (empty strings, `False` for booleans)
- **Network Issues**: Catches and logs network-related exceptions
- **Invalid Package Names**: Handles invalid/non-existent package names gracefully

## **Key Benefits**

✅ **Focused Scope**: Extracts only the 4 specified data points, no bloat
✅ **Single File**: Simple implementation in one file for easy maintenance
✅ **Lightweight**: Minimal dependencies and memory footprint
✅ **Error Resilient**: Handles failures gracefully without crashing
✅ **Flexible Output**: Supports both rich console and JSON formats
✅ **Type Safe**: Uses dataclasses and type hints for better code quality
✅ **Easy Integration**: Can be imported and used by other scripts

## **Limitations (By Design)**
- Only extracts 4 specific fields (intentional)
- No caching mechanism (keeps it simple)
- No rate limiting (relies on google-play-scraper defaults)
- Single app processing (can be extended if needed)

## **Implementation Steps**

### **Step 1**: Create the scraper file
- Implement `AppBasicInfo` dataclass
- Implement `PlayStoreBasicInfoScraper` class
- Add error handling and logging

### **Step 2**: Add dependencies
- Ensure `google-play-scraper` is installed
- Verify `rich` library availability

### **Step 3**: Testing
- Test with known app package names
- Verify all 4 fields are extracted correctly
- Test error handling with invalid package names

### **Step 4**: Integration
- Add to existing automation workflows if needed
- Document usage for other team members

## **File Location**
```
automatool/automatool/src/play_app_metadata_scraper.py
```

This specification provides a focused, lightweight solution for extracting the specific Google Play Store metadata you requested.
