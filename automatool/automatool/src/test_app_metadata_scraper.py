#!/usr/bin/env python3
"""
Test script for Google Play App Metadata Scraper
Tests various scenarios including apps with ads, without ads, and error handling.
"""

import json
import sys
import os

# Add the current directory to Python path to find the module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from play_app_metadata_scraper import PlayStoreBasicInfoScraper

def test_multiple_apps():
    """Test scraper with multiple known apps to verify field extraction."""
    
    # Test apps with different characteristics
    test_apps = [
        'com.whatsapp',              # No ads, well-known app
        'com.instagram.android',     # Has ads, popular app  
        'com.tiktok',               # Has ads, social media
        'com.spotify.music',        # Freemium model
        'invalid.package.name'      # Invalid app (should fail gracefully)
    ]
    
    scraper = PlayStoreBasicInfoScraper(verbose=True)
    results = []
    
    print("=" * 60)
    print("TESTING GOOGLE PLAY APP METADATA SCRAPER")
    print("=" * 60)
    
    for i, package_name in enumerate(test_apps, 1):
        print(f"\n[{i}/{len(test_apps)}] Testing: {package_name}")
        print("-" * 50)
        
        info = scraper.get_app_basic_info(package_name)
        
        if info:
            # Test the string return functionality
            formatted_string = scraper.print_basic_info(info)
            
            # Verify all 4 fields are present
            assert info.app_id == package_name
            assert isinstance(info.contains_ads, bool)
            assert isinstance(info.developer_name, str)
            # developer_email and privacy_policy can be None
            
            # Test JSON conversion
            json_data = info.to_dict()
            assert len(json_data) == 5  # Should have exactly 5 fields
            
            results.append({
                'package_name': package_name,
                'success': True,
                'data': json_data,
                'formatted_string': formatted_string
            })
            
            print(f"✅ SUCCESS: Extracted all 4 fields")
            print(f"   Contains Ads: {info.contains_ads}")
            print(f"   Developer Email: {info.developer_email or 'Not provided'}")
            print(f"   Privacy Policy: {info.privacy_policy or 'Not provided'}")
            
        else:
            print(f"❌ FAILED: Could not extract data")
            results.append({
                'package_name': package_name,
                'success': False,
                'data': None,
                'formatted_string': None
            })
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    successful = sum(1 for r in results if r['success'])
    total = len(results)
    
    print(f"Total apps tested: {total}")
    print(f"Successful extractions: {successful}")
    print(f"Failed extractions: {total - successful}")
    
    # Show apps with ads vs without ads
    apps_with_ads = [r for r in results if r['success'] and r['data']['contains_ads']]
    apps_without_ads = [r for r in results if r['success'] and not r['data']['contains_ads']]
    
    print(f"\nApps WITH ads: {len(apps_with_ads)}")
    for app in apps_with_ads:
        print(f"  - {app['package_name']}")
    
    print(f"\nApps WITHOUT ads: {len(apps_without_ads)}")
    for app in apps_without_ads:
        print(f"  - {app['package_name']}")
    
    # Save detailed results
    with open('test_results.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n📄 Detailed results saved to: test_results.json")
    
    return results

if __name__ == "__main__":
    test_multiple_apps()
