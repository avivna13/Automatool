#!/usr/bin/python3
import requests
import json
import argparse
import sys
from datetime import datetime
# --- CONFIGURATION ---
# This is a placeholder URL. In a real scenario, you would replace this
# with the actual API endpoint you have legitimate access to.
API_BASE_URL = "https://app.sensortower.com/api/android/apps/"
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Dnt': '1',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Te': 'trailers'
}
JSON_OUTPUT_FILE = "sensortower.json"
MARKDOWN_OUTPUT_FILE = "sensorShort.md"

def format_timestamp(ts):
    """Helper function to format Unix timestamps (in milliseconds)."""
    if not ts:
        return "N/A"
    try:
        # Timestamps from the API are in milliseconds
        # Check for negative timestamps or invalid ranges
        if ts < 0:
            return "Invalid Date"
        return datetime.fromtimestamp(ts / 1000).strftime('%Y-%m-%d')
    except (ValueError, TypeError, OSError):
        return "Invalid Date"

def generate_google_play_url(app_id: str, country: str = "US") -> str:
    """
    Generates Google Play Store URL from API data.
    
    Args:
        app_id (str): The app package name from API response
        country (str): Country code for localization (default: "US")
        
    Returns:
        str: Complete Google Play Store URL
    """
    if not app_id or not app_id.strip():
        return "N/A"
    
    return f"https://play.google.com/store/apps/details?id={app_id}&gl={country}"

def filter_json_data(data: dict) -> dict:
    """
    Filters out unwanted fields from the SensorTower API response.
    
    Removes large, unnecessary fields to reduce JSON file size and improve readability.
    
    Args:
        data (dict): The original API response data
        
    Returns:
        dict: Filtered data with unwanted fields removed
    """
    # List of fields to remove from the JSON output
    fields_to_remove = [
         "game_intel_data",
          "top_in_app_purchases",
         "versions",
        "feature_graphic",
        "trailers", 
        "advertised_on_any_network",
        "screenshots",
        "content_rating",
        "valid_countries",
        "available_countries", 
        "pre_order_countries",
        "os",
        "price",
        "rating_breakdown",
        "rating_count",
        "release_status",
        "supported_languages",
        "cohort_id",
        "worldwide_last_month_revenue",
        "worldwide_last_month_downloads",
        "category_rankings"
    ]
    
    # Create a copy of the data to avoid modifying the original
    filtered_data = data.copy()
    
    # Remove unwanted fields
    removed_fields = []
    for field in fields_to_remove:
        if field in filtered_data:
            del filtered_data[field]
            removed_fields.append(field)
    
    # Log which fields were removed for transparency
    if removed_fields:
        print(f"[+] Filtered out {len(removed_fields)} fields: {', '.join(removed_fields[:5])}" + 
              (f" and {len(removed_fields) - 5} more..." if len(removed_fields) > 5 else ""))
    
    return filtered_data

def parse_to_text(data: dict, google_play_url: str = None) -> str:
    """
    Parses the JSON data and returns it as a formatted text string.
    
    Args:
        data (dict): The app data from SensorTower API
        google_play_url (str, optional): The Google Play Store URL to include
        
    Returns:
        str: Formatted text representation of the app data
    """
    output_lines = []

    # --- Basic App Info ---
    output_lines.append("\n" + "="*60)
    output_lines.append(" " * 20 + "APP INFORMATION" + " " * 21)
    output_lines.append("="*60)
    output_lines.append(f" 📱 App: {data.get('name', 'N/A')} ({data.get('app_id', 'N/A')})")
    output_lines.append(f" 🏢 Publisher: {data.get('publisher_name', 'N/A')}")
    output_lines.append(f" 🏷️ Category: {data.get('categories', [{}])[0].get('name', 'N/A')}")
    output_lines.append(f" 🌍 OS: {data.get('os', 'N/A').capitalize()}")
    output_lines.append(f" 📝 Description: {data.get('description', {}).get('short_description', 'N/A')}")
    
    # Add Google Play Store URL if available
    if google_play_url and google_play_url != "N/A":
        output_lines.append(f" 🔗 Google Play: {google_play_url}")

    # --- Release & Version Info ---
    output_lines.append("\n" + "-"*22 + " Release & Version " + "-"*21)
    output_lines.append(f" 🗓️ Worldwide Release: {format_timestamp(data.get('worldwide_release_date'))}")
    output_lines.append(f" 📦 Current Version: {data.get('current_version', 'N/A')} (Released: {format_timestamp(data.get('recent_release_date'))})")
    output_lines.append(f" ⚙️ Minimum OS: {data.get('minimum_os_version', 'N/A')}")
    output_lines.append(f" 📏 File Size: {data.get('file_size', 'N/A')}")

    # --- Ratings & Financials ---
    output_lines.append("\n" + "-"*22 + " Ratings & Financials " + "-"*19)
    output_lines.append(f" ⭐ Rating: {data.get('rating', 0):.2f} stars ({data.get('rating_count', 0):,} reviews)")
    
    purchases = data.get('top_in_app_purchases', {})
    if data.get('has_in_app_purchases') and purchases:
        iap_string = next(iter(purchases.values()), "Available")
        output_lines.append(f" 💰 In-App Purchases: {iap_string}")
    else:
        output_lines.append(" 💰 In-App Purchases: None")
        
    revenue = data.get('worldwide_last_month_revenue', {})
    if revenue.get('value') is not None:
        output_lines.append(f" 💵 Est. Revenue (Last Month): ${revenue.get('value', 0) / 100:,.2f}")
        
    downloads = data.get('worldwide_last_month_downloads', {})
    if downloads.get('value') is not None:
        output_lines.append(f" 📥 Est. Downloads (Last Month): {downloads.get('value', 0):,}")
    output_lines.append(f" 📈 Total Installs: {data.get('installs', 'N/A')}")

    # --- Availability ---
    output_lines.append("\n" + "-"*26 + " Availability " + "-"*24)
    top_countries = data.get('top_countries', [])
    if top_countries:
        line = f" 🌍 Top Countries: "
        if len(top_countries) > 5:
            line += ', '.join(top_countries[:5]) + f" and {len(top_countries) - 5} more..."
        else:
            line += ', '.join(top_countries)
        output_lines.append(line)

    available_countries = data.get('valid_countries', [])
    if available_countries:
        line = f" ✅ Available in {len(available_countries)} countries, including: "
        line += ', '.join(available_countries[:5]) + "..."
        output_lines.append(line)

    # --- Version History ---
    output_lines.append("\n" + "-"*23 + " Version History " + "-"*22)
    versions = data.get('versions', [])
    if not versions:
        output_lines.append("No version history found.")
    else:
        for version in versions[:5]:
            release_date = format_timestamp(version.get('date'))
            output_lines.append(f"  - Version {version.get('value', 'N/A'):<10} | Released on: {release_date}")
        if len(versions) > 5:
            output_lines.append(f"  ... and {len(versions) - 5} older versions.")
            
    output_lines.append("="*60 + "\n")

    # Return the formatted text string
    return "\n".join(output_lines)

def display_app_data(data: dict, google_play_url: str = None):
    """
    Parses the JSON data, prints it, and saves the formatted output to a file.
    
    Args:
        data (dict): The app data from SensorTower API
        google_play_url (str, optional): The Google Play Store URL to display
    """
    # Use the new parse_to_text method to get formatted output
    formatted_output = parse_to_text(data, google_play_url)
    
    # Print the formatted output
    print(formatted_output)

    # Save to markdown file
    try:
        with open(MARKDOWN_OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(formatted_output)
        print(f"[+] Formatted summary saved to {MARKDOWN_OUTPUT_FILE}")
    except IOError as e:
        print(f"[!] Error writing to markdown file: {e}", file=sys.stderr)


def fetch_app_data(package_name: str):
    """
    Fetches data for a given package name from the API and generates Google Play URL.
    
    Args:
        package_name (str): The Android package name to lookup
        
    Returns:
        dict: The app data from the API, or None if failed
    """
    url = f"{API_BASE_URL}{package_name}"
    params = {'country': 'US'}
    
    print(f"[*] Sending request to: {url}")
    
    try:
        response = requests.get(url, headers=HEADERS, params=params, timeout=10)
        response.raise_for_status()
        
        print("[+] Request successful!")
        data = response.json()
        
        # Generate Google Play URL from API response data
        app_id = data.get('app_id', '')
        country = data.get('country', 'US')
        google_play_url = generate_google_play_url(app_id, country)
        
        # Add the generated Google Play URL to the data for JSON storage
        data['generated_google_play_url'] = google_play_url
        
        # Filter out unwanted fields to reduce JSON size and improve readability
        filtered_data = filter_json_data(data)
        
        with open(JSON_OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(filtered_data, f, ensure_ascii=False, indent=4)
            
        print(f"[+] Filtered JSON response saved to {JSON_OUTPUT_FILE}")
        print(f"[+] Generated Google Play URL: {google_play_url}")
        
        # Use original data for display (includes all fields for comprehensive output)
        display_app_data(data, google_play_url)
        
        return data

    except requests.exceptions.HTTPError as http_err:
        print(f"[!] HTTP error occurred: {http_err}", file=sys.stderr)
        print(f" |  Response: {response.text}", file=sys.stderr)
    except requests.exceptions.RequestException as req_err:
        print(f"[!] A request error occurred: {req_err}", file=sys.stderr)
    except json.JSONDecodeError:
        print("[!] Failed to decode JSON from the response.", file=sys.stderr)
    
    return None

def view_saved_data():
    """
    Prints the content of the saved JSON file in a formatted way.
    Extracts and displays previously saved Google Play URLs if available.
    """
    try:
        with open(JSON_OUTPUT_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
            # Extract Google Play URL if it was previously generated and saved
            google_play_url = data.get('generated_google_play_url', None)
            
            # If no generated URL exists, try to generate one from the data
            if not google_play_url:
                app_id = data.get('app_id', '')
                country = data.get('country', 'US')
                if app_id:
                    google_play_url = generate_google_play_url(app_id, country)
                    print(f"[+] Generated Google Play URL from saved data: {google_play_url}")
            else:
                print(f"[+] Using previously saved Google Play URL: {google_play_url}")
            
            display_app_data(data, google_play_url)
            
    except FileNotFoundError:
        print(f"[!] Error: Output file '{JSON_OUTPUT_FILE}' not found.", file=sys.stderr)
        print(" |  Please run the script with a package name first to fetch data.", file=sys.stderr)
    except json.JSONDecodeError:
        print(f"[!] Error: Could not parse the JSON data in '{JSON_OUTPUT_FILE}'.", file=sys.stderr)

def main():
    """
    Main function to parse arguments and execute the script's logic.
    """
    parser = argparse.ArgumentParser(
        description="A script to scrape app information from the Sensor Tower API.",
        epilog="Example: python3 sensor_scraper.py com.example.app"
    )
    
    parser.add_argument(
        "package_name",
        nargs='?',
        default=None,
        help="The package name of the app to look up (e.g., com.example.app)."
    )
    
    parser.add_argument(
        "-v", "--view",
        action="store_true",
        help="View and format the contents of the last saved response file."
    )
    
    args = parser.parse_args()
    
    if args.view:
        view_saved_data()
    elif args.package_name:
        fetch_app_data(args.package_name)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
