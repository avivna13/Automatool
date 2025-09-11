import json
import os
from typing import Dict, Set, Union, Optional


def parse_apkleaks_json(json_file_path: str) -> Dict[str, Set[str]]:
    """
    Parse APKLeaks JSON output file into a dictionary with sets of API keys.
    
    Args:
        json_file_path (str): Path to the APKLeaks JSON output file
        
    Returns:
        Dict[str, Set[str]]: Dictionary where keys are API key type names and 
                            values are sets of unique API keys found
                            
    Raises:
        FileNotFoundError: If the JSON file doesn't exist
        json.JSONDecodeError: If the file is not valid JSON
        ValueError: If the JSON structure is unexpected
    """
    # Validate file exists
    if not os.path.exists(json_file_path):
        raise FileNotFoundError(f"APKLeaks JSON file not found: {json_file_path}")
    
    # Read and parse JSON file
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON format in file {json_file_path}: {e}")
    
    # Validate data is a dictionary
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object (dictionary) but got {type(data).__name__}")
    
    # Parse data into dictionary with sets
    result = {}
    
    # Handle different APKLeaks JSON structures
    if "results" in data and isinstance(data["results"], list):
        # New APKLeaks format: {"package": "...", "results": [{"name": "...", "matches": [...]}]}
        for item in data["results"]:
            if isinstance(item, dict) and "name" in item and "matches" in item:
                api_key_type = item["name"]
                matches = item["matches"]
                if isinstance(matches, list):
                    result[api_key_type] = set(matches)
                else:
                    result[api_key_type] = {str(matches)}
    else:
        # Old/flat APKLeaks format: {"api_type": [...], "another_type": [...]}
        for api_key_type, api_keys in data.items():
            # Skip metadata fields
            if api_key_type in ["package", "results"]:
                continue
                
            # Handle different possible data structures
            if isinstance(api_keys, list):
                # Convert list to set to remove duplicates
                result[api_key_type] = set(api_keys)
            elif isinstance(api_keys, str):
                # Single string value, convert to set with one item
                result[api_key_type] = {api_keys}
            elif isinstance(api_keys, set):
                # Already a set, use as-is
                result[api_key_type] = api_keys
            elif isinstance(api_keys, dict):
                # Handle nested dictionary (shouldn't happen but just in case)
                if "matches" in api_keys:
                    matches = api_keys["matches"]
                    if isinstance(matches, list):
                        result[api_key_type] = set(matches)
                    else:
                        result[api_key_type] = {str(matches)}
                else:
                    # Convert dict keys or values to set
                    result[api_key_type] = set(str(v) for v in api_keys.values())
            else:
                # Convert other types to string and add to set
                result[api_key_type] = {str(api_keys)}
    
    return result


def print_parsed_results(parsed_data: Dict[str, Set[str]], verbose: bool = False) -> None:
    """
    Print the parsed APKLeaks results in a readable format.
    
    Args:
        parsed_data (Dict[str, Set[str]]): Parsed APKLeaks data
        verbose (bool): Whether to print detailed information
    """
    if not parsed_data:
        print("No API keys found in the parsed data.")
        return
    
    print("🔍 Parsed APKLeaks Results:")
    print("=" * 50)
    
    total_keys = 0
    for api_type, keys in parsed_data.items():
        key_count = len(keys)
        total_keys += key_count
        
        print(f"\n📋 {api_type}: {key_count} unique key(s)")
        
        if verbose and keys:
            for i, key in enumerate(sorted(keys), 1):
                print(f"  {i}. {key}")
        elif keys:
            # Show first few keys if not verbose
            keys_list = sorted(list(keys))
            if len(keys_list) <= 3:
                for key in keys_list:
                    print(f"  - {key}")
            else:
                for key in keys_list[:2]:
                    print(f"  - {key}")
                print(f"  - ... and {len(keys_list) - 2} more")
    
    print(f"\n📊 Total: {total_keys} API keys across {len(parsed_data)} categories")


def get_keys_by_type(parsed_data: Dict[str, Set[str]], api_type: str) -> Set[str]:
    """
    Get all API keys of a specific type.
    
    Args:
        parsed_data (Dict[str, Set[str]]): Parsed APKLeaks data
        api_type (str): The type of API keys to retrieve (e.g., 'appsflyer_api_keys')
        
    Returns:
        Set[str]: Set of API keys of the specified type, empty set if not found
    """
    return parsed_data.get(api_type, set())


def merge_parsed_results(*parsed_data_list: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
    """
    Merge multiple parsed APKLeaks results into one dictionary.
    
    Args:
        *parsed_data_list: Variable number of parsed APKLeaks dictionaries
        
    Returns:
        Dict[str, Set[str]]: Merged dictionary with combined sets
    """
    merged = {}
    
    for parsed_data in parsed_data_list:
        for api_type, keys in parsed_data.items():
            if api_type in merged:
                # Merge sets
                merged[api_type].update(keys)
            else:
                # Create new set
                merged[api_type] = set(keys)
    
    return merged


def save_parsed_results(parsed_data: Dict[str, Set[str]], output_path: str) -> None:
    """
    Save parsed results to a JSON file (converting sets to lists for JSON serialization).
    
    Args:
        parsed_data (Dict[str, Set[str]]): Parsed APKLeaks data
        output_path (str): Path where to save the JSON file (can be directory or file path)
    """
    # If output_path is a directory, create a default filename
    if os.path.isdir(output_path):
        output_path = os.path.join(output_path, "parsed_apkleaks_results.json")
    
    # Convert sets to lists for JSON serialization
    serializable_data = {
        api_type: sorted(list(keys)) for api_type, keys in parsed_data.items()
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(serializable_data, f, indent=2, ensure_ascii=False)
    
    print(f"📄 Parsed results saved to: {output_path}")


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description="Parse APKLeaks JSON output into structured data.")
    parser.add_argument("json_file", help="Path to APKLeaks JSON output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all API keys in detail")
    parser.add_argument("-o", "--output", help="Save parsed results to JSON file")
    parser.add_argument("--type", help="Show only keys of specific type (e.g., appsflyer_api_keys)")
    
    args = parser.parse_args()
    
    try:
        # Parse the JSON file
        parsed_data = parse_apkleaks_json(args.json_file)
        
        if args.type:
            # Show only specific type
            keys = get_keys_by_type(parsed_data, args.type)
            print(f"🔑 {args.type}: {len(keys)} unique key(s)")
            for key in sorted(keys):
                print(f"  - {key}")
        else:
            # Show all results
            print_parsed_results(parsed_data, args.verbose)
        
        # Save to output file if requested
        if args.output:
            save_parsed_results(parsed_data, args.output)
            
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        print(f"❌ Error: {e}")
        exit(1)
