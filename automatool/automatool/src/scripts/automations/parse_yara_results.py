import os
import json


def parse_yara_to_summary(output_directory, verbose=False):
    """
    Parse YARA JSON results and create a simplified summary in text format.
    
    Args:
        output_directory (str): Directory containing yara.json file
        verbose (bool): Enable verbose output
        
    Returns:
        str: YARA summary content as string, or None if parsing failed
    """
    yara_json_path = os.path.join(output_directory, "yara.json")
    output_file = os.path.join(output_directory, "yara_summary.txt")
    
    if verbose:
        print(f"[DEBUG] Looking for YARA results: {yara_json_path}")
    
    # Check if yara.json exists
    if not os.path.exists(yara_json_path):
        if verbose:
            print("[DEBUG] No yara.json found, skipping YARA parsing")
        print("ℹ️  No YARA results found to parse")
        return None
    
    try:
        # Read and parse the JSON file
        encodings_to_try = ['utf-8', 'utf-8-sig', 'utf-16', 'utf-16-le', 'utf-16-be', 'latin-1']
        content = None
        
        for encoding in encodings_to_try:
            try:
                with open(yara_json_path, 'r', encoding=encoding) as f:
                    content = f.read()
                if verbose:
                    print(f"[DEBUG] Successfully read file using {encoding} encoding")
                break
            except UnicodeDecodeError:
                continue
        
        if content is None:
            print(f"❌ ERROR: Could not read yara.json with any supported encoding")
            return False
        
        if verbose:
            print(f"[DEBUG] Read {len(content)} characters from yara.json")
        
        # Split content to separate JSON from summary
        json_end_marker = None
        lines = content.split('\n')
        
        # Find where JSON ends (look for "Summary:" or closing brace followed by text)
        json_content = ""
        summary_content = ""
        in_summary = False
        
        for i, line in enumerate(lines):
            if line.strip().startswith("Summary:") or in_summary:
                in_summary = True
                summary_content += line + '\n'
            else:
                json_content += line + '\n'
                # Check if this might be the end of JSON
                if line.strip() == '}' and i < len(lines) - 1:
                    # Peek ahead to see if next non-empty line starts summary
                    for j in range(i + 1, len(lines)):
                        if lines[j].strip():
                            if lines[j].strip().startswith("Summary:") or lines[j].strip().startswith("="):
                                in_summary = True
                                # Add remaining lines to summary
                                for k in range(i + 1, len(lines)):
                                    summary_content += lines[k] + '\n'
                                break
                            break
                    if in_summary:
                        break
        
        # Parse the JSON part
        try:
            yara_data = json.loads(json_content.strip())
        except json.JSONDecodeError as e:
            if verbose:
                print(f"[DEBUG] JSON parsing failed: {e}")
                print(f"[DEBUG] Trying to extract JSON more carefully...")
            
            # Fallback: try to find the JSON structure more carefully
            brace_count = 0
            json_chars = []
            for char in content:
                json_chars.append(char)
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        # This might be the end of JSON
                        break
            
            json_content = ''.join(json_chars)
            yara_data = json.loads(json_content)
            
            # Extract summary from remaining content
            remaining_content = content[len(json_content):].strip()
            if remaining_content:
                summary_content = remaining_content
        
        if verbose:
            print(f"[DEBUG] Successfully parsed YARA data with {len(yara_data.get('files', []))} files")
        
        # Generate the summary content
        summary_lines = []
        summary_lines.append("YARA Analysis Summary")
        summary_lines.append("=" * 50)
        summary_lines.append("")
        
        # Process each file
        for file_obj in yara_data.get('files', []):
            filename = file_obj.get('filename', 'Unknown')
            matches = file_obj.get('matches', [])
            
            if not matches:
                continue
            
            # Clean up the filename (remove Windows path, keep APK-relative path)
            clean_filename = _clean_filename(filename)
            
            summary_lines.append(f"=== {clean_filename} ===")
            
            # Process each match
            for i, match in enumerate(matches, 1):
                description = match.get('description', 'No description')
                strings = match.get('strings', [])
                
                summary_lines.append(f"")
                summary_lines.append(f"Match {i}:")
                summary_lines.append(f"- Description: {description}")
                
                if strings:
                    # Join strings with commas, clean up the format
                    cleaned_strings = []
                    for s in strings:
                        # Remove the variable name prefix (e.g., "$lib - ")
                        if ' - ' in s:
                            cleaned_string = s.split(' - ', 1)[1].strip("'\"")
                        else:
                            cleaned_string = s.strip("'\"")
                        cleaned_strings.append(cleaned_string)
                    
                    strings_text = ", ".join(cleaned_strings)
                    summary_lines.append(f"- Strings: {strings_text}")
                else:
                    summary_lines.append(f"- Strings: (none)")
            
            summary_lines.append("")
            summary_lines.append("-" * 40)
        
        # Add the summary section if it exists
        if summary_content.strip():
            summary_lines.append("")
            summary_lines.append("")
            summary_lines.append(summary_content.strip())
        
        # Join all lines to create the final content
        final_summary_content = '\n'.join(summary_lines)
        
        # Write to file for debugging/logging purposes
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(final_summary_content)
        
        if verbose:
            print(f"[DEBUG] ✅ YARA summary written to: {output_file}")
        
        print(f"✅ YARA summary created: {output_file}")
        
        # Return the actual content instead of file path
        return final_summary_content
        
    except json.JSONDecodeError as e:
        print(f"❌ ERROR: Failed to parse yara.json - Invalid JSON format: {e}")
        if verbose:
            print(f"[DEBUG] JSON Error details: {type(e).__name__}: {e}")
        return None
        
    except FileNotFoundError:
        print(f"❌ ERROR: yara.json not found at: {yara_json_path}")
        return None
        
    except Exception as e:
        print(f"❌ ERROR: Failed to parse YARA results: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return None


def _clean_filename(filename):
    """
    Clean up filename to show only APK-relative path.
    
    Args:
        filename (str): Full file path from YARA results
        
    Returns:
        str: Cleaned filename
    """
    if '!' in filename:
        # Extract the part after the APK name (after the '!')
        parts = filename.split('!')
        if len(parts) > 1:
            return parts[-1]
    
    # If no '!' found, try to extract just the filename
    if '\\' in filename:
        return filename.split('\\')[-1]
    elif '/' in filename:
        return filename.split('/')[-1]
    
    return filename

if __name__ == "__main__":
    path = input('enter path')
    parse_yara_to_summary(os.path.dirname(path), True)