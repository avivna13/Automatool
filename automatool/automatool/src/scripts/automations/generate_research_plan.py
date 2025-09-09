import os


def generate_research_plan(output_directory, reviews_data, yara_data, verbose=False):
    """
    Generate research plan by combining reviews and YARA summaries with the template.
    
    Args:
        output_directory (str): Directory where prompts/ will be created
        reviews_data (str): Reviews data from run_reviews_with_parsing() - could be summary or error message
        yara_data (str|None|False): YARA data from parse_yara_to_summary() - could be content, None, or False
        verbose (bool): Enable verbose output
        
    Returns:
        str: Path to the generated research plan file, or None if failed
    """
    if verbose:
        print("[DEBUG] Starting research plan generation...")
        print(f"[DEBUG] Output directory: {output_directory}")
        print(f"[DEBUG] Reviews data type: {type(reviews_data)}")
        print(f"[DEBUG] YARA data type: {type(yara_data)}")
    
    # Step 2: Load template prompt
    template_path = os.path.join(os.path.dirname(__file__), "..", "llm_prompts", "research_plan.txt")
    
    if verbose:
        print(f"[DEBUG] Loading template from: {template_path}")
    
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()
        
        if verbose:
            print(f"[DEBUG] Template loaded successfully, {len(template_content)} characters")
            
    except FileNotFoundError:
        print(f"❌ ERROR: Template file not found at: {template_path}")
        return None
    except Exception as e:
        print(f"❌ ERROR: Failed to load template: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return None
    
    # Step 3: Format template with data
    if verbose:
        print("[DEBUG] Formatting template with reviews and YARA data...")
    
    # Handle reviews data (always string, but might be error message)
    if reviews_data and not reviews_data.startswith("❌ ERROR:") and not reviews_data.startswith("⚠️  WARNING:"):
        reviews_content = reviews_data
        if verbose:
            print("[DEBUG] Using valid reviews data for template")
    else:
        reviews_content = "[No valid reviews data available]"
        if verbose:
            print("[DEBUG] Using placeholder for reviews data")
    
    # Handle YARA data (can be None, False, or string)
    if yara_data and isinstance(yara_data, str):
        yara_content = yara_data
        if verbose:
            print("[DEBUG] Using valid YARA data for template")
    else:
        yara_content = "[No YARA analysis results available]"
        if verbose:
            print("[DEBUG] Using placeholder for YARA data")
    
    # Format the template by replacing placeholders
    try:
        formatted_content = template_content.format(
            reviews=reviews_content,
            yara_output=yara_content
        )
        
        if verbose:
            print(f"[DEBUG] Template formatted successfully, {len(formatted_content)} characters")
            
    except KeyError as e:
        print(f"❌ ERROR: Template formatting failed - missing placeholder: {e}")
        if verbose:
            print(f"[DEBUG] Template content: {template_content[:200]}...")
        return None
    except Exception as e:
        print(f"❌ ERROR: Template formatting failed: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return None
    
    # Step 4: Create prompts directory
    prompts_dir = os.path.join(output_directory, "prompts")
    
    if verbose:
        print(f"[DEBUG] Creating prompts directory: {prompts_dir}")
    
    try:
        # Create prompts directory if it doesn't exist
        os.makedirs(prompts_dir, exist_ok=True)
        
        if verbose:
            print(f"[DEBUG] Prompts directory ready: {prompts_dir}")
            
    except PermissionError:
        print(f"❌ ERROR: Permission denied creating directory: {prompts_dir}")
        return None
    except Exception as e:
        print(f"❌ ERROR: Failed to create prompts directory: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return None
    
    # Step 5: Save formatted content
    output_file = os.path.join(prompts_dir, "research_plan.txt")
    
    if verbose:
        print(f"[DEBUG] Saving research plan to: {output_file}")
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(formatted_content)
        
        if verbose:
            print(f"[DEBUG] ✅ Research plan saved successfully: {output_file}")
        
        print(f"✅ Research plan generated: {output_file}")
        return output_file
        
    except PermissionError:
        print(f"❌ ERROR: Permission denied writing to file: {output_file}")
        return None
    except Exception as e:
        print(f"❌ ERROR: Failed to save research plan: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return None

