import os
import subprocess
import re
from datetime import datetime

# Set Google Cloud Project environment variable for Gemini CLI
os.environ['GOOGLE_CLOUD_PROJECT'] = 'vast-art-469412-k3'  # Replace with your actual project ID


def send_prompt_to_gemini(prompt, output_directory, verbose=False):
    """
    Send a prompt to Gemini CLI and store the response in the output directory.
    
    CRITICAL: This function handles directory context switching to ensure Gemini CLI
    runs from within the output directory, regardless of where the automation is called from.
    
    Args:
        prompt (str): The prompt text to send to Gemini
        output_directory (str): Directory where prompts/outputs/ will be created 
                               AND where Gemini will execute from
        verbose (bool): Enable verbose output
        
    Returns:
        str: Path to the generated response file, or None if failed
    """
    if verbose:
        print(f"[DEBUG] Automation called from: {os.getcwd()}")
        print(f"[DEBUG] Gemini will execute from: {output_directory}")
        print(f"[DEBUG] Prompt: {prompt[:100]}..." if len(prompt) > 100 else f"[DEBUG] Prompt: {prompt}")
    
    # Validate input parameters
    if not prompt or not prompt.strip():
        print("❌ ERROR: Prompt cannot be empty")
        return None
        
    if not output_directory:
        print("❌ ERROR: Output directory cannot be empty")
        return None
    
    # Step 2: Create directory structure
    prompts_dir = os.path.join(output_directory, "prompts")
    outputs_dir = os.path.join(prompts_dir, "outputs")
    
    if verbose:
        print(f"[DEBUG] Creating directory structure:")
        print(f"[DEBUG] - Prompts dir: {prompts_dir}")
        print(f"[DEBUG] - Outputs dir: {outputs_dir}")
    
    try:
        # Create prompts/outputs directory structure
        os.makedirs(outputs_dir, exist_ok=True)
        
        if verbose:
            print(f"[DEBUG] ✅ Directory structure ready: {outputs_dir}")
            
    except PermissionError:
        print(f"❌ ERROR: Permission denied creating directory: {outputs_dir}")
        return None
    except Exception as e:
        print(f"❌ ERROR: Failed to create directory structure: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return None
    
    # Step 3: Generate filename from prompt content
    def generate_filename_from_prompt(prompt_text, max_length=50):
        """Generate a safe filename from prompt content with timestamp."""
        # Remove special characters and normalize
        safe_name = re.sub(r'[^a-zA-Z0-9\s]', '', prompt_text)
        
        # Replace spaces with underscores
        safe_name = re.sub(r'\s+', '_', safe_name.strip())
        
        # Truncate to max length to leave room for timestamp
        if len(safe_name) > max_length:
            safe_name = safe_name[:max_length]
        
        # Ensure it's not empty
        if not safe_name:
            safe_name = "gemini_response"
        
        # Add timestamp for uniqueness
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        return f"{safe_name.lower()}_{timestamp}"
    
    # Generate filename for response
    filename_base = generate_filename_from_prompt(prompt)
    filename = f"{filename_base}.txt"
    output_file = os.path.join(outputs_dir, filename)
    
    if verbose:
        print(f"[DEBUG] Generated filename: {filename}")
        print(f"[DEBUG] Full output path: {output_file}")
    
    # Step 4: Execute Gemini CLI from output directory
    def execute_gemini_from_output_dir(prompt_text, output_dir, verbose_mode=False):
        """
        Execute Gemini CLI from within the output directory using shell command.
        This ensures Gemini has access to all analysis files regardless of where automation runs from.
        """
        if verbose_mode:
            print(f"[DEBUG] Executing Gemini CLI from directory: {output_dir}")
        
        # Verify output directory exists and is accessible
        if not os.path.exists(output_dir):
            print(f"❌ ERROR: Output directory does not exist: {output_dir}")
            return None
            
        if not os.access(output_dir, os.R_OK | os.X_OK):
            print(f"❌ ERROR: Cannot access output directory: {output_dir}")
            return None
        
        # Build shell command that changes to output directory and runs gemini
        # Using shell=True with proper escaping for cross-platform compatibility
        escaped_prompt = prompt_text.replace('"', '\\"')  # Escape quotes in prompt
        shell_command = f'cd "{output_dir}" && gemini -p "{escaped_prompt}"'
        
        if verbose_mode:
            print(f"[DEBUG] Shell command: {shell_command}")
        
        try:
            result = subprocess.run(
                shell_command,
                shell=True,  # Required for cd && command chaining
                capture_output=True,
                text=True,
                check=False,
                timeout=300,  # 5 minute timeout
            )
            
            if result.returncode == 0:
                response_content = result.stdout.strip()
                if response_content:
                    if verbose_mode:
                        print(f"[DEBUG] ✅ Gemini CLI executed successfully from {output_dir}")
                        print(f"[DEBUG] Response length: {len(response_content)} characters")
                    return response_content
                else:
                    print("❌ ERROR: Gemini CLI returned empty response")
                    return None
            else:
                print(f"❌ ERROR: Gemini CLI failed with return code {result.returncode}")
                if result.stderr.strip():
                    print(f"Error details: {result.stderr.strip()}")
                return None
                
        except subprocess.TimeoutExpired:
            print("❌ ERROR: Gemini CLI command timed out after 5 minutes")
            print("This may indicate network connectivity issues or a very complex prompt.")
            return None
        except FileNotFoundError:
            print("❌ ERROR: 'gemini' command not found.")
            print("Please ensure Gemini CLI is installed and in your system PATH.")
            print("Installation: npm install -g @google-ai/generative-ai-cli")
            return None
        except Exception as e:
            print(f"❌ ERROR: Shell command execution failed: {e}")
            return None
    
    # Execute Gemini CLI with directory context
    if verbose:
        print(f"[DEBUG] Current working directory: {os.getcwd()}")
        print(f"[DEBUG] Switching to output directory for Gemini execution: {output_directory}")
    
    gemini_response = execute_gemini_from_output_dir(prompt, output_directory, verbose)
    
    if gemini_response is None:
        print("❌ ERROR: Failed to get response from Gemini CLI")
        return None
    
    if verbose:
        print(f"[DEBUG] ✅ Successfully received response from Gemini CLI")
    
    # Step 5: Save response to file
    if verbose:
        print(f"[DEBUG] Saving response to file: {output_file}")
        print(f"[DEBUG] Response preview: {gemini_response[:200]}..." if len(gemini_response) > 200 else f"[DEBUG] Response: {gemini_response}")
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(gemini_response)
        
        if verbose:
            print(f"[DEBUG] ✅ Response saved successfully: {output_file}")
            print(f"[DEBUG] File size: {len(gemini_response)} characters")
        
        print(f"✅ Gemini response saved to: {output_file}")
        return output_file
        
    except PermissionError:
        print(f"❌ ERROR: Permission denied writing to file: {output_file}")
        return None
    except Exception as e:
        print(f"❌ ERROR: Failed to save response to file: {e}")
        if verbose:
            print(f"[DEBUG] Exception details: {type(e).__name__}: {e}")
        return None
