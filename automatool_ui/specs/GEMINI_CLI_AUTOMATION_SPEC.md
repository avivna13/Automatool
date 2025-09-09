# 🤖 Gemini CLI Integration Specification

## **Overview**
Integrate Google's Gemini CLI into the existing automatool workflow to enable AI-powered analysis and insights generation through command-line prompts, with automated storage of responses in the project's prompt output structure.

## **Purpose**
The Gemini CLI integration will:
1. **Command-Line Integration**: Execute Gemini CLI commands via subprocess
2. **Context Awareness**: Include all output directory files as context (limited by Gemini CLI security to working directory only)
3. **Prompt Management**: Send user-defined prompts to Gemini AI with full APK analysis context
4. **Response Storage**: Store AI responses in structured output directories
5. **Filename Generation**: Create meaningful filenames from prompt content
6. **Resource Tracking**: Full integration with existing GlobalResourceTracker system

## **Architecture Strategy**

### **Simple Subprocess Execution**
The Gemini CLI automation follows the established pattern used by other automations in the project:

1. **Single Function**: `send_prompt_to_gemini(prompt, output_directory, verbose=False)`
2. **Shell Command Execution**: Execute `cd output_dir && gemini -p "prompt" --all-files` to ensure proper directory context
3. **File Storage**: Save response to `{output_directory}/prompts/outputs/`
4. **Filename Generation**: Create meaningful filenames from prompt content with timestamp
5. **Error Handling**: Comprehensive error handling with user-friendly messages

### **Integration Points**
- Can be called independently or integrated into main automatool workflow
- Follows same resource tracking patterns as other automations
- Uses existing output directory structure
- **Directory Independence**: Works regardless of where the parent automation is executed from

## **File Structure**
```
automatool/automatool/src/scripts/automations/
├── launch_gemini_prompt.py        # NEW: Main Gemini CLI automation
└── (existing automation files...)

automatool/automatool/specs/
├── GEMINI_CLI_AUTOMATION_SPEC.md   # NEW: This specification
└── (existing specification files...)
```

## **Implementation Details**

### **Core Function (`launch_gemini_prompt.py`)**

Following the exact pattern from existing automations like `generate_research_plan.py`:

```python
import os
import subprocess
import re
from datetime import datetime

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
```

### **Directory Structure Creation**
```python
# Create prompts/outputs directory structure
prompts_dir = os.path.join(output_directory, "prompts")
outputs_dir = os.path.join(prompts_dir, "outputs")

os.makedirs(outputs_dir, exist_ok=True)
```

### **Filename Generation Strategy**
```python
def generate_filename_from_prompt(prompt, max_length=50):
    """
    Generate a safe filename from prompt content with timestamp.
    
    Args:
        prompt (str): Original prompt text
        max_length (int): Maximum filename length
        
    Returns:
        str: Safe filename with timestamp (without extension)
    """
    from datetime import datetime
    
    # Remove special characters and normalize
    safe_name = re.sub(r'[^a-zA-Z0-9\s]', '', prompt)
    
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
```

### **Gemini CLI Command Execution with Context**
```python
# CRITICAL: Execute Gemini CLI command from the output directory
# The automation runs from automatool root, but Gemini must execute from output directory
# Gemini CLI is security-restricted to only access files within its current working directory

def execute_gemini_from_output_dir(prompt, output_directory, verbose=False):
    """
    Execute Gemini CLI from within the output directory using shell command.
    This ensures Gemini has access to all analysis files regardless of where automation runs from.
    """
    if verbose:
        print(f"[DEBUG] Executing Gemini CLI from directory: {output_directory}")
    
    # Verify output directory exists and is accessible
    if not os.path.exists(output_directory):
        print(f"❌ ERROR: Output directory does not exist: {output_directory}")
        return None
        
    if not os.access(output_directory, os.R_OK | os.X_OK):
        print(f"❌ ERROR: Cannot access output directory: {output_directory}")
        return None
    
    # Build shell command that changes to output directory and runs gemini
    # Using shell=True with proper escaping for cross-platform compatibility
    escaped_prompt = prompt.replace('"', '\\"')  # Escape quotes in prompt
    shell_command = f'cd "{output_directory}" && gemini -p "{escaped_prompt}" --all-files'
    
    if verbose:
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
                if verbose:
                    print(f"[DEBUG] ✅ Gemini CLI executed successfully from {output_directory}")
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
        return None
    except FileNotFoundError:
        print("❌ ERROR: 'gemini' command not found.")
        print("Please ensure Gemini CLI is installed and in your system PATH.")
        return None
    except Exception as e:
        print(f"❌ ERROR: Shell command execution failed: {e}")
        return None
```

## **Expected Usage Patterns**

### **Standalone Usage**
```python
from scripts.automations.launch_gemini_prompt import send_prompt_to_gemini

# Send prompt with context from APK analysis results
prompt = "Analyze the security implications based on the reviews, YARA results, and APK structure in this directory"
output_dir = "/path/to/analysis/output"  # Contains reviews.json, yara_summary.txt, etc.

response_file = send_prompt_to_gemini(prompt, output_dir, verbose=True)
if response_file:
    print(f"✅ Gemini response saved to: {response_file}")
```

### **Integration with Main Workflow**
Could be integrated into `automatool.py` as an optional analysis step after all other analyses complete:
```python
# Optional Gemini analysis step - after reviews, YARA, etc. are complete
if args.gemini_analysis:
    context_prompt = """Based on all the analysis results in this directory including:
    - APK reviews and user feedback
    - YARA security analysis results
    - APK structure and manifest
    - Any steganography or vulnerability findings
    
    Please provide comprehensive security recommendations and risk assessment."""
    
    gemini_response = send_prompt_to_gemini(context_prompt, target_dir, args.verbose)
    if gemini_response:
        resource_tracker.add_file(gemini_response)
```

## **Output File Structure**
```
{output_directory}/
├── reviews.json                    # APK reviews data (context for Gemini)
├── yara_summary.txt               # YARA analysis results (context for Gemini)
├── apktool_output/                # APK structure (context for Gemini)
└── prompts/
    ├── research_plan.txt          # Existing research plan
    └── outputs/                   # NEW: Gemini responses with full context
        ├── analyze_security_implications_20250101_120000.txt
        ├── provide_recommendations_20250101_120500.txt
        └── summarize_findings_20250101_121000.txt
```

## **Error Handling Strategy**

### **Prerequisites Check**
1. **Gemini CLI Available**: Check if `gemini` command exists
2. **Directory Permissions**: Ensure output directory is writable and accessible
3. **Working Directory**: Verify we can execute from the output directory
4. **Context Files Present**: Confirm analysis files exist in output directory
5. **Prompt Validation**: Ensure prompt is not empty

### **Runtime Error Handling**
1. **Directory Access**: Verify output directory exists and is accessible before execution
2. **Shell Command Execution**: Handle shell command failures and directory changes
3. **Command Timeout**: 5-minute timeout for CLI command
4. **Network Issues**: Handle API connectivity problems
5. **Rate Limiting**: Handle Gemini API rate limit responses
6. **File I/O**: Handle permission and disk space issues
7. **Prompt Escaping**: Handle special characters in prompts for shell execution

### **User-Friendly Error Messages**
```python
❌ ERROR: 'gemini' command not found.
Please ensure Gemini CLI is installed and in your system PATH.
Installation: npm install -g @google-ai/generative-ai-cli

❌ ERROR: Gemini CLI command timed out after 5 minutes
This may indicate network connectivity issues or a very complex prompt.

❌ ERROR: Permission denied creating directory: /path/to/outputs
Please ensure you have write permissions to the output directory.

❌ ERROR: Cannot access output directory for execution
Gemini CLI must execute from within the output directory to access analysis files.
Please check directory permissions and path validity.

❌ ERROR: Shell command execution failed
Could not change to output directory or execute Gemini CLI.
Check that the directory path is valid and you have necessary permissions.
```

## **Resource Tracking Integration**

### **File Tracking**
Generated response files will be tracked using the existing GlobalResourceTracker:

```python
# In main automatool workflow (if integrated)
gemini_response_file = send_prompt_to_gemini(prompt, target_dir, args.verbose)
if gemini_response_file:
    resource_tracker.add_file(gemini_response_file)
```

### **Directory Tracking**
The `outputs/` directory will be tracked as a resource:

```python
outputs_dir = os.path.join(target_dir, "prompts", "outputs")
if os.path.exists(outputs_dir):
    resource_tracker.add_directory(outputs_dir)
```

## **Testing Strategy**

### **Unit Tests**
- Filename generation from various prompt formats
- Directory creation and permissions
- Error handling for missing CLI tool
- Command timeout behavior

### **Integration Tests**
- Full workflow with mock Gemini CLI responses
- Resource tracker integration
- File system operations

### **Manual Testing**
- Real Gemini CLI commands with various prompt types
- Long prompts and response handling
- Network connectivity edge cases

## **Future Enhancements**

1. **Prompt Templates**: Pre-defined security analysis prompts that leverage available context
2. **Batch Processing**: Multiple prompts in sequence for comprehensive analysis
3. **Response Parsing**: Structure specific types of responses (threats, recommendations, etc.)
4. **Configuration Options**: Custom timeouts, model selection, context inclusion flags
5. **Web UI Integration**: Add to automatool_ui for GUI access
6. **Selective Context**: Options to include/exclude specific file types from context

## **Security Considerations**

### **Gemini CLI Workspace Restrictions**
**CRITICAL SECURITY FEATURE**: Gemini CLI restricts file access to the current working directory only.

- ✅ **Secure by Design**: Cannot access files outside the execution directory
- ✅ **Prevents Data Leaks**: Analysis results stay within the designated workspace
- ⚠️ **Working Directory Matters**: MUST execute from output directory to provide context

### **Example of Security Restriction and Directory Context**
```bash
# Automation runs from /path/to/automatool/ but needs analysis files:

# WRONG - Gemini executes from automatool directory:
cd /path/to/automatool/
gemini -p "analyze the reviews.json file"
# Result: "File not found" - reviews.json is not in automatool directory

# CORRECT - Our implementation changes to output directory first:
cd /home/user/apk_analysis/app1/
gemini -p "analyze the reviews.json file" --all-files  
# Result: Successfully analyzes reviews.json, yara_summary.txt, etc.

# Security still applies - cannot access other app directories:
cd /home/user/apk_analysis/app1/
gemini -p "access /home/user/apk_analysis/app2/"
# Result: "Access denied - Path must be within workspace directory"
```

### **Additional Security Measures**
1. **API Key Management**: Ensure Gemini API keys are properly configured
2. **Prompt Sanitization**: Validate prompt content before sending
3. **Response Filtering**: Consider filtering sensitive information from responses
4. **Rate Limiting**: Respect Gemini API rate limits
5. **Directory Isolation**: Each APK analysis is isolated to its own directory

## **Dependencies**

### **System Requirements**
- Google Generative AI CLI (`gemini` command)
- Node.js and npm (for CLI installation)
- Python 3.7+
- Internet connectivity for Gemini API

### **Python Packages**
No additional Python packages required beyond standard library:
- `os` (file operations)
- `subprocess` (CLI execution)  
- `re` (filename generation)
- `datetime` (timestamp generation)

### **Installation Command**
```bash
npm install -g @google-ai/generative-ai-cli
```

## **Success Criteria**

1. ✅ **CLI Integration**: Successfully execute Gemini CLI commands
2. ✅ **File Storage**: Generate properly named output files
3. ✅ **Directory Structure**: Create and organize output directories
4. ✅ **Error Handling**: Comprehensive error messages and recovery
5. ✅ **Resource Tracking**: Full integration with existing tracker
6. ✅ **Pattern Compliance**: Follow existing automation patterns
