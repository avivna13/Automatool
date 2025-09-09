import os
import threading
import time
import json
from datetime import datetime
from scripts.automations.launch_reviews_scraper import run_reviews_scraper
from scripts.automations.parse_reviews_summary import parse_reviews_to_summary

# Global result storage
summary_result = None


def _create_fallback_reviews_file(output_directory, verbose):
    """Create a fallback reviews.json when scraper fails."""
    fallback_data = {
        "reviews": [],
        "metadata": {
            "status": "no_reviews_found",
            "message": "Reviews scraper did not find any reviews or failed to complete",
            "timestamp": datetime.now().isoformat(),
            "fallback": True
        }
    }
    
    reviews_file = os.path.join(output_directory, "reviews.json")
    
    try:
        with open(reviews_file, 'w', encoding='utf-8') as f:
            json.dump(fallback_data, f, indent=2, ensure_ascii=False)
        
        if verbose:
            print(f"[DEBUG] Created fallback reviews file: {reviews_file}")
            
    except Exception as e:
        if verbose:
            print(f"[DEBUG] Failed to create fallback file: {e}")
        # Create minimal fallback
        try:
            with open(reviews_file, 'w') as f:
                f.write('{"reviews": [], "error": "fallback_creation_failed"}')
        except:
            pass  # Last resort - continue without file


def _wait_and_parse(output_directory, verbose, timeout=60):
    """Wait for reviews.json file with timeout and fallback."""
    global summary_result
    
    reviews_file = os.path.join(output_directory, "reviews.json")
    start_time = time.time()
    
    if verbose:
        print(f"[DEBUG] Parser thread waiting for file: {reviews_file}")
        print(f"[DEBUG] Timeout set to: {timeout} seconds")
    
    # Wait for file with timeout
    while not os.path.exists(reviews_file):
        elapsed = time.time() - start_time
        if elapsed > timeout:
            if verbose:
                print(f"[DEBUG] Timeout reached after {elapsed:.1f}s, creating fallback file")
            _create_fallback_reviews_file(output_directory, verbose)
            break
        time.sleep(0.1)
    
    if verbose:
        print(f"[DEBUG] File detected or fallback created: {reviews_file}, starting parsing...")
    
    # Parse reviews (either real or fallback)
    try:
        summary_result = parse_reviews_to_summary(output_directory, verbose)
        if verbose:
            print("[DEBUG] Reviews parsing completed")
    except Exception as e:
        if verbose:
            print(f"[DEBUG] Error during parsing: {e}")
        summary_result = "Error: Failed to parse reviews"


def run_reviews_with_parsing(package_name, output_directory, verbose=False, timeout=60):
    """
    Run reviews scraper and parser with threading synchronization and timeout protection.
    
    Args:
        package_name (str): Package name for scraping
        output_directory (str): Output directory for files
        verbose (bool): Enable verbose output
        timeout (int): Timeout in seconds for waiting for reviews.json file (default: 60)
        
    Returns:
        str: Summary result from parser, or error message if parsing fails
        
    Raises:
        No exceptions raised - function always returns a result
    """
    global summary_result
    
    if verbose:
        print("[DEBUG] Starting threaded reviews automation...")
        print(f"[DEBUG] Timeout configuration: {timeout}s for file wait, {timeout + 5}s for thread join")
    
    # Reset result
    summary_result = None
    
    # Start parser thread with timeout protection
    parser_thread = threading.Thread(
        target=_wait_and_parse, 
        args=(output_directory, verbose, timeout),
        daemon=True  # Safety: thread won't block main process
    )
    parser_thread.start()
    
    if verbose:
        print("[DEBUG] Parser thread started, beginning scraping...")
    
    # Run scraper (blocking) - creates reviews.json when done
    scraper_success = run_reviews_scraper(package_name, output_directory, verbose)
    
    if verbose:
        print("[DEBUG] Scraping completed, waiting for parser to finish...")
    
    # Wait for parser with timeout protection
    thread_timeout = timeout + 5  # Extra buffer for thread completion
    parser_thread.join(timeout=thread_timeout)
    
    # Check if thread is still alive (timeout occurred)
    if parser_thread.is_alive():
        if verbose:
            print(f"[DEBUG] Parser thread did not complete within {thread_timeout}s")
            print("[DEBUG] Forcing fallback file creation and parsing")
        
        # Force fallback file creation and parsing
        _create_fallback_reviews_file(output_directory, verbose)
        try:
            summary_result = parse_reviews_to_summary(output_directory, verbose)
        except Exception as e:
            if verbose:
                print(f"[DEBUG] Error during fallback parsing: {e}")
            summary_result = "Error: Failed to parse reviews (fallback)"
    
    if verbose:
        print("[DEBUG] Threaded reviews automation completed")
    
    return summary_result
