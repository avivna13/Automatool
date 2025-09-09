# utils/path_validator.py
import os

class PathValidator:
    def __init__(self):
        pass
    
    def validate_directory(self, directory_path):
        """Validate that directory exists and is accessible."""
        if not directory_path:
            return False, "Directory path cannot be empty"
        
        # Convert to absolute path
        abs_path = os.path.abspath(directory_path)
        
        # Check if directory exists
        if not os.path.exists(abs_path):
            return False, f"Directory does not exist: {abs_path}"
        
        # Check if it's actually a directory
        if not os.path.isdir(abs_path):
            return False, f"Path is not a directory: {abs_path}"
        
        # Check if directory is readable
        if not os.access(abs_path, os.R_OK):
            return False, f"Directory is not readable: {abs_path}"
        
        # Check if directory is writable
        if not os.access(abs_path, os.W_OK):
            return False, f"Directory is not writable: {abs_path}"
        
        return True, abs_path
    
    def validate_apk_file(self, directory_path, apk_filename):
        """Validate that APK file exists in directory."""
        if not apk_filename:
            return False, "APK filename cannot be empty"
        
        # Validate directory first
        dir_valid, dir_result = self.validate_directory(directory_path)
        if not dir_valid:
            return False, dir_result
        
        # Construct full APK path
        apk_path = os.path.join(dir_result, apk_filename)
        
        # Check if APK file exists
        if not os.path.exists(apk_path):
            return False, f"APK file does not exist: {apk_path}"
        
        # Check if it's actually a file
        if not os.path.isfile(apk_path):
            return False, f"APK path is not a file: {apk_path}"
        
        # Check if file is readable
        if not os.access(apk_path, os.R_OK):
            return False, f"APK file is not readable: {apk_path}"
        
        # Check file extension
        if not apk_filename.lower().endswith('.apk'):
            return False, f"File must have .apk extension: {apk_filename}"
        
        return True, apk_path
    
    def sanitize_path(self, path):
        """Sanitize path to prevent path traversal attacks."""
        if not path:
            return ""
        
        # Remove any path traversal attempts
        path = path.replace('..', '')
        path = path.replace('//', '/')
        path = path.replace('\\\\', '\\')
        
        # Convert to absolute path for safety
        return os.path.abspath(path)
