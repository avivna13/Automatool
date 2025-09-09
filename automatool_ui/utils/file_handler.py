# utils/file_handler.py
import os
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename

class FileHandler:
    def __init__(self, upload_dir='static/uploads', max_size=500*1024*1024):
        self.upload_dir = upload_dir
        self.max_size = max_size
        self.allowed_extensions = {'.apk', '.json'}
    
    def create_analysis_directory(self):
        """Create timestamped analysis directory."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        dir_name = f"{timestamp}_analysis"
        full_path = os.path.join(self.upload_dir, dir_name)
        
        # If directory already exists, add microseconds for uniqueness
        if os.path.exists(full_path):
            timestamp_with_micro = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            dir_name = f"{timestamp_with_micro}_analysis"
            full_path = os.path.join(self.upload_dir, dir_name)
        
        os.makedirs(full_path, exist_ok=True)
        return full_path
    
    def validate_and_save_apk(self, file, output_dir):
        """Validate and save uploaded APK file."""
        if not file or not file.filename:
            return None, "No file provided"
        
        if not file.filename.lower().endswith('.apk'):
            return None, "File must be an APK"
        
        # Check file size by reading content
        file_content = file.read()
        if len(file_content) > self.max_size:
            return None, f"File too large (max {self.max_size//1024//1024}MB)"
        
        # Reset file pointer and save
        file.seek(0)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(output_dir, filename)
        
        # Save the file
        with open(filepath, 'wb') as f:
            f.write(file_content)
        
        return filepath, None
    
    def validate_and_save_yara(self, file, output_dir):
        """Validate and save uploaded YARA JSON file."""
        if not file or not file.filename:
            return None, None  # YARA is optional
        
        if not file.filename.lower().endswith('.json'):
            return None, "YARA file must be JSON"
        
        filename = "yara.json"  # Standardize name
        filepath = os.path.join(output_dir, filename)
        file.save(filepath)
        
        return filepath, None
    
    def is_valid_extension(self, filename, extension):
        """Check if file has valid extension."""
        return filename.lower().endswith(extension.lower())
    
    def get_file_size_mb(self, filepath):
        """Get file size in MB."""
        if os.path.exists(filepath):
            size_bytes = os.path.getsize(filepath)
            return size_bytes / (1024 * 1024)
        return 0
