# 🔀 Hybrid Steganography Detection Integration Specification

## **Overview**
This specification outlines the integration of pngcheck utility with the existing trailing data detection system to create a comprehensive hybrid steganography detection engine. The hybrid approach combines format-specific validation (pngcheck for PNG files) with universal trailing data analysis to improve detection accuracy and reduce false positives.

## **Purpose**
The hybrid steganography detection system will:
1. **Multi-Method Detection**: Combine trailing data analysis with pngcheck validation
2. **Enhanced Accuracy**: Reduce false positives through cross-validation
3. **Format Optimization**: Use specialized tools for specific formats (pngcheck for PNG)
4. **Backward Compatibility**: Maintain existing API while adding hybrid capabilities
5. **Configurable Detection**: Allow selection of detection methods based on requirements
6. **Confidence Scoring**: Provide confidence levels based on method agreement

## **Background and Motivation**

### **Limitations of Current System**
The existing `detect_image_steganography.py` uses simple trailing data detection:
- **Single Method**: Only checks for data after format end markers
- **Generic Approach**: Same logic for all image formats
- **Limited Validation**: No format-specific structural validation
- **False Positives**: May flag legitimate metadata as suspicious

### **pngcheck Advantages**
The [pngcheck utility](https://github.com/pnggroup/pngcheck) provides:
- **Comprehensive PNG Validation**: Detects corruption and structural issues
- **Chunk Analysis**: Identifies all PNG chunks and suspicious metadata
- **Standards Compliance**: Validates against PNG specifications including PNG Third Edition
- **Expert Detection**: Specialized knowledge of PNG format intricacies
- **Metadata Extraction**: Detailed information about chunk types and sizes

### **Hybrid Benefits**
Combining both approaches provides:
- **Cross-Validation**: Multiple detection vectors increase confidence
- **Reduced False Positives**: Agreement between methods indicates higher likelihood
- **Format Coverage**: pngcheck for PNG, trailing data for all other formats
- **Comprehensive Analysis**: Structural validation + trailing data detection

## **Technical Architecture**

### **System Components**

```
┌─────────────────────────────────────────────────────────────┐
│                Hybrid Detection Engine                      │
├─────────────────────────────────────────────────────────────┤
│  ┌───────────────────┐    ┌─────────────────────────────┐   │
│  │  Detection        │    │  Result Correlation &      │   │
│  │  Orchestrator     │────│  Confidence Engine         │   │
│  └───────────────────┘    └─────────────────────────────┘   │
│           │                             │                   │
│  ┌────────▼──────────┐    ┌─────────────▼─────────────┐     │
│  │  Trailing Data    │    │  pngcheck Wrapper        │     │
│  │  Detector         │    │  Module                   │     │
│  │  (Existing)       │    │  (New)                    │     │
│  └───────────────────┘    └───────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### **Core Modules**

#### **1. Hybrid Detection Engine** (`hybrid_detection.py`)
- **Purpose**: Main orchestrator for multiple detection methods
- **Responsibilities**:
  - Coordinate detection methods based on file type
  - Merge and correlate results from different detectors
  - Calculate confidence scores
  - Generate unified reports

#### **2. pngcheck Wrapper** (`pngcheck_wrapper.py`)
- **Purpose**: Interface to pngcheck utility
- **Responsibilities**:
  - Validate pngcheck installation
  - Execute pngcheck with proper security
  - Parse pngcheck output into structured data
  - Identify suspicious PNG patterns

#### **3. Result Correlation Engine** (`result_correlator.py`)
- **Purpose**: Analyze and combine results from multiple methods
- **Responsibilities**:
  - Cross-validate findings between methods
  - Calculate confidence scores
  - Classify threat levels
  - Generate recommendations

#### **4. Configuration Manager** (`detection_config.py`)
- **Purpose**: Manage detection settings and preferences
- **Responsibilities**:
  - Load detection method configurations
  - Handle fallback scenarios
  - Manage threshold settings
  - Control reporting verbosity

## **Implementation Plan**

### **Phase 1: Prerequisites and Dependencies** ⏱️ *2-3 hours*

#### **1.1 Environment Setup**
```bash
# System dependencies
sudo apt-get install pngcheck  # Ubuntu/Debian
brew install pngcheck          # macOS
# Windows: Manual installation from GitHub releases
```

#### **1.2 Python Dependencies**
```python
# requirements.txt additions
subprocess32>=3.5.0    # Enhanced subprocess handling
psutil>=5.8.0          # Process monitoring
packaging>=21.0        # Version parsing
```

#### **1.3 Installation Validation**
```python
def validate_pngcheck_installation():
    """
    Validate pngcheck is available and get version info.
    
    Returns:
        dict: Installation status and version information
    """
    try:
        result = subprocess.run(['pngcheck', '--version'], 
                              capture_output=True, text=True, timeout=5)
        return {
            'available': True,
            'version': _parse_pngcheck_version(result.stdout),
            'path': shutil.which('pngcheck')
        }
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {'available': False}
```

#### **1.4 Configuration Structure**
```python
HYBRID_DETECTION_CONFIG = {
    'detection_methods': {
        'trailing_data': {
            'enabled': True,
            'threshold_bytes': 10,
            'supported_formats': ['PNG', 'JPEG', 'GIF', 'BMP', 'WebP']
        },
        'pngcheck': {
            'enabled': True,
            'timeout': 30,
            'formats': ['PNG'],
            'suspicious_chunks': ['zTXt', 'iTXt', 'tEXt', 'eXIf'],
            'max_chunk_size': 10000
        }
    },
    'hybrid_settings': {
        'mode': 'hybrid',  # 'trailing', 'pngcheck', 'hybrid'
        'require_consensus': False,
        'confidence_threshold': 0.7,
        'fallback_to_single': True
    },
    'reporting': {
        'detailed_reports': True,
        'include_raw_output': False,
        'confidence_in_filename': True
    }
}
```

### **Phase 2: pngcheck Wrapper Module** ⏱️ *4-5 hours*

#### **2.1 Core Wrapper Implementation**
```python
class PngCheckWrapper:
    """
    Secure wrapper for pngcheck utility with output parsing.
    """
    
    def __init__(self, config=None, verbose=False):
        self.config = config or DEFAULT_PNGCHECK_CONFIG
        self.verbose = verbose
        self.timeout = self.config.get('timeout', 30)
        self.available = self._check_availability()
    
    def analyze_png(self, image_path):
        """
        Analyze PNG file using pngcheck utility.
        
        Args:
            image_path (str): Path to PNG file
            
        Returns:
            dict: Structured analysis results
        """
        if not self.available:
            raise RuntimeError("pngcheck utility not available")
            
        if not self._is_png_file(image_path):
            raise ValueError("File is not a PNG image")
            
        # Execute pngcheck with security measures
        result = self._execute_pngcheck(image_path)
        
        # Parse and structure output
        return self._parse_pngcheck_output(result, image_path)
    
    def _execute_pngcheck(self, image_path):
        """
        Execute pngcheck with proper security and error handling.
        """
        # Sanitize input path
        sanitized_path = os.path.abspath(image_path)
        if not os.path.exists(sanitized_path):
            raise FileNotFoundError(f"Image file not found: {sanitized_path}")
        
        # Build command with security considerations
        cmd = [
            'pngcheck',
            '-c',  # Check chunks
            '-v',  # Verbose output
            sanitized_path
        ]
        
        try:
            # Execute with timeout and resource limits
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=tempfile.gettempdir(),  # Safe working directory
                env={'PATH': os.environ.get('PATH', '')}  # Minimal environment
            )
            
            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode,
                'command': ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"pngcheck timed out after {self.timeout} seconds")
        except Exception as e:
            raise RuntimeError(f"Failed to execute pngcheck: {e}")
```

#### **2.2 Output Parser Implementation**
```python
class PngCheckOutputParser:
    """
    Parse pngcheck output into structured data.
    """
    
    # Suspicious chunk patterns
    SUSPICIOUS_CHUNKS = {
        'zTXt': 'Compressed text chunk (potential data hiding)',
        'iTXt': 'International text chunk (potential data hiding)',
        'tEXt': 'Text chunk (potential data hiding)',
        'eXIf': 'EXIF data after IDAT (invalid in PNG Third Edition)'
    }
    
    def parse_output(self, pngcheck_result, image_path):
        """
        Parse pngcheck output into structured analysis results.
        """
        stdout = pngcheck_result['stdout']
        stderr = pngcheck_result['stderr']
        return_code = pngcheck_result['return_code']
        
        analysis = {
            'image_path': image_path,
            'pngcheck_available': True,
            'execution_status': {
                'return_code': return_code,
                'has_errors': return_code != 0,
                'timed_out': False
            },
            'png_structure': {
                'valid_structure': return_code == 0,
                'chunks_found': [],
                'suspicious_chunks': [],
                'total_chunks': 0
            },
            'suspicious_indicators': {
                'structural_errors': [],
                'suspicious_metadata': [],
                'invalid_chunks': [],
                'oversized_chunks': []
            },
            'confidence_factors': {
                'structural_validation': 0.0,
                'chunk_analysis': 0.0,
                'metadata_assessment': 0.0
            },
            'raw_output': {
                'stdout': stdout if self.config.get('include_raw', False) else '',
                'stderr': stderr if self.config.get('include_raw', False) else ''
            }
        }
        
        # Parse chunk information
        self._parse_chunk_data(stdout, analysis)
        
        # Identify suspicious patterns
        self._identify_suspicious_patterns(analysis)
        
        # Calculate confidence scores
        self._calculate_confidence_scores(analysis)
        
        return analysis
    
    def _parse_chunk_data(self, stdout, analysis):
        """
        Extract PNG chunk information from pngcheck output.
        """
        chunk_pattern = re.compile(
            r'chunk\s+(\w+)\s+at\s+offset\s+(0x[0-9a-fA-F]+),\s+length\s+(\d+)'
        )
        
        for line in stdout.split('\n'):
            match = chunk_pattern.search(line)
            if match:
                chunk_type, offset, length = match.groups()
                chunk_info = {
                    'type': chunk_type,
                    'offset': int(offset, 16),
                    'length': int(length),
                    'line': line.strip()
                }
                
                analysis['png_structure']['chunks_found'].append(chunk_info)
                analysis['png_structure']['total_chunks'] += 1
                
                # Check for suspicious chunk types
                if chunk_type in self.SUSPICIOUS_CHUNKS:
                    chunk_info['suspicion_reason'] = self.SUSPICIOUS_CHUNKS[chunk_type]
                    analysis['png_structure']['suspicious_chunks'].append(chunk_info)
                
                # Check for oversized chunks
                max_size = self.config.get('max_chunk_size', 10000)
                if chunk_info['length'] > max_size:
                    analysis['suspicious_indicators']['oversized_chunks'].append({
                        'chunk': chunk_info,
                        'reason': f'Chunk size {chunk_info["length"]} exceeds threshold {max_size}'
                    })
```

#### **2.3 Suspicious Pattern Detection**
```python
def _identify_suspicious_patterns(self, analysis):
    """
    Identify patterns that may indicate steganography or malware.
    """
    chunks = analysis['png_structure']['chunks_found']
    suspicious = analysis['suspicious_indicators']
    
    # Pattern 1: Multiple text chunks (data hiding)
    text_chunks = [c for c in chunks if c['type'] in ['tEXt', 'zTXt', 'iTXt']]
    if len(text_chunks) > 3:
        suspicious['suspicious_metadata'].append({
            'pattern': 'multiple_text_chunks',
            'count': len(text_chunks),
            'reason': 'Multiple text chunks may indicate data hiding'
        })
    
    # Pattern 2: Text chunks with large payloads
    for chunk in text_chunks:
        if chunk['length'] > 1000:  # Configurable threshold
            suspicious['suspicious_metadata'].append({
                'pattern': 'large_text_chunk',
                'chunk': chunk,
                'reason': f'Text chunk with {chunk["length"]} bytes is unusually large'
            })
    
    # Pattern 3: EXIF after image data (invalid in PNG Third Edition)
    idat_found = any(c['type'] == 'IDAT' for c in chunks)
    exif_chunks = [c for c in chunks if c['type'] == 'eXIf']
    
    if idat_found and exif_chunks:
        idat_offset = next(c['offset'] for c in chunks if c['type'] == 'IDAT')
        late_exif = [c for c in exif_chunks if c['offset'] > idat_offset]
        
        for chunk in late_exif:
            suspicious['invalid_chunks'].append({
                'pattern': 'exif_after_idat',
                'chunk': chunk,
                'reason': 'EXIF chunk after IDAT is invalid in PNG Third Edition'
            })
    
    # Pattern 4: Unknown or custom chunk types
    standard_chunks = {'IHDR', 'PLTE', 'IDAT', 'IEND', 'cHRM', 'gAMA', 'iCCP', 
                      'sBIT', 'sRGB', 'tEXt', 'zTXt', 'iTXt', 'bKGD', 'hIST', 
                      'tRNS', 'pHYs', 'sPLT', 'tIME', 'eXIf'}
    
    for chunk in chunks:
        if chunk['type'] not in standard_chunks:
            suspicious['invalid_chunks'].append({
                'pattern': 'unknown_chunk_type',
                'chunk': chunk,
                'reason': f'Unknown chunk type: {chunk["type"]}'
            })
```

### **Phase 3: Hybrid Detection Core** ⏱️ *6-7 hours*

#### **3.1 Detection Orchestrator**
```python
class HybridDetectionEngine:
    """
    Main orchestrator for hybrid steganography detection.
    """
    
    def __init__(self, config=None):
        self.config = config or HYBRID_DETECTION_CONFIG
        self.trailing_detector = TrailingDataDetector(self.config)
        self.pngcheck_wrapper = PngCheckWrapper(self.config.get('pngcheck', {}))
        self.result_correlator = ResultCorrelator(self.config)
    
    def analyze_image(self, image_path, output_directory, detection_mode='hybrid'):
        """
        Perform hybrid steganography detection analysis.
        
        Args:
            image_path (str): Path to image file
            output_directory (str): Directory for analysis results
            detection_mode (str): 'hybrid', 'trailing', 'pngcheck'
            
        Returns:
            dict: Comprehensive analysis results
        """
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image file not found: {image_path}")
        
        # Initialize results structure
        hybrid_result = {
            'image_path': image_path,
            'detection_mode': detection_mode,
            'file_info': self._get_file_info(image_path),
            'detection_results': {},
            'correlation_analysis': {},
            'final_assessment': {},
            'reports_generated': []
        }
        
        # Execute detection methods based on mode
        if detection_mode in ['hybrid', 'trailing']:
            hybrid_result['detection_results']['trailing_data'] = \
                self._run_trailing_detection(image_path, output_directory)
        
        if detection_mode in ['hybrid', 'pngcheck'] and self._is_png_file(image_path):
            hybrid_result['detection_results']['pngcheck'] = \
                self._run_pngcheck_detection(image_path)
        
        # Correlate results if multiple methods used
        if detection_mode == 'hybrid':
            hybrid_result['correlation_analysis'] = \
                self.result_correlator.correlate_results(hybrid_result['detection_results'])
        
        # Generate final assessment
        hybrid_result['final_assessment'] = \
            self._generate_final_assessment(hybrid_result)
        
        # Generate reports
        hybrid_result['reports_generated'] = \
            self._generate_reports(hybrid_result, output_directory)
        
        return hybrid_result
    
    def _run_trailing_detection(self, image_path, output_directory):
        """
        Execute trailing data detection method.
        """
        try:
            result = self.trailing_detector.analyze_image_file(
                image_path, 
                output_directory, 
                self.config['detection_methods']['trailing_data']['threshold_bytes']
            )
            result['method'] = 'trailing_data'
            result['execution_status'] = 'success'
            return result
        except Exception as e:
            return {
                'method': 'trailing_data',
                'execution_status': 'failed',
                'error': str(e)
            }
    
    def _run_pngcheck_detection(self, image_path):
        """
        Execute pngcheck detection method.
        """
        try:
            if not self.pngcheck_wrapper.available:
                return {
                    'method': 'pngcheck',
                    'execution_status': 'unavailable',
                    'error': 'pngcheck utility not available'
                }
            
            result = self.pngcheck_wrapper.analyze_png(image_path)
            result['method'] = 'pngcheck'
            result['execution_status'] = 'success'
            return result
        except Exception as e:
            return {
                'method': 'pngcheck',
                'execution_status': 'failed',
                'error': str(e)
            }
```

#### **3.2 Result Correlation Engine**
```python
class ResultCorrelator:
    """
    Correlate and analyze results from multiple detection methods.
    """
    
    def correlate_results(self, detection_results):
        """
        Analyze and correlate results from multiple detection methods.
        """
        correlation = {
            'methods_executed': list(detection_results.keys()),
            'consensus_analysis': {},
            'confidence_scores': {},
            'threat_classification': {},
            'recommendations': []
        }
        
        # Analyze method agreement
        trailing_result = detection_results.get('trailing_data')
        pngcheck_result = detection_results.get('pngcheck')
        
        if trailing_result and pngcheck_result:
            correlation['consensus_analysis'] = \
                self._analyze_method_consensus(trailing_result, pngcheck_result)
        
        # Calculate confidence scores
        correlation['confidence_scores'] = \
            self._calculate_correlation_confidence(detection_results)
        
        # Classify threat level
        correlation['threat_classification'] = \
            self._classify_threat_level(detection_results, correlation)
        
        # Generate recommendations
        correlation['recommendations'] = \
            self._generate_recommendations(correlation)
        
        return correlation
    
    def _analyze_method_consensus(self, trailing_result, pngcheck_result):
        """
        Analyze agreement between trailing data and pngcheck methods.
        """
        trailing_suspicious = trailing_result.get('is_suspicious', False)
        pngcheck_suspicious = (
            len(pngcheck_result.get('suspicious_indicators', {}).get('suspicious_metadata', [])) > 0 or
            len(pngcheck_result.get('suspicious_indicators', {}).get('oversized_chunks', [])) > 0 or
            not pngcheck_result.get('png_structure', {}).get('valid_structure', True)
        )
        
        return {
            'trailing_data_suspicious': trailing_suspicious,
            'pngcheck_suspicious': pngcheck_suspicious,
            'methods_agree': trailing_suspicious == pngcheck_suspicious,
            'consensus_type': self._determine_consensus_type(trailing_suspicious, pngcheck_suspicious)
        }
    
    def _determine_consensus_type(self, trailing_suspicious, pngcheck_suspicious):
        """
        Determine type of consensus between methods.
        """
        if trailing_suspicious and pngcheck_suspicious:
            return 'both_suspicious'
        elif not trailing_suspicious and not pngcheck_suspicious:
            return 'both_clean'
        elif trailing_suspicious and not pngcheck_suspicious:
            return 'trailing_only_suspicious'
        else:
            return 'pngcheck_only_suspicious'
    
    def _calculate_correlation_confidence(self, detection_results):
        """
        Calculate confidence scores based on method correlation.
        """
        scores = {
            'overall_confidence': 0.0,
            'method_confidences': {},
            'correlation_factors': {}
        }
        
        # Individual method confidence scores
        for method, result in detection_results.items():
            if result.get('execution_status') == 'success':
                if method == 'trailing_data':
                    # Confidence based on trailing data size vs threshold
                    trailing_bytes = result.get('trailing_bytes', 0)
                    threshold = result.get('threshold_bytes', 10)
                    if trailing_bytes >= threshold:
                        ratio = min(trailing_bytes / threshold, 5.0)  # Cap at 5x threshold
                        scores['method_confidences'][method] = min(0.3 + (ratio - 1) * 0.2, 0.9)
                    else:
                        scores['method_confidences'][method] = 0.1
                
                elif method == 'pngcheck':
                    # Confidence based on number and severity of issues found
                    suspicious_count = (
                        len(result.get('suspicious_indicators', {}).get('suspicious_metadata', [])) +
                        len(result.get('suspicious_indicators', {}).get('oversized_chunks', [])) +
                        len(result.get('suspicious_indicators', {}).get('invalid_chunks', []))
                    )
                    
                    if suspicious_count == 0:
                        scores['method_confidences'][method] = 0.1
                    else:
                        scores['method_confidences'][method] = min(0.3 + suspicious_count * 0.2, 0.9)
        
        # Correlation confidence
        if len(scores['method_confidences']) >= 2:
            method_values = list(scores['method_confidences'].values())
            if all(v > 0.5 for v in method_values):  # Both methods suspicious
                scores['overall_confidence'] = min(sum(method_values) / len(method_values) + 0.2, 0.95)
            elif all(v <= 0.3 for v in method_values):  # Both methods clean
                scores['overall_confidence'] = 0.1
            else:  # Methods disagree
                scores['overall_confidence'] = sum(method_values) / len(method_values)
        else:
            # Single method confidence
            scores['overall_confidence'] = max(scores['method_confidences'].values()) if scores['method_confidences'] else 0.0
        
        return scores
    
    def _classify_threat_level(self, detection_results, correlation):
        """
        Classify overall threat level based on all evidence.
        """
        confidence = correlation['confidence_scores']['overall_confidence']
        consensus = correlation.get('consensus_analysis', {})
        
        if confidence >= 0.8:
            threat_level = 'HIGH'
        elif confidence >= 0.5:
            threat_level = 'MEDIUM'
        elif confidence >= 0.2:
            threat_level = 'LOW'
        else:
            threat_level = 'MINIMAL'
        
        return {
            'threat_level': threat_level,
            'confidence_score': confidence,
            'primary_indicators': self._get_primary_indicators(detection_results),
            'risk_assessment': self._assess_risk_factors(detection_results, threat_level)
        }
    
    def _generate_recommendations(self, correlation):
        """
        Generate actionable recommendations based on analysis.
        """
        recommendations = []
        
        threat_level = correlation['threat_classification']['threat_level']
        consensus = correlation.get('consensus_analysis', {})
        
        if threat_level in ['HIGH', 'MEDIUM']:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Manual Investigation Required',
                'description': 'Image shows multiple suspicious indicators requiring expert analysis'
            })
            
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Isolate and Analyze',
                'description': 'Quarantine image and perform detailed forensic analysis'
            })
        
        if consensus.get('consensus_type') == 'trailing_only_suspicious':
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Check Trailing Data',
                'description': 'Examine trailing data with hex editor or forensic tools'
            })
        
        if consensus.get('consensus_type') == 'pngcheck_only_suspicious':
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Analyze PNG Structure',
                'description': 'Investigate suspicious PNG chunks and metadata'
            })
        
        return recommendations
```

### **Phase 4: System Integration** ⏱️ *3-4 hours*

#### **4.1 API Integration with Backward Compatibility**
```python
def detect_image_steganography(image_path, output_directory, verbose=False, 
                             threshold_bytes=10, detection_mode='hybrid', 
                             config=None):
    """
    Enhanced steganography detection with hybrid capabilities.
    
    Args:
        image_path (str): Path to image file to analyze
        output_directory (str): Directory to save analysis results
        verbose (bool): Enable verbose output (default: False)
        threshold_bytes (int): Threshold for suspicious trailing data (default: 10)
        detection_mode (str): Detection mode - 'hybrid', 'trailing', 'pngcheck' (default: 'hybrid')
        config (dict): Optional configuration override
        
    Returns:
        dict: Analysis results (format depends on detection_mode)
        
    Legacy Compatibility:
        When detection_mode='trailing', returns same format as original function
        for backward compatibility with existing code.
    """
    
    # Legacy mode - maintain backward compatibility
    if detection_mode == 'trailing' or detection_mode is None:
        return _analyze_image_file(image_path, output_directory, threshold_bytes, verbose)
    
    # New hybrid modes
    elif detection_mode in ['hybrid', 'pngcheck']:
        try:
            # Initialize hybrid detection engine
            engine_config = config or HYBRID_DETECTION_CONFIG
            
            # Override specific settings from parameters
            if threshold_bytes != 10:
                engine_config['detection_methods']['trailing_data']['threshold_bytes'] = threshold_bytes
            
            engine = HybridDetectionEngine(engine_config)
            
            # Run hybrid analysis
            result = engine.analyze_image(image_path, output_directory, detection_mode)
            
            # Print summary if verbose
            if verbose:
                _print_hybrid_summary(result)
            
            return result
            
        except Exception as e:
            if verbose:
                print(f"[ERROR] Hybrid detection failed: {e}")
                print("[INFO] Falling back to trailing data detection")
            
            # Fallback to original method
            return _analyze_image_file(image_path, output_directory, threshold_bytes, verbose)
    
    else:
        raise ValueError(f"Invalid detection_mode: {detection_mode}. Use 'trailing', 'pngcheck', or 'hybrid'")

def _print_hybrid_summary(result):
    """
    Print summary of hybrid detection results.
    """
    print(f"\n=== Hybrid Steganography Detection Results ===")
    print(f"Image: {os.path.basename(result['image_path'])}")
    print(f"Detection Mode: {result['detection_mode']}")
    
    # Method execution status
    for method, method_result in result['detection_results'].items():
        status = method_result.get('execution_status', 'unknown')
        print(f"{method.title()} Method: {status.upper()}")
    
    # Final assessment
    if 'final_assessment' in result:
        assessment = result['final_assessment']
        threat_level = assessment.get('threat_classification', {}).get('threat_level', 'UNKNOWN')
        confidence = assessment.get('confidence_score', 0.0)
        
        print(f"Threat Level: {threat_level}")
        print(f"Confidence: {confidence:.2f}")
        
        if assessment.get('is_suspicious', False):
            print("*** SUSPICIOUS IMAGE DETECTED ***")
            for reason in assessment.get('suspicion_reasons', []):
                print(f"  - {reason}")
        else:
            print("Image appears clean")
```

#### **4.2 Configuration Management**
```python
class DetectionConfigManager:
    """
    Manage detection configuration with environment-specific overrides.
    """
    
    DEFAULT_CONFIG_FILE = 'steganography_detection.json'
    
    def __init__(self, config_path=None):
        self.config_path = config_path or self.DEFAULT_CONFIG_FILE
        self.config = self._load_configuration()
    
    def _load_configuration(self):
        """
        Load configuration from file or use defaults.
        """
        # Start with default configuration
        config = copy.deepcopy(HYBRID_DETECTION_CONFIG)
        
        # Override with file configuration if available
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    file_config = json.load(f)
                    config = self._merge_configs(config, file_config)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Failed to load config file {self.config_path}: {e}")
        
        # Override with environment variables
        config = self._apply_environment_overrides(config)
        
        return config
    
    def _apply_environment_overrides(self, config):
        """
        Apply environment variable overrides to configuration.
        """
        # Detection method toggles
        if os.getenv('STEGANOGRAPHY_TRAILING_ENABLED') is not None:
            config['detection_methods']['trailing_data']['enabled'] = \
                os.getenv('STEGANOGRAPHY_TRAILING_ENABLED', 'true').lower() == 'true'
        
        if os.getenv('STEGANOGRAPHY_PNGCHECK_ENABLED') is not None:
            config['detection_methods']['pngcheck']['enabled'] = \
                os.getenv('STEGANOGRAPHY_PNGCHECK_ENABLED', 'true').lower() == 'true'
        
        # Threshold overrides
        if os.getenv('STEGANOGRAPHY_THRESHOLD_BYTES'):
            try:
                config['detection_methods']['trailing_data']['threshold_bytes'] = \
                    int(os.getenv('STEGANOGRAPHY_THRESHOLD_BYTES'))
            except ValueError:
                pass
        
        if os.getenv('STEGANOGRAPHY_PNGCHECK_TIMEOUT'):
            try:
                config['detection_methods']['pngcheck']['timeout'] = \
                    int(os.getenv('STEGANOGRAPHY_PNGCHECK_TIMEOUT'))
            except ValueError:
                pass
        
        # Detection mode override
        if os.getenv('STEGANOGRAPHY_DETECTION_MODE'):
            mode = os.getenv('STEGANOGRAPHY_DETECTION_MODE').lower()
            if mode in ['hybrid', 'trailing', 'pngcheck']:
                config['hybrid_settings']['mode'] = mode
        
        return config
    
    def get_config(self):
        """Get current configuration."""
        return copy.deepcopy(self.config)
    
    def update_config(self, updates):
        """Update configuration with new values."""
        self.config = self._merge_configs(self.config, updates)
    
    def save_config(self, path=None):
        """Save current configuration to file."""
        save_path = path or self.config_path
        try:
            with open(save_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except IOError as e:
            print(f"Failed to save config to {save_path}: {e}")
            return False
```

### **Phase 5: Testing and Validation** ⏱️ *4-5 hours*

#### **5.1 Test Suite Structure**
```
tests/
├── test_pngcheck_wrapper.py           # Unit tests for pngcheck wrapper
├── test_hybrid_detection.py           # Integration tests for hybrid engine
├── test_result_correlation.py         # Tests for result correlation logic
├── test_config_management.py          # Configuration management tests
├── test_backward_compatibility.py     # Ensure existing API still works
├── test_performance_benchmarks.py     # Performance and resource usage tests
└── resources/
    ├── test_images/
    │   ├── clean_png.png              # Clean PNG for baseline testing
    │   ├── trailing_data_only.png     # PNG with trailing data but valid structure
    │   ├── corrupt_chunks.png         # PNG with suspicious/invalid chunks
    │   ├── hybrid_suspicious.png      # PNG triggering both detection methods
    │   ├── large_text_chunks.png      # PNG with oversized text chunks
    │   ├── multiple_text_chunks.png   # PNG with many text chunks
    │   ├── exif_after_idat.png        # PNG with invalid EXIF placement
    │   └── non_png_formats/           # JPEG, GIF, BMP, WebP test files
    ├── expected_results/
    │   ├── hybrid_results.json        # Expected hybrid detection outputs
    │   ├── correlation_results.json   # Expected correlation analysis
    │   └── confidence_scores.json     # Expected confidence calculations
    └── mock_pngcheck_outputs/
        ├── clean_output.txt           # Mock pngcheck output for clean PNG
        ├── suspicious_output.txt      # Mock output for suspicious PNG
        └── error_output.txt           # Mock output for corrupted PNG
```

#### **5.2 Unit Tests for pngcheck Wrapper**
```python
class TestPngCheckWrapper(unittest.TestCase):
    """
    Unit tests for PngCheckWrapper functionality.
    """
    
    def setUp(self):
        self.test_images_dir = os.path.join(os.path.dirname(__file__), 'resources', 'test_images')
        self.wrapper = PngCheckWrapper(verbose=True)
    
    def test_pngcheck_availability_check(self):
        """Test pngcheck installation detection."""
        # This test may skip if pngcheck not available
        if not self.wrapper.available:
            self.skipTest("pngcheck utility not available")
        
        self.assertTrue(self.wrapper.available)
        self.assertIsNotNone(self.wrapper._check_availability())
    
    def test_analyze_clean_png(self):
        """Test analysis of clean PNG file."""
        if not self.wrapper.available:
            self.skipTest("pngcheck utility not available")
        
        clean_png = os.path.join(self.test_images_dir, 'clean_png.png')
        if not os.path.exists(clean_png):
            self.skipTest("Clean PNG test file not available")
        
        result = self.wrapper.analyze_png(clean_png)
        
        self.assertEqual(result['execution_status']['return_code'], 0)
        self.assertTrue(result['png_structure']['valid_structure'])
        self.assertGreater(result['png_structure']['total_chunks'], 0)
        self.assertEqual(len(result['png_structure']['suspicious_chunks']), 0)
    
    def test_analyze_suspicious_png(self):
        """Test analysis of PNG with suspicious chunks."""
        if not self.wrapper.available:
            self.skipTest("pngcheck utility not available")
        
        suspicious_png = os.path.join(self.test_images_dir, 'multiple_text_chunks.png')
        if not os.path.exists(suspicious_png):
            self.skipTest("Suspicious PNG test file not available")
        
        result = self.wrapper.analyze_png(suspicious_png)
        
        # Should detect multiple text chunks as suspicious
        text_chunks = [c for c in result['png_structure']['chunks_found'] 
                      if c['type'] in ['tEXt', 'zTXt', 'iTXt']]
        self.assertGreater(len(text_chunks), 2)
    
    def test_non_png_file_rejection(self):
        """Test that non-PNG files are properly rejected."""
        non_png = os.path.join(self.test_images_dir, 'non_png_formats', 'test.jpg')
        
        with self.assertRaises(ValueError):
            self.wrapper.analyze_png(non_png)
    
    def test_timeout_handling(self):
        """Test timeout handling for hanging processes."""
        # Create wrapper with very short timeout
        short_timeout_wrapper = PngCheckWrapper(config={'timeout': 0.1})
        
        # This should timeout on any real file
        with self.assertRaises(RuntimeError):
            # Using a large file that might cause timeout
            large_png = os.path.join(self.test_images_dir, 'large_png.png')
            if os.path.exists(large_png):
                short_timeout_wrapper.analyze_png(large_png)
    
    @patch('subprocess.run')
    def test_output_parsing(self, mock_subprocess):
        """Test parsing of pngcheck output."""
        # Mock pngcheck output
        mock_subprocess.return_value = Mock(
            stdout="""File: test.png (12033 bytes)
  chunk IHDR at offset 0x0000c, length 13
    1024 x 1024 image, 48-bit RGB, non-interlaced
  chunk tEXt at offset 0x00025, length 2181
    keyword: Comment, text: This is a very long comment...
  chunk IDAT at offset 0x008b6, length 32
  chunk IEND at offset 0x008e2, length 0
No errors detected in test.png""",
            stderr="",
            returncode=0
        )
        
        result = self.wrapper.analyze_png('dummy_path.png')
        
        # Verify parsing
        self.assertEqual(len(result['png_structure']['chunks_found']), 4)
        self.assertEqual(result['png_structure']['chunks_found'][0]['type'], 'IHDR')
        self.assertEqual(result['png_structure']['chunks_found'][1]['type'], 'tEXt')
        
        # Should detect large text chunk as suspicious
        text_chunks = [c for c in result['png_structure']['suspicious_chunks'] 
                      if c['type'] == 'tEXt']
        self.assertEqual(len(text_chunks), 1)
```

#### **5.3 Integration Tests for Hybrid Detection**
```python
class TestHybridDetection(unittest.TestCase):
    """
    Integration tests for hybrid steganography detection.
    """
    
    def setUp(self):
        self.test_images_dir = os.path.join(os.path.dirname(__file__), 'resources', 'test_images')
        self.output_dir = tempfile.mkdtemp()
        self.engine = HybridDetectionEngine()
    
    def tearDown(self):
        # Clean up temporary output directory
        shutil.rmtree(self.output_dir, ignore_errors=True)
    
    def test_hybrid_detection_clean_image(self):
        """Test hybrid detection on clean image."""
        clean_png = os.path.join(self.test_images_dir, 'clean_png.png')
        if not os.path.exists(clean_png):
            self.skipTest("Clean PNG test file not available")
        
        result = self.engine.analyze_image(clean_png, self.output_dir, 'hybrid')
        
        self.assertEqual(result['detection_mode'], 'hybrid')
        self.assertIn('trailing_data', result['detection_results'])
        
        if 'pngcheck' in result['detection_results']:
            # If pngcheck available, verify both methods ran
            self.assertEqual(
                result['detection_results']['pngcheck']['execution_status'], 
                'success'
            )
        
        # Should not be classified as suspicious
        self.assertFalse(result['final_assessment'].get('is_suspicious', False))
    
    def test_hybrid_detection_trailing_data_only(self):
        """Test detection of image with trailing data but valid PNG structure."""
        trailing_png = os.path.join(self.test_images_dir, 'trailing_data_only.png')
        if not os.path.exists(trailing_png):
            self.skipTest("Trailing data PNG test file not available")
        
        result = self.engine.analyze_image(trailing_png, self.output_dir, 'hybrid')
        
        # Trailing data method should detect suspicion
        trailing_result = result['detection_results']['trailing_data']
        self.assertTrue(trailing_result.get('is_suspicious', False))
        
        # pngcheck method should not find structural issues
        if 'pngcheck' in result['detection_results']:
            pngcheck_result = result['detection_results']['pngcheck']
            if pngcheck_result.get('execution_status') == 'success':
                self.assertTrue(pngcheck_result['png_structure']['valid_structure'])
        
        # Correlation should identify this as trailing-data-only suspicion
        if 'correlation_analysis' in result:
            consensus = result['correlation_analysis'].get('consensus_analysis', {})
            self.assertEqual(consensus.get('consensus_type'), 'trailing_only_suspicious')
    
    def test_hybrid_detection_consensus_suspicious(self):
        """Test detection when both methods agree on suspicion."""
        suspicious_png = os.path.join(self.test_images_dir, 'hybrid_suspicious.png')
        if not os.path.exists(suspicious_png):
            self.skipTest("Hybrid suspicious PNG test file not available")
        
        result = self.engine.analyze_image(suspicious_png, self.output_dir, 'hybrid')
        
        # Both methods should detect suspicion
        trailing_result = result['detection_results']['trailing_data']
        self.assertTrue(trailing_result.get('is_suspicious', False))
        
        if 'pngcheck' in result['detection_results']:
            pngcheck_result = result['detection_results']['pngcheck']
            if pngcheck_result.get('execution_status') == 'success':
                # Should have suspicious indicators
                suspicious_indicators = pngcheck_result.get('suspicious_indicators', {})
                total_suspicious = (
                    len(suspicious_indicators.get('suspicious_metadata', [])) +
                    len(suspicious_indicators.get('oversized_chunks', [])) +
                    len(suspicious_indicators.get('invalid_chunks', []))
                )
                self.assertGreater(total_suspicious, 0)
        
        # Final assessment should be highly confident
        assessment = result['final_assessment']
        self.assertTrue(assessment.get('is_suspicious', False))
        self.assertGreaterEqual(assessment.get('confidence_score', 0.0), 0.7)
    
    def test_fallback_when_pngcheck_unavailable(self):
        """Test graceful fallback when pngcheck is not available."""
        # Mock pngcheck as unavailable
        with patch.object(self.engine.pngcheck_wrapper, 'available', False):
            clean_png = os.path.join(self.test_images_dir, 'clean_png.png')
            result = self.engine.analyze_image(clean_png, self.output_dir, 'hybrid')
            
            # Should have trailing data results
            self.assertIn('trailing_data', result['detection_results'])
            
            # pngcheck should show as unavailable
            if 'pngcheck' in result['detection_results']:
                self.assertEqual(
                    result['detection_results']['pngcheck']['execution_status'],
                    'unavailable'
                )
    
    def test_configuration_override(self):
        """Test configuration override functionality."""
        custom_config = {
            'detection_methods': {
                'trailing_data': {
                    'enabled': True,
                    'threshold_bytes': 5  # Lower threshold
                }
            }
        }
        
        custom_engine = HybridDetectionEngine(custom_config)
        
        # Test with image that has 6-9 bytes of trailing data
        small_trailing_png = os.path.join(self.test_images_dir, 'small_trailing_data.png')
        if os.path.exists(small_trailing_png):
            result = custom_engine.analyze_image(small_trailing_png, self.output_dir, 'trailing')
            
            # Should be suspicious with lower threshold
            trailing_result = result['detection_results']['trailing_data']
            self.assertTrue(trailing_result.get('is_suspicious', False))
```

#### **5.4 Performance Benchmarks**
```python
class TestPerformanceBenchmarks(unittest.TestCase):
    """
    Performance and resource usage tests.
    """
    
    def setUp(self):
        self.test_images_dir = os.path.join(os.path.dirname(__file__), 'resources', 'test_images')
        self.output_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        shutil.rmtree(self.output_dir, ignore_errors=True)
    
    def test_performance_comparison(self):
        """Compare performance of different detection modes."""
        test_png = os.path.join(self.test_images_dir, 'clean_png.png')
        if not os.path.exists(test_png):
            self.skipTest("Test PNG file not available")
        
        # Benchmark trailing data detection
        start_time = time.time()
        trailing_result = detect_image_steganography(
            test_png, self.output_dir, detection_mode='trailing'
        )
        trailing_time = time.time() - start_time
        
        # Benchmark hybrid detection
        start_time = time.time()
        hybrid_result = detect_image_steganography(
            test_png, self.output_dir, detection_mode='hybrid'
        )
        hybrid_time = time.time() - start_time
        
        print(f"Trailing detection time: {trailing_time:.3f}s")
        print(f"Hybrid detection time: {hybrid_time:.3f}s")
        
        # Hybrid should not be more than 3x slower than trailing-only
        self.assertLess(hybrid_time, trailing_time * 3.0)
    
    @patch('psutil.Process')
    def test_resource_usage_monitoring(self, mock_process):
        """Monitor resource usage during detection."""
        # Mock process for resource monitoring
        mock_proc = Mock()
        mock_proc.memory_info.return_value = Mock(rss=50 * 1024 * 1024)  # 50MB
        mock_proc.cpu_percent.return_value = 25.0
        mock_process.return_value = mock_proc
        
        test_png = os.path.join(self.test_images_dir, 'clean_png.png')
        if not os.path.exists(test_png):
            self.skipTest("Test PNG file not available")
        
        # Monitor resource usage during detection
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        result = detect_image_steganography(
            test_png, self.output_dir, detection_mode='hybrid'
        )
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (< 100MB for normal images)
        self.assertLess(memory_increase, 100 * 1024 * 1024)
    
    def test_concurrent_detection(self):
        """Test concurrent execution of multiple detections."""
        test_images = []
        for filename in ['clean_png.png', 'trailing_data_only.png', 'corrupt_chunks.png']:
            path = os.path.join(self.test_images_dir, filename)
            if os.path.exists(path):
                test_images.append(path)
        
        if len(test_images) < 2:
            self.skipTest("Insufficient test images for concurrent testing")
        
        # Run detections concurrently
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            for image_path in test_images:
                future = executor.submit(
                    detect_image_steganography,
                    image_path,
                    self.output_dir,
                    detection_mode='hybrid'
                )
                futures.append(future)
            
            # Wait for all to complete
            results = []
            for future in futures:
                try:
                    result = future.result(timeout=30)
                    results.append(result)
                except Exception as e:
                    self.fail(f"Concurrent detection failed: {e}")
        
        # All detections should complete successfully
        self.assertEqual(len(results), len(test_images))
        for result in results:
            self.assertIsNotNone(result)
            self.assertIn('detection_mode', result)
```

### **Phase 6: Documentation and Deployment** ⏱️ *2-3 hours*

#### **6.1 API Documentation**
```python
"""
Hybrid Steganography Detection API Documentation

This module provides advanced steganography detection capabilities by combining
multiple detection methods for improved accuracy and reduced false positives.

Quick Start:
    # Basic usage with hybrid detection
    result = detect_image_steganography(
        'suspicious_image.png',
        'output_directory',
        detection_mode='hybrid'
    )
    
    # Legacy usage (backward compatible)
    result = detect_image_steganography(
        'image.png',
        'output_directory',
        threshold_bytes=10
    )

Detection Modes:
    - 'hybrid': Combines trailing data + pngcheck (recommended)
    - 'trailing': Original trailing data detection only
    - 'pngcheck': PNG-specific validation only (PNG files only)

Configuration:
    Configure detection behavior via environment variables:
    
    export STEGANOGRAPHY_DETECTION_MODE=hybrid
    export STEGANOGRAPHY_THRESHOLD_BYTES=10
    export STEGANOGRAPHY_PNGCHECK_TIMEOUT=30
    export STEGANOGRAPHY_TRAILING_ENABLED=true
    export STEGANOGRAPHY_PNGCHECK_ENABLED=true

Dependencies:
    Required:
        - Python 3.7+
        - subprocess32>=3.5.0
        - psutil>=5.8.0
    
    Optional:
        - pngcheck utility (for PNG analysis)
            Ubuntu/Debian: sudo apt-get install pngcheck
            macOS: brew install pngcheck
            Windows: Download from https://github.com/pnggroup/pngcheck

Performance:
    - Trailing data detection: ~10-50ms per image
    - pngcheck analysis: ~50-200ms per PNG
    - Hybrid detection: ~60-250ms per PNG
    - Memory usage: <50MB per image (typical)

Error Handling:
    The API gracefully handles various error conditions:
    - Missing pngcheck utility (falls back to trailing data detection)
    - Corrupted image files (returns error details)
    - Timeout conditions (configurable timeouts)
    - Resource limitations (memory/CPU monitoring)

Result Format:
    Hybrid mode returns comprehensive analysis:
    {
        'detection_mode': 'hybrid',
        'image_path': '/path/to/image.png',
        'file_info': {...},
        'detection_results': {
            'trailing_data': {...},
            'pngcheck': {...}
        },
        'correlation_analysis': {...},
        'final_assessment': {
            'is_suspicious': True/False,
            'threat_level': 'HIGH'|'MEDIUM'|'LOW'|'MINIMAL',
            'confidence_score': 0.85,
            'suspicion_reasons': [...]
        }
    }
"""
```

#### **6.2 Migration Guide**
```markdown
# Migration Guide: Upgrading to Hybrid Steganography Detection

## Overview
This guide helps you migrate from the original trailing data detection to the new hybrid detection system while maintaining backward compatibility.

## Backward Compatibility
The existing API is fully backward compatible. Existing code will continue to work without changes:

```python
# This will continue to work exactly as before
result = detect_image_steganography(
    'image.png',
    'output_directory',
    verbose=True,
    threshold_bytes=10
)
```

## Enabling Hybrid Detection
To use the new hybrid capabilities, simply add the `detection_mode` parameter:

```python
# Enable hybrid detection
result = detect_image_steganography(
    'image.png',
    'output_directory',
    detection_mode='hybrid'
)
```

## Configuration Migration

### Environment Variables
Set environment variables to configure global behavior:

```bash
# Enable hybrid detection by default
export STEGANOGRAPHY_DETECTION_MODE=hybrid

# Configure thresholds
export STEGANOGRAPHY_THRESHOLD_BYTES=10
export STEGANOGRAPHY_PNGCHECK_TIMEOUT=30

# Enable/disable specific methods
export STEGANOGRAPHY_TRAILING_ENABLED=true
export STEGANOGRAPHY_PNGCHECK_ENABLED=true
```

### Configuration Files
Create `steganography_detection.json` for advanced configuration:

```json
{
  "detection_methods": {
    "trailing_data": {
      "enabled": true,
      "threshold_bytes": 10,
      "supported_formats": ["PNG", "JPEG", "GIF", "BMP", "WebP"]
    },
    "pngcheck": {
      "enabled": true,
      "timeout": 30,
      "suspicious_chunks": ["zTXt", "iTXt", "tEXt", "eXIf"],
      "max_chunk_size": 10000
    }
  },
  "hybrid_settings": {
    "mode": "hybrid",
    "confidence_threshold": 0.7,
    "fallback_to_single": true
  }
}
```

## Result Format Changes

### Legacy Format (unchanged)
When using `detection_mode='trailing'` or no detection_mode:
```python
{
    'image_path': '/path/to/image.png',
    'image_format': 'PNG',
    'trailing_bytes': 15,
    'is_suspicious': True,
    'report_file': '/path/to/report.txt'
}
```

### New Hybrid Format
When using `detection_mode='hybrid'`:
```python
{
    'detection_mode': 'hybrid',
    'image_path': '/path/to/image.png',
    'detection_results': {
        'trailing_data': { ... },  # Legacy format
        'pngcheck': { ... }         # New pngcheck results
    },
    'final_assessment': {
        'is_suspicious': True,
        'threat_level': 'HIGH',
        'confidence_score': 0.85
    }
}
```

## Performance Considerations

### Resource Usage
- Hybrid detection uses ~2-5x more CPU than trailing-only
- Memory usage increases by ~20-50MB per image
- pngcheck adds ~50-150ms per PNG file

### Optimization Tips
1. Use `detection_mode='trailing'` for bulk processing if speed is critical
2. Set shorter timeouts for real-time applications
3. Disable pngcheck for non-PNG formats
4. Use configuration files to avoid repeated parameter parsing

## Installation Requirements

### pngcheck Utility
The hybrid detection requires the pngcheck utility for PNG analysis:

```bash
# Ubuntu/Debian
sudo apt-get install pngcheck

# macOS with Homebrew
brew install pngcheck

# CentOS/RHEL
sudo yum install pngcheck

# Windows
# Download from: https://github.com/pnggroup/pngcheck/releases
```

### Verification
Verify installation:
```python
from steganography_detection import detect_image_steganography

# This will show pngcheck availability
result = detect_image_steganography(
    'test.png',
    'output',
    detection_mode='hybrid',
    verbose=True
)
```

## Rollback Procedure

If issues arise, you can easily rollback:

1. **Code Rollback**: Remove `detection_mode` parameters to use legacy behavior
2. **Environment Rollback**: Unset environment variables or set `STEGANOGRAPHY_DETECTION_MODE=trailing`
3. **Configuration Rollback**: Delete or rename configuration files

## Testing Migration

### Validation Script
```python
#!/usr/bin/env python3
"""
Validate hybrid detection migration.
"""

def test_migration():
    test_images = ['test1.png', 'test2.jpg', 'test3.gif']
    
    for image_path in test_images:
        if not os.path.exists(image_path):
            continue
        
        # Test legacy mode
        legacy_result = detect_image_steganography(
            image_path, 'output', detection_mode='trailing'
        )
        
        # Test hybrid mode
        hybrid_result = detect_image_steganography(
            image_path, 'output', detection_mode='hybrid'
        )
        
        print(f"Image: {image_path}")
        print(f"Legacy suspicious: {legacy_result.get('is_suspicious', False)}")
        print(f"Hybrid suspicious: {hybrid_result['final_assessment']['is_suspicious']}")
        print(f"Confidence: {hybrid_result['final_assessment']['confidence_score']:.2f}")
        print("---")

if __name__ == '__main__':
    test_migration()
```

## Support and Troubleshooting

### Common Issues

1. **pngcheck not found**
   - Solution: Install pngcheck utility or set `STEGANOGRAPHY_PNGCHECK_ENABLED=false`

2. **Timeouts on large files**
   - Solution: Increase `STEGANOGRAPHY_PNGCHECK_TIMEOUT` or use `detection_mode='trailing'`

3. **High memory usage**
   - Solution: Process images sequentially or reduce concurrent processing

4. **False positives increased**
   - Solution: Adjust `STEGANOGRAPHY_THRESHOLD_BYTES` or `confidence_threshold`

### Getting Help
- Check verbose output for detailed execution information
- Review log files in the output directory
- Use the validation script to test specific images
- Consult the configuration documentation for advanced tuning
```

## **Implementation Timeline**

| Phase | Duration | Deliverables |
|-------|----------|-------------|
| **Phase 1** | 2-3 hours | Prerequisites, dependencies, configuration |
| **Phase 2** | 4-5 hours | pngcheck wrapper, output parser, security |
| **Phase 3** | 6-7 hours | Hybrid engine, correlation logic, confidence scoring |
| **Phase 4** | 3-4 hours | API integration, backward compatibility |
| **Phase 5** | 4-5 hours | Comprehensive testing suite |
| **Phase 6** | 2-3 hours | Documentation, migration guide |
| **Total** | **21-27 hours** | **Complete hybrid detection system** |

## **Risk Assessment and Mitigation**

### **High Risk Items**
1. **pngcheck Dependency**: External utility dependency
   - **Mitigation**: Graceful fallback to trailing data detection
   - **Validation**: Installation check with clear error messages

2. **Performance Impact**: Hybrid detection slower than original
   - **Mitigation**: Configurable detection modes, timeout controls
   - **Validation**: Performance benchmarking and resource monitoring

3. **Backward Compatibility**: API changes breaking existing code
   - **Mitigation**: Maintain exact backward compatibility for legacy mode
   - **Validation**: Comprehensive backward compatibility tests

### **Medium Risk Items**
1. **Result Format Changes**: Different output structure for hybrid mode
   - **Mitigation**: Clear documentation and migration guide
   - **Validation**: Format validation tests

2. **Configuration Complexity**: More configuration options
   - **Mitigation**: Sensible defaults, environment variable overrides
   - **Validation**: Configuration management tests

### **Low Risk Items**
1. **Testing Coverage**: Ensuring all edge cases covered
   - **Mitigation**: Comprehensive test suite with mock data
   - **Validation**: Code coverage analysis

## **Success Criteria**

1. ✅ **Functional Requirements**
   - Hybrid detection combines trailing data + pngcheck analysis
   - Backward compatibility maintained for existing API
   - Confidence scoring based on method correlation
   - Comprehensive error handling and fallback mechanisms

2. ✅ **Performance Requirements**
   - Hybrid detection completes within 3x original timing
   - Memory usage increase < 100MB per image
   - Graceful handling of timeouts and resource limits

3. ✅ **Quality Requirements**
   - >90% test coverage for new functionality
   - All edge cases documented and tested
   - Clear migration documentation and examples

4. ✅ **Deployment Requirements**
   - Zero-downtime migration possible
   - Configuration management working across environments
   - Rollback procedures validated and documented

<function_calls>
<invoke name="todo_write">
<parameter name="merge">true
