# Automatool Test Suite

This directory contains comprehensive tests for the Automatool malware analysis suite.

## Test Categories

### 🟢 CI Tests (Always Run)
These tests run in the CI environment and don't require external tools:
- `test_automatool.py` - Basic automatool functionality
- `test_generate_research_plan.py` - Research plan generation
- `test_merge_app_intelligence.py` - Intelligence merging
- `test_run_reviews_with_parsing.py` - Reviews processing
- `test_sensor_scraper.py` - SensorTower scraping
- Basic utility and validation tests

### 🟡 Local Tests (Require Tools)
These tests require external tools and run only locally:
- `test_base64_scanner.py` - Requires base64 detector script
- `test_cleanup_script.py` - Requires ADB and device access
- `test_launch_gemini_prompt.py` - Time-dependent tests
- `test_parse_yara_results.py` - Requires YARA output files
- `test_ttf_steganography_detection.py` - Requires font analysis tools
- `test_steganography_detection*.py` - Requires steganography tools

### 🔴 Integration Tests (Local Only)
These tests require full environment setup:
- `test_automatool_integration.py` - Full workflow integration
- `test_cleanup_integration.py` - ADB and device integration
- `test_mobsf_integration.py` - Docker and MobSF setup
- `test_mobsf_standalone.py` - MobSF container tests
- `test_vscode_process_termination.py` - VS Code process tests

### 🟠 Enhanced/Experimental Tests
These tests are for enhanced features and may require specific configurations:
- `test_enhanced_base64_detector.py` - Enhanced base64 detection
- `test_enhanced_decompilation.py` - Advanced decompilation features

## Running Tests

### CI Environment
The CI automatically runs basic tests that don't require external tools:
```bash
pytest tests/ -v --tb=short \
  --ignore=tests/test_mobsf_integration.py \
  --ignore=tests/test_enhanced_base64_detector.py \
  # ... (see .github/workflows/test.yml for full list)
```

### Local Development - All Tests
```bash
# Run all tests (requires all tools installed)
pytest tests/

# Run only basic tests
pytest tests/ -k "not integration and not mobsf and not requires_tools"

# Run integration tests
pytest tests/ -m integration

# Run MobSF tests (requires Docker)
pytest tests/ -m mobsf

# Run local-only tests
pytest tests/ -m local_only
```

### Local Development - Specific Categories
```bash
# Basic functionality tests only
pytest tests/test_automatool.py tests/test_generate_research_plan.py

# Tool-dependent tests (requires ADB, etc.)
pytest tests/test_cleanup_script.py tests/test_base64_scanner.py

# Integration tests (requires full setup)
pytest tests/test_automatool_integration.py
```

## Test Requirements

### System Dependencies
- Python 3.8+
- Android SDK (ADB) - for device-related tests
- Docker - for MobSF tests
- Java Runtime Environment - for APK analysis tests

### Python Dependencies
See `requirements.txt` for the full list. Key testing dependencies:
- `pytest`
- `pytest-cov`
- `unittest.mock`

### External Tools (Local Only)
- **MobSF**: Docker container for mobile security analysis
- **YARA**: Malware detection rules engine
- **APKTool**: APK reverse engineering tool
- **Jadx**: Dex to Java decompiler

## Test Markers

Tests are marked with pytest markers for selective execution:

- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.slow` - Slow-running tests
- `@pytest.mark.mobsf` - Requires MobSF/Docker
- `@pytest.mark.requires_tools` - Requires external tools
- `@pytest.mark.local_only` - Local environment only

## Troubleshooting

### Common Issues

1. **ADB Not Found**
   ```
   ❌ ADB not available
   💡 Please install Android SDK platform-tools
   ```
   **Solution**: Install Android SDK or mark test as `requires_tools`

2. **Docker Not Available**
   ```
   docker: command not found
   ```
   **Solution**: Install Docker or skip MobSF tests with `-m "not mobsf"`

3. **Import Errors**
   ```
   ModuleNotFoundError: No module named 'run_apktool_decode'
   ```
   **Solution**: Ensure proper Python path or mark as `local_only`

4. **Time-Dependent Test Failures**
   ```
   AssertionError: assert 'analyze_security_20250910_054116' != 'analyze_security_20250910_054116'
   ```
   **Solution**: Mock datetime in tests or use relative time assertions

### Running Specific Test Categories

```bash
# Only tests that pass in CI
pytest tests/ -v --tb=short \
  --ignore=tests/test_mobsf_integration.py \
  --ignore=tests/test_enhanced_base64_detector.py \
  # ... (see CI config for full list)

# Only local tests
pytest tests/ -m "local_only or requires_tools"

# Everything except integration
pytest tests/ -m "not integration"
```

## Contributing

When adding new tests:

1. **Mark appropriately**: Use pytest markers for test categorization
2. **Mock external dependencies**: Use `unittest.mock` for CI compatibility
3. **Handle missing tools gracefully**: Provide fallbacks or skip tests
4. **Update CI exclusions**: Add to `.github/workflows/test.yml` if needed
5. **Document requirements**: Update this README with new dependencies

## Test Structure

```
tests/
├── README.md                           # This file
├── conftest.py                         # Pytest configuration
├── resources/                          # Test data and fixtures
│   ├── test.apk                       # Sample APK for testing
│   ├── yara.json                      # Sample YARA results
│   └── ...
├── test_*.py                          # Individual test files
└── temp_test/                         # Temporary test outputs
```
