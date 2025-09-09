#!/usr/bin/env python3
"""
Test runner script for Automatool Web Interface

This script runs the complete test suite with different options.
"""
import sys
import subprocess
import os


def run_command(cmd, description):
    """Run a command and return success status."""
    print(f"\n🧪 {description}")
    print("=" * 60)
    
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=False)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed with exit code {e.returncode}")
        return False


def main():
    """Main test runner."""
    print("🚀 Automatool Web Interface Test Suite")
    print("=" * 60)
    
    # Change to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    test_commands = [
        # Run unit tests for utilities
        ("python -m pytest tests/test_file_handler.py -v", 
         "Unit Tests: File Handler"),
        
        ("python -m pytest tests/test_path_validator.py -v", 
         "Unit Tests: Path Validator"),
        
        # Run Flask app tests
        ("python -m pytest tests/test_flask_app.py -v", 
         "Unit Tests: Flask Application"),
        
        # Run integration tests
        ("python -m pytest tests/test_integration.py -v -m 'not slow'", 
         "Integration Tests (Fast)"),
        
        # Run all tests with coverage
        ("python -m pytest tests/ --cov=utils --cov=app --cov-report=term-missing", 
         "All Tests with Coverage Report"),
    ]
    
    passed = 0
    total = len(test_commands)
    
    for cmd, description in test_commands:
        if run_command(cmd, description):
            passed += 1
        else:
            print(f"\n💥 Test failure in: {description}")
            if input("\nContinue with remaining tests? (y/n): ").lower() != 'y':
                break
    
    # Final summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    print(f"Tests Passed: {passed}/{total}")
    
    if passed == total:
        print("🎉 All tests passed! The web interface is ready for deployment.")
        return 0
    else:
        print("💥 Some tests failed. Please review the failures above.")
        return 1


def run_specific_test():
    """Run specific test categories based on command line args."""
    if len(sys.argv) < 2:
        return main()
    
    test_type = sys.argv[1].lower()
    
    if test_type == "unit":
        print("🧪 Running Unit Tests Only")
        commands = [
            ("python -m pytest tests/test_file_handler.py tests/test_path_validator.py -v", 
             "Unit Tests"),
        ]
    elif test_type == "flask":
        print("🌐 Running Flask Tests Only")
        commands = [
            ("python -m pytest tests/test_flask_app.py -v", 
             "Flask Application Tests"),
        ]
    elif test_type == "integration":
        print("🔗 Running Integration Tests Only")
        commands = [
            ("python -m pytest tests/test_integration.py -v", 
             "Integration Tests"),
        ]
    elif test_type == "slow":
        print("🐌 Running All Tests Including Slow Tests")
        commands = [
            ("python -m pytest tests/ -v", 
             "All Tests (Including Slow)"),
        ]
    elif test_type == "coverage":
        print("📊 Running Tests with Coverage")
        commands = [
            ("python -m pytest tests/ --cov=utils --cov=app --cov-report=html --cov-report=term", 
             "Tests with Coverage Report"),
        ]
    else:
        print(f"❌ Unknown test type: {test_type}")
        print("Available options: unit, flask, integration, slow, coverage")
        return 1
    
    passed = 0
    for cmd, description in commands:
        if run_command(cmd, description):
            passed += 1
    
    return 0 if passed == len(commands) else 1


if __name__ == "__main__":
    exit_code = run_specific_test()
    sys.exit(exit_code)
