#!/usr/bin/env python3
"""
Test Runner for ThreatSentinel

Simple script to run all tests for the ThreatSentinel project.
"""

import subprocess
import sys
import os
from pathlib import Path


def run_command(command, description):
    """Run a command and print the result"""
    print(f"\n{'='*60}")
    print(f"🔄 {description}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent
        )
        
        if result.returncode == 0:
            print(f"✅ {description} - PASSED")
            if result.stdout.strip():
                print(f"Output:\n{result.stdout}")
        else:
            print(f"❌ {description} - FAILED")
            if result.stderr.strip():
                print(f"Error:\n{result.stderr}")
            if result.stdout.strip():
                print(f"Output:\n{result.stdout}")
        
        return result.returncode == 0
    
    except Exception as e:
        print(f"❌ {description} - ERROR: {str(e)}")
        return False


def main():
    """Main test runner"""
    print("🚀 ThreatSentinel Test Runner")
    print("Running comprehensive tests for all components...")
    
    # Check if we're in the right directory
    if not os.path.exists("tests") or not os.path.exists("agent"):
        print("❌ Error: Please run this script from the ThreatSentinel root directory")
        sys.exit(1)
    
    # Install test dependencies if needed
    print("\n📦 Installing test dependencies...")
    run_command("pip install pytest pytest-asyncio", "Installing pytest dependencies")
    
    tests_passed = 0
    total_tests = 0
    
    # Run unit tests with pytest
    test_commands = [
        ("python -m pytest tests/test_tools.py -v", "Unit Tests - Tools Module"),
        ("python -m pytest tests/test_memory.py -v", "Unit Tests - Memory Module"),
        ("python -m pytest tests/test_task_queue.py -v", "Unit Tests - Task Queue Module"),
        ("python -m pytest tests/test_action_logger.py -v", "Unit Tests - Action Logger Module"),
        ("python -m pytest tests/test_integrations.py -v", "Unit Tests - Integrations Module"),
        ("python -m pytest tests/test_planner.py -v", "Unit Tests - SOC Agent Planner Module"),
        ("python -m pytest tests/test_reporter.py -v", "Unit Tests - Report Generator Module"),
        ("python -m pytest tests/ -v --tb=short", "All Unit Tests"),
    ]
    
    for command, description in test_commands:
        total_tests += 1
        if run_command(command, description):
            tests_passed += 1
    
    # Run CLI tool tester
    cli_tests = [
        ("python tests/cli_tool_tester.py --component tools", "CLI Tests - Tools"),
        ("python tests/cli_tool_tester.py --component memory", "CLI Tests - Memory"),
        ("python tests/cli_tool_tester.py --component queue", "CLI Tests - Task Queue"),
        ("python tests/cli_tool_tester.py --component integrations", "CLI Tests - Integrations"),
        ("python tests/cli_tool_tester.py --component workflow", "CLI Tests - Workflow"),
        ("python -m pytest tests/test_tools.py::TestCLIMockInteractions -v -s", "CLI Mock Tests - Tools"),
        ("python -m pytest tests/test_memory.py::TestMemoryCLIMockInteractions -v -s", "CLI Mock Tests - Memory"),
        ("python -m pytest tests/test_task_queue.py::TestTaskQueueCLIMockInteractions -v -s", "CLI Mock Tests - Task Queue"),
        ("python -m pytest tests/test_action_logger.py::TestActionLoggerCLIMockInteractions -v -s", "CLI Mock Tests - Action Logger"),
        ("python -m pytest tests/test_integrations.py::TestIntegrationsCLIMockInteractions -v -s", "CLI Mock Tests - Integrations"),
        ("python -m pytest tests/test_planner.py::TestPlannerCLIMockInteractions -v -s", "CLI Mock Tests - Planner"),
        ("python -m pytest tests/test_reporter.py::TestReporterCLIMockInteractions -v -s", "CLI Mock Tests - Reporter"),
    ]
    
    for command, description in cli_tests:
        total_tests += 1
        if run_command(command, description):
            tests_passed += 1
    
    # Summary
    print(f"\n{'='*60}")
    print("📊 TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Tests Passed: {tests_passed}/{total_tests}")
    print(f"Success Rate: {(tests_passed/total_tests)*100:.1f}%")
    
    if tests_passed == total_tests:
        print("✅ All tests passed successfully!")
        print("\n🎉 ThreatSentinel is ready for deployment!")
    else:
        print(f"⚠️  {total_tests - tests_passed} tests failed")
        print("❗ Please review failed tests before deployment")
    
    # Additional information
    print("\n📋 Test Coverage Summary:")
    print("• Tools Module: VirusTotal, AbuseIPDB, URLVoid, Shodan, ToolRegistry")
    print("• Memory System: Investigation storage, pattern analysis, cross-session retention")
    print("• Task Queue: Priority-based processing, persistence, retry logic")
    print("• Action Logger: Comprehensive audit trails, performance metrics")
    print("• Integrations: Firewalls, SIEMs, communication, incident response")
    print("• SOC Planner: Main orchestration, human review, emergency mode")
    print("• Reporter: Markdown/JSON reports, templating, file operations")
    print("• CLI Interactions: Mock demonstrations for all components")
    
    print("\n💡 Next Steps:")
    print("1. Configure API keys in .env file")
    print("2. Start ThreatSentinel API: python main_api.py")
    print("3. Test with real security events")
    print("4. Deploy to production environment")
    
    print("\n🧪 Run Individual Test Modules:")
    print("• python -m pytest tests/test_tools.py -v")
    print("• python -m pytest tests/test_memory.py -v")
    print("• python -m pytest tests/test_task_queue.py -v")
    print("• python -m pytest tests/test_action_logger.py -v")
    print("• python -m pytest tests/test_integrations.py -v")
    print("• python -m pytest tests/test_planner.py -v")
    print("• python -m pytest tests/test_reporter.py -v")
    
    print("\n🎯 Run Specific Test Categories:")
    print("• python -m pytest tests/ -m unit -v        # Unit tests only")
    print("• python -m pytest tests/ -m mock -v        # CLI mock tests only")
    print("• python -m pytest tests/ -m integration -v # Integration tests only")
    
    return tests_passed == total_tests


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 