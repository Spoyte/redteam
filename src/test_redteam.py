import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from redteam import (
    RedTeamFramework, PortScanTest, WeakCredentialsTest,
    SSLTLSConfigTest, ContainerEscapeTest, TestStatus, Severity
)


async def test_port_scan():
    """Test port scanning functionality."""
    print("Testing: Port Scan...")
    
    test = PortScanTest()
    result = await test.run("localhost", {"ports": [22, 80, 443], "timeout": 1})
    
    assert result.test_id == "port_scan"
    assert result.test_name == "Port Scanning"
    assert result.status in [TestStatus.PASSED, TestStatus.FAILED]
    assert result.duration_ms >= 0
    assert result.started_at is not None
    assert result.completed_at is not None
    
    print(f"  ✓ Status: {result.status.value}")
    print(f"  ✓ Duration: {result.duration_ms}ms")
    print(f"  ✓ Vulnerabilities: {len(result.vulnerabilities)}")
    return True


async def test_weak_creds():
    """Test weak credentials check."""
    print("Testing: Weak Credentials...")
    
    test = WeakCredentialsTest()
    result = await test.run("localhost", {"check_paths": []})
    
    assert result.test_id == "weak_creds"
    assert result.status in [TestStatus.PASSED, TestStatus.FAILED, TestStatus.ERROR]
    
    print(f"  ✓ Status: {result.status.value}")
    print(f"  ✓ Duration: {result.duration_ms}ms")
    return True


async def test_ssl_tls():
    """Test SSL/TLS configuration check."""
    print("Testing: SSL/TLS Config...")
    
    test = SSLTLSConfigTest()
    result = await test.run("localhost", {"port": 443})
    
    assert result.test_id == "ssl_tls"
    assert result.status in [TestStatus.PASSED, TestStatus.FAILED, TestStatus.ERROR]
    
    print(f"  ✓ Status: {result.status.value}")
    print(f"  ✓ Duration: {result.duration_ms}ms")
    return True


async def test_container_escape():
    """Test container escape detection."""
    print("Testing: Container Escape...")
    
    test = ContainerEscapeTest()
    result = await test.run("localhost", {})
    
    assert result.test_id == "container_escape"
    assert result.status in [TestStatus.PASSED, TestStatus.FAILED]
    
    print(f"  ✓ Status: {result.status.value}")
    print(f"  ✓ Duration: {result.duration_ms}ms")
    print(f"  ✓ Vulnerabilities: {len(result.vulnerabilities)}")
    return True


async def test_framework():
    """Test the main framework."""
    print("Testing: Framework...")
    
    framework = RedTeamFramework()
    
    # Check default tests are registered
    assert "port_scan" in framework.tests
    assert "weak_creds" in framework.tests
    assert "ssl_tls" in framework.tests
    assert "container_escape" in framework.tests
    
    print("  ✓ Default tests registered")
    
    # Test report generation
    report = framework.generate_report()
    assert "summary" in report
    assert "vulnerabilities" in report
    assert "test_results" in report
    
    print("  ✓ Report generation works")
    return True


async def test_report_save():
    """Test report saving."""
    print("Testing: Report Save...")
    
    framework = RedTeamFramework()
    
    # Run a quick test to generate some data
    await framework.run_test("port_scan", "localhost")
    
    # Save report
    report_path = framework.save_report()
    
    assert Path(report_path).exists()
    
    # Verify it's valid JSON
    with open(report_path) as f:
        data = json.load(f)
        assert "summary" in data
    
    print(f"  ✓ Report saved to: {report_path}")
    
    # Cleanup
    Path(report_path).unlink()
    return True


async def test_custom_test_registration():
    """Test registering custom tests."""
    print("Testing: Custom Test Registration...")
    
    framework = RedTeamFramework()
    
    # Create a custom test
    class CustomTest:
        def __init__(self):
            self.test_id = "custom_test"
            self.name = "Custom Test"
            self.description = "A custom test"
            self.rollback = None
        
        async def run(self, target, config):
            from redteam import TestResult, TestStatus
            return TestResult(
                test_id=self.test_id,
                test_name=self.name,
                status=TestStatus.PASSED,
                duration_ms=10
            )
        
        async def cleanup(self):
            pass
    
    custom = CustomTest()
    framework.register_test(custom)
    
    assert "custom_test" in framework.tests
    print("  ✓ Custom test registered")
    return True


async def run_all_tests():
    """Run all tests."""
    print("="*50)
    print("RED TEAM FRAMEWORK TEST SUITE")
    print("="*50)
    print()
    
    tests = [
        test_port_scan,
        test_weak_creds,
        test_ssl_tls,
        test_container_escape,
        test_framework,
        test_report_save,
        test_custom_test_registration,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            await test()
            passed += 1
            print()
        except Exception as e:
            print(f"  ✗ FAILED: {e}")
            failed += 1
            print()
    
    print("="*50)
    print(f"Results: {passed} passed, {failed} failed")
    print("="*50)
    
    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(run_all_tests())
    sys.exit(0 if success else 1)
