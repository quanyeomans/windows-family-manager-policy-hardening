# pytest Configuration and Global Fixtures
import pytest
import json
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any

# pytest-bdd configuration
pytest_plugins = ["pytest_bdd"]

# Test markers configuration
def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers", "contract: Component interface agreement tests - MUST PASS"
    )
    config.addinivalue_line(
        "markers", "integration: Multi-component interaction tests"
    )
    config.addinivalue_line(
        "markers", "bdd: Behavior-driven development scenario tests"
    )
    config.addinivalue_line(
        "markers", "e2e: End-to-end user workflow tests"
    )
    config.addinivalue_line(
        "markers", "critical: Tests that must never fail"
    )
    config.addinivalue_line(
        "markers", "slow: Tests that take longer than 30 seconds"
    )

@pytest.fixture(scope="session")
def project_root():
    """Return the project root directory."""
    return Path(__file__).parent.parent

@pytest.fixture(scope="session")
def src_directory(project_root):
    """Return the source code directory."""
    return project_root / "src"

@pytest.fixture(scope="session")
def powershell_scripts_path(src_directory):
    """Return the PowerShell scripts directory."""
    return src_directory

@pytest.fixture
def temp_directory():
    """Provide a temporary directory for test isolation."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)

@pytest.fixture
def mock_system_state():
    """Provide mock system state for testing."""
    return {
        "user_accounts": [
            {"name": "TestUser", "admin": False, "enabled": True},
            {"name": "Administrator", "admin": True, "enabled": True}
        ],
        "network_config": {
            "wifi_profiles": ["HomeNetwork", "TestNetwork"],
            "ethernet_enabled": True
        },
        "security_status": {
            "essential8_score": 43.8,
            "findings": {"critical": 8, "high": 12, "medium": 15, "low": 5}
        }
    }

@pytest.fixture
def powershell_executor():
    """Factory for executing PowerShell scripts in tests."""
    class PowerShellExecutor:
        def __init__(self):
            self.base_command = ["powershell", "-ExecutionPolicy", "Bypass"]
            
        def run_script(self, script_path: Path, *args) -> subprocess.CompletedProcess:
            """Execute a PowerShell script with arguments."""
            cmd = self.base_command + ["-File", str(script_path)] + list(args)
            return subprocess.run(cmd, capture_output=True, text=True)
            
        def run_command(self, command: str) -> subprocess.CompletedProcess:
            """Execute a PowerShell command directly."""
            cmd = self.base_command + ["-Command", command]
            return subprocess.run(cmd, capture_output=True, text=True)
            
        def run_script_json(self, script_path: Path, *args) -> Dict[Any, Any]:
            """Execute PowerShell script and parse JSON output."""
            result = self.run_script(script_path, *args)
            if result.returncode != 0:
                raise RuntimeError(f"PowerShell script failed: {result.stderr}")
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON output from PowerShell: {e}")
    
    return PowerShellExecutor()

@pytest.fixture
def assessment_result_schema():
    """JSON schema for validating system assessment output."""
    return {
        "type": "object",
        "required": [
            "assessment_metadata",
            "security_scorecard", 
            "findings_summary",
            "detailed_findings",
            "remediation_approach"
        ],
        "properties": {
            "assessment_metadata": {
                "type": "object",
                "required": ["timestamp", "system_info", "assessment_version"]
            },
            "security_scorecard": {
                "type": "object", 
                "required": ["overall_score", "essential8_compliance"]
            },
            "findings_summary": {
                "type": "object",
                "required": ["critical", "high", "medium", "low"]
            },
            "remediation_approach": {
                "type": "object",
                "required": ["recommended_strategy", "rationale"]
            }
        }
    }

# Skip integration tests if not in integration environment
def pytest_collection_modifyitems(config, items):
    """Modify test collection to handle integration test skipping."""
    if not config.getoption("--integration"):
        skip_integration = pytest.mark.skip(reason="need --integration option to run")
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)

def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--integration",
        action="store_true", 
        default=False,
        help="run integration tests"
    )
    parser.addoption(
        "--slow",
        action="store_true",
        default=False, 
        help="run slow tests"
    )