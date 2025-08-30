# Framework Validation Tests
import pytest
import json
from pathlib import Path

class TestFrameworkValidation:
    """Validate that the testing framework is properly set up."""
    
    @pytest.mark.unit
    def test_pytest_configuration_loaded(self):
        """Verify pytest configuration is loaded correctly."""
        # This test passes if pytest can run with our configuration
        assert True
    
    @pytest.mark.unit    
    def test_json_validation_capabilities(self):
        """Verify JSON validation capabilities work."""
        from jsonschema import validate
        
        # Test data structure
        test_data = {
            "assessment_metadata": {
                "timestamp": "2025-08-30T10:00:00Z",
                "system_info": "Test System",
                "assessment_version": "1.0"
            },
            "security_scorecard": {
                "overall_score": 85.5,
                "essential8_compliance": {}
            },
            "findings_summary": {
                "critical": 0,
                "high": 2,
                "medium": 5,
                "low": 8
            },
            "detailed_findings": [],
            "remediation_approach": {
                "recommended_strategy": "in_place_remediation",
                "rationale": "System is in good state"
            }
        }
        
        # Schema validation
        schema = {
            "type": "object",
            "required": ["assessment_metadata", "security_scorecard", "findings_summary", "detailed_findings", "remediation_approach"]
        }
        
        # Should not raise exception
        validate(test_data, schema)
    
    @pytest.mark.unit
    def test_powershell_executor_fixture_available(self, powershell_executor):
        """Verify PowerShell executor fixture works."""
        assert powershell_executor is not None
        assert hasattr(powershell_executor, 'run_command')
        assert hasattr(powershell_executor, 'run_script')
        assert hasattr(powershell_executor, 'run_script_json')
    
    @pytest.mark.unit 
    def test_temp_directory_fixture_available(self, temp_directory):
        """Verify temporary directory fixture works."""
        assert temp_directory.exists()
        assert temp_directory.is_dir()
    
    @pytest.mark.unit
    def test_project_structure_available(self, project_root, src_directory):
        """Verify project structure fixtures work."""
        assert project_root.exists()
        assert src_directory == project_root / "src"
    
    @pytest.mark.unit
    def test_mock_system_state_fixture(self, mock_system_state):
        """Verify mock system state fixture provides expected data."""
        assert "user_accounts" in mock_system_state
        assert "network_config" in mock_system_state  
        assert "security_status" in mock_system_state
        
        # Verify structure
        assert isinstance(mock_system_state["user_accounts"], list)
        assert "essential8_score" in mock_system_state["security_status"]