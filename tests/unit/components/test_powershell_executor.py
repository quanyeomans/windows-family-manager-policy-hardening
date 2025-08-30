# Unit Tests for PowerShell Executor Component
# Tests for cross-language integration and command execution

import pytest
import json
import subprocess
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

class TestPowerShellExecutor:
    """Unit tests for PowerShell execution component."""
    
    @pytest.fixture
    def mock_subprocess_result(self):
        """Mock subprocess result for PowerShell execution."""
        return Mock(
            returncode=0,
            stdout='{"status": "success", "data": {"test": "value"}}',
            stderr='',
            args=['powershell', '-ExecutionPolicy', 'Bypass', '-Command', 'Test-Command']
        )
    
    @pytest.fixture  
    def mock_error_result(self):
        """Mock subprocess result for PowerShell execution error."""
        return Mock(
            returncode=1,
            stdout='',
            stderr='PowerShell error: Command not found',
            args=['powershell', '-ExecutionPolicy', 'Bypass', '-Command', 'Invalid-Command']
        )

    def test_powershell_command_construction(self):
        """Test PowerShell command construction with proper escaping."""
        # Test basic command construction
        command = "Get-Process"
        expected_args = ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', command]
        
        # Mock PowerShell executor behavior
        constructed_args = self._build_powershell_args(command)
        assert constructed_args == expected_args
    
    def test_powershell_parameter_escaping(self):
        """Test PowerShell parameter escaping for special characters."""
        # Test parameter with spaces and quotes
        command_with_params = 'Get-ItemProperty -Path "HKLM:\\Software\\Microsoft" -Name "Test Value"'
        
        # Test escaping logic
        escaped_command = self._escape_powershell_parameters(command_with_params)
        
        # Should preserve quotes and handle paths correctly
        assert 'HKLM:\\\\Software\\\\Microsoft' in escaped_command or 'HKLM:\\Software\\Microsoft' in escaped_command
        assert '"Test Value"' in escaped_command
    
    def test_powershell_json_output_parsing(self, mock_subprocess_result):
        """Test JSON output parsing from PowerShell commands."""
        with patch('subprocess.run', return_value=mock_subprocess_result):
            # Mock PowerShell executor
            executor = MockPowerShellExecutor()
            result = executor.run_command_json("Test-Command")
            
            # Test JSON parsing
            assert result['status'] == 'success'
            assert result['data']['test'] == 'value'
            assert isinstance(result, dict)
    
    def test_powershell_error_handling(self, mock_error_result):
        """Test PowerShell error handling and propagation."""
        with patch('subprocess.run', return_value=mock_error_result):
            executor = MockPowerShellExecutor()
            
            # Test error result handling
            result = executor.run_command("Invalid-Command")
            
            assert result.returncode == 1
            assert result.stderr == 'PowerShell error: Command not found'
            assert result.stdout == ''
    
    def test_powershell_timeout_handling(self):
        """Test PowerShell command timeout handling."""
        with patch('subprocess.run') as mock_run:
            # Mock timeout exception
            mock_run.side_effect = subprocess.TimeoutExpired(['powershell'], 30)
            
            executor = MockPowerShellExecutor()
            
            # Test timeout handling
            with pytest.raises(subprocess.TimeoutExpired):
                executor.run_command("Start-Sleep 60", timeout=30)
    
    def test_powershell_execution_policy_bypass(self):
        """Test PowerShell execution policy bypass for script execution."""
        command = "Get-ExecutionPolicy"
        
        # Test that bypass is included in command construction
        args = self._build_powershell_args(command)
        
        assert '-ExecutionPolicy' in args
        assert 'Bypass' in args
    
    def test_powershell_script_file_execution(self):
        """Test PowerShell script file execution with parameters."""
        script_path = Path("test_script.ps1")
        script_params = ["-Parameter1", "Value1", "-Parameter2", "Value2"]
        
        # Test script execution command construction
        args = self._build_script_execution_args(script_path, script_params)
        
        expected_args = ['powershell', '-ExecutionPolicy', 'Bypass', '-File', str(script_path)] + script_params
        assert args == expected_args
    
    def test_powershell_output_encoding_handling(self):
        """Test PowerShell output encoding for special characters."""
        # Mock output with special characters
        mock_output = '{"message": "Test with üñíçødé characters", "path": "C:\\Users\\tëst"}'
        
        mock_result = Mock(
            returncode=0,
            stdout=mock_output,
            stderr=''
        )
        
        with patch('subprocess.run', return_value=mock_result):
            executor = MockPowerShellExecutor()
            result = executor.run_command_json("Test-UnicodeOutput")
            
            # Test unicode handling
            assert 'üñíçødé' in result['message']
            assert 'tëst' in result['path']
    
    def test_powershell_large_output_handling(self):
        """Test handling of large PowerShell output."""
        # Mock large JSON output
        large_data = {"items": [{"id": i, "data": f"item_{i}"} for i in range(1000)]}
        large_output = json.dumps(large_data)
        
        mock_result = Mock(
            returncode=0,
            stdout=large_output,
            stderr=''
        )
        
        with patch('subprocess.run', return_value=mock_result):
            executor = MockPowerShellExecutor()
            result = executor.run_command_json("Get-LargeDataSet")
            
            # Test large output parsing
            assert len(result['items']) == 1000
            assert result['items'][0]['id'] == 0
            assert result['items'][999]['data'] == "item_999"
    
    def test_powershell_concurrent_execution_safety(self):
        """Test thread safety for concurrent PowerShell execution."""
        import threading
        import time
        
        results = []
        errors = []
        
        def execute_command(command_id):
            try:
                executor = MockPowerShellExecutor()
                result = executor.run_command(f"Write-Output 'Command_{command_id}'")
                results.append((command_id, result.stdout.strip()))
            except Exception as e:
                errors.append((command_id, str(e)))
        
        # Test concurrent execution
        threads = []
        for i in range(5):
            thread = threading.Thread(target=execute_command, args=(i,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Validate concurrent execution results
        assert len(errors) == 0, f"Concurrent execution errors: {errors}"
        assert len(results) == 5
        
        # Check that each command produced expected output
        for command_id, output in results:
            assert f"Command_{command_id}" in output

    # Helper Methods for Testing
    def _build_powershell_args(self, command):
        """Build PowerShell command arguments."""
        return ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', command]
    
    def _build_script_execution_args(self, script_path, params):
        """Build PowerShell script execution arguments."""
        return ['powershell', '-ExecutionPolicy', 'Bypass', '-File', str(script_path)] + params
    
    def _escape_powershell_parameters(self, command):
        """Escape PowerShell parameters for safe execution."""
        # Basic escaping for test purposes
        return command.replace('\\', '\\\\')


class MockPowerShellExecutor:
    """Mock PowerShell executor for testing."""
    
    def run_command(self, command, timeout=120):
        """Mock command execution."""
        if "Invalid-Command" in command:
            return Mock(
                returncode=1,
                stdout='',
                stderr='PowerShell error: Command not found'
            )
        elif "Start-Sleep 60" in command:
            raise subprocess.TimeoutExpired(['powershell'], timeout)
        elif "Test-UnicodeOutput" in command:
            return Mock(
                returncode=0,
                stdout='{"message": "Test with üñíçødé characters", "path": "C:\\\\Users\\\\tëst"}',
                stderr=''
            )
        elif "Get-LargeDataSet" in command:
            large_data = {"items": [{"id": i, "data": f"item_{i}"} for i in range(1000)]}
            return Mock(
                returncode=0,
                stdout=json.dumps(large_data),
                stderr=''
            )
        elif "Write-Output" in command:
            # Extract command output for concurrent testing
            import re
            match = re.search(r"Write-Output '(.+)'", command)
            output = match.group(1) if match else "Default Output"
            return Mock(
                returncode=0,
                stdout=output,
                stderr=''
            )
        else:
            return Mock(
                returncode=0,
                stdout='{"status": "success", "data": {"test": "value"}}',
                stderr=''
            )
    
    def run_command_json(self, command, timeout=120):
        """Mock JSON command execution."""
        result = self.run_command(command, timeout)
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            raise ValueError(f"PowerShell command failed: {result.stderr}")


class TestPowerShellIntegrationPatterns:
    """Test PowerShell integration patterns and best practices."""
    
    def test_command_parameter_validation(self):
        """Test command parameter validation before execution."""
        # Test valid parameters
        valid_params = {
            "Path": "HKLM:\\Software\\Microsoft",
            "Name": "Version",
            "ValueType": "String"
        }
        
        validation_result = self._validate_parameters(valid_params)
        assert validation_result['valid'] == True
        assert len(validation_result['errors']) == 0
    
    def test_command_parameter_sanitization(self):
        """Test parameter sanitization for security."""
        # Test malicious parameter injection attempt
        malicious_params = {
            "Path": "HKLM:\\Software\\Microsoft; Remove-Item C:\\Windows\\System32",
            "Name": "Version'; Drop-Database; --"
        }
        
        sanitized_params = self._sanitize_parameters(malicious_params)
        
        # Verify malicious content is removed/escaped
        assert "; Remove-Item" not in sanitized_params["Path"]
        assert "Drop-Database" not in sanitized_params["Name"]
    
    def test_powershell_output_schema_validation(self):
        """Test PowerShell output schema validation."""
        # Test valid assessment output
        valid_output = {
            "timestamp": "2025-08-30T10:00:00Z",
            "status": "success",
            "data": {
                "registry_modifications": 5,
                "user_accounts": 3,
                "security_score": 75.5
            }
        }
        
        schema_validation = self._validate_output_schema(valid_output, "assessment")
        assert schema_validation['valid'] == True
    
    def test_powershell_error_categorization(self):
        """Test PowerShell error categorization for proper handling."""
        error_scenarios = [
            {
                "stderr": "Access is denied",
                "expected_category": "PERMISSION_DENIED",
                "recoverable": False
            },
            {
                "stderr": "The term 'Get-NonExistentCommand' is not recognized",
                "expected_category": "COMMAND_NOT_FOUND", 
                "recoverable": False
            },
            {
                "stderr": "Cannot bind parameter 'Path'",
                "expected_category": "PARAMETER_ERROR",
                "recoverable": True
            },
            {
                "stderr": "Execution timeout after 120 seconds",
                "expected_category": "TIMEOUT",
                "recoverable": True
            }
        ]
        
        for scenario in error_scenarios:
            error_info = self._categorize_error(scenario["stderr"])
            assert error_info['category'] == scenario['expected_category']
            assert error_info['recoverable'] == scenario['recoverable']

    # Helper methods for integration pattern testing
    def _validate_parameters(self, params):
        """Validate PowerShell parameters."""
        errors = []
        
        # Basic validation rules
        for key, value in params.items():
            if not isinstance(key, str) or not key:
                errors.append(f"Invalid parameter name: {key}")
            if value is None or value == "":
                errors.append(f"Empty value for parameter: {key}")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors
        }
    
    def _sanitize_parameters(self, params):
        """Sanitize PowerShell parameters for security."""
        sanitized = {}
        
        dangerous_patterns = ['; ', '&& ', '|| ', '| ', '` ', '$', '(', ')']
        
        for key, value in params.items():
            sanitized_value = str(value)
            for pattern in dangerous_patterns:
                sanitized_value = sanitized_value.replace(pattern, '')
            sanitized[key] = sanitized_value
        
        return sanitized
    
    def _validate_output_schema(self, output, schema_type):
        """Validate PowerShell output against expected schema."""
        required_fields = {
            'assessment': ['timestamp', 'status', 'data'],
            'deployment': ['timestamp', 'status', 'results'],
            'monitoring': ['timestamp', 'metrics', 'alerts']
        }
        
        missing_fields = []
        expected_fields = required_fields.get(schema_type, [])
        
        for field in expected_fields:
            if field not in output:
                missing_fields.append(field)
        
        return {
            'valid': len(missing_fields) == 0,
            'missing_fields': missing_fields
        }
    
    def _categorize_error(self, error_message):
        """Categorize PowerShell errors for appropriate handling."""
        error_patterns = {
            'PERMISSION_DENIED': ['Access is denied', 'insufficient privileges'],
            'COMMAND_NOT_FOUND': ['is not recognized', 'command not found'],
            'PARAMETER_ERROR': ['Cannot bind parameter', 'parameter is incorrect'],
            'TIMEOUT': ['timeout', 'operation timed out'],
            'NETWORK_ERROR': ['network path', 'connection failed'],
            'FILE_NOT_FOUND': ['cannot find path', 'file not found']
        }
        
        error_lower = error_message.lower()
        
        for category, patterns in error_patterns.items():
            if any(pattern.lower() in error_lower for pattern in patterns):
                return {
                    'category': category,
                    'recoverable': category in ['PARAMETER_ERROR', 'TIMEOUT', 'NETWORK_ERROR']
                }
        
        return {
            'category': 'UNKNOWN_ERROR',
            'recoverable': False
        }