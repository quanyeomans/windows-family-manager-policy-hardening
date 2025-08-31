# PowerShell Integration Unit Tests for Admin Interface
# Tests for PowerShell-Python integration within the Streamlit admin interface

import pytest
import json
import asyncio
import subprocess
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from datetime import datetime
import threading
import time

class TestPowerShellIntegration:
    """Unit tests for PowerShell integration in the admin interface."""
    
    @pytest.fixture
    def mock_powershell_output(self):
        """Mock PowerShell assessment script output."""
        return {
            "B001": {
                "security_score": 85,
                "findings": [
                    {
                        "category": "B001_registry_modification",
                        "severity": "MEDIUM",
                        "finding": "Non-standard registry value detected",
                        "remediation": "Review and correct registry value"
                    }
                ],
                "assessment_summary": {
                    "total_keys_analyzed": 5,
                    "bypass_indicators_found": 0,
                    "critical_findings": 0,
                    "high_findings": 0,
                    "medium_findings": 1,
                    "low_findings": 0
                }
            }
        }

    @pytest.fixture
    def mock_subprocess(self):
        """Mock subprocess for PowerShell execution."""
        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = json.dumps({
                "security_score": 85,
                "findings": [],
                "assessment_summary": {}
            })
            mock_result.stderr = ""
            mock_run.return_value = mock_result
            yield mock_run

    def test_powershell_integration_initialization(self):
        """Test PowerShell integration component initialization."""
        from src.admin_interface.components.powershell_integration import PowerShellIntegration
        
        integration = PowerShellIntegration()
        
        assert integration is not None
        assert hasattr(integration, 'execute_assessment_script')
        assert hasattr(integration, 'parse_assessment_results')
        assert hasattr(integration, 'handle_execution_errors')

    def test_assessment_script_execution(self, mock_subprocess):
        """Test execution of PowerShell assessment scripts."""
        from src.admin_interface.components.powershell_integration import PowerShellIntegration
        
        integration = PowerShellIntegration()
        
        # Execute registry modification assessment
        result = integration.execute_assessment_script(
            script_name="Get-RegistryModifications.ps1",
            parameters={"-Verbose": True},
            timeout=30
        )
        
        assert result is not None
        assert 'security_score' in result
        assert 'findings' in result
        
        # Verify subprocess was called with correct parameters
        mock_subprocess.assert_called_once()
        call_args = mock_subprocess.call_args[0][0]  # Get the command arguments
        assert 'powershell.exe' in call_args or 'pwsh.exe' in call_args
        assert 'Get-RegistryModifications.ps1' in ' '.join(call_args)

    def test_parallel_script_execution(self, mock_subprocess):
        """Test parallel execution of multiple assessment scripts."""
        from src.admin_interface.components.powershell_integration import PowerShellIntegration
        
        integration = PowerShellIntegration()
        
        script_configs = [
            {"script": "Get-RegistryModifications.ps1", "params": {"-Verbose": True}},
            {"script": "Get-UserAccountInventory.ps1", "params": {"-Verbose": True}},
            {"script": "Get-GroupPolicyInventory.ps1", "params": {"-Verbose": True}}
        ]
        
        # Execute scripts in parallel
        results = integration.execute_scripts_parallel(script_configs, max_workers=3)
        
        assert len(results) == 3
        assert all('security_score' in result for result in results.values())
        
        # Verify all scripts were executed
        assert mock_subprocess.call_count == 3

    def test_assessment_orchestration(self, mock_subprocess):
        """Test orchestration of complete assessment workflow."""
        from src.admin_interface.components.powershell_integration import PowerShellIntegration
        
        integration = PowerShellIntegration()
        
        # Mock progress callback
        progress_updates = []
        def progress_callback(step, status, data=None):
            progress_updates.append({"step": step, "status": status, "data": data})
        
        # Execute full assessment
        assessment_result = integration.execute_full_assessment(
            progress_callback=progress_callback,
            verbose=True
        )
        
        assert assessment_result is not None
        assert 'assessment_metadata' in assessment_result
        assert 'security_scorecard' in assessment_result
        assert 'detailed_findings' in assessment_result
        
        # Verify progress updates were sent
        assert len(progress_updates) > 0
        assert any(update['step'] == 'B001_registry_modification' for update in progress_updates)

    def test_powershell_error_handling(self):
        """Test handling of PowerShell execution errors."""
        from src.admin_interface.components.powershell_integration import PowerShellIntegration
        
        integration = PowerShellIntegration()
        
        # Mock subprocess failure
        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 1
            mock_result.stdout = ""
            mock_result.stderr = "Access denied when accessing registry"
            mock_run.return_value = mock_result
            
            result = integration.execute_assessment_script(
                script_name="Get-RegistryModifications.ps1",
                parameters={},
                timeout=30
            )
            
            assert result is not None
            assert 'error' in result
            assert result['error']['error_code'] == 1
            assert 'Access denied' in result['error']['error_message']

    def test_execution_timeout_handling(self):
        """Test handling of PowerShell script execution timeouts."""
        from src.admin_interface.components.powershell_integration import PowerShellIntegration
        
        integration = PowerShellIntegration()
        
        # Mock subprocess timeout
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(
                cmd=['powershell.exe'], timeout=5
            )
            
            result = integration.execute_assessment_script(
                script_name="Get-RegistryModifications.ps1",
                parameters={},
                timeout=5
            )
            
            assert result is not None
            assert 'error' in result
            assert result['error']['error_type'] == 'TIMEOUT'

    def test_output_json_parsing(self, mock_powershell_output):
        """Test parsing of PowerShell JSON output."""
        from src.admin_interface.components.powershell_integration import PowerShellIntegration
        
        integration = PowerShellIntegration()
        
        # Test valid JSON parsing
        json_output = json.dumps(mock_powershell_output['B001'])
        parsed_result = integration.parse_powershell_output(json_output)
        
        assert parsed_result is not None
        assert parsed_result['security_score'] == 85
        assert len(parsed_result['findings']) == 1
        
        # Test invalid JSON handling
        invalid_json = "{ invalid json structure"
        parsed_result = integration.parse_powershell_output(invalid_json)
        
        assert parsed_result is not None
        assert 'error' in parsed_result
        assert parsed_result['error']['error_type'] == 'JSON_PARSE_ERROR'

    def test_script_parameter_validation(self):
        """Test validation of PowerShell script parameters."""
        from src.admin_interface.components.powershell_integration import PowerShellIntegration
        
        integration = PowerShellIntegration()
        
        # Test valid parameters
        valid_params = {"-Verbose": True, "-OutputFormat": "JSON"}
        validation_result = integration.validate_script_parameters(valid_params)
        assert validation_result['valid'] == True
        
        # Test invalid parameters (potential injection)
        invalid_params = {"-Command": "Remove-Item C:\\Windows"}
        validation_result = integration.validate_script_parameters(invalid_params)
        assert validation_result['valid'] == False
        assert 'security_violation' in validation_result

    def test_real_time_output_streaming(self):
        """Test real-time streaming of PowerShell script output."""
        from src.admin_interface.components.powershell_integration import PowerShellIntegration
        
        integration = PowerShellIntegration()
        
        output_chunks = []
        def output_callback(chunk):
            output_chunks.append(chunk)
        
        # Mock Popen for streaming
        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.stdout.readline.side_effect = [
                b'Step 1: Starting registry analysis...\n',
                b'Step 2: Analyzing UAC settings...\n',
                b'Step 3: Assessment complete.\n',
                b''  # End of output
            ]
            mock_process.poll.return_value = None  # Still running
            mock_process.returncode = 0
            mock_popen.return_value = mock_process
            
            # Execute with streaming
            result = integration.execute_with_streaming(
                script_name="Get-RegistryModifications.ps1",
                output_callback=output_callback
            )
            
            assert len(output_chunks) > 0
            assert any('registry analysis' in chunk for chunk in output_chunks)

    def test_concurrent_execution_safety(self, mock_subprocess):
        """Test thread safety during concurrent PowerShell executions."""
        from src.admin_interface.components.powershell_integration import PowerShellIntegration
        
        integration = PowerShellIntegration()
        
        results = {}
        errors = []
        
        def execute_script(script_id):
            try:
                result = integration.execute_assessment_script(
                    script_name=f"Test-Script{script_id}.ps1",
                    parameters={},
                    timeout=30
                )
                results[script_id] = result
            except Exception as e:
                errors.append(e)
        
        # Start multiple concurrent executions
        threads = []
        for i in range(5):
            thread = threading.Thread(target=execute_script, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        assert len(errors) == 0  # No thread safety errors
        assert len(results) == 5  # All executions completed

    def test_assessment_result_aggregation(self, mock_powershell_output):
        """Test aggregation of individual script results into complete assessment."""
        from src.admin_interface.components.powershell_integration import PowerShellIntegration
        
        integration = PowerShellIntegration()
        
        individual_results = {
            "B001": mock_powershell_output['B001'],
            "B002": {
                "security_score": 72,
                "findings": [
                    {
                        "category": "B002_user_account_security",
                        "severity": "HIGH",
                        "finding": "Guest account enabled"
                    }
                ]
            },
            "B003": {
                "security_score": 88,
                "findings": []
            }
        }
        
        aggregated_result = integration.aggregate_assessment_results(individual_results)
        
        assert 'security_scorecard' in aggregated_result
        assert 'overall_score' in aggregated_result['security_scorecard']
        assert 'detailed_findings' in aggregated_result
        
        # Verify overall score calculation
        expected_score = (85 + 72 + 88) / 3  # Average of component scores
        assert abs(aggregated_result['security_scorecard']['overall_score'] - expected_score) < 1

    def test_execution_policy_bypass(self):
        """Test PowerShell execution policy bypass for assessment scripts."""
        from src.admin_interface.components.powershell_integration import PowerShellIntegration
        
        integration = PowerShellIntegration()
        
        # Test that execution policy bypass is included in command
        command = integration.build_powershell_command(
            script_path="C:\\Scripts\\Get-RegistryModifications.ps1",
            parameters={"-Verbose": True}
        )
        
        assert '-ExecutionPolicy Bypass' in command or '-ExecutionPolicy RemoteSigned' in command
        assert '-File' in command
        assert 'Get-RegistryModifications.ps1' in command

    def test_output_size_validation(self):
        """Test validation of PowerShell output size limits."""
        from src.admin_interface.components.powershell_integration import PowerShellIntegration
        
        integration = PowerShellIntegration()
        
        # Test normal size output
        normal_output = json.dumps({"data": "normal content"})
        validation_result = integration.validate_output_size(normal_output, max_size_mb=1)
        assert validation_result['valid'] == True
        
        # Test oversized output
        large_output = json.dumps({"data": "x" * (2 * 1024 * 1024)})  # 2MB
        validation_result = integration.validate_output_size(large_output, max_size_mb=1)
        assert validation_result['valid'] == False
        assert validation_result['size_mb'] > 1.0

    def test_script_integrity_verification(self):
        """Test verification of PowerShell script integrity before execution."""
        from src.admin_interface.components.powershell_integration import PowerShellIntegration
        
        integration = PowerShellIntegration()
        
        # Mock script file existence and content
        with patch('os.path.exists') as mock_exists, \
             patch('builtins.open', create=True) as mock_open:
            
            mock_exists.return_value = True
            mock_open.return_value.__enter__.return_value.read.return_value = "# Valid PowerShell script content"
            
            integrity_result = integration.verify_script_integrity(
                "Get-RegistryModifications.ps1"
            )
            
            assert integrity_result['valid'] == True
            assert integrity_result['script_exists'] == True

    def test_assessment_cancellation(self):
        """Test cancellation of running PowerShell assessment."""
        from src.admin_interface.components.powershell_integration import PowerShellIntegration
        
        integration = PowerShellIntegration()
        
        # Start assessment in background
        assessment_future = integration.start_assessment_async(
            scripts=["Get-RegistryModifications.ps1"],
            timeout=60
        )
        
        # Cancel after short delay
        time.sleep(0.1)
        cancellation_result = integration.cancel_assessment(assessment_future)
        
        assert cancellation_result == True

    def test_error_recovery_strategies(self):
        """Test error recovery and retry strategies."""
        from src.admin_interface.components.powershell_integration import PowerShellIntegration
        
        integration = PowerShellIntegration()
        
        # Mock intermittent failure followed by success
        call_count = 0
        def mock_run_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First call fails
                result = Mock()
                result.returncode = 1
                result.stderr = "Temporary access denied"
                return result
            else:
                # Second call succeeds
                result = Mock()
                result.returncode = 0
                result.stdout = json.dumps({"security_score": 85})
                result.stderr = ""
                return result
        
        with patch('subprocess.run', side_effect=mock_run_side_effect):
            result = integration.execute_with_retry(
                script_name="Get-RegistryModifications.ps1",
                max_retries=2,
                retry_delay=0.1
            )
            
            assert result is not None
            assert 'security_score' in result
            assert call_count == 2  # Retried once

    def test_performance_monitoring(self):
        """Test performance monitoring of PowerShell script execution."""
        from src.admin_interface.components.powershell_integration import PowerShellIntegration
        
        integration = PowerShellIntegration()
        
        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = json.dumps({"security_score": 85})
            mock_run.return_value = mock_result
            
            # Execute with performance monitoring
            result = integration.execute_with_monitoring(
                script_name="Get-RegistryModifications.ps1"
            )
            
            assert 'performance_metrics' in result
            assert 'execution_time_seconds' in result['performance_metrics']
            assert 'memory_usage_mb' in result['performance_metrics']