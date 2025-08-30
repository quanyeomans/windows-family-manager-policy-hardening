# Contract Tests for PowerShell-Python Integration
import pytest
import json
import subprocess
from pathlib import Path
from jsonschema import validate, ValidationError

class TestPowerShellPythonContracts:
    """Contract tests ensuring stable interfaces between PowerShell and Python."""
    
    @pytest.mark.contract
    def test_system_assessment_output_contract(self, powershell_executor, assessment_result_schema):
        """CONTRACT: System assessment must provide consistent JSON output format."""
        # This contract ensures the assessment output format never breaks
        assessment_script_content = '''
        # Minimal assessment script that meets contract
        $result = @{
            assessment_metadata = @{
                timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                system_info = "Contract Test System"
                assessment_version = "1.0-contract"
            }
            security_scorecard = @{
                overall_score = 75.5
                essential8_compliance = @{
                    B020_passwords = @{ status = "PASS"; score = 10 }
                    B021_admin_rights = @{ status = "FAIL"; score = 0 }
                }
            }
            findings_summary = @{
                critical = 2
                high = 5
                medium = 8
                low = 3
            }
            detailed_findings = @(
                @{
                    category = "B021_admin_rights"
                    severity = "CRITICAL"
                    finding = "Multiple admin accounts detected"
                    recommendation = "Remove unauthorized admin accounts"
                }
            )
            remediation_approach = @{
                recommended_strategy = "in_place_remediation"
                rationale = "System shows manageable security gaps"
                data_preservation_required = $false
            }
        }
        
        $result | ConvertTo-Json -Depth 10
        '''
        
        result = powershell_executor.run_command(assessment_script_content)
        
        # Contract: Must execute successfully
        assert result.returncode == 0, f"Assessment script must execute successfully: {result.stderr}"
        
        # Contract: Must produce valid JSON
        try:
            assessment_data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            pytest.fail(f"Assessment output must be valid JSON: {e}")
        
        # Contract: Must conform to required schema
        try:
            validate(assessment_data, assessment_result_schema)
        except ValidationError as e:
            pytest.fail(f"Assessment output must conform to contract schema: {e}")
        
        # Contract: Required field types must be correct
        assert isinstance(assessment_data['security_scorecard']['overall_score'], (int, float)), \
            "Overall score must be numeric"
        assert isinstance(assessment_data['findings_summary']['critical'], int), \
            "Critical findings count must be integer"
        assert isinstance(assessment_data['detailed_findings'], list), \
            "Detailed findings must be a list"
    
    @pytest.mark.contract
    def test_policy_deployment_result_contract(self, powershell_executor):
        """CONTRACT: Policy deployment must return consistent result format."""
        deployment_script = '''
        param(
            [Parameter(Mandatory)]
            [string]$PolicyConfigJson
        )
        
        # Parse input configuration
        $config = $PolicyConfigJson | ConvertFrom-Json
        
        # Contract-compliant deployment result
        $result = @{
            deployment_metadata = @{
                timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                deployment_id = [guid]::NewGuid().ToString()
                version = "1.0"
            }
            deployment_status = "success"
            policies_processed = @()
            rollback_available = $true
            validation_results = @{
                total_tests = 0
                passed_tests = 0
                failed_tests = 0
                warnings = 0
            }
        }
        
        # Process each policy in configuration
        foreach ($policy in $config.policies) {
            $policyResult = @{
                policy_name = $policy.name
                policy_type = $policy.type
                status = "applied"
                message = "Policy $($policy.name) applied successfully"
                timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                rollback_info = @{
                    can_rollback = $true
                    rollback_script = "Undo-$($policy.name)Policy"
                }
            }
            $result.policies_processed += $policyResult
        }
        
        $result | ConvertTo-Json -Depth 10
        '''
        
        # Create test policy configuration
        test_config = {
            "policies": [
                {"name": "NetworkSecurity", "type": "network", "enabled": True},
                {"name": "ApplicationControl", "type": "application", "enabled": True}
            ]
        }
        
        config_json = json.dumps(test_config)
        # Create a script that defines the function and then calls it
        script_block = f"""
function Invoke-PolicyDeployment {{
{deployment_script}
}}

# Execute the function with the parameter
Invoke-PolicyDeployment -PolicyConfigJson '{config_json}'
"""
        result = powershell_executor.run_command(script_block)
        
        # Contract: Must execute successfully
        assert result.returncode == 0, f"Policy deployment must execute successfully: {result.stderr}"
        
        # Contract: Must produce valid JSON
        deployment_data = json.loads(result.stdout)
        
        # Contract: Must have required top-level fields
        required_fields = ['deployment_metadata', 'deployment_status', 'policies_processed', 'rollback_available', 'validation_results']
        for field in required_fields:
            assert field in deployment_data, f"Deployment result must contain {field}"
        
        # Contract: Status must be valid enum value
        valid_statuses = ['success', 'failure', 'partial', 'rollback_required']
        assert deployment_data['deployment_status'] in valid_statuses, \
            f"Deployment status must be one of {valid_statuses}"
        
        # Contract: Policies processed must be a list with correct structure
        policies_processed = deployment_data['policies_processed']
        assert isinstance(policies_processed, list), "Policies processed must be a list"
        
        for policy_result in policies_processed:
            required_policy_fields = ['policy_name', 'policy_type', 'status', 'message', 'rollback_info']
            for field in required_policy_fields:
                assert field in policy_result, f"Policy result must contain {field}"
    
    @pytest.mark.contract
    def test_error_response_contract(self, powershell_executor):
        """CONTRACT: Error responses must have consistent format for proper handling."""
        error_script = '''
        param([string]$ErrorType = "ValidationError")
        
        # Simulate different types of errors with consistent format
        switch ($ErrorType) {
            "ValidationError" {
                $errorResponse = @{
                    error_metadata = @{
                        timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                        error_id = [guid]::NewGuid().ToString()
                        source = "PolicyValidation"
                    }
                    error_type = "ValidationError"
                    error_message = "Policy configuration validation failed"
                    error_details = @{
                        validation_failures = @(
                            @{
                                field = "network.allowed_ssids"
                                error = "Array cannot be empty"
                                current_value = @()
                            }
                        )
                    }
                    suggested_actions = @(
                        "Review policy configuration",
                        "Ensure all required fields are populated",
                        "Check configuration against schema"
                    )
                    recoverable = $true
                    retry_possible = $true
                }
            }
            "SystemError" {
                $errorResponse = @{
                    error_metadata = @{
                        timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                        error_id = [guid]::NewGuid().ToString()
                        source = "SystemOperation"
                    }
                    error_type = "SystemError"
                    error_message = "System operation failed"
                    error_details = @{
                        system_component = "NetworkAdapter"
                        operation_attempted = "DisableEthernet"
                        system_error_code = 87
                    }
                    suggested_actions = @(
                        "Check system administrator privileges",
                        "Verify network adapter exists",
                        "Run system diagnostics"
                    )
                    recoverable = $false
                    retry_possible = $false
                }
            }
        }
        
        # Output error as JSON to stdout (for contract testing)
        $errorResponse | ConvertTo-Json -Depth 10
        
        # Exit with error code
        exit 1
        '''
        
        # Test validation error format
        result = powershell_executor.run_command(f'{error_script} -ErrorType "ValidationError"')
        
        # Contract: Should fail with non-zero exit code
        assert result.returncode != 0, "Error script should exit with non-zero code"
        
        # Contract: Should produce valid JSON error response
        error_data = json.loads(result.stdout)
        
        # Contract: Must have required error fields
        required_error_fields = ['error_metadata', 'error_type', 'error_message', 'error_details', 'suggested_actions', 'recoverable', 'retry_possible']
        for field in required_error_fields:
            assert field in error_data, f"Error response must contain {field}"
        
        # Contract: Error type must be meaningful
        assert error_data['error_type'] in ['ValidationError', 'SystemError', 'DeploymentError', 'NetworkError'], \
            "Error type must be from known categories"
        
        # Contract: Suggested actions must be actionable
        suggested_actions = error_data['suggested_actions']
        assert isinstance(suggested_actions, list), "Suggested actions must be a list"
        assert len(suggested_actions) > 0, "Must provide at least one suggested action"
        
        # Contract: Recovery flags must be boolean
        assert isinstance(error_data['recoverable'], bool), "Recoverable flag must be boolean"
        assert isinstance(error_data['retry_possible'], bool), "Retry possible flag must be boolean"
    
    @pytest.mark.contract
    def test_progress_reporting_contract(self, powershell_executor):
        """CONTRACT: Long-running operations must report progress in consistent format."""
        progress_script = '''
        param([int]$TotalSteps = 3)
        
        # Contract-compliant progress reporting
        for ($i = 1; $i -le $TotalSteps; $i++) {
            $progress = @{
                progress_metadata = @{
                    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                    operation_id = "contract-test-operation"
                }
                current_step = $i
                total_steps = $TotalSteps
                percentage = [math]::Round(($i / $TotalSteps) * 100, 1)
                current_operation = "Step $i operation"
                estimated_remaining_seconds = ($TotalSteps - $i) * 2
                can_cancel = $true
                status = if ($i -eq $TotalSteps) { "completed" } else { "in_progress" }
            }
            
            # Output progress with consistent prefix
            "PROGRESS: $($progress | ConvertTo-Json -Compress)"
            
            if ($i -lt $TotalSteps) {
                Start-Sleep -Milliseconds 100
            }
        }
        '''
        
        result = powershell_executor.run_command(progress_script)
        
        # Contract: Progress operation must complete successfully
        assert result.returncode == 0, f"Progress script must complete successfully: {result.stderr}"
        
        # Contract: Must output progress lines with consistent format
        output_lines = result.stdout.strip().split('\n')
        progress_lines = [line for line in output_lines if line.startswith('PROGRESS:')]
        
        assert len(progress_lines) == 3, "Must output progress for each step"
        
        # Contract: Each progress line must be valid JSON with required fields
        for i, line in enumerate(progress_lines):
            progress_json = line.replace('PROGRESS: ', '')
            progress_data = json.loads(progress_json)
            
            # Contract: Required progress fields
            required_progress_fields = ['progress_metadata', 'current_step', 'total_steps', 'percentage', 'current_operation', 'estimated_remaining_seconds', 'can_cancel', 'status']
            for field in required_progress_fields:
                assert field in progress_data, f"Progress report must contain {field}"
            
            # Contract: Progress values must be logical
            assert progress_data['current_step'] == i + 1, f"Step {i+1} must have correct step number"
            assert progress_data['total_steps'] == 3, "Must have correct total steps"
            assert 0 <= progress_data['percentage'] <= 100, "Percentage must be 0-100"
            assert isinstance(progress_data['can_cancel'], bool), "Can cancel must be boolean"
            
            # Contract: Final step must be marked as completed
            if i == 2:  # Last step
                assert progress_data['status'] == 'completed', "Final step must be marked completed"
            else:
                assert progress_data['status'] == 'in_progress', "Non-final steps must be in progress"
    
    @pytest.mark.contract
    def test_configuration_input_contract(self, powershell_executor):
        """CONTRACT: PowerShell scripts must accept configuration in consistent format."""
        config_processing_script = '''
        param(
            [Parameter(Mandatory)]
            [string]$ConfigurationJson
        )
        
        # Contract: Must accept and validate configuration JSON
        try {
            $config = $ConfigurationJson | ConvertFrom-Json
        } catch {
            $error = @{
                error_type = "ConfigurationParsingError"
                error_message = "Invalid JSON configuration provided"
                error_details = @{
                    json_error = $_.Exception.Message
                }
            }
            $error | ConvertTo-Json -Depth 3
            exit 1
        }
        
        # Contract: Must validate required configuration sections
        $requiredSections = @('metadata', 'policies', 'users')
        $missingSections = @()
        
        foreach ($section in $requiredSections) {
            if (-not ($config.PSObject.Properties.Name -contains $section)) {
                $missingSections += $section
            }
        }
        
        if ($missingSections.Count -gt 0) {
            $error = @{
                error_type = "ConfigurationValidationError"
                error_message = "Required configuration sections missing"
                error_details = @{
                    missing_sections = $missingSections
                    required_sections = $requiredSections
                }
            }
            $error | ConvertTo-Json -Depth 3
            exit 1
        }
        
        # Contract: Must return processed configuration confirmation
        $result = @{
            configuration_processed = $true
            processed_at = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            configuration_summary = @{
                metadata_version = $config.metadata.version
                policies_count = $config.policies.Count
                users_count = $config.users.Count
            }
            validation_status = "passed"
        }
        
        $result | ConvertTo-Json -Depth 3
        '''
        
        # Test with valid configuration
        valid_config = {
            "metadata": {
                "version": "1.0",
                "created_at": "2025-08-30T10:00:00Z"
            },
            "policies": [
                {"name": "network_security", "enabled": True},
                {"name": "application_control", "enabled": True}
            ],
            "users": [
                {"name": "daniel", "role": "child"},
                {"name": "parent1", "role": "parent"}
            ]
        }
        
        config_json = json.dumps(valid_config)
        # Create a script that defines the function and then calls it
        script_block = f"""
function Invoke-ConfigurationProcessing {{
{config_processing_script}
}}

# Execute the function with the parameter
Invoke-ConfigurationProcessing -ConfigurationJson '{config_json}'
"""
        result = powershell_executor.run_command(script_block)
        
        # Contract: Must process valid configuration successfully
        assert result.returncode == 0, f"Valid configuration must be processed successfully: {result.stderr}"
        
        # Contract: Must return processing confirmation
        processing_result = json.loads(result.stdout)
        
        required_result_fields = ['configuration_processed', 'processed_at', 'configuration_summary', 'validation_status']
        for field in required_result_fields:
            assert field in processing_result, f"Processing result must contain {field}"
        
        assert processing_result['configuration_processed'] == True, "Must confirm configuration was processed"
        assert processing_result['validation_status'] == 'passed', "Must confirm validation passed"
        
        # Test with invalid configuration (missing required section)
        invalid_config = {
            "metadata": {"version": "1.0"},
            "policies": []
            # Missing 'users' section
        }
        
        invalid_json = json.dumps(invalid_config)
        # Create a script that defines the function and then calls it  
        invalid_script_block = f"""
function Invoke-ConfigurationProcessing {{
{config_processing_script}
}}

# Execute the function with the parameter
Invoke-ConfigurationProcessing -ConfigurationJson '{invalid_json}'
"""
        invalid_result = powershell_executor.run_command(invalid_script_block)
        
        # Contract: Must reject invalid configuration
        assert invalid_result.returncode != 0, "Invalid configuration must be rejected"
        
        # Contract: Must provide structured error response
        error_response = json.loads(invalid_result.stdout)
        assert 'error_type' in error_response, "Must provide structured error for invalid config"
        assert error_response['error_type'] == 'ConfigurationValidationError', "Must identify configuration validation error"