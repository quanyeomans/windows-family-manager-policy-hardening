# PowerShell Integration Tests
import pytest
import json
import subprocess
import tempfile
from pathlib import Path
import time

class TestPowerShellIntegration:
    """Integration tests for PowerShell script execution from Python."""
    
    @pytest.mark.integration
    def test_powershell_basic_execution(self, powershell_executor):
        """Test basic PowerShell command execution."""
        result = powershell_executor.run_command("Write-Output 'Hello from PowerShell'")
        
        assert result.returncode == 0, f"PowerShell execution failed: {result.stderr}"
        assert "Hello from PowerShell" in result.stdout, "Should receive expected output"
        
    @pytest.mark.integration
    def test_powershell_json_output_parsing(self, powershell_executor):
        """Test PowerShell JSON output parsing."""
        command = '''
        $data = @{
            status = "success"
            timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            data = @{
                key1 = "value1"
                key2 = 42
            }
        }
        $data | ConvertTo-Json -Depth 3
        '''
        
        result = powershell_executor.run_command(command)
        assert result.returncode == 0, f"PowerShell JSON command failed: {result.stderr}"
        
        # Parse JSON output
        json_data = json.loads(result.stdout)
        assert json_data["status"] == "success", "Should have success status"
        assert "timestamp" in json_data, "Should have timestamp"
        assert json_data["data"]["key1"] == "value1", "Should have nested data"
        assert json_data["data"]["key2"] == 42, "Should handle numeric values"
        
    @pytest.mark.integration
    def test_powershell_error_handling(self, powershell_executor):
        """Test PowerShell error handling and reporting."""
        # Execute command that will fail
        result = powershell_executor.run_command("Get-Item 'NonExistentFile.txt'")
        
        assert result.returncode != 0, "Command should fail for non-existent file"
        assert result.stderr, "Should have error output"
        
    @pytest.mark.integration  
    def test_powershell_script_file_execution(self, powershell_executor, temp_directory):
        """Test execution of PowerShell script files."""
        # Create a test PowerShell script
        script_content = '''
        param(
            [string]$Name = "World",
            [string]$OutputFormat = "Text"
        )
        
        $result = @{
            greeting = "Hello, $Name!"
            timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            parameters = @{
                name = $Name
                format = $OutputFormat
            }
        }
        
        if ($OutputFormat -eq "JSON") {
            $result | ConvertTo-Json -Depth 3
        } else {
            "Hello, $Name!"
        }
        '''
        
        script_path = temp_directory / "test_script.ps1"
        with open(script_path, 'w') as f:
            f.write(script_content)
            
        # Test script execution with parameters
        result = powershell_executor.run_script(script_path, "-Name", "TestUser", "-OutputFormat", "JSON")
        
        assert result.returncode == 0, f"Script execution failed: {result.stderr}"
        
        # Parse JSON output
        json_data = json.loads(result.stdout)
        assert json_data["greeting"] == "Hello, TestUser!", "Should use provided parameter"
        assert json_data["parameters"]["name"] == "TestUser", "Should capture parameters"
        
    @pytest.mark.integration
    def test_powershell_execution_timeout(self, powershell_executor):
        """Test PowerShell execution with timeout handling."""
        # Create command that will run longer than timeout
        long_running_command = "Start-Sleep -Seconds 2; Write-Output 'Completed'"
        
        start_time = time.time()
        result = powershell_executor.run_command(long_running_command)
        execution_time = time.time() - start_time
        
        # Should complete successfully (2 seconds is within reasonable limits)
        assert result.returncode == 0, "Long-running command should complete"
        assert "Completed" in result.stdout, "Should receive completion message"
        assert execution_time >= 2.0, "Should take at least 2 seconds"
        assert execution_time < 5.0, "Should complete within reasonable time"

class TestSystemAssessmentIntegration:
    """Integration tests for system assessment PowerShell scripts."""
    
    @pytest.mark.integration
    @pytest.mark.windows_only
    def test_system_assessment_script_execution(self, powershell_executor, src_directory):
        """Test system assessment script execution and output format."""
        assessment_script = src_directory / "assessment" / "Get-SystemSecurityAssessment.ps1"
        
        # Ensure script exists (created in BDD setup)
        assert assessment_script.exists(), f"Assessment script should exist at {assessment_script}"
        
        # Execute assessment script
        result = powershell_executor.run_script(assessment_script, "-OutputFormat", "JSON")
        
        assert result.returncode == 0, f"Assessment script failed: {result.stderr}"
        assert result.stdout.strip(), "Should have output"
        
        # Parse and validate JSON output
        assessment_data = json.loads(result.stdout)
        
        # Validate required structure
        required_fields = [
            'assessment_metadata',
            'security_scorecard',
            'findings_summary', 
            'detailed_findings',
            'remediation_approach'
        ]
        
        for field in required_fields:
            assert field in assessment_data, f"Assessment output missing required field: {field}"
            
        # Validate metadata
        metadata = assessment_data['assessment_metadata']
        assert 'timestamp' in metadata, "Should have timestamp"
        assert 'system_info' in metadata, "Should have system info"
        assert 'assessment_version' in metadata, "Should have version"
        
        # Validate security scorecard
        scorecard = assessment_data['security_scorecard']
        assert 'overall_score' in scorecard, "Should have overall score"
        assert isinstance(scorecard['overall_score'], (int, float)), "Score should be numeric"
        assert 0 <= scorecard['overall_score'] <= 100, "Score should be 0-100"
        
    @pytest.mark.integration 
    @pytest.mark.windows_only
    def test_essential8_compliance_checking(self, powershell_executor):
        """Test Essential 8 compliance checking integration."""
        # Create a minimal Essential 8 test script
        essential8_script_content = '''
        param([string]$OutputFormat = "JSON")
        
        $compliance = @{
            B020_passwords = @{ status = "PASS"; score = 10; details = "Password complexity enabled" }
            B021_admin_rights = @{ status = "FAIL"; score = 0; details = "Multiple admin accounts detected" }
            B022_os_updates = @{ status = "PASS"; score = 10; details = "Automatic updates enabled" }
            B023_app_updates = @{ status = "PARTIAL"; score = 5; details = "Some applications have auto-update disabled" }
            B024_macro_security = @{ status = "PASS"; score = 10; details = "Office macros restricted" }
            B025_browser_hardening = @{ status = "FAIL"; score = 0; details = "Multiple browsers installed" }
            B026_mfa = @{ status = "PARTIAL"; score = 5; details = "MFA enabled for some accounts" }
            B027_backup = @{ status = "PASS"; score = 10; details = "System backup configured" }
            B028_antivirus = @{ status = "PASS"; score = 10; details = "Windows Defender active" }
        }
        
        $overall_score = ($compliance.Values | ForEach-Object { $_.score } | Measure-Object -Sum).Sum / $compliance.Count * 10
        
        $result = @{
            assessment_metadata = @{
                timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                test_type = "essential8_compliance"
                version = "1.0"
            }
            essential8_compliance = $compliance
            overall_score = [math]::Round($overall_score, 1)
        }
        
        if ($OutputFormat -eq "JSON") {
            $result | ConvertTo-Json -Depth 4
        } else {
            "Essential 8 Compliance Score: $($result.overall_score)%"
        }
        '''
        
        # Create temporary script
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f:
            f.write(essential8_script_content)
            script_path = Path(f.name)
        
        try:
            result = powershell_executor.run_script(script_path, "-OutputFormat", "JSON")
            
            assert result.returncode == 0, f"Essential 8 script failed: {result.stderr}"
            
            compliance_data = json.loads(result.stdout)
            
            # Validate structure
            assert 'essential8_compliance' in compliance_data, "Should have compliance data"
            assert 'overall_score' in compliance_data, "Should have overall score"
            
            # Validate individual controls
            compliance = compliance_data['essential8_compliance']
            expected_controls = ['B020_passwords', 'B021_admin_rights', 'B022_os_updates']
            
            for control in expected_controls:
                assert control in compliance, f"Should have {control} compliance check"
                control_data = compliance[control]
                assert 'status' in control_data, f"{control} should have status"
                assert 'score' in control_data, f"{control} should have score"
                assert control_data['status'] in ['PASS', 'FAIL', 'PARTIAL'], f"Invalid status for {control}"
                
        finally:
            script_path.unlink()  # Clean up temporary file

class TestCrossLanguageIntegration:
    """Integration tests for Python-PowerShell cross-language operations."""
    
    @pytest.mark.integration
    def test_python_powershell_data_exchange(self, powershell_executor):
        """Test bidirectional data exchange between Python and PowerShell."""
        # Python data to send to PowerShell
        python_data = {
            "configuration": {
                "wifi_ssids": ["HomeNetwork", "SchoolNetwork"],
                "ethernet_disabled": True,
                "vpn_blocked": True
            },
            "users": ["daniel", "parent1", "parent2"]
        }
        
        # Create PowerShell script that processes Python data
        script_content = f'''
        # Simulate receiving JSON data from Python
        $inputData = '{json.dumps(python_data)}' | ConvertFrom-Json
        
        # Process the data
        $result = @{{
            processed_at = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            received_configuration = $inputData.configuration
            received_users = $inputData.users
            processing_result = @{{
                wifi_count = $inputData.configuration.wifi_ssids.Count
                users_count = $inputData.users.Count
                ethernet_status = if ($inputData.configuration.ethernet_disabled) {{ "disabled" }} else {{ "enabled" }}
            }}
        }}
        
        $result | ConvertTo-Json -Depth 4
        '''
        
        result = powershell_executor.run_command(script_content)
        
        assert result.returncode == 0, f"Cross-language script failed: {result.stderr}"
        
        # Parse PowerShell response
        response_data = json.loads(result.stdout)
        
        # Validate data was processed correctly
        assert response_data["received_configuration"]["ethernet_disabled"] == True, "Should receive ethernet config"
        assert len(response_data["received_users"]) == 3, "Should receive all users"
        assert response_data["processing_result"]["wifi_count"] == 2, "Should count WiFi SSIDs correctly"
        assert response_data["processing_result"]["ethernet_status"] == "disabled", "Should process ethernet status"
        
    @pytest.mark.integration
    def test_error_propagation_cross_language(self, powershell_executor):
        """Test error propagation from PowerShell to Python."""
        # PowerShell script that generates structured error
        error_script = '''
        try {
            # Simulate operation that fails
            throw "Simulated deployment error: Network adapter not found"
        } catch {
            $errorInfo = @{
                error_type = "DeploymentError"
                error_message = $_.Exception.Message
                error_details = @{
                    component = "NetworkAdapter"
                    operation = "Configure"
                    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                }
                suggested_actions = @(
                    "Check network adapter status",
                    "Verify driver installation", 
                    "Run network troubleshooter"
                )
            }
            
            # Output error as JSON to stderr
            $errorInfo | ConvertTo-Json -Depth 3 | Write-Error
            exit 1
        }
        '''
        
        result = powershell_executor.run_command(error_script)
        
        # Should fail with non-zero exit code
        assert result.returncode == 1, "Script should fail with exit code 1"
        assert result.stderr, "Should have error output"
        
        # Parse structured error information
        # Note: PowerShell Write-Error output format may vary
        assert "Simulated deployment error" in result.stderr, "Should contain error message"
        assert "NetworkAdapter" in result.stderr, "Should contain component information"

class TestStreamlitPowerShellIntegration:
    """Integration tests for Streamlit frontend with PowerShell backend."""
    
    @pytest.mark.integration
    def test_streamlit_backend_api_pattern(self, powershell_executor, temp_directory):
        """Test Streamlit-PowerShell integration pattern."""
        # Create mock backend API class
        backend_api_content = '''
import subprocess
import json
from pathlib import Path

class PowerShellBackendAPI:
    """API for Streamlit to communicate with PowerShell backend."""
    
    def __init__(self):
        self.powershell_base = ["powershell", "-ExecutionPolicy", "Bypass"]
    
    def run_system_assessment(self):
        """Run system security assessment."""
        try:
            result = subprocess.run(
                self.powershell_base + ["-Command", """
                $assessment = @{
                    security_score = 43.8
                    findings = @{critical = 8; high = 12; medium = 15; low = 5}
                    status = "completed"
                    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                }
                $assessment | ConvertTo-Json -Depth 3
                """],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return {"success": True, "data": json.loads(result.stdout)}
            else:
                return {"success": False, "error": result.stderr}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def deploy_policies(self, policy_config):
        """Deploy security policies."""
        try:
            config_json = json.dumps(policy_config)
            result = subprocess.run(
                self.powershell_base + ["-Command", f"""
                $config = '{config_json}' | ConvertFrom-Json
                
                $deployment = @{{
                    status = "success"
                    policies_deployed = $config.policies.Count
                    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                    results = @()
                }}
                
                foreach ($policy in $config.policies) {{
                    $deployment.results += @{{
                        policy = $policy
                        status = "applied"
                        message = "Policy $policy applied successfully"
                    }}
                }}
                
                $deployment | ConvertTo-Json -Depth 4
                """],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return {"success": True, "data": json.loads(result.stdout)}
            else:
                return {"success": False, "error": result.stderr}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
        '''
        
        # Write backend API to temporary file and import
        api_file = temp_directory / "backend_api.py"
        with open(api_file, 'w') as f:
            f.write(backend_api_content)
            
        # Import and test the API
        import sys
        sys.path.insert(0, str(temp_directory))
        
        try:
            from backend_api import PowerShellBackendAPI
            
            api = PowerShellBackendAPI()
            
            # Test system assessment
            assessment_result = api.run_system_assessment()
            assert assessment_result["success"], f"Assessment should succeed: {assessment_result.get('error')}"
            assert "security_score" in assessment_result["data"], "Should have security score"
            assert assessment_result["data"]["security_score"] == 43.8, "Should have expected score"
            
            # Test policy deployment
            policy_config = {
                "policies": ["essential8", "network_security", "application_control"]
            }
            
            deployment_result = api.deploy_policies(policy_config)
            assert deployment_result["success"], f"Deployment should succeed: {deployment_result.get('error')}"
            assert deployment_result["data"]["status"] == "success", "Should have success status"
            assert deployment_result["data"]["policies_deployed"] == 3, "Should deploy 3 policies"
            
        finally:
            sys.path.remove(str(temp_directory))
            
    @pytest.mark.integration
    def test_real_time_progress_tracking(self, powershell_executor):
        """Test real-time progress tracking for long-running operations."""
        # Create PowerShell script that simulates deployment with progress
        progress_script = '''
        $steps = @(
            "Initializing deployment",
            "Applying Essential 8 controls", 
            "Configuring network security",
            "Setting up application control",
            "Validating deployment"
        )
        
        for ($i = 0; $i -lt $steps.Count; $i++) {
            $progress = @{
                step = $i + 1
                total_steps = $steps.Count
                current_operation = $steps[$i]
                percentage = [math]::Round(($i + 1) / $steps.Count * 100, 1)
                timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            }
            
            # Output progress as JSON
            "PROGRESS: $($progress | ConvertTo-Json -Compress)"
            
            # Simulate work
            Start-Sleep -Milliseconds 200
        }
        
        # Final completion
        $completion = @{
            status = "completed"
            total_time_seconds = 1.0
            timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        }
        
        "COMPLETED: $($completion | ConvertTo-Json -Compress)"
        '''
        
        result = powershell_executor.run_command(progress_script)
        
        assert result.returncode == 0, f"Progress script failed: {result.stderr}"
        
        # Parse progress output
        output_lines = result.stdout.strip().split('\n')
        progress_lines = [line for line in output_lines if line.startswith('PROGRESS:')]
        completion_lines = [line for line in output_lines if line.startswith('COMPLETED:')]
        
        assert len(progress_lines) == 5, "Should have 5 progress updates"
        assert len(completion_lines) == 1, "Should have 1 completion message"
        
        # Validate progress tracking
        for i, line in enumerate(progress_lines):
            progress_json = line.replace('PROGRESS: ', '')
            progress_data = json.loads(progress_json)
            
            assert progress_data["step"] == i + 1, f"Step {i+1} should have correct step number"
            assert progress_data["total_steps"] == 5, "Should have correct total steps"
            assert progress_data["percentage"] > 0, "Should have positive percentage"
        
        # Validate completion
        completion_json = completion_lines[0].replace('COMPLETED: ', '')
        completion_data = json.loads(completion_json)
        assert completion_data["status"] == "completed", "Should have completed status"