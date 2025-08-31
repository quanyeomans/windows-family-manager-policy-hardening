# PowerShell Integration Component for Admin Interface
# Handles PowerShell-Python integration for system assessments

import subprocess
import json
import os
import time
import threading
import asyncio
import concurrent.futures
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
import queue
import psutil
import tempfile
import hashlib

class PowerShellIntegration:
    """PowerShell-Python integration for system security assessments."""
    
    def __init__(self, script_directory: Optional[str] = None, max_workers: int = 3):
        """Initialize PowerShell integration."""
        self.script_directory = script_directory or self._get_default_script_directory()
        self.max_workers = max_workers
        self.active_processes = {}
        self.execution_history = []
        self._lock = threading.Lock()
        
        # Validate PowerShell availability
        self.powershell_path = self._detect_powershell()
    
    def _get_default_script_directory(self) -> str:
        """Get default script directory path."""
        # Assumes scripts are in src/core/assessment relative to this file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(os.path.dirname(os.path.dirname(current_dir)), 'core', 'assessment')
    
    def _detect_powershell(self) -> str:
        """Detect available PowerShell executable."""
        # Try PowerShell Core (pwsh) first, then Windows PowerShell
        for ps_exe in ['pwsh.exe', 'powershell.exe']:
            try:
                result = subprocess.run([ps_exe, '-Command', 'Write-Output "test"'], 
                                      capture_output=True, timeout=5)
                if result.returncode == 0:
                    return ps_exe
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        raise RuntimeError("PowerShell not found. Please install PowerShell.")
    
    def execute_assessment_script(self, script_name: str, parameters: Dict[str, Any] = None, 
                                timeout: int = 60) -> Dict[str, Any]:
        """Execute a single PowerShell assessment script."""
        parameters = parameters or {}
        script_path = os.path.join(self.script_directory, script_name)
        
        # Verify script exists and integrity
        integrity_result = self.verify_script_integrity(script_name)
        if not integrity_result['valid']:
            return {
                'error': {
                    'error_type': 'SCRIPT_INTEGRITY_ERROR',
                    'error_message': 'Script integrity verification failed',
                    'details': integrity_result
                }
            }
        
        # Validate parameters
        param_validation = self.validate_script_parameters(parameters)
        if not param_validation['valid']:
            return {
                'error': {
                    'error_type': 'PARAMETER_VALIDATION_ERROR',
                    'error_message': 'Invalid parameters detected',
                    'details': param_validation
                }
            }
        
        # Build PowerShell command
        command = self.build_powershell_command(script_path, parameters)
        
        start_time = time.time()
        
        try:
            # Execute PowerShell script
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.script_directory
            )
            
            execution_time = time.time() - start_time
            
            # Record execution history
            self._record_execution(script_name, parameters, execution_time, result.returncode)
            
            if result.returncode == 0:
                # Parse successful output
                parsed_output = self.parse_powershell_output(result.stdout)
                
                # Validate output size
                size_validation = self.validate_output_size(result.stdout)
                if not size_validation['valid']:
                    return {
                        'error': {
                            'error_type': 'OUTPUT_SIZE_ERROR',
                            'error_message': 'Output exceeds size limits',
                            'details': size_validation
                        }
                    }
                
                # Add performance metrics
                if 'error' not in parsed_output:
                    parsed_output['performance_metrics'] = {
                        'execution_time_seconds': round(execution_time, 2),
                        'memory_usage_mb': self._get_memory_usage(),
                        'script_name': script_name
                    }
                
                return parsed_output
            
            else:
                # Handle execution error
                return self._handle_execution_error(result, script_name)
        
        except subprocess.TimeoutExpired:
            return {
                'error': {
                    'error_type': 'TIMEOUT',
                    'error_message': f'Script execution timed out after {timeout} seconds',
                    'script_name': script_name
                }
            }
        
        except Exception as e:
            return {
                'error': {
                    'error_type': 'EXECUTION_ERROR',
                    'error_message': str(e),
                    'script_name': script_name
                }
            }
    
    def execute_scripts_parallel(self, script_configs: List[Dict[str, Any]], 
                               max_workers: Optional[int] = None) -> Dict[str, Any]:
        """Execute multiple PowerShell scripts in parallel."""
        max_workers = max_workers or self.max_workers
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scripts for execution
            future_to_script = {}
            
            for config in script_configs:
                script_name = config['script']
                parameters = config.get('params', {})
                timeout = config.get('timeout', 60)
                
                future = executor.submit(
                    self.execute_assessment_script,
                    script_name, parameters, timeout
                )
                future_to_script[future] = script_name
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_script):
                script_name = future_to_script[future]
                try:
                    result = future.result()
                    results[script_name] = result
                except Exception as e:
                    results[script_name] = {
                        'error': {
                            'error_type': 'PARALLEL_EXECUTION_ERROR',
                            'error_message': str(e),
                            'script_name': script_name
                        }
                    }
        
        return results
    
    def execute_full_assessment(self, progress_callback: Optional[Callable] = None, 
                              verbose: bool = False) -> Dict[str, Any]:
        """Execute complete security assessment workflow."""
        assessment_scripts = [
            {"script": "Get-RegistryModifications.ps1", "step": "B001_registry_modification"},
            {"script": "Get-UserAccountInventory.ps1", "step": "B002_user_account_security"},
            {"script": "Get-GroupPolicyInventory.ps1", "step": "B003_group_policy_compliance"},
            {"script": "Test-SystemIntegrity.ps1", "step": "B004_system_integrity"},
            {"script": "Get-NetworkConfiguration.ps1", "step": "B005_network_configuration"},
            {"script": "Test-TimeControlBypasses.ps1", "step": "B006_time_control_bypass"}
        ]
        
        individual_results = {}
        start_time = datetime.now()
        
        for i, script_config in enumerate(assessment_scripts):
            script_name = script_config["script"]
            step_name = script_config["step"]
            
            if progress_callback:
                progress_callback(step_name, "started", {"step_number": i + 1, "total_steps": len(assessment_scripts)})
            
            # Execute individual assessment script
            step_start_time = time.time()
            result = self.execute_assessment_script(
                script_name, 
                {"-Verbose": verbose}, 
                timeout=120
            )
            step_execution_time = time.time() - step_start_time
            
            individual_results[step_name] = result
            
            if progress_callback:
                status = "completed" if 'error' not in result else "error"
                progress_callback(step_name, status, {
                    "execution_time": step_execution_time,
                    "result_preview": self._get_result_preview(result)
                })
        
        # Aggregate results into comprehensive assessment
        assessment_result = self.aggregate_assessment_results(individual_results)
        
        # Add assessment metadata
        total_duration = (datetime.now() - start_time).total_seconds()
        assessment_result['assessment_metadata'] = {
            'timestamp': start_time.isoformat(),
            'system_info': self._get_system_info(),
            'assessment_version': '1.0',
            'duration_seconds': round(total_duration, 2),
            'scripts_executed': len(assessment_scripts),
            'powershell_version': self._get_powershell_version()
        }
        
        return assessment_result
    
    def aggregate_assessment_results(self, individual_results: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate individual script results into comprehensive assessment."""
        aggregated = {
            'security_scorecard': {
                'overall_score': 0,
                'component_scores': {},
                'essential8_compliance': {}
            },
            'findings_summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'total_findings': 0
            },
            'detailed_findings': [],
            'remediation_approach': {
                'recommended_strategy': 'assessment_required',
                'rationale': 'Comprehensive assessment completed',
                'data_preservation_required': True
            }
        }
        
        component_scores = []
        
        for step_name, result in individual_results.items():
            if 'error' not in result:
                # Extract component score
                security_score = result.get('security_score', 0)
                component_scores.append(security_score)
                
                # Map step to component name
                component_name = self._map_step_to_component(step_name)
                aggregated['security_scorecard']['component_scores'][component_name] = security_score
                
                # Aggregate findings
                findings = result.get('findings', [])
                aggregated['detailed_findings'].extend(findings)
                
                # Update findings summary
                for finding in findings:
                    severity = finding.get('severity', 'LOW').lower()
                    if severity in aggregated['findings_summary']:
                        aggregated['findings_summary'][severity] += 1
                    aggregated['findings_summary']['total_findings'] += 1
        
        # Calculate overall score
        if component_scores:
            aggregated['security_scorecard']['overall_score'] = round(sum(component_scores) / len(component_scores), 1)
        
        # Determine remediation strategy
        overall_score = aggregated['security_scorecard']['overall_score']
        critical_findings = aggregated['findings_summary']['critical']
        
        if overall_score >= 80:
            aggregated['remediation_approach'] = {
                'recommended_strategy': 'selective_hardening',
                'rationale': 'System is in good condition, selective improvements recommended',
                'estimated_effort_hours': 2,
                'risk_level': 'LOW',
                'data_preservation_required': True
            }
        elif overall_score >= 60:
            aggregated['remediation_approach'] = {
                'recommended_strategy': 'in_place_remediation',
                'rationale': 'System shows manageable security gaps, in-place remediation feasible',
                'estimated_effort_hours': 4,
                'risk_level': 'MEDIUM',
                'data_preservation_required': True
            }
        elif critical_findings >= 3 or overall_score < 40:
            aggregated['remediation_approach'] = {
                'recommended_strategy': 'baseline_reset',
                'rationale': 'Multiple critical findings require comprehensive baseline reset',
                'estimated_effort_hours': 8,
                'risk_level': 'HIGH',
                'data_preservation_required': True
            }
        else:
            aggregated['remediation_approach'] = {
                'recommended_strategy': 'in_place_remediation',
                'rationale': 'Moderate security issues can be addressed through targeted remediation',
                'estimated_effort_hours': 6,
                'risk_level': 'MEDIUM',
                'data_preservation_required': True
            }
        
        return aggregated
    
    def parse_powershell_output(self, output: str) -> Dict[str, Any]:
        """Parse PowerShell JSON output."""
        if not output or output.strip() == "":
            return {
                'error': {
                    'error_type': 'EMPTY_OUTPUT',
                    'error_message': 'PowerShell script produced no output'
                }
            }
        
        try:
            # Clean output (remove any non-JSON content)
            cleaned_output = self._clean_powershell_output(output)
            return json.loads(cleaned_output)
            
        except json.JSONDecodeError as e:
            return {
                'error': {
                    'error_type': 'JSON_PARSE_ERROR',
                    'error_message': f'Failed to parse JSON output: {str(e)}',
                    'raw_output': output[:500]  # First 500 chars for debugging
                }
            }
    
    def build_powershell_command(self, script_path: str, parameters: Dict[str, Any]) -> List[str]:
        """Build PowerShell command with parameters."""
        command = [
            self.powershell_path,
            '-ExecutionPolicy', 'Bypass',
            '-NoProfile',
            '-File', script_path
        ]
        
        # Add parameters
        for param, value in parameters.items():
            if isinstance(value, bool):
                if value:  # Only add switch parameters if True
                    command.append(param)
            else:
                command.extend([param, str(value)])
        
        return command
    
    def validate_script_parameters(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Validate PowerShell script parameters for security."""
        dangerous_patterns = [
            'Remove-Item', 'Delete', 'Format-', 'Clear-', 'Stop-Process',
            'Invoke-Expression', 'iex', 'Invoke-WebRequest', 'curl', 'wget',
            '&', '|', ';', '`', '$', 'cmd.exe', 'powershell.exe'
        ]
        
        validation_result = {'valid': True, 'violations': []}
        
        for param, value in parameters.items():
            value_str = str(value)
            
            # Check for dangerous patterns
            for pattern in dangerous_patterns:
                if pattern.lower() in value_str.lower():
                    validation_result['valid'] = False
                    validation_result['violations'].append({
                        'parameter': param,
                        'value': value_str,
                        'pattern': pattern,
                        'risk': 'SECURITY_VIOLATION'
                    })
        
        if not validation_result['valid']:
            validation_result['security_violation'] = True
        
        return validation_result
    
    def verify_script_integrity(self, script_name: str) -> Dict[str, Any]:
        """Verify PowerShell script integrity before execution."""
        script_path = os.path.join(self.script_directory, script_name)
        
        result = {
            'valid': False,
            'script_exists': False,
            'script_path': script_path,
            'file_size': 0,
            'checksum': None
        }
        
        try:
            if os.path.exists(script_path):
                result['script_exists'] = True
                result['file_size'] = os.path.getsize(script_path)
                
                # Calculate file checksum
                with open(script_path, 'rb') as f:
                    file_content = f.read()
                    result['checksum'] = hashlib.md5(file_content).hexdigest()
                
                # Basic content validation
                with open(script_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Check if it looks like a PowerShell script
                    if content.strip() and ('function' in content or 'param(' in content):
                        result['valid'] = True
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def validate_output_size(self, output: str, max_size_mb: float = 10.0) -> Dict[str, Any]:
        """Validate PowerShell output size."""
        if not output:
            return {'valid': True, 'size_mb': 0.0}
        
        size_bytes = len(output.encode('utf-8'))
        size_mb = size_bytes / (1024 * 1024)
        
        return {
            'valid': size_mb <= max_size_mb,
            'size_mb': round(size_mb, 2),
            'size_bytes': size_bytes,
            'max_size_mb': max_size_mb
        }
    
    def execute_with_retry(self, script_name: str, max_retries: int = 2, 
                         retry_delay: float = 1.0) -> Dict[str, Any]:
        """Execute PowerShell script with retry logic."""
        last_error = None
        
        for attempt in range(max_retries + 1):
            try:
                result = self.execute_assessment_script(script_name)
                
                # If successful or non-retryable error, return result
                if 'error' not in result or not self._is_retryable_error(result['error']):
                    return result
                
                last_error = result['error']
                
                if attempt < max_retries:
                    time.sleep(retry_delay)
            
            except Exception as e:
                last_error = {'error_type': 'RETRY_EXCEPTION', 'error_message': str(e)}
                if attempt < max_retries:
                    time.sleep(retry_delay)
        
        return {'error': last_error}
    
    def execute_with_monitoring(self, script_name: str) -> Dict[str, Any]:
        """Execute PowerShell script with performance monitoring."""
        process_start = psutil.Process().memory_info().rss
        start_time = time.time()
        
        result = self.execute_assessment_script(script_name)
        
        end_time = time.time()
        process_end = psutil.Process().memory_info().rss
        
        # Add performance metrics to result
        if 'performance_metrics' not in result:
            result['performance_metrics'] = {}
        
        result['performance_metrics'].update({
            'execution_time_seconds': round(end_time - start_time, 2),
            'memory_usage_mb': round((process_end - process_start) / (1024 * 1024), 2),
            'monitoring_enabled': True
        })
        
        return result
    
    def start_assessment_async(self, scripts: List[str], timeout: int = 300) -> Any:
        """Start assessment asynchronously and return future."""
        # This would return a Future object for async execution
        # For now, return a placeholder
        return {"status": "async_started", "scripts": scripts, "timeout": timeout}
    
    def cancel_assessment(self, assessment_future: Any) -> bool:
        """Cancel running assessment."""
        # Implementation for cancelling async assessment
        return True
    
    # Helper methods
    def _handle_execution_error(self, result: subprocess.CompletedProcess, script_name: str) -> Dict[str, Any]:
        """Handle PowerShell execution error."""
        return {
            'error': {
                'error_type': 'POWERSHELL_EXECUTION_ERROR',
                'error_code': result.returncode,
                'error_message': result.stderr.strip() if result.stderr else 'Unknown PowerShell error',
                'script_name': script_name,
                'stdout': result.stdout[:500] if result.stdout else None
            }
        }
    
    def _clean_powershell_output(self, output: str) -> str:
        """Clean PowerShell output to extract JSON."""
        lines = output.strip().split('\n')
        json_lines = []
        in_json = False
        
        for line in lines:
            line = line.strip()
            if line.startswith('{') or line.startswith('['):
                in_json = True
            
            if in_json:
                json_lines.append(line)
            
            if in_json and (line.endswith('}') or line.endswith(']')):
                break
        
        return '\n'.join(json_lines) if json_lines else output
    
    def _record_execution(self, script_name: str, parameters: Dict, execution_time: float, return_code: int):
        """Record script execution in history."""
        with self._lock:
            self.execution_history.append({
                'timestamp': datetime.now().isoformat(),
                'script_name': script_name,
                'parameters': parameters,
                'execution_time': execution_time,
                'return_code': return_code
            })
            
            # Keep only last 100 entries
            if len(self.execution_history) > 100:
                self.execution_history = self.execution_history[-100:]
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            process = psutil.Process()
            return round(process.memory_info().rss / (1024 * 1024), 2)
        except:
            return 0.0
    
    def _get_result_preview(self, result: Dict[str, Any]) -> str:
        """Get preview of result for progress reporting."""
        if 'error' in result:
            return f"Error: {result['error'].get('error_message', 'Unknown error')}"
        
        security_score = result.get('security_score', 'N/A')
        findings_count = len(result.get('findings', []))
        
        return f"Score: {security_score}, Findings: {findings_count}"
    
    def _map_step_to_component(self, step_name: str) -> str:
        """Map assessment step to component name."""
        mapping = {
            'B001_registry_modification': 'registry_security',
            'B002_user_account_security': 'user_account_security',
            'B003_group_policy_compliance': 'group_policy_compliance',
            'B004_system_integrity': 'system_integrity',
            'B005_network_configuration': 'network_security',
            'B006_time_control_bypass': 'time_control_security'
        }
        return mapping.get(step_name, step_name)
    
    def _get_system_info(self) -> str:
        """Get basic system information."""
        try:
            import platform
            return f"{platform.node()} - {platform.system()} {platform.release()}"
        except:
            return "Unknown System"
    
    def _get_powershell_version(self) -> str:
        """Get PowerShell version."""
        try:
            result = subprocess.run([self.powershell_path, '-Command', '$PSVersionTable.PSVersion.ToString()'],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        return "Unknown"
    
    def _is_retryable_error(self, error: Dict[str, Any]) -> bool:
        """Check if error is retryable."""
        retryable_types = ['TIMEOUT', 'ACCESS_DENIED', 'TEMPORARY_ERROR']
        return error.get('error_type') in retryable_types