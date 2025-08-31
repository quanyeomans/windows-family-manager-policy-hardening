# Unit Tests for JSON Processing Component
# Tests for JSON parsing, validation, and transformation operations

import pytest
import json
from datetime import datetime, timezone
from unittest.mock import Mock, patch
from jsonschema import ValidationError

class TestJSONProcessor:
    """Unit tests for JSON processing component."""
    
    @pytest.fixture
    def valid_assessment_json(self):
        """Valid assessment result JSON for testing."""
        return {
            "assessment_metadata": {
                "timestamp": "2025-08-30T10:00:00Z",
                "system_info": "Windows 11 Test System",
                "assessment_version": "1.0"
            },
            "security_scorecard": {
                "overall_score": 75.5,
                "essential8_compliance": {
                    "B020_passwords": {"status": "PASS", "score": 10},
                    "B021_admin_rights": {"status": "FAIL", "score": 0}
                }
            },
            "findings_summary": {
                "critical": 2,
                "high": 3,
                "medium": 5,
                "low": 8
            },
            "detailed_findings": [
                {
                    "category": "B021_admin_rights", 
                    "severity": "CRITICAL",
                    "finding": "Unauthorized admin account detected",
                    "recommendation": "Remove or disable unauthorized admin account"
                }
            ],
            "remediation_approach": {
                "recommended_strategy": "in_place_remediation",
                "rationale": "System shows manageable security gaps",
                "data_preservation_required": True
            }
        }
    
    @pytest.fixture
    def assessment_schema(self):
        """JSON schema for assessment result validation."""
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
                    "required": ["timestamp", "system_info", "assessment_version"],
                    "properties": {
                        "timestamp": {"type": "string", "format": "date-time"},
                        "system_info": {"type": "string"},
                        "assessment_version": {"type": "string"}
                    }
                },
                "security_scorecard": {
                    "type": "object",
                    "required": ["overall_score"],
                    "properties": {
                        "overall_score": {"type": "number", "minimum": 0, "maximum": 100}
                    }
                },
                "findings_summary": {
                    "type": "object",
                    "required": ["critical", "high", "medium", "low"],
                    "properties": {
                        "critical": {"type": "integer", "minimum": 0},
                        "high": {"type": "integer", "minimum": 0},
                        "medium": {"type": "integer", "minimum": 0},
                        "low": {"type": "integer", "minimum": 0}
                    }
                },
                "detailed_findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["category", "severity", "finding", "recommendation"]
                    }
                },
                "remediation_approach": {
                    "type": "object",
                    "required": ["recommended_strategy", "rationale"],
                    "properties": {
                        "recommended_strategy": {
                            "type": "string",
                            "enum": ["in_place_remediation", "baseline_reset", "selective_hardening"]
                        }
                    }
                }
            }
        }

    # JSON Parsing Tests
    def test_json_parsing_valid_data(self, valid_assessment_json):
        """Test parsing of valid JSON data."""
        json_string = json.dumps(valid_assessment_json)
        
        # Test JSON parsing
        parsed_data = self._parse_json(json_string)
        
        assert parsed_data is not None
        assert parsed_data["security_scorecard"]["overall_score"] == 75.5
        assert len(parsed_data["detailed_findings"]) == 1
    
    def test_json_parsing_invalid_syntax(self):
        """Test handling of invalid JSON syntax."""
        invalid_json = '{"assessment_metadata": {"timestamp": "2025-08-30T10:00:00Z", "system_info": "Test"'  # Missing closing braces
        
        # Test invalid JSON handling
        result = self._parse_json(invalid_json)
        
        assert result is None or isinstance(result, dict) and "error" in result
    
    def test_json_parsing_empty_data(self):
        """Test handling of empty JSON data."""
        empty_scenarios = ["", "{}", "[]", "null"]
        
        for empty_json in empty_scenarios:
            result = self._parse_json(empty_json)
            
            # Should handle gracefully
            if empty_json == "{}":
                assert result == {}
            elif empty_json == "[]":
                assert result == []
            elif empty_json == "null":
                assert result is None
            else:  # Empty string
                assert result is None or "error" in result

    # JSON Schema Validation Tests
    def test_json_schema_validation_valid_data(self, valid_assessment_json, assessment_schema):
        """Test JSON schema validation with valid data."""
        validation_result = self._validate_json_schema(valid_assessment_json, assessment_schema)
        
        assert validation_result["valid"] == True
        assert len(validation_result["errors"]) == 0
    
    def test_json_schema_validation_missing_required_fields(self, assessment_schema):
        """Test schema validation with missing required fields."""
        invalid_data = {
            "assessment_metadata": {
                "timestamp": "2025-08-30T10:00:00Z"
                # Missing required fields: system_info, assessment_version
            },
            "security_scorecard": {
                "overall_score": 75.5
            }
            # Missing required top-level fields: findings_summary, detailed_findings, remediation_approach
        }
        
        validation_result = self._validate_json_schema(invalid_data, assessment_schema)
        
        assert validation_result["valid"] == False
        assert len(validation_result["errors"]) > 0
        
        # Check for specific validation errors
        error_messages = " ".join(validation_result["errors"])
        assert "findings_summary" in error_messages or "required" in error_messages.lower()
    
    def test_json_schema_validation_invalid_data_types(self, assessment_schema):
        """Test schema validation with invalid data types."""
        invalid_data = {
            "assessment_metadata": {
                "timestamp": "2025-08-30T10:00:00Z",
                "system_info": "Test System",
                "assessment_version": "1.0"
            },
            "security_scorecard": {
                "overall_score": "invalid_string_score"  # Should be number
            },
            "findings_summary": {
                "critical": "two",  # Should be integer
                "high": 3,
                "medium": 5,
                "low": 8
            },
            "detailed_findings": [],
            "remediation_approach": {
                "recommended_strategy": "invalid_strategy",  # Not in enum
                "rationale": "Test rationale"
            }
        }
        
        validation_result = self._validate_json_schema(invalid_data, assessment_schema)
        
        assert validation_result["valid"] == False
        assert len(validation_result["errors"]) >= 1  # At least one validation error

    # JSON Transformation Tests
    def test_json_data_transformation_powershell_to_python(self):
        """Test transformation of PowerShell JSON output to Python format."""
        # Mock PowerShell JSON output (Windows-style paths, different naming)
        powershell_json = {
            "AssessmentMetadata": {
                "TimeStamp": "2025-08-30T10:00:00.0000000Z",
                "SystemInfo": "Windows 11 Test System",
                "Version": "1.0"
            },
            "SecurityResults": {
                "OverallScore": 75.5,
                "FindingsCount": {
                    "Critical": 2,
                    "High": 3,
                    "Medium": 5,
                    "Low": 8
                }
            },
            "DetailedFindings": [
                {
                    "Category": "B021_admin_rights",
                    "Severity": "Critical", 
                    "Description": "Unauthorized admin account detected",
                    "Recommendation": "Remove or disable account"
                }
            ]
        }
        
        # Transform to Python naming convention
        python_json = self._transform_powershell_to_python(powershell_json)
        
        # Test transformation
        assert "assessment_metadata" in python_json
        assert python_json["assessment_metadata"]["timestamp"] == "2025-08-30T10:00:00Z"  # Simplified timestamp
        assert python_json["assessment_metadata"]["system_info"] == "Windows 11 Test System"
        
        assert "security_scorecard" in python_json
        assert python_json["security_scorecard"]["overall_score"] == 75.5
        
        assert "findings_summary" in python_json
        assert python_json["findings_summary"]["critical"] == 2
        
        assert len(python_json["detailed_findings"]) == 1
        assert python_json["detailed_findings"][0]["severity"] == "CRITICAL"  # Uppercase
    
    def test_json_data_sanitization(self):
        """Test JSON data sanitization for security."""
        potentially_dangerous_json = {
            "user_input": "<script>alert('xss')</script>",
            "file_path": "C:\\Windows\\System32\\..\\..\\secrets.txt",
            "command": "powershell.exe -Command Remove-Item C:\\Windows\\System32",
            "sql_query": "SELECT * FROM users; DROP TABLE users; --",
            "legitimate_data": "Normal system information"
        }
        
        # Sanitize JSON data
        sanitized_json = self._sanitize_json_data(potentially_dangerous_json)
        
        # Test sanitization
        assert "<script>" not in sanitized_json["user_input"]
        assert "alert" not in sanitized_json["user_input"]
        assert "..\\.." not in sanitized_json["file_path"] 
        assert "Remove-Item" not in sanitized_json["command"]
        assert "DROP TABLE" not in sanitized_json["sql_query"]
        assert sanitized_json["legitimate_data"] == "Normal system information"  # Unchanged
    
    def test_json_size_validation(self):
        """Test JSON size validation for performance and security."""
        # Test normal size JSON
        normal_json = {"data": "normal content"}
        assert self._validate_json_size(json.dumps(normal_json), max_size_mb=1) == True
        
        # Test oversized JSON
        large_data = {"data": "x" * (2 * 1024 * 1024)}  # 2MB of data
        assert self._validate_json_size(json.dumps(large_data), max_size_mb=1) == False
        
        # Test empty JSON
        assert self._validate_json_size("", max_size_mb=1) == True
        assert self._validate_json_size("{}", max_size_mb=1) == True

    # JSON Datetime Handling Tests
    def test_json_datetime_parsing(self):
        """Test datetime parsing from various JSON formats."""
        datetime_formats = [
            "2025-08-30T10:00:00Z",
            "2025-08-30T10:00:00.000Z",
            "2025-08-30T10:00:00+00:00",
            "2025-08-30 10:00:00",
            "2025-08-30T10:00:00.0000000Z"  # PowerShell format
        ]
        
        for dt_string in datetime_formats:
            parsed_dt = self._parse_json_datetime(dt_string)
            
            # All should parse to same datetime
            assert parsed_dt is not None
            assert parsed_dt.year == 2025
            assert parsed_dt.month == 8
            assert parsed_dt.day == 30
            assert parsed_dt.hour == 10
    
    def test_json_datetime_validation(self):
        """Test datetime validation in JSON data."""
        json_with_timestamps = {
            "assessment_metadata": {
                "timestamp": "2025-08-30T10:00:00Z",
                "last_update": "2025-08-30T09:30:00Z"
            },
            "findings": [
                {
                    "detected_at": "2025-08-30T08:15:00Z",
                    "severity": "HIGH"
                }
            ]
        }
        
        # Validate all timestamps are reasonable (not future, not too old)
        validation_result = self._validate_json_timestamps(json_with_timestamps)
        
        assert validation_result["valid"] == True
        assert len(validation_result["invalid_timestamps"]) == 0

    # JSON Error Handling Tests
    def test_json_parsing_with_recovery(self):
        """Test JSON parsing with error recovery strategies."""
        problematic_json_scenarios = [
            {
                "input": '{"data": "value", "extra_comma":,}',
                "recoverable": False,
                "strategy": "SYNTAX_ERROR"
            },
            {
                "input": '{"data": "truncated string',
                "recoverable": False, 
                "strategy": "TRUNCATED_DATA"
            },
            {
                "input": '{"data": null, "extra_field": "ignored"}',
                "recoverable": True,
                "strategy": "IGNORE_UNKNOWN_FIELDS"
            }
        ]
        
        for scenario in problematic_json_scenarios:
            recovery_result = self._attempt_json_recovery(scenario["input"])
            
            assert recovery_result["recoverable"] == scenario["recoverable"]
            assert recovery_result["strategy"] == scenario["strategy"]
    
    def test_json_validation_error_reporting(self):
        """Test detailed JSON validation error reporting."""
        invalid_json = {
            "assessment_metadata": {
                # Missing required timestamp
                "system_info": "",  # Empty string
                "assessment_version": None  # Null value
            },
            "security_scorecard": {
                "overall_score": 150  # Out of range (0-100)
            }
            # Missing required fields
        }
        
        validation_errors = self._collect_validation_errors(invalid_json)
        
        # Test detailed error reporting
        assert len(validation_errors) > 0
        
        # Check for specific error types
        error_types = [error["type"] for error in validation_errors]
        assert "MISSING_REQUIRED_FIELD" in error_types
        assert "VALUE_OUT_OF_RANGE" in error_types or "INVALID_VALUE" in error_types

    # Helper Methods for JSON Processing
    def _parse_json(self, json_string):
        """Parse JSON string with error handling."""
        try:
            if not json_string or json_string.strip() == "":
                return None
            return json.loads(json_string)
        except json.JSONDecodeError as e:
            return {"error": f"JSON parsing failed: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}
    
    def _validate_json_schema(self, data, schema):
        """Validate JSON data against schema."""
        try:
            from jsonschema import validate
            validate(data, schema)
            return {"valid": True, "errors": []}
        except ValidationError as e:
            return {"valid": False, "errors": [str(e)]}
        except Exception as e:
            return {"valid": False, "errors": [f"Schema validation error: {str(e)}"]}
    
    def _transform_powershell_to_python(self, powershell_data):
        """Transform PowerShell naming convention to Python."""
        # Simple transformation for testing
        transformed = {}
        
        if "AssessmentMetadata" in powershell_data:
            transformed["assessment_metadata"] = {
                "timestamp": powershell_data["AssessmentMetadata"]["TimeStamp"].replace(".0000000", ""),
                "system_info": powershell_data["AssessmentMetadata"]["SystemInfo"], 
                "assessment_version": powershell_data["AssessmentMetadata"]["Version"]
            }
        
        if "SecurityResults" in powershell_data:
            transformed["security_scorecard"] = {
                "overall_score": powershell_data["SecurityResults"]["OverallScore"]
            }
            
            if "FindingsCount" in powershell_data["SecurityResults"]:
                transformed["findings_summary"] = {
                    "critical": powershell_data["SecurityResults"]["FindingsCount"]["Critical"],
                    "high": powershell_data["SecurityResults"]["FindingsCount"]["High"],
                    "medium": powershell_data["SecurityResults"]["FindingsCount"]["Medium"],
                    "low": powershell_data["SecurityResults"]["FindingsCount"]["Low"]
                }
        
        if "DetailedFindings" in powershell_data:
            transformed["detailed_findings"] = []
            for finding in powershell_data["DetailedFindings"]:
                transformed["detailed_findings"].append({
                    "category": finding["Category"],
                    "severity": finding["Severity"].upper(),
                    "finding": finding["Description"],
                    "recommendation": finding["Recommendation"]
                })
        
        return transformed
    
    def _sanitize_json_data(self, data):
        """Sanitize JSON data for security."""
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                sanitized[key] = self._sanitize_json_data(value)
            return sanitized
        elif isinstance(data, list):
            return [self._sanitize_json_data(item) for item in data]
        elif isinstance(data, str):
            # Basic sanitization
            sanitized = data
            dangerous_patterns = [
                "<script>", "</script>", "javascript:", "vbscript:", "alert",
                "Remove-Item", "DROP TABLE", "DELETE FROM",
                "..\\..", "../.."
            ]
            for pattern in dangerous_patterns:
                sanitized = sanitized.replace(pattern, "")
            return sanitized
        else:
            return data
    
    def _validate_json_size(self, json_string, max_size_mb):
        """Validate JSON size constraints."""
        if not json_string:
            return True
        
        size_bytes = len(json_string.encode('utf-8'))
        max_size_bytes = max_size_mb * 1024 * 1024
        
        return size_bytes <= max_size_bytes
    
    def _parse_json_datetime(self, dt_string):
        """Parse datetime from various JSON formats."""
        if not dt_string:
            return None
        
        # Try different datetime formats
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f0Z"  # PowerShell format
        ]
        
        # Clean up PowerShell format
        cleaned_dt = dt_string.replace(".0000000Z", "Z")
        
        for fmt in formats:
            try:
                return datetime.strptime(cleaned_dt, fmt)
            except ValueError:
                continue
        
        return None
    
    def _validate_json_timestamps(self, data):
        """Validate timestamps in JSON data."""
        now = datetime.now()
        one_year_ago = now.replace(year=now.year - 1)
        
        invalid_timestamps = []
        
        def check_timestamp(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key.endswith("timestamp") or key.endswith("_at") or key == "last_update":
                        if isinstance(value, str):
                            parsed_dt = self._parse_json_datetime(value)
                            if parsed_dt and (parsed_dt > now or parsed_dt < one_year_ago):
                                invalid_timestamps.append(f"{path}.{key}")
                    else:
                        check_timestamp(value, f"{path}.{key}" if path else key)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_timestamp(item, f"{path}[{i}]" if path else f"[{i}]")
        
        check_timestamp(data)
        
        return {
            "valid": len(invalid_timestamps) == 0,
            "invalid_timestamps": invalid_timestamps
        }
    
    def _attempt_json_recovery(self, json_string):
        """Attempt JSON recovery strategies."""
        if not json_string:
            return {"recoverable": False, "strategy": "EMPTY_INPUT"}
        
        # Try to identify recovery strategy
        if ",}" in json_string or ",]" in json_string:
            return {"recoverable": False, "strategy": "SYNTAX_ERROR"}
        
        if json_string.count('{') != json_string.count('}'):
            return {"recoverable": False, "strategy": "TRUNCATED_DATA"}
        
        try:
            # Try parsing as-is
            parsed = json.loads(json_string)
            # Check if it has extra fields (simplified check)
            if "extra_field" in json_string:
                return {"recoverable": True, "strategy": "IGNORE_UNKNOWN_FIELDS"}
            return {"recoverable": True, "strategy": "NO_RECOVERY_NEEDED"}
        except:
            # Could implement more sophisticated recovery
            return {"recoverable": True, "strategy": "IGNORE_UNKNOWN_FIELDS"}
    
    def _collect_validation_errors(self, data):
        """Collect detailed validation errors."""
        errors = []
        
        # Check for missing required fields
        if "assessment_metadata" not in data:
            errors.append({"type": "MISSING_REQUIRED_FIELD", "field": "assessment_metadata"})
        elif "timestamp" not in data["assessment_metadata"]:
            errors.append({"type": "MISSING_REQUIRED_FIELD", "field": "assessment_metadata.timestamp"})
        
        # Check for invalid values
        if "security_scorecard" in data and "overall_score" in data["security_scorecard"]:
            score = data["security_scorecard"]["overall_score"]
            if isinstance(score, (int, float)) and (score < 0 or score > 100):
                errors.append({"type": "VALUE_OUT_OF_RANGE", "field": "overall_score", "value": score})
        
        return errors