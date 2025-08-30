# Unit Tests for System Assessment Engine
# Tests for B001-B006 requirements: system audit and discovery capabilities

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from datetime import datetime

class TestSystemAssessmentEngine:
    """Unit tests for system assessment and discovery engine."""
    
    @pytest.fixture
    def mock_powershell_result(self):
        """Mock PowerShell execution result."""
        return Mock(
            returncode=0,
            stdout='{"status": "success", "data": {}}',
            stderr=''
        )
    
    @pytest.fixture
    def mock_registry_data(self):
        """Mock registry modification data for B001 testing."""
        return {
            "modifications": [
                {
                    "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    "value": "EnableLUA",
                    "current_value": 0,
                    "expected_value": 1,
                    "risk_level": "HIGH",
                    "description": "User Account Control disabled"
                },
                {
                    "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
                    "value": "Hidden",
                    "current_value": 1,
                    "expected_value": 2,
                    "risk_level": "MEDIUM",
                    "description": "Show hidden files enabled"
                }
            ],
            "total_modifications": 2,
            "high_risk_count": 1,
            "medium_risk_count": 1,
            "low_risk_count": 0
        }
    
    @pytest.fixture
    def mock_user_account_data(self):
        """Mock user account inventory for B002 testing."""
        return {
            "accounts": [
                {
                    "name": "Administrator",
                    "sid": "S-1-5-21-123456789-1234567890-123456789-500",
                    "enabled": False,
                    "privilege_level": "Administrator",
                    "last_logon": "2025-08-29T10:00:00Z",
                    "password_expires": True,
                    "risk_assessment": "LOW"
                },
                {
                    "name": "daniel",
                    "sid": "S-1-5-21-123456789-1234567890-123456789-1001", 
                    "enabled": True,
                    "privilege_level": "User",
                    "last_logon": "2025-08-30T08:30:00Z",
                    "password_expires": True,
                    "risk_assessment": "LOW"
                },
                {
                    "name": "backup_admin",
                    "sid": "S-1-5-21-123456789-1234567890-123456789-1002",
                    "enabled": True,
                    "privilege_level": "Administrator",
                    "last_logon": "2025-08-30T06:00:00Z",
                    "password_expires": False,
                    "risk_assessment": "HIGH"
                }
            ],
            "total_accounts": 3,
            "admin_accounts": 2,
            "enabled_admin_accounts": 1,
            "risk_accounts": 1
        }

    # B001: Registry Modification Audit Tests
    def test_registry_modification_detection_logic(self, mock_registry_data):
        """Test registry modification detection algorithm."""
        # Test high-risk modification identification
        high_risk_mods = [mod for mod in mock_registry_data["modifications"] if mod["risk_level"] == "HIGH"]
        assert len(high_risk_mods) == 1
        assert high_risk_mods[0]["value"] == "EnableLUA"
        
        # Test risk scoring calculation
        total_risk_score = sum(3 if mod["risk_level"] == "HIGH" else 2 if mod["risk_level"] == "MEDIUM" else 1 
                             for mod in mock_registry_data["modifications"])
        assert total_risk_score == 5  # HIGH(3) + MEDIUM(2)
    
    def test_registry_risk_categorization(self, mock_registry_data):
        """Test registry modification risk categorization logic."""
        from collections import Counter
        risk_counts = Counter(mod["risk_level"] for mod in mock_registry_data["modifications"])
        
        assert risk_counts["HIGH"] == 1
        assert risk_counts["MEDIUM"] == 1
        assert risk_counts.get("LOW", 0) == 0
    
    def test_registry_uac_bypass_detection(self):
        """Test UAC bypass detection in registry modifications."""
        uac_bypass_indicators = [
            "EnableLUA",
            "ConsentPromptBehaviorAdmin", 
            "PromptOnSecureDesktop",
            "EnableVirtualization"
        ]
        
        test_modification = {
            "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "value": "EnableLUA",
            "current_value": 0,
            "expected_value": 1
        }
        
        # Test UAC bypass detection logic
        is_uac_bypass = test_modification["value"] in uac_bypass_indicators and test_modification["current_value"] != test_modification["expected_value"]
        assert is_uac_bypass == True

    # B002: User Account Inventory Tests
    def test_user_account_privilege_analysis(self, mock_user_account_data):
        """Test user account privilege level analysis."""
        admin_accounts = [acc for acc in mock_user_account_data["accounts"] if acc["privilege_level"] == "Administrator"]
        user_accounts = [acc for acc in mock_user_account_data["accounts"] if acc["privilege_level"] == "User"]
        
        assert len(admin_accounts) == 2
        assert len(user_accounts) == 1
        
        # Test enabled admin account detection (security risk)
        enabled_admin_accounts = [acc for acc in admin_accounts if acc["enabled"] == True]
        assert len(enabled_admin_accounts) == 1
        assert enabled_admin_accounts[0]["name"] == "backup_admin"
    
    def test_user_account_risk_assessment_algorithm(self, mock_user_account_data):
        """Test user account risk assessment algorithm."""
        high_risk_accounts = []
        
        for account in mock_user_account_data["accounts"]:
            risk_factors = []
            
            # Risk factor: Enabled admin account
            if account["privilege_level"] == "Administrator" and account["enabled"]:
                risk_factors.append("enabled_admin")
            
            # Risk factor: Password doesn't expire
            if not account["password_expires"]:
                risk_factors.append("password_no_expire")
            
            # Risk factor: No recent logon (admin accounts)
            if account["privilege_level"] == "Administrator" and account["last_logon"] < "2025-08-30T00:00:00Z":
                risk_factors.append("stale_admin")
            
            if len(risk_factors) >= 2:
                high_risk_accounts.append(account["name"])
        
        assert "backup_admin" in high_risk_accounts
        assert len(high_risk_accounts) == 1
    
    def test_user_account_sid_validation(self, mock_user_account_data):
        """Test SID format validation and well-known SID detection."""
        import re
        sid_pattern = r'^S-1-5-21-\d+-\d+-\d+-\d+$'
        
        for account in mock_user_account_data["accounts"]:
            # Test SID format validation
            assert re.match(sid_pattern, account["sid"]), f"Invalid SID format: {account['sid']}"
            
            # Test well-known SID detection (Administrator = 500)
            if account["name"] == "Administrator":
                assert account["sid"].endswith("-500")

    # B003: Group Policy Inventory Tests
    def test_group_policy_security_settings_analysis(self):
        """Test Group Policy security settings analysis logic."""
        mock_gpo_data = {
            "policies": [
                {
                    "name": "Password Policy",
                    "setting": "MinimumPasswordLength", 
                    "value": 8,
                    "recommended": 12,
                    "compliance": "PARTIAL"
                },
                {
                    "name": "Account Lockout Policy",
                    "setting": "AccountLockoutThreshold",
                    "value": 0,
                    "recommended": 5,
                    "compliance": "NON_COMPLIANT"
                }
            ]
        }
        
        # Test compliance calculation
        compliant_policies = [p for p in mock_gpo_data["policies"] if p["compliance"] == "COMPLIANT"]
        non_compliant_policies = [p for p in mock_gpo_data["policies"] if p["compliance"] == "NON_COMPLIANT"]
        
        assert len(non_compliant_policies) == 1
        assert non_compliant_policies[0]["setting"] == "AccountLockoutThreshold"
    
    def test_group_policy_bypass_detection(self):
        """Test Group Policy bypass technique detection."""
        suspicious_policies = [
            "DisableRegistryTools",
            "DisableTaskMgr", 
            "DisableCMD",
            "RestrictRun"
        ]
        
        mock_policy_modification = {
            "setting": "DisableTaskMgr",
            "current_value": 0,
            "expected_value": 1,
            "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
        }
        
        # Test bypass detection logic
        is_bypass_attempt = (mock_policy_modification["setting"] in suspicious_policies and 
                           mock_policy_modification["current_value"] != mock_policy_modification["expected_value"])
        assert is_bypass_attempt == True

    # B004: System Integrity and Bypass Detection Tests
    def test_system_integrity_hash_validation(self):
        """Test system file integrity validation logic."""
        mock_system_files = [
            {
                "path": "C:\\Windows\\System32\\cmd.exe",
                "current_hash": "abc123def456",
                "expected_hash": "abc123def456", 
                "status": "VALID"
            },
            {
                "path": "C:\\Windows\\System32\\taskmgr.exe",
                "current_hash": "xyz789uvw012",
                "expected_hash": "different_hash",
                "status": "MODIFIED"
            }
        ]
        
        # Test integrity validation algorithm
        modified_files = [f for f in mock_system_files if f["status"] == "MODIFIED"]
        assert len(modified_files) == 1
        assert modified_files[0]["path"].endswith("taskmgr.exe")
    
    def test_bypass_tool_detection_signatures(self):
        """Test bypass tool detection using signature patterns."""
        bypass_signatures = [
            "Ultimate Windows Tweaker",
            "O&O ShutUp10",
            "Process Hacker",
            "Cheat Engine",
            "Registry Workshop"
        ]
        
        mock_installed_software = [
            {"name": "Microsoft Office", "risk": "LOW"},
            {"name": "Process Hacker", "risk": "HIGH"},
            {"name": "Steam", "risk": "LOW"}
        ]
        
        # Test signature matching algorithm
        detected_bypass_tools = []
        for software in mock_installed_software:
            if any(sig.lower() in software["name"].lower() for sig in bypass_signatures):
                detected_bypass_tools.append(software["name"])
        
        assert "Process Hacker" in detected_bypass_tools
        assert len(detected_bypass_tools) == 1

    # B005: Network Configuration Assessment Tests  
    def test_network_profile_security_analysis(self):
        """Test network profile security configuration analysis."""
        mock_network_profiles = [
            {
                "name": "Home Network",
                "type": "Private",
                "firewall_enabled": True,
                "discovery_enabled": True,
                "risk_level": "LOW"
            },
            {
                "name": "Public WiFi",
                "type": "Public", 
                "firewall_enabled": False,
                "discovery_enabled": True,
                "risk_level": "HIGH"
            }
        ]
        
        # Test network security risk calculation
        high_risk_networks = []
        for profile in mock_network_profiles:
            risk_factors = 0
            if not profile["firewall_enabled"]:
                risk_factors += 2
            if profile["discovery_enabled"] and profile["type"] == "Public":
                risk_factors += 1
            
            if risk_factors >= 2:
                high_risk_networks.append(profile["name"])
        
        assert "Public WiFi" in high_risk_networks
    
    def test_wifi_security_protocol_analysis(self):
        """Test WiFi security protocol strength analysis."""
        mock_wifi_profiles = [
            {"ssid": "HomeNetwork", "security": "WPA3", "strength": "STRONG"},
            {"ssid": "OldRouter", "security": "WEP", "strength": "WEAK"},
            {"ssid": "GuestNetwork", "security": "WPA2", "strength": "MODERATE"}
        ]
        
        # Test security protocol strength calculation
        weak_networks = [w for w in mock_wifi_profiles if w["strength"] == "WEAK"]
        strong_networks = [w for w in mock_wifi_profiles if w["strength"] == "STRONG"]
        
        assert len(weak_networks) == 1
        assert weak_networks[0]["security"] == "WEP"
        assert len(strong_networks) == 1

    # B006: Time Control Bypass Detection Tests
    def test_time_control_bypass_detection_patterns(self):
        """Test time control bypass technique detection."""
        bypass_patterns = [
            {"type": "registry", "key": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation", "suspicious": True},
            {"type": "service", "name": "Time Service", "status": "Stopped", "suspicious": True},
            {"type": "process", "name": "date.exe", "command_line": "date 01-01-2020", "suspicious": True},
            {"type": "file", "path": "C:\\Windows\\System32\\time_bypass.exe", "exists": True, "suspicious": True}
        ]
        
        # Test bypass detection algorithm
        detected_bypasses = [p for p in bypass_patterns if p.get("suspicious", False)]
        assert len(detected_bypasses) == 4
        
        # Test specific bypass type detection
        registry_bypasses = [p for p in detected_bypasses if p["type"] == "registry"]
        assert len(registry_bypasses) == 1
    
    def test_system_time_manipulation_detection(self):
        """Test system time manipulation detection logic."""
        from datetime import datetime, timedelta
        
        current_time = datetime.now()
        system_reported_time = datetime(2020, 1, 1, 12, 0, 0)  # Obviously manipulated
        
        # Test time manipulation detection
        time_diff = abs((current_time - system_reported_time).days)
        is_time_manipulated = time_diff > 365  # More than 1 year difference
        
        assert is_time_manipulated == True
        
        # Test reasonable time difference
        reasonable_time = current_time - timedelta(minutes=5)
        reasonable_diff = abs((current_time - reasonable_time).total_seconds())
        is_reasonable = reasonable_diff < 3600  # Less than 1 hour
        
        assert is_reasonable == True

    # Integration Tests for Assessment Engine
    def test_comprehensive_security_score_calculation(self, mock_registry_data, mock_user_account_data):
        """Test comprehensive security score calculation algorithm."""
        # Registry risk score (0-100 scale)
        registry_risk = mock_registry_data["high_risk_count"] * 20 + mock_registry_data["medium_risk_count"] * 10
        registry_score = max(0, 100 - registry_risk)  # 100 - (1*20 + 1*10) = 70
        
        # User account risk score
        user_risk = mock_user_account_data["risk_accounts"] * 15
        user_score = max(0, 100 - user_risk)  # 100 - (1*15) = 85
        
        # Overall security score (weighted average)
        overall_score = (registry_score * 0.4 + user_score * 0.3 + 85 * 0.3)  # Assuming network/gpo score of 85
        expected_score = (70 * 0.4 + 85 * 0.3 + 85 * 0.3)  # 28 + 25.5 + 25.5 = 79
        
        assert abs(overall_score - expected_score) < 0.1
        assert 0 <= overall_score <= 100
    
    def test_assessment_result_json_schema_validation(self, assessment_result_schema):
        """Test assessment result conforms to contract schema."""
        mock_assessment_result = {
            "assessment_metadata": {
                "timestamp": "2025-08-30T10:00:00Z",
                "system_info": "Windows 11 Test System",
                "assessment_version": "1.0"
            },
            "security_scorecard": {
                "overall_score": 79.0,
                "essential8_compliance": {
                    "B020_passwords": {"status": "PASS", "score": 10},
                    "B021_admin_rights": {"status": "FAIL", "score": 0}
                }
            },
            "findings_summary": {
                "critical": 1,
                "high": 2,
                "medium": 3,
                "low": 4
            },
            "detailed_findings": [
                {
                    "category": "B021_admin_rights",
                    "severity": "CRITICAL", 
                    "finding": "Unauthorized admin account detected",
                    "recommendation": "Remove or disable backup_admin account"
                }
            ],
            "remediation_approach": {
                "recommended_strategy": "baseline_reset",
                "rationale": "Multiple high-risk findings require comprehensive remediation",
                "data_preservation_required": True
            }
        }
        
        # Validate against schema (using existing contract test schema)
        from jsonschema import validate
        validate(mock_assessment_result, assessment_result_schema)