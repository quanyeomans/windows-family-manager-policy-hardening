# System Assessment Engine - Minimal implementation for TDD
# This will be fully implemented following the unit test specifications

def analyze_registry_modifications(registry_data):
    """Analyze registry modifications for security risks."""
    # Minimal implementation to make tests pass
    return {
        "high_risk_count": len([mod for mod in registry_data.get("modifications", []) if mod.get("risk_level") == "HIGH"]),
        "total_risk_score": sum(3 if mod.get("risk_level") == "HIGH" else 2 if mod.get("risk_level") == "MEDIUM" else 1 
                               for mod in registry_data.get("modifications", []))
    }

def assess_user_accounts(user_data):
    """Assess user account security risks."""
    # Minimal implementation to make tests pass
    admin_accounts = [acc for acc in user_data.get("accounts", []) if acc.get("privilege_level") == "Administrator"]
    return {
        "admin_count": len(admin_accounts),
        "risk_accounts": [acc["name"] for acc in admin_accounts if not acc.get("password_expires", True) and acc.get("enabled", False)]
    }

def validate_system_integrity(system_files):
    """Validate system file integrity."""
    # Minimal implementation to make tests pass
    modified_files = [f for f in system_files if f.get("status") == "MODIFIED"]
    return {
        "modified_count": len(modified_files),
        "integrity_score": max(0, 100 - len(modified_files) * 5)
    }

def detect_bypass_tools(software_list):
    """Detect bypass tools in installed software."""
    # Minimal implementation to make tests pass
    bypass_signatures = [
        "Ultimate Windows Tweaker", "O&O ShutUp10", "Process Hacker", 
        "Cheat Engine", "Registry Workshop"
    ]
    
    detected = []
    for software in software_list:
        if any(sig.lower() in software.get("name", "").lower() for sig in bypass_signatures):
            detected.append(software["name"])
    
    return detected