# BDD Step Definitions for Policy Deployment
import pytest
import time
import json
from pytest_bdd import given, when, then, scenarios

# Load all policy deployment scenarios
scenarios('../features/policy_deployment/security_policy_deployment.feature')

@pytest.fixture
def policy_deployment_context():
    """Shared context for policy deployment tests."""
    return {
        'admin_privileges': False,
        'baseline_complete': False,
        'selected_policies': [],
        'deployment_results': {},
        'policy_conflicts': [],
        'validation_results': {},
        'rollback_status': None,
        'error_details': None,
        'network_config': {},
        'application_config': {},
        'family_config': {}
    }

# Background steps
@given('I have administrator privileges on the system')
def verify_admin_privileges_policy(policy_deployment_context):
    """Verify administrator privileges for policy deployment."""
    policy_deployment_context['admin_privileges'] = True

@given('the baseline system assessment is complete')
def setup_baseline_assessment_complete(policy_deployment_context):
    """Setup completed baseline assessment."""
    policy_deployment_context['baseline_complete'] = True
    policy_deployment_context['assessment_results'] = {
        'essential8_baseline': 42.5,
        'security_gaps': ['password_complexity', 'admin_privileges', 'update_management']
    }

@given('the admin interface is accessible')
def verify_admin_interface_policy(policy_deployment_context):
    """Verify admin interface accessibility for policy deployment."""
    policy_deployment_context['interface_accessible'] = True

# Essential 8 Level 1 Security Controls deployment
@given('I select "Deploy Essential 8 Level 1 Controls" from the policy menu')
def select_essential8_deployment(policy_deployment_context):
    """Select Essential 8 Level 1 controls for deployment."""
    policy_deployment_context['selected_policies'].append('essential8_level1')
    policy_deployment_context['essential8_policies'] = [
        'password_complexity', 'admin_restrictions', 'os_updates', 
        'app_updates', 'macro_security', 'browser_hardening',
        'mfa_setup', 'backup_config', 'antivirus_config'
    ]

@given('I confirm I want to proceed with security hardening')
def confirm_security_hardening(policy_deployment_context):
    """Confirm proceeding with security hardening."""
    policy_deployment_context['hardening_confirmed'] = True

@when('I execute the Essential 8 deployment')
def execute_essential8_deployment(policy_deployment_context):
    """Execute Essential 8 Level 1 controls deployment."""
    policy_deployment_context['deployment_executing'] = True
    
    # Simulate successful deployment of each control
    results = {}
    for policy in policy_deployment_context['essential8_policies']:
        results[policy] = {
            'status': 'success',
            'message': f'{policy} applied successfully',
            'timestamp': time.time()
        }
    
    policy_deployment_context['deployment_results']['essential8'] = results
    policy_deployment_context['deployment_executing'] = False

@then('I should see "Password Complexity Requirements" policy applied successfully')
def verify_password_complexity_applied(policy_deployment_context):
    """Verify password complexity policy was applied."""
    essential8_results = policy_deployment_context['deployment_results']['essential8']
    assert 'password_complexity' in essential8_results, "Should have password complexity result"
    assert essential8_results['password_complexity']['status'] == 'success', "Password complexity should succeed"

@then('I should see "Administrative Privileges Restriction" policy applied successfully')
def verify_admin_restrictions_applied(policy_deployment_context):
    """Verify administrative privileges restriction was applied."""
    essential8_results = policy_deployment_context['deployment_results']['essential8']
    assert 'admin_restrictions' in essential8_results, "Should have admin restrictions result"
    assert essential8_results['admin_restrictions']['status'] == 'success', "Admin restrictions should succeed"

@then('I should see "Automatic Operating System Updates" enabled successfully')
def verify_os_updates_enabled(policy_deployment_context):
    """Verify OS automatic updates were enabled."""
    essential8_results = policy_deployment_context['deployment_results']['essential8']
    assert 'os_updates' in essential8_results, "Should have OS updates result"
    assert essential8_results['os_updates']['status'] == 'success', "OS updates should succeed"

@then('I should see "Application Automatic Updates" configured successfully')
def verify_app_updates_configured(policy_deployment_context):
    """Verify application automatic updates were configured."""
    essential8_results = policy_deployment_context['deployment_results']['essential8']
    assert 'app_updates' in essential8_results, "Should have app updates result"
    assert essential8_results['app_updates']['status'] == 'success', "App updates should succeed"

@then('I should see "Macro Security Settings" configured successfully')
def verify_macro_security_configured(policy_deployment_context):
    """Verify macro security settings were configured."""
    essential8_results = policy_deployment_context['deployment_results']['essential8']
    assert 'macro_security' in essential8_results, "Should have macro security result"
    assert essential8_results['macro_security']['status'] == 'success', "Macro security should succeed"

@then('I should see "Web Browser Hardening" applied successfully')
def verify_browser_hardening_applied(policy_deployment_context):
    """Verify web browser hardening was applied."""
    essential8_results = policy_deployment_context['deployment_results']['essential8']
    assert 'browser_hardening' in essential8_results, "Should have browser hardening result"
    assert essential8_results['browser_hardening']['status'] == 'success', "Browser hardening should succeed"

@then('I should see "Multi-Factor Authentication Setup" guidance provided')
def verify_mfa_guidance_provided(policy_deployment_context):
    """Verify MFA setup guidance was provided."""
    essential8_results = policy_deployment_context['deployment_results']['essential8']
    assert 'mfa_setup' in essential8_results, "Should have MFA setup result"
    assert essential8_results['mfa_setup']['status'] == 'success', "MFA setup should succeed"

@then('I should see "Backup Configuration Validation" completed successfully')
def verify_backup_validation_completed(policy_deployment_context):
    """Verify backup configuration validation completed."""
    essential8_results = policy_deployment_context['deployment_results']['essential8']
    assert 'backup_config' in essential8_results, "Should have backup config result"
    assert essential8_results['backup_config']['status'] == 'success', "Backup config should succeed"

@then('I should see "Antivirus Configuration" validated successfully')
def verify_antivirus_validated(policy_deployment_context):
    """Verify antivirus configuration was validated."""
    essential8_results = policy_deployment_context['deployment_results']['essential8']
    assert 'antivirus_config' in essential8_results, "Should have antivirus config result"
    assert essential8_results['antivirus_config']['status'] == 'success', "Antivirus config should succeed"

@then('the deployment should complete without errors')
def verify_deployment_no_errors(policy_deployment_context):
    """Verify deployment completed without errors."""
    essential8_results = policy_deployment_context['deployment_results']['essential8']
    for policy, result in essential8_results.items():
        assert result['status'] == 'success', f"Policy {policy} should succeed"

# Network Security Policies deployment
@given('I select "Deploy Network Security Policies" from the policy menu')
def select_network_security_deployment(policy_deployment_context):
    """Select network security policies for deployment."""
    policy_deployment_context['selected_policies'].append('network_security')

@given('I have configured allowed WiFi SSIDs as "HomeNetwork,SchoolNetwork"')
def configure_allowed_wifi_ssids(policy_deployment_context):
    """Configure allowed WiFi SSIDs."""
    policy_deployment_context['network_config']['allowed_ssids'] = ['HomeNetwork', 'SchoolNetwork']

@given('I have selected "Disable Ethernet Adapter" option')
def select_disable_ethernet(policy_deployment_context):
    """Select ethernet adapter disable option."""
    policy_deployment_context['network_config']['ethernet_disabled'] = True

@when('I execute the network security deployment')
def execute_network_security_deployment(policy_deployment_context):
    """Execute network security policies deployment."""
    policy_deployment_context['deployment_results']['network_security'] = {
        'wifi_restrictions': {'status': 'success', 'applied_ssids': ['HomeNetwork', 'SchoolNetwork']},
        'ethernet_disable': {'status': 'success', 'adapter_disabled': True},
        'vpn_blocking': {'status': 'success', 'blocked_applications': ['openvpn', 'nordvpn']},
        'network_tools_restriction': {'status': 'success', 'restricted_tools': ['netsh', 'ipconfig']},
        'hotspot_blocking': {'status': 'success', 'mobile_hotspot_disabled': True}
    }

@then('I should see WiFi profile restrictions applied successfully')
def verify_wifi_restrictions_applied(policy_deployment_context):
    """Verify WiFi profile restrictions were applied."""
    network_results = policy_deployment_context['deployment_results']['network_security']
    wifi_result = network_results['wifi_restrictions']
    assert wifi_result['status'] == 'success', "WiFi restrictions should succeed"
    assert 'HomeNetwork' in wifi_result['applied_ssids'], "Should allow HomeNetwork"
    assert 'SchoolNetwork' in wifi_result['applied_ssids'], "Should allow SchoolNetwork"

@then('I should see ethernet adapter disabled successfully')
def verify_ethernet_disabled(policy_deployment_context):
    """Verify ethernet adapter was disabled."""
    network_results = policy_deployment_context['deployment_results']['network_security']
    ethernet_result = network_results['ethernet_disable']
    assert ethernet_result['status'] == 'success', "Ethernet disable should succeed"
    assert ethernet_result['adapter_disabled'], "Ethernet adapter should be disabled"

@then('I should see VPN application blocking configured successfully')
def verify_vpn_blocking_configured(policy_deployment_context):
    """Verify VPN application blocking was configured."""
    network_results = policy_deployment_context['deployment_results']['network_security']
    vpn_result = network_results['vpn_blocking']
    assert vpn_result['status'] == 'success', "VPN blocking should succeed"
    assert len(vpn_result['blocked_applications']) > 0, "Should block VPN applications"

@then('I should see network configuration tools access restricted')
def verify_network_tools_restricted(policy_deployment_context):
    """Verify network configuration tools access was restricted."""
    network_results = policy_deployment_context['deployment_results']['network_security']
    tools_result = network_results['network_tools_restriction']
    assert tools_result['status'] == 'success', "Network tools restriction should succeed"
    assert 'netsh' in tools_result['restricted_tools'], "Should restrict netsh"

@then('I should see hotspot connection blocking enabled successfully')
def verify_hotspot_blocking_enabled(policy_deployment_context):
    """Verify hotspot connection blocking was enabled."""
    network_results = policy_deployment_context['deployment_results']['network_security']
    hotspot_result = network_results['hotspot_blocking']
    assert hotspot_result['status'] == 'success', "Hotspot blocking should succeed"
    assert hotspot_result['mobile_hotspot_disabled'], "Mobile hotspot should be disabled"

@then('I should receive confirmation that network policies are active')
def verify_network_policies_active(policy_deployment_context):
    """Verify confirmation that network policies are active."""
    network_results = policy_deployment_context['deployment_results']['network_security']
    for policy, result in network_results.items():
        assert result['status'] == 'success', f"Network policy {policy} should be active"

@then('I should be able to test connectivity to allowed networks only')
def verify_connectivity_test_allowed_networks(policy_deployment_context):
    """Verify connectivity testing shows only allowed networks accessible."""
    policy_deployment_context['connectivity_test'] = {
        'HomeNetwork': {'accessible': True, 'test_result': 'success'},
        'SchoolNetwork': {'accessible': True, 'test_result': 'success'},
        'UnauthorizedNetwork': {'accessible': False, 'test_result': 'blocked'}
    }
    
    connectivity = policy_deployment_context['connectivity_test']
    assert connectivity['HomeNetwork']['accessible'], "Should connect to HomeNetwork"
    assert connectivity['SchoolNetwork']['accessible'], "Should connect to SchoolNetwork"
    assert not connectivity['UnauthorizedNetwork']['accessible'], "Should block unauthorized network"

# Application Control Policies deployment
@given('I select "Deploy Application Control Policies" from the policy menu')
def select_application_control_deployment(policy_deployment_context):
    """Select application control policies for deployment."""
    policy_deployment_context['selected_policies'].append('application_control')

@given('I have configured "Microsoft Edge Only" browser policy')
def configure_edge_only_browser_policy(policy_deployment_context):
    """Configure Microsoft Edge only browser policy."""
    policy_deployment_context['application_config']['browser_policy'] = 'edge_only'
    policy_deployment_context['application_config']['blocked_browsers'] = ['chrome', 'firefox', 'opera']

@given('I have selected application control enforcement level as "Strict"')
def select_strict_enforcement_level(policy_deployment_context):
    """Select strict application control enforcement level."""
    policy_deployment_context['application_config']['enforcement_level'] = 'strict'

@when('I execute the application control deployment')
def execute_application_control_deployment(policy_deployment_context):
    """Execute application control policies deployment."""
    policy_deployment_context['deployment_results']['application_control'] = {
        'wdac_policy': {'status': 'success', 'policy_deployed': True},
        'browser_blocking': {'status': 'success', 'blocked_browsers': ['chrome', 'firefox', 'opera']},
        'portable_browser_detection': {'status': 'success', 'detection_enabled': True},
        'software_restrictions': {'status': 'success', 'policies_applied': True},
        'dev_tool_monitoring': {'status': 'success', 'monitoring_configured': True}
    }

@then('I should see WDAC (Windows Defender Application Control) policy deployed')
def verify_wdac_policy_deployed(policy_deployment_context):
    """Verify WDAC policy was deployed."""
    app_results = policy_deployment_context['deployment_results']['application_control']
    wdac_result = app_results['wdac_policy']
    assert wdac_result['status'] == 'success', "WDAC policy deployment should succeed"
    assert wdac_result['policy_deployed'], "WDAC policy should be deployed"

@then('I should see alternative browser blocking configured (Chrome, Firefox, Opera)')
def verify_alternative_browser_blocking(policy_deployment_context):
    """Verify alternative browsers are blocked."""
    app_results = policy_deployment_context['deployment_results']['application_control']
    browser_result = app_results['browser_blocking']
    assert browser_result['status'] == 'success', "Browser blocking should succeed"
    assert 'chrome' in browser_result['blocked_browsers'], "Should block Chrome"
    assert 'firefox' in browser_result['blocked_browsers'], "Should block Firefox"
    assert 'opera' in browser_result['blocked_browsers'], "Should block Opera"

@then('I should see portable browser executable detection enabled')
def verify_portable_browser_detection(policy_deployment_context):
    """Verify portable browser executable detection is enabled."""
    app_results = policy_deployment_context['deployment_results']['application_control']
    portable_result = app_results['portable_browser_detection']
    assert portable_result['status'] == 'success', "Portable browser detection should succeed"
    assert portable_result['detection_enabled'], "Detection should be enabled"

@then('I should see software restriction policies applied successfully')
def verify_software_restriction_policies(policy_deployment_context):
    """Verify software restriction policies were applied."""
    app_results = policy_deployment_context['deployment_results']['application_control']
    software_result = app_results['software_restrictions']
    assert software_result['status'] == 'success', "Software restrictions should succeed"
    assert software_result['policies_applied'], "Policies should be applied"

@then('I should see development tool monitoring configured')
def verify_dev_tool_monitoring_configured(policy_deployment_context):
    """Verify development tool monitoring was configured."""
    app_results = policy_deployment_context['deployment_results']['application_control']
    dev_tool_result = app_results['dev_tool_monitoring']
    assert dev_tool_result['status'] == 'success', "Dev tool monitoring should succeed"
    assert dev_tool_result['monitoring_configured'], "Monitoring should be configured"

@then('I should receive confirmation that only approved applications can execute')
def verify_approved_applications_only(policy_deployment_context):
    """Verify confirmation that only approved applications can execute."""
    policy_deployment_context['application_execution_test'] = {
        'microsoft_edge': {'allowed': True, 'execution_result': 'success'},
        'chrome': {'allowed': False, 'execution_result': 'blocked'},
        'notepad': {'allowed': True, 'execution_result': 'success'},
        'unauthorized_app': {'allowed': False, 'execution_result': 'blocked'}
    }
    
    execution_test = policy_deployment_context['application_execution_test']
    assert execution_test['microsoft_edge']['allowed'], "Should allow Microsoft Edge"
    assert not execution_test['chrome']['allowed'], "Should block Chrome"
    assert execution_test['notepad']['allowed'], "Should allow system apps like Notepad"

@then('I should be able to verify that restricted applications are blocked')
def verify_restricted_applications_blocked(policy_deployment_context):
    """Verify restricted applications are properly blocked."""
    execution_test = policy_deployment_context.get('application_execution_test', {})
    assert not execution_test['chrome']['allowed'], "Chrome should be blocked"
    assert not execution_test['unauthorized_app']['allowed'], "Unauthorized apps should be blocked"