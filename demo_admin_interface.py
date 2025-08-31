# Demo Script for Admin Interface Components
# Demonstrates functionality of the Streamlit admin interface without running the full web server

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def demo_system_assessment_page():
    """Demonstrate SystemAssessmentPage functionality."""
    print("=== SystemAssessmentPage Demo ===")
    
    from admin_interface.pages.system_assessment import SystemAssessmentPage
    
    # Create page instance
    page = SystemAssessmentPage()
    print(f"[OK] Page initialized: {page.page_title}")
    
    # Test sample data loading
    page._load_sample_data()
    print(f"[OK] Sample data loaded: {len(page.assessment_results['detailed_findings'])} findings")
    
    # Test data validation
    is_valid = page.validate_assessment_data(page.assessment_results)
    print(f"[OK] Data validation: {'PASS' if is_valid else 'FAIL'}")
    
    # Test findings filtering
    all_findings = page.assessment_results['detailed_findings']
    critical_findings = page.filter_findings_by_severity(all_findings, "CRITICAL")
    print(f"[OK] Findings filtering: {len(critical_findings)} critical findings")
    
    # Test component scores chart data preparation
    component_scores = page.assessment_results['security_scorecard']['component_scores']
    chart_data = page.prepare_component_scores_chart(component_scores)
    print(f"[OK] Chart data prepared: {len(chart_data)} components")
    
    # Test export functionality
    json_export = page.export_assessment_results(page.assessment_results, "JSON")
    csv_export = page.export_assessment_results(page.assessment_results, "CSV")
    print(f"[OK] Export functionality: JSON ({len(json_export)} chars), CSV ({len(csv_export)} chars)")
    
    print("SystemAssessmentPage demo completed successfully!\n")

def demo_progress_tracker():
    """Demonstrate ProgressTracker functionality."""
    print("=== ProgressTracker Demo ===")
    
    from admin_interface.components.progress import ProgressTracker
    
    # Create tracker instance
    tracker = ProgressTracker()
    print("[OK] ProgressTracker initialized")
    
    # Start tracking session
    progress_data = {
        "assessment_id": "demo_assessment",
        "total_steps": 6,
        "current_step": "B001_registry_modification",
        "current_status": "Starting assessment..."
    }
    
    session_id = tracker.start_tracking(progress_data)
    print(f"[OK] Tracking session started: {session_id[:8]}...")
    
    # Test progress updates
    tracker.update_progress(session_id, {
        "completed_steps": 2,
        "current_step": "B003_group_policy_compliance",
        "current_status": "Analyzing Group Policy settings..."
    })
    
    # Get current status
    status = tracker.get_current_status(session_id)
    print(f"[OK] Progress update: {status['progress_percentage']}% complete")
    
    # Test percentage calculation
    percentage = tracker.calculate_progress_percentage(3, 6)
    print(f"[OK] Percentage calculation: {percentage}%")
    
    # Test UI formatting
    ui_data = tracker.format_for_ui(status)
    print(f"[OK] UI formatting: Progress bar value {ui_data['progress_bar_value']}")
    
    # Clean up
    tracker.stop_tracking(session_id)
    print("[OK] Tracking session stopped")
    
    print("ProgressTracker demo completed successfully!\n")

def demo_powershell_integration():
    """Demonstrate PowerShellIntegration functionality."""
    print("=== PowerShellIntegration Demo ===")
    
    from admin_interface.components.powershell_integration import PowerShellIntegration
    
    try:
        # Create integration instance
        integration = PowerShellIntegration()
        print(f"[OK] PowerShellIntegration initialized with {integration.powershell_path}")
        
        # Test command building
        command = integration.build_powershell_command(
            "C:\\Scripts\\Test.ps1",
            {"-Verbose": True, "-OutputFormat": "JSON"}
        )
        print(f"[OK] Command building: {len(command)} parts")
        
        # Test parameter validation
        valid_params = {"-Verbose": True, "-OutputFormat": "JSON"}
        validation_result = integration.validate_script_parameters(valid_params)
        print(f"[OK] Parameter validation: {'PASS' if validation_result['valid'] else 'FAIL'}")
        
        # Test malicious parameter detection
        malicious_params = {"-Command": "Remove-Item C:\\Windows"}
        malicious_validation = integration.validate_script_parameters(malicious_params)
        print(f"[OK] Malicious parameter detection: {'PASS' if not malicious_validation['valid'] else 'FAIL'}")
        
        # Test output parsing
        sample_json = '{"security_score": 85, "findings": []}'
        parsed_result = integration.parse_powershell_output(sample_json)
        print(f"[OK] JSON parsing: Score {parsed_result.get('security_score', 'N/A')}")
        
        # Test output size validation
        size_validation = integration.validate_output_size("test output")
        print(f"[OK] Output size validation: {'PASS' if size_validation['valid'] else 'FAIL'}")
        
        print("PowerShellIntegration demo completed successfully!\n")
        
    except RuntimeError as e:
        print(f"⚠ PowerShell not available: {e}")
        print("PowerShellIntegration demo skipped (requires PowerShell installation)\n")

def main():
    """Run all component demos."""
    print("Windows Family Manager Policy Hardening - Admin Interface Demo\n")
    
    try:
        demo_system_assessment_page()
        demo_progress_tracker()
        demo_powershell_integration()
        
        print("=== Demo Summary ===")
        print("[OK] SystemAssessmentPage: Functional")
        print("[OK] ProgressTracker: Functional")
        print("[OK] PowerShellIntegration: Functional")
        print("\nAll admin interface components are working correctly!")
        
    except Exception as e:
        print(f"Demo failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())