# Admin Interface System Assessment Page Unit Tests
# Tests for Streamlit-based system assessment dashboard

import pytest
import streamlit as st
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import pandas as pd

class TestSystemAssessmentPage:
    """Unit tests for the system assessment page of the admin interface."""
    
    @pytest.fixture
    def mock_assessment_results(self):
        """Mock assessment results for testing."""
        return {
            "assessment_metadata": {
                "timestamp": "2025-08-30T10:00:00Z",
                "system_info": "TEST-SYSTEM - Windows 11 Pro",
                "assessment_version": "1.0",
                "duration_seconds": 45.2
            },
            "security_scorecard": {
                "overall_score": 78.5,
                "essential8_compliance": {
                    "B020_passwords": {"status": "PASS", "score": 10},
                    "B021_admin_rights": {"status": "FAIL", "score": 0},
                    "B022_os_updates": {"status": "PASS", "score": 8}
                },
                "component_scores": {
                    "registry_security": 85,
                    "user_account_security": 72,
                    "group_policy_compliance": 80,
                    "system_integrity": 75,
                    "network_security": 82,
                    "time_control_security": 77
                }
            },
            "findings_summary": {
                "critical": 1,
                "high": 3,
                "medium": 5,
                "low": 8,
                "total_findings": 17
            },
            "detailed_findings": [
                {
                    "category": "B001_registry_modification",
                    "severity": "HIGH",
                    "finding": "UAC bypass detected in registry",
                    "details": {
                        "registry_path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                        "property_name": "EnableLUA",
                        "current_value": 0,
                        "risk_description": "User Account Control completely disabled"
                    },
                    "remediation": "Re-enable UAC by setting EnableLUA to 1",
                    "impact": "System vulnerable to privilege escalation"
                },
                {
                    "category": "B002_user_account_security",
                    "severity": "CRITICAL",
                    "finding": "Guest account is enabled",
                    "details": {
                        "username": "Guest",
                        "account_enabled": True,
                        "risk_description": "Built-in Guest account provides anonymous access"
                    },
                    "remediation": "Disable the Guest account immediately",
                    "impact": "Unauthorized anonymous access to system"
                }
            ],
            "remediation_approach": {
                "recommended_strategy": "in_place_remediation",
                "rationale": "System shows manageable security gaps",
                "data_preservation_required": True,
                "estimated_effort_hours": 4,
                "risk_level": "MEDIUM"
            }
        }
    
    @pytest.fixture
    def mock_streamlit_elements(self):
        """Mock Streamlit UI elements for testing."""
        with patch('streamlit.title') as mock_title, \
             patch('streamlit.header') as mock_header, \
             patch('streamlit.subheader') as mock_subheader, \
             patch('streamlit.metric') as mock_metric, \
             patch('streamlit.progress') as mock_progress, \
             patch('streamlit.json') as mock_json, \
             patch('streamlit.dataframe') as mock_dataframe, \
             patch('streamlit.button') as mock_button, \
             patch('streamlit.selectbox') as mock_selectbox, \
             patch('streamlit.checkbox') as mock_checkbox:
            
            yield {
                'title': mock_title,
                'header': mock_header,
                'subheader': mock_subheader,
                'metric': mock_metric,
                'progress': mock_progress,
                'json': mock_json,
                'dataframe': mock_dataframe,
                'button': mock_button,
                'selectbox': mock_selectbox,
                'checkbox': mock_checkbox
            }

    def test_assessment_page_initialization(self, mock_streamlit_elements):
        """Test system assessment page loads correctly."""
        from src.admin_interface.pages.system_assessment import SystemAssessmentPage
        
        page = SystemAssessmentPage()
        
        # Test page initialization
        assert page is not None
        assert hasattr(page, 'render')
        assert hasattr(page, 'load_assessment_results')
        assert hasattr(page, 'display_security_scorecard')

    def test_security_scorecard_display(self, mock_assessment_results, mock_streamlit_elements):
        """Test security scorecard rendering with metrics."""
        from src.admin_interface.pages.system_assessment import SystemAssessmentPage
        
        page = SystemAssessmentPage()
        page.display_security_scorecard(mock_assessment_results['security_scorecard'])
        
        # Verify overall score metric is displayed
        mock_streamlit_elements['metric'].assert_called()
        metric_calls = mock_streamlit_elements['metric'].call_args_list
        
        # Check if overall score is displayed
        overall_score_call = next((call for call in metric_calls 
                                  if '78.5' in str(call) or 'Overall Security Score' in str(call)), None)
        assert overall_score_call is not None
        
        # Verify progress bar is shown for score
        mock_streamlit_elements['progress'].assert_called()

    def test_findings_table_display(self, mock_assessment_results, mock_streamlit_elements):
        """Test detailed findings table rendering."""
        from src.admin_interface.pages.system_assessment import SystemAssessmentPage
        
        page = SystemAssessmentPage()
        page.display_findings_table(mock_assessment_results['detailed_findings'])
        
        # Verify dataframe is displayed with findings
        mock_streamlit_elements['dataframe'].assert_called()
        
        # Get the dataframe call arguments
        dataframe_call = mock_streamlit_elements['dataframe'].call_args
        assert dataframe_call is not None

    def test_findings_severity_filtering(self, mock_assessment_results):
        """Test filtering findings by severity level."""
        from src.admin_interface.pages.system_assessment import SystemAssessmentPage
        
        page = SystemAssessmentPage()
        findings = mock_assessment_results['detailed_findings']
        
        # Test critical findings filter
        critical_findings = page.filter_findings_by_severity(findings, "CRITICAL")
        assert len(critical_findings) == 1
        assert critical_findings[0]['severity'] == "CRITICAL"
        
        # Test high findings filter  
        high_findings = page.filter_findings_by_severity(findings, "HIGH")
        assert len(high_findings) == 1
        assert high_findings[0]['severity'] == "HIGH"
        
        # Test all findings (no filter)
        all_findings = page.filter_findings_by_severity(findings, "ALL")
        assert len(all_findings) == 2

    def test_component_scores_visualization(self, mock_assessment_results, mock_streamlit_elements):
        """Test component scores chart visualization."""
        from src.admin_interface.pages.system_assessment import SystemAssessmentPage
        
        page = SystemAssessmentPage()
        component_scores = mock_assessment_results['security_scorecard']['component_scores']
        
        chart_data = page.prepare_component_scores_chart(component_scores)
        
        # Verify chart data structure
        assert 'component' in chart_data.columns
        assert 'score' in chart_data.columns
        assert len(chart_data) == 6  # 6 components (B001-B006)
        
        # Verify score values are correct
        registry_score = chart_data[chart_data['component'] == 'Registry Security']['score'].iloc[0]
        assert registry_score == 85

    def test_essential8_compliance_display(self, mock_assessment_results, mock_streamlit_elements):
        """Test Essential 8 compliance status display."""
        from src.admin_interface.pages.system_assessment import SystemAssessmentPage
        
        page = SystemAssessmentPage()
        essential8_data = mock_assessment_results['security_scorecard']['essential8_compliance']
        
        page.display_essential8_compliance(essential8_data)
        
        # Verify metrics are displayed for Essential 8 controls
        mock_streamlit_elements['metric'].assert_called()
        
        # Check that pass/fail status is shown
        metric_calls = mock_streamlit_elements['metric'].call_args_list
        assert any('PASS' in str(call) or 'FAIL' in str(call) for call in metric_calls)

    def test_remediation_recommendations_display(self, mock_assessment_results, mock_streamlit_elements):
        """Test remediation recommendations section."""
        from src.admin_interface.pages.system_assessment import SystemAssessmentPage
        
        page = SystemAssessmentPage()
        remediation_data = mock_assessment_results['remediation_approach']
        
        page.display_remediation_recommendations(remediation_data)
        
        # Verify remediation strategy is shown
        mock_streamlit_elements['subheader'].assert_called()
        
        # Check that effort estimation is displayed
        subheader_calls = mock_streamlit_elements['subheader'].call_args_list
        assert any('remediation' in str(call).lower() for call in subheader_calls)

    def test_assessment_refresh_functionality(self, mock_streamlit_elements):
        """Test assessment refresh button and functionality."""
        from src.admin_interface.pages.system_assessment import SystemAssessmentPage
        
        page = SystemAssessmentPage()
        
        # Mock button click
        mock_streamlit_elements['button'].return_value = True
        
        refresh_triggered = page.handle_refresh_button()
        
        # Verify refresh button is rendered
        mock_streamlit_elements['button'].assert_called()
        
        # Check refresh functionality
        assert refresh_triggered == True

    def test_assessment_export_functionality(self, mock_assessment_results):
        """Test assessment results export to different formats."""
        from src.admin_interface.pages.system_assessment import SystemAssessmentPage
        
        page = SystemAssessmentPage()
        
        # Test JSON export
        json_export = page.export_assessment_results(mock_assessment_results, format="JSON")
        assert json_export is not None
        assert isinstance(json_export, str)
        
        # Verify JSON is valid
        parsed_json = json.loads(json_export)
        assert 'assessment_metadata' in parsed_json
        assert 'security_scorecard' in parsed_json
        
        # Test CSV export
        csv_export = page.export_assessment_results(mock_assessment_results, format="CSV")
        assert csv_export is not None
        assert isinstance(csv_export, str)

    def test_real_time_status_updates(self, mock_streamlit_elements):
        """Test real-time status updates during assessment."""
        from src.admin_interface.pages.system_assessment import SystemAssessmentPage
        
        page = SystemAssessmentPage()
        
        # Test progress tracking
        progress_data = {
            "current_step": "B003_group_policy_compliance",
            "completed_steps": 3,
            "total_steps": 6,
            "progress_percentage": 50.0,
            "current_status": "Analyzing Group Policy settings..."
        }
        
        page.display_assessment_progress(progress_data)
        
        # Verify progress bar and status are shown
        mock_streamlit_elements['progress'].assert_called()
        progress_call = mock_streamlit_elements['progress'].call_args
        assert 0.5 in progress_call[0]  # 50% progress

    def test_error_handling_display(self, mock_streamlit_elements):
        """Test error handling and display in assessment page."""
        from src.admin_interface.pages.system_assessment import SystemAssessmentPage
        
        page = SystemAssessmentPage()
        
        # Test error state handling
        error_data = {
            "error_type": "POWERSHELL_EXECUTION_ERROR",
            "error_message": "PowerShell script failed to execute",
            "error_details": "Access denied when accessing registry keys",
            "recovery_suggestions": ["Run as Administrator", "Check PowerShell execution policy"]
        }
        
        page.display_error_state(error_data)
        
        # Verify error information is displayed
        mock_streamlit_elements['subheader'].assert_called()
        
        # Check that recovery suggestions are shown
        subheader_calls = mock_streamlit_elements['subheader'].call_args_list
        assert any('error' in str(call).lower() for call in subheader_calls)

    def test_assessment_comparison_functionality(self, mock_assessment_results):
        """Test comparison between multiple assessment results."""
        from src.admin_interface.pages.system_assessment import SystemAssessmentPage
        
        page = SystemAssessmentPage()
        
        # Create a second assessment result for comparison
        comparison_results = mock_assessment_results.copy()
        comparison_results['security_scorecard']['overall_score'] = 85.2
        comparison_results['assessment_metadata']['timestamp'] = "2025-08-30T11:00:00Z"
        
        comparison_data = page.compare_assessment_results(
            mock_assessment_results, 
            comparison_results
        )
        
        # Verify comparison data structure
        assert 'score_improvement' in comparison_data
        assert 'findings_change' in comparison_data
        assert comparison_data['score_improvement'] == 6.7  # 85.2 - 78.5

    def test_assessment_data_validation(self, mock_assessment_results):
        """Test validation of assessment result data structure."""
        from src.admin_interface.pages.system_assessment import SystemAssessmentPage
        
        page = SystemAssessmentPage()
        
        # Test valid data validation
        is_valid = page.validate_assessment_data(mock_assessment_results)
        assert is_valid == True
        
        # Test invalid data validation (missing required fields)
        invalid_data = {"assessment_metadata": {}}
        is_valid = page.validate_assessment_data(invalid_data)
        assert is_valid == False

    def test_responsive_layout_adaptation(self, mock_streamlit_elements):
        """Test responsive layout for different screen sizes."""
        from src.admin_interface.pages.system_assessment import SystemAssessmentPage
        
        page = SystemAssessmentPage()
        
        # Test layout configuration
        layout_config = page.get_responsive_layout_config()
        
        assert 'columns' in layout_config
        assert 'sidebar_width' in layout_config
        assert isinstance(layout_config['columns'], list)

    # Helper methods for testing (these would be implemented in the actual class)
    def _create_mock_page_instance(self):
        """Helper to create a mock page instance for testing."""
        # This method would be used internally by test methods
        pass