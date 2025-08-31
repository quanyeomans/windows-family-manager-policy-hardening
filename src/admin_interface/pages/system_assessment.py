# System Assessment Page for Admin Interface
# Streamlit-based dashboard for displaying security assessment results

import streamlit as st
import pandas as pd
import json
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import io
import csv

class SystemAssessmentPage:
    """Streamlit page for system security assessment dashboard."""
    
    def __init__(self):
        """Initialize the system assessment page."""
        self.page_title = "System Security Assessment"
        self.assessment_results = None
        
    def render(self):
        """Render the complete system assessment page."""
        st.title(self.page_title)
        
        # Page layout configuration
        layout_config = self.get_responsive_layout_config()
        
        # Assessment controls section
        self._render_assessment_controls()
        
        # Load and display assessment results
        if self.assessment_results:
            self._render_assessment_dashboard()
        else:
            self._render_empty_state()
    
    def _render_assessment_controls(self):
        """Render assessment control buttons and options."""
        col1, col2, col3 = st.columns([2, 2, 2])
        
        with col1:
            if st.button("🔍 Run Assessment", type="primary"):
                self._start_assessment()
        
        with col2:
            if st.button("🔄 Refresh Results"):
                if self.handle_refresh_button():
                    st.rerun()
        
        with col3:
            if st.button("📊 Load Sample Data"):
                self._load_sample_data()
                st.rerun()
    
    def _render_assessment_dashboard(self):
        """Render the complete assessment dashboard."""
        if not self.assessment_results:
            return
        
        # Validate data structure
        if not self.validate_assessment_data(self.assessment_results):
            st.error("Invalid assessment data structure detected.")
            return
        
        # Assessment metadata section
        self._render_assessment_metadata()
        
        # Security scorecard section
        self.display_security_scorecard(self.assessment_results['security_scorecard'])
        
        # Findings summary
        self._render_findings_summary()
        
        # Detailed findings table
        self.display_findings_table(self.assessment_results['detailed_findings'])
        
        # Component scores visualization
        self._render_component_scores_chart()
        
        # Essential 8 compliance
        if 'essential8_compliance' in self.assessment_results['security_scorecard']:
            self.display_essential8_compliance(
                self.assessment_results['security_scorecard']['essential8_compliance']
            )
        
        # Remediation recommendations
        self.display_remediation_recommendations(self.assessment_results['remediation_approach'])
        
        # Export options
        self._render_export_options()
    
    def _render_assessment_metadata(self):
        """Render assessment metadata information."""
        metadata = self.assessment_results['assessment_metadata']
        
        st.subheader("Assessment Information")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric(
                label="Assessment Time", 
                value=self._format_timestamp(metadata['timestamp'])
            )
        
        with col2:
            st.metric(
                label="Duration", 
                value=f"{metadata['duration_seconds']}s"
            )
        
        with col3:
            st.metric(
                label="System", 
                value=metadata['system_info']
            )
    
    def display_security_scorecard(self, scorecard_data: Dict[str, Any]):
        """Display the security scorecard with overall score and metrics."""
        st.header("🛡️ Security Scorecard")
        
        overall_score = scorecard_data['overall_score']
        
        # Overall score display
        col1, col2 = st.columns([1, 2])
        
        with col1:
            # Score metric with color coding
            score_color = self._get_score_color(overall_score)
            st.metric(
                label="Overall Security Score",
                value=f"{overall_score}/100",
                help="Comprehensive security assessment score based on all components"
            )
        
        with col2:
            # Progress bar for visual representation
            st.progress(overall_score / 100.0)
            score_grade = self._get_score_grade(overall_score)
            st.write(f"**Grade:** {score_grade}")
    
    def display_findings_table(self, findings: List[Dict[str, Any]]):
        """Display detailed findings in a filterable table."""
        if not findings:
            st.info("No security findings detected.")
            return
        
        st.header("🔍 Detailed Findings")
        
        # Severity filter
        col1, col2 = st.columns([1, 3])
        
        with col1:
            severity_filter = st.selectbox(
                "Filter by Severity",
                ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                help="Filter findings by severity level"
            )
        
        # Filter findings based on selection
        filtered_findings = self.filter_findings_by_severity(findings, severity_filter)
        
        if not filtered_findings:
            st.info(f"No {severity_filter.lower()} severity findings found.")
            return
        
        # Convert findings to DataFrame for display
        findings_df = self._prepare_findings_dataframe(filtered_findings)
        
        # Display findings table
        st.dataframe(
            findings_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "severity": st.column_config.TextColumn(
                    "Severity",
                    width="small"
                ),
                "finding": st.column_config.TextColumn(
                    "Finding",
                    width="large"
                ),
                "category": st.column_config.TextColumn(
                    "Category",
                    width="medium"
                ),
                "remediation": st.column_config.TextColumn(
                    "Remediation",
                    width="large"
                )
            }
        )
    
    def filter_findings_by_severity(self, findings: List[Dict], severity: str) -> List[Dict]:
        """Filter findings by severity level."""
        if severity == "ALL":
            return findings
        
        return [f for f in findings if f.get('severity', '').upper() == severity.upper()]
    
    def _prepare_findings_dataframe(self, findings: List[Dict]) -> pd.DataFrame:
        """Prepare findings data for DataFrame display."""
        df_data = []
        
        for finding in findings:
            df_data.append({
                'severity': finding.get('severity', 'UNKNOWN'),
                'category': finding.get('category', '').replace('_', ' ').title(),
                'finding': finding.get('finding', ''),
                'remediation': finding.get('remediation', ''),
                'impact': finding.get('impact', '')
            })
        
        return pd.DataFrame(df_data)
    
    def _render_component_scores_chart(self):
        """Render component scores as a bar chart."""
        if 'component_scores' not in self.assessment_results['security_scorecard']:
            return
        
        st.header("📊 Component Security Scores")
        
        component_scores = self.assessment_results['security_scorecard']['component_scores']
        chart_data = self.prepare_component_scores_chart(component_scores)
        
        # Create bar chart
        fig = px.bar(
            chart_data,
            x='component',
            y='score',
            title='Security Score by Component',
            color='score',
            color_continuous_scale='RdYlGn',
            range_color=[0, 100]
        )
        
        fig.update_layout(
            xaxis_title="Security Component",
            yaxis_title="Score (0-100)",
            showlegend=False
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def prepare_component_scores_chart(self, component_scores: Dict[str, float]) -> pd.DataFrame:
        """Prepare component scores data for chart visualization."""
        chart_data = []
        
        component_labels = {
            'registry_security': 'Registry Security',
            'user_account_security': 'User Account Security',
            'group_policy_compliance': 'Group Policy Compliance',
            'system_integrity': 'System Integrity',
            'network_security': 'Network Security',
            'time_control_security': 'Time Control Security'
        }
        
        for component, score in component_scores.items():
            chart_data.append({
                'component': component_labels.get(component, component.title()),
                'score': score
            })
        
        return pd.DataFrame(chart_data)
    
    def display_essential8_compliance(self, essential8_data: Dict[str, Any]):
        """Display Essential 8 compliance status."""
        st.header("🎯 Essential 8 Compliance")
        
        # Calculate overall compliance
        total_controls = len(essential8_data)
        passed_controls = sum(1 for control in essential8_data.values() 
                            if control.get('status') == 'PASS')
        
        compliance_percentage = (passed_controls / total_controls * 100) if total_controls > 0 else 0
        
        # Compliance overview
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Overall Compliance", f"{compliance_percentage:.1f}%")
        
        with col2:
            st.metric("Controls Passed", f"{passed_controls}/{total_controls}")
        
        with col3:
            compliance_status = "COMPLIANT" if compliance_percentage >= 80 else "NON-COMPLIANT"
            st.metric("Status", compliance_status)
        
        # Individual control status
        st.subheader("Control Status")
        
        controls_df = []
        for control_id, control_data in essential8_data.items():
            controls_df.append({
                'Control': control_id,
                'Status': control_data.get('status', 'UNKNOWN'),
                'Score': control_data.get('score', 0),
                'Details': control_data.get('details', '')
            })
        
        if controls_df:
            st.dataframe(pd.DataFrame(controls_df), use_container_width=True)
    
    def display_remediation_recommendations(self, remediation_data: Dict[str, Any]):
        """Display remediation recommendations and strategy."""
        st.header("🔧 Remediation Recommendations")
        
        # Remediation strategy overview
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric(
                "Recommended Strategy",
                remediation_data.get('recommended_strategy', 'Unknown').replace('_', ' ').title()
            )
        
        with col2:
            st.metric(
                "Estimated Effort",
                f"{remediation_data.get('estimated_effort_hours', 0)} hours"
            )
        
        with col3:
            st.metric(
                "Risk Level",
                remediation_data.get('risk_level', 'Unknown')
            )
        
        # Remediation rationale
        st.subheader("Strategy Rationale")
        st.write(remediation_data.get('rationale', 'No rationale provided.'))
        
        # Data preservation notice
        if remediation_data.get('data_preservation_required', False):
            st.warning("⚠️ Data preservation is required before implementing remediation measures.")
    
    def _render_findings_summary(self):
        """Render findings summary with severity breakdown."""
        findings_summary = self.assessment_results['findings_summary']
        
        st.header("📋 Findings Summary")
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric("Critical", findings_summary['critical'], help="Critical severity findings")
        
        with col2:
            st.metric("High", findings_summary['high'], help="High severity findings")
        
        with col3:
            st.metric("Medium", findings_summary['medium'], help="Medium severity findings")
        
        with col4:
            st.metric("Low", findings_summary['low'], help="Low severity findings")
        
        with col5:
            st.metric("Total", findings_summary['total_findings'], help="Total findings")
    
    def _render_export_options(self):
        """Render export options for assessment results."""
        st.header("📤 Export Results")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("Export as JSON"):
                json_data = self.export_assessment_results(self.assessment_results, "JSON")
                st.download_button(
                    label="Download JSON",
                    data=json_data,
                    file_name=f"assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
        
        with col2:
            if st.button("Export as CSV"):
                csv_data = self.export_assessment_results(self.assessment_results, "CSV")
                st.download_button(
                    label="Download CSV",
                    data=csv_data,
                    file_name=f"assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with col3:
            if st.button("Generate Report"):
                st.info("Comprehensive report generation feature coming soon.")
    
    def export_assessment_results(self, assessment_data: Dict[str, Any], format: str) -> str:
        """Export assessment results in specified format."""
        if format.upper() == "JSON":
            return json.dumps(assessment_data, indent=2, default=str)
        
        elif format.upper() == "CSV":
            # Convert findings to CSV format
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write headers
            writer.writerow(['Severity', 'Category', 'Finding', 'Remediation', 'Impact'])
            
            # Write findings data
            for finding in assessment_data.get('detailed_findings', []):
                writer.writerow([
                    finding.get('severity', ''),
                    finding.get('category', ''),
                    finding.get('finding', ''),
                    finding.get('remediation', ''),
                    finding.get('impact', '')
                ])
            
            return output.getvalue()
        
        return ""
    
    def _render_empty_state(self):
        """Render empty state when no assessment results are available."""
        st.info("No assessment results available. Run a security assessment to view results.")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**To get started:**")
            st.write("1. Click 'Run Assessment' to start a new security assessment")
            st.write("2. Wait for the assessment to complete")
            st.write("3. View comprehensive security results and recommendations")
        
        with col2:
            st.write("**Assessment includes:**")
            st.write("- Registry security analysis")
            st.write("- User account security review")
            st.write("- Group Policy compliance check")
            st.write("- System integrity validation")
            st.write("- Network configuration assessment")
            st.write("- Time control bypass detection")
    
    def load_assessment_results(self, results_data: Optional[Dict[str, Any]] = None):
        """Load assessment results data."""
        if results_data:
            self.assessment_results = results_data
        else:
            # Try to load from session state
            if 'assessment_results' in st.session_state:
                self.assessment_results = st.session_state.assessment_results
    
    def validate_assessment_data(self, data: Dict[str, Any]) -> bool:
        """Validate assessment result data structure."""
        required_keys = ['assessment_metadata', 'security_scorecard', 'findings_summary', 'detailed_findings']
        
        for key in required_keys:
            if key not in data:
                return False
        
        # Validate metadata structure
        metadata_keys = ['timestamp', 'system_info', 'assessment_version']
        for key in metadata_keys:
            if key not in data['assessment_metadata']:
                return False
        
        # Validate scorecard structure
        if 'overall_score' not in data['security_scorecard']:
            return False
        
        return True
    
    def handle_refresh_button(self) -> bool:
        """Handle refresh button click."""
        # Refresh assessment results from cache or trigger reload
        return True
    
    def get_responsive_layout_config(self) -> Dict[str, Any]:
        """Get responsive layout configuration."""
        return {
            'columns': [1, 2, 1],
            'sidebar_width': 300,
            'main_content_width': 800
        }
    
    def display_assessment_progress(self, progress_data: Dict[str, Any]):
        """Display real-time assessment progress."""
        progress_percentage = progress_data.get('progress_percentage', 0.0) / 100.0
        current_status = progress_data.get('current_status', 'Processing...')
        
        st.progress(progress_percentage)
        st.write(f"**Status:** {current_status}")
        
        if 'completed_steps' in progress_data and 'total_steps' in progress_data:
            st.write(f"Progress: {progress_data['completed_steps']}/{progress_data['total_steps']} steps completed")
    
    def display_error_state(self, error_data: Dict[str, Any]):
        """Display error state information."""
        st.error(f"Assessment Error: {error_data.get('error_message', 'Unknown error occurred')}")
        
        if 'error_details' in error_data:
            st.write("**Error Details:**")
            st.code(error_data['error_details'])
        
        if 'recovery_suggestions' in error_data:
            st.write("**Recovery Suggestions:**")
            for suggestion in error_data['recovery_suggestions']:
                st.write(f"• {suggestion}")
    
    def compare_assessment_results(self, current_results: Dict, previous_results: Dict) -> Dict[str, Any]:
        """Compare two assessment results for improvement tracking."""
        current_score = current_results['security_scorecard']['overall_score']
        previous_score = previous_results['security_scorecard']['overall_score']
        
        return {
            'score_improvement': round(current_score - previous_score, 1),
            'findings_change': {
                'current_total': current_results['findings_summary']['total_findings'],
                'previous_total': previous_results['findings_summary']['total_findings']
            },
            'timestamp_current': current_results['assessment_metadata']['timestamp'],
            'timestamp_previous': previous_results['assessment_metadata']['timestamp']
        }
    
    def _start_assessment(self):
        """Start a new security assessment."""
        st.info("Starting security assessment... This may take a few minutes.")
        # This would trigger the actual assessment process
        # For now, we'll show a placeholder
        with st.spinner("Running security assessment..."):
            # Simulate assessment progress
            import time
            time.sleep(2)  # Simulate processing time
    
    def _load_sample_data(self):
        """Load sample assessment data for demonstration."""
        sample_data = {
            "assessment_metadata": {
                "timestamp": datetime.now().isoformat(),
                "system_info": "SAMPLE-SYSTEM - Windows 11 Pro",
                "assessment_version": "1.0",
                "duration_seconds": 42.5
            },
            "security_scorecard": {
                "overall_score": 78.5,
                "component_scores": {
                    "registry_security": 85,
                    "user_account_security": 72,
                    "group_policy_compliance": 80,
                    "system_integrity": 75,
                    "network_security": 82,
                    "time_control_security": 77
                },
                "essential8_compliance": {
                    "B020_passwords": {"status": "PASS", "score": 10, "details": "Password policy compliant"},
                    "B021_admin_rights": {"status": "FAIL", "score": 0, "details": "Excessive admin accounts"},
                    "B022_os_updates": {"status": "PASS", "score": 8, "details": "Updates current"}
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
                    "category": "B002_user_account_security",
                    "severity": "CRITICAL",
                    "finding": "Guest account is enabled",
                    "remediation": "Disable the Guest account immediately",
                    "impact": "Unauthorized anonymous access to system"
                },
                {
                    "category": "B001_registry_modification",
                    "severity": "HIGH",
                    "finding": "UAC bypass detected in registry",
                    "remediation": "Re-enable UAC by setting EnableLUA to 1",
                    "impact": "System vulnerable to privilege escalation"
                }
            ],
            "remediation_approach": {
                "recommended_strategy": "in_place_remediation",
                "rationale": "System shows manageable security gaps that can be addressed through targeted remediation",
                "data_preservation_required": True,
                "estimated_effort_hours": 4,
                "risk_level": "MEDIUM"
            }
        }
        
        self.assessment_results = sample_data
        st.session_state.assessment_results = sample_data
    
    # Helper methods
    def _get_score_color(self, score: float) -> str:
        """Get color based on security score."""
        if score >= 80:
            return "green"
        elif score >= 60:
            return "orange"
        else:
            return "red"
    
    def _get_score_grade(self, score: float) -> str:
        """Get letter grade based on security score."""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    def _format_timestamp(self, timestamp_str: str) -> str:
        """Format timestamp for display."""
        try:
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return timestamp_str