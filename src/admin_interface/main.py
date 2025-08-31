# Main Streamlit Application for Windows Family Manager Policy Hardening
# Entry point for the admin interface dashboard

import streamlit as st
import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from admin_interface.pages.system_assessment import SystemAssessmentPage

def main():
    """Main Streamlit application entry point."""
    
    # Page configuration
    st.set_page_config(
        page_title="Windows Family Manager - Security Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Sidebar navigation
    st.sidebar.title("🛡️ Security Dashboard")
    st.sidebar.markdown("---")
    
    # Navigation menu
    page = st.sidebar.selectbox(
        "Navigate to:",
        ["System Assessment", "Guided Setup", "System Status"],
        index=0
    )
    
    # Page routing
    if page == "System Assessment":
        assessment_page = SystemAssessmentPage()
        assessment_page.render()
    
    elif page == "Guided Setup":
        from admin_interface.pages.guided_setup_wizard import GuidedSetupWizard
        guided_setup = GuidedSetupWizard()
        guided_setup.render()
    
    elif page == "System Status":
        st.title("📊 System Status Monitor")
        st.info("System status monitoring coming soon in Day 3 implementation.")
        st.write("This will include:")
        st.write("- Real-time system health monitoring")
        st.write("- Security control status")
        st.write("- Performance metrics")
        st.write("- Alert management")
    
    # Footer
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Windows Family Manager Policy Hardening**")
    st.sidebar.markdown("Phase 1 - System Assessment & Baseline")

if __name__ == "__main__":
    main()