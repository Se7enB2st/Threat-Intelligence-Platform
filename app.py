import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import ipaddress
from threat_analyzer.database import get_db
from threat_analyzer.threat_analyzer import ThreatAnalyzer

# Add health check endpoint
if st.query_params.get("health") == "check":
    st.write("OK")
    st.stop()

# Initialize session state
if 'db' not in st.session_state:
    st.session_state.db = get_db()
if 'analyzer' not in st.session_state:
    st.session_state.analyzer = ThreatAnalyzer()

def is_valid_ip(ip_str):
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def display_ip_details(ip_details: dict):
    """Display detailed information about an IP address"""
    if not ip_details or "error" in ip_details:
        st.error(ip_details.get("error", "No data available"))
        return

    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric(
            "Overall Threat Score",
            f"{ip_details.get('overall_threat_score', 0):.2f}",
            delta="High Risk" if ip_details.get('is_malicious') else "Low Risk"
        )
    
    with col2:
        st.metric("First Seen", ip_details.get('first_seen', 'N/A'))
    
    with col3:
        st.metric("Last Updated", ip_details.get('last_updated', 'N/A'))

    if 'threat_data' in ip_details:
        st.subheader("Threat Intelligence Data")
        for source in ['virustotal', 'shodan', 'alienvault']:
            if source in ip_details['threat_data'] and ip_details['threat_data'][source]:
                st.write(f"{source.title()} Data:")
                st.json(ip_details['threat_data'][source])

def main():
    st.title("Threat Intelligence Platform")
    
    # Sidebar for navigation
    page = st.sidebar.selectbox(
        "Select a page",
        ["Dashboard", "IP Lookup"]
    )

    if page == "Dashboard":
        st.header("Threat Intelligence Dashboard")
        try:
            stats = st.session_state.analyzer.get_statistics(st.session_state.db)
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Total IPs", stats.get('total_ips_tracked', 0))
                st.metric("Average Threat Score", f"{stats.get('average_threat_score', 0):.2f}")
            with col2:
                st.metric("Malicious IPs", stats.get('malicious_ips_count', 0))
                st.metric("Malicious IP %", f"{stats.get('malicious_ip_percentage', 0):.1f}%")
                
        except Exception as e:
            st.error(f"Error loading dashboard: {str(e)}")

    elif page == "IP Lookup":
        st.header("IP Address Lookup")
        ip_address = st.text_input("Enter IP Address")
        
        if ip_address:
            if is_valid_ip(ip_address):
                with st.spinner(f"Looking up information for {ip_address}..."):
                    try:
                        ip_details = st.session_state.analyzer.get_ip_details(
                            st.session_state.db, 
                            ip_address
                        )
                        display_ip_details(ip_details)
                    except Exception as e:
                        st.error(f"Error looking up IP: {str(e)}")
            else:
                st.error("Invalid IP address format")

if __name__ == "__main__":
    main() 