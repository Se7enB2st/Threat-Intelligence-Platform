import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from database import get_db
from threat_analyzer import ThreatAnalyzer
from data_manager import ThreatDataManager
from threat_aggregation import ThreatAggregator
import json
import re
import html

# Initialize global variables
db = None
analyzer = None
data_manager = None
aggregator = None

# Add input validation functions
def is_valid_ip(ip: str) -> bool:
    """Validate IP address format"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(part) <= 255 for part in ip.split('.'))

def sanitize_input(input_str: str) -> str:
    """Sanitize user input to prevent XSS"""
    return html.escape(input_str.strip())

def show_dashboard():
    """Display the main dashboard with key metrics and visualizations"""
    # Get statistics
    stats = analyzer.get_statistics(db)
    
    # Create columns for metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total IPs", stats['total_ips_tracked'])
    with col2:
        st.metric("Malicious IPs", stats['malicious_ips_count'])
    with col3:
        st.metric("Average Threat Score", f"{stats['average_threat_score']:.2f}")
    with col4:
        st.metric("Malicious IP %", f"{stats['malicious_ip_percentage']:.1f}%")

    # Create two columns for graphs
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Recent Threat Trends")
        trend_data = analyzer.analyze_threat_trends(db)
        if trend_data['trend_data']:
            df = pd.DataFrame(trend_data['trend_data'])
            fig = px.line(df, x='date', y='average_threat_score',
                         title='Average Threat Score Over Time')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No trend data available yet")

    with col2:
        st.subheader("Threat Source Distribution")
        source_correlation = analyzer.analyze_source_correlation(db)
        if 'correlations' in source_correlation:
            corr_data = source_correlation['correlations']
            fig = px.bar(
                x=list(corr_data.keys()),
                y=list(corr_data.values()),
                title='Source Correlation Scores'
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No correlation data available yet")

def show_ip_lookup():
    """Display IP lookup interface with improved security"""
    st.subheader("IP Address Lookup")
    
    ip_address = st.text_input("Enter IP Address")
    
    if ip_address:
        # Validate and sanitize input
        ip_address = sanitize_input(ip_address)
        if not is_valid_ip(ip_address):
            st.error("Invalid IP address format")
            return
            
        # Proceed with lookup
        ip_details = analyzer.get_ip_details(db, ip_address)
        if "error" in ip_details:
            st.error(ip_details["error"])
            return
            
        # Display results
        display_ip_details(ip_details)

def show_high_risk_ips():
    """Display a list of high-risk IPs"""
    st.header("High Risk IPs")
    
    min_score = st.slider("Minimum Threat Score", 0.0, 100.0, 70.0)
    high_risk = analyzer.get_high_risk_ips(db, min_score)
    
    if high_risk:
        df = pd.DataFrame(high_risk)
        st.dataframe(df)
        
        # Create a bar chart of threat scores
        fig = px.bar(df, x='ip_address', y='threat_score',
                    title='High Risk IPs by Threat Score')
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info(f"No IPs found with threat score above {min_score}")

def show_threat_analysis():
    """Display threat analysis visualizations"""
    st.header("Threat Analysis")
    
    # Show port exposure analysis
    st.subheader("Port Exposure Analysis")
    port_data = analyzer.analyze_port_exposure(db)
    if port_data['port_statistics']:
        df = pd.DataFrame(port_data['port_statistics'])
        fig = px.bar(df, x='port', y='count',
                    color='is_high_risk',
                    title='Port Exposure Distribution')
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No port exposure data available")

    # Show threat patterns
    st.subheader("Threat Patterns")
    pattern_data = analyzer.analyze_threat_patterns(db)
    if pattern_data['activity_patterns']:
        df = pd.DataFrame(pattern_data['activity_patterns'])
        fig = px.bar(df, x='activity', y='count',
                    title='Common Threat Activities')
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No threat pattern data available")

def show_scan_ip():
    """Scan and analyze a new IP address"""
    st.header("Scan New IP")
    
    ip_address = st.text_input("Enter IP address to scan:")
    if st.button("Scan IP") and ip_address:
        with st.spinner(f"Scanning {ip_address}..."):
            try:
                # Collect and save threat data
                threat_data = aggregator.aggregate_threat_data(ip_address)
                ip_record = data_manager.save_threat_data(db, ip_address, threat_data)
                
                st.success("Scan completed successfully!")
                
                # Show quick summary
                st.metric("Threat Score", f"{ip_record.overall_threat_score:.2f}")
                st.metric("Status", "Malicious" if ip_record.is_malicious else "Clean")
                
                # Add button to view full details
                if st.button("View Full Details"):
                    show_ip_lookup()
            except Exception as e:
                st.error(f"Error scanning IP: {str(e)}")

def main():
    """Main function to run the Streamlit app"""
    st.set_page_config(
        page_title="Threat Intelligence Dashboard",
        page_icon="🛡️",
        layout="wide"
    )

    st.title("🛡️ Threat Intelligence Dashboard")

    # Initialize database connection and classes
    global db, analyzer, data_manager, aggregator
    db = next(get_db())
    analyzer = ThreatAnalyzer()
    data_manager = ThreatDataManager()
    aggregator = ThreatAggregator()

    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.radio(
        "Select a page",
        ["Dashboard", "IP Lookup", "High Risk IPs", "Threat Analysis", "Scan New IP"]
    )

    try:
        if page == "Dashboard":
            show_dashboard()
        elif page == "IP Lookup":
            show_ip_lookup()
        elif page == "High Risk IPs":
            show_high_risk_ips()
        elif page == "Threat Analysis":
            show_threat_analysis()
        elif page == "Scan New IP":
            show_scan_ip()
    finally:
        db.close()

if __name__ == "__main__":
    main() 