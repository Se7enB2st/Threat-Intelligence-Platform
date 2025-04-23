import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import ipaddress
from database import get_db
from threat_analyzer import ThreatAnalyzer
from data_manager import ThreatDataManager
from threat_aggregation import ThreatAggregator
from domain_analyzer import DomainAnalyzer
import json
import re
import html
import os

# Initialize global variables
db = None
analyzer = None
data_manager = None
aggregator = None
domain_analyzer = None

# Add input validation functions
def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def sanitize_input(input_str: str) -> str:
    """Sanitize user input to prevent XSS"""
    return html.escape(input_str.strip())

def display_ip_details(ip_details: dict):
    """Display detailed information about an IP address"""
    if not ip_details or "error" in ip_details:
        st.error(ip_details.get("error", "No data available"))
        return

    # Create columns for key metrics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric(
            "Overall Threat Score",
            f"{ip_details.get('overall_threat_score', 0):.2f}",
            delta="High Risk" if ip_details.get('is_malicious') else "Low Risk"
        )
    
    with col2:
        st.metric(
            "First Seen",
            ip_details.get('first_seen', 'N/A')
        )
    
    with col3:
        st.metric(
            "Last Updated",
            ip_details.get('last_updated', 'N/A')
        )

    # Display source data if available
    if 'threat_data' in ip_details:
        st.subheader("Threat Intelligence Data")
        threat_data = ip_details['threat_data']
        
        # Show data from different sources if available
        for source in ['virustotal', 'shodan', 'alienvault']:
            if source in threat_data:
                st.write(f"{source.title()} Data:")
                st.json(threat_data[source])

def show_dashboard():
    """Display the main dashboard with key metrics and visualizations"""
    try:
        # Get statistics
        stats = analyzer.get_statistics(db)
        
        # Create columns for metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total IPs", stats.get('total_ips_tracked', 0))
        with col2:
            st.metric("Malicious IPs", stats.get('malicious_ips_count', 0))
        with col3:
            st.metric("Average Threat Score", f"{stats.get('average_threat_score', 0):.2f}")
        with col4:
            st.metric("Malicious IP %", f"{stats.get('malicious_ip_percentage', 0):.1f}%")

        # Create two columns for graphs
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Recent Threat Trends")
            trend_data = analyzer.analyze_threat_trends(db)
            if trend_data and trend_data.get('trend_data'):
                df = pd.DataFrame(trend_data['trend_data'])
                fig = px.line(df, x='date', y='average_threat_score',
                             title='Average Threat Score Over Time')
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No trend data available yet")

        with col2:
            st.subheader("Threat Source Distribution")
            source_data = analyzer.analyze_source_correlation(db)
            if source_data and source_data.get('correlations'):
                corr_df = pd.DataFrame([
                    {'Source': k, 'Correlation': v}
                    for k, v in source_data['correlations'].items()
                ])
                fig = px.bar(corr_df, x='Source', y='Correlation',
                            title='Source Correlation Analysis')
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No source correlation data available yet")

    except Exception as e:
        st.error(f"Error loading dashboard: {str(e)}")

def show_ip_lookup():
    """Display IP lookup interface"""
    st.subheader("IP Address Lookup")
    
    ip_address = st.text_input("Enter IP Address")
    
    if ip_address:
        if is_valid_ip(ip_address):
            with st.spinner(f"Looking up information for {ip_address}..."):
                try:
                    ip_details = analyzer.get_ip_details(db, ip_address)
                    display_ip_details(ip_details)
                except Exception as e:
                    st.error(f"Error looking up IP: {str(e)}")
        else:
            st.error("Invalid IP address format")

def show_high_risk_ips():
    """Display high risk IPs"""
    st.subheader("High Risk IP Addresses")
    
    try:
        high_risk_ips = analyzer.get_high_risk_ips(db)
        if high_risk_ips:
            st.write("High Risk IPs Detected:")
            df = pd.DataFrame(high_risk_ips)
            st.dataframe(df)
        else:
            st.info("No high risk IPs detected")
    except Exception as e:
        st.error(f"Error loading high risk IPs: {str(e)}")

def show_scan_ip():
    """Display IP scanning interface"""
    st.subheader("Scan New IP")
    
    ip_address = st.text_input("Enter IP Address to Scan")
    
    if ip_address and st.button("Start Scan"):
        try:
            # Validate IP address
            ip_obj = ipaddress.ip_address(ip_address)
            ip_str = str(ip_obj)
            
            with st.spinner(f"Scanning {ip_str}..."):
                try:
                    # Get threat data
                    result = aggregator.aggregate_threat_data(ip_str)
                    
                    if "error" not in result:
                        # Save to database
                        ip_record = data_manager.save_threat_data(db, ip_str, result)
                        st.success(f"Scan completed for {ip_str}")
                        
                        # Display results
                        st.subheader("Scan Results")
                        
                        # Show basic metrics
                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric("Threat Score", 
                                    f"{ip_record.overall_threat_score:.1f}")
                        with col2:
                            st.metric("Status", 
                                    "Malicious" if ip_record.is_malicious else "Clean")
                        
                        # Show detailed results
                        with st.expander("View Detailed Results"):
                            st.json(result)
                    else:
                        st.error(f"Error during scan: {result['error']}")
                except Exception as e:
                    st.error(f"Error during scan: {str(e)}")
        except ValueError:
            st.error("Invalid IP address format")

def show_domain_analysis():
    """Display domain security analysis interface"""
    st.subheader("Domain Security Analysis")
    
    domain = st.text_input("Enter Domain Name (e.g., google.com)")
    
    if domain and st.button("Analyze Domain"):
        with st.spinner(f"Analyzing {domain}..."):
            try:
                results = domain_analyzer.analyze_domain(domain)
                if "error" not in results:
                    st.success("Domain analysis completed")
                    st.json(results)
                else:
                    st.error(f"Error analyzing domain: {results['error']}")
            except Exception as e:
                st.error(f"Error analyzing domain: {str(e)}")

def main():
    """Main function to run the Streamlit app"""
    st.set_page_config(
        page_title="Threat Intelligence Dashboard",
        page_icon="🛡️",
        layout="wide"
    )

    st.title("🛡️ Threat Intelligence Dashboard")

    # Initialize global variables
    global db, analyzer, data_manager, aggregator, domain_analyzer
    try:
        db = next(get_db())
        analyzer = ThreatAnalyzer()
        data_manager = ThreatDataManager()
        aggregator = ThreatAggregator()
        domain_analyzer = DomainAnalyzer()
    except Exception as e:
        st.error(f"Error initializing services: {str(e)}")
        return

    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.radio(
        "Select a page",
        ["Dashboard", "Domain Analysis", "IP Lookup", "High Risk IPs", "Scan New IP"]
    )

    try:
        if page == "Dashboard":
            show_dashboard()
        elif page == "Domain Analysis":
            show_domain_analysis()
        elif page == "IP Lookup":
            show_ip_lookup()
        elif page == "High Risk IPs":
            show_high_risk_ips()
        elif page == "Scan New IP":
            show_scan_ip()
    except Exception as e:
        st.error(f"Error loading page: {str(e)}")
    finally:
        if db:
            db.close()

if __name__ == "__main__":
    main()