import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import ipaddress
from threat_analyzer.database import get_db
from threat_analyzer.threat_analyzer import ThreatAnalyzer
from threat_analyzer.analyzers.domain_analyzer import DomainAnalyzer

# Add health check endpoint
if st.query_params.get("health") == "check":
    st.write("OK")
    st.stop()

# Initialize session state
if 'db' not in st.session_state:
    st.session_state.db = get_db()
if 'analyzer' not in st.session_state:
    st.session_state.analyzer = ThreatAnalyzer()
if 'domain_analyzer' not in st.session_state:
    st.session_state.domain_analyzer = DomainAnalyzer()

def is_valid_ip(ip_str):
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def is_valid_domain(domain_str):
    """Validate domain format"""
    try:
        from urllib.parse import urlparse
        result = urlparse(domain_str)
        return all([result.scheme, result.netloc])
    except:
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

def display_domain_details(domain_details: dict):
    """Display detailed information about a domain"""
    if not domain_details or "error" in domain_details:
        st.error(domain_details.get("error", "No data available"))
        return

    st.subheader("Domain Analysis Results")
    
    # Basic Information
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Domain", domain_details.get('domain', 'N/A'))
    with col2:
        timestamp = domain_details.get('analysis_timestamp', 'N/A')
        if isinstance(timestamp, datetime):
            timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        st.metric("Analysis Timestamp", timestamp)

    # SSL Information
    st.subheader("SSL Certificate Information")
    ssl_info = domain_details.get('ssl_info', {})
    if "error" not in ssl_info:
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Issuer", ssl_info.get('issuer', {}).get('organizationName', 'N/A'))
            st.metric("Version", ssl_info.get('version', 'N/A'))
        with col2:
            expires = ssl_info.get('expires', 'N/A')
            if isinstance(expires, datetime):
                expires = expires.strftime('%Y-%m-%d %H:%M:%S')
            st.metric("Expiration", expires)
            st.metric("Status", "Expired" if ssl_info.get('is_expired') else "Valid")
    else:
        st.error(ssl_info.get("error"))

    # DNS Records
    st.subheader("DNS Records")
    dns_records = domain_details.get('dns_records', {})
    if "error" not in dns_records:
        for record_type, records in dns_records.items():
            if records:
                st.write(f"{record_type} Records:")
                if isinstance(records, list):
                    for record in records:
                        st.write(f"- {record}")
                else:
                    st.write(records)
    else:
        st.warning("DNS resolution failed. This could be due to network issues or the domain not being accessible.")
        st.error(dns_records.get("error"))

    # WHOIS Information
    st.subheader("WHOIS Information")
    whois_info = domain_details.get('whois_info', {})
    if "error" not in whois_info:
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Registrar", whois_info.get('registrar', 'N/A'))
            creation_date = whois_info.get('creation_date', 'N/A')
            if isinstance(creation_date, datetime):
                creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S')
            elif isinstance(creation_date, list):
                creation_date = creation_date[0].strftime('%Y-%m-%d %H:%M:%S') if creation_date else 'N/A'
            st.metric("Creation Date", creation_date)
        with col2:
            expiration_date = whois_info.get('expiration_date', 'N/A')
            if isinstance(expiration_date, datetime):
                expiration_date = expiration_date.strftime('%Y-%m-%d %H:%M:%S')
            elif isinstance(expiration_date, list):
                expiration_date = expiration_date[0].strftime('%Y-%m-%d %H:%M:%S') if expiration_date else 'N/A'
            st.metric("Expiration Date", expiration_date)
            last_updated = whois_info.get('last_updated', 'N/A')
            if isinstance(last_updated, datetime):
                last_updated = last_updated.strftime('%Y-%m-%d %H:%M:%S')
            elif isinstance(last_updated, list):
                last_updated = last_updated[0].strftime('%Y-%m-%d %H:%M:%S') if last_updated else 'N/A'
            st.metric("Last Updated", last_updated)
        
        # Display name servers if available
        if whois_info.get('name_servers'):
            st.write("Name Servers:")
            for ns in whois_info['name_servers']:
                st.write(f"- {ns}")
    else:
        st.error(whois_info.get("error"))

    # VirusTotal Information
    st.subheader("VirusTotal Analysis")
    vt_info = domain_details.get('virustotal_info', {})
    if "error" not in vt_info:
        st.metric("Reputation Score", vt_info.get('reputation', 'N/A'))
        st.write("Analysis Statistics:")
        st.json(vt_info.get('last_analysis_stats', {}))
    else:
        st.error(vt_info.get("error"))

    # Security Headers
    st.subheader("Security Headers")
    security_headers = domain_details.get('security_headers', {})
    if "error" not in security_headers:
        st.metric("Security Score", f"{security_headers.get('security_score', 0):.2f}%")
        st.write("Headers Status:")
        for header, value in security_headers.items():
            if header != "security_score":
                st.write(f"{header}: {value}")
    else:
        st.error(security_headers.get("error"))

def main():
    st.title("Threat Intelligence Platform")
    
    # Sidebar for navigation
    page = st.sidebar.selectbox(
        "Select a page",
        ["Dashboard", "IP Lookup", "Domain Analysis"]
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

    elif page == "Domain Analysis":
        st.header("Domain Analysis")
        domain = st.text_input("Enter Domain (e.g., https://example.com)")
        
        if domain:
            if is_valid_domain(domain):
                with st.spinner(f"Analyzing domain {domain}..."):
                    try:
                        domain_details = st.session_state.domain_analyzer.analyze_domain(domain)
                        display_domain_details(domain_details)
                    except Exception as e:
                        st.error(f"Error analyzing domain: {str(e)}")
            else:
                st.error("Invalid domain format. Please include protocol (http:// or https://)")

if __name__ == "__main__":
    main() 