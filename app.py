import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
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
        first_seen = ip_details.get('first_seen')
        if isinstance(first_seen, str):
            first_seen = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
        st.metric("First Seen", first_seen.strftime('%Y-%m-%d %H:%M:%S') if first_seen else 'N/A')
    
    with col3:
        last_updated = ip_details.get('last_updated')
        if isinstance(last_updated, str):
            last_updated = datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
        st.metric("Last Updated", last_updated.strftime('%Y-%m-%d %H:%M:%S') if last_updated else 'N/A')

    # Display historical scan data
    if 'scan_history' in ip_details:
        st.subheader("Analysis History")
        scan_history = pd.DataFrame(ip_details['scan_history'])
        if not scan_history.empty:
            # Convert scan_date to datetime if it's not already
            scan_history['scan_date'] = pd.to_datetime(scan_history['scan_date'])
            
            # Create a line chart of threat scores over time
            fig = px.line(
                scan_history,
                x='scan_date',
                y='threat_score',
                title='Threat Score History'
            )
            st.plotly_chart(fig)

            # Display scan history details in an expandable section
            with st.expander("View Detailed Scan History"):
                st.dataframe(
                    scan_history.sort_values('scan_date', ascending=False),
                    use_container_width=True
                )

    if 'threat_data' in ip_details:
        st.subheader("Current Threat Intelligence Data")
        
        # Create tabs for different data sources
        tabs = st.tabs(['VirusTotal', 'Shodan', 'AlienVault'])
        
        with tabs[0]:  # VirusTotal
            if 'virustotal' in ip_details['threat_data'] and ip_details['threat_data']['virustotal']:
                vt_data = ip_details['threat_data']['virustotal']
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Malicious", vt_data.get('malicious_count', 0))
                with col2:
                    st.metric("Suspicious", vt_data.get('suspicious_count', 0))
                with col3:
                    st.metric("Harmless", vt_data.get('harmless_count', 0))
            else:
                st.info("No VirusTotal data available")
        
        with tabs[1]:  # Shodan
            if 'shodan' in ip_details['threat_data'] and ip_details['threat_data']['shodan']:
                shodan_data = ip_details['threat_data']['shodan']
                col1, col2 = st.columns(2)
                with col1:
                    st.write("Open Ports")
                    ports = shodan_data.get('ports', [])
                    if ports:
                        st.json(ports)
                    else:
                        st.info("No open ports found")
                with col2:
                    st.write("Vulnerabilities")
                    vulns = shodan_data.get('vulnerabilities', [])
                    if vulns:
                        st.json(vulns)
                    else:
                        st.info("No vulnerabilities found")
            else:
                st.info("No Shodan data available")
        
        with tabs[2]:  # AlienVault
            if 'alienvault' in ip_details['threat_data'] and ip_details['threat_data']['alienvault']:
                av_data = ip_details['threat_data']['alienvault']
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Pulse Count", av_data.get('pulse_count', 0))
                with col2:
                    st.metric("Reputation", av_data.get('reputation', 'N/A'))
                
                activity_types = av_data.get('activity_types', [])
                if activity_types:
                    st.write("Activity Types:")
                    st.json(activity_types)
            else:
                st.info("No AlienVault data available")

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
        ["Dashboard", "IP Lookup", "Domain Analysis", "Historical Analysis"]
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
            
            # Add threat trends
            trends = st.session_state.analyzer.analyze_threat_trends(st.session_state.db)
            if trends and 'trend_data' in trends:
                st.subheader("Threat Score Trends")
                # Convert trend data to DataFrame
                trend_data = pd.DataFrame(trends['trend_data'])
                if not trend_data.empty:
                    # Ensure date column is datetime
                    trend_data['date'] = pd.to_datetime(trend_data['date'])
                    
                    # Create line chart
                    fig = px.line(
                        trend_data,
                        x='date',
                        y='average_threat_score',
                        title='Average Daily Threat Scores',
                        labels={
                            'date': 'Date',
                            'average_threat_score': 'Average Threat Score'
                        }
                    )
                    
                    # Add hover data
                    fig.update_traces(
                        hovertemplate="<br>".join([
                            "Date: %{x}",
                            "Average Score: %{y:.2f}",
                            "IPs Analyzed: %{customdata[0]}",
                            "Change: %{customdata[1]:.1f}%",
                            "<extra></extra>"
                        ]),
                        customdata=trend_data[['ips_analyzed', 'percentage_change']].values
                    )
                    
                    st.plotly_chart(fig)
                    
                    # Display trend summary
                    if 'summary' in trends:
                        summary = trends['summary']
                        st.write(f"**Overall Trend:** {summary.get('overall_trend', 'N/A')}")
                        st.write(f"**Period:** {summary.get('start_date', 'N/A')} to {summary.get('end_date', 'N/A')}")
                else:
                    st.info("No trend data available")
            else:
                st.info("No trend data available")
                
            # Display significant changes if available
            if trends and 'significant_changes' in trends and trends['significant_changes']:
                st.subheader("Significant Changes")
                for change in trends['significant_changes']:
                    st.write(f"- {change}")
                
        except Exception as e:
            st.error(f"Error loading dashboard: {str(e)}")
            st.error("Please try refreshing the page or contact support if the issue persists")
            
    elif page == "Historical Analysis":
        st.header("Historical Analysis")
        
        # Date range selector
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input(
                "Start Date",
                value=datetime.now() - timedelta(days=30)
            )
        with col2:
            end_date = st.date_input(
                "End Date",
                value=datetime.now()
            )
            
        try:
            # Get historical data
            historical_data = st.session_state.analyzer.get_historical_analysis(
                st.session_state.db,
                start_date,
                end_date
            )
            
            if historical_data:
                # Display trends
                st.subheader("Threat Score Trends")
                if historical_data['trends']:
                    trend_df = pd.DataFrame(historical_data['trends'])
                    fig = px.line(
                        trend_df,
                        x='date',
                        y='avg_score',
                        title='Historical Threat Scores'
                    )
                    # Add hover data
                    fig.update_traces(
                        hovertemplate="<br>".join([
                            "Date: %{x}",
                            "Average Score: %{y:.2f}",
                            "<extra></extra>"
                        ])
                    )
                    st.plotly_chart(fig)
                else:
                    st.info("No trend data available for the selected date range")
                
                # Display top malicious IPs
                st.subheader("Top Malicious IPs")
                if historical_data['top_malicious_ips']:
                    malicious_ips = pd.DataFrame(historical_data['top_malicious_ips'])
                    # Format the columns for better display
                    malicious_ips['threat_score'] = malicious_ips['threat_score'].round(2)
                    malicious_ips['last_seen'] = pd.to_datetime(malicious_ips['last_seen']).dt.strftime('%Y-%m-%d %H:%M:%S')
                    st.dataframe(
                        malicious_ips,
                        column_config={
                            "ip_address": "IP Address",
                            "threat_score": "Threat Score",
                            "scan_count": "Number of Scans",
                            "last_seen": "Last Seen"
                        },
                        use_container_width=True
                    )
                else:
                    st.info("No malicious IPs found in the selected date range")
                
                # Display common attack patterns
                st.subheader("Common Attack Patterns")
                patterns = historical_data.get('attack_patterns', [])
                if patterns:
                    for pattern in patterns:
                        st.write(f"- {pattern['description']} (Confidence: {pattern['confidence']}%)")
                else:
                    st.info("No attack patterns detected in the selected date range")
                    
        except Exception as e:
            st.error(f"Error loading historical analysis: {str(e)}")
            st.error("Please try adjusting the date range or contact support if the issue persists")

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