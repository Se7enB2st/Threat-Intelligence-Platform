import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import ipaddress
from threat_analyzer.database import get_db
from threat_analyzer.threat_analyzer import ThreatAnalyzer
from threat_analyzer.analyzers.domain_analyzer import DomainAnalyzer
from sqlalchemy import text

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

def reset_database():
    """Reset all database tables by deleting all data"""
    try:
        st.info("Starting database reset...")
        db = st.session_state.db
        
        # Delete all data from all tables
        tables = [
            'threat_data',
            'scan_history', 
            'virustotal_data',
            'shodan_data',
            'alienvault_data',
            'ip_analysis',
            'domain_analysis',
            'ip_addresses'
        ]
        
        for table in tables:
            st.info(f"Deleting data from {table}...")
            result = db.execute(text(f"DELETE FROM {table}"))
            st.info(f"Deleted {result.rowcount} rows from {table}")
        
        db.commit()
        st.success("Database reset successfully! All data has been cleared.")
        
    except Exception as e:
        st.error(f"Error resetting database: {str(e)}")
        db.rollback()

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
        # Remove whitespace
        domain_str = domain_str.strip()
        
        # If it already has a scheme, validate as URL
        if domain_str.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            result = urlparse(domain_str)
            return all([result.scheme, result.netloc])
        
        # Otherwise, validate as a domain name
        import re
        # Basic domain regex pattern
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, domain_str))
    except:
        return False

def normalize_domain_input(domain_str):
    """Normalize domain input by adding https:// if no scheme is present"""
    domain_str = domain_str.strip()
    
    # If it already has a scheme, return as is
    if domain_str.startswith(('http://', 'https://')):
        return domain_str
    
    # Otherwise, add https:// prefix
    return f"https://{domain_str}"

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
    
    # Add reset button to sidebar
    st.sidebar.markdown("---")
    st.sidebar.subheader("Database Management")
    
    # Use session state to manage reset confirmation
    if 'reset_confirmed' not in st.session_state:
        st.session_state.reset_confirmed = False
    
    if st.sidebar.button("🗑️ Reset Database", type="secondary"):
        st.session_state.reset_confirmed = True
    
    if st.session_state.reset_confirmed:
        st.sidebar.warning("⚠️ This will delete ALL data!")
        col1, col2 = st.sidebar.columns(2)
        with col1:
            if st.button("✅ Confirm", type="primary"):
                reset_database()
                st.session_state.reset_confirmed = False
                st.rerun()
        with col2:
            if st.button("❌ Cancel"):
                st.session_state.reset_confirmed = False
                st.rerun()

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
                # Display summary statistics
                st.subheader("Analysis Summary")
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric(
                        "Total IPs Analyzed", 
                        historical_data.get('total_ips_analyzed', 0)
                    )
                
                with col2:
                    st.metric(
                        "Total Domains Analyzed", 
                        historical_data.get('total_domains_analyzed', 0)
                    )
                
                with col3:
                    st.metric(
                        "Malicious IPs", 
                        historical_data.get('malicious_ips_count', 0)
                    )
                
                with col4:
                    st.metric(
                        "Malicious Domains", 
                        historical_data.get('malicious_domains_count', 0)
                    )
                
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
                
                # Display domain analysis data
                st.subheader("Domain Analysis")
                
                # Display top malicious domains
                st.write("**Top Malicious Domains**")
                if historical_data.get('top_malicious_domains'):
                    malicious_domains = pd.DataFrame(historical_data['top_malicious_domains'])
                    # Format the columns for better display
                    malicious_domains['threat_score'] = malicious_domains['threat_score'].round(2)
                    malicious_domains['last_updated'] = pd.to_datetime(malicious_domains['last_updated']).dt.strftime('%Y-%m-%d %H:%M:%S')
                    st.dataframe(
                        malicious_domains,
                        column_config={
                            "domain": "Domain",
                            "threat_score": "Threat Score",
                            "last_updated": "Last Updated"
                        },
                        use_container_width=True
                    )
                else:
                    st.info("No malicious domains found in the selected date range")
                
                # Display domain trends
                st.write("**Domain Threat Score Trends**")
                if historical_data.get('domain_trends'):
                    domain_trend_df = pd.DataFrame(historical_data['domain_trends'])
                    if not domain_trend_df.empty:
                        # Ensure date column is datetime
                        domain_trend_df['date'] = pd.to_datetime(domain_trend_df['date'])
                        
                        # Create line chart for domain trends
                        fig = px.line(
                            domain_trend_df,
                            x='date',
                            y='avg_score',
                            title='Domain Threat Score Trends',
                            labels={
                                'date': 'Date',
                                'avg_score': 'Average Domain Threat Score'
                            }
                        )
                        
                        # Add hover data
                        fig.update_traces(
                            hovertemplate="<br>".join([
                                "Date: %{x}",
                                "Average Score: %{y:.2f}",
                                "Domains Analyzed: %{customdata[0]}",
                                "<extra></extra>"
                            ]),
                            customdata=domain_trend_df[['domain_count']].values
                        )
                        
                        st.plotly_chart(fig)
                    else:
                        st.info("No domain trend data available")
                else:
                    st.info("No domain trend data available for the selected date range")
                
                # Display threat score distribution
                st.subheader("Threat Score Distribution")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**IP Threat Score Distribution**")
                    if historical_data.get('ip_score_distribution'):
                        ip_dist_df = pd.DataFrame(historical_data['ip_score_distribution'])
                        if not ip_dist_df.empty:
                            # Create bar chart for IP score distribution
                            fig = px.bar(
                                ip_dist_df,
                                x='range',
                                y='count',
                                title='IP Threat Score Distribution',
                                labels={'range': 'Threat Score Range', 'count': 'Number of IPs'},
                                color='count',
                                color_continuous_scale='viridis'
                            )
                            st.plotly_chart(fig)
                            
                            # Display table with percentages
                            st.write("**Detailed Breakdown:**")
                            ip_dist_df['percentage'] = ip_dist_df['percentage'].astype(str) + '%'
                            st.dataframe(
                                ip_dist_df,
                                column_config={
                                    "range": "Score Range",
                                    "count": "Count",
                                    "percentage": "Percentage"
                                },
                                use_container_width=True
                            )
                        else:
                            st.info("No IP score distribution data available")
                    else:
                        st.info("No IP score distribution data available")
                
                with col2:
                    st.write("**Domain Threat Score Distribution**")
                    if historical_data.get('domain_score_distribution'):
                        domain_dist_df = pd.DataFrame(historical_data['domain_score_distribution'])
                        if not domain_dist_df.empty:
                            # Create bar chart for domain score distribution
                            fig = px.bar(
                                domain_dist_df,
                                x='range',
                                y='count',
                                title='Domain Threat Score Distribution',
                                labels={'range': 'Threat Score Range', 'count': 'Number of Domains'},
                                color='count',
                                color_continuous_scale='plasma'
                            )
                            st.plotly_chart(fig)
                            
                            # Display table with percentages
                            st.write("**Detailed Breakdown:**")
                            domain_dist_df['percentage'] = domain_dist_df['percentage'].astype(str) + '%'
                            st.dataframe(
                                domain_dist_df,
                                column_config={
                                    "range": "Score Range",
                                    "count": "Count",
                                    "percentage": "Percentage"
                                },
                                use_container_width=True
                            )
                        else:
                            st.info("No domain score distribution data available")
                    else:
                        st.info("No domain score distribution data available")
                    
        except Exception as e:
            st.error(f"Error loading historical analysis: {str(e)}")
            st.info("Please try adjusting the date range or contact support if the issue persists")
        
        # Display geographic analysis
        st.subheader("Geographic Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Geographic Distribution of Threats**")
            if historical_data.get('geographic_distribution'):
                geo_df = pd.DataFrame(historical_data['geographic_distribution'])
                if not geo_df.empty:
                    # Create bar chart for geographic distribution
                    fig = px.bar(
                        geo_df,
                        x='country_code',
                        y='count',
                        title='Threat Distribution by Country',
                        labels={'country_code': 'Country Code', 'count': 'Number of IPs'},
                        color='avg_threat_score',
                        color_continuous_scale='reds'
                    )
                    st.plotly_chart(fig)
                    
                    # Display table with geographic details
                    st.write("**Detailed Geographic Breakdown:**")
                    geo_df['percentage'] = geo_df['percentage'].astype(str) + '%'
                    geo_df['avg_threat_score'] = geo_df['avg_threat_score'].round(2)
                    st.dataframe(
                        geo_df,
                        column_config={
                            "country_code": "Country",
                            "city": "City",
                            "count": "Count",
                            "avg_threat_score": "Avg Threat Score",
                            "percentage": "Percentage"
                        },
                        use_container_width=True
                    )
                else:
                    st.info("No geographic distribution data available")
            else:
                st.info("No geographic distribution data available")
        
        with col2:
            st.write("**Country-Level Threat Statistics**")
            if historical_data.get('country_statistics'):
                country_df = pd.DataFrame(historical_data['country_statistics'])
                if not country_df.empty:
                    # Create metrics for top countries
                    for _, country in country_df.head(3).iterrows():
                        col_a, col_b, col_c = st.columns(3)
                        with col_a:
                            st.metric(
                                f"🇺🇸 {country['country_code']}",
                                f"{country['total_ips']} IPs",
                                f"{country['malicious_ips']} malicious"
                            )
                        with col_b:
                            st.metric(
                                "Malicious %",
                                f"{country['malicious_percentage']}%"
                            )
                        with col_c:
                            st.metric(
                                "Avg Threat Score",
                                f"{country['avg_threat_score']:.1f}"
                            )
                    
                    # Display detailed country statistics table
                    st.write("**Detailed Country Statistics:**")
                    country_df['malicious_percentage'] = country_df['malicious_percentage'].astype(str) + '%'
                    country_df['avg_threat_score'] = country_df['avg_threat_score'].round(2)
                    country_df['max_threat_score'] = country_df['max_threat_score'].round(2)
                    st.dataframe(
                        country_df,
                        column_config={
                            "country_code": "Country",
                            "total_ips": "Total IPs",
                            "malicious_ips": "Malicious IPs",
                            "malicious_percentage": "Malicious %",
                            "avg_threat_score": "Avg Threat Score",
                            "max_threat_score": "Max Threat Score"
                        },
                        use_container_width=True
                    )
                else:
                    st.info("No country statistics data available")
            else:
                st.info("No country statistics data available")

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
        domain = st.text_input("Enter Domain (e.g., example.com or https://example.com)")
        
        if domain:
            if is_valid_domain(domain):
                # Normalize the domain input
                normalized_domain = normalize_domain_input(domain)
                with st.spinner(f"Analyzing domain {normalized_domain}..."):
                    try:
                        domain_details = st.session_state.domain_analyzer.analyze_domain(
                            normalized_domain, 
                            st.session_state.db
                        )
                        display_domain_details(domain_details)
                    except Exception as e:
                        st.error(f"Error analyzing domain: {str(e)}")
            else:
                st.error("Invalid domain format")

if __name__ == "__main__":
    main() 