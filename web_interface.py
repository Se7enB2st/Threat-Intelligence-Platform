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
import json
import re
import html
import os
from domain_analyzer import DomainAnalyzer

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

def show_dashboard():
    """Display the main dashboard with enhanced metrics and visualizations"""
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

    # Create two columns for the main dashboard
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Recent Threat Trends")
        trend_data = analyzer.analyze_threat_trends(db)
        if trend_data.get('trend_data'):
            df = pd.DataFrame(trend_data['trend_data'])
            fig = px.line(df, x='date', y='average_threat_score',
                         title='Average Threat Score Over Time')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No trend data available yet")

        # Add Top Vulnerable Ports
        st.subheader("Most Common Vulnerable Ports")
        port_data = analyzer.analyze_port_exposure(db)
        if port_data and port_data.get('port_statistics'):
            port_df = pd.DataFrame(port_data['port_statistics']).head(5)
            fig = px.bar(port_df, x='port', y='count', 
                        color='is_high_risk',
                        title='Top 5 Open Ports')
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Threat Source Distribution")
        source_correlation = analyzer.analyze_source_correlation(db)
        if source_correlation:
            correlation_data = source_correlation.get('correlations', {})
            corr_df = pd.DataFrame([
                {'Source Pair': k, 'Correlation': v}
                for k, v in correlation_data.items()
            ])
            fig = px.bar(corr_df, x='Source Pair', y='Correlation',
                        title='Source Correlation Analysis')
            st.plotly_chart(fig, use_container_width=True)

        # Add Geographic Distribution
        st.subheader("Geographic Distribution")
        geo_data = analyzer.get_ip_geographic_distribution(db)
        if geo_data:
            fig = px.choropleth(geo_data, 
                              locations='country_code',
                              color='ip_count',
                              title='IP Distribution by Country')
            st.plotly_chart(fig, use_container_width=True)

    # Add Recent Activities Section
    st.subheader("Recent Activities")
    recent_activities = analyzer.get_recent_activities(db, limit=5)
    if recent_activities:
        activity_df = pd.DataFrame(recent_activities)
        st.table(activity_df)

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
    """Enhanced high risk IPs display"""
    st.subheader("High Risk IP Addresses")
    
    # Add filter options
    col1, col2 = st.columns(2)
    with col1:
        min_score = st.slider("Minimum Threat Score", 0, 100, 70)
    with col2:
        sort_by = st.selectbox("Sort By", ["Threat Score", "Last Updated", "Country"])
    
    high_risk_ips = analyzer.get_high_risk_ips(db, min_score)
    
    if high_risk_ips:
        df = pd.DataFrame(high_risk_ips)
        
        # Add visualization
        fig = px.scatter(df, x='last_updated', y='threat_score',
                        hover_data=['ip_address', 'country'],
                        title='High Risk IPs Distribution')
        st.plotly_chart(fig, use_container_width=True)
        
        # Display detailed table
        st.dataframe(df)
    else:
        st.info("No high risk IPs found with the current criteria")

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
    """Enhanced IP scanning interface"""
    st.subheader("Scan New IP Addresses")
    
    # Add bulk IP input option
    input_type = st.radio("Input Type", ["Single IP", "Multiple IPs"])
    
    if input_type == "Single IP":
        ip_address = st.text_input("Enter IP Address")
        if ip_address and st.button("Scan IP"):
            if is_valid_ip(ip_address):
                with st.spinner(f"Scanning {ip_address}..."):
                    result = aggregator.aggregate_threat_data(ip_address)
                    if "error" not in result:
                        ip_record = data_manager.save_threat_data(db, ip_address, result)
                        st.success(f"Scan completed for {ip_address}")
                        show_ip_details(ip_record)
                    else:
                        st.error(f"Error scanning IP: {result['error']}")
            else:
                st.error("Invalid IP address format")
    else:
        ip_list = st.text_area("Enter IP Addresses (one per line)")
        if ip_list and st.button("Scan IPs"):
            ips = [ip.strip() for ip in ip_list.split('\n') if ip.strip()]
            valid_ips = [ip for ip in ips if is_valid_ip(ip)]
            
            if not valid_ips:
                st.error("No valid IP addresses found")
                return
                
            progress_bar = st.progress(0)
            for i, ip in enumerate(valid_ips):
                with st.spinner(f"Scanning {ip} ({i+1}/{len(valid_ips)})..."):
                    result = aggregator.aggregate_threat_data(ip)
                    if "error" not in result:
                        data_manager.save_threat_data(db, ip, result)
                    progress_bar.progress((i + 1) / len(valid_ips))
            st.success(f"Completed scanning {len(valid_ips)} IP addresses")

def show_analytics():
    """Display detailed analytics and insights"""
    st.subheader("Threat Intelligence Analytics")

    # Create tabs for different analytics views
    tab1, tab2, tab3, tab4 = st.tabs([
        "Threat Patterns", 
        "Source Analysis", 
        "Geographic Insights",
        "Time-based Analysis"
    ])

    with tab1:
        st.subheader("Threat Patterns")
        patterns = analyzer.analyze_threat_patterns(db)
        if patterns:
            # Common Attack Patterns
            st.write("Common Attack Patterns")
            if patterns.get('attack_patterns'):
                pattern_df = pd.DataFrame(patterns['attack_patterns'])
                fig = px.bar(pattern_df, x='pattern', y='count',
                            title='Common Attack Patterns')
                st.plotly_chart(fig, use_container_width=True)

            # Threat Categories
            st.write("Threat Categories Distribution")
            if patterns.get('threat_categories'):
                cat_df = pd.DataFrame(patterns['threat_categories'])
                fig = px.pie(cat_df, values='count', names='category',
                           title='Threat Categories')
                st.plotly_chart(fig, use_container_width=True)

    with tab2:
        st.subheader("Source Analysis")
        # Source reliability analysis
        source_analysis = analyzer.analyze_source_correlation(db)
        if source_analysis:
            st.write("Source Correlation Analysis")
            corr_data = source_analysis.get('correlations', {})
            corr_df = pd.DataFrame([
                {'Source Pair': k, 'Correlation': v}
                for k, v in corr_data.items()
            ])
            fig = px.bar(corr_df, x='Source Pair', y='Correlation',
                        title='Source Correlation Strength')
            st.plotly_chart(fig, use_container_width=True)

            # Source accuracy metrics
            if source_analysis.get('accuracy_metrics'):
                st.write("Source Accuracy Metrics")
                accuracy_df = pd.DataFrame(source_analysis['accuracy_metrics'])
                st.table(accuracy_df)

    with tab3:
        st.subheader("Geographic Insights")
        geo_data = analyzer.get_ip_geographic_distribution(db)
        if geo_data:
            # World map of threats
            fig = px.choropleth(geo_data,
                              locations='country_code',
                              color='threat_score',
                              hover_data=['ip_count'],
                              title='Global Threat Distribution')
            st.plotly_chart(fig, use_container_width=True)

            # Top affected countries
            st.write("Top Affected Countries")
            top_countries = pd.DataFrame(geo_data).sort_values(
                by='threat_score', ascending=False).head(10)
            st.table(top_countries)

    with tab4:
        st.subheader("Time-based Analysis")
        time_analysis = analyzer.analyze_threat_trends(db)
        if time_analysis and time_analysis.get('trend_data'):
            # Threat score trends
            trend_df = pd.DataFrame(time_analysis['trend_data'])
            fig = px.line(trend_df, x='date', y='average_threat_score',
                         title='Threat Score Trends')
            st.plotly_chart(fig, use_container_width=True)

            # Peak activity periods
            st.write("Peak Activity Periods")
            if time_analysis.get('peak_periods'):
                peak_df = pd.DataFrame(time_analysis['peak_periods'])
                st.table(peak_df)

def show_settings():
    """Display and manage application settings"""
    st.subheader("Settings")

    # Create tabs for different settings categories
    tab1, tab2, tab3 = st.tabs(["General", "API Configuration", "Notification Settings"])

    with tab1:
        st.subheader("General Settings")
        
        # Scan Interval
        scan_interval = st.number_input(
            "Scan Interval (minutes)",
            min_value=5,
            max_value=1440,
            value=60,
            help="How often to scan IPs for updates"
        )

        # Risk Threshold
        risk_threshold = st.slider(
            "High Risk Threshold",
            min_value=0,
            max_value=100,
            value=70,
            help="Threshold for considering an IP high risk"
        )

        # Data Retention
        data_retention = st.number_input(
            "Data Retention Period (days)",
            min_value=1,
            max_value=365,
            value=30,
            help="How long to keep historical data"
        )

        if st.button("Save General Settings"):
            # Here you would implement saving these settings
            st.success("Settings saved successfully!")

    with tab2:
        st.subheader("API Configuration")
        
        # API Keys (showing masked versions)
        st.text_input(
            "VirusTotal API Key",
            value="********" if os.getenv("VIRUSTOTAL_API_KEY") else "",
            type="password"
        )
        st.text_input(
            "Shodan API Key",
            value="********" if os.getenv("SHODAN_API_KEY") else "",
            type="password"
        )
        st.text_input(
            "AlienVault API Key",
            value="********" if os.getenv("ALIENVAULT_API_KEY") else "",
            type="password"
        )

        if st.button("Test API Connections"):
            # Here you would implement API connection testing
            st.info("Testing API connections...")
            # Simulate API tests
            st.success("All API connections successful!")

    with tab3:
        st.subheader("Notification Settings")
        
        # Enable/Disable notifications
        enable_notifications = st.checkbox(
            "Enable Notifications",
            value=True
        )

        if enable_notifications:
            # Notification methods
            notification_methods = st.multiselect(
                "Notification Methods",
                ["Email", "Slack", "Discord"],
                ["Email"]
            )

            # Notification triggers
            st.write("Notification Triggers")
            st.checkbox("High Risk IP Detected", value=True)
            st.checkbox("API Connection Issues", value=True)
            st.checkbox("Daily Summary", value=True)

            # Email settings if email is selected
            if "Email" in notification_methods:
                st.text_input("Email Recipients (comma-separated)")

            if st.button("Save Notification Settings"):
                # Here you would implement saving notification settings
                st.success("Notification settings saved!")

    # Add a button to reset all settings to default
    if st.button("Reset to Default Settings"):
        # Here you would implement resetting settings
        st.warning("Are you sure you want to reset all settings?")
        if st.button("Confirm Reset"):
            st.success("Settings reset to default values!")

def show_domain_analysis():
    """Display domain security analysis interface"""
    st.subheader("Domain Security Analysis")
    
    # Domain input
    domain = st.text_input("Enter Domain Name (e.g., google.com, netflix.com)")
    
    if domain and st.button("Analyze Domain"):
        with st.spinner(f"Analyzing {domain}..."):
            try:
                results = domain_analyzer.analyze_domain(domain)
                
                # Create tabs for different aspects of analysis
                tab1, tab2, tab3, tab4 = st.tabs([
                    "Overview", 
                    "SSL/TLS", 
                    "DNS & WHOIS",
                    "Security Headers"
                ])
                
                with tab1:
                    st.subheader("Security Overview")
                    
                    # Create metrics for quick overview
                    col1, col2, col3 = st.columns(3)
                    
                    # Security Headers Score
                    header_score = results['security_headers'].get('security_score', 0)
                    with col1:
                        st.metric(
                            "Security Headers Score",
                            f"{header_score:.1f}%",
                            delta="Good" if header_score > 80 else ("Fair" if header_score > 60 else "Poor")
                        )
                    
                    # SSL Status
                    ssl_status = "Valid" if not results['ssl_info'].get('is_expired') else "Expired"
                    with col2:
                        st.metric("SSL Status", ssl_status)
                    
                    # VirusTotal Reputation
                    vt_info = results['virustotal_info']
                    if 'error' not in vt_info:
                        reputation = vt_info['reputation']
                        with col3:
                            st.metric("VT Reputation", reputation)
                    
                    # Display VirusTotal analysis stats if available
                    if 'error' not in vt_info:
                        st.subheader("Threat Analysis")
                        analysis_stats = vt_info['last_analysis_stats']
                        fig = px.pie(
                            values=list(analysis_stats.values()),
                            names=list(analysis_stats.keys()),
                            title="VirusTotal Analysis Results"
                        )
                        st.plotly_chart(fig, use_container_width=True)
                
                with tab2:
                    st.subheader("SSL/TLS Information")
                    ssl_info = results['ssl_info']
                    if 'error' not in ssl_info:
                        st.write("Certificate Details:")
                        st.json({
                            "Issuer": ssl_info['issuer'],
                            "Subject": ssl_info['subject'],
                            "Expires": ssl_info['expires'].isoformat(),
                            "Version": ssl_info['version']
                        })
                    else:
                        st.error(ssl_info['error'])
                
                with tab3:
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.subheader("DNS Records")
                        dns_records = results['dns_records']
                        if 'error' not in dns_records:
                            for record_type, records in dns_records.items():
                                st.write(f"{record_type} Records:")
                                for record in records:
                                    st.code(record)
                    
                    with col2:
                        st.subheader("WHOIS Information")
                        whois_info = results['whois_info']
                        if 'error' not in whois_info:
                            st.write("Registration Details:")
                            st.json({
                                "Registrar": whois_info['registrar'],
                                "Created": whois_info['creation_date'],
                                "Expires": whois_info['expiration_date'],
                                "Updated": whois_info['last_updated']
                            })
                
                with tab4:
                    st.subheader("Security Headers")
                    headers = results['security_headers']
                    if 'error' not in headers:
                        # Create a color-coded table of security headers
                        for header, value in headers.items():
                            if header != 'security_score':
                                if value == "Not Set":
                                    st.error(f"{header}: {value}")
                                else:
                                    st.success(f"{header}: {value}")
                
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

    # Initialize database connection and classes
    global db, analyzer, data_manager, aggregator, domain_analyzer
    db = next(get_db())
    analyzer = ThreatAnalyzer()
    data_manager = ThreatDataManager()
    aggregator = ThreatAggregator()
    domain_analyzer = DomainAnalyzer()

    # Enhanced sidebar with more options
    st.sidebar.title("Navigation")
    page = st.sidebar.radio(
        "Select a page",
        ["Dashboard", "Domain Analysis", "IP Lookup", "High Risk IPs", 
         "Scan New IP", "Analytics", "Settings"]
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
        elif page == "Analytics":
            show_analytics()
        elif page == "Settings":
            show_settings()
    finally:
        db.close()

if __name__ == "__main__":
    main() 