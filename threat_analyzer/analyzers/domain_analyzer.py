import requests
import socket
import ssl
import whois
import dns.resolver
from datetime import datetime
from typing import Dict, List, Optional, Any
import tldextract
from urllib.parse import urlparse
import os
from dotenv import load_dotenv
from threat_analyzer.models.threat_models import DomainAnalysis, ThreatData

load_dotenv()

class DomainAnalyzer:
    def __init__(self):
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.shodan_api_key = os.getenv("SHODAN_API_KEY")
        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        # Use public DNS servers
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']

    def clean_domain(self, domain: str) -> str:
        """Clean and validate domain name"""
        # Remove http/https and www if present
        parsed = tldextract.extract(domain)
        return f"{parsed.domain}.{parsed.suffix}"

    def get_ssl_info(self, domain: str) -> Dict:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
            return {
                "issuer": dict(x[0] for x in cert['issuer']),
                "expires": datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z'),
                "subject": dict(x[0] for x in cert['subject']),
                "version": cert['version'],
                "is_expired": datetime.strptime(cert['notAfter'], 
                                              '%b %d %H:%M:%S %Y %Z') < datetime.now()
            }
        except Exception as e:
            return {"error": f"SSL Error: {str(e)}"}

    def get_dns_records(self, domain: str) -> Dict:
        """Get DNS records"""
        try:
            records = {}
            for record_type in ['A', 'MX', 'NS', 'TXT', 'CNAME']:
                try:
                    answers = self.resolver.resolve(domain, record_type)
                    records[record_type] = [str(answer) for answer in answers]
                except dns.resolver.NoAnswer:
                    records[record_type] = []
                except dns.resolver.Timeout:
                    records[record_type] = ["Timeout"]
                except dns.resolver.NXDOMAIN:
                    records[record_type] = ["Domain not found"]
                except Exception as e:
                    records[record_type] = [f"Error: {str(e)}"]
            return records
        except Exception as e:
            return {"error": f"DNS Error: {str(e)}"}

    def get_whois_info(self, domain: str) -> Dict:
        """Get WHOIS information"""
        try:
            w = whois.whois(domain)
            
            # Handle date fields that might be lists
            def process_date(date_field):
                if isinstance(date_field, list):
                    return date_field[0] if date_field else None
                return date_field

            return {
                "registrar": w.registrar,
                "creation_date": process_date(w.creation_date),
                "expiration_date": process_date(w.expiration_date),
                "last_updated": process_date(w.updated_date),
                "status": w.status,
                "name_servers": w.name_servers
            }
        except Exception as e:
            return {"error": f"WHOIS Error: {str(e)}"}

    def check_virustotal(self, domain: str) -> Dict:
        """Check domain reputation on VirusTotal"""
        if not self.vt_api_key:
            return {"error": "VirusTotal API key not configured"}

        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": self.vt_api_key}
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            return {
                "reputation": data["data"]["attributes"]["reputation"],
                "last_analysis_stats": data["data"]["attributes"]["last_analysis_stats"],
                "total_votes": data["data"]["attributes"]["total_votes"]
            }
        except Exception as e:
            return {"error": f"VirusTotal Error: {str(e)}"}

    def check_security_headers(self, domain: str) -> Dict:
        """Check security headers"""
        try:
            url = f"https://{domain}"
            response = requests.get(url)
            headers = response.headers

            security_headers = {
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Not Set"),
                "Content-Security-Policy": headers.get("Content-Security-Policy", "Not Set"),
                "X-Frame-Options": headers.get("X-Frame-Options", "Not Set"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Not Set"),
                "X-XSS-Protection": headers.get("X-XSS-Protection", "Not Set"),
                "Referrer-Policy": headers.get("Referrer-Policy", "Not Set")
            }

            # Calculate security score based on headers
            score = 0
            for header, value in security_headers.items():
                if value != "Not Set":
                    score += 1
            
            security_headers["security_score"] = (score / 6) * 100
            return security_headers
        except Exception as e:
            return {"error": f"Header Check Error: {str(e)}"}

    def analyze_domain(self, domain: str, db_session=None) -> Dict:
        """Perform comprehensive domain analysis and store results"""
        domain = self.clean_domain(domain)
        
        # Perform analysis
        analysis_results = {
            "domain": domain,
            "ssl_info": self.get_ssl_info(domain),
            "dns_records": self.get_dns_records(domain),
            "whois_info": self.get_whois_info(domain),
            "virustotal_info": self.check_virustotal(domain),
            "security_headers": self.check_security_headers(domain),
            "analysis_timestamp": datetime.now().isoformat()
        }
        
        # Store in database if session is provided
        if db_session:
            try:
                # Check if domain already exists
                existing_domain = db_session.query(DomainAnalysis).filter_by(domain=domain).first()
                
                # Prepare data for storage (convert datetime objects to strings)
                whois_data = self._prepare_whois_data(analysis_results.get('whois_info', {}))
                dns_records = analysis_results.get('dns_records', {})
                
                if existing_domain:
                    # Update existing record
                    existing_domain.last_updated = datetime.utcnow()
                    existing_domain.whois_data = whois_data
                    existing_domain.dns_records = dns_records
                    
                    # Calculate threat score based on analysis
                    threat_score = self._calculate_threat_score(analysis_results)
                    existing_domain.overall_threat_score = threat_score
                    existing_domain.is_malicious = threat_score > 50.0
                    
                    db_session.commit()
                else:
                    # Create new record
                    threat_score = self._calculate_threat_score(analysis_results)
                    new_domain = DomainAnalysis(
                        domain=domain,
                        first_seen=datetime.utcnow(),
                        last_updated=datetime.utcnow(),
                        overall_threat_score=threat_score,
                        is_malicious=threat_score > 50.0,
                        whois_data=whois_data,
                        dns_records=dns_records
                    )
                    db_session.add(new_domain)
                    db_session.commit()
                    
            except Exception as e:
                print(f"Error storing domain analysis: {str(e)}")
                db_session.rollback()
        
        return analysis_results
    
    def _prepare_whois_data(self, whois_info: Dict) -> Dict:
        """Convert datetime objects in WHOIS data to strings for JSON storage"""
        if 'error' in whois_info:
            return whois_info
        
        prepared_data = {}
        for key, value in whois_info.items():
            if isinstance(value, datetime):
                prepared_data[key] = value.isoformat()
            elif isinstance(value, list):
                # Handle lists that might contain datetime objects
                prepared_data[key] = [
                    item.isoformat() if isinstance(item, datetime) else item 
                    for item in value
                ]
            else:
                prepared_data[key] = value
        
        return prepared_data
    
    def _calculate_threat_score(self, analysis_results: Dict) -> float:
        """Calculate threat score based on analysis results"""
        score = 0.0
        
        # Check VirusTotal reputation
        vt_info = analysis_results.get('virustotal_info', {})
        if 'error' not in vt_info:
            reputation = vt_info.get('reputation', 0)
            if reputation < 0:
                score += abs(reputation) * 10  # Negative reputation increases threat score
            elif reputation > 0:
                score -= reputation * 5  # Positive reputation decreases threat score
        
        # Check security headers
        security_headers = analysis_results.get('security_headers', {})
        if 'error' not in security_headers:
            security_score = security_headers.get('security_score', 0)
            if security_score < 50:
                score += (100 - security_score) * 0.5  # Poor security increases threat score
        
        # Check SSL certificate
        ssl_info = analysis_results.get('ssl_info', {})
        if 'error' not in ssl_info:
            if ssl_info.get('is_expired', False):
                score += 20  # Expired certificate
        
        # Check DNS records for suspicious patterns
        dns_records = analysis_results.get('dns_records', {})
        if 'error' not in dns_records:
            # Check for suspicious TXT records
            txt_records = dns_records.get('TXT', [])
            for record in txt_records:
                if any(suspicious in record.lower() for suspicious in ['spam', 'malware', 'phishing']):
                    score += 15
        
        return max(0.0, min(100.0, score))  # Clamp between 0 and 100 