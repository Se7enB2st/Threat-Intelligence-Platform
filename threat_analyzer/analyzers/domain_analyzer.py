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
                    answers = dns.resolver.resolve(domain, record_type)
                    records[record_type] = [str(answer) for answer in answers]
                except dns.resolver.NoAnswer:
                    records[record_type] = []
            return records
        except Exception as e:
            return {"error": f"DNS Error: {str(e)}"}

    def get_whois_info(self, domain: str) -> Dict:
        """Get WHOIS information"""
        try:
            w = whois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date,
                "last_updated": w.updated_date,
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

    def analyze_domain(self, domain: str) -> Dict:
        """Perform comprehensive domain analysis"""
        domain = self.clean_domain(domain)
        
        return {
            "domain": domain,
            "ssl_info": self.get_ssl_info(domain),
            "dns_records": self.get_dns_records(domain),
            "whois_info": self.get_whois_info(domain),
            "virustotal_info": self.check_virustotal(domain),
            "security_headers": self.check_security_headers(domain),
            "analysis_timestamp": datetime.now().isoformat()
        } 