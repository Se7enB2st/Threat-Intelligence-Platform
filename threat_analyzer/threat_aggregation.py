import os
import requests
from dotenv import load_dotenv
from threat_analyzer.database import get_db
import ipaddress
import time
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from threat_analyzer.models.threat_models import IPAnalysis, DomainAnalysis, ThreatData
from sqlalchemy.orm import Session

# Load API keys from .env file
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")

# Add validation for required API keys
def validate_api_keys():
    missing_keys = []
    if not VIRUSTOTAL_API_KEY:
        missing_keys.append("VIRUSTOTAL_API_KEY")
    if not SHODAN_API_KEY:
        missing_keys.append("SHODAN_API_KEY")
    if not ALIENVAULT_API_KEY:
        missing_keys.append("ALIENVAULT_API_KEY")
    
    if missing_keys:
        raise ValueError(f"Missing required API keys: {', '.join(missing_keys)}")

# Add API key validation at startup
validate_api_keys()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatAggregator:
    """
    Fetches threat intelligence from VirusTotal, Shodan, and AlienVault OTX.
    """

    def __init__(self, db: Session):
        self.db = db

    @staticmethod
    def fetch_data(url: str, headers: dict = None, params: dict = None):
        """Helper method to make an API request and handle errors."""
        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()  # Raise an error for non-200 responses
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}

    @staticmethod
    def check_ip_virustotal(ip: str):
        """Query VirusTotal for IP reputation."""
        if not VIRUSTOTAL_API_KEY:
            return {"error": "Missing VirusTotal API key"}

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        return ThreatAggregator.fetch_data(url, headers)

    @staticmethod
    def check_ip_shodan(ip: str):
        """Query Shodan for IP details."""
        if not SHODAN_API_KEY:
            return {"error": "Missing Shodan API key"}

        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        return ThreatAggregator.fetch_data(url)

    @staticmethod
    def check_ip_alienvault(ip: str):
        """Query AlienVault OTX for IP reputation."""
        if not ALIENVAULT_API_KEY:
            return {"error": "Missing AlienVault OTX API key"}

        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
        return ThreatAggregator.fetch_data(url, headers)

    @staticmethod
    def aggregate_threat_data(ip: str):
        """Fetch threat intelligence data from multiple sources."""
        # Validate and clean IP address
        try:
            ip_obj = ipaddress.ip_address(ip)
            ip_str = str(ip_obj)  # Convert to string format
        except ValueError:
            return {"error": "Invalid IP address format"}

        # Add delay between API calls to respect rate limits
        time.sleep(1)

        return {
            "ip": ip_str,
            "virustotal": ThreatAggregator.check_ip_virustotal(ip_str),
            "shodan": ThreatAggregator.check_ip_shodan(ip_str),
            "alienvault": ThreatAggregator.check_ip_alienvault(ip_str)
        }

    def get_ip_analysis(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get aggregated analysis for an IP address"""
        try:
            analysis = self.db.query(IPAnalysis).filter_by(ip_address=ip_address).first()
            if not analysis:
                return None

            threat_data = self.db.query(ThreatData).filter_by(ip_analysis_id=analysis.id).all()
            
            return {
                "ip_address": analysis.ip_address,
                "overall_threat_score": analysis.overall_threat_score,
                "is_malicious": analysis.is_malicious,
                "first_seen": analysis.first_seen,
                "last_updated": analysis.last_updated,
                "threat_data": {data.source: data.data for data in threat_data}
            }
        except Exception as e:
            logger.error(f"Error getting IP analysis: {str(e)}")
            return None

    def get_domain_analysis(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get aggregated analysis for a domain"""
        try:
            analysis = self.db.query(DomainAnalysis).filter_by(domain=domain).first()
            if not analysis:
                return None

            threat_data = self.db.query(ThreatData).filter_by(domain_analysis_id=analysis.id).all()
            
            return {
                "domain": analysis.domain,
                "overall_threat_score": analysis.overall_threat_score,
                "is_malicious": analysis.is_malicious,
                "first_seen": analysis.first_seen,
                "last_updated": analysis.last_updated,
                "whois_data": analysis.whois_data,
                "dns_records": analysis.dns_records,
                "threat_data": {data.source: data.data for data in threat_data}
            }
        except Exception as e:
            logger.error(f"Error getting domain analysis: {str(e)}")
            return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics about analyzed IPs and domains"""
        try:
            ip_count = self.db.query(IPAnalysis).count()
            malicious_ip_count = self.db.query(IPAnalysis).filter_by(is_malicious=True).count()
            
            domain_count = self.db.query(DomainAnalysis).count()
            malicious_domain_count = self.db.query(DomainAnalysis).filter_by(is_malicious=True).count()
            
            return {
                "total_ips": ip_count,
                "malicious_ips": malicious_ip_count,
                "malicious_ip_percentage": (malicious_ip_count / ip_count * 100) if ip_count > 0 else 0,
                "total_domains": domain_count,
                "malicious_domains": malicious_domain_count,
                "malicious_domain_percentage": (malicious_domain_count / domain_count * 100) if domain_count > 0 else 0
            }
        except Exception as e:
            logger.error(f"Error getting statistics: {str(e)}")
            return {
                "total_ips": 0,
                "malicious_ips": 0,
                "malicious_ip_percentage": 0,
                "total_domains": 0,
                "malicious_domains": 0,
                "malicious_domain_percentage": 0
            }

# Example usage
if __name__ == "__main__":
    test_ip = "8.8.8.8"  # Replace with an actual IP to test
    db = next(get_db())
    try:
        aggregator = ThreatAggregator(db)
        data = aggregator.aggregate_threat_data(test_ip)
        print(f"Data retrieved successfully for IP: {test_ip}")
    except Exception as e:
        print(f"Error retrieving data: {str(e)}")
    finally:
        db.close()
