import os
import requests
from dotenv import load_dotenv
from database import get_db
from data_manager import ThreatDataManager
import ipaddress
import time

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

class ThreatAggregator:
    """
    Fetches threat intelligence from VirusTotal, Shodan, and AlienVault OTX.
    """

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

# Example usage
if __name__ == "__main__":
    test_ip = "8.8.8.8"  # Replace with an actual IP to test
    aggregator = ThreatAggregator()
    data = aggregator.aggregate_threat_data(test_ip)
    
    # Save to database
    db = next(get_db())
    try:
        data_manager = ThreatDataManager()
        ip_record = data_manager.save_threat_data(db, test_ip, data)
        print(f"Data saved successfully for IP: {test_ip}")
    except Exception as e:
        print(f"Error saving data: {str(e)}")
    finally:
        db.close()
