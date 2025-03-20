import os
import requests
from dotenv import load_dotenv

# Load API keys from .env file
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")

class ThreatAggregator:
    """
    Fetches threat intelligence from VirusTotal, Shodan, and AlienVault OTX.
    """

    @staticmethod
    def fetch_data(url: str, headers: dict = None):
        """Helper method to make an API request and handle errors."""
        try:
            response = requests.get(url, headers=headers, timeout=10)
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
        return {
            "ip": ip,
            "virustotal": ThreatAggregator.check_ip_virustotal(ip),
            "shodan": ThreatAggregator.check_ip_shodan(ip),
            "alienvault": ThreatAggregator.check_ip_alienvault(ip),
        }

# Example usage
if __name__ == "__main__":
    test_ip = "8.8.8.8"  # Replace with an actual IP to test
    data = ThreatAggregator.aggregate_threat_data(test_ip)
    print(data)
