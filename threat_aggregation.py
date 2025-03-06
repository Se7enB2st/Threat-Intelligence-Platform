import os
import requests
from dotenv import load_dotenv

# Load API keys from .env file
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

class ThreatAggregator:
    """
    Fetches threat intelligence from VirusTotal and Shodan.
    """
    
    @staticmethod
    def check_ip_virustotal(ip: str):
        """Query VirusTotal for IP reputation."""
        if not VIRUSTOTAL_API_KEY:
            return {"error": "Missing VirusTotal API key"}
        
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        return {"error": f"VirusTotal request failed with status {response.status_code}"}
    
    @staticmethod
    def check_ip_shodan(ip: str):
        """Query Shodan for IP details."""
        if not SHODAN_API_KEY:
            return {"error": "Missing Shodan API key"}
        
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        response = requests.get(url)
        
        if response.status_code == 200:
            return response.json()
        return {"error": f"Shodan request failed with status {response.status_code}"}
    
    @staticmethod
    def aggregate_threat_data(ip: str):
        """Fetch threat intelligence data from multiple sources."""
        return {
            "ip": ip,
            "virustotal": ThreatAggregator.check_ip_virustotal(ip),
            "shodan": ThreatAggregator.check_ip_shodan(ip)
        }

# Example usage
if __name__ == "__main__":
    test_ip = "8.8.8.8"  # Replace with an actual IP to test
    data = ThreatAggregator.aggregate_threat_data(test_ip)
    print(data)