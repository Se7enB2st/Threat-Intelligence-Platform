import requests
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from threat_analyzer.models.threat_models import IPAnalysis, ThreatData
from sqlalchemy.orm import Session

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IPAnalyzer:
    def __init__(self, db: Session):
        self.db = db
        self.virustotal_api_key = "YOUR_VIRUSTOTAL_API_KEY"  # Replace with actual API key
        self.shodan_api_key = "YOUR_SHODAN_API_KEY"  # Replace with actual API key
        self.alienvault_api_key = "YOUR_ALIENVAULT_API_KEY"  # Replace with actual API key

    def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """Analyze an IP address using multiple threat intelligence sources"""
        try:
            # Check if we already have analysis for this IP
            existing_analysis = self.db.query(IPAnalysis).filter_by(ip_address=ip_address).first()
            
            if existing_analysis:
                # Update existing analysis
                analysis = existing_analysis
                analysis.last_updated = datetime.utcnow()
            else:
                # Create new analysis
                analysis = IPAnalysis(
                    ip_address=ip_address,
                    first_seen=datetime.utcnow(),
                    last_updated=datetime.utcnow()
                )
                self.db.add(analysis)
            
            # Get threat data from various sources
            virustotal_data = self._get_virustotal_data(ip_address)
            shodan_data = self._get_shodan_data(ip_address)
            alienvault_data = self._get_alienvault_data(ip_address)
            
            # Store threat data
            if virustotal_data:
                self._store_threat_data(analysis, "virustotal", virustotal_data)
            if shodan_data:
                self._store_threat_data(analysis, "shodan", shodan_data)
            if alienvault_data:
                self._store_threat_data(analysis, "alienvault", alienvault_data)
            
            # Calculate overall threat score
            analysis.overall_threat_score = self._calculate_threat_score(
                virustotal_data, shodan_data, alienvault_data
            )
            analysis.is_malicious = analysis.overall_threat_score >= 0.7
            
            self.db.commit()
            
            return {
                "ip_address": analysis.ip_address,
                "overall_threat_score": analysis.overall_threat_score,
                "is_malicious": analysis.is_malicious,
                "first_seen": analysis.first_seen,
                "last_updated": analysis.last_updated,
                "threat_data": {
                    "virustotal": virustotal_data,
                    "shodan": shodan_data,
                    "alienvault": alienvault_data
                }
            }
            
        except Exception as e:
            logger.error(f"Error analyzing IP {ip_address}: {str(e)}")
            self.db.rollback()
            raise

    def _get_virustotal_data(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get threat data from VirusTotal"""
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            headers = {"x-apikey": self.virustotal_api_key}
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error getting VirusTotal data: {str(e)}")
            return None

    def _get_shodan_data(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get threat data from Shodan"""
        try:
            url = f"https://api.shodan.io/shodan/host/{ip_address}"
            params = {"key": self.shodan_api_key}
            response = requests.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error getting Shodan data: {str(e)}")
            return None

    def _get_alienvault_data(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get threat data from AlienVault"""
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
            headers = {"X-OTX-API-KEY": self.alienvault_api_key}
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error getting AlienVault data: {str(e)}")
            return None

    def _store_threat_data(self, analysis: IPAnalysis, source: str, data: Dict[str, Any]) -> None:
        """Store threat data in the database"""
        threat_data = ThreatData(
            ip_analysis_id=analysis.id,
            source=source,
            data=data,
            timestamp=datetime.utcnow()
        )
        self.db.add(threat_data)

    def _calculate_threat_score(self, *data_sources: Optional[Dict[str, Any]]) -> float:
        """Calculate overall threat score based on data from multiple sources"""
        scores = []
        
        for data in data_sources:
            if not data:
                continue
                
            if isinstance(data, dict):
                # VirusTotal scoring
                if "data" in data and "attributes" in data["data"]:
                    stats = data["data"]["attributes"].get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values())
                    if total > 0:
                        scores.append((malicious + 0.5 * suspicious) / total)
                
                # Shodan scoring
                if "vulns" in data and data["vulns"]:
                    scores.append(min(1.0, len(data["vulns"]) * 0.1))
                
                # AlienVault scoring
                if "pulse_info" in data and "count" in data["pulse_info"]:
                    pulse_count = data["pulse_info"]["count"]
                    scores.append(min(1.0, pulse_count * 0.05))
        
        if not scores:
            return 0.0
            
        return sum(scores) / len(scores) 