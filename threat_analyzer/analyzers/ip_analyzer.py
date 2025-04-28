import requests
import logging
import json
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
from threat_analyzer.models.threat_models import IPAnalysis, ThreatData, ShodanData, IPAddress
from sqlalchemy.orm import Session
from dotenv import load_dotenv
from threat_analyzer.utils.security import validate_input, rate_limit

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

class IPAnalyzer:
    def __init__(self, db: Session):
        self.db = db
        # Get API keys from environment variables
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.shodan_api_key = os.getenv('SHODAN_API_KEY')
        self.alienvault_api_key = os.getenv('ALIENVAULT_API_KEY')
        
        # Validate API keys
        self._validate_api_keys()

    def _validate_api_keys(self) -> None:
        """Validate that all required API keys are present"""
        missing_keys = []
        if not self.virustotal_api_key:
            missing_keys.append('VIRUSTOTAL_API_KEY')
        if not self.shodan_api_key:
            missing_keys.append('SHODAN_API_KEY')
        if not self.alienvault_api_key:
            missing_keys.append('ALIENVAULT_API_KEY')
        
        if missing_keys:
            error_msg = f"Missing required API keys: {', '.join(missing_keys)}. Please set them in your .env file."
            logger.error(error_msg)
            raise ValueError(error_msg)

    @validate_input
    @rate_limit(max_calls=60, time_window=60)  # 60 calls per minute
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
                # Commit to ensure we have an ID
                self.db.commit()
            
            # Get threat data from various sources
            virustotal_data = self._get_virustotal_data(ip_address)
            shodan_data = self._get_shodan_data(ip_address)
            alienvault_data = self._get_alienvault_data(ip_address)
            
            # Initialize threat data dictionary
            threat_data = {
                "virustotal": virustotal_data or {},
                "shodan": shodan_data or {},
                "alienvault": alienvault_data or {}
            }
            
            # Store threat data
            if virustotal_data:
                self._store_threat_data(analysis, "virustotal", virustotal_data)
            if shodan_data:
                self._store_threat_data(analysis, "shodan", shodan_data)
            if alienvault_data:
                self._store_threat_data(analysis, "alienvault", alienvault_data)
            
            # Calculate overall threat score
            overall_threat_score = self._calculate_threat_score(
                virustotal_data, shodan_data, alienvault_data
            )
            is_malicious = overall_threat_score >= 0.7
            
            # Update analysis with calculated values
            analysis.overall_threat_score = overall_threat_score
            analysis.is_malicious = is_malicious
            
            self.db.commit()
            
            return {
                "ip_address": analysis.ip_address,
                "overall_threat_score": overall_threat_score,
                "is_malicious": is_malicious,
                "first_seen": analysis.first_seen,
                "last_updated": analysis.last_updated,
                "threat_data": threat_data
            }
            
        except Exception as e:
            logger.error(f"Error analyzing IP {ip_address}: {str(e)}")
            self.db.rollback()
            raise

    @rate_limit(max_calls=4, time_window=60)  # 4 calls per minute (VirusTotal free tier limit)
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

    @rate_limit(max_calls=1, time_window=1)  # 1 call per second (Shodan free tier limit)
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

    @rate_limit(max_calls=10, time_window=60)  # 10 calls per minute (AlienVault free tier limit)
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
        # First, ensure we have an IPAddress record
        ip_address = self.db.query(IPAddress).filter_by(ip_address=analysis.ip_address).first()
        if not ip_address:
            ip_address = IPAddress(
                ip_address=analysis.ip_address,
                first_seen=analysis.first_seen,
                last_updated=analysis.last_updated,
                overall_threat_score=analysis.overall_threat_score,
                is_malicious=analysis.is_malicious
            )
            self.db.add(ip_address)
        else:
            # Update existing record
            ip_address.last_updated = analysis.last_updated
            ip_address.overall_threat_score = analysis.overall_threat_score
            ip_address.is_malicious = analysis.is_malicious
        
        self.db.commit()

        if source == "shodan":
            # Check if Shodan data already exists
            existing_shodan = self.db.query(ShodanData).filter_by(ip_address_id=ip_address.id).first()
            if existing_shodan:
                # Update existing Shodan data
                existing_shodan.ports = json.dumps(data.get('ports', []))
                existing_shodan.vulns = json.dumps(data.get('vulnerabilities', []))
                existing_shodan.tags = json.dumps(data.get('tags', []))
                existing_shodan.hostnames = json.dumps(data.get('hostnames', []))
                existing_shodan.raw_data = json.dumps(data)
                threat_data = existing_shodan
            else:
                # Create new Shodan data
                threat_data = ShodanData(
                    ip_address_id=ip_address.id,
                    ports=json.dumps(data.get('ports', [])),
                    vulns=json.dumps(data.get('vulnerabilities', [])),
                    tags=json.dumps(data.get('tags', [])),
                    hostnames=json.dumps(data.get('hostnames', [])),
                    raw_data=json.dumps(data)
                )
        else:
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