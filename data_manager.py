from sqlalchemy.orm import Session
from datetime import datetime
from typing import Dict, Optional
import models
from database import get_db
import json
import ipaddress

class ThreatDataManager:
    """Manages all database operations for threat intelligence data"""
    
    @staticmethod
    def save_threat_data(db: Session, ip_address: str, threat_data: Dict) -> models.IPAddress:
        """
        Save or update threat intelligence data for an IP address from all sources
        
        Args:
            db: Database session
            ip_address: The IP address being analyzed
            threat_data: Dictionary containing data from all sources
        """
        try:
            # Ensure IP address is a string
            ip_str = str(ip_address)

            # Check if IP already exists
            ip_record = db.query(models.IPAddress).filter(
                models.IPAddress.ip_address == ip_str
            ).first()

            # Create new IP record if it doesn't exist
            if not ip_record:
                ip_record = models.IPAddress(
                    ip_address=ip_str,
                    first_seen=datetime.utcnow(),
                    last_updated=datetime.utcnow(),
                    overall_threat_score=0.0,
                    is_malicious=False
                )
                db.add(ip_record)
                db.flush()

            # Update the last_updated timestamp
            ip_record.last_updated = datetime.utcnow()

            # Calculate threat score and malicious status
            threat_score = 0
            malicious_indicators = 0

            # Process VirusTotal Data
            vt_data = threat_data.get("virustotal", {})
            if isinstance(vt_data, dict) and "error" not in vt_data:
                try:
                    vt_result = ThreatDataManager._save_virustotal_data(db, ip_record.id, vt_data)
                    if vt_result:
                        threat_score += float(vt_result.malicious_count or 0) * 10
                        if (vt_result.malicious_count or 0) > 0:
                            malicious_indicators += 1
                except Exception as e:
                    print(f"Error processing VirusTotal data: {str(e)}")

            # Process Shodan Data
            shodan_data = threat_data.get("shodan", {})
            if isinstance(shodan_data, dict) and "error" not in shodan_data:
                try:
                    shodan_result = ThreatDataManager._save_shodan_data(db, ip_record.id, shodan_data)
                    if shodan_result and shodan_result.vulns:
                        vuln_count = len(json.loads(shodan_result.vulns))
                        threat_score += vuln_count * 5
                        if vuln_count > 0:
                            malicious_indicators += 1
                except Exception as e:
                    print(f"Error processing Shodan data: {str(e)}")

            # Process AlienVault Data
            av_data = threat_data.get("alienvault", {})
            if isinstance(av_data, dict) and "error" not in av_data:
                try:
                    av_result = ThreatDataManager._save_alienvault_data(db, ip_record.id, av_data)
                    if av_result:
                        threat_score += float(av_result.pulse_count or 0) * 5
                        if (av_result.reputation or 0) < 0:
                            malicious_indicators += 1
                except Exception as e:
                    print(f"Error processing AlienVault data: {str(e)}")

            # Update IP record with calculated scores
            ip_record.overall_threat_score = min(100, threat_score)
            ip_record.is_malicious = malicious_indicators >= 2

            db.commit()
            return ip_record

        except Exception as e:
            db.rollback()
            raise Exception(f"Error saving threat data: {str(e)}")

    @staticmethod
    def _save_virustotal_data(db: Session, ip_id: int, vt_data: Dict) -> Optional[models.VirusTotalData]:
        """Save VirusTotal data"""
        try:
            vt_record = db.query(models.VirusTotalData).filter(
                models.VirusTotalData.ip_address_id == ip_id
            ).first()

            if not vt_record:
                vt_record = models.VirusTotalData(ip_address_id=ip_id)
                db.add(vt_record)

            # Extract relevant data
            analysis_stats = vt_data.get('last_analysis_stats', {})
            vt_record.malicious_count = analysis_stats.get('malicious', 0)
            vt_record.suspicious_count = analysis_stats.get('suspicious', 0)
            vt_record.harmless_count = analysis_stats.get('harmless', 0)
            vt_record.last_analysis_date = datetime.utcnow()
            vt_record.raw_data = json.dumps(vt_data)

            db.flush()
            return vt_record

        except Exception as e:
            print(f"Error saving VirusTotal data: {str(e)}")
            return None

    @staticmethod
    def _save_shodan_data(db: Session, ip_id: int, shodan_data: Dict) -> Optional[models.ShodanData]:
        """Save Shodan data"""
        try:
            shodan_record = db.query(models.ShodanData).filter(
                models.ShodanData.ip_address_id == ip_id
            ).first()

            if not shodan_record:
                shodan_record = models.ShodanData(ip_address_id=ip_id)
                db.add(shodan_record)

            # Extract and save relevant data
            shodan_record.ports = json.dumps(shodan_data.get('ports', []))
            shodan_record.vulns = json.dumps(shodan_data.get('vulns', []))
            shodan_record.tags = json.dumps(shodan_data.get('tags', []))
            shodan_record.hostnames = json.dumps(shodan_data.get('hostnames', []))
            shodan_record.last_update = datetime.utcnow()
            shodan_record.raw_data = json.dumps(shodan_data)

            db.flush()
            return shodan_record

        except Exception as e:
            print(f"Error saving Shodan data: {str(e)}")
            return None

    @staticmethod
    def _save_alienvault_data(db: Session, ip_id: int, av_data: Dict) -> Optional[models.AlienVaultData]:
        """Save AlienVault data"""
        try:
            av_record = db.query(models.AlienVaultData).filter(
                models.AlienVaultData.ip_address_id == ip_id
            ).first()

            if not av_record:
                av_record = models.AlienVaultData(ip_address_id=ip_id)
                db.add(av_record)

            # Extract and save relevant data
            av_record.pulse_count = av_data.get('pulse_count', 0)
            av_record.reputation = av_data.get('reputation', 0)
            av_record.activity_types = json.dumps(av_data.get('activity_types', []))
            av_record.raw_data = json.dumps(av_data)
            av_record.last_updated = datetime.utcnow()

            db.flush()
            return av_record

        except Exception as e:
            print(f"Error saving AlienVault data: {str(e)}")
            return None 