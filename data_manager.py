from sqlalchemy.orm import Session
from datetime import datetime
from typing import Dict, Optional
import models
from database import get_db
import json  # Add this import at the top of the file

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
        # Check if IP already exists
        ip_record = db.query(models.IPAddress).filter(
            models.IPAddress.ip_address == ip_address
        ).first()

        # Create new IP record if it doesn't exist
        if not ip_record:
            ip_record = models.IPAddress(
                ip_address=ip_address,
                first_seen=datetime.utcnow(),
            )
            db.add(ip_record)
            db.flush()  # Get the ID of the new record

        # Update VirusTotal Data
        if "virustotal" in threat_data:
            vt_data = threat_data["virustotal"]
            if not isinstance(vt_data, dict) or "error" in vt_data:
                vt_result = None
            else:
                vt_result = ThreatDataManager._save_virustotal_data(db, ip_record.id, vt_data)

        # Update Shodan Data
        if "shodan" in threat_data:
            shodan_data = threat_data["shodan"]
            if not isinstance(shodan_data, dict) or "error" in shodan_data:
                shodan_result = None
            else:
                shodan_result = ThreatDataManager._save_shodan_data(db, ip_record.id, shodan_data)

        # Update AlienVault Data
        if "alienvault" in threat_data:
            av_data = threat_data["alienvault"]
            if not isinstance(av_data, dict) or "error" in av_data:
                av_result = None
            else:
                av_result = ThreatDataManager._save_alienvault_data(db, ip_record.id, av_data)

        # Calculate and update overall threat score
        ThreatDataManager._update_threat_score(db, ip_record)

        # Create scan history entry with JSON string for sources_checked
        scan_history = models.ScanHistory(
            ip_address_id=ip_record.id,
            scan_date=datetime.utcnow(),
            scan_type="full",
            status="success",
            error_message=None,
            sources_checked=json.dumps({  # Convert dict to JSON string
                "virustotal": vt_result is not None,
                "shodan": shodan_result is not None,
                "alienvault": av_result is not None
            })
        )
        db.add(scan_history)

        # Commit all changes
        db.commit()
        return ip_record

    @staticmethod
    def _save_virustotal_data(db: Session, ip_id: int, vt_data: Dict) -> Optional[models.VirusTotalData]:
        """Save VirusTotal data for an IP"""
        vt_record = db.query(models.VirusTotalData).filter(
            models.VirusTotalData.ip_address_id == ip_id
        ).first()

        if not vt_record:
            vt_record = models.VirusTotalData(ip_address_id=ip_id)
            db.add(vt_record)

        # Extract relevant data from VirusTotal response
        if 'data' in vt_data and 'attributes' in vt_data['data']:
            attrs = vt_data['data']['attributes']
            last_analysis_stats = attrs.get('last_analysis_stats', {})
            
            vt_record.malicious_count = last_analysis_stats.get('malicious', 0)
            vt_record.suspicious_count = last_analysis_stats.get('suspicious', 0)
            vt_record.harmless_count = last_analysis_stats.get('harmless', 0)
            vt_record.last_analysis_date = datetime.fromtimestamp(attrs.get('last_analysis_date', 0))
            vt_record.raw_data = vt_data

        db.flush()
        return vt_record

    @staticmethod
    def _save_shodan_data(db: Session, ip_id: int, shodan_data: Dict) -> Optional[models.ShodanData]:
        """Save Shodan data for an IP"""
        shodan_record = db.query(models.ShodanData).filter(
            models.ShodanData.ip_address_id == ip_id
        ).first()

        if not shodan_record:
            shodan_record = models.ShodanData(ip_address_id=ip_id)
            db.add(shodan_record)

        # Convert Python lists and dicts to JSON strings before storing
        shodan_record.ports = json.dumps(shodan_data.get('ports', []))
        shodan_record.vulns = json.dumps(shodan_data.get('vulns', []))
        shodan_record.tags = json.dumps(shodan_data.get('tags', []))
        shodan_record.hostnames = json.dumps(shodan_data.get('hostnames', []))
        shodan_record.raw_data = json.dumps(shodan_data)
        shodan_record.last_update = datetime.utcnow()

        db.flush()
        return shodan_record

    @staticmethod
    def _save_alienvault_data(db: Session, ip_id: int, av_data: Dict) -> Optional[models.AlienVaultData]:
        """Save AlienVault data for an IP"""
        av_record = db.query(models.AlienVaultData).filter(
            models.AlienVaultData.ip_address_id == ip_id
        ).first()

        if not av_record:
            av_record = models.AlienVaultData(ip_address_id=ip_id)
            db.add(av_record)

        av_record.pulse_count = av_data.get('pulse_info', {}).get('count', 0)
        av_record.reputation = av_data.get('reputation', 0)
        av_record.activity_types = av_data.get('activity_types', [])
        av_record.raw_data = av_data

        db.flush()
        return av_record

    @staticmethod
    def _update_threat_score(db: Session, ip_record: models.IPAddress):
        """Calculate and update the overall threat score for an IP"""
        score = 0.0
        count = 0

        # VirusTotal score (0-100)
        if ip_record.virustotal_data:
            vt_total = (ip_record.virustotal_data.malicious_count or 0) + (ip_record.virustotal_data.suspicious_count or 0)
            if vt_total > 0:
                score += min(100, vt_total * 10)
                count += 1

        # AlienVault score (0-100)
        if ip_record.alienvault_data and ip_record.alienvault_data.reputation is not None:
            score += min(100, abs(ip_record.alienvault_data.reputation))
            count += 1

        # Shodan vulnerabilities score (0-100)
        if ip_record.shodan_data and ip_record.shodan_data.vulns:
            vuln_count = len(ip_record.shodan_data.vulns)
            score += min(100, vuln_count * 20)
            count += 1

        # Calculate final score (0-100)
        ip_record.overall_threat_score = score / max(1, count)
        ip_record.is_malicious = ip_record.overall_threat_score >= 50
        ip_record.last_updated = datetime.utcnow() 