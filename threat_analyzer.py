from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from datetime import datetime, timedelta
import json
from typing import List, Dict, Optional
from models import IPAddress, VirusTotalData, ShodanData, AlienVaultData, ScanHistory
from database import get_db

class ThreatAnalyzer:
    """Analyzes threat intelligence data from the database"""

    @staticmethod
    def get_ip_details(db: Session, ip_address: str) -> Dict:
        """
        Get comprehensive details about an IP address from all sources
        """
        ip_record = db.query(IPAddress).filter(IPAddress.ip_address == ip_address).first()
        if not ip_record:
            return {"error": "IP address not found in database"}

        result = {
            "ip_address": ip_record.ip_address,
            "first_seen": ip_record.first_seen.isoformat(),
            "last_updated": ip_record.last_updated.isoformat(),
            "overall_threat_score": ip_record.overall_threat_score,
            "is_malicious": ip_record.is_malicious,
            "threat_data": {
                "virustotal": None,
                "shodan": None,
                "alienvault": None
            }
        }

        # Add VirusTotal data if available
        if ip_record.virustotal_data:
            result["threat_data"]["virustotal"] = {
                "malicious_count": ip_record.virustotal_data.malicious_count,
                "suspicious_count": ip_record.virustotal_data.suspicious_count,
                "harmless_count": ip_record.virustotal_data.harmless_count,
                "last_analysis_date": ip_record.virustotal_data.last_analysis_date.isoformat() if ip_record.virustotal_data.last_analysis_date else None
            }

        # Add Shodan data if available
        if ip_record.shodan_data:
            result["threat_data"]["shodan"] = {
                "ports": json.loads(ip_record.shodan_data.ports) if ip_record.shodan_data.ports else [],
                "vulnerabilities": json.loads(ip_record.shodan_data.vulns) if ip_record.shodan_data.vulns else [],
                "tags": json.loads(ip_record.shodan_data.tags) if ip_record.shodan_data.tags else [],
                "hostnames": json.loads(ip_record.shodan_data.hostnames) if ip_record.shodan_data.hostnames else []
            }

        # Add AlienVault data if available
        if ip_record.alienvault_data:
            result["threat_data"]["alienvault"] = {
                "pulse_count": ip_record.alienvault_data.pulse_count,
                "reputation": ip_record.alienvault_data.reputation,
                "activity_types": json.loads(ip_record.alienvault_data.activity_types) if ip_record.alienvault_data.activity_types else []
            }

        return result

    @staticmethod
    def get_high_risk_ips(db: Session, min_threat_score: float = 70.0) -> List[Dict]:
        """
        Get all IPs with high threat scores
        """
        high_risk_ips = db.query(IPAddress).filter(
            IPAddress.overall_threat_score >= min_threat_score
        ).order_by(desc(IPAddress.overall_threat_score)).all()

        return [{
            "ip_address": ip.ip_address,
            "threat_score": ip.overall_threat_score,
            "last_updated": ip.last_updated.isoformat()
        } for ip in high_risk_ips]

    @staticmethod
    def get_recent_scans(db: Session, hours: int = 24) -> List[Dict]:
        """
        Get all scans from the last X hours
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        recent_scans = db.query(ScanHistory).filter(
            ScanHistory.scan_date >= cutoff_time
        ).order_by(desc(ScanHistory.scan_date)).all()

        return [{
            "ip_address": scan.ip_address_id,
            "scan_date": scan.scan_date.isoformat(),
            "scan_type": scan.scan_type,
            "status": scan.status,
            "sources_checked": json.loads(scan.sources_checked) if scan.sources_checked else {}
        } for scan in recent_scans]

    @staticmethod
    def get_common_vulnerabilities(db: Session) -> List[Dict]:
        """
        Analyze common vulnerabilities found across all IPs
        """
        vulns_count = {}
        shodan_records = db.query(ShodanData).all()
        
        for record in shodan_records:
            if record.vulns:
                vulns = json.loads(record.vulns)
                for vuln in vulns:
                    vulns_count[vuln] = vulns_count.get(vuln, 0) + 1

        return [{
            "vulnerability": vuln,
            "count": count
        } for vuln, count in sorted(vulns_count.items(), key=lambda x: x[1], reverse=True)]

    @staticmethod
    def get_statistics(db: Session) -> Dict:
        """
        Get overall statistics about the threat intelligence data
        """
        total_ips = db.query(func.count(IPAddress.id)).scalar()
        malicious_ips = db.query(func.count(IPAddress.id)).filter(IPAddress.is_malicious == True).scalar()
        avg_threat_score = db.query(func.avg(IPAddress.overall_threat_score)).scalar() or 0

        return {
            "total_ips_tracked": total_ips,
            "malicious_ips_count": malicious_ips,
            "average_threat_score": round(avg_threat_score, 2),
            "malicious_ip_percentage": round((malicious_ips / total_ips * 100) if total_ips > 0 else 0, 2)
        }

# Example usage
if __name__ == "__main__":
    db = next(get_db())
    try:
        # Example 1: Get details for a specific IP
        ip_details = ThreatAnalyzer.get_ip_details(db, "8.8.8.8")
        print("\nIP Details:")
        print(json.dumps(ip_details, indent=2))

        # Example 2: Get high risk IPs
        high_risk = ThreatAnalyzer.get_high_risk_ips(db)
        print("\nHigh Risk IPs:")
        print(json.dumps(high_risk, indent=2))

        # Example 3: Get recent scans
        recent_scans = ThreatAnalyzer.get_recent_scans(db)
        print("\nRecent Scans:")
        print(json.dumps(recent_scans, indent=2))

        # Example 4: Get common vulnerabilities
        vulnerabilities = ThreatAnalyzer.get_common_vulnerabilities(db)
        print("\nCommon Vulnerabilities:")
        print(json.dumps(vulnerabilities, indent=2))

        # Example 5: Get overall statistics
        stats = ThreatAnalyzer.get_statistics(db)
        print("\nOverall Statistics:")
        print(json.dumps(stats, indent=2))

    finally:
        db.close() 