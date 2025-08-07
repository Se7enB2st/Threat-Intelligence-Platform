from sqlalchemy.orm import Session
from sqlalchemy import desc, func, and_, text
from datetime import datetime, timedelta
import json
from typing import List, Dict, Optional, Tuple
import math
from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import os
import requests

# Local imports
from .models.threat_models import (
    IPAddress, 
    VirusTotalData, 
    ShodanData, 
    AlienVaultData, 
    ScanHistory,
    DomainAnalysis
)
from threat_analyzer.database import get_db
from threat_analyzer.analyzers.domain_analyzer import DomainAnalyzer
from threat_analyzer.analyzers.ip_analyzer import IPAnalyzer
from threat_analyzer.threat_aggregation import ThreatAggregator

class ThreatAnalyzer:
    """Analyzes threat intelligence data from the database"""

    def __init__(self):
        self.app = Flask(__name__)
        CORS(self.app)
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def get_ip_details(db: Session, ip_address: str) -> Dict:
        """Get detailed information about an IP address"""
        ip_record = db.query(IPAddress).filter(IPAddress.ip_address == ip_address).first()
        
        # If IP doesn't exist or needs update, perform new analysis
        if not ip_record or (datetime.utcnow() - ip_record.last_updated).days >= 1:
            try:
                # Initialize IPAnalyzer with database session
                ip_analyzer = IPAnalyzer(db=db)
                
                # Get fresh analysis data
                analysis_data = ip_analyzer.analyze_ip(ip_address)
                
                # The IPAnalyzer.analyze_ip method now handles IP record creation
                # So we just need to get the updated record
                ip_record = db.query(IPAddress).filter(IPAddress.ip_address == ip_address).first()
                
                if not ip_record:
                    # This shouldn't happen, but just in case
                    logging.error(f"IP record not found after analysis for {ip_address}")
                    return {"error": "Failed to create IP record"}
                
                # Update the record with analysis results
                ip_record.last_updated = datetime.utcnow()
                ip_record.overall_threat_score = analysis_data.get('overall_threat_score', ip_record.overall_threat_score)
                ip_record.is_malicious = analysis_data.get('is_malicious', ip_record.is_malicious)
                
                # Update or create VirusTotal data
                if 'virustotal' in analysis_data.get('threat_data', {}):
                    vt_data = analysis_data['threat_data']['virustotal']
                    if ip_record.virustotal_data:
                        # Update existing VirusTotal data
                        ip_record.virustotal_data.last_analysis_date = datetime.fromisoformat(vt_data.get('last_analysis_date')) if vt_data.get('last_analysis_date') else None
                        ip_record.virustotal_data.malicious_count = vt_data.get('malicious_count', 0)
                        ip_record.virustotal_data.suspicious_count = vt_data.get('suspicious_count', 0)
                        ip_record.virustotal_data.harmless_count = vt_data.get('harmless_count', 0)
                        ip_record.virustotal_data.raw_data = json.dumps(vt_data)
                    else:
                        # Create new VirusTotal data
                        vt_record = VirusTotalData(
                            ip_address_id=ip_record.id,
                            last_analysis_date=datetime.fromisoformat(vt_data.get('last_analysis_date')) if vt_data.get('last_analysis_date') else None,
                            malicious_count=vt_data.get('malicious_count', 0),
                            suspicious_count=vt_data.get('suspicious_count', 0),
                            harmless_count=vt_data.get('harmless_count', 0),
                            raw_data=json.dumps(vt_data)
                        )
                        db.add(vt_record)

                # Update or create Shodan data
                if 'shodan' in analysis_data.get('threat_data', {}):
                    shodan_data = analysis_data['threat_data']['shodan']
                    if ip_record.shodan_data:
                        # Update existing Shodan data
                        ip_record.shodan_data.ports = json.dumps(shodan_data.get('ports', []))
                        ip_record.shodan_data.vulns = json.dumps(shodan_data.get('vulnerabilities', []))
                        ip_record.shodan_data.tags = json.dumps(shodan_data.get('tags', []))
                        ip_record.shodan_data.hostnames = json.dumps(shodan_data.get('hostnames', []))
                        ip_record.shodan_data.raw_data = json.dumps(shodan_data)
                    else:
                        # Create new Shodan data
                        shodan_record = ShodanData(
                            ip_address_id=ip_record.id,
                            ports=json.dumps(shodan_data.get('ports', [])),
                            vulns=json.dumps(shodan_data.get('vulnerabilities', [])),
                            tags=json.dumps(shodan_data.get('tags', [])),
                            hostnames=json.dumps(shodan_data.get('hostnames', [])),
                            raw_data=json.dumps(shodan_data)
                        )
                        db.add(shodan_record)

                # Update or create AlienVault data
                if 'alienvault' in analysis_data.get('threat_data', {}):
                    av_data = analysis_data['threat_data']['alienvault']
                    if ip_record.alienvault_data:
                        # Update existing AlienVault data
                        ip_record.alienvault_data.pulse_count = av_data.get('pulse_count')
                        ip_record.alienvault_data.reputation = av_data.get('reputation')
                        ip_record.alienvault_data.activity_types = json.dumps(av_data.get('activity_types', []))
                        ip_record.alienvault_data.raw_data = json.dumps(av_data)
                    else:
                        # Create new AlienVault data
                        av_record = AlienVaultData(
                            ip_address_id=ip_record.id,
                            pulse_count=av_data.get('pulse_count'),
                            reputation=av_data.get('reputation'),
                            activity_types=json.dumps(av_data.get('activity_types', [])),
                            raw_data=json.dumps(av_data)
                        )
                        db.add(av_record)

                # Add scan history
                scan_history = ScanHistory(
                    ip_address_id=ip_record.id,
                    scan_type='full',
                    status='success',
                    sources_checked=json.dumps(list(analysis_data.get('threat_data', {}).keys()))
                )
                db.add(scan_history)

                # Commit all changes
                db.commit()

            except Exception as e:
                db.rollback()
                return {"error": f"Error analyzing IP: {str(e)}"}

        # Return the results
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

    @staticmethod
    def analyze_threat_trends(db: Session, days: int = 30) -> Dict:
        """
        Analyze threat score trends over time
        Returns daily averages and identifies significant changes
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Get daily threat scores
        daily_scores = db.query(
            func.date(IPAddress.last_updated).label('date'),
            func.avg(IPAddress.overall_threat_score).label('avg_score'),
            func.count(IPAddress.id).label('ip_count')
        ).filter(
            IPAddress.last_updated >= cutoff_date
        ).group_by(
            func.date(IPAddress.last_updated)
        ).order_by(
            text('date')
        ).all()

        # Calculate trend data
        trend_data = []
        prev_score = None
        for day in daily_scores:
            change = None
            if prev_score is not None:
                change = ((day.avg_score - prev_score) / prev_score) * 100 if prev_score > 0 else 0
            
            trend_data.append({
                "date": day.date,
                "average_threat_score": round(day.avg_score, 2),
                "ips_analyzed": day.ip_count,
                "percentage_change": round(change, 2) if change is not None else None
            })
            prev_score = day.avg_score

        return {
            "trend_data": trend_data,
            "summary": {
                "start_date": trend_data[0]["date"] if trend_data else None,
                "end_date": trend_data[-1]["date"] if trend_data else None,
                "overall_trend": "increasing" if len(trend_data) > 1 and 
                    trend_data[-1]["average_threat_score"] > trend_data[0]["average_threat_score"]
                    else "decreasing"
            }
        }

    @staticmethod
    def analyze_source_correlation(db: Session) -> Dict:
        """
        Analyze correlation between different threat intelligence sources
        """
        ips = db.query(IPAddress).all()
        correlations = []

        for ip in ips:
            vt_score = 0
            if ip.virustotal_data:
                vt_total = (ip.virustotal_data.malicious_count or 0) + (ip.virustotal_data.suspicious_count or 0)
                vt_score = min(100, vt_total * 10)

            av_score = 0
            if ip.alienvault_data and ip.alienvault_data.reputation is not None:
                av_score = min(100, abs(ip.alienvault_data.reputation))

            shodan_score = 0
            if ip.shodan_data and ip.shodan_data.vulns:
                vuln_count = len(json.loads(ip.shodan_data.vulns))
                shodan_score = min(100, vuln_count * 20)

            correlations.append({
                "vt_score": vt_score,
                "av_score": av_score,
                "shodan_score": shodan_score
            })

        # Calculate correlation coefficients
        def calculate_correlation(x: List[float], y: List[float]) -> float:
            if not x or not y or len(x) != len(y):
                return 0
            n = len(x)
            sum_x = sum(x)
            sum_y = sum(y)
            sum_xy = sum(i * j for i, j in zip(x, y))
            sum_x2 = sum(i * i for i in x)
            sum_y2 = sum(i * i for i in y)
            
            try:
                correlation = (n * sum_xy - sum_x * sum_y) / (
                    math.sqrt(n * sum_x2 - sum_x * sum_x) * 
                    math.sqrt(n * sum_y2 - sum_y * sum_y)
                )
                return round(correlation, 3)
            except:
                return 0

        vt_scores = [c["vt_score"] for c in correlations]
        av_scores = [c["av_score"] for c in correlations]
        shodan_scores = [c["shodan_score"] for c in correlations]

        return {
            "correlations": {
                "virustotal_alienvault": calculate_correlation(vt_scores, av_scores),
                "virustotal_shodan": calculate_correlation(vt_scores, shodan_scores),
                "alienvault_shodan": calculate_correlation(av_scores, shodan_scores)
            },
            "interpretation": {
                "strongest_correlation": max([
                    ("VirusTotal-AlienVault", abs(calculate_correlation(vt_scores, av_scores))),
                    ("VirusTotal-Shodan", abs(calculate_correlation(vt_scores, shodan_scores))),
                    ("AlienVault-Shodan", abs(calculate_correlation(av_scores, shodan_scores)))
                ], key=lambda x: x[1])
            }
        }

    @staticmethod
    def analyze_port_exposure(db: Session) -> Dict:
        """
        Analyze common open ports and their security implications
        """
        common_ports = {
            "21": "FTP",
            "22": "SSH",
            "23": "Telnet",
            "25": "SMTP",
            "53": "DNS",
            "80": "HTTP",
            "443": "HTTPS",
            "3389": "RDP",
            "3306": "MySQL",
            "5432": "PostgreSQL"
        }
        
        port_stats = {}
        high_risk_ports = ["21", "23", "3389"]  # Ports considered high-risk
        
        shodan_records = db.query(ShodanData).all()
        for record in shodan_records:
            if record.ports:
                ports = json.loads(record.ports)
                for port in ports:
                    port_str = str(port)
                    if port_str not in port_stats:
                        port_stats[port_str] = {
                            "count": 0,
                            "service": common_ports.get(port_str, "Unknown"),
                            "is_high_risk": port_str in high_risk_ports
                        }
                    port_stats[port_str]["count"] += 1

        return {
            "port_statistics": sorted(
                [{"port": k, **v} for k, v in port_stats.items()],
                key=lambda x: x["count"],
                reverse=True
            ),
            "high_risk_exposure": {
                "total_high_risk_ports": sum(1 for p in port_stats.values() if p["is_high_risk"]),
                "most_exposed_high_risk": max(
                    ({"port": k, **v} for k, v in port_stats.items() if v["is_high_risk"]),
                    key=lambda x: x["count"],
                    default=None
                )
            }
        }

    @staticmethod
    def analyze_threat_patterns(db: Session, days: int = 30) -> Dict:
        """
        Analyze patterns in threat activities and identify potential attack campaigns
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Get IPs with significant threat changes
        threat_changes = db.query(IPAddress).filter(
            and_(
                IPAddress.last_updated >= cutoff_date,
                IPAddress.overall_threat_score >= 50
            )
        ).all()

        # Analyze AlienVault activity types
        activity_patterns = {}
        for ip in threat_changes:
            if ip.alienvault_data and ip.alienvault_data.activity_types:
                activities = json.loads(ip.alienvault_data.activity_types)
                for activity in activities:
                    if activity not in activity_patterns:
                        activity_patterns[activity] = {
                            "count": 0,
                            "average_threat_score": 0,
                            "ips": []
                        }
                    activity_patterns[activity]["count"] += 1
                    activity_patterns[activity]["average_threat_score"] += ip.overall_threat_score
                    activity_patterns[activity]["ips"].append(ip.ip_address)

        # Calculate averages and sort patterns
        for pattern in activity_patterns.values():
            pattern["average_threat_score"] = round(pattern["average_threat_score"] / pattern["count"], 2)

        return {
            "activity_patterns": sorted(
                [{"activity": k, **v} for k, v in activity_patterns.items()],
                key=lambda x: x["count"],
                reverse=True
            ),
            "potential_campaigns": [
                {
                    "activity": k,
                    "ip_count": v["count"],
                    "avg_threat_score": v["average_threat_score"]
                }
                for k, v in activity_patterns.items()
                if v["count"] >= 3 and v["average_threat_score"] >= 70
            ]
        }

    def get_ip_geographic_distribution(self, db: Session) -> List[Dict]:
        """Get geographic distribution of IPs"""
        # Implementation for getting geographic distribution
        pass

    def get_recent_activities(self, db: Session, limit: int = 5) -> List[Dict]:
        """Get recent scanning activities"""
        # Implementation for getting recent activities
        pass

    @staticmethod
    def get_historical_analysis(db: Session, start_date: datetime, end_date: datetime) -> Dict:
        """
        Get historical analysis data for a specified date range
        """
        try:
            # Convert dates to datetime with time
            start_datetime = datetime.combine(start_date, datetime.min.time())
            end_datetime = datetime.combine(end_date, datetime.max.time())
            
            # Get trend data
            trends = db.query(
                func.date(ScanHistory.scan_date).label('date'),
                func.avg(IPAddress.overall_threat_score).label('avg_score'),
                func.count(IPAddress.id).label('ip_count')
            ).join(
                IPAddress,
                ScanHistory.ip_address_id == IPAddress.id
            ).filter(
                ScanHistory.scan_date.between(start_datetime, end_datetime)
            ).group_by(
                func.date(ScanHistory.scan_date)
            ).order_by(
                text('date')
            ).all()
            
            trend_data = [{
                'date': trend.date,
                'avg_score': float(trend.avg_score) if trend.avg_score else 0.0,
                'ip_count': trend.ip_count
            } for trend in trends]
            
            # Get top malicious IPs
            malicious_ips = db.query(
                IPAddress.ip_address,
                IPAddress.overall_threat_score,
                func.count(ScanHistory.id).label('scan_count'),
                func.max(ScanHistory.scan_date).label('last_seen')
            ).join(
                ScanHistory,
                IPAddress.id == ScanHistory.ip_address_id
            ).filter(
                and_(
                    ScanHistory.scan_date.between(start_datetime, end_datetime),
                    IPAddress.is_malicious == True
                )
            ).group_by(
                IPAddress.id
            ).order_by(
                desc(IPAddress.overall_threat_score)
            ).limit(10).all()
            
            malicious_ip_data = [{
                'ip_address': ip.ip_address,
                'threat_score': float(ip.overall_threat_score),
                'scan_count': ip.scan_count,
                'last_seen': ip.last_seen.isoformat()
            } for ip in malicious_ips]
            
            # Get domain analysis data
            malicious_domains = db.query(
                DomainAnalysis.domain,
                DomainAnalysis.overall_threat_score,
                DomainAnalysis.last_updated
            ).filter(
                and_(
                    DomainAnalysis.last_updated.between(start_datetime, end_datetime),
                    DomainAnalysis.is_malicious == True
                )
            ).order_by(
                desc(DomainAnalysis.overall_threat_score)
            ).limit(10).all()
            
            malicious_domain_data = [{
                'domain': domain.domain,
                'threat_score': float(domain.overall_threat_score),
                'last_updated': domain.last_updated.isoformat()
            } for domain in malicious_domains]
            
            # Get domain trend data
            domain_trends = db.query(
                func.date(DomainAnalysis.last_updated).label('date'),
                func.avg(DomainAnalysis.overall_threat_score).label('avg_score'),
                func.count(DomainAnalysis.id).label('domain_count')
            ).filter(
                DomainAnalysis.last_updated.between(start_datetime, end_datetime)
            ).group_by(
                func.date(DomainAnalysis.last_updated)
            ).order_by(
                text('date')
            ).all()
            
            domain_trend_data = [{
                'date': trend.date,
                'avg_score': float(trend.avg_score) if trend.avg_score else 0.0,
                'domain_count': trend.domain_count
            } for trend in domain_trends]
            
            # Get total counts for the date range
            total_ips = db.query(func.count(IPAddress.id)).filter(
                IPAddress.last_updated.between(start_datetime, end_datetime)
            ).scalar()
            
            total_domains = db.query(func.count(DomainAnalysis.id)).filter(
                DomainAnalysis.last_updated.between(start_datetime, end_datetime)
            ).scalar()
            
            # Get malicious counts
            malicious_ip_count = db.query(func.count(IPAddress.id)).filter(
                and_(
                    IPAddress.last_updated.between(start_datetime, end_datetime),
                    IPAddress.is_malicious == True
                )
            ).scalar()
            
            malicious_domain_count = db.query(func.count(DomainAnalysis.id)).filter(
                and_(
                    DomainAnalysis.last_updated.between(start_datetime, end_datetime),
                    DomainAnalysis.is_malicious == True
                )
            ).scalar()
            
            # Analyze attack patterns
            patterns = []
            
            # Check for port scan patterns
            port_scan_ips = db.query(
                IPAddress.ip_address,
                ShodanData.ports
            ).join(
                ShodanData,
                IPAddress.id == ShodanData.ip_address_id
            ).filter(
                and_(
                    IPAddress.last_updated.between(start_datetime, end_datetime),
                    ShodanData.ports.isnot(None)
                )
            ).all()
            
            port_counts = {}
            for ip in port_scan_ips:
                if ip.ports:
                    ports = json.loads(ip.ports)
                    for port in ports:
                        port_counts[port] = port_counts.get(port, 0) + 1
            
            # Identify commonly targeted ports
            common_ports = sorted(
                [(port, count) for port, count in port_counts.items()],
                key=lambda x: x[1],
                reverse=True
            )[:5]
            
            if common_ports:
                patterns.append({
                    'description': f"Common targeted ports: {', '.join(str(p[0]) for p in common_ports)}",
                    'confidence': min(100, max(0, int(common_ports[0][1] / len(port_scan_ips) * 100)))
                })
            
            # Check for common malicious activities
            activity_patterns = db.query(
                AlienVaultData.activity_types,
                func.count(AlienVaultData.id).label('count')
            ).join(
                IPAddress,
                AlienVaultData.ip_address_id == IPAddress.id
            ).filter(
                IPAddress.last_updated.between(start_datetime, end_datetime)
            ).group_by(
                AlienVaultData.activity_types
            ).order_by(
                desc('count')
            ).limit(5).all()
            
            for pattern in activity_patterns:
                if pattern.activity_types:
                    activities = json.loads(pattern.activity_types)
                    if activities:
                        patterns.append({
                            'description': f"Common malicious activity: {', '.join(activities)}",
                            'confidence': min(100, max(0, int(pattern.count / len(activity_patterns) * 100)))
                        })
            
            return {
                'trends': trend_data,
                'top_malicious_ips': malicious_ip_data,
                'top_malicious_domains': malicious_domain_data,
                'domain_trends': domain_trend_data,
                'attack_patterns': patterns,
                'total_ips_analyzed': total_ips,
                'total_domains_analyzed': total_domains,
                'malicious_ips_count': malicious_ip_count,
                'malicious_domains_count': malicious_domain_count
            }
            
        except Exception as e:
            self.logger.error(f"Error getting historical analysis: {str(e)}")
            return None

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

        # Example 6: Analyze threat trends
        trends = ThreatAnalyzer.analyze_threat_trends(db)
        print("\nThreat Trends Analysis:")
        print(json.dumps(trends, indent=2))

        # Example 7: Analyze source correlation
        correlations = ThreatAnalyzer.analyze_source_correlation(db)
        print("\nSource Correlation Analysis:")
        print(json.dumps(correlations, indent=2))

        # Example 8: Analyze port exposure
        port_analysis = ThreatAnalyzer.analyze_port_exposure(db)
        print("\nPort Exposure Analysis:")
        print(json.dumps(port_analysis, indent=2))

        # Example 9: Analyze threat patterns
        patterns = ThreatAnalyzer.analyze_threat_patterns(db)
        print("\nThreat Patterns Analysis:")
        print(json.dumps(patterns, indent=2))

    finally:
        db.close() 