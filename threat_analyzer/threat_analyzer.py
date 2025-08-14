from sqlalchemy.orm import Session
from sqlalchemy import desc, func, and_, text, case
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
    def analyze_vulnerability_severity(db: Session) -> Dict:
        """
        Analyze vulnerability severity distribution and categorize vulnerabilities
        """
        try:
            # Ensure clean transaction state
            db.rollback()
            
            severity_categories = {
                'Critical': ['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2021-45105'],  # Log4j variants
                'High': ['CVE-2021-34527', 'CVE-2021-34484', 'CVE-2021-34523'],      # ProxyShell
                'Medium': ['CVE-2021-26855', 'CVE-2021-26857', 'CVE-2021-26858'],    # Exchange
                'Low': ['CVE-2021-26867', 'CVE-2021-26868', 'CVE-2021-26869']        # Exchange
            }
            
            # Default severity mapping for common vulnerabilities
            default_severity = {
                'CVE-2021-44228': 'Critical',
                'CVE-2021-45046': 'Critical', 
                'CVE-2021-45105': 'Critical',
                'CVE-2021-34527': 'High',
                'CVE-2021-34484': 'High',
                'CVE-2021-34523': 'High',
                'CVE-2021-26855': 'Medium',
                'CVE-2021-26857': 'Medium',
                'CVE-2021-26858': 'Medium',
                'CVE-2021-26867': 'Low',
                'CVE-2021-26868': 'Low',
                'CVE-2021-26869': 'Low'
            }
            
            severity_stats = {
                'Critical': {'count': 0, 'vulnerabilities': []},
                'High': {'count': 0, 'vulnerabilities': []},
                'Medium': {'count': 0, 'vulnerabilities': []},
                'Low': {'count': 0, 'vulnerabilities': []},
                'Unknown': {'count': 0, 'vulnerabilities': []}
            }
            
            shodan_records = db.query(ShodanData).all()
            
            for record in shodan_records:
                if record.vulns:
                    vulns = json.loads(record.vulns)
                    for vuln in vulns:
                        severity = default_severity.get(vuln, 'Unknown')
                        severity_stats[severity]['count'] += 1
                        if vuln not in severity_stats[severity]['vulnerabilities']:
                            severity_stats[severity]['vulnerabilities'].append(vuln)
            
            return {
                'severity_distribution': severity_stats,
                'total_vulnerabilities': sum(stats['count'] for stats in severity_stats.values()),
                'most_common_severity': max(severity_stats.items(), key=lambda x: x[1]['count'])[0] if any(stats['count'] > 0 for stats in severity_stats.values()) else 'None'
            }
        except Exception as e:
            logger.error(f"Error in analyze_vulnerability_severity: {str(e)}")
            return {
                'severity_distribution': {
                    'Critical': {'count': 0, 'vulnerabilities': []},
                    'High': {'count': 0, 'vulnerabilities': []},
                    'Medium': {'count': 0, 'vulnerabilities': []},
                    'Low': {'count': 0, 'vulnerabilities': []},
                    'Unknown': {'count': 0, 'vulnerabilities': []}
                },
                'total_vulnerabilities': 0,
                'most_common_severity': 'None'
            }

    @staticmethod
    def analyze_cve_correlations(db: Session) -> Dict:
        """
        Analyze correlations between different CVEs and identify common attack patterns
        """
        try:
            # Ensure clean transaction state
            db.rollback()
            
            cve_cooccurrence = {}
            ip_vulnerabilities = {}
            
            shodan_records = db.query(ShodanData).all()
            
            # Build IP to vulnerabilities mapping
            for record in shodan_records:
                if record.vulns:
                    vulns = json.loads(record.vulns)
                    ip_vulnerabilities[record.ip_address_id] = vulns
                    
                    # Build co-occurrence matrix
                    for i, vuln1 in enumerate(vulns):
                        for vuln2 in vulns[i+1:]:
                            pair = tuple(sorted([vuln1, vuln2]))
                            cve_cooccurrence[pair] = cve_cooccurrence.get(pair, 0) + 1
            
            # Find most common CVE pairs
            common_pairs = sorted(cve_cooccurrence.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Analyze attack patterns
            attack_patterns = []
            for (cve1, cve2), count in common_pairs:
                if count >= 2:  # Only consider patterns that appear multiple times
                    attack_patterns.append({
                        'cve_pair': [cve1, cve2],
                        'cooccurrence_count': count,
                        'description': f"Common attack pattern: {cve1} + {cve2}"
                    })
            
            return {
                'cve_cooccurrence': [{
                    'cve_pair': list(pair),
                    'count': count
                } for pair, count in common_pairs],
                'attack_patterns': attack_patterns,
                'total_unique_cves': len(set(vuln for vulns in ip_vulnerabilities.values() for vuln in vulns)),
                'ips_with_vulnerabilities': len(ip_vulnerabilities)
            }
        except Exception as e:
            logger.error(f"Error in analyze_cve_correlations: {str(e)}")
            return {
                'cve_cooccurrence': [],
                'attack_patterns': [],
                'total_unique_cves': 0,
                'ips_with_vulnerabilities': 0
            }

    @staticmethod
    def analyze_vulnerability_trends(db: Session, days: int = 30) -> Dict:
        """
        Analyze vulnerability trends over time
        """
        try:
            # Ensure clean transaction state
            db.rollback()
            
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Get daily vulnerability counts
            daily_vulns = db.query(
                func.date(IPAddress.last_updated).label('date'),
                func.count(ShodanData.id).label('vuln_records'),
                func.sum(func.jsonb_array_length(text("shodan_data.vulns::jsonb"))).label('total_vulns')
            ).join(
                ShodanData,
                IPAddress.id == ShodanData.ip_address_id
            ).filter(
                and_(
                    IPAddress.last_updated >= cutoff_date,
                    ShodanData.vulns.isnot(None)
                )
            ).group_by(
                func.date(IPAddress.last_updated)
            ).order_by(
                text('date')
            ).all()
            
            trend_data = [{
                'date': day.date,
                'vulnerability_records': day.vuln_records,
                'total_vulnerabilities': int(day.total_vulns) if day.total_vulns else 0,
                'avg_vulns_per_ip': round(float(day.total_vulns) / day.vuln_records, 2) if day.vuln_records > 0 else 0
            } for day in daily_vulns]
            
            # Calculate trend direction
            if len(trend_data) > 1:
                first_avg = trend_data[0]['avg_vulns_per_ip']
                last_avg = trend_data[-1]['avg_vulns_per_ip']
                trend_direction = 'increasing' if last_avg > first_avg else 'decreasing' if last_avg < first_avg else 'stable'
            else:
                trend_direction = 'insufficient_data'
            
            return {
                'daily_trends': trend_data,
                'trend_direction': trend_direction,
                'total_days_analyzed': len(trend_data),
                'peak_vulnerability_day': max(trend_data, key=lambda x: x['total_vulnerabilities']) if trend_data else None
            }
        except Exception as e:
            logger.error(f"Error in analyze_vulnerability_trends: {str(e)}")
            return {
                'daily_trends': [],
                'trend_direction': 'insufficient_data',
                'total_days_analyzed': 0,
                'peak_vulnerability_day': None
            }

    @staticmethod
    def get_vulnerability_statistics(db: Session) -> Dict:
        """
        Get comprehensive vulnerability statistics
        """
        try:
            # Ensure clean transaction state
            db.rollback()
            
            # Get basic vulnerability stats
            total_ips_with_vulns = db.query(func.count(ShodanData.ip_address_id.distinct())).filter(
                ShodanData.vulns.isnot(None)
            ).scalar()
            
            total_vulns = db.query(
                func.sum(func.jsonb_array_length(text("shodan_data.vulns::jsonb")))
            ).filter(
                ShodanData.vulns.isnot(None)
            ).scalar()
            
            # Get most vulnerable IPs
            most_vulnerable_ips = db.query(
                IPAddress.ip_address,
                func.jsonb_array_length(text("shodan_data.vulns::jsonb")).label('vuln_count'),
                IPAddress.overall_threat_score
            ).join(
                ShodanData,
                IPAddress.id == ShodanData.ip_address_id
            ).filter(
                ShodanData.vulns.isnot(None)
            ).order_by(
                desc('vuln_count')
            ).limit(10).all()
            
            # Get vulnerability by port analysis
            port_vulns = {}
            shodan_records = db.query(ShodanData).filter(
                and_(
                    ShodanData.vulns.isnot(None),
                    ShodanData.ports.isnot(None)
                )
            ).all()
            
            for record in shodan_records:
                if record.ports and record.vulns:
                    ports = json.loads(record.ports)
                    vulns = json.loads(record.vulns)
                    for port in ports:
                        if port not in port_vulns:
                            port_vulns[port] = {'count': 0, 'vulnerabilities': set()}
                        port_vulns[port]['count'] += 1
                        port_vulns[port]['vulnerabilities'].update(vulns)
            
            # Convert sets to lists for JSON serialization
            port_vulnerability_analysis = [{
                'port': port,
                'ip_count': data['count'],
                'unique_vulnerabilities': list(data['vulnerabilities'])
            } for port, data in sorted(port_vulns.items(), key=lambda x: x[1]['count'], reverse=True)]
            
            return {
                'total_ips_with_vulnerabilities': total_ips_with_vulns,
                'total_vulnerabilities_found': int(total_vulns) if total_vulns else 0,
                'average_vulnerabilities_per_ip': round(float(total_vulns) / total_ips_with_vulns, 2) if total_ips_with_vulns > 0 else 0,
                'most_vulnerable_ips': [{
                    'ip_address': ip.ip_address,
                    'vulnerability_count': ip.vuln_count,
                    'threat_score': float(ip.overall_threat_score)
                } for ip in most_vulnerable_ips],
                'port_vulnerability_analysis': port_vulnerability_analysis[:10]  # Top 10 most vulnerable ports
            }
        except Exception as e:
            logger.error(f"Error in get_vulnerability_statistics: {str(e)}")
            return {
                'total_ips_with_vulnerabilities': 0,
                'total_vulnerabilities_found': 0,
                'average_vulnerabilities_per_ip': 0,
                'most_vulnerable_ips': [],
                'port_vulnerability_analysis': []
            }

    @staticmethod
    def analyze_zero_day_vulnerabilities(db: Session) -> Dict:
        """
        Analyze potential zero-day vulnerabilities and emerging threats
        """
        try:
            # Ensure clean transaction state
            db.rollback()
            
            # This is a placeholder for zero-day analysis
            # In a real implementation, this would integrate with threat feeds
            # and analyze patterns that might indicate zero-day exploits
            
            # For now, we'll analyze vulnerabilities that appear frequently
            # but don't have well-known CVE patterns
            vuln_patterns = {}
            shodan_records = db.query(ShodanData).all()
            
            for record in shodan_records:
                if record.vulns:
                    vulns = json.loads(record.vulns)
                    for vuln in vulns:
                        # Check if it's a known CVE pattern
                        if not vuln.startswith('CVE-'):
                            vuln_patterns[vuln] = vuln_patterns.get(vuln, 0) + 1
            
            # Find potential zero-day candidates (frequent but unknown patterns)
            potential_zero_days = [
                {'vulnerability': vuln, 'count': count}
                for vuln, count in sorted(vuln_patterns.items(), key=lambda x: x[1], reverse=True)
                if count >= 2  # Only consider if it appears multiple times
            ][:5]
            
            return {
                'potential_zero_days': potential_zero_days,
                'total_unknown_vulnerabilities': len(vuln_patterns),
                'analysis_note': 'This analysis identifies vulnerabilities that do not follow standard CVE patterns and may represent emerging threats.'
            }
        except Exception as e:
            logger.error(f"Error in analyze_zero_day_vulnerabilities: {str(e)}")
            return {
                'potential_zero_days': [],
                'total_unknown_vulnerabilities': 0,
                'analysis_note': 'Analysis failed due to database error.'
            }

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
            # Ensure clean transaction state
            db.rollback()
            # Convert dates to datetime with time
            start_datetime = datetime.combine(start_date, datetime.min.time())
            end_datetime = datetime.combine(end_date, datetime.max.time())
            
            # Get trend data - use IPAddress directly instead of ScanHistory
            trends = db.query(
                func.date(IPAddress.last_updated).label('date'),
                func.avg(IPAddress.overall_threat_score).label('avg_score'),
                func.count(IPAddress.id).label('ip_count')
            ).filter(
                IPAddress.last_updated.between(start_datetime, end_datetime)
            ).group_by(
                func.date(IPAddress.last_updated)
            ).order_by(
                text('date')
            ).all()
            
            trend_data = [{
                'date': trend.date,
                'avg_score': float(trend.avg_score) if trend.avg_score else 0.0,
                'ip_count': trend.ip_count
            } for trend in trends]
            
            # Get top malicious IPs - use IPAddress directly
            malicious_ips = db.query(
                IPAddress.ip_address,
                IPAddress.overall_threat_score,
                func.count(IPAddress.id).label('scan_count'),
                func.max(IPAddress.last_updated).label('last_seen')
            ).filter(
                and_(
                    IPAddress.last_updated.between(start_datetime, end_datetime),
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
            
            # Get threat score distribution for IPs
            ip_score_distribution = db.query(
                func.count(IPAddress.id).label('count'),
                case(
                    (IPAddress.overall_threat_score < 20, 'Low (0-19)'),
                    (IPAddress.overall_threat_score < 40, 'Medium-Low (20-39)'),
                    (IPAddress.overall_threat_score < 60, 'Medium (40-59)'),
                    (IPAddress.overall_threat_score < 80, 'Medium-High (60-79)'),
                    (IPAddress.overall_threat_score < 100, 'High (80-99)'),
                    else_='Critical (100)'
                ).label('score_range')
            ).filter(
                IPAddress.last_updated.between(start_datetime, end_datetime)
            ).group_by(
                text('score_range')
            ).order_by(
                text('score_range')
            ).all()
            
            ip_score_distribution_data = [{
                'range': item.score_range,
                'count': item.count,
                'percentage': round((item.count / total_ips * 100) if total_ips > 0 else 0, 2)
            } for item in ip_score_distribution]
            
            # Get threat score distribution for domains
            domain_score_distribution = db.query(
                func.count(DomainAnalysis.id).label('count'),
                case(
                    (DomainAnalysis.overall_threat_score < 20, 'Low (0-19)'),
                    (DomainAnalysis.overall_threat_score < 40, 'Medium-Low (20-39)'),
                    (DomainAnalysis.overall_threat_score < 60, 'Medium (40-59)'),
                    (DomainAnalysis.overall_threat_score < 80, 'Medium-High (60-79)'),
                    (DomainAnalysis.overall_threat_score < 100, 'High (80-99)'),
                    else_='Critical (100)'
                ).label('score_range')
            ).filter(
                DomainAnalysis.last_updated.between(start_datetime, end_datetime)
            ).group_by(
                text('score_range')
            ).order_by(
                text('score_range')
            ).all()
            
            domain_score_distribution_data = [{
                'range': item.score_range,
                'count': item.count,
                'percentage': round((item.count / total_domains * 100) if total_domains > 0 else 0, 2)
            } for item in domain_score_distribution]
            
            # Get geographic distribution of threats (from Shodan raw data)
            geographic_distribution = []
            country_stats = {}
            
            # Query IPs with Shodan data and extract geographic info from raw_data
            shodan_ips = db.query(
                IPAddress.id,
                IPAddress.ip_address,
                IPAddress.overall_threat_score,
                IPAddress.is_malicious,
                ShodanData.raw_data
            ).join(
                ShodanData,
                IPAddress.id == ShodanData.ip_address_id
            ).filter(
                and_(
                    IPAddress.last_updated.between(start_datetime, end_datetime),
                    ShodanData.raw_data.isnot(None)
                )
            ).all()
            
            # Process geographic data from raw Shodan data
            for ip in shodan_ips:
                if ip.raw_data and isinstance(ip.raw_data, dict):
                    country_code = ip.raw_data.get('country_code', 'Unknown')
                    city = ip.raw_data.get('city', 'Unknown')
                    
                    # Update geographic distribution
                    geo_key = f"{country_code}_{city}"
                    if geo_key not in [g['key'] for g in geographic_distribution]:
                        geographic_distribution.append({
                            'key': geo_key,
                            'country_code': country_code,
                            'city': city,
                            'count': 1,
                            'avg_threat_score': ip.overall_threat_score,
                            'total_threat_score': ip.overall_threat_score
                        })
                    else:
                        for geo in geographic_distribution:
                            if geo['key'] == geo_key:
                                geo['count'] += 1
                                geo['total_threat_score'] += ip.overall_threat_score
                                geo['avg_threat_score'] = geo['total_threat_score'] / geo['count']
                                break
                    
                    # Update country statistics
                    if country_code not in country_stats:
                        country_stats[country_code] = {
                            'total_ips': 0,
                            'malicious_ips': 0,
                            'total_threat_score': 0,
                            'max_threat_score': 0
                        }
                    
                    country_stats[country_code]['total_ips'] += 1
                    country_stats[country_code]['total_threat_score'] += ip.overall_threat_score
                    country_stats[country_code]['max_threat_score'] = max(
                        country_stats[country_code]['max_threat_score'], 
                        ip.overall_threat_score
                    )
                    if ip.is_malicious:
                        country_stats[country_code]['malicious_ips'] += 1
            
            # Convert to final format
            geographic_data = [{
                'country_code': item['country_code'],
                'city': item['city'],
                'count': item['count'],
                'avg_threat_score': round(item['avg_threat_score'], 2),
                'percentage': round((item['count'] / total_ips * 100) if total_ips > 0 else 0, 2)
            } for item in geographic_distribution]
            
            country_statistics = [{
                'country_code': country_code,
                'total_ips': stats['total_ips'],
                'malicious_ips': stats['malicious_ips'],
                'malicious_percentage': round((stats['malicious_ips'] / stats['total_ips'] * 100) if stats['total_ips'] > 0 else 0, 2),
                'avg_threat_score': round(stats['total_threat_score'] / stats['total_ips'], 2) if stats['total_ips'] > 0 else 0.0,
                'max_threat_score': stats['max_threat_score']
            } for country_code, stats in country_stats.items()]
            
            # Sort by count for geographic data and by total_ips for country stats
            geographic_data.sort(key=lambda x: x['count'], reverse=True)
            country_statistics.sort(key=lambda x: x['total_ips'], reverse=True)
            
            # Limit results
            geographic_data = geographic_data[:10]
            country_statistics = country_statistics[:5]
            
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
            
            # Get vulnerability analysis data with error handling
            try:
                vulnerability_severity = ThreatAnalyzer.analyze_vulnerability_severity(db)
            except Exception as e:
                logging.error(f"Error in vulnerability_severity: {str(e)}")
                vulnerability_severity = {
                    'severity_distribution': {
                        'Critical': {'count': 0, 'vulnerabilities': []},
                        'High': {'count': 0, 'vulnerabilities': []},
                        'Medium': {'count': 0, 'vulnerabilities': []},
                        'Low': {'count': 0, 'vulnerabilities': []},
                        'Unknown': {'count': 0, 'vulnerabilities': []}
                    },
                    'total_vulnerabilities': 0,
                    'most_common_severity': 'None'
                }
            
            try:
                cve_correlations = ThreatAnalyzer.analyze_cve_correlations(db)
            except Exception as e:
                logging.error(f"Error in cve_correlations: {str(e)}")
                cve_correlations = {
                    'common_cve_pairs': [],
                    'attack_patterns': [],
                    'total_correlations': 0
                }
            
            try:
                vulnerability_trends = ThreatAnalyzer.analyze_vulnerability_trends(db, 30)
            except Exception as e:
                logging.error(f"Error in vulnerability_trends: {str(e)}")
                vulnerability_trends = {
                    'daily_trends': [],
                    'trend_direction': 'insufficient_data',
                    'total_days_analyzed': 0,
                    'peak_vulnerability_day': None
                }
            
            try:
                vulnerability_stats = ThreatAnalyzer.get_vulnerability_statistics(db)
            except Exception as e:
                logging.error(f"Error in vulnerability_stats: {str(e)}")
                vulnerability_stats = {
                    'total_ips_with_vulns': 0,
                    'total_vulnerabilities': 0,
                    'avg_vulns_per_ip': 0,
                    'most_vulnerable_ips': [],
                    'port_vulnerability_analysis': []
                }
            
            try:
                zero_day_analysis = ThreatAnalyzer.analyze_zero_day_vulnerabilities(db)
            except Exception as e:
                logging.error(f"Error in zero_day_analysis: {str(e)}")
                zero_day_analysis = {
                    'potential_zero_days': [],
                    'non_cve_patterns': [],
                    'total_candidates': 0
                }
            
            return {
                'trends': trend_data,
                'top_malicious_ips': malicious_ip_data,
                'top_malicious_domains': malicious_domain_data,
                'domain_trends': domain_trend_data,
                'attack_patterns': patterns,
                'total_ips_analyzed': total_ips,
                'total_domains_analyzed': total_domains,
                'malicious_ips_count': malicious_ip_count,
                'malicious_domains_count': malicious_domain_count,
                'ip_score_distribution': ip_score_distribution_data,
                'domain_score_distribution': domain_score_distribution_data,
                'geographic_distribution': geographic_data,
                'country_statistics': country_statistics,
                'vulnerability_analysis': {
                    'severity_distribution': vulnerability_severity,
                    'cve_correlations': cve_correlations,
                    'vulnerability_trends': vulnerability_trends,
                    'vulnerability_statistics': vulnerability_stats,
                    'zero_day_analysis': zero_day_analysis
                }
            }
            
        except Exception as e:
            logging.error(f"Error getting historical analysis: {str(e)}")
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