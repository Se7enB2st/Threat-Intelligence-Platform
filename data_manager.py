from sqlalchemy.orm import Session
from datetime import datetime
from typing import Dict, Optional, List
import models
from database import get_db
import json
import ipaddress
import pandas as pd
import random

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

    def get_training_data(self, db: Session) -> pd.DataFrame:
        """
        Get historical data for ML model training
        """
        try:
            # Get all IP records with their related data
            ip_records = db.query(models.IPAddress).all()
            training_data = []

            for ip in ip_records:
                try:
                    # Get related data
                    vt_data = ip.virustotal_data
                    shodan_data = ip.shodan_data
                    av_data = ip.alienvault_data

                    # Parse Shodan data safely
                    shodan_ports = []
                    shodan_vulns = []
                    if shodan_data:
                        if shodan_data.ports:
                            try:
                                shodan_ports = json.loads(shodan_data.ports) if isinstance(shodan_data.ports, str) else []
                            except:
                                shodan_ports = []
                        if shodan_data.vulns:
                            try:
                                shodan_vulns = json.loads(shodan_data.vulns) if isinstance(shodan_data.vulns, str) else []
                            except:
                                shodan_vulns = []

                    # Create feature dictionary with consistent ordering
                    features = {
                        'ip_address': ip.ip_address,
                        'is_malicious': bool(ip.is_malicious),
                        'vt_malicious_count': vt_data.malicious_count if vt_data else 0,
                        'vt_suspicious_count': vt_data.suspicious_count if vt_data else 0,
                        'shodan_vuln_count': len(shodan_vulns),
                        'shodan_port_count': len(shodan_ports),
                        'av_pulse_count': av_data.pulse_count if av_data else 0,
                        'av_reputation': av_data.reputation if av_data else 0,
                        'port_risk_score': self._calculate_port_risk(shodan_ports),
                        'update_frequency': (
                            (ip.last_updated - ip.first_seen).days 
                            if ip.last_updated and ip.first_seen else 0
                        ),
                        'geographic_risk': self._calculate_geographic_risk(ip)
                    }
                    
                    training_data.append(features)
                except Exception as e:
                    print(f"Error processing IP {ip.ip_address}: {str(e)}")
                    continue

            # Convert to DataFrame
            df = pd.DataFrame(training_data)
            
            # Handle missing values
            df = df.fillna(0)
            
            # Ensure we have enough data
            if len(df) < 10:
                # Add synthetic data for initial training
                synthetic_data = self._generate_synthetic_data(100)
                df = pd.concat([df, pd.DataFrame(synthetic_data)], ignore_index=True)

            return df

        except Exception as e:
            raise Exception(f"Error getting training data: {str(e)}")

    def _calculate_port_risk(self, ports: List[int]) -> float:
        """Calculate risk score based on open ports"""
        high_risk_ports = {21, 23, 3389, 445, 135, 137, 138, 139}
        medium_risk_ports = {80, 443, 8080, 8443, 22}
        
        risk_score = 0
        for port in ports:
            if port in high_risk_ports:
                risk_score += 10
            elif port in medium_risk_ports:
                risk_score += 5
            else:
                risk_score += 1
        
        return min(100, risk_score)

    def _calculate_geographic_risk(self, ip_record: models.IPAddress) -> float:
        """Calculate risk score based on geographic location"""
        # Get country code from Shodan data if available
        country_code = None
        if ip_record.shodan_data and ip_record.shodan_data.raw_data:
            try:
                shodan_raw = json.loads(ip_record.shodan_data.raw_data)
                country_code = shodan_raw.get('country_code', '')
            except:
                pass

        # Define high-risk countries
        high_risk_countries = {'CN', 'RU', 'IR', 'KP', 'SY'}
        medium_risk_countries = {'BR', 'IN', 'NG', 'VN', 'ID'}
        
        if country_code in high_risk_countries:
            return 100
        elif country_code in medium_risk_countries:
            return 50
        return 0

    def _generate_synthetic_data(self, n_samples: int) -> List[Dict]:
        """
        Generate synthetic data for initial model training
        """
        synthetic_data = []
        
        # Define ranges for features
        feature_ranges = {
            'vt_malicious_count': (0, 50),
            'vt_suspicious_count': (0, 30),
            'shodan_vuln_count': (0, 20),
            'shodan_port_count': (0, 100),
            'av_pulse_count': (0, 100),
            'av_reputation': (-100, 100),
            'port_risk_score': (0, 100),
            'update_frequency': (0, 365),
            'geographic_risk': (0, 100)
        }
        
        for _ in range(n_samples):
            # Generate random features
            features = {
                'ip_address': f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}",
            }
            
            # Generate random values for each feature
            for feature, (min_val, max_val) in feature_ranges.items():
                features[feature] = random.uniform(min_val, max_val)
            
            # Determine if IP is malicious based on feature values
            malicious_score = (
                features['vt_malicious_count'] * 0.3 +
                features['shodan_vuln_count'] * 0.2 +
                features['port_risk_score'] * 0.2 +
                features['geographic_risk'] * 0.2 +
                abs(features['av_reputation']) * 0.1
            ) / 100
            
            features['is_malicious'] = malicious_score > 0.7
            
            synthetic_data.append(features)
        
        return synthetic_data 