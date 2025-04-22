from sqlalchemy import Column, Integer, String, DateTime, JSON, Float, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import json
from sqlalchemy.orm import Session
from typing import Dict, Optional
from database import get_db

Base = declarative_base()

# SQLite doesn't have a JSON type, so we'll create a custom type
class JSONString(String):
    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value)
        return None

    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value)
        return None

class IPAddress(Base):
    """Main table for storing IP addresses and their overall threat scores"""
    __tablename__ = 'ip_addresses'

    id = Column(Integer, primary_key=True)
    ip_address = Column(String, unique=True, nullable=False, index=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow)
    overall_threat_score = Column(Float, default=0.0)
    is_malicious = Column(Boolean, default=False)
    
    # Relationships
    virustotal_data = relationship("VirusTotalData", back_populates="ip", uselist=False)
    shodan_data = relationship("ShodanData", back_populates="ip", uselist=False)
    alienvault_data = relationship("AlienVaultData", back_populates="ip", uselist=False)
    abuseipdb_data = relationship("AbuseIPDBData", back_populates="ip", uselist=False)

class VirusTotalData(Base):
    """Store VirusTotal specific data"""
    __tablename__ = 'virustotal_data'

    id = Column(Integer, primary_key=True)
    ip_address_id = Column(Integer, ForeignKey('ip_addresses.id'), nullable=False)
    last_analysis_date = Column(DateTime)
    malicious_count = Column(Integer)
    suspicious_count = Column(Integer)
    harmless_count = Column(Integer)
    raw_data = Column(JSONString)  # Store complete API response
    last_updated = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    ip = relationship("IPAddress", back_populates="virustotal_data")

class ShodanData(Base):
    """Store Shodan specific data"""
    __tablename__ = 'shodan_data'

    id = Column(Integer, primary_key=True)
    ip_address_id = Column(Integer, ForeignKey('ip_addresses.id'), nullable=False)
    last_update = Column(DateTime)
    ports = Column(JSONString)  # Store open ports
    vulns = Column(JSONString)  # Store vulnerabilities
    tags = Column(JSONString)  # Store tags
    hostnames = Column(JSONString)  # Store hostnames
    raw_data = Column(JSONString)  # Store complete API response
    last_updated = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    ip = relationship("IPAddress", back_populates="shodan_data")

class AlienVaultData(Base):
    """Store AlienVault OTX specific data"""
    __tablename__ = 'alienvault_data'

    id = Column(Integer, primary_key=True)
    ip_address_id = Column(Integer, ForeignKey('ip_addresses.id'), nullable=False)
    pulse_count = Column(Integer)
    reputation = Column(Integer)
    activity_types = Column(JSONString)  # Store types of malicious activities
    raw_data = Column(JSONString)  # Store complete API response
    last_updated = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    ip = relationship("IPAddress", back_populates="alienvault_data")

class AbuseIPDBData(Base):
    """Store AbuseIPDB specific data"""
    __tablename__ = 'abuseipdb_data'

    id = Column(Integer, primary_key=True)
    ip_address_id = Column(Integer, ForeignKey('ip_addresses.id'), nullable=False)
    abuse_confidence_score = Column(Integer)
    total_reports = Column(Integer)
    last_reported_at = Column(DateTime)
    raw_data = Column(JSONString)  # Store complete API response
    last_updated = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    ip = relationship("IPAddress", back_populates="abuseipdb_data")

class ScanHistory(Base):
    """Track scanning history and results"""
    __tablename__ = 'scan_history'

    id = Column(Integer, primary_key=True)
    ip_address_id = Column(Integer, ForeignKey('ip_addresses.id'), nullable=False)
    scan_date = Column(DateTime, default=datetime.utcnow)
    scan_type = Column(String)  # Type of scan (full, partial, etc.)
    status = Column(String)  # Success, failed, partial
    error_message = Column(String, nullable=True)
    sources_checked = Column(JSONString)  # List of sources checked in this scan 