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

class JSONEncodedString(String):
    """Custom type to handle JSON serialization/deserialization"""
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

class VirusTotalData(Base):
    """Store VirusTotal specific data"""
    __tablename__ = 'virustotal_data'

    id = Column(Integer, primary_key=True)
    ip_address_id = Column(Integer, ForeignKey('ip_addresses.id'), nullable=False)
    last_analysis_date = Column(DateTime)
    malicious_count = Column(Integer)
    suspicious_count = Column(Integer)
    harmless_count = Column(Integer)
    raw_data = Column(String)  # Changed from JSONString to String
    last_updated = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    ip = relationship("IPAddress", back_populates="virustotal_data")

    def get_raw_data(self) -> Dict:
        """Get raw data as Python dictionary"""
        import json
        return json.loads(self.raw_data) if self.raw_data else {}

class ShodanData(Base):
    """Store Shodan specific data"""
    __tablename__ = 'shodan_data'

    id = Column(Integer, primary_key=True)
    ip_address_id = Column(Integer, ForeignKey('ip_addresses.id'), nullable=False)
    last_update = Column(DateTime)
    ports = Column(String)  # Changed from JSONString to String
    vulns = Column(String)  # Changed from JSONString to String
    tags = Column(String)  # Changed from JSONString to String
    hostnames = Column(String)  # Changed from JSONString to String
    raw_data = Column(String)  # Changed from JSONString to String
    last_updated = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    ip = relationship("IPAddress", back_populates="shodan_data")

    def get_ports(self):
        """Get ports as Python list"""
        import json
        return json.loads(self.ports) if self.ports else []

    def get_vulns(self):
        """Get vulnerabilities as Python list"""
        import json
        return json.loads(self.vulns) if self.vulns else []

    def get_tags(self):
        """Get tags as Python list"""
        import json
        return json.loads(self.tags) if self.tags else []

    def get_hostnames(self):
        """Get hostnames as Python list"""
        import json
        return json.loads(self.hostnames) if self.hostnames else []

    def get_raw_data(self):
        """Get raw data as Python dict"""
        import json
        return json.loads(self.raw_data) if self.raw_data else {}

class AlienVaultData(Base):
    """Store AlienVault OTX specific data"""
    __tablename__ = 'alienvault_data'

    id = Column(Integer, primary_key=True)
    ip_address_id = Column(Integer, ForeignKey('ip_addresses.id'), nullable=False)
    pulse_count = Column(Integer, nullable=True)
    reputation = Column(Integer, nullable=True)
    activity_types = Column(JSONEncodedString(1024), nullable=True)  # Store as JSON string
    raw_data = Column(JSONEncodedString(4096), nullable=True)  # Store as JSON string
    last_updated = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    ip = relationship("IPAddress", back_populates="alienvault_data")

class ScanHistory(Base):
    """Track scanning history and results"""
    __tablename__ = 'scan_history'

    id = Column(Integer, primary_key=True)
    ip_address_id = Column(Integer, ForeignKey('ip_addresses.id'), nullable=False)
    scan_date = Column(DateTime, default=datetime.utcnow)
    scan_type = Column(String)  # Type of scan (full, partial, etc.)
    status = Column(String)  # Success, failed, partial
    error_message = Column(String, nullable=True)
    sources_checked = Column(String)  # Store JSON string of sources checked

    def get_sources_checked(self):
        """Get sources checked as Python dict"""
        import json
        return json.loads(self.sources_checked) if self.sources_checked else {} 