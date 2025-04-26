from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os
from dotenv import load_dotenv
import json

# Load environment variables
load_dotenv()

Base = declarative_base()

class IPAddress(Base):
    __tablename__ = 'ip_addresses'

    id = Column(Integer, primary_key=True)
    ip_address = Column(String, unique=True, nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    overall_threat_score = Column(Float, default=0.0)
    is_malicious = Column(Boolean, default=False)

    # Relationships
    virustotal_data = relationship("VirusTotalData", back_populates="ip_address", uselist=False)
    shodan_data = relationship("ShodanData", back_populates="ip_address", uselist=False)
    alienvault_data = relationship("AlienVaultData", back_populates="ip_address", uselist=False)
    scan_history = relationship("ScanHistory", back_populates="ip_address")

class VirusTotalData(Base):
    __tablename__ = 'virustotal_data'

    id = Column(Integer, primary_key=True)
    ip_address_id = Column(Integer, ForeignKey('ip_addresses.id'))
    malicious_count = Column(Integer)
    suspicious_count = Column(Integer)
    harmless_count = Column(Integer)
    last_analysis_date = Column(DateTime)
    raw_data = Column(JSON)

    ip_address = relationship("IPAddress", back_populates="virustotal_data")

class ShodanData(Base):
    __tablename__ = 'shodan_data'

    id = Column(Integer, primary_key=True)
    ip_address_id = Column(Integer, ForeignKey('ip_addresses.id'))
    ports = Column(String)  # JSON string of ports
    vulns = Column(String)  # JSON string of vulnerabilities
    tags = Column(String)   # JSON string of tags
    hostnames = Column(String)  # JSON string of hostnames
    raw_data = Column(JSON)

    ip_address = relationship("IPAddress", back_populates="shodan_data")

class AlienVaultData(Base):
    __tablename__ = 'alienvault_data'

    id = Column(Integer, primary_key=True)
    ip_address_id = Column(Integer, ForeignKey('ip_addresses.id'))
    pulse_count = Column(Integer)
    reputation = Column(Integer)
    activity_types = Column(String)  # JSON string of activity types
    raw_data = Column(JSON)

    ip_address = relationship("IPAddress", back_populates="alienvault_data")

class ScanHistory(Base):
    __tablename__ = 'scan_history'

    id = Column(Integer, primary_key=True)
    ip_address_id = Column(Integer, ForeignKey('ip_addresses.id'))
    scan_date = Column(DateTime, default=datetime.utcnow)
    scan_type = Column(String)
    status = Column(String)
    sources_checked = Column(String)  # JSON string of sources checked

    ip_address = relationship("IPAddress", back_populates="scan_history")

def get_db():
    """Create database connection"""
    DB_USER = os.getenv("POSTGRES_USER", "admin")
    DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "your_secure_password")
    DB_HOST = os.getenv("POSTGRES_HOST", "db")
    DB_PORT = os.getenv("POSTGRES_PORT", "5432")
    DB_NAME = os.getenv("POSTGRES_DB", "threats_db")
    
    DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)  # Create tables if they don't exist
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    return SessionLocal() 