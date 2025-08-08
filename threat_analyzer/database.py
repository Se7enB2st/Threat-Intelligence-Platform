from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey, JSON, text, inspect
from sqlalchemy.orm import sessionmaker, relationship, DeclarativeBase
from datetime import datetime
import os
from dotenv import load_dotenv
import json
import logging

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

class IPAddress(Base):
    __tablename__ = 'ip_addresses'

    id = Column(Integer, primary_key=True)
    ip_address = Column(String, unique=True, nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    overall_threat_score = Column(Float, default=0.0)
    is_malicious = Column(Boolean, default=False)

    # Relationships
    analysis = relationship("IPAnalysis", back_populates="ip_address", uselist=False)
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

class IPAnalysis(Base):
    __tablename__ = 'ip_analysis'
    
    id = Column(Integer, primary_key=True)
    ip_address_id = Column(Integer, ForeignKey('ip_addresses.id'), unique=True, nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    overall_threat_score = Column(Float, default=0.0)
    is_malicious = Column(Boolean, default=False)
    
    # Relationships
    ip_address = relationship("IPAddress", back_populates="analysis")
    threat_data = relationship("ThreatData", back_populates="ip_analysis")

class DomainAnalysis(Base):
    __tablename__ = 'domain_analysis'
    
    id = Column(Integer, primary_key=True)
    domain = Column(String, unique=True, nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    overall_threat_score = Column(Float, default=0.0)
    is_malicious = Column(Boolean, default=False)
    whois_data = Column(JSON)
    dns_records = Column(JSON)
    threat_data = relationship("ThreatData", back_populates="domain_analysis")

class ThreatData(Base):
    __tablename__ = 'threat_data'
    
    id = Column(Integer, primary_key=True)
    ip_analysis_id = Column(Integer, ForeignKey('ip_analysis.id'), nullable=True)
    domain_analysis_id = Column(Integer, ForeignKey('domain_analysis.id'), nullable=True)
    source = Column(String, nullable=False)
    data = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    ip_analysis = relationship("IPAnalysis", back_populates="threat_data")
    domain_analysis = relationship("DomainAnalysis", back_populates="threat_data")

def get_db():
    """Create database connection"""
    DB_USER = os.getenv("POSTGRES_USER", "postgres")
    DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "postgres")
    DB_HOST = os.getenv("POSTGRES_HOST", "db")
    DB_PORT = os.getenv("POSTGRES_PORT", "5432")
    DB_NAME = os.getenv("POSTGRES_DB", "threat_intel")
    
    # Log the connection parameters (except password)
    logger.info(f"Connecting to database at {DB_HOST}:{DB_PORT}/{DB_NAME} with user {DB_USER}")
    
    try:
        DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=300)
        
        # Test the connection using SQLAlchemy's text()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            conn.commit()  # Ensure clean transaction state
            
        # Check if tables exist, create them only if they don't
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()
        
        if not existing_tables:
            logger.info("No tables found, creating database schema...")
            Base.metadata.create_all(engine)
        else:
            logger.info(f"Found existing tables: {existing_tables}")
        
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        return SessionLocal()
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        raise 