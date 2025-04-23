from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os
from urllib.parse import quote_plus
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get database credentials with default values
DB_USER = os.getenv("POSTGRES_USER", "admin")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "admin")
DB_NAME = os.getenv("POSTGRES_DB", "threats_db")
DB_HOST = os.getenv("POSTGRES_HOST", "localhost")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")

# Validate database credentials
if not all([DB_USER, DB_PASSWORD, DB_NAME]):
    raise ValueError("Missing required database credentials. Please check your .env file.")

# For development, use SQLite as fallback if PostgreSQL credentials are not properly configured
if os.getenv("ENVIRONMENT", "development").lower() == "development":
    DATABASE_URL = "sqlite:///threat_intelligence.db"
else:
    # Construct PostgreSQL URL with proper encoding
    try:
        DATABASE_URL = (
            f"postgresql://"
            f"{quote_plus(str(DB_USER))}:"
            f"{quote_plus(str(DB_PASSWORD))}@"
            f"{DB_HOST}:{DB_PORT}/{DB_NAME}"
        )
    except Exception as e:
        raise ValueError(f"Error constructing database URL: {str(e)}")

# Create engine with appropriate settings based on environment
if DATABASE_URL.startswith('sqlite'):
    engine = create_engine(
        DATABASE_URL,
        echo=False,  # Set to False in production
        connect_args={'check_same_thread': False}  # SQLite specific
    )
else:
    engine = create_engine(
        DATABASE_URL,
        echo=False,  # Set to False in production
        pool_size=5,
        max_overflow=10,
        pool_timeout=30,
        pool_recycle=1800,  # Recycle connections every 30 minutes
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Create all tables
def init_db():
    Base.metadata.create_all(bind=engine)

def reset_db():
    """Drop all tables and recreate them"""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine) 