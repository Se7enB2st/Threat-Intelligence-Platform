from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database connection
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///threat_intelligence.db')
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

def init_database():
    try:
        # Drop all tables
        Base.metadata.drop_all(engine)
        
        # Create all tables
        Base.metadata.create_all(engine)
        
        print("Successfully initialized database with correct schema")
        
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        session.rollback()
    finally:
        session.close()

if __name__ == "__main__":
    init_database() 