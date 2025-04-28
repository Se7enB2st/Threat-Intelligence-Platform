from sqlalchemy import create_engine, MetaData, Table
from sqlalchemy.orm import sessionmaker
from models import Base, ShodanData
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database connection
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///threat_intelligence.db')
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

def update_shodan_table():
    try:
        # Drop the existing table
        ShodanData.__table__.drop(engine)
        
        # Create the table with the new schema
        Base.metadata.create_all(engine)
        
        print("Successfully updated ShodanData table schema")
        
    except Exception as e:
        print(f"Error updating ShodanData table: {str(e)}")
        session.rollback()
    finally:
        session.close()

if __name__ == "__main__":
    update_shodan_table() 