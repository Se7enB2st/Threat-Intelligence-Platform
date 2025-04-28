from sqlalchemy import create_engine, inspect
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database connection
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///threat_intelligence.db')
engine = create_engine(DATABASE_URL)

def inspect_database():
    inspector = inspect(engine)
    
    # Get all tables
    tables = inspector.get_table_names()
    print("Tables in database:", tables)
    
    # Inspect ShodanData table
    if 'shodan_data' in tables:
        print("\nShodanData table columns:")
        columns = inspector.get_columns('shodan_data')
        for column in columns:
            print(f"- {column['name']}: {column['type']}")

if __name__ == "__main__":
    inspect_database() 