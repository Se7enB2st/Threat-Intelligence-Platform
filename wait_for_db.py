import time
import psycopg2
import os
import sys
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def wait_for_db():
    max_retries = 30
    retry_interval = 2

    for i in range(max_retries):
        try:
            conn = psycopg2.connect(
                dbname=os.getenv("POSTGRES_DB", "threats_db"),
                user=os.getenv("POSTGRES_USER", "admin"),
                password=os.getenv("POSTGRES_PASSWORD", "your_secure_password"),
                host=os.getenv("POSTGRES_HOST", "db"),
                port=os.getenv("POSTGRES_PORT", "5432")
            )
            conn.close()
            logger.info("Successfully connected to the database")
            return True
        except psycopg2.OperationalError as e:
            logger.warning(f"Attempt {i + 1}/{max_retries}: Database not ready yet: {e}")
            time.sleep(retry_interval)

    logger.error("Could not connect to the database after maximum retries")
    return False

if __name__ == "__main__":
    if not wait_for_db():
        sys.exit(1) 