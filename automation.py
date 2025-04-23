import schedule
import time
from datetime import datetime
import threading
from typing import List, Dict
import logging
from data_manager import ThreatDataManager
from threat_analyzer import ThreatAnalyzer
from threat_aggregation import ThreatAggregator
from database import get_db
import os
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('threat_automation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Database Configuration
POSTGRES_USER=admin
POSTGRES_PASSWORD=secure_password_here
POSTGRES_DB=threats_db
POSTGRES_HOST=db
POSTGRES_PORT=5432

# Application Configuration
ENVIRONMENT=development
DEBUG=true

# API Keys (replace with your actual API keys)
VIRUSTOTAL_API_KEY=your_virustotal_api_key
SHODAN_API_KEY=your_shodan_api_key
ALIENVAULT_API_KEY=your_alienvault_api_key

# Service Ports
WEB_PORT=8501
ML_SERVICE_PORT=5000
ANALYZER_PORT=5001

class ThreatAutomation:
    def __init__(self):
        load_dotenv()
        self.data_manager = ThreatDataManager()
        self.analyzer = ThreatAnalyzer()
        self.aggregator = ThreatAggregator()
        
        # Get configuration from environment variables
        self.scan_interval = int(os.getenv('SCAN_INTERVAL_MINUTES', '60'))
        self.batch_size = int(os.getenv('BATCH_SIZE', '10'))
        self.high_risk_threshold = float(os.getenv('HIGH_RISK_THRESHOLD', '70.0'))

    def scan_ip(self, ip: str) -> Dict:
        """Scan a single IP address"""
        try:
            db = next(get_db())
            threat_data = self.aggregator.aggregate_threat_data(ip)
            ip_record = self.data_manager.save_threat_data(db, ip, threat_data)
            db.commit()
            return threat_data
        except Exception as e:
            logger.error(f"Error scanning IP {ip}: {str(e)}")
            return {"error": str(e)}
        finally:
            db.close()

    def process_high_risk_ips(self):
        """Process IPs with high risk scores"""
        try:
            db = next(get_db())
            high_risk_ips = self.analyzer.get_high_risk_ips(db, self.high_risk_threshold)
            
            for ip_data in high_risk_ips:
                logger.warning(f"High risk IP detected: {ip_data['ip_address']} "
                             f"(Score: {ip_data['threat_score']})")
                # Here you could add additional actions like notifications
                
        except Exception as e:
            logger.error(f"Error processing high risk IPs: {str(e)}")
        finally:
            db.close()

    def update_analytics(self):
        """Update analytics data"""
        try:
            db = next(get_db())
            
            # Update various analytics
            self.analyzer.analyze_threat_trends(db)
            self.analyzer.analyze_source_correlation(db)
            self.analyzer.analyze_port_exposure(db)
            self.analyzer.analyze_threat_patterns(db)
            
            logger.info("Analytics updated successfully")
        except Exception as e:
            logger.error(f"Error updating analytics: {str(e)}")
        finally:
            db.close()

    def run_scheduled_scan(self):
        """Run a scheduled scan of the system"""
        logger.info("Starting scheduled scan")
        
        try:
            db = next(get_db())
            # Get IPs that need updating (oldest first)
            ips_to_scan = self.data_manager.get_ips_for_update(db, self.batch_size)
            
            for ip in ips_to_scan:
                logger.info(f"Scanning IP: {ip}")
                self.scan_ip(ip)
            
            # Process high risk IPs
            self.process_high_risk_ips()
            
            # Update analytics
            self.update_analytics()
            
            logger.info("Scheduled scan completed successfully")
        except Exception as e:
            logger.error(f"Error in scheduled scan: {str(e)}")
        finally:
            db.close()

    def get_initial_ip_list(self) -> List[str]:
        """Get initial list of IPs to scan"""
        return [
            "8.8.8.8",  # Google DNS
            "1.1.1.1",  # Cloudflare DNS
            "208.67.222.222",  # OpenDNS
            # Add more IPs as needed
        ]

    def initial_scan(self):
        """Perform initial scan of IPs"""
        ip_list = self.get_initial_ip_list()
        for ip in ip_list:
            self.scan_ip(ip)

def run_threaded(job_func):
    """Run function in a thread"""
    job_thread = threading.Thread(target=job_func)
    job_thread.start()

def main():
    automation = ThreatAutomation()
    
    # Schedule jobs
    schedule.every(automation.scan_interval).minutes.do(
        run_threaded, automation.run_scheduled_scan
    )
    
    # Run analytics updates less frequently
    schedule.every(6).hours.do(
        run_threaded, automation.update_analytics
    )
    
    logger.info("Threat Intelligence Automation Started")
    
    while True:
        schedule.run_pending()
        time.sleep(60)  # Wait one minute before checking schedule again

if __name__ == "__main__":
    main() 