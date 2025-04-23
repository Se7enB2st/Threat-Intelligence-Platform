import subprocess
import sys
import os
from threading import Thread
import time
import signal
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatService:
    def __init__(self):
        self.automation_process = None
        self.web_process = None
        self.running = False

    def start_automation(self):
        """Start the automation script"""
        self.automation_process = subprocess.Popen(
            [sys.executable, "automation.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        logger.info("Automation process started")

    def start_web_interface(self):
        """Start the Streamlit web interface"""
        self.web_process = subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run", "web_interface.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        logger.info("Web interface started")

    def monitor_processes(self):
        """Monitor and restart processes if they fail"""
        while self.running:
            if self.automation_process.poll() is not None:
                logger.warning("Automation process died, restarting...")
                self.start_automation()

            if self.web_process.poll() is not None:
                logger.warning("Web interface died, restarting...")
                self.start_web_interface()

            time.sleep(30)

    def start(self):
        """Start all services"""
        self.running = True
        self.start_automation()
        self.start_web_interface()
        
        # Start monitoring in a separate thread
        monitor_thread = Thread(target=self.monitor_processes)
        monitor_thread.daemon = True
        monitor_thread.start()

    def stop(self):
        """Stop all services"""
        self.running = False
        
        if self.automation_process:
            self.automation_process.terminate()
        if self.web_process:
            self.web_process.terminate()
        
        logger.info("All services stopped")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info("Shutdown signal received")
    service.stop()
    sys.exit(0)

if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    service = ThreatService()
    service.start()

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        service.stop() 