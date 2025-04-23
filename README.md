# Threat Intelligence Platform (MVP)

## Overview
The **Threat Intelligence Platform** is a minimal viable product designed to aggregate and analyze cyber threat intelligence from key sources. It provides essential threat detection capabilities with a focus on simplicity, automation, and scalability. The platform features automated data collection, continuous analysis, and a real-time web interface for monitoring threats.

## Core Features
- **Automated Threat Intelligence:** Continuous collection and analysis of threat data
- **Threat Aggregation:** Fetches intelligence from VirusTotal, Shodan, and AlienVault OTX
- **Real-time Monitoring:** Automated detection and alerting for high-risk IPs
- **Advanced Analytics:** Automated trend analysis and threat pattern detection
- **Secure Implementation:** Environment-based configuration and secure API key management
- **Web Dashboard:** Real-time visualization of threat intelligence data
- **Domain Analysis** Comprehensive Domain Analysis on certificate validation, DNS analysis etc
- **Automated Service Management:** Self-healing processes and continuous operation
- **Comprehensive Logging:** Detailed activity and error logging for monitoring

## Tech Stack
- **Programming Language:** Python 3.10+
- **Web Framework:** Streamlit for interactive dashboard
- **Threat Intelligence Sources:** 
  - VirusTotal API
  - Shodan API
  - AlienVault OTX API
- **Database:** SQLite (Development) / PostgreSQL (Production)
- **Automation:** Schedule library for task management
- **Process Management:** Threading and subprocess handling

## Prerequisites
Before you begin, ensure you have:
- Python 3.10+
- pip (Python package manager)
- API keys from:
  - [VirusTotal](https://www.virustotal.com/gui/join-us)
  - [Shodan](https://account.shodan.io/)
  - [AlienVault OTX](https://otx.alienvault.com/)

## Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/Se7enB2st/Threat-Intelligence-Platform.git
cd Threat-Intelligence-Platform
```

### Step 2: Set Up Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables
Create a `.env` file in the root directory:
```plaintext
# API Keys (required)
VIRUSTOTAL_API_KEY=your_virustotal_api_key
SHODAN_API_KEY=your_shodan_api_key
ALIENVAULT_API_KEY=your_alienvault_api_key

# Database Configuration
POSTGRES_USER=admin
POSTGRES_PASSWORD=your_strong_password_here
POSTGRES_DB=threats_db
POSTGRES_HOST=localhost
POSTGRES_PORT=5432

# Automation Settings
SCAN_INTERVAL_MINUTES=60
BATCH_SIZE=10
HIGH_RISK_THRESHOLD=70.0

# Environment
ENVIRONMENT=development
```

### Step 4: Initialize the Database
```bash
python reset_database.py
```

## Running the Platform

### Option 1: Running as a Service (Recommended)
This option provides automated operation with self-healing capabilities:
```bash
python threat_service.py
```
This will:
- Start the automated data collection and analysis
- Launch the web interface
- Monitor and restart processes if they fail
- Handle graceful shutdowns

### Option 2: Running Components Separately
For development or debugging:

1. Start the automation:
```bash
python automation.py
```

2. Start the web interface:
```bash
streamlit run web_interface.py
```

## Monitoring and Logs
- Main application logs: `threat_automation.log`
- Access the web interface at: `http://localhost:8501`

## Security Features
- Secure API key management through environment variables
- Input validation and sanitization
- Error handling and logging
- Rate limiting for API requests
- Database connection security
- JSON data validation and sanitization

## Architecture
The platform consists of several key components:

1. **Data Collection (`threat_aggregation.py`)**
   - Handles API interactions with threat intelligence sources
   - Implements rate limiting and error handling

2. **Data Management (`data_manager.py`)**
   - Manages database operations
   - Handles data validation and storage

3. **Threat Analysis (`threat_analyzer.py`)**
   - Processes threat intelligence data
   - Generates insights and risk scores

4. **Web Interface (`web_interface.py`)**
   - Provides real-time dashboard
   - Visualizes threat data and analytics

5. **Automation (`automation.py`)**
   - Manages scheduled tasks
   - Handles continuous data collection and analysis

6. **Service Management (`threat_service.py`)**
   - Manages platform processes
   - Provides self-healing capabilities

## Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Troubleshooting
Common issues and solutions:

1. **Database Errors**
   - Run `reset_database.py` to reinitialize the database
   - Check database credentials in `.env`

2. **API Key Issues**
   - Verify API keys in `.env`
   - Check API rate limits

3. **Process Crashes**
   - Check `threat_automation.log` for error details
   - Verify system resources

## Future Enhancements
- Machine learning-based threat detection
- Additional threat intelligence sources
- Advanced correlation analysis
- Email/Slack notifications
- Custom alerting rules
- API endpoint for external integration

## Contact
For support or queries, please open an issue in the GitHub repository.

