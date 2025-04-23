# Threat Intelligence Platform

## Overview
The **Threat Intelligence Platform** is a comprehensive security analysis tool that combines threat intelligence gathering, domain security analysis, and continuous monitoring capabilities. It provides real-time security insights for both IP addresses and domains, with automated data collection and analysis features.

## Core Features

### Threat Intelligence
- **Automated Data Collection:** Continuous gathering of threat intelligence
- **Multi-Source Analysis:** Integration with VirusTotal, Shodan, and AlienVault OTX
- **Real-time Monitoring:** Automated detection and alerting for security threats
- **Trend Analysis:** Historical data analysis and threat pattern detection

### Domain Security Analysis
- **SSL/TLS Verification:** Certificate validation and expiration monitoring
- **Security Headers:** Analysis of HTTP security headers
- **DNS Analysis:** Comprehensive DNS record verification
- **WHOIS Information:** Domain registration and ownership verification
- **Reputation Checking:** Domain reputation analysis via VirusTotal

### Platform Features
- **Automated Operation:** Self-healing processes and continuous monitoring
- **Interactive Dashboard:** Real-time data visualization
- **Secure Implementation:** Environment-based configuration and secure API handling
- **Comprehensive Logging:** Detailed activity and error tracking

## Security Features

### Data Protection
- Secure API key management via environment variables
- Database connection security with parameterized queries
- Input validation and sanitization for all user inputs
- SSL/TLS verification for all external API calls

### Access Control
- Rate limiting for API requests
- Error handling and logging
- Secure data storage practices
- Protection against common web vulnerabilities

### Best Practices
- Environment-based configuration
- Secure dependency management
- Regular security updates
- Comprehensive error logging

## Tech Stack
- **Backend:** Python 3.10+
- **Web Framework:** Streamlit
- **Database:** SQLite (Development) / PostgreSQL (Production)
- **API Integrations:**
  - VirusTotal API
  - Shodan API
  - AlienVault OTX API
- **Additional Libraries:**
  - python-whois
  - dnspython
  - tldextract
  - requests
  - pandas
  - plotly

## Prerequisites
- Python 3.10+
- pip (Python package manager)
- Required API keys:
  - [VirusTotal](https://www.virustotal.com/gui/join-us)
  - [Shodan](https://account.shodan.io/)
  - [AlienVault OTX](https://otx.alienvault.com/)

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/Se7enB2st/Threat-Intelligence-Platform.git
cd Threat-Intelligence-Platform
```

### 2. Set Up Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure Environment Variables
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

# Rate Limiting
MAX_REQUESTS_PER_MINUTE=60
DOMAIN_SCAN_COOLDOWN=300

# Environment
ENVIRONMENT=development
```

### 4. Initialize the Database
```bash
python reset_database.py
```

## Usage

### Running as a Service (Recommended)
```bash
python threat_service.py
```

This will:
- Start the automated threat intelligence collection
- Launch the web interface
- Begin domain security monitoring
- Enable self-healing capabilities

### Development Mode
```bash
# Start automation separately
python automation.py

# Start web interface
streamlit run web_interface.py
```

## Features Guide

### 1. Threat Intelligence Dashboard
- Real-time threat metrics
- Trend analysis
- Geographic distribution
- Source correlation analysis

### 2. Domain Security Analysis
- Enter any domain name for analysis
- View comprehensive security metrics
- SSL/TLS verification
- Security header analysis
- DNS and WHOIS verification

### 3. IP Analysis
- Single or bulk IP scanning
- Threat score calculation
- Historical trend analysis
- Correlation with known threats

### 4. Automated Monitoring
- Continuous security scanning
- Automated alerts for high-risk threats
- Regular data updates
- Self-healing processes

## Security Considerations

### API Key Protection
- Store API keys in `.env` file
- Never commit `.env` file to version control
- Use environment variables for sensitive data

### Rate Limiting
- Implemented for all API calls
- Configurable limits in `.env`
- Protection against API abuse

### Data Security
- Secure database connections
- Input validation and sanitization
- Parameterized queries
- Error handling and logging

### Best Practices
- Regular dependency updates
- Secure coding practices
- Comprehensive error handling
- Activity logging

## Monitoring and Logs
- Application logs: `threat_automation.log`
- Web interface: `http://localhost:8501`
- Database logs (when enabled)

## Troubleshooting

### Common Issues
1. **API Key Errors**
   - Verify keys in `.env`
   - Check API rate limits
   - Confirm API service status

2. **Database Errors**
   - Run `reset_database.py`
   - Check database credentials
   - Verify database connections

3. **Process Crashes**
   - Check `threat_automation.log`
   - Verify system resources
   - Check for Python updates

## Future Enhancements
- Machine learning-based threat detection
- Additional threat intelligence sources
- Advanced correlation analysis
- Email/Slack notifications
- Custom alerting rules
- API endpoint for external integration
- Enhanced rate limiting
- Additional security features

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Security Policy
- Report security vulnerabilities privately
- Regular security audits
- Dependency vulnerability scanning
- Secure coding guidelines

## Contact
For support or queries, please open an issue in the GitHub repository.

