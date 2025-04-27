# Threat Intelligence Platform

## Overview
The **Threat Intelligence Platform** is a security analysis tool that provides comprehensive threat intelligence for IP addresses and domains. It integrates with multiple security data sources to provide detailed analysis and threat scoring.

## Core Features

### IP Analysis
- **IP Lookup:** Detailed analysis of IP addresses
- **Threat Scoring:** Overall threat score calculation
- **Multi-Source Analysis:** Integration with VirusTotal, Shodan, and AlienVault OTX
- **Historical Tracking:** First seen and last updated timestamps

### Domain Analysis
- **SSL/TLS Analysis:** Certificate validation and expiration monitoring
- **DNS Analysis:** Comprehensive DNS record verification
- **WHOIS Information:** Domain registration and ownership details
- **Security Headers:** Analysis of HTTP security headers
- **VirusTotal Integration:** Domain reputation checking
- **Security Scoring:** Overall security assessment

### Dashboard Features
- **Statistics Overview:**
  - Total IPs tracked
  - Average threat score
  - Malicious IPs count
  - Malicious IP percentage
- **Real-time Analysis:** Immediate threat assessment
- **Detailed Reports:** Comprehensive threat intelligence data

## Tech Stack
- **Backend:** Python 3.9+
- **Web Framework:** Streamlit
- **Database:** PostgreSQL
- **API Integrations:**
  - VirusTotal API
  - Shodan API
  - AlienVault OTX API
- **Additional Libraries:**
  - sqlalchemy
  - psycopg2-binary
  - python-dotenv
  - streamlit
  - pandas
  - plotly
  - python-whois
  - dnspython
  - tldextract

## Prerequisites
- Python 3.9+
- pip (Python package manager)
- Docker and Docker Compose
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

### 2. Set Up Environment Variables
Create a `.env` file in the root directory:
```plaintext
# Database Configuration
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=threat_intel
POSTGRES_HOST=db
POSTGRES_PORT=5432

# API Keys
VIRUSTOTAL_API_KEY=your_virustotal_api_key
SHODAN_API_KEY=your_shodan_api_key

# Streamlit Configuration
STREAMLIT_SERVER_ADDRESS=0.0.0.0
STREAMLIT_SERVER_PORT=8501
STREAMLIT_SERVER_HEADLESS=true
STREAMLIT_SERVER_ENABLE_CORS=true
STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION=true
STREAMLIT_SERVER_MAX_UPLOAD_SIZE=200
```

### 3. Start the Application
```bash
docker-compose up --build
```

## Usage

### Accessing the Web Interface
Once the application is running, access the web interface at:
```
http://localhost:8501
```

### Features

#### 1. Dashboard
- View overall statistics about tracked IP addresses
- Monitor threat levels and malicious IP counts
- Track average threat scores

#### 2. IP Lookup
- Enter an IP address for detailed analysis
- View threat intelligence from multiple sources
- Get comprehensive threat scoring
- Access historical data and timestamps

#### 3. Domain Analysis
- Enter a domain (with protocol) for comprehensive analysis
- View SSL/TLS certificate information
- Check DNS records and configurations
- Access WHOIS registration details
- Analyze security headers
- Get VirusTotal reputation score
- View overall security assessment

## Security Features

### Data Protection
- Secure database connections
- Environment-based configuration
- Input validation for IP addresses and domains
- Error handling and logging

### Best Practices
- Environment-based configuration
- Secure dependency management
- Comprehensive error logging
- Input validation

## Monitoring and Logs
- Application logs are available in the Docker containers
- Database logs are accessible through PostgreSQL
- Web interface: `http://localhost:8501`

## Troubleshooting

### Common Issues
1. **Database Connection Errors**
   - Verify database credentials in `.env`
   - Check if the database container is running
   - Ensure wait_for_db.py completes successfully

2. **API Integration Issues**
   - Verify API keys are properly configured
   - Check network connectivity
   - Review API rate limits

3. **Application Errors**
   - Check Docker logs
   - Verify environment variables
   - Ensure all containers are running

4. **Domain Analysis Issues**
   - Ensure domain includes protocol (http:// or https://)
   - Check network connectivity for DNS queries
   - Verify SSL certificate access
   - Check WHOIS service availability

## Support
For issues and feature requests, please open an issue in the GitHub repository.

