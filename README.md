# Threat Intelligence Platform

## Overview
The **Threat Intelligence Platform** is a security analysis tool that provides comprehensive threat intelligence for IP addresses and domains. It integrates with multiple security data sources to provide detailed analysis and threat scoring.

## Core Features

### IP Analysis
- **IP Lookup:** Detailed analysis of IP addresses
- **Threat Scoring:** Overall threat score calculation
- **Multi-Source Analysis:** Integration with VirusTotal, Shodan, and AlienVault OTX
- **Historical Tracking:** First seen and last updated timestamps
- **Input Validation:** Strict validation of IP addresses
- **Rate Limiting:** Protection against API abuse

### Domain Analysis
- **SSL/TLS Analysis:** Certificate validation and expiration monitoring
- **DNS Analysis:** Comprehensive DNS record verification
- **WHOIS Information:** Domain registration and ownership details
- **Security Headers:** Analysis of HTTP security headers
- **VirusTotal Integration:** Domain reputation checking
- **Security Scoring:** Overall security assessment
- **Input Validation:** Strict validation of domain names
- **Rate Limiting:** Protection against API abuse

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

## Security Features

### Input Validation & Sanitization
- **IP Address Validation:** Strict format checking and validation
- **Domain Name Validation:** Comprehensive domain format validation
- **Input Sanitization:** Protection against injection attacks
- **Error Handling:** Clear error messages for invalid inputs

### Rate Limiting
- **API Rate Limiting:** Protection against API abuse
  - VirusTotal: 4 calls per minute
  - Shodan: 1 call per second
  - AlienVault: 10 calls per minute
  - Overall IP analysis: 60 calls per minute
- **Per-IP/Domain Limits:** Individual rate limiting for each identifier
- **Time Window Tracking:** Sliding window for rate limit enforcement

### Data Protection
- **Environment Variables:** Secure storage of API keys and credentials
- **Database Security:** Protected database connections
- **Input Sanitization:** Prevention of injection attacks
- **Error Handling:** Comprehensive error logging and handling

### API Security
- **API Key Management:** Secure storage in environment variables
- **Rate Limiting:** Protection against API abuse
- **Error Handling:** Proper handling of API errors
- **Logging:** Comprehensive API call logging

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
ALIENVAULT_API_KEY=your_alienvault_api_key

# Streamlit Configuration
STREAMLIT_SERVER_ADDRESS=0.0.0.0
STREAMLIT_SERVER_PORT=8501
STREAMLIT_SERVER_HEADLESS=true
STREAMLIT_SERVER_ENABLE_CORS=true
STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION=true
STREAMLIT_SERVER_MAX_UPLOAD_SIZE=200

# Security Configuration
RATE_LIMIT_ENABLED=true
MAX_REQUESTS_PER_MINUTE=60
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
- Input validation and rate limiting

#### 3. Domain Analysis
- Enter a domain (with protocol) for comprehensive analysis
- View SSL/TLS certificate information
- Check DNS records and configurations
- Access WHOIS registration details
- Analyze security headers
- Get VirusTotal reputation score
- View overall security assessment
- Input validation and rate limiting

## Monitoring and Logs
- Application logs are available in the Docker containers
- Database logs are accessible through PostgreSQL
- Security logs track rate limiting and validation events
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
   - Check rate limiting configuration

3. **Application Errors**
   - Check Docker logs
   - Verify environment variables
   - Ensure all containers are running
   - Review security logs

4. **Domain Analysis Issues**
   - Ensure domain includes protocol (http:// or https://)
   - Check network connectivity for DNS queries
   - Verify SSL certificate access
   - Check WHOIS service availability
   - Review rate limiting status

5. **Rate Limiting Issues**
   - Check rate limit configuration
   - Verify time window settings
   - Review API quotas
   - Check security logs

## Support
For issues and feature requests, please open an issue in the GitHub repository.

