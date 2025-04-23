# Threat Intelligence Platform

## Overview
The **Threat Intelligence Platform** is an advanced security analysis tool that combines traditional threat intelligence with machine learning capabilities. It provides comprehensive security insights for both IP addresses and domains, featuring automated data collection, ML-based threat detection, and continuous monitoring capabilities.

## Core Features

### Threat Intelligence
- **Automated Data Collection:** Continuous gathering of threat intelligence
- **Multi-Source Analysis:** Integration with VirusTotal, Shodan, and AlienVault OTX
- **Real-time Monitoring:** Automated detection and alerting for security threats
- **Trend Analysis:** Historical data analysis and threat pattern detection

### Machine Learning Capabilities
- **ML-Based Threat Detection:** Advanced threat prediction using Random Forest
- **Anomaly Detection:** Isolation Forest for identifying unusual patterns
- **Feature Importance Analysis:** Understanding key threat indicators
- **Automated Learning:** Continuous model improvement with new data
- **Synthetic Data Generation:** Smart sampling for improved model training

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
- ML model input validation and sanitization

### Access Control
- Rate limiting for API requests
- Error handling and logging
- Secure data storage practices
- Protection against common web vulnerabilities
- ML prediction validation

### Best Practices
- Environment-based configuration
- Secure dependency management
- Regular security updates
- Comprehensive error logging
- Model security controls

## Tech Stack
- **Backend:** Python 3.10+
- **Web Framework:** Streamlit
- **Database:** SQLite (Development) / PostgreSQL (Production)
- **Machine Learning:** scikit-learn
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
  - numpy
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

# ML Settings
MODEL_UPDATE_INTERVAL=24
MIN_TRAINING_SAMPLES=100
SYNTHETIC_DATA_RATIO=0.2

# Environment
ENVIRONMENT=development
```

### 4. Initialize the Database
```bash
python reset_database.py
```

## Usage

### Running as a Service
```bash
python threat_service.py
```

This will:
- Start the automated threat intelligence collection
- Launch the web interface
- Initialize ML models
- Enable continuous monitoring
- Provide self-healing capabilities

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
- ML-based predictions
- Trend analysis
- Geographic distribution
- Source correlation analysis

### 2. Machine Learning Analysis
- Threat probability prediction
- Anomaly detection
- Feature importance analysis
- Confidence scoring
- Model performance metrics

### 3. Domain Security Analysis
- SSL/TLS verification
- Security header analysis
- DNS record verification
- WHOIS information
- Reputation checking

### 4. IP Analysis
- Threat intelligence gathering
- ML-based risk assessment
- Historical trend analysis
- Correlation with known threats
- Detailed feature analysis

### 5. Automated Monitoring
- Continuous security scanning
- ML model updates
- Automated alerts
- Regular data updates
- Self-healing processes

## Security Considerations

### API Key Protection
- Store API keys in `.env` file
- Never commit `.env` file to version control
- Use environment variables for sensitive data
- Regular key rotation recommended

### Rate Limiting
- Implemented for all API calls
- Configurable limits in `.env`
- Protection against API abuse
- ML prediction rate limiting

### Data Security
- Secure database connections
- Input validation and sanitization
- Parameterized queries
- Error handling and logging
- ML input validation

### Model Security
- Secure model storage
- Input validation for predictions
- Synthetic data controls
- Regular model updates
- Performance monitoring

## Monitoring and Logs
- Application logs: `threat_automation.log`
- ML model logs: `ml_predictions.log`
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

3. **ML Model Issues**
   - Check training data quality
   - Verify feature consistency
   - Review model logs
   - Retrain models if needed

4. **Process Crashes**
   - Check `threat_automation.log`
   - Verify system resources
   - Review ML model status
   - Check for Python updates

## Future Enhancements
- Advanced ML model architectures
- Deep learning integration
- Additional threat intelligence sources
- Advanced correlation analysis
- Real-time alerting system
- Custom ML model training
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
- ML model security reviews


## Contact
For support or queries, please open an issue in the GitHub repository.

