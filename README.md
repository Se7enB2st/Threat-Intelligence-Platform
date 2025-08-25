# Threat Intelligence Platform

## Overview
The **Threat Intelligence Platform** is a comprehensive security analysis tool that provides detailed threat intelligence for IP addresses and domains. It integrates with multiple security data sources to provide real-time analysis, threat scoring, and historical tracking with persistent data storage.

## Core Features

### IP Analysis
- **IP Lookup:** Detailed analysis of IP addresses with persistent storage
- **Threat Scoring:** Overall threat score calculation based on multiple sources
- **Multi-Source Analysis:** Integration with VirusTotal, Shodan, and AlienVault OTX
- **Historical Tracking:** First seen and last updated timestamps with data persistence
- **Input Validation:** Strict validation of IP addresses
- **Rate Limiting:** Protection against API abuse
- **Data Persistence:** All analysis data is stored and persists between container restarts

### Domain Analysis
- **Flexible Input:** Accept domains with or without protocols (e.g., `example.com` or `https://example.com`)
- **SSL/TLS Analysis:** Certificate validation and expiration monitoring
- **DNS Analysis:** Comprehensive DNS record verification
- **WHOIS Information:** Domain registration and ownership details
- **Security Headers:** Analysis of HTTP security headers
- **VirusTotal Integration:** Domain reputation checking
- **Security Scoring:** Overall security assessment with threat score calculation
- **Input Validation:** Strict validation of domain names
- **Rate Limiting:** Protection against API abuse
- **Data Persistence:** Domain analysis results are stored and tracked

### Historical Analysis
- **Comprehensive Statistics:** Track total IPs and domains analyzed
- **Malicious Counts:** Monitor malicious IPs and domains
- **Trend Analysis:** View threat score trends over time
- **Attack Patterns:** Identify common attack patterns and vulnerabilities
- **Date Range Filtering:** Analyze data for specific time periods
- **Domain Trends:** Track domain threat score trends
- **Top Malicious Lists:** View most threatening IPs and domains
- **Threat Score Distribution:** Visualize threat score ranges and percentages
- **Geographic Analysis:** 
  - Geographic distribution of threats by country
  - Country-level threat statistics
  - City-level threat analysis
  - Average threat scores by geographic location
  - Malicious percentage by country
  - Interactive charts and detailed breakdowns
- **Vulnerability Analysis:**
  - Vulnerability severity distribution (Critical, High, Medium, Low, Unknown)
  - CVE correlation analysis and attack patterns
  - Vulnerability trends over time
  - Comprehensive vulnerability statistics
  - Zero-day vulnerability detection
  - Port-based vulnerability analysis
  - Most vulnerable IPs identification

### Database Management
- **Reset Functionality:** Complete database reset with confirmation
- **Data Persistence:** All data survives container restarts and rebuilds
- **Smart Schema Management:** Automatic table creation without data loss
- **Volume Storage:** Persistent PostgreSQL data storage

### Dashboard Features
- **Statistics Overview:**
  - Total IPs tracked
  - Total domains analyzed
  - Average threat score
  - Malicious IPs count
  - Malicious domains count
  - Malicious percentage calculations
- **Real-time Analysis:** Immediate threat assessment
- **Detailed Reports:** Comprehensive threat intelligence data
- **Historical Insights:** Trend analysis and pattern recognition
- **Geographic Insights:** Threat distribution by location

## Recent Improvements

### Geographic Analysis (New Feature)
- **Geographic Distribution:** Visualize threats by country and city
- **Country Statistics:** Track threat levels by geographic location
- **Interactive Charts:** Bar charts showing threat distribution
- **Detailed Breakdowns:** Tables with percentages and averages
- **Data Sources:** Geographic data extracted from Shodan API responses
- **Real-time Updates:** Geographic analysis updates with new data

### Threat Score Distribution (New Feature)
- **Score Ranges:** Categorize threats into Low, Medium-Low, Medium, Medium-High, High, and Critical
- **Visual Charts:** Bar charts showing distribution of threat scores
- **Percentage Analysis:** Calculate and display percentages for each score range
- **Detailed Tables:** Comprehensive breakdowns with counts and percentages
- **IP and Domain Analysis:** Separate analysis for IPs and domains

### Data Persistence (Fixed)
- **Issue Resolved:** Data was being wiped on container restarts
- **Solution:** Implemented smart database initialization that only creates tables if they don't exist
- **Result:** All analysis data now persists between `docker-compose down` and `docker-compose up --build`

### Domain Tracking Enhancement
- **Issue Resolved:** Historical analysis wasn't counting domain analysis
- **Solution:** Added database storage to domain analyzer with JSON serialization fixes
- **Result:** Domain analysis is now properly tracked in historical statistics

### Reset Database Feature
- **New Feature:** Added comprehensive database reset functionality
- **Safety Features:** Two-step confirmation process
- **Scope:** Clears all data from all tables (IPs, domains, threat data, etc.)
- **Location:** Available in sidebar under "Database Management"

### Enhanced Domain Input
- **Improvement:** Users can now enter domains without requiring `http://` or `https://`
- **Auto-Normalization:** Automatically adds `https://` if no protocol is specified

### Vulnerability Analysis (New Feature)
- **Severity Distribution:** Categorize vulnerabilities by severity (Critical, High, Medium, Low, Unknown)
- **CVE Correlations:** Analyze relationships between different CVEs and identify attack patterns
- **Vulnerability Trends:** Track vulnerability counts and trends over time
- **Comprehensive Statistics:** 
  - Total IPs with vulnerabilities
  - Average vulnerabilities per IP
  - Most vulnerable IPs identification
  - Port-based vulnerability analysis
- **Zero-Day Detection:** Identify potential zero-day vulnerabilities and emerging threats
- **Interactive Visualizations:** 
  - Pie charts for severity distribution
  - Line charts for vulnerability trends
  - Bar charts for port vulnerability analysis
  - Detailed tables with comprehensive breakdowns
- **Attack Pattern Recognition:** Identify common CVE pairs and attack patterns
- **Real-time Analysis:** Vulnerability analysis updates with new data
- **Flexible Validation:** Accepts multiple domain formats
- **Better UX:** More user-friendly domain input experience

### Historical Analysis Enhancement
- **New Metrics:** Added total counts for analyzed IPs and domains
- **Domain Integration:** Domain analysis now included in historical data
- **Enhanced Statistics:** More comprehensive analysis summary
- **Better Visualization:** Improved charts and data presentation

## Tech Stack
- **Backend:** Python 3.9+
- **Web Framework:** Streamlit
- **Database:** PostgreSQL with persistent volume storage
- **Containerization:** Docker and Docker Compose
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
- **Domain Name Validation:** Comprehensive domain format validation with protocol flexibility
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
- **Database Security:** Protected database connections with persistent storage
- **Input Sanitization:** Prevention of injection attacks
- **Error Handling:** Comprehensive error logging and handling
- **JSON Serialization:** Safe handling of datetime objects in database storage

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
- View overall statistics about tracked IP addresses and domains
- Monitor threat levels and malicious counts
- Track average threat scores
- Real-time updates of analysis data

#### 2. IP Lookup
- Enter an IP address for detailed analysis
- View threat intelligence from multiple sources
- Get comprehensive threat scoring
- Access historical data and timestamps
- Input validation and rate limiting
- Persistent data storage

#### 3. Domain Analysis
- Enter a domain with flexible input (e.g., `example.com` or `https://example.com`)
- View SSL/TLS certificate information
- Check DNS records and configurations
- Access WHOIS registration details
- Analyze security headers
- Get VirusTotal reputation score
- View overall security assessment with threat scoring
- Input validation and rate limiting
- Persistent data storage

#### 4. Historical Analysis
- **Date Range Selection:** Choose specific time periods for analysis
- **Comprehensive Statistics:**
  - Total IPs analyzed
  - Total domains analyzed
  - Malicious IPs count
  - Malicious domains count
- **Trend Analysis:** View threat score trends over time
- **Top Malicious Lists:** See most threatening IPs and domains
- **Attack Patterns:** Identify common vulnerabilities and attack patterns
- **Domain Trends:** Track domain threat score trends
- **Threat Score Distribution:**
  - Visual breakdown of threat scores by range
  - Percentage analysis for each score category
  - Separate analysis for IPs and domains
  - Interactive charts and detailed tables
- **Geographic Analysis:**
  - Geographic distribution of threats by country
  - Country-level threat statistics with averages
  - City-level threat analysis
  - Malicious percentage by geographic location
  - Interactive bar charts and detailed breakdowns
  - Real-time geographic threat mapping

#### 5. Database Management
- **Reset Database:** Complete data reset with safety confirmations
- **Two-Step Confirmation:** Prevents accidental data loss
- **Comprehensive Clearing:** Removes all data from all tables
- **Safety Warnings:** Clear warnings about data loss

### Using the AI/ML Model

The platform includes a powerful AI/ML model for threat prediction and analysis. Here's how to use it:

#### 1. Initializing the Model
```python
from threat_analyzer.ml.threat_predictor import ThreatPredictor

# Initialize with a pre-trained model
predictor = ThreatPredictor(model_path="path/to/saved/model.joblib")

# Or initialize a new model
predictor = ThreatPredictor()
```

#### 2. Training the Model
```python
# Example training data
training_data = [
    {
        'virustotal': {'malicious_count': 5, 'suspicious_count': 2},
        'shodan': {'vulnerabilities': ['CVE-2021-1234'], 'ports': [80, 443]},
        'alienvault': {'pulse_count': 3, 'reputation': -0.8},
        'is_malicious': True
    },
    # Add more training examples
]

# Train the model
predictor.train_model(training_data)

# Save the trained model
predictor.save_model("path/to/save/model.joblib")
```

#### 3. Making Predictions
```python
# Example threat data for prediction
threat_data = {
    'virustotal': {'malicious_count': 3, 'suspicious_count': 1},
    'shodan': {'vulnerabilities': ['CVE-2021-5678'], 'ports': [22, 80]},
    'alienvault': {'pulse_count': 2, 'reputation': -0.5},
    'historical_threat_score': 0.6,
    'first_seen': datetime.utcnow() - timedelta(days=30)
}

# Get prediction
prediction = predictor.predict_threat(threat_data)
print(f"Prediction: {prediction}")
# Output example:
# {
#     'is_malicious': True,
#     'malicious_probability': 0.85,
#     'confidence': 0.92,
#     'features_used': ['virustotal_malicious_count', ...]
# }
```

#### 4. Analyzing Threat Patterns
```python
# Analyze patterns in threat data
analysis = predictor.analyze_threat_patterns(threat_data_list)
print(f"Analysis: {analysis}")
# Output example:
# {
#     'total_samples': 1000,
#     'malicious_percentage': 15.5,
#     'average_threat_score': 0.45,
#     'common_vulnerabilities': [
#         {'vulnerability': 'CVE-2021-1234', 'count': 50},
#         {'vulnerability': 'CVE-2021-5678', 'count': 30}
#     ],
#     'threat_trends': {
#         'daily_threat_scores': [...],
#         'trend_direction': 'increasing'
#     }
# }
```

#### 5. Model Features
The model uses the following features for prediction:
- VirusTotal data (malicious and suspicious counts)
- Shodan data (vulnerabilities and open ports)
- AlienVault data (pulse count and reputation)
- Historical threat score
- Days since first seen

#### 6. Integration with Threat Analysis
The model is automatically integrated with the main threat analysis pipeline. When analyzing an IP or domain, the platform:
1. Collects data from all sources (VirusTotal, Shodan, AlienVault)
2. Prepares the features for the model
3. Makes a prediction
4. Includes the prediction in the final analysis

Example of integrated usage:
```python
from threat_analyzer.threat_aggregation import ThreatAggregator

# Initialize the aggregator
aggregator = ThreatAggregator(db_session)

# Get analysis with AI prediction
analysis = aggregator.get_ip_analysis("8.8.8.8")
print(f"Analysis with AI prediction: {analysis}")
```

## Data Persistence

### How It Works
- **Persistent Volume:** PostgreSQL data is stored in a Docker volume
- **Smart Initialization:** Database only creates tables if they don't exist
- **No Data Loss:** Data survives container restarts and rebuilds
- **Automatic Recovery:** Data is preserved across system reboots

### Database Reset
- **Reset Button:** Available in the sidebar under "Database Management"
- **Safety Confirmation:** Two-step process prevents accidental resets
- **Complete Clearing:** Removes all data from all tables
- **Immediate Effect:** Reset takes effect immediately

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
   - Ensure domain format is valid (e.g., `example.com` or `https://example.com`)
   - Check network connectivity for DNS queries
   - Verify SSL certificate access
   - Check WHOIS service availability
   - Review rate limiting status

5. **Rate Limiting Issues**
   - Check rate limit configuration
   - Verify time window settings
   - Review API quotas
   - Check security logs

6. **Data Persistence Issues**
   - Verify Docker volume is properly configured
   - Check database initialization logs
   - Ensure no manual table dropping occurs
   - Review database connection parameters

7. **Geographic Analysis Issues**
   - Verify Shodan API key is valid and has sufficient quota
   - Check if geographic data is available in Shodan responses
   - Review API rate limiting for Shodan calls
   - Ensure proper JSON parsing of geographic data

## Recent Updates

### Version 2.1 - Geographic Analysis & Enhanced Visualizations
- **Geographic Analysis:** Added comprehensive geographic threat distribution analysis
- **Threat Score Distribution:** New visualization of threat scores by ranges
- **Enhanced Charts:** Interactive bar charts for geographic and score analysis
- **Detailed Breakdowns:** Comprehensive tables with percentages and statistics
- **Country Statistics:** Track threat levels by geographic location
- **City-Level Analysis:** Detailed threat analysis by city
- **Real-time Mapping:** Geographic threat mapping with live data

### Version 2.0 - Major Improvements
- **Data Persistence:** Fixed database initialization to preserve data across restarts
- **Domain Tracking:** Enhanced domain analysis with proper database storage
- **Reset Functionality:** Added comprehensive database reset feature
- **Enhanced Input:** Improved domain input flexibility
- **Historical Analysis:** Added domain statistics and enhanced metrics
- **JSON Serialization:** Fixed datetime serialization issues in domain storage
- **Better UX:** Improved user experience with flexible domain input

## Support
For issues and feature requests, please open an issue in the GitHub repository.

