# Threat Intelligence Platform (MVP)

## Overview
The **Threat Intelligence Platform (MVP)** is a minimal viable product designed to aggregate and analyze cyber threat intelligence from key sources. It provides essential threat detection capabilities with a focus on simplicity, automation, and scalability.

## Core Features
- **Threat Aggregation:** Fetches intelligence from VirusTotal, Shodan, and AlienVault OTX.
- **Error Handling:** Provides detailed error messages for API failures and network issues.
- **Basic Threat Analysis:** Identifies potential threats based on known indicators of compromise (IOCs).
- **Simple Web Interface:** Provides a lightweight dashboard for visualization and notifications.
- **Containerized Deployment:** Uses Docker for easy setup and scalability.
- **Cloud Readiness:** Deployable with Terraform on AWS/Azure/GCP.

## Tech Stack
- **Programming Language:** Python (FastAPI for API, Pandas for data processing)
- **Threat Intelligence Sources:** VirusTotal, Shodan, AlienVault OTX
- **Database:** PostgreSQL for scalable storage
- **Containerization:** Docker for deployment
- **Infrastructure:** Terraform for cloud deployment

## Prerequisites
Before you begin, ensure you have:
- Python 3.10+
- Docker & Docker Compose
- PostgreSQL installed (if using locally)
- API keys from:
  - [VirusTotal](https://www.virustotal.com/gui/join-us)
  - [Shodan](https://account.shodan.io/)
  - [AlienVault OTX](https://otx.alienvault.com/)

## Setup

### Step 1: Clone the Repository
```bash
git clone https://github.com/Se7enB2st/Threat-Intelligence-Platform.git
cd Threat-Intelligence-Platform
```

### Step 2: Configure Environment Variables
Create a `.env` file using `.env.example` as a template:
```bash
cp .env.example .env
```
Add your API keys and PostgreSQL credentials in the `.env` file:
```
VIRUSTOTAL_API_KEY=your_virustotal_api_key
SHODAN_API_KEY=your_shodan_api_key
ALIENVAULT_API_KEY=your_alienvault_api_key
POSTGRES_USER=admin
POSTGRES_PASSWORD=admin
POSTGRES_DB=threats_db
```

### Step 3: Set Up the Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```
Install dependencies:
```bash
pip install -r requirements.txt
```

### Step 4: Set Up PostgreSQL Database
If you don't have PostgreSQL running, use Docker:
```bash
docker run --name postgres   -e POSTGRES_USER=admin   -e POSTGRES_PASSWORD=admin   -e POSTGRES_DB=threats_db   -p 5432:5432   -d postgres
```

### Step 5: Run Threat Aggregation
You can test the threat aggregation for a sample IP:
```bash
python threat_aggregation.py
```
Example Output:
```json
{
  "ip": "8.8.8.8",
  "virustotal": {...},
  "shodan": {...},
  "alienvault": {...}
}
```

## Next Steps
- Expand data sources (e.g., AbuseIPDB)
- Implement machine learning-based threat correlation
- Add support for Elasticsearch

## Contributions
Contributions are welcome! Fork the repository and submit a pull request.

