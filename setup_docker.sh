#!/bin/bash

# Create necessary directories
mkdir -p data logs models model_cache threat_cache

# Create .env file
cat > .env << EOL
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
EOL

# Create requirements.txt
cat > requirements.txt << EOL
# Core dependencies
streamlit==1.32.0
pandas==2.2.0
plotly==5.18.0
sqlalchemy==2.0.27
psycopg2-binary==2.9.9
python-dotenv==1.0.1

# ML and Analysis dependencies
scikit-learn==1.4.0
numpy==1.26.4
tensorflow==2.15.0
requests==2.31.0

# Domain analysis
dnspython==2.6.0
aiohttp==3.9.3
EOL

# Create Dockerfile.web
cat > Dockerfile.web << EOL
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY web_interface.py .
COPY database.py .
COPY threat_analyzer.py .
COPY data_manager.py .
COPY threat_aggregation.py .
COPY domain_analyzer.py .
COPY ml_detector.py .

# Create directory for SQLite database (if used in development)
RUN mkdir -p /app/data

# Expose Streamlit port
EXPOSE 8501

# Run the application
CMD ["streamlit", "run", "web_interface.py", "--server.address=0.0.0.0"]
EOL

# Create Dockerfile.ml
cat > Dockerfile.ml << EOL
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy ML-related code
COPY ml_detector.py .
COPY database.py .
COPY models/ ./models/

# Create model cache directory
RUN mkdir -p /app/model_cache

# Expose port for ML service API
EXPOSE 5000

# Run the ML service
CMD ["python", "ml_detector.py"]
EOL

# Create Dockerfile.analyzer
cat > Dockerfile.analyzer << EOL
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy analysis-related code
COPY threat_analyzer.py .
COPY domain_analyzer.py .
COPY threat_aggregation.py .
COPY database.py .

# Create cache directory for threat data
RUN mkdir -p /app/threat_cache

# Expose port for analyzer service API
EXPOSE 5001

# Run the analyzer service
CMD ["python", "threat_analyzer.py"]
EOL

# Create Dockerfile.db
cat > Dockerfile.db << EOL
FROM postgres:13

# Copy initialization scripts if needed
COPY init.sql /docker-entrypoint-initdb.d/

# Set default environment variables
ENV POSTGRES_DB=threats_db
ENV POSTGRES_USER=admin
ENV POSTGRES_PASSWORD=admin

# Expose PostgreSQL port
EXPOSE 5432
EOL

# Create docker-compose.yml
cat > docker-compose.yml << EOL
version: '3.8'

services:
  # Database service
  db:
    build:
      context: .
      dockerfile: Dockerfile.db
    env_file: .env
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U \${POSTGRES_USER}"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - threat-intel-network
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 512M

  # Web Interface service
  web:
    build:
      context: .
      dockerfile: Dockerfile.web
    env_file: .env
    ports:
      - "\${WEB_PORT}:8501"
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    networks:
      - threat-intel-network
    environment:
      - POSTGRES_HOST=db
      - ML_SERVICE_URL=http://ml:5000
      - ANALYZER_SERVICE_URL=http://analyzer:5001
    security_opt:
      - no-new-privileges:true
    user: "1000:1000"
    deploy:
      resources:
        limits:
          cpus: '0.50'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M

  # ML Detection service
  ml:
    build:
      context: .
      dockerfile: Dockerfile.ml
    env_file: .env
    volumes:
      - ./models:/app/models
      - ./model_cache:/app/model_cache
    depends_on:
      db:
        condition: service_healthy
    networks:
      - threat-intel-network
    environment:
      - POSTGRES_HOST=db
    security_opt:
      - no-new-privileges:true
    user: "1000:1000"
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 512M

  # Threat Analysis service
  analyzer:
    build:
      context: .
      dockerfile: Dockerfile.analyzer
    env_file: .env
    volumes:
      - ./threat_cache:/app/threat_cache
    depends_on:
      db:
        condition: service_healthy
    networks:
      - threat-intel-network
    environment:
      - POSTGRES_HOST=db
    security_opt:
      - no-new-privileges:true
    user: "1000:1000"
    deploy:
      resources:
        limits:
          cpus: '0.75'
          memory: 768M
        reservations:
          cpus: '0.25'
          memory: 384M

networks:
  threat-intel-network:
    driver: bridge

volumes:
  postgres_data:
  model_cache:
  threat_cache:
EOL

# Create test-local.sh
cat > test-local.sh << EOL
#!/bin/bash

# Stop any running containers
docker-compose down

# Remove old volumes (optional, uncomment if needed)
# docker-compose down -v

# Build and start services
docker-compose up --build -d

# Wait for services to be ready
echo "Waiting for services to start..."
sleep 10

# Check service health
echo "Checking service health..."
docker-compose ps

# Display logs
echo "Displaying logs..."
docker-compose logs --tail=100

echo "Local environment is ready!"
echo "Access the web interface at http://localhost:8501"
EOL

# Make scripts executable
chmod +x test-local.sh

echo "Docker setup files have been created successfully!"
echo "Please review the .env file and update the API keys before running the containers."