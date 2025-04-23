FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y     build-essential     && rm -rf /var/lib/apt/lists/*

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
