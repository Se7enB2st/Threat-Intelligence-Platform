FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 appuser

# Copy requirements first
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY database.py .
COPY threat_analyzer.py .
COPY wait_for_db.py .

# Set environment variables
ENV PYTHONPATH=/app

# Create necessary directories
RUN mkdir -p /app/data && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8501

# Wait for DB and then start Streamlit
CMD ["sh", "-c", "python wait_for_db.py && streamlit run app.py"] 