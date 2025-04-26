FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 appuser

# Copy requirements first
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir black pylint pytest pytest-cov

# Copy application files
COPY . /app/

# Set development environment variables
ENV PYTHONPATH=/app
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_ENABLE_CORS=true
ENV STREAMLIT_SERVER_HEADLESS=false
ENV STREAMLIT_SERVER_MAX_UPLOAD_SIZE=200
ENV STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION=true
ENV STREAMLIT_SERVER_ENABLE_WEBSOCKET_COMPRESSION=true
ENV STREAMLIT_SERVER_FILE_WATCHER_TYPE=watchdog
ENV STREAMLIT_SERVER_SHOW_ERROR_DETAILS=true
ENV STREAMLIT_SERVER_SHOW_TRACE_IN_CONSOLE=true
ENV STREAMLIT_SERVER_SHOW_DEBUG_MESSAGES=true
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Create necessary directories and set permissions
RUN mkdir -p /app/data /app/logs /app/tests && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8501

# Start Streamlit in development mode
CMD ["streamlit", "run", \
    "--server.address", "0.0.0.0", \
    "--server.port", "8501", \
    "--server.enableCORS", "true", \
    "--server.headless", "false", \
    "--server.maxUploadSize", "200", \
    "--server.enableXsrfProtection", "true", \
    "--server.enableWebsocketCompression", "true", \
    "--server.fileWatcherType", "watchdog", \
    "--server.showErrorDetails", "true", \
    "--server.showTraceInConsole", "true", \
    "--server.showDebugMessages", "true", \
    "app.py"] 