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
