#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ $2${NC}"
    else
        echo -e "${RED}✗ $2${NC}"
        if [ ! -z "$3" ]; then
            echo -e "${RED}  Error: $3${NC}"
        fi
    fi
}

# Function to check prerequisites
check_prerequisites() {
    echo -e "\n${YELLOW}Checking prerequisites...${NC}"
    
    # Check Docker
    if command -v docker &> /dev/null; then
        docker_version=$(docker --version)
        print_status 0 "Docker installed: $docker_version"
    else
        print_status 1 "Docker is not installed"
        exit 1
    fi

    # Check Docker Compose
    if command -v docker-compose &> /dev/null; then
        compose_version=$(docker-compose --version)
        print_status 0 "Docker Compose installed: $compose_version"
    else
        print_status 1 "Docker Compose is not installed"
        exit 1
    fi
}

# Function to check required files
check_required_files() {
    echo -e "\n${YELLOW}Checking required files...${NC}"
    
    required_files=(".env" "docker-compose.yml" "requirements.txt" "Dockerfile.web" "Dockerfile.ml" "Dockerfile.analyzer" "Dockerfile.db")
    
    for file in "${required_files[@]}"; do
        if [ -f "$file" ]; then
            print_status 0 "$file exists"
        else
            print_status 1 "$file is missing"
            echo -e "${RED}Please ensure all required files are present before continuing${NC}"
            exit 1
        fi
    done
}

# Function to check environment variables
check_env_variables() {
    echo -e "\n${YELLOW}Checking environment variables...${NC}"
    
    if [ -f ".env" ]; then
        required_vars=("POSTGRES_USER" "POSTGRES_PASSWORD" "POSTGRES_DB" "VIRUSTOTAL_API_KEY" "SHODAN_API_KEY" "ALIENVAULT_API_KEY")
        missing_vars=()
        
        while IFS= read -r line || [ -n "$line" ]; do
            if [[ $line =~ ^[^#] ]]; then
                for var in "${required_vars[@]}"; do
                    if [[ $line == $var=* ]]; then
                        value="${line#*=}"
                        if [ -z "$value" ]; then
                            missing_vars+=("$var")
                        fi
                    fi
                done
            fi
        done < ".env"
        
        if [ ${#missing_vars[@]} -eq 0 ]; then
            print_status 0 "All required environment variables are set"
        else
            print_status 1 "Missing or empty environment variables: ${missing_vars[*]}"
            exit 1
        fi
    else
        print_status 1 ".env file not found"
        exit 1
    fi
}

# Function to clean up existing containers
cleanup_containers() {
    echo -e "\n${YELLOW}Cleaning up existing containers...${NC}"
    
    docker-compose down --remove-orphans
    print_status $? "Stopped and removed existing containers"
}

# Function to build and start services
start_services() {
    echo -e "\n${YELLOW}Building and starting services...${NC}"
    
    docker-compose up --build -d
    print_status $? "Services built and started"
}

# Function to check service health
check_service_health() {
    echo -e "\n${YELLOW}Checking service health...${NC}"
    
    # Wait for services to be ready
    echo "Waiting for services to initialize (30 seconds)..."
    sleep 30
    
    # Check each service
    services=("web" "ml" "analyzer" "db")
    for service in "${services[@]}"; do
        container_status=$(docker-compose ps -q $service)
        if [ ! -z "$container_status" ]; then
            container_health=$(docker inspect --format='{{.State.Status}}' $container_status)
            print_status 0 "$service service: $container_health"
        else
            print_status 1 "$service service not found"
        fi
    done
}

# Function to check logs for errors
check_logs() {
    echo -e "\n${YELLOW}Checking service logs for errors...${NC}"
    
    services=("web" "ml" "analyzer" "db")
    for service in "${services[@]}"; do
        error_count=$(docker-compose logs $service | grep -i "error" | wc -l)
        if [ $error_count -eq 0 ]; then
            print_status 0 "No errors found in $service logs"
        else
            print_status 1 "Found $error_count errors in $service logs"
            echo -e "${RED}Recent errors in $service:${NC}"
            docker-compose logs $service | grep -i "error" | tail -n 5
        fi
    done
}

# Function to display resource usage
show_resource_usage() {
    echo -e "\n${YELLOW}Current resource usage:${NC}"
    docker stats --no-stream
}

# Function to run security checks
run_security_checks() {
    echo -e "\n${YELLOW}Running security checks...${NC}"
    
    # Check container user
    for service in $(docker-compose ps -q); do
        user=$(docker inspect --format '{{.Config.User}}' $service)
        if [ -z "$user" ] || [ "$user" == "root" ]; then
            print_status 1 "Container $(docker inspect --format '{{.Name}}' $service) is running as root"
        else
            print_status 0 "Container $(docker inspect --format '{{.Name}}' $service) is running as $user"
        fi
    done
    
    # Check exposed ports
    echo -e "\n${YELLOW}Exposed ports:${NC}"
    docker-compose ps | grep -v "Name" | awk '{print $1 " -> " $6}'
}

# Main execution
echo -e "${YELLOW}Starting Threat Intelligence Platform local environment test...${NC}"

check_prerequisites
check_required_files
check_env_variables
cleanup_containers
start_services
check_service_health
check_logs
show_resource_usage
run_security_checks

echo -e "\n${GREEN}Test complete!${NC}"
echo -e "${GREEN}Access the web interface at http://localhost:8501${NC}"

# Provide helper commands
echo -e "\n${YELLOW}Useful commands:${NC}"
echo "- View all logs: docker-compose logs -f"
echo "- View specific service logs: docker-compose logs -f [service_name]"
echo "- Stop all services: docker-compose down"
echo "- Restart a service: docker-compose restart [service_name]"
echo "- Check container status: docker-compose ps"
