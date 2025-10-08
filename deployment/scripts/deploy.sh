#!/bin/bash

# Go Forward Deployment Script
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
ENVIRONMENT=${1:-development}
COMPOSE_FILE=""
ENV_FILE=""

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
}

# Function to check if Docker Compose is available
check_docker_compose() {
    if ! command -v docker-compose > /dev/null 2>&1; then
        print_error "Docker Compose is not installed. Please install Docker Compose and try again."
        exit 1
    fi
}

# Function to set environment-specific configuration
set_environment() {
    case $ENVIRONMENT in
        development|dev)
            COMPOSE_FILE="docker-compose.dev.yml"
            ENV_FILE=".env.dev"
            print_status "Deploying to development environment"
            ;;
        production|prod)
            COMPOSE_FILE="docker-compose.prod.yml"
            ENV_FILE=".env"
            print_status "Deploying to production environment"
            ;;
        *)
            COMPOSE_FILE="docker-compose.yml"
            ENV_FILE=".env"
            print_status "Deploying to default environment"
            ;;
    esac
}

# Function to check if environment file exists
check_env_file() {
    if [ ! -f "$ENV_FILE" ]; then
        print_warning "Environment file $ENV_FILE not found."
        if [ -f ".env.example" ]; then
            print_status "Copying .env.example to $ENV_FILE"
            cp .env.example "$ENV_FILE"
            print_warning "Please edit $ENV_FILE with your configuration before continuing."
            read -p "Press Enter to continue after editing the environment file..."
        else
            print_error "No environment file found. Please create $ENV_FILE with your configuration."
            exit 1
        fi
    fi
}

# Function to create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    mkdir -p storage logs plugins ssl backups
    chmod 755 storage logs plugins
}

# Function to build and start services
deploy_services() {
    print_status "Building and starting services..."
    
    # Export environment variables
    export $(grep -v '^#' "$ENV_FILE" | xargs)
    
    # Build and start services
    docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --build
    
    print_status "Services started successfully!"
}

# Function to run database migrations
run_migrations() {
    print_status "Running database migrations..."
    
    # Wait for database to be ready
    print_status "Waiting for database to be ready..."
    sleep 10
    
    # Run migrations
    docker-compose -f "$COMPOSE_FILE" exec goforward ./migrate up
    
    print_status "Database migrations completed!"
}

# Function to show service status
show_status() {
    print_status "Service status:"
    docker-compose -f "$COMPOSE_FILE" ps
    
    print_status "Service logs (last 20 lines):"
    docker-compose -f "$COMPOSE_FILE" logs --tail=20
}

# Function to perform health checks
health_check() {
    print_status "Performing health checks..."
    
    # Wait a bit for services to start
    sleep 5
    
    # Check if the application is responding
    if curl -f http://localhost:8080/health > /dev/null 2>&1; then
        print_status "Application health check passed!"
    else
        print_warning "Application health check failed. Check the logs for more information."
    fi
}

# Function to show deployment information
show_info() {
    print_status "Deployment completed!"
    echo ""
    echo "Application URL: http://localhost:8080"
    echo "Admin Dashboard: http://localhost:8080/admin"
    echo "API Documentation: http://localhost:8080/docs"
    echo ""
    echo "Useful commands:"
    echo "  View logs: docker-compose -f $COMPOSE_FILE logs -f"
    echo "  Stop services: docker-compose -f $COMPOSE_FILE down"
    echo "  Restart services: docker-compose -f $COMPOSE_FILE restart"
    echo "  Run migrations: docker-compose -f $COMPOSE_FILE exec goforward ./migrate up"
    echo ""
}

# Main deployment function
main() {
    print_status "Starting Go Forward deployment..."
    
    # Check prerequisites
    check_docker
    check_docker_compose
    
    # Set environment configuration
    set_environment
    
    # Check environment file
    check_env_file
    
    # Create directories
    create_directories
    
    # Deploy services
    deploy_services
    
    # Run migrations
    run_migrations
    
    # Show status
    show_status
    
    # Health check
    health_check
    
    # Show deployment info
    show_info
}

# Handle script arguments
case "${1:-}" in
    -h|--help)
        echo "Usage: $0 [environment]"
        echo ""
        echo "Environments:"
        echo "  development, dev  - Deploy to development environment"
        echo "  production, prod  - Deploy to production environment"
        echo "  (default)         - Deploy to default environment"
        echo ""
        echo "Options:"
        echo "  -h, --help        - Show this help message"
        exit 0
        ;;
    *)
        main
        ;;
esac