#!/bin/bash

# Go Forward Backup Script
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BACKUP_DIR="./backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
COMPOSE_FILE="docker-compose.yml"

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

# Function to create backup directory
create_backup_dir() {
    mkdir -p "$BACKUP_DIR"
    print_status "Backup directory created: $BACKUP_DIR"
}

# Function to backup database
backup_database() {
    print_status "Starting database backup..."
    
    # Get database container name
    DB_CONTAINER=$(docker-compose -f "$COMPOSE_FILE" ps -q postgres)
    
    if [ -z "$DB_CONTAINER" ]; then
        print_error "Database container not found. Is the application running?"
        exit 1
    fi
    
    # Create database backup
    BACKUP_FILE="$BACKUP_DIR/database_backup_$TIMESTAMP.sql"
    
    docker exec "$DB_CONTAINER" pg_dumpall -c -U postgres > "$BACKUP_FILE"
    
    if [ $? -eq 0 ]; then
        print_status "Database backup completed: $BACKUP_FILE"
        
        # Compress the backup
        gzip "$BACKUP_FILE"
        print_status "Database backup compressed: $BACKUP_FILE.gz"
    else
        print_error "Database backup failed"
        exit 1
    fi
}

# Function to backup storage files
backup_storage() {
    print_status "Starting storage backup..."
    
    if [ -d "./storage" ]; then
        STORAGE_BACKUP="$BACKUP_DIR/storage_backup_$TIMESTAMP.tar.gz"
        tar -czf "$STORAGE_BACKUP" -C . storage
        
        if [ $? -eq 0 ]; then
            print_status "Storage backup completed: $STORAGE_BACKUP"
        else
            print_error "Storage backup failed"
            exit 1
        fi
    else
        print_warning "Storage directory not found, skipping storage backup"
    fi
}

# Function to backup configuration files
backup_config() {
    print_status "Starting configuration backup..."
    
    CONFIG_BACKUP="$BACKUP_DIR/config_backup_$TIMESTAMP.tar.gz"
    
    # List of configuration files to backup
    CONFIG_FILES=""
    
    # Check for configuration files
    for file in config.yaml config.prod.yaml .env .env.prod nginx.conf nginx.prod.conf; do
        if [ -f "$file" ]; then
            CONFIG_FILES="$CONFIG_FILES $file"
        fi
    done
    
    if [ -n "$CONFIG_FILES" ]; then
        tar -czf "$CONFIG_BACKUP" $CONFIG_FILES
        
        if [ $? -eq 0 ]; then
            print_status "Configuration backup completed: $CONFIG_BACKUP"
        else
            print_error "Configuration backup failed"
            exit 1
        fi
    else
        print_warning "No configuration files found, skipping configuration backup"
    fi
}

# Function to backup logs
backup_logs() {
    print_status "Starting logs backup..."
    
    if [ -d "./logs" ]; then
        LOGS_BACKUP="$BACKUP_DIR/logs_backup_$TIMESTAMP.tar.gz"
        tar -czf "$LOGS_BACKUP" -C . logs
        
        if [ $? -eq 0 ]; then
            print_status "Logs backup completed: $LOGS_BACKUP"
        else
            print_error "Logs backup failed"
            exit 1
        fi
    else
        print_warning "Logs directory not found, skipping logs backup"
    fi
}

# Function to create full backup
full_backup() {
    print_status "Starting full backup..."
    
    create_backup_dir
    backup_database
    backup_storage
    backup_config
    backup_logs
    
    # Create a manifest file
    MANIFEST_FILE="$BACKUP_DIR/backup_manifest_$TIMESTAMP.txt"
    cat > "$MANIFEST_FILE" << EOF
Go Forward Backup Manifest
Timestamp: $TIMESTAMP
Date: $(date)

Files included in this backup:
$(ls -la "$BACKUP_DIR"/*_$TIMESTAMP.*)

Database backup: database_backup_$TIMESTAMP.sql.gz
Storage backup: storage_backup_$TIMESTAMP.tar.gz
Configuration backup: config_backup_$TIMESTAMP.tar.gz
Logs backup: logs_backup_$TIMESTAMP.tar.gz

To restore from this backup:
1. Stop the application: docker-compose down
2. Restore database: gunzip -c database_backup_$TIMESTAMP.sql.gz | docker exec -i <postgres_container> psql -U postgres
3. Extract storage: tar -xzf storage_backup_$TIMESTAMP.tar.gz
4. Extract configuration: tar -xzf config_backup_$TIMESTAMP.tar.gz
5. Start the application: docker-compose up -d
EOF
    
    print_status "Backup manifest created: $MANIFEST_FILE"
    print_status "Full backup completed successfully!"
}

# Function to cleanup old backups
cleanup_old_backups() {
    local DAYS=${1:-7}
    print_status "Cleaning up backups older than $DAYS days..."
    
    find "$BACKUP_DIR" -name "*backup_*" -type f -mtime +$DAYS -delete
    
    print_status "Old backups cleaned up"
}

# Function to list available backups
list_backups() {
    print_status "Available backups:"
    
    if [ -d "$BACKUP_DIR" ]; then
        ls -la "$BACKUP_DIR"
    else
        print_warning "No backup directory found"
    fi
}

# Function to restore from backup
restore_backup() {
    local BACKUP_TIMESTAMP=$1
    
    if [ -z "$BACKUP_TIMESTAMP" ]; then
        print_error "Please provide a backup timestamp (e.g., 20231201_143000)"
        exit 1
    fi
    
    print_status "Restoring from backup: $BACKUP_TIMESTAMP"
    
    # Check if backup files exist
    DB_BACKUP="$BACKUP_DIR/database_backup_$BACKUP_TIMESTAMP.sql.gz"
    STORAGE_BACKUP="$BACKUP_DIR/storage_backup_$BACKUP_TIMESTAMP.tar.gz"
    CONFIG_BACKUP="$BACKUP_DIR/config_backup_$BACKUP_TIMESTAMP.tar.gz"
    
    if [ ! -f "$DB_BACKUP" ]; then
        print_error "Database backup not found: $DB_BACKUP"
        exit 1
    fi
    
    # Stop services
    print_status "Stopping services..."
    docker-compose -f "$COMPOSE_FILE" down
    
    # Restore database
    print_status "Restoring database..."
    docker-compose -f "$COMPOSE_FILE" up -d postgres
    sleep 10
    
    DB_CONTAINER=$(docker-compose -f "$COMPOSE_FILE" ps -q postgres)
    gunzip -c "$DB_BACKUP" | docker exec -i "$DB_CONTAINER" psql -U postgres
    
    # Restore storage
    if [ -f "$STORAGE_BACKUP" ]; then
        print_status "Restoring storage..."
        tar -xzf "$STORAGE_BACKUP"
    fi
    
    # Restore configuration
    if [ -f "$CONFIG_BACKUP" ]; then
        print_status "Restoring configuration..."
        tar -xzf "$CONFIG_BACKUP"
    fi
    
    # Start services
    print_status "Starting services..."
    docker-compose -f "$COMPOSE_FILE" up -d
    
    print_status "Restore completed successfully!"
}

# Main function
main() {
    case "${1:-full}" in
        full)
            full_backup
            ;;
        database|db)
            create_backup_dir
            backup_database
            ;;
        storage)
            create_backup_dir
            backup_storage
            ;;
        config)
            create_backup_dir
            backup_config
            ;;
        logs)
            create_backup_dir
            backup_logs
            ;;
        cleanup)
            cleanup_old_backups "${2:-7}"
            ;;
        list)
            list_backups
            ;;
        restore)
            restore_backup "$2"
            ;;
        -h|--help)
            echo "Usage: $0 [command] [options]"
            echo ""
            echo "Commands:"
            echo "  full              - Create full backup (default)"
            echo "  database, db      - Backup database only"
            echo "  storage           - Backup storage files only"
            echo "  config            - Backup configuration files only"
            echo "  logs              - Backup log files only"
            echo "  cleanup [days]    - Cleanup backups older than [days] (default: 7)"
            echo "  list              - List available backups"
            echo "  restore <timestamp> - Restore from backup"
            echo ""
            echo "Options:"
            echo "  -h, --help        - Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown command: $1"
            echo "Use '$0 --help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"