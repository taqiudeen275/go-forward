# Go Forward Deployment Guide

This guide covers deploying the Go Forward framework in different environments using Docker and Docker Compose.

## Prerequisites

- Docker 20.10 or later
- Docker Compose 2.0 or later
- Git
- At least 2GB of available RAM
- At least 5GB of available disk space

## Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/taqiudeen275/go-forward.git
   cd go-forward
   ```

2. **Copy environment configuration**
   ```bash
   cp .env.example .env
   ```

3. **Edit environment variables**
   ```bash
   nano .env  # or your preferred editor
   ```

4. **Deploy using the deployment script**
   ```bash
   chmod +x scripts/deploy.sh
   ./scripts/deploy.sh
   ```

5. **Access the application**
   - Application: http://localhost:8080
   - Admin Dashboard: http://localhost:8080/admin
   - API Documentation: http://localhost:8080/docs

## Environment Configurations

### Development Environment

For development with hot reloading and debugging tools:

```bash
./scripts/deploy.sh development
```

This uses `docker-compose.dev.yml` and includes:
- Development database on port 5433
- Redis on port 6380
- Adminer (database management) on port 8081
- Redis Commander on port 8082

### Production Environment

For production deployment with optimized settings:

```bash
./scripts/deploy.sh production
```

This uses `docker-compose.prod.yml` and includes:
- SSL/TLS configuration
- Resource limits
- Health checks
- Nginx reverse proxy
- Backup volumes

## Manual Deployment

### 1. Environment Configuration

Create and configure your environment file:

```bash
cp .env.example .env
```

Required environment variables:

```bash
# Database
POSTGRES_DB=goforward
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your-secure-password

# JWT Secret (at least 32 characters)
JWT_SECRET=your-super-secret-jwt-key-at-least-32-characters-long

# SMTP Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=noreply@yourapp.com
```

### 2. Build and Start Services

```bash
# Development
docker-compose -f docker-compose.dev.yml up -d --build

# Production
docker-compose -f docker-compose.prod.yml up -d --build
```

### 3. Run Database Migrations

```bash
# Wait for database to be ready
sleep 10

# Run migrations
docker-compose exec goforward ./migrate up
```

### 4. Verify Deployment

```bash
# Check service status
docker-compose ps

# Check application health
curl http://localhost:8080/health

# View logs
docker-compose logs -f goforward
```

## Configuration Files

### Docker Compose Files

- `docker-compose.yml` - Default configuration
- `docker-compose.dev.yml` - Development environment
- `docker-compose.prod.yml` - Production environment

### Nginx Configuration

- `nginx.conf` - Default Nginx configuration
- `nginx.prod.conf` - Production Nginx configuration with SSL

### Application Configuration

- `config.yaml` - Default application configuration
- `config.prod.yaml` - Production application configuration

## SSL/TLS Configuration

For production deployments with SSL:

1. **Obtain SSL certificates**
   ```bash
   # Using Let's Encrypt with Certbot
   certbot certonly --standalone -d yourdomain.com
   
   # Copy certificates
   mkdir -p ssl
   cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem ssl/
   cp /etc/letsencrypt/live/yourdomain.com/privkey.pem ssl/
   ```

2. **Update Nginx configuration**
   ```nginx
   server {
       listen 443 ssl http2;
       server_name yourdomain.com;
       
       ssl_certificate /etc/nginx/ssl/fullchain.pem;
       ssl_certificate_key /etc/nginx/ssl/privkey.pem;
       
       # SSL configuration
       ssl_protocols TLSv1.2 TLSv1.3;
       ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
       ssl_prefer_server_ciphers off;
       
       # ... rest of configuration
   }
   ```

## Scaling and Load Balancing

### Horizontal Scaling

Scale the application service:

```bash
docker-compose up -d --scale goforward=3
```

### Load Balancer Configuration

Update Nginx upstream configuration:

```nginx
upstream goforward_backend {
    server goforward_1:8080;
    server goforward_2:8080;
    server goforward_3:8080;
    keepalive 32;
}
```

## Monitoring and Logging

### Application Logs

```bash
# View real-time logs
docker-compose logs -f goforward

# View specific service logs
docker-compose logs -f postgres
docker-compose logs -f redis
```

### Health Checks

```bash
# Application health
curl http://localhost:8080/health

# Database health
docker-compose exec postgres pg_isready -U postgres

# Redis health
docker-compose exec redis redis-cli ping
```

### Metrics and Monitoring

For production monitoring, consider integrating:

- Prometheus for metrics collection
- Grafana for visualization
- ELK stack for log aggregation
- Jaeger for distributed tracing

## Backup and Recovery

### Automated Backups

Use the backup script:

```bash
chmod +x scripts/backup.sh

# Full backup
./scripts/backup.sh full

# Database only
./scripts/backup.sh database

# Schedule daily backups
crontab -e
# Add: 0 2 * * * /path/to/go-forward/scripts/backup.sh full
```

### Manual Backup

```bash
# Database backup
docker-compose exec postgres pg_dumpall -c -U postgres > backup.sql

# Storage backup
tar -czf storage_backup.tar.gz storage/

# Configuration backup
tar -czf config_backup.tar.gz config.yaml .env nginx.conf
```

### Recovery

```bash
# Restore database
docker-compose exec -T postgres psql -U postgres < backup.sql

# Restore storage
tar -xzf storage_backup.tar.gz

# Restore configuration
tar -xzf config_backup.tar.gz
```

## Troubleshooting

### Common Issues

1. **Port conflicts**
   ```bash
   # Check port usage
   netstat -tulpn | grep :8080
   
   # Change port in docker-compose.yml
   ports:
     - "8081:8080"  # Use different external port
   ```

2. **Database connection issues**
   ```bash
   # Check database logs
   docker-compose logs postgres
   
   # Test connection
   docker-compose exec postgres psql -U postgres -d goforward
   ```

3. **Permission issues**
   ```bash
   # Fix storage permissions
   sudo chown -R 1001:1001 storage/
   sudo chmod -R 755 storage/
   ```

4. **Memory issues**
   ```bash
   # Check resource usage
   docker stats
   
   # Increase memory limits in docker-compose.yml
   deploy:
     resources:
       limits:
         memory: 2G
   ```

### Debug Mode

Enable debug logging:

```bash
# Set environment variable
GOFORWARD_LOGGING_LEVEL=debug

# Or update config.yaml
logging:
  level: debug
```

### Container Shell Access

```bash
# Access application container
docker-compose exec goforward sh

# Access database container
docker-compose exec postgres psql -U postgres

# Access Redis container
docker-compose exec redis redis-cli
```

## Performance Optimization

### Database Optimization

1. **Connection pooling**
   ```yaml
   database:
     max_connections: 50
     max_idle_connections: 10
   ```

2. **Indexes and queries**
   - Monitor slow queries
   - Add appropriate indexes
   - Use connection pooling

### Application Optimization

1. **Resource limits**
   ```yaml
   deploy:
     resources:
       limits:
         memory: 1G
         cpus: '1.0'
   ```

2. **Caching**
   - Enable Redis caching
   - Configure cache TTL
   - Use CDN for static assets

### Network Optimization

1. **Nginx optimization**
   ```nginx
   # Enable compression
   gzip on;
   gzip_comp_level 6;
   
   # Enable caching
   location /static/ {
       expires 1y;
       add_header Cache-Control "public, immutable";
   }
   ```

## Security Best Practices

1. **Use strong passwords and secrets**
2. **Enable SSL/TLS in production**
3. **Configure firewall rules**
4. **Regular security updates**
5. **Monitor access logs**
6. **Use non-root containers**
7. **Implement rate limiting**
8. **Regular backups**

## Maintenance

### Regular Tasks

1. **Update dependencies**
   ```bash
   docker-compose pull
   docker-compose up -d --build
   ```

2. **Clean up old images**
   ```bash
   docker system prune -a
   ```

3. **Monitor disk space**
   ```bash
   df -h
   docker system df
   ```

4. **Review logs**
   ```bash
   docker-compose logs --since 24h
   ```

### Scheduled Maintenance

1. **Weekly backups**
2. **Monthly security updates**
3. **Quarterly performance reviews**
4. **Annual disaster recovery tests**