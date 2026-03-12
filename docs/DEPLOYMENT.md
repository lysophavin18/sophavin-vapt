# VAPT Deployment Guide

## Table of Contents
1. [VM Requirements](#vm-requirements)
2. [Quick Start](#quick-start)
3. [Production Deployment](#production-deployment)
4. [Configuration](#configuration)
5. [SSL/TLS Setup](#ssltls-setup)
6. [Monitoring](#monitoring)
7. [Backup & Recovery](#backup--recovery)
8. [Troubleshooting](#troubleshooting)

---

## VM Requirements

### Minimum Requirements (Development/Testing)
| Resource | Specification |
|----------|--------------|
| CPU | 4 cores |
| RAM | 8 GB |
| Storage | 50 GB SSD |
| OS | Ubuntu 22.04 LTS / Debian 12 |
| Network | 1 Gbps NIC |

### Recommended (Production - Small Team)
| Resource | Specification |
|----------|--------------|
| CPU | 8 cores (Intel Xeon / AMD EPYC) |
| RAM | 16 GB |
| Storage | 200 GB NVMe SSD |
| OS | Ubuntu 22.04 LTS |
| Network | 1 Gbps NIC |

### Enterprise (Production - Large Deployments)
| Resource | Specification |
|----------|--------------|
| CPU | 16+ cores |
| RAM | 32+ GB |
| Storage | 500 GB+ NVMe SSD |
| OS | Ubuntu 22.04 LTS (hardened) |
| Network | 10 Gbps NIC |

### Storage Breakdown
```
/                      - 30 GB (OS + Docker)
/var/lib/docker        - 50+ GB (Container images and volumes)
/opt/noovastack        - 20+ GB (Application data)
/var/log               - 10 GB (Logs)
```

### Network Requirements
- Outbound access to targets being scanned
- Inbound ports: 80, 443 (HTTPS), 22 (SSH for management)
- Internal Docker network (isolated)
- Recommended: Separate VLAN for scanner traffic

---

## Quick Start

### Prerequisites
```bash
# Install Docker
curl -fsSL https://get.docker.com | bash

# Install Docker Compose
sudo apt install docker-compose-plugin

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

### Deploy
```bash
# Clone repository
git clone https://github.com/your-org/noovastack-vapt.git
cd noovastack-vapt

# Configure environment
cp .env.example .env
nano .env  # Edit configuration

# Start services
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs -f
```

### Access
- **Web UI**: http://localhost (or your server IP)
- **Default Credentials**: admin / ChangeMe123!

> ⚠️ **IMPORTANT**: Change the default password immediately after first login!

---

## Production Deployment

### 1. System Preparation
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    fail2ban \
    ufw

# Enable firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Configure fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 2. Docker Installation (Production)
```bash
# Install Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Configure Docker daemon
sudo tee /etc/docker/daemon.json << EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "live-restore": true
}
EOF

sudo systemctl restart docker
```

### 3. Deploy Application
```bash
# Create application directory
sudo mkdir -p /opt/noovastack
cd /opt/noovastack

# Copy or clone application files
# git clone ... or copy files

# Set permissions
sudo chown -R $USER:docker /opt/noovastack

# Create production .env
cp .env.example .env

# Generate secure secrets
SECRET_KEY=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -base64 24)

# Update .env with secure values
sed -i "s/change-this-to-a-secure-random-string-in-production/$SECRET_KEY/" .env
sed -i "s/change-this-jwt-secret-in-production/$JWT_SECRET/" .env
sed -i "s/SecurePassword123!/$DB_PASSWORD/" .env

# Start services
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### 4. Create systemd Service
```bash
sudo tee /etc/systemd/system/noovastack.service << EOF
[Unit]
Description=Noovastack VAPT Platform
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/noovastack
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable noovastack
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | (required) | Application secret key |
| `JWT_SECRET_KEY` | (required) | JWT signing key |
| `POSTGRES_PASSWORD` | (required) | Database password |
| `MAX_CONCURRENT_SCANS` | 5 | Maximum parallel scans |
| `SCAN_TIMEOUT_MINUTES` | 60 | Scan timeout |
| `REQUIRE_SCAN_APPROVAL` | true | Require approval for external targets |
| `ALLOWED_SCAN_NETWORKS` | RFC1918 | Networks allowed for scanning |

### Resource Limits
Edit `docker-compose.yml` to adjust resource limits:
```yaml
services:
  backend:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
```

---

## SSL/TLS Setup

### Option 1: Let's Encrypt (Recommended)
```bash
# Install certbot
sudo apt install certbot

# Get certificate
sudo certbot certonly --standalone -d your-domain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem configs/nginx/ssl/
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem configs/nginx/ssl/

# Enable HTTPS in nginx.conf
# Uncomment the HTTPS server block

# Restart nginx
docker compose restart nginx
```

### Option 2: Self-Signed (Development)
```bash
# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout configs/nginx/ssl/privkey.pem \
  -out configs/nginx/ssl/fullchain.pem \
  -subj "/CN=localhost"
```

### Auto-Renewal (Let's Encrypt)
```bash
# Add cron job
echo "0 12 * * * /usr/bin/certbot renew --quiet && docker compose restart nginx" | sudo crontab -
```

---

## Monitoring

### Prometheus + Grafana
The platform exposes metrics at `/metrics`. For complete monitoring:

```bash
# Access Grafana
open http://localhost:3001

# Default credentials
# admin / admin
```

### Health Checks
```bash
# Check all services
curl http://localhost/health

# Check individual services
docker compose ps
docker compose logs backend --tail=100
```

### Log Aggregation
Logs are output in JSON format for easy parsing:
```bash
# View all logs
docker compose logs -f

# Filter by service
docker compose logs -f backend orchestrator

# Export to file
docker compose logs --no-color > logs/$(date +%Y%m%d).log
```

---

## Backup & Recovery

### Database Backup
```bash
# Create backup
docker compose exec postgres pg_dump -U noovastack noovastack | gzip > backup_$(date +%Y%m%d_%H%M%S).sql.gz

# Automated daily backup
cat << 'EOF' | sudo tee /etc/cron.daily/noovastack-backup
#!/bin/bash
cd /opt/noovastack
docker compose exec -T postgres pg_dump -U noovastack noovastack | gzip > /opt/backups/noovastack_$(date +%Y%m%d).sql.gz
find /opt/backups -name "noovastack_*.sql.gz" -mtime +30 -delete
EOF
sudo chmod +x /etc/cron.daily/noovastack-backup
```

### Restore Database
```bash
# Stop services
docker compose stop backend orchestrator

# Restore
gunzip -c backup_20240101_120000.sql.gz | docker compose exec -T postgres psql -U noovastack noovastack

# Start services
docker compose start backend orchestrator
```

### Volume Backup
```bash
# Backup all volumes
docker run --rm -v noovastack_postgres-data:/data -v $(pwd):/backup alpine tar czf /backup/postgres-data.tar.gz /data
docker run --rm -v noovastack_redis-data:/data -v $(pwd):/backup alpine tar czf /backup/redis-data.tar.gz /data
```

---

## Troubleshooting

### Common Issues

#### Services Not Starting
```bash
# Check logs
docker compose logs --tail=50

# Check resource usage
docker stats

# Restart all services
docker compose restart
```

#### Database Connection Failed
```bash
# Check postgres is running
docker compose ps postgres

# Check connection
docker compose exec backend python -c "from app.core.database import engine; print('OK')"

# Recreate database
docker compose down -v
docker compose up -d
```

#### Scans Not Running
```bash
# Check orchestrator logs
docker compose logs orchestrator -f

# Check Redis connection
docker compose exec redis redis-cli ping

# Check Celery workers
docker compose exec orchestrator celery -A tasks inspect active
```

#### High Memory Usage
```bash
# Check container memory
docker stats --no-stream

# Restart memory-heavy containers
docker compose restart openvas zap

# Adjust resource limits in docker-compose.yml
```

### Performance Tuning

#### PostgreSQL
```sql
-- Add to postgresql.conf or as environment variables
shared_buffers = 256MB
effective_cache_size = 768MB
work_mem = 16MB
maintenance_work_mem = 128MB
```

#### Redis
```bash
# Increase max memory
docker compose exec redis redis-cli CONFIG SET maxmemory 512mb
docker compose exec redis redis-cli CONFIG SET maxmemory-policy allkeys-lru
```

### Getting Help
1. Check the logs: `docker compose logs`
2. Review the documentation
3. Search existing issues on GitHub
4. Open a new issue with:
   - Environment details (OS, Docker version)
   - Error messages
   - Steps to reproduce

---

## Security Checklist

- [ ] Changed default admin password
- [ ] Set strong SECRET_KEY and JWT_SECRET_KEY
- [ ] Enabled HTTPS/TLS
- [ ] Configured firewall (ufw/iptables)
- [ ] Enabled fail2ban
- [ ] Restricted ALLOWED_SCAN_NETWORKS
- [ ] Enabled REQUIRE_SCAN_APPROVAL for external targets
- [ ] Configured backup automation
- [ ] Set up monitoring alerts
- [ ] Reviewed Docker security (non-root users, read-only filesystems)
- [ ] Enabled audit logging
- [ ] Rotated secrets periodically
