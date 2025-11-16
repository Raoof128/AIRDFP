# AIRDFP Deployment Guide

## Prerequisites

### System Requirements

**Minimum Specifications:**
- CPU: 8 cores
- RAM: 16 GB
- Storage: 500 GB SSD (for evidence vault: 2TB+ recommended)
- OS: Ubuntu 22.04 LTS / RHEL 8+ / Debian 11+

**Recommended Specifications (Production):**
- CPU: 16+ cores
- RAM: 32 GB
- Storage: 10 TB (evidence vault with 90-day retention)
- Network: 1 Gbps
- Backup: Automated daily backups to offsite location

### Software Dependencies

```bash
# Docker & Docker Compose
Docker Engine: 24.0+
Docker Compose: 2.20+

# Python
Python: 3.8+
pip: Latest

# Optional (for advanced forensics)
Volatility 3: 2.5.0+
Plaso: 20230308+
```

## Installation Steps

### Step 1: Clone Repository

```bash
git clone https://github.com/Raoof128/AIRDFP.git
cd AIRDFP
```

### Step 2: Install Python Dependencies

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

### Step 3: Deploy Core Infrastructure

```bash
# Navigate to Phase 1 directory
cd phase_1_foundation

# Start Docker Compose services
docker-compose up -d

# Verify all services are running
docker-compose ps
```

**Expected Output:**
```
NAME                    STATUS              PORTS
airdfp-elasticsearch    running             0.0.0.0:9200->9200/tcp
airdfp-thehive          running             0.0.0.0:9000->9000/tcp
airdfp-cortex           running             0.0.0.0:9001->9001/tcp
airdfp-redis            running             0.0.0.0:6379->6379/tcp
airdfp-minio            running             0.0.0.0:9002->9000/tcp
airdfp-postgres         running             0.0.0.0:5432->5432/tcp
```

### Step 4: Initialize TheHive

**Access TheHive UI:**
```
URL: http://localhost:9000
Default Credentials:
  Username: admin@thehive.local
  Password: secret

⚠️ IMPORTANT: Change default password immediately!
```

**Generate API Key:**
1. Log in to TheHive UI
2. Navigate to: Username (top right) → Settings → API Keys
3. Click "Create API Key"
4. Copy API key (you'll need this for configuration)

### Step 5: Configure Case Templates

```bash
cd /home/user/AIRDFP

# Setup TheHive case templates
python phase_1_foundation/thehive_setup.py \
  --url http://localhost:9000 \
  --api-key YOUR_THEHIVE_API_KEY

# Verify templates created
python phase_1_foundation/thehive_setup.py \
  --url http://localhost:9000 \
  --api-key YOUR_THEHIVE_API_KEY \
  --verify
```

**Expected Output:**
```
✅ Connected to TheHive at http://localhost:9000
🔧 Setting up TheHive case templates...

✅ Created template: CRITICAL_MALWARE
✅ Created template: LATERAL_MOVEMENT
✅ Created template: DATA_EXFILTRATION
✅ Created template: ACCOUNT_COMPROMISE

📋 Template Setup Summary:
  ✅ Created: 4
  ❌ Failed: 0
  📊 Total: 4

✅ Verification: Found 4 auto-generated templates
✅ Setup complete and verified!
```

### Step 6: Test SIEM Integration

```bash
# Test with simulated SIEM alerts
python phase_1_foundation/siem_integration.py \
  --thehive-url http://localhost:9000 \
  --thehive-key YOUR_THEHIVE_API_KEY \
  --test-mode

# Check created cases in TheHive UI
```

### Step 7: Configure Evidence Vault

```bash
# Create evidence vault directory
sudo mkdir -p /evidence_vault
sudo chown $USER:$USER /evidence_vault
sudo chmod 750 /evidence_vault

# Generate encryption key for evidence sealing
python phase_5_reporting/evidence_integrity.py --generate-coc

# IMPORTANT: Backup the generated key file!
sudo cp evidence_vault_key.bin /secure/backup/location/
```

### Step 8: Configure Velociraptor (Optional)

**Download Velociraptor:**
```bash
cd /opt
wget https://github.com/Velocidex/velociraptor/releases/download/v0.6.8/velociraptor-v0.6.8-linux-amd64
chmod +x velociraptor-v0.6.8-linux-amd64
sudo ln -s /opt/velociraptor-v0.6.8-linux-amd64 /usr/local/bin/velociraptor
```

**Generate Configuration:**
```bash
# Interactive configuration wizard
velociraptor config generate -i

# Follow prompts:
# - Server type: Linux
# - Deployment type: Server
# - Public DNS name: your-server.company.com
# - Port: 8000 (default)
```

**Start Velociraptor Server:**
```bash
velociraptor --config server.config.yaml frontend -v

# Access UI at: https://localhost:8000
# Default credentials in server.config.yaml
```

### Step 9: Deploy Agents (Production)

**Deploy to Endpoints:**
```bash
# Generate Windows MSI installer
velociraptor --config server.config.yaml config client > client.config.yaml
velociraptor --config server.config.yaml debian client

# Deploy via GPO, SCCM, or manual installation
# Agents will auto-enroll with server
```

## Configuration

### Environment Variables

Create `.env` file in project root:

```bash
# TheHive Configuration
THEHIVE_URL=http://localhost:9000
THEHIVE_API_KEY=your_api_key_here

# Cortex Configuration
CORTEX_URL=http://localhost:9001
CORTEX_API_KEY=your_cortex_key_here

# Velociraptor Configuration
VELOCIRAPTOR_URL=https://localhost:8000
VELOCIRAPTOR_API_KEY=your_velociraptor_key

# Evidence Storage
EVIDENCE_VAULT=/evidence_vault
EVIDENCE_RETENTION_DAYS=90

# SIEM Integration
SIEM_URL=https://siem.company.com
SIEM_API_KEY=your_siem_key

# Notifications
SMTP_SERVER=smtp.company.com
SMTP_FROM=airdfp-alerts@company.com
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
PAGERDUTY_API_KEY=your_pagerduty_key

# Database
POSTGRES_DSN=postgresql://airdfp:password@localhost:5432/airdfp_analytics
REDIS_URL=redis://localhost:6379

# MinIO/S3
MINIO_ENDPOINT=localhost:9002
MINIO_ACCESS_KEY=airdfp_admin
MINIO_SECRET_KEY=change_this_password_in_production
```

### Firewall Rules

```bash
# Allow inbound (external access)
sudo ufw allow 9000/tcp  # TheHive UI
sudo ufw allow 9001/tcp  # Cortex UI
sudo ufw allow 8000/tcp  # Velociraptor (HTTPS)

# Internal services (localhost only)
sudo ufw deny 9200/tcp   # Elasticsearch
sudo ufw deny 6379/tcp   # Redis
sudo ufw deny 5432/tcp   # PostgreSQL
sudo ufw deny 9002/tcp   # MinIO

sudo ufw enable
```

### SSL/TLS Configuration (Production)

**Generate Certificates:**
```bash
# Using Let's Encrypt
sudo certbot certonly --standalone -d airdfp.company.com

# Or self-signed for testing
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

**Configure Nginx Reverse Proxy:**
```bash
sudo apt install nginx

# Create config: /etc/nginx/sites-available/airdfp
```

```nginx
server {
    listen 443 ssl http2;
    server_name airdfp.company.com;

    ssl_certificate /etc/letsencrypt/live/airdfp.company.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/airdfp.company.com/privkey.pem;

    location / {
        proxy_pass http://localhost:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /cortex/ {
        proxy_pass http://localhost:9001/;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/airdfp /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## Testing

### Smoke Tests

```bash
# Test TheHive connectivity
curl http://localhost:9000/api/status

# Test Cortex
curl http://localhost:9001/api/status

# Test Elasticsearch
curl http://localhost:9200/_cluster/health

# Test SIEM integration
python phase_1_foundation/siem_integration.py --thehive-key YOUR_KEY --test-mode
```

### End-to-End Test

```bash
# Run full incident simulation
cd tests
./run_e2e_test.sh

# Expected output:
# ✅ SIEM alert ingestion
# ✅ Case creation
# ✅ Evidence collection
# ✅ Forensic analysis
# ✅ Report generation
# ✅ All tests passed
```

## Monitoring

### Health Checks

```bash
# Check all Docker services
docker-compose ps

# Check logs
docker-compose logs -f thehive
docker-compose logs -f cortex
docker-compose logs -f elasticsearch
```

### Metrics Dashboard (Optional)

**Deploy Prometheus + Grafana:**
```bash
# Add to docker-compose.yml
services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

**Access Grafana:**
- URL: http://localhost:3000
- Default: admin/admin
- Import dashboard: `grafana/airdfp-dashboard.json`

## Backup & Recovery

### Automated Backups

```bash
# Create backup script: /etc/cron.daily/airdfp-backup
#!/bin/bash

BACKUP_DIR=/backup/airdfp/$(date +%Y%m%d)
mkdir -p $BACKUP_DIR

# Backup Elasticsearch indices
docker exec airdfp-elasticsearch elasticdump \
  --input=http://localhost:9200/thehive \
  --output=$BACKUP_DIR/thehive_index.json

# Backup evidence vault
rsync -avz /evidence_vault/ $BACKUP_DIR/evidence_vault/

# Backup configuration
cp -r /home/user/AIRDFP/config $BACKUP_DIR/

# Compress and encrypt
tar czf $BACKUP_DIR.tar.gz $BACKUP_DIR
gpg --encrypt --recipient backup@company.com $BACKUP_DIR.tar.gz
```

### Recovery Procedure

```bash
# Restore from backup
BACKUP_FILE=/backup/airdfp/20241115.tar.gz.gpg

# Decrypt
gpg --decrypt $BACKUP_FILE > backup.tar.gz

# Extract
tar xzf backup.tar.gz

# Restore Elasticsearch
docker exec airdfp-elasticsearch elasticdump \
  --input=backup/thehive_index.json \
  --output=http://localhost:9200/thehive

# Restore evidence vault
rsync -avz backup/evidence_vault/ /evidence_vault/
```

## Troubleshooting

### Common Issues

**1. TheHive won't start**
```bash
# Check Elasticsearch health
curl http://localhost:9200/_cluster/health

# Reset Elasticsearch
docker-compose restart elasticsearch
docker-compose logs elasticsearch
```

**2. Evidence collection fails**
```bash
# Check Velociraptor server status
systemctl status velociraptor

# Verify agent connectivity
velociraptor --config server.config.yaml query "SELECT * FROM clients()"
```

**3. Memory analysis fails**
```bash
# Install Volatility 3
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python setup.py install

# Verify installation
volatility3 -h
```

## Security Hardening

### Production Checklist

- [ ] Change all default passwords
- [ ] Enable SSL/TLS on all services
- [ ] Implement firewall rules
- [ ] Enable audit logging
- [ ] Configure automated backups
- [ ] Implement MFA for admin accounts
- [ ] Restrict API access by IP whitelist
- [ ] Enable intrusion detection (Fail2ban)
- [ ] Regular security updates (apt-get update)
- [ ] Vulnerability scanning (Nessus, OpenVAS)

### Compliance

**APRA CPS 234:**
- Evidence retention: 90 days minimum
- Incident response SLA: <30 minutes
- Executive reporting: Within 24 hours
- Quarterly testing: Tabletop exercises

**Essential Eight:**
- Application whitelisting: Configured
- Patch management: Automated
- MFA: Enabled for admin accounts
- Restrict admin privileges: RBAC implemented
- User application hardening: Enforced
- Backups: Daily automated
- Network segmentation: Firewall rules
- Logging: Centralized (Elasticsearch)

## Support

### Documentation
- Architecture: `ARCHITECTURE.md`
- API Docs: `docs/API_DOCUMENTATION.md`
- Case Studies: `examples/`

### Community
- GitHub Issues: https://github.com/Raoof128/AIRDFP/issues
- Security Advisories: security@airdfp.local

### Professional Services
For enterprise deployment assistance:
- Email: support@airdfp.local
- SLA: 24/7 incident response support available

---

**Last Updated**: 2024-11-16
**Version**: 1.0
**Maintainer**: AIRDFP Engineering Team
