# Security Policy

## Supported Versions

The following versions of AIRDFP are currently being supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

The AIRDFP team takes security bugs seriously. We appreciate your efforts to responsibly disclose your findings and will make every effort to acknowledge your contributions.

### How to Report a Security Vulnerability

To report a security vulnerability, please use one of the following methods:

#### 1. Email (Preferred)

Send an email to: **security@airdfp.local**

Include the following information:
- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

#### 2. GitHub Security Advisory

Use GitHub's private vulnerability reporting feature:
1. Go to the [Security tab](https://github.com/Raoof128/AIRDFP/security)
2. Click "Report a vulnerability"
3. Fill out the advisory form

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your vulnerability report within **48 hours**
- **Initial Assessment**: We will send you an initial assessment within **5 business days**
- **Updates**: We will keep you informed of our progress
- **Credit**: If you wish, we will acknowledge your contribution in the security advisory

### Security Update Process

1. **Confirmation**: We confirm the vulnerability and determine its severity
2. **Fix Development**: We develop a fix in a private repository
3. **Testing**: The fix is thoroughly tested
4. **Advisory Draft**: We prepare a security advisory
5. **Release**: We release a patched version
6. **Disclosure**: We publish the security advisory (typically 7 days after release)

## Security Best Practices

### Deployment

When deploying AIRDFP in production:

#### 1. Change Default Credentials

```bash
# TheHive
# Navigate to UI → Settings → Change admin password immediately

# Update all API keys
# Generate new API keys and update configuration:
# - TheHive API key
# - Cortex API key
# - Velociraptor API key
```

#### 2. Enable SSL/TLS

```nginx
# Use Nginx reverse proxy with SSL
server {
    listen 443 ssl http2;
    server_name airdfp.company.com;

    ssl_certificate /etc/letsencrypt/live/airdfp.company.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/airdfp.company.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
}
```

#### 3. Firewall Configuration

```bash
# Allow only necessary ports
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (if needed)
sudo ufw allow 22/tcp

# Allow HTTPS only (reverse proxy)
sudo ufw allow 443/tcp

# Block direct access to internal services
sudo ufw deny 9000/tcp  # TheHive
sudo ufw deny 9001/tcp  # Cortex
sudo ufw deny 9200/tcp  # Elasticsearch

sudo ufw enable
```

#### 4. Network Segmentation

```yaml
# Deploy services in isolated networks
networks:
  frontend:
    # Web-facing services
  backend:
    # Internal services only
  forensics:
    # Evidence collection network (isolated)
```

#### 5. Access Control

```python
# Implement IP whitelisting in configuration
allowed_ips = [
    "10.0.0.0/8",      # Internal network
    "172.16.0.0/12",   # VPN network
    "192.168.1.0/24"   # SOC subnet
]

# Implement rate limiting
rate_limit = {
    "requests_per_minute": 100,
    "burst": 200
}
```

#### 6. Secrets Management

**DO NOT** store secrets in:
- Git repository
- Configuration files committed to version control
- Environment variables in Docker Compose files

**DO** use:
- Environment variables loaded from `.env` file (gitignored)
- Docker secrets
- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault

Example:
```bash
# Create .env file (never commit this)
cat > .env <<EOF
THEHIVE_API_KEY=your_secure_key_here
CORTEX_API_KEY=your_secure_key_here
DATABASE_PASSWORD=your_secure_password_here
EOF

# Restrict permissions
chmod 600 .env
```

#### 7. Evidence Encryption

```python
# Always encrypt evidence at rest
evidence_config = {
    "encryption": True,
    "algorithm": "AES-256-GCM",
    "key_rotation": "30_days"
}
```

#### 8. Audit Logging

```python
# Enable comprehensive audit logging
logging_config = {
    "enable_audit_log": True,
    "log_all_api_calls": True,
    "log_evidence_access": True,
    "log_configuration_changes": True,
    "retention_days": 90
}
```

### Code Security

#### 1. Input Validation

Always validate and sanitize user input:

```python
def process_alert(alert: Dict) -> None:
    # Validate required fields
    required_fields = ['rule_name', 'alert_type', 'hostname']
    for field in required_fields:
        if field not in alert:
            raise ValueError(f"Missing required field: {field}")

    # Sanitize input
    hostname = sanitize_hostname(alert['hostname'])
    if not is_valid_hostname(hostname):
        raise ValueError(f"Invalid hostname: {hostname}")
```

#### 2. Prevent Command Injection

Never use `shell=True` with subprocess:

```python
# BAD - Vulnerable to command injection
subprocess.run(f"ping {user_input}", shell=True)

# GOOD - Safe from command injection
subprocess.run(["ping", "-c", "1", user_input])
```

#### 3. SQL Injection Prevention

Use parameterized queries:

```python
# BAD - Vulnerable to SQL injection
cursor.execute(f"SELECT * FROM cases WHERE id = {case_id}")

# GOOD - Protected from SQL injection
cursor.execute("SELECT * FROM cases WHERE id = %s", (case_id,))
```

#### 4. Path Traversal Prevention

```python
import os
from pathlib import Path

def safe_path_join(base_dir: str, user_path: str) -> Path:
    """Safely join paths preventing directory traversal"""
    base = Path(base_dir).resolve()
    target = (base / user_path).resolve()

    # Ensure target is within base directory
    if not target.is_relative_to(base):
        raise ValueError("Path traversal attempt detected")

    return target
```

### Docker Security

#### 1. Run as Non-Root

```dockerfile
# Create non-root user
RUN useradd -m -u 1000 airdfp

# Switch to non-root user
USER airdfp
```

#### 2. Minimal Base Images

```dockerfile
# Use minimal base images
FROM python:3.11-slim-bookworm

# Or use distroless for production
FROM gcr.io/distroless/python3-debian12
```

#### 3. Security Scanning

```bash
# Scan Docker images for vulnerabilities
docker scan airdfp:latest

# Or use Trivy
trivy image airdfp:latest
```

## Known Security Considerations

### 1. Evidence Integrity

- All evidence is cryptographically sealed with SHA256 + Fernet encryption
- Chain of custody maintained with immutable audit logs
- Tamper detection on all unsealing operations

### 2. API Authentication

- All API endpoints require Bearer token authentication
- API keys should be rotated every 90 days
- Failed authentication attempts are logged and rate-limited

### 3. Data Privacy

- PII data in evidence should be handled per GDPR/privacy regulations
- Implement data retention policies (default: 90 days)
- Evidence can be marked for secure deletion after retention period

### 4. Network Security

- Evidence collection uses encrypted channels (HTTPS/TLS)
- Velociraptor uses certificate-based authentication
- All internal services communicate over encrypted connections

## Security Scanning Tools

We recommend running these security tools regularly:

```bash
# Static Application Security Testing (SAST)
bandit -r . -f json -o security-report.json

# Dependency vulnerability scanning
safety check

# Container security
docker scan airdfp:latest

# Infrastructure as Code scanning
checkov -d phase_1_foundation/
```

## Compliance

AIRDFP is designed to support:

- **APRA CPS 234** - Information security requirements
- **Essential Eight** - Australian Cyber Security Centre guidelines
- **ISO 27037** - Digital evidence handling
- **GDPR** - Data privacy (with proper configuration)
- **NIST 800-61** - Incident handling guidelines

## Security Hardening Checklist

Use this checklist for production deployments:

- [ ] All default passwords changed
- [ ] SSL/TLS enabled on all services
- [ ] Firewall rules configured
- [ ] IP whitelisting implemented
- [ ] API rate limiting enabled
- [ ] Audit logging enabled
- [ ] Evidence encryption enabled
- [ ] Secrets stored securely (not in git)
- [ ] Docker containers run as non-root
- [ ] Security scanning completed
- [ ] Vulnerability assessment performed
- [ ] Incident response plan documented
- [ ] Backup and disaster recovery tested
- [ ] Access control policies implemented
- [ ] MFA enabled for admin accounts

## Contact

For security concerns, contact:

- **Email**: security@airdfp.local
- **GitHub Security Advisory**: [Report a vulnerability](https://github.com/Raoof128/AIRDFP/security/advisories/new)

**Emergency Security Issues**: If you believe there is an immediate security threat, please contact us immediately via email with "URGENT SECURITY" in the subject line.

---

**Last Updated**: 2024-11-16
**Version**: 1.0
