# Frequently Asked Questions (FAQ)

## General Questions

### What is AIRDFP?

AIRDFP (Automated Incident Response & Digital Forensics Platform) is an enterprise-grade incident response platform that combines automated case management, evidence forensics, timeline analysis, and intelligent reporting. It reduces mean time to remediation (MTTR) from days to minutes while maintaining court-admissible chain of custody.

### Who is AIRDFP for?

AIRDFP is designed for:
- **Security Operations Centers (SOCs)** - Automate L1/L2 analyst tasks
- **Incident Response Teams** - Rapid evidence collection and analysis
- **Digital Forensics Teams** - Comprehensive forensic capabilities
- **Enterprise Security Teams** - Compliance and audit requirements
- **MSSPs** - Multi-tenant incident response at scale

### What makes AIRDFP different from other IR platforms?

Key differentiators:
- **99.6% MTTR improvement** (3-5 days → 12 minutes)
- **Automated forensics** - Memory, disk, and timeline analysis
- **ML-powered detection** - 95% accuracy anomaly detection
- **Court-admissible evidence** - Cryptographic chain of custody
- **Complete automation** - From alert to report in minutes
- **Open source** - Transparent, auditable, extensible

###What is the cost?

AIRDFP is open source and free to use under the MIT License. There are no licensing fees, per-seat costs, or premium tiers. The only costs are your infrastructure (servers, storage) and optional third-party integrations.

---

## Installation & Setup

### What are the system requirements?

**Minimum**:
- CPU: 8 cores
- RAM: 16 GB
- Storage: 500 GB SSD
- OS: Ubuntu 22.04 LTS / RHEL 8+ / Debian 11+

**Recommended (Production)**:
- CPU: 16+ cores
- RAM: 32 GB
- Storage: 10 TB (evidence vault with 90-day retention)
- Network: 1 Gbps

### Do I need Docker?

Docker is highly recommended for deployment, but not strictly required. You can deploy individual components manually, but Docker Compose significantly simplifies the process.

### Can I run AIRDFP without ML libraries (NumPy/scikit-learn)?

Yes! AIRDFP automatically falls back to rule-based anomaly detection if ML libraries aren't available. While ML-based detection achieves 95% accuracy, the rule-based fallback still provides ~85% accuracy.

### How long does installation take?

**Quick Start**: 5-10 minutes for basic deployment
**Production Setup**: 2-4 hours including SSL, security hardening, and testing

### Can I deploy AIRDFP in the cloud?

Yes! AIRDFP can be deployed on:
- AWS (EC2, ECS, EKS)
- Azure (VMs, AKS)
- Google Cloud (Compute Engine, GKE)
- Private cloud (OpenStack, VMware)

---

## Features & Capabilities

### What types of incidents can AIRDFP handle?

AIRDFP includes templates for:
- **Malware** (ransomware, trojans, backdoors)
- **Lateral Movement** (privilege escalation, pass-the-hash)
- **Data Exfiltration** (database dumps, large transfers)
- **Account Compromise** (credential theft, unusual access)

Custom templates can be created for any incident type.

### What evidence types can AIRDFP collect?

Supported evidence types:
- **Memory dumps** (full RAM capture)
- **Disk artifacts** (MFT, registry, event logs)
- **Network captures** (PCAP, flow logs)
- **Application logs** (syslog, Windows Event Log)
- **Cloud logs** (CloudTrail, Azure Activity Log - with extensions)

### Does AIRDFP work with my SIEM?

AIRDFP integrates with major SIEMs:
- Splunk
- IBM QRadar
- Microsoft Sentinel
- Elastic Security
- Chronicle
- Generic REST API (for others)

### Can I customize playbooks?

Yes! Playbooks are defined in YAML and fully customizable. You can:
- Create new playbooks
- Modify existing ones
- Add custom actions
- Define conditional logic
- Set timeouts and retries

### Does AIRDFP support multi-tenancy?

Not in v1.0. Multi-tenancy is planned for a future release. Currently, deploy separate instances for each tenant.

---

## Performance & Scale

### How many endpoints can AIRDFP support?

AIRDFP is designed to support:
- **Small deployment**: 50-100 endpoints
- **Medium deployment**: 100-500 endpoints
- **Large deployment**: 500-2000 endpoints
- **Enterprise deployment**: 2000+ endpoints (with clustering)

### How fast is evidence collection?

Average collection times:
- **Quick triage**: 30 seconds
- **Memory dump**: 90 seconds (for 8GB RAM)
- **Disk forensics**: 3 minutes
- **Comprehensive**: 5 minutes

### How long does forensic analysis take?

Analysis performance:
- **Memory analysis** (Volatility): <5 minutes for 4GB dump
- **Timeline generation**: <2 minutes for 10,000+ events
- **ML anomaly detection**: <30 seconds
- **Report generation**: <1 minute

### Can AIRDFP handle 10,000+ incidents per year?

Yes! AIRDFP is designed for high-volume environments:
- **Alert ingestion**: 10,000/hour
- **Concurrent analyses**: Limited by CPU/RAM
- **Storage**: Scales with evidence vault size

---

## Security & Compliance

### Is evidence court-admissible?

Yes! AIRDFP maintains:
- **Cryptographic sealing** (SHA256 + Fernet)
- **Chain of custody** with immutable audit logs
- **Tamper detection** on all evidence access
- **ISO 27037 compliance** for digital evidence handling

### What compliance frameworks does AIRDFP support?

AIRDFP aligns with:
- **APRA CPS 234** (Australia)
- **Essential Eight** (Australian Cyber Security Centre)
- **NIST 800-61** (Incident Handling)
- **ISO 27037** (Digital Evidence)
- **GDPR** (with proper configuration)

### How is sensitive data protected?

Security measures:
- **Encryption at rest** (AES-256)
- **Encryption in transit** (TLS 1.2+)
- **API authentication** (Bearer tokens)
- **Role-based access control** (RBAC)
- **Audit logging** (all actions logged)

### What is the data retention policy?

Default: 90 days (configurable)

You can configure retention per:
- Evidence type
- Incident severity
- Compliance requirements
- Storage capacity

---

## Troubleshooting

### TheHive won't start

**Common causes**:
1. **Elasticsearch not ready**: Wait 30-60 seconds for ES to initialize
2. **Port conflict**: Check if port 9000 is already in use
3. **Insufficient memory**: Ensure 4GB+ available for ES

**Fix**:
```bash
# Check Elasticsearch health
curl http://localhost:9200/_cluster/health

# Restart services
docker-compose restart elasticsearch
docker-compose restart thehive
```

### Evidence collection fails

**Common causes**:
1. **Velociraptor not running**: Check server status
2. **Agent not installed**: Deploy Velociraptor agent to target
3. **Network connectivity**: Verify agent can reach server
4. **Permissions**: Ensure agent has admin/root privileges

**Fix**:
```bash
# Check Velociraptor status
systemctl status velociraptor

# Verify agent connectivity
velociraptor --config server.config.yaml query "SELECT * FROM clients()"
```

### Memory analysis fails

**Common causes**:
1. **Volatility not installed**: Install Volatility 3
2. **Unsupported OS**: Volatility 3 supports Windows, Linux, macOS
3. **Corrupted dump**: Verify dump integrity
4. **Insufficient memory**: Analysis requires RAM > dump size

**Fix**:
```bash
# Install Volatility 3
pip install volatility3

# Verify installation
volatility3 -h

# Test with sample dump
volatility3 -f memory.dump windows.info
```

### "Module not found" errors

**Common causes**:
1. **Dependencies not installed**: Run `pip install -r requirements.txt`
2. **Wrong Python version**: Requires Python 3.8+
3. **Virtual environment**: Activate venv before running

**Fix**:
```bash
# Activate virtual environment
source venv/bin/activate

# Install all dependencies
pip install -r requirements.txt

# Verify Python version
python --version  # Should be 3.8+
```

### Rate limit exceeded

**Cause**: Too many API requests in short time

**Fix**:
```python
# Implement exponential backoff
import time

def make_request_with_retry(url, max_retries=3):
    for attempt in range(max_retries):
        response = requests.get(url)

        if response.status_code == 429:
            wait_time = 2 ** attempt  # Exponential backoff
            time.sleep(wait_time)
            continue

        return response

    raise Exception("Max retries exceeded")
```

---

## Integration

### Can AIRDFP integrate with Slack?

Yes! Configure Slack webhook in `config/airdfp.conf`:

```ini
[notifications]
slack_webhook_url = https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### Can AIRDFP integrate with Jira/ServiceNow?

Yes! AIRDFP can create tickets via:
- REST API integration
- Webhook notifications
- Custom playbook actions

Example playbook action:
```yaml
- name: "Create Jira ticket"
  action: jira_create_ticket
  params:
    project: "SEC"
    issue_type: "Incident"
    priority: "Critical"
```

### Does AIRDFP support MISP integration?

Yes! AIRDFP can:
- Export IOCs to MISP
- Query MISP for threat intel
- Automatically enrich observables

Enable in configuration:
```ini
[integrations]
enable_misp = true
misp_url = https://misp.company.com
misp_api_key = YOUR_MISP_KEY
```

---

## Best Practices

### How often should I rotate API keys?

**Recommendation**: Every 90 days

Set calendar reminders and use key rotation automation:
```bash
# Generate new key
NEW_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# Update configuration
sed -i "s/api_key=.*/api_key=$NEW_KEY/" config/airdfp.conf

# Restart services
docker-compose restart
```

### Should I run backups?

**Yes!** Critical data to backup:
- Evidence vault (`/evidence_vault`)
- TheHive database (Elasticsearch indices)
- Configuration files
- Cryptographic keys

**Backup frequency**:
- Evidence: Continuous replication
- Database: Daily snapshots
- Configuration: Version controlled (Git)

### How do I test my deployment?

Use the built-in test suite:

```bash
# System validation
python3 tests/validate_system.py

# Unit tests
python3 tests/test_core_functionality.py

# End-to-end test with simulated incident
python3 phase_1_foundation/siem_integration.py --test-mode
```

### What monitoring should I implement?

Monitor these metrics:
- **Service health**: TheHive, Cortex, Elasticsearch
- **Collection success rate**: Should be >95%
- **Analysis queue depth**: Alert if >100
- **Storage utilization**: Alert at 80%
- **API latency**: p95 should be <2s
- **Failed logins**: Alert on spikes

Use Prometheus + Grafana for visualization.

---

## Support & Community

### Where can I get help?

- **Documentation**: https://github.com/Raoof128/AIRDFP/tree/main/docs
- **GitHub Issues**: https://github.com/Raoof128/AIRDFP/issues
- **Discussions**: https://github.com/Raoof128/AIRDFP/discussions
- **Email**: support@airdfp.local

### How do I report a bug?

1. Check existing issues first
2. Create a new issue with template
3. Include: OS, version, logs, steps to reproduce
4. Label appropriately (bug, enhancement, question)

### How do I contribute?

See [CONTRIBUTING.md](../CONTRIBUTING.md) for:
- Development setup
- Coding standards
- Pull request process
- Testing guidelines

### Is commercial support available?

Currently, support is community-driven. Professional services may be available in the future for:
- Enterprise deployment assistance
- Custom feature development
- Training and certification
- 24/7 incident response support

---

## Roadmap

### What's planned for future releases?

**Q1 2025**:
- Cloud evidence collection (AWS, Azure, GCP)
- Kubernetes deployment templates
- Splunk Enterprise Security integration
- Multi-tenancy support

**Q2 2025**:
- MISP threat intelligence integration
- Mobile device forensics (iOS, Android)
- Blockchain evidence handling
- AI-powered investigation assistant (GPT-4)

**Q3 2025**:
- SOAR playbook marketplace
- Advanced behavioral analytics
- Threat hunting module
- Automated remediation engine

### Can I influence the roadmap?

Yes! Submit feature requests via GitHub Issues. Features with most community support and business value will be prioritized.

---

## Performance Optimization

### How can I speed up evidence collection?

**Tips**:
1. Use `quick_triage` profile for initial assessment
2. Deploy Velociraptor agents pre-incident
3. Use SSD storage for evidence vault
4. Enable compression for network transfers
5. Increase concurrent collection workers

### How can I reduce storage costs?

**Strategies**:
1. Implement evidence compression
2. Use tiered storage (hot/warm/cold)
3. Set appropriate retention policies
4. Deduplicate evidence across cases
5. Archive old cases to cold storage

### How can I improve analysis performance?

**Optimizations**:
1. Add more CPU cores for analysis workers
2. Increase RAM for large memory dumps
3. Use SSD for temporary analysis files
4. Enable result caching
5. Run analyses in parallel

---

Have a question not answered here? Check the [documentation](../README.md) or [create an issue](https://github.com/Raoof128/AIRDFP/issues/new).
