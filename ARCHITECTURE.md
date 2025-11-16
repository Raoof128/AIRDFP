# AIRDFP Architecture Documentation

## System Architecture Overview

The Automated Incident Response & Digital Forensics Platform follows a **modular, microservices-based architecture** designed for scalability, resilience, and forensic integrity.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         EXTERNAL INTEGRATIONS                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│  │   SIEM   │  │   EDR    │  │  SOAR    │  │  Threat  │               │
│  │(Splunk)  │  │(CrowdStr)│  │(Phantom) │  │  Intel   │               │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘               │
└───────┼─────────────┼─────────────┼─────────────┼────────────────────┘
        │             │             │             │
        └─────────────┴─────────────┴─────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        API GATEWAY / LOAD BALANCER                      │
│                    (Rate Limiting, Authentication)                       │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
┌───────────────┐      ┌───────────────┐      ┌───────────────┐
│  INGESTION    │      │  ORCHESTRATION│      │  ANALYSIS     │
│  LAYER        │      │  LAYER        │      │  LAYER        │
├───────────────┤      ├───────────────┤      ├───────────────┤
│• Alert Parser │      │• TheHive API  │      │• Volatility 3 │
│• ML Classifier│      │• Cortex Engine│      │• DFIR-IRIS    │
│• Normalizer   │──────▶• Case Manager │──────▶• Plaso L2T    │
│• Enrichment   │      │• Playbook Exec│      │• ML Engine    │
└───────────────┘      └───────┬───────┘      └───────────────┘
                               │
                               ▼
                     ┌───────────────────┐
                     │ COLLECTION LAYER  │
                     ├───────────────────┤
                     │• Velociraptor     │
                     │• Remote Collectors│
                     │• Network Sensors  │
                     └─────────┬─────────┘
                               │
                               ▼
                     ┌───────────────────┐
                     │ STORAGE LAYER     │
                     ├───────────────────┤
                     │• Evidence Vault   │
                     │• Elasticsearch    │
                     │• S3/MinIO         │
                     │• PostgreSQL       │
                     └───────────────────┘
```

## Component Details

### 1. Ingestion Layer

**Purpose**: Normalize and classify incoming security alerts from diverse sources

**Components**:
- **Alert Parser**: Converts SIEM/EDR alerts to standardized format
- **ML Classifier**: Severity classification using Isolation Forest
- **Enrichment Engine**: Adds threat intelligence context
- **Normalization Service**: Converts to Common Event Format (CEF)

**Technologies**:
- Python 3.8+ (asyncio for concurrent processing)
- Redis (alert queue)
- scikit-learn (ML models)

**Data Flow**:
```
SIEM Alert → Redis Queue → Parser → ML Classifier → TheHive Case Creation
```

**Performance Targets**:
- Alert ingestion rate: 10,000/hour
- Classification latency: <2 seconds
- Queue depth warning: >1,000 alerts

### 2. Orchestration Layer

**Purpose**: Central case management and automated response coordination

**Components**:

#### TheHive (Case Management)
- **Version**: 5.0+
- **Database**: Elasticsearch 8.5
- **Role**: Central case repository, task management, collaboration
- **Customizations**:
  - 4 case templates (Malware, Lateral Movement, Exfiltration, Account Compromise)
  - Custom fields for forensics metadata
  - API webhooks for automation

#### Cortex (Analysis Engine)
- **Version**: 3.1+
- **Role**: Observable analysis (IPs, domains, file hashes)
- **Analyzers**:
  - VirusTotal
  - AlienVault OTX
  - MISP
  - Custom ML analyzers

#### Playbook Executor
- **Language**: Python
- **Engine**: YAML-defined workflows
- **Capabilities**:
  - Conditional branching
  - Parallel execution
  - Timeout handling
  - Audit logging

**Data Flow**:
```
Case Created → Playbook Triggered → Parallel Actions:
  ├─ Network Isolation
  ├─ Evidence Collection (Velociraptor)
  ├─ Credential Reset (AD)
  └─ Notification (Email/Slack)
```

### 3. Collection Layer

**Purpose**: Rapid, forensically-sound evidence acquisition from endpoints

**Primary Tool**: Velociraptor

**Collection Profiles**:

| Profile | Artifacts | Time | Size |
|---------|-----------|------|------|
| **Quick Triage** | Processes, Network, Services | <30s | ~50MB |
| **Memory Dump** | Full RAM capture | <90s | ~8GB |
| **Disk Forensics** | MFT, Registry, Event Logs | <3m | ~2GB |
| **Comprehensive** | All above + file carving | <5m | ~10GB |

**Evidence Chain of Custody**:
```python
1. Collection Request → Velociraptor Server
2. Agent Execution → Target Endpoint
3. Artifact Packaging → ZIP with metadata
4. Hash Calculation → SHA256
5. Cryptographic Seal → Fernet encryption
6. Storage → Evidence Vault (append-only)
7. Integrity Verification → On-access verification
```

**Technologies**:
- Velociraptor 0.6.8+
- Python client library
- MinIO/S3 for storage

### 4. Analysis Layer

**Purpose**: Automated forensic analysis with IOC extraction

#### Volatility 3 (Memory Forensics)
**Plugins Used**:
- `windows.pslist` - Process enumeration
- `windows.netscan` - Network connections
- `windows.malfind` - Code injection detection
- `windows.services` - Service analysis
- `windows.registry.*` - Registry forensics

**Output Format**: JSON for downstream processing

**Automation Flow**:
```
Memory Dump → Volatility CLI → JSON Output → IOC Extractor → TheHive Observables
```

#### DFIR-IRIS (Disk Forensics)
**Capabilities**:
- Timeline visualization
- Artifact correlation
- Multi-evidence case management

**Integration**:
```python
Evidence Upload → IRIS API → Timeline Generation → Event Correlation → Report Export
```

#### Plaso (Timeline Analysis)
**Purpose**: Create super timeline from all evidence sources

**Process**:
```
log2timeline (extraction) → psort (filtering) → psteal (analysis) → JSON export
```

**Event Sources**:
- Windows Event Logs (Security, System, Application)
- Registry hives (NTUSER.DAT, SYSTEM, SOFTWARE)
- Filesystem metadata (MFT, USN Journal)
- Browser history
- Memory analysis output

### 5. Intelligence Layer

**Purpose**: ML-based anomaly detection and attack reconstruction

#### ML Anomaly Detection Engine

**Algorithm**: Isolation Forest (scikit-learn)

**Feature Engineering**:
```python
features = [
    event_frequency,      # How often this event type occurs
    user_risk_score,      # Historical user behavior
    time_delta,           # Time since last similar event
    data_volume,          # Size of affected data
    geographic_anomaly,   # Location deviation
    process_lineage       # Parent-child process chain
]
```

**Training**:
- Baseline: 30 days normal activity
- Retrain: Weekly
- Contamination parameter: 0.1 (10% anomalies expected)

**Output**:
- Anomaly score: -1.0 (high) to 0 (normal)
- Severity mapping: Critical/High/Medium/Low
- Confidence interval

#### Attack Narrative Reconstruction

**Inputs**:
- Timeline events (chronological)
- Anomaly scores (ML output)
- Artifact correlations (user/host/file linkages)

**Process**:
1. Cluster related events by user/host
2. Identify temporal sequences (within 5-minute window)
3. Map to MITRE ATT&CK techniques
4. Generate chronological narrative

**Output Format**:
```json
{
  "attack_phases": [
    {
      "phase": "Initial Access",
      "technique": "T1566.001 - Phishing: Spearphishing Attachment",
      "timestamp": "2024-11-15T09:23:15Z",
      "evidence": ["email_forensics.json", "attachment_analysis.json"]
    },
    {
      "phase": "Execution",
      "technique": "T1059.001 - PowerShell",
      "timestamp": "2024-11-15T09:24:32Z",
      "evidence": ["process_tree.json", "memory_dump.json"]
    }
  ]
}
```

### 6. Reporting Layer

**Purpose**: Automated generation of executive and technical reports

#### Report Generator

**Technologies**:
- ReportLab (PDF generation)
- Jinja2 (HTML templates)
- Matplotlib (visualization)

**Report Types**:

1. **Executive Summary** (2-3 pages)
   - Business impact
   - Timeline overview
   - Remediation status
   - Cost estimation

2. **Technical Report** (15-30 pages)
   - Full timeline
   - IOC catalog
   - Evidence manifest
   - Forensic findings

3. **Chain of Custody** (Legal)
   - Evidence handling log
   - Hash verification
   - Access audit trail

**Generation Process**:
```
Template Selection → Data Aggregation → Visualization Creation → PDF Rendering → Digital Signature
```

**Performance**: <60 seconds for 30-page report

## Data Flow Architecture

### End-to-End Incident Flow

```
1. ALERT DETECTION (SIEM)
   └─> Alert sent to AIRDFP API

2. INGESTION (5 seconds)
   ├─> Parse alert format
   ├─> ML severity classification
   └─> Threat intel enrichment

3. CASE CREATION (2 seconds)
   ├─> Create TheHive case
   ├─> Assign severity
   ├─> Select case template
   └─> Trigger playbook

4. AUTOMATED RESPONSE (30-90 seconds)
   ├─> Network isolation
   ├─> Evidence collection (Velociraptor)
   ├─> Credential reset
   └─> Notification

5. FORENSIC ANALYSIS (3-15 minutes)
   ├─> Memory analysis (Volatility)
   ├─> Disk forensics (DFIR-IRIS)
   ├─> Timeline generation (Plaso)
   └─> IOC extraction

6. CORRELATION (1-2 minutes)
   ├─> ML anomaly detection
   ├─> Artifact correlation
   └─> Attack narrative reconstruction

7. REPORTING (1 minute)
   ├─> Generate executive summary
   ├─> Create technical report
   ├─> Chain of custody documentation
   └─> Evidence sealing

Total Time: 5-20 minutes (vs. 4+ hours manual)
```

## Security Architecture

### Authentication & Authorization

**Multi-Layer Security**:
1. **API Gateway**: JWT token authentication
2. **TheHive**: RBAC (Role-Based Access Control)
3. **Velociraptor**: Certificate-based client auth
4. **Evidence Vault**: Encryption at rest + in transit

**User Roles**:
- **Analyst**: View cases, run analyses
- **Responder**: Execute playbooks, collect evidence
- **Lead**: Approve actions, review reports
- **Admin**: System configuration, user management

### Evidence Integrity

**Cryptographic Chain**:
```
Evidence Collection → SHA256 Hash → Fernet Encryption → Tamper-Evident Seal
```

**Verification Process**:
```python
1. Read encrypted seal file
2. Decrypt with symmetric key
3. Extract original hash
4. Recompute current hash
5. Compare: Match = ✅ / Mismatch = ❌ ALERT
```

**Audit Trail**:
- All evidence access logged
- Immutable append-only log
- Cryptographic timestamping

## Scalability Design

### Horizontal Scaling

**Stateless Components** (scale horizontally):
- API Gateway (multiple instances behind load balancer)
- Playbook Executors (worker pool)
- Analysis Workers (distributed task queue)

**Stateful Components** (vertical scaling + replication):
- TheHive (Elasticsearch cluster)
- Evidence Vault (distributed object storage)
- PostgreSQL (primary + read replicas)

### Performance Optimization

**Caching Strategy**:
- Redis cache for:
  - Threat intel lookups
  - User session data
  - ML model predictions (short TTL)

**Async Processing**:
- Celery task queue for:
  - Evidence analysis (long-running)
  - Report generation
  - Timeline creation

**Database Optimization**:
- Elasticsearch indices partitioned by month
- Hot/warm/cold storage tiering
- Automated index lifecycle management

### Capacity Planning

**Target Environment**: 500 endpoints, 10,000 alerts/month

| Component | CPU | RAM | Storage | Instances |
|-----------|-----|-----|---------|-----------|
| API Gateway | 4 cores | 8GB | 50GB | 2 |
| TheHive | 8 cores | 16GB | 200GB | 1 |
| Cortex | 4 cores | 8GB | 100GB | 1 |
| Elasticsearch | 16 cores | 32GB | 2TB | 3 |
| Evidence Vault | 8 cores | 16GB | 10TB | 1 |
| Analysis Workers | 8 cores | 32GB | 500GB | 3 |
| **Total** | **52 cores** | **120GB** | **13TB** | **11** |

## Disaster Recovery

### Backup Strategy

**Evidence Vault**:
- Continuous replication to cold storage
- 90-day retention policy
- Geo-redundant backups

**Elasticsearch**:
- Daily snapshots
- 30-day retention
- Point-in-time recovery

**Configuration**:
- Git-tracked (infrastructure as code)
- Automated deployment via Ansible

### High Availability

**RTO/RPO Targets**:
- Recovery Time Objective (RTO): 1 hour
- Recovery Point Objective (RPO): 15 minutes

**Implementation**:
- Active-passive failover for TheHive
- Load-balanced API gateways
- Distributed storage with replication factor 3

## Monitoring & Observability

### Metrics Collection

**Prometheus Metrics**:
- Alert ingestion rate
- Case creation latency
- Evidence collection time
- Analysis processing time
- API response times

**Grafana Dashboards**:
1. **Operations Dashboard**
   - Cases by severity
   - Collection success rate
   - Playbook execution times

2. **Performance Dashboard**
   - API latency (p50, p95, p99)
   - Queue depth
   - Storage utilization

3. **Security Dashboard**
   - Failed authentication attempts
   - Evidence access patterns
   - Integrity verification failures

### Alerting

**PagerDuty Integration**:
- Critical: Evidence integrity failure
- High: Collection failure rate >10%
- Medium: Queue depth >1000
- Low: Storage utilization >80%

## Compliance Considerations

### APRA CPS 234 Alignment

**Requirement 35-38 (Incident Management)**:
- ✅ Automated incident detection and response
- ✅ Evidence preservation within 15 minutes
- ✅ Executive reporting within 24 hours
- ✅ Quarterly incident response testing

**Audit Trail**:
- All user actions logged
- Evidence handling tracked
- Report generation timestamped
- Chain of custody maintained

### Data Privacy

**GDPR Compliance**:
- PII data minimization in evidence collection
- Right to erasure (configurable retention)
- Data processing agreements with tool vendors
- Encryption of data at rest and in transit

**Australian Privacy Principles**:
- Collection limitation (Principle 3)
- Data security (Principle 11)
- Data breach notification (Notifiable Data Breaches scheme)

## Technology Stack

| Layer | Technology | Version | Purpose |
|-------|------------|---------|---------|
| **Orchestration** | TheHive | 5.0+ | Case management |
| **Analysis** | Cortex | 3.1+ | Observable analysis |
| **Search** | Elasticsearch | 8.5 | Data store |
| **Collection** | Velociraptor | 0.6.8+ | Endpoint forensics |
| **Memory** | Volatility | 3.0+ | Memory analysis |
| **Timeline** | Plaso | 20240308+ | Timeline generation |
| **ML** | scikit-learn | 1.3+ | Anomaly detection |
| **Reporting** | ReportLab | 4.0+ | PDF generation |
| **Storage** | MinIO | Latest | Object storage |
| **Queue** | Redis | 7.0+ | Task queue |
| **Database** | PostgreSQL | 15+ | Structured data |
| **Container** | Docker | 24.0+ | Deployment |
| **Orchestration** | Docker Compose | 2.20+ | Multi-container |

## Integration Points

### Inbound Integrations (Alerts)
- Splunk (HEC - HTTP Event Collector)
- IBM QRadar (REST API)
- Microsoft Sentinel (Azure Monitor)
- CrowdStrike Falcon (Event Stream API)
- Carbon Black (CB Response API)

### Outbound Integrations (Actions)
- Active Directory (LDAP/PowerShell)
- Firewall APIs (Palo Alto, Cisco)
- Email (SMTP for notifications)
- Slack/Teams (Webhooks)
- MISP (Threat intel sharing)

### Bi-directional Integrations
- SOAR platforms (Splunk Phantom, IBM Resilient)
- Ticketing systems (Jira, ServiceNow)
- Threat intel platforms (MISP, ThreatConnect)

## Development Roadmap

### Phase 1 (Completed)
- ✅ Core infrastructure deployment
- ✅ Case management integration
- ✅ SIEM alert ingestion

### Phase 2 (Completed)
- ✅ Velociraptor deployment
- ✅ Automated playbooks
- ✅ Evidence vault

### Phase 3 (Completed)
- ✅ Volatility 3 integration
- ✅ DFIR-IRIS setup
- ✅ IOC extraction

### Phase 4 (Completed)
- ✅ Plaso timeline generation
- ✅ ML anomaly detection
- ✅ Attack narrative reconstruction

### Phase 5 (Completed)
- ✅ Automated reporting
- ✅ Evidence integrity verification
- ✅ Chain of custody

### Future Enhancements
- [ ] Cloud forensics (AWS, Azure, GCP)
- [ ] Container forensics (Docker, Kubernetes)
- [ ] Mobile device forensics (iOS, Android)
- [ ] Blockchain evidence handling
- [ ] AI investigation assistant (GPT-4 integration)

---

**Document Version**: 1.0
**Last Updated**: 2024-11-16
**Author**: AIRDFP Engineering Team
