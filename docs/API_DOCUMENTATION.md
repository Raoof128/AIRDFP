# AIRDFP API Documentation

## Overview

AIRDFP provides RESTful APIs for integration with external systems, SIEM platforms, and automation tools. All APIs use JSON for request and response payloads.

## Base URL

```
Production: https://airdfp.company.com/api/v1
Development: http://localhost:8080/api/v1
```

## Authentication

All API endpoints require Bearer token authentication.

### Obtaining an API Key

1. Log in to TheHive UI
2. Navigate to **Settings** → **API Keys**
3. Click **Create API Key**
4. Copy the generated key (shown only once)

### Using API Keys

Include the API key in the Authorization header:

```http
Authorization: Bearer YOUR_API_KEY_HERE
```

### Example with curl

```bash
curl -H "Authorization: Bearer abc123..." \
     https://airdfp.company.com/api/v1/cases
```

## Rate Limiting

- **Default**: 100 requests per minute per IP
- **Burst**: 200 requests
- **Headers**: Rate limit information included in response headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1234567890
```

## Error Handling

### Error Response Format

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Missing required field: hostname",
    "details": {
      "field": "hostname",
      "requirement": "required"
    }
  },
  "request_id": "req_abc123",
  "timestamp": "2024-11-16T10:30:00Z"
}
```

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Invalid/missing API key |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error |
| 503 | Service Unavailable |

---

## Endpoints

### Cases

#### Create Case

Create a new incident case from SIEM alert.

**Endpoint**: `POST /cases`

**Request Body**:
```json
{
  "title": "[SIEM] Ransomware Detection",
  "description": "Ransomware activity detected on WS-FINANCE-001",
  "severity": 3,
  "tlp": 2,
  "pap": 2,
  "tags": ["ransomware", "critical", "auto-ingested"],
  "customFields": {
    "siem_rule_id": "RULE_001",
    "affected_host": "WS-FINANCE-001",
    "user_account": "jsmith",
    "source_ip": "192.168.1.105"
  }
}
```

**Response**: `201 Created`
```json
{
  "id": "CASE-2024-001",
  "title": "[SIEM] Ransomware Detection",
  "severity": 3,
  "status": "Open",
  "created_at": "2024-11-16T10:30:00Z",
  "playbook_triggered": "RANSOMWARE_ACTIVE",
  "url": "https://airdfp.company.com/cases/CASE-2024-001"
}
```

#### Get Case

Retrieve case details by ID.

**Endpoint**: `GET /cases/{case_id}`

**Response**: `200 OK`
```json
{
  "id": "CASE-2024-001",
  "title": "[SIEM] Ransomware Detection",
  "description": "...",
  "severity": 3,
  "status": "In Progress",
  "created_at": "2024-11-16T10:30:00Z",
  "updated_at": "2024-11-16T10:35:00Z",
  "tasks": [
    {
      "id": "TASK-001",
      "title": "Evidence Collection",
      "status": "Completed",
      "completed_at": "2024-11-16T10:32:00Z"
    }
  ],
  "observables": [
    {
      "type": "ip",
      "value": "203.0.113.50",
      "ioc": true
    }
  ]
}
```

#### List Cases

List all cases with optional filtering.

**Endpoint**: `GET /cases`

**Query Parameters**:
- `status`: Filter by status (Open, In Progress, Resolved, Closed)
- `severity`: Filter by severity (1-4)
- `tag`: Filter by tag
- `limit`: Number of results (default: 50, max: 100)
- `offset`: Pagination offset

**Example**:
```bash
GET /cases?status=Open&severity=3&limit=20
```

**Response**: `200 OK`
```json
{
  "cases": [...],
  "total": 42,
  "limit": 20,
  "offset": 0,
  "has_more": true
}
```

---

### Evidence Collection

#### Trigger Collection

Trigger evidence collection on a target endpoint.

**Endpoint**: `POST /evidence/collect`

**Request Body**:
```json
{
  "hostname": "WS-FINANCE-001",
  "collection_type": "comprehensive",
  "urgent": true,
  "case_id": "CASE-2024-001"
}
```

**Collection Types**:
- `quick_triage`: ~30 seconds
- `memory_dump`: ~90 seconds
- `disk_forensics`: ~3 minutes
- `event_logs`: ~60 seconds
- `registry_analysis`: ~45 seconds
- `comprehensive`: ~5 minutes

**Response**: `202 Accepted`
```json
{
  "collection_id": "COLL-123456",
  "hostname": "WS-FINANCE-001",
  "status": "in_progress",
  "started_at": "2024-11-16T10:30:00Z",
  "estimated_completion": "2024-11-16T10:35:00Z",
  "progress_url": "/evidence/collect/COLL-123456"
}
```

#### Check Collection Status

**Endpoint**: `GET /evidence/collect/{collection_id}`

**Response**: `200 OK`
```json
{
  "collection_id": "COLL-123456",
  "status": "completed",
  "progress": 100,
  "started_at": "2024-11-16T10:30:00Z",
  "completed_at": "2024-11-16T10:33:45Z",
  "evidence_file": "evidence_WS-FINANCE-001_1699956285.zip",
  "file_size_bytes": 10737418240,
  "sha256": "e7f3c8d9a1b2f4e5c6d8a9b0c1d2e3f4..."
}
```

---

### Forensic Analysis

#### Analyze Memory Dump

Run Volatility analysis on a memory dump.

**Endpoint**: `POST /forensics/memory/analyze`

**Request Body**:
```json
{
  "evidence_file": "evidence_WS-FINANCE-001_1699956285.zip",
  "case_id": "CASE-2024-001",
  "plugins": ["all"]
}
```

**Available Plugins**:
- `all`: Run all plugins
- `process_tree`: Process enumeration
- `network_connections`: Network analysis
- `injected_code`: Code injection detection
- `services`: Service analysis

**Response**: `202 Accepted`
```json
{
  "analysis_id": "ANAL-789012",
  "status": "in_progress",
  "started_at": "2024-11-16T10:35:00Z",
  "estimated_completion": "2024-11-16T10:40:00Z",
  "progress_url": "/forensics/memory/analyze/ANAL-789012"
}
```

#### Get Analysis Results

**Endpoint**: `GET /forensics/memory/analyze/{analysis_id}`

**Response**: `200 OK`
```json
{
  "analysis_id": "ANAL-789012",
  "status": "completed",
  "severity": "CRITICAL",
  "summary": {
    "total_processes": 87,
    "suspicious_processes": 3,
    "network_connections": 45,
    "c2_candidates": 2,
    "code_injections": 2
  },
  "iocs": {
    "process_names": ["ransomware.exe", "malicious.dll"],
    "network_ips": ["203.0.113.50", "198.51.100.25"],
    "file_hashes": ["f8d3e4b5c6a7d8e9..."]
  },
  "report_url": "/forensics/memory/analyze/ANAL-789012/report"
}
```

---

### Timeline Analysis

#### Generate Timeline

Create super timeline from multiple evidence sources.

**Endpoint**: `POST /timeline/generate`

**Request Body**:
```json
{
  "case_id": "CASE-2024-001",
  "evidence_sources": [
    {
      "type": "memory",
      "path": "/evidence/memory_analysis.json"
    },
    {
      "type": "log",
      "path": "/evidence/syslog"
    },
    {
      "type": "disk",
      "path": "/evidence/ntfs_mft"
    }
  ],
  "use_ml": true
}
```

**Response**: `202 Accepted`
```json
{
  "timeline_id": "TIMELINE-345678",
  "status": "processing",
  "started_at": "2024-11-16T10:40:00Z",
  "progress_url": "/timeline/TIMELINE-345678"
}
```

#### Get Timeline

**Endpoint**: `GET /timeline/{timeline_id}`

**Response**: `200 OK`
```json
{
  "timeline_id": "TIMELINE-345678",
  "status": "completed",
  "metadata": {
    "total_events": 1247,
    "anomalies_detected": 15,
    "correlations_found": 7,
    "generated_at": "2024-11-16T10:42:00Z"
  },
  "attack_narrative": [
    {
      "timestamp": "2024-11-15T09:15:32Z",
      "type": "ANOMALY",
      "severity": "HIGH",
      "description": "User opened phishing email attachment"
    }
  ],
  "download_url": "/timeline/TIMELINE-345678/export"
}
```

---

### Reports

#### Generate Report

Generate automated incident report.

**Endpoint**: `POST /reports/generate`

**Request Body**:
```json
{
  "case_id": "CASE-2024-001",
  "format": "markdown",
  "sections": ["executive", "technical", "chain_of_custody"],
  "include_iocs": true
}
```

**Formats**:
- `markdown`: Markdown format
- `json`: JSON format
- `pdf`: PDF format (requires additional rendering)

**Response**: `201 Created`
```json
{
  "report_id": "REPORT-901234",
  "case_id": "CASE-2024-001",
  "format": "markdown",
  "generated_at": "2024-11-16T10:45:00Z",
  "download_url": "/reports/REPORT-901234/download",
  "expires_at": "2024-11-23T10:45:00Z"
}
```

#### Download Report

**Endpoint**: `GET /reports/{report_id}/download`

**Response**: `200 OK`

Returns the report file with appropriate `Content-Type` header.

---

### Playbooks

#### Execute Playbook

Manually trigger an incident response playbook.

**Endpoint**: `POST /playbooks/execute`

**Request Body**:
```json
{
  "playbook": "RANSOMWARE_ACTIVE",
  "context": {
    "hostname": "WS-FINANCE-001",
    "user": "jsmith",
    "case_id": "CASE-2024-001"
  },
  "dry_run": false
}
```

**Response**: `202 Accepted`
```json
{
  "execution_id": "EXEC-567890",
  "playbook": "RANSOMWARE_ACTIVE",
  "status": "running",
  "started_at": "2024-11-16T10:23:15Z",
  "estimated_duration": 300,
  "progress_url": "/playbooks/execute/EXEC-567890"
}
```

#### Get Playbook Status

**Endpoint**: `GET /playbooks/execute/{execution_id}`

**Response**: `200 OK`
```json
{
  "execution_id": "EXEC-567890",
  "status": "completed",
  "playbook": "RANSOMWARE_ACTIVE",
  "started_at": "2024-11-16T10:23:15Z",
  "completed_at": "2024-11-16T10:28:30Z",
  "steps": [
    {
      "name": "Isolate affected system",
      "status": "completed",
      "duration": 30
    },
    {
      "name": "Collect memory dump",
      "status": "completed",
      "duration": 90
    }
  ],
  "success_rate": "100%"
}
```

---

## Webhooks

AIRDFP can send webhook notifications for important events.

### Configure Webhook

**Endpoint**: `POST /webhooks`

**Request Body**:
```json
{
  "url": "https://your-server.com/webhook",
  "events": ["case.created", "evidence.collected", "analysis.completed"],
  "secret": "your_webhook_secret",
  "active": true
}
```

### Webhook Payload Example

```json
{
  "event": "case.created",
  "timestamp": "2024-11-16T10:30:00Z",
  "data": {
    "case_id": "CASE-2024-001",
    "title": "[SIEM] Ransomware Detection",
    "severity": 3,
    "url": "https://airdfp.company.com/cases/CASE-2024-001"
  },
  "signature": "sha256=abc123..."
}
```

### Verifying Webhook Signatures

```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(f"sha256={expected}", signature)
```

---

## SDKs and Client Libraries

### Python

```python
from airdfp import Client

# Initialize client
client = Client(
    base_url="https://airdfp.company.com/api/v1",
    api_key="your_api_key_here"
)

# Create case
case = client.cases.create(
    title="Ransomware Detection",
    severity=3,
    tags=["ransomware", "critical"]
)

# Trigger evidence collection
collection = client.evidence.collect(
    hostname="WS-FINANCE-001",
    collection_type="comprehensive",
    case_id=case.id
)

# Wait for completion
collection.wait_until_complete()

# Run analysis
analysis = client.forensics.analyze_memory(
    evidence_file=collection.evidence_file,
    case_id=case.id
)

# Generate report
report = client.reports.generate(
    case_id=case.id,
    format="markdown"
)
```

### cURL Examples

```bash
# Create case
curl -X POST https://airdfp.company.com/api/v1/cases \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Ransomware Detection",
    "severity": 3,
    "tags": ["ransomware"]
  }'

# Get case
curl https://airdfp.company.com/api/v1/cases/CASE-2024-001 \
  -H "Authorization: Bearer YOUR_API_KEY"

# Trigger collection
curl -X POST https://airdfp.company.com/api/v1/evidence/collect \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "WS-FINANCE-001",
    "collection_type": "comprehensive"
  }'
```

---

## Best Practices

### 1. Error Handling

Always check response status codes and handle errors appropriately:

```python
response = client.cases.create(...)
if response.status_code == 201:
    case_id = response.json()['id']
elif response.status_code == 400:
    print(f"Validation error: {response.json()['error']['message']}")
elif response.status_code == 429:
    print("Rate limit exceeded, waiting...")
    time.sleep(60)
else:
    print(f"Unexpected error: {response.status_code}")
```

### 2. Pagination

For large result sets, use pagination:

```python
offset = 0
limit = 50

while True:
    response = client.cases.list(offset=offset, limit=limit)
    cases = response['cases']

    # Process cases
    for case in cases:
        process_case(case)

    if not response['has_more']:
        break

    offset += limit
```

### 3. Asynchronous Operations

For long-running operations, poll status endpoint:

```python
# Start operation
response = client.forensics.analyze_memory(...)
analysis_id = response['analysis_id']

# Poll for completion
while True:
    status = client.forensics.get_analysis(analysis_id)
    if status['status'] == 'completed':
        break
    elif status['status'] == 'failed':
        raise Exception("Analysis failed")

    time.sleep(5)

# Get results
results = status['results']
```

---

## API Versioning

API versions are specified in the URL path:

- Current version: `/api/v1`
- Beta features: `/api/v1-beta`

**Deprecation Policy**: API versions are supported for minimum 12 months after deprecation announcement.

---

## Support

For API support:
- **Documentation**: https://docs.airdfp.io
- **Issues**: https://github.com/Raoof128/AIRDFP/issues
- **Email**: api-support@airdfp.local

---

**Last Updated**: 2024-11-16
**API Version**: 1.0
