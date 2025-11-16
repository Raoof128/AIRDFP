#!/usr/bin/env python3
"""
SIEM/SOAR Integration Module
Bi-directional alerting: Alerts → Cases → Playbooks → Response
"""

import requests
import json
import argparse
from datetime import datetime
from typing import Dict, Optional, List
import time


class SIEMIntegration:
    """Connect SIEM alerts to IR platform"""

    def __init__(self, thehive_url: str, thehive_key: str, soar_url: str):
        self.thehive_url = thehive_url.rstrip('/')
        self.thehive_key = thehive_key
        self.soar_url = soar_url.rstrip('/') if soar_url else None
        self.headers = {
            "Authorization": f"Bearer {thehive_key}",
            "Content-Type": "application/json"
        }

        # ML-based severity mapping (simplified - in production use actual ML model)
        self.severity_mapping = {
            "ransomware_detection": {"level": 3, "template": "CRITICAL_MALWARE"},
            "lateral_movement": {"level": 2, "template": "LATERAL_MOVEMENT"},
            "data_exfiltration": {"level": 3, "template": "DATA_EXFILTRATION"},
            "account_compromise": {"level": 2, "template": "ACCOUNT_COMPROMISE"},
            "brute_force_attempt": {"level": 1, "template": "ACCOUNT_COMPROMISE"},
            "suspicious_script": {"level": 2, "template": "CRITICAL_MALWARE"},
            "malware_detected": {"level": 3, "template": "CRITICAL_MALWARE"},
            "privilege_escalation": {"level": 2, "template": "LATERAL_MOVEMENT"},
            "unusual_outbound": {"level": 2, "template": "DATA_EXFILTRATION"}
        }

        # Playbook mapping
        self.playbook_mapping = {
            "ransomware_detection": "isolate_host_and_preserve_evidence",
            "lateral_movement": "collect_ad_forensics",
            "data_exfiltration": "block_and_analyze",
            "account_compromise": "credential_reset_and_audit",
            "malware_detected": "isolate_host_and_preserve_evidence"
        }

    def classify_severity(self, alert_type: str) -> Dict:
        """ML-based severity classification"""
        return self.severity_mapping.get(
            alert_type,
            {"level": 1, "template": "CRITICAL_MALWARE"}  # Default: Medium severity
        )

    def ingest_siem_alert(self, alert: Dict) -> Optional[str]:
        """
        Convert SIEM alert → TheHive case with severity classification

        Args:
            alert: SIEM alert data with keys:
                - rule_name: str
                - alert_type: str
                - source_ip: str
                - dest_ip: str (optional)
                - hostname: str
                - user: str (optional)
                - timestamp: str (ISO format)
                - raw_log: str (optional)

        Returns:
            case_id if successful, None otherwise
        """

        # Classify severity using ML model
        classification = self.classify_severity(alert.get('alert_type', 'unknown'))

        # Build case payload
        case_payload = {
            "title": f"[SIEM] {alert['rule_name']}",
            "description": self._build_description(alert),
            "severity": classification['level'],
            "tlp": 2,  # Amber
            "pap": 2,  # Amber
            "startDate": int(datetime.now().timestamp() * 1000),
            "tags": [
                "siem-alert",
                alert['alert_type'],
                "auto-ingested",
                f"severity-{classification['level']}"
            ],
            "customFields": {
                "siem_rule_id": alert.get('rule_id', 'unknown'),
                "affected_host": alert.get('hostname', 'unknown'),
                "user_account": alert.get('user', 'N/A'),
                "source_ip": alert.get('source_ip', 'N/A'),
                "alert_type": alert.get('alert_type', 'unknown')
            }
        }

        # Add tasks based on template
        case_payload['tasks'] = self._get_template_tasks(classification['template'])

        # Create case in TheHive
        try:
            response = requests.post(
                f"{self.thehive_url}/api/case",
                headers=self.headers,
                json=case_payload,
                timeout=30
            )

            if response.status_code == 201:
                case_data = response.json()
                case_id = case_data.get('id')
                print(f"✅ Created case {case_id} from alert: {alert['rule_name']}")
                print(f"   Severity: {classification['level']} ({self._severity_name(classification['level'])})")
                print(f"   Template: {classification['template']}")

                # Add observables
                self._add_observables(case_id, alert)

                # Trigger SOAR playbook if configured
                if self.soar_url:
                    self.trigger_playbook(case_id, alert['alert_type'], alert)

                return case_id
            else:
                print(f"❌ Failed to create case: HTTP {response.status_code}")
                print(f"   Response: {response.text}")
                return None

        except Exception as e:
            print(f"❌ Error creating case: {e}")
            return None

    def _build_description(self, alert: Dict) -> str:
        """Build detailed case description"""
        return f"""
# SIEM Alert Details

**Alert Type**: {alert.get('alert_type', 'Unknown')}
**Rule Name**: {alert['rule_name']}
**Timestamp**: {alert.get('timestamp', datetime.now().isoformat())}

## Affected Systems
- **Hostname**: {alert.get('hostname', 'Unknown')}
- **Source IP**: {alert.get('source_ip', 'N/A')}
- **Destination IP**: {alert.get('dest_ip', 'N/A')}
- **User**: {alert.get('user', 'N/A')}

## Evidence
```
{alert.get('raw_log', 'No raw log available')}
```

## Recommended Actions
This alert has been automatically classified and assigned appropriate response tasks.
Review the tasks below and execute according to incident severity.

**Auto-generated**: {datetime.now().isoformat()}
        """.strip()

    def _get_template_tasks(self, template: str) -> List[Dict]:
        """Get tasks for case template"""
        task_templates = {
            "CRITICAL_MALWARE": [
                {"title": "Evidence Collection (Memory + Disk)", "status": "Waiting"},
                {"title": "Malware Analysis", "status": "Waiting"},
                {"title": "IOC Extraction", "status": "Waiting"},
                {"title": "Impact Assessment", "status": "Waiting"},
                {"title": "Remediation", "status": "Waiting"}
            ],
            "LATERAL_MOVEMENT": [
                {"title": "AD Forensics Collection", "status": "Waiting"},
                {"title": "Network Timeline Analysis", "status": "Waiting"},
                {"title": "Credential Audit", "status": "Waiting"},
                {"title": "Containment", "status": "Waiting"}
            ],
            "DATA_EXFILTRATION": [
                {"title": "Network Flow Analysis", "status": "Waiting"},
                {"title": "Database Forensics", "status": "Waiting"},
                {"title": "DLP Investigation", "status": "Waiting"},
                {"title": "Impact Quantification", "status": "Waiting"}
            ],
            "ACCOUNT_COMPROMISE": [
                {"title": "Access Timeline Creation", "status": "Waiting"},
                {"title": "Email Forensics", "status": "Waiting"},
                {"title": "MFA Audit", "status": "Waiting"},
                {"title": "Password Reset", "status": "Waiting"}
            ]
        }

        return task_templates.get(template, [])

    def _severity_name(self, level: int) -> str:
        """Convert severity level to name"""
        names = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        return names.get(level, "Unknown")

    def _add_observables(self, case_id: str, alert: Dict) -> None:
        """Add observables (IOCs) to case"""
        observables = []

        # Add IP addresses
        if alert.get('source_ip'):
            observables.append({
                "dataType": "ip",
                "data": alert['source_ip'],
                "message": "Source IP from SIEM alert",
                "tlp": 2,
                "ioc": True,
                "tags": ["auto-extracted", "source-ip"]
            })

        if alert.get('dest_ip'):
            observables.append({
                "dataType": "ip",
                "data": alert['dest_ip'],
                "message": "Destination IP from SIEM alert",
                "tlp": 2,
                "ioc": True,
                "tags": ["auto-extracted", "dest-ip"]
            })

        # Add hostname
        if alert.get('hostname'):
            observables.append({
                "dataType": "hostname",
                "data": alert['hostname'],
                "message": "Affected hostname",
                "tlp": 2,
                "tags": ["auto-extracted", "affected-host"]
            })

        # Add user
        if alert.get('user'):
            observables.append({
                "dataType": "user-agent",  # Or appropriate type
                "data": alert['user'],
                "message": "Affected user account",
                "tlp": 2,
                "tags": ["auto-extracted", "user-account"]
            })

        # Create observables
        for obs in observables:
            try:
                response = requests.post(
                    f"{self.thehive_url}/api/case/{case_id}/observable",
                    headers=self.headers,
                    json=obs,
                    timeout=10
                )
                if response.status_code == 201:
                    print(f"   ➕ Added observable: {obs['dataType']} = {obs['data']}")
            except Exception as e:
                print(f"   ⚠️ Failed to add observable: {e}")

    def trigger_playbook(self, case_id: str, incident_type: str, alert: Dict) -> None:
        """Trigger SOAR playbook based on incident type"""

        playbook = self.playbook_mapping.get(incident_type)

        if not playbook:
            print(f"   ℹ️ No playbook mapping for incident type: {incident_type}")
            return

        payload = {
            "playbook": playbook,
            "case_id": case_id,
            "auto_triggered": True,
            "context": {
                "hostname": alert.get('hostname'),
                "user": alert.get('user'),
                "source_ip": alert.get('source_ip'),
                "incident_type": incident_type,
                "severity": self.classify_severity(incident_type)['level']
            }
        }

        try:
            response = requests.post(
                f"{self.soar_url}/api/execute",
                json=payload,
                timeout=10
            )
            if response.status_code in [200, 201]:
                print(f"   🎬 Triggered playbook: {playbook}")
            else:
                print(f"   ⚠️ Playbook trigger failed: HTTP {response.status_code}")
        except Exception as e:
            print(f"   ⚠️ Playbook trigger error: {e}")


def simulate_siem_alerts() -> List[Dict]:
    """Generate sample SIEM alerts for testing"""
    return [
        {
            "rule_name": "Ransomware - File Encryption Activity Detected",
            "rule_id": "RULE_001",
            "alert_type": "ransomware_detection",
            "source_ip": "192.168.1.105",
            "dest_ip": "10.0.0.50",
            "hostname": "WS-FINANCE-001",
            "user": "jsmith",
            "timestamp": datetime.now().isoformat(),
            "raw_log": "Process explorer.exe spawned powershell.exe with arguments: -enc <base64_payload>"
        },
        {
            "rule_name": "Lateral Movement - PsExec Execution Detected",
            "rule_id": "RULE_002",
            "alert_type": "lateral_movement",
            "source_ip": "10.0.10.25",
            "dest_ip": "10.0.10.30",
            "hostname": "WS-IT-003",
            "user": "admin",
            "timestamp": datetime.now().isoformat(),
            "raw_log": "EventID 4688: Process psexec.exe created by user admin"
        },
        {
            "rule_name": "Data Exfiltration - Unusual Outbound Transfer",
            "rule_id": "RULE_003",
            "alert_type": "data_exfiltration",
            "source_ip": "10.0.5.15",
            "dest_ip": "203.0.113.50",  # External IP
            "hostname": "DB-SERVER-01",
            "user": "svc_backup",
            "timestamp": datetime.now().isoformat(),
            "raw_log": "Firewall: Outbound connection to 203.0.113.50:443, 2.3GB transferred"
        },
        {
            "rule_name": "Account Compromise - Impossible Travel Detected",
            "rule_id": "RULE_004",
            "alert_type": "account_compromise",
            "source_ip": "198.51.100.25",  # External IP
            "hostname": "N/A",
            "user": "mjohnson",
            "timestamp": datetime.now().isoformat(),
            "raw_log": "User mjohnson authenticated from Sydney (10:00 AM) and London (10:05 AM)"
        }
    ]


def main():
    parser = argparse.ArgumentParser(
        description="SIEM Integration for AIRDFP"
    )
    parser.add_argument(
        "--thehive-url",
        default="http://localhost:9000",
        help="TheHive URL (default: http://localhost:9000)"
    )
    parser.add_argument(
        "--thehive-key",
        required=True,
        help="TheHive API key (required)"
    )
    parser.add_argument(
        "--soar-url",
        default=None,
        help="SOAR platform URL (optional)"
    )
    parser.add_argument(
        "--test-mode",
        action="store_true",
        help="Run with simulated SIEM alerts"
    )
    parser.add_argument(
        "--alert-file",
        help="JSON file containing SIEM alerts to ingest"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("SIEM Integration - AIRDFP")
    print("=" * 60)

    integration = SIEMIntegration(
        args.thehive_url,
        args.thehive_key,
        args.soar_url
    )

    if args.test_mode:
        print("\n🧪 TEST MODE: Simulating SIEM alerts\n")
        alerts = simulate_siem_alerts()
    elif args.alert_file:
        print(f"\n📁 Loading alerts from: {args.alert_file}\n")
        with open(args.alert_file, 'r') as f:
            alerts = json.load(f)
    else:
        print("\n❌ Error: Use --test-mode or --alert-file to provide alerts")
        return 1

    print(f"Processing {len(alerts)} alerts...\n")

    results = {
        "success": 0,
        "failed": 0,
        "case_ids": []
    }

    for i, alert in enumerate(alerts, 1):
        print(f"\n[{i}/{len(alerts)}] Processing: {alert['rule_name']}")
        case_id = integration.ingest_siem_alert(alert)

        if case_id:
            results['success'] += 1
            results['case_ids'].append(case_id)
        else:
            results['failed'] += 1

        # Rate limiting
        time.sleep(0.5)

    print("\n" + "=" * 60)
    print("INGESTION SUMMARY")
    print("=" * 60)
    print(f"✅ Successful: {results['success']}")
    print(f"❌ Failed: {results['failed']}")
    print(f"📊 Total: {len(alerts)}")

    if results['case_ids']:
        print(f"\n📋 Created Cases:")
        for case_id in results['case_ids']:
            print(f"   - {args.thehive_url}/index.html#!/case/{case_id}")

    return 0 if results['failed'] == 0 else 1


if __name__ == "__main__":
    exit(main())
