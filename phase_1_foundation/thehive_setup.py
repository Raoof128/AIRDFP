#!/usr/bin/env python3
"""
TheHive Case Template Configuration
Creates standardized incident classification templates for ML training
"""

import requests
import json
import argparse
from datetime import datetime
from typing import List, Dict, Optional


class TheHiveSetup:
    """TheHive API client for case template configuration"""

    def __init__(self, url: str, api_key: str):
        self.url = url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

    def test_connection(self) -> bool:
        """Test connectivity to TheHive instance"""
        try:
            response = requests.get(
                f"{self.url}/api/status",
                headers=self.headers,
                timeout=10
            )
            if response.status_code == 200:
                print(f"✅ Connected to TheHive at {self.url}")
                return True
            else:
                print(f"❌ Connection failed: HTTP {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Connection error: {e}")
            return False

    def create_case_template(self, template: Dict) -> Optional[str]:
        """Create a single case template"""
        try:
            response = requests.post(
                f"{self.url}/api/case",
                headers=self.headers,
                json=template,
                timeout=30
            )

            if response.status_code == 201:
                case_id = response.json().get('id')
                print(f"✅ Created template: {template['title']}")
                return case_id
            else:
                print(f"❌ Failed to create {template['title']}: {response.text}")
                return None
        except Exception as e:
            print(f"❌ Error creating template: {e}")
            return None

    def get_case_templates(self) -> List[str]:
        """Define incident case templates"""
        return [
            {
                "title": "CRITICAL_MALWARE",
                "severity": 3,  # Critical
                "tlp": 2,  # Amber
                "pap": 2,  # Amber
                "description": """
                Active malware infection detected on endpoint.

                This template is used for confirmed malware infections including:
                - Ransomware
                - Banking trojans
                - RAT/backdoors
                - Cryptominers
                - Worms

                IMMEDIATE ACTIONS REQUIRED:
                - Network isolation
                - Memory dump collection
                - Disk preservation
                """,
                "tags": ["malware", "critical", "auto-template"],
                "tasks": [
                    {
                        "title": "Evidence Collection (Memory + Disk)",
                        "description": "Use Velociraptor to collect memory dump and disk artifacts",
                        "status": "Waiting"
                    },
                    {
                        "title": "Malware Analysis",
                        "description": "Run Volatility 3 analysis suite on memory dump",
                        "status": "Waiting"
                    },
                    {
                        "title": "IOC Extraction",
                        "description": "Extract indicators of compromise (IPs, domains, hashes)",
                        "status": "Waiting"
                    },
                    {
                        "title": "Impact Assessment",
                        "description": "Determine scope: affected systems, data, business impact",
                        "status": "Waiting"
                    },
                    {
                        "title": "Remediation",
                        "description": "Execute playbook: isolate, clean/reimage, validate",
                        "status": "Waiting"
                    }
                ],
                "customFields": {
                    "incident_type": "malware",
                    "playbook": "RANSOMWARE_ACTIVE",
                    "auto_isolation": True
                }
            },
            {
                "title": "LATERAL_MOVEMENT",
                "severity": 2,  # High
                "tlp": 2,
                "pap": 2,
                "description": """
                Suspected privilege escalation or lateral movement detected.

                Indicators may include:
                - Unusual authentication patterns
                - Privilege escalation events
                - Pass-the-hash/Pass-the-ticket attacks
                - PSExec or remote execution tools
                - Suspicious process creation chains

                FOCUS AREAS:
                - Active Directory forensics
                - Authentication logs
                - Network timeline analysis
                """,
                "tags": ["lateral-movement", "high", "apt", "auto-template"],
                "tasks": [
                    {
                        "title": "AD Forensics Collection",
                        "description": "Collect Security event logs from domain controllers (4624, 4672, 4768)",
                        "status": "Waiting"
                    },
                    {
                        "title": "Network Timeline Analysis",
                        "description": "Create timeline of authentication events across affected systems",
                        "status": "Waiting"
                    },
                    {
                        "title": "Credential Audit",
                        "description": "Review compromised accounts, privilege levels, access patterns",
                        "status": "Waiting"
                    },
                    {
                        "title": "Containment",
                        "description": "Reset credentials, revoke sessions, isolate affected accounts",
                        "status": "Waiting"
                    }
                ],
                "customFields": {
                    "incident_type": "lateral_movement",
                    "playbook": "LATERAL_MOVEMENT_DETECTED",
                    "auto_isolation": False
                }
            },
            {
                "title": "DATA_EXFILTRATION",
                "severity": 3,  # Critical
                "tlp": 3,  # Red
                "pap": 2,
                "description": """
                Suspected data exfiltration event detected.

                Indicators may include:
                - Unusual outbound data transfers
                - Access to sensitive databases/file shares
                - Cloud storage uploads (non-sanctioned)
                - Compressed/encrypted file creation
                - Off-hours access patterns

                CRITICAL PRIORITIES:
                - Quantify data exposure
                - Identify exfiltration method
                - Preserve network evidence
                """,
                "tags": ["data-exfiltration", "critical", "data-breach", "auto-template"],
                "tasks": [
                    {
                        "title": "Network Flow Analysis",
                        "description": "Analyze NetFlow/firewall logs for large outbound transfers",
                        "status": "Waiting"
                    },
                    {
                        "title": "Database Forensics",
                        "description": "Review database query logs, access patterns, exported records",
                        "status": "Waiting"
                    },
                    {
                        "title": "DLP Investigation",
                        "description": "Check DLP alerts, blocked transfers, policy violations",
                        "status": "Waiting"
                    },
                    {
                        "title": "Impact Quantification",
                        "description": "Determine: records affected, data classification, business impact",
                        "status": "Waiting"
                    }
                ],
                "customFields": {
                    "incident_type": "data_exfiltration",
                    "playbook": "DATA_EXFILTRATION",
                    "auto_isolation": True
                }
            },
            {
                "title": "ACCOUNT_COMPROMISE",
                "severity": 2,  # High
                "tlp": 2,
                "pap": 2,
                "description": """
                User account or credentials compromised.

                Indicators may include:
                - Impossible travel (logins from distant locations)
                - Failed authentication spikes
                - Unusual access patterns
                - MFA bypass attempts
                - Credential stuffing attacks

                INVESTIGATION FOCUS:
                - Access timeline
                - Email forensics (forwarding rules, sent items)
                - MFA audit
                """,
                "tags": ["account-compromise", "high", "credential-theft", "auto-template"],
                "tasks": [
                    {
                        "title": "Access Timeline Creation",
                        "description": "Document all account activity: logins, resource access, privilege changes",
                        "status": "Waiting"
                    },
                    {
                        "title": "Email Forensics",
                        "description": "Check for: forwarding rules, sent emails, calendar access",
                        "status": "Waiting"
                    },
                    {
                        "title": "MFA Audit",
                        "description": "Review MFA status, bypass events, token generation",
                        "status": "Waiting"
                    },
                    {
                        "title": "Password Reset",
                        "description": "Force password reset, revoke all sessions, re-enable MFA",
                        "status": "Waiting"
                    }
                ],
                "customFields": {
                    "incident_type": "account_compromise",
                    "playbook": "ACCOUNT_COMPROMISE",
                    "auto_isolation": False
                }
            }
        ]

    def setup_templates(self) -> None:
        """Create all case templates"""
        print("\n🔧 Setting up TheHive case templates...\n")

        templates = self.get_case_templates()
        created = 0
        failed = 0

        for template in templates:
            result = self.create_case_template(template)
            if result:
                created += 1
            else:
                failed += 1

        print(f"\n📋 Template Setup Summary:")
        print(f"  ✅ Created: {created}")
        print(f"  ❌ Failed: {failed}")
        print(f"  📊 Total: {len(templates)}")

    def verify_setup(self) -> bool:
        """Verify all templates were created"""
        try:
            response = requests.get(
                f"{self.url}/api/case",
                headers=self.headers,
                timeout=30
            )

            if response.status_code == 200:
                cases = response.json()
                auto_templates = [
                    c for c in cases
                    if "auto-template" in c.get('tags', [])
                ]

                print(f"\n✅ Verification: Found {len(auto_templates)} auto-generated templates")
                return len(auto_templates) >= 4
            else:
                print(f"❌ Verification failed: HTTP {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Verification error: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Setup TheHive case templates for AIRDFP"
    )
    parser.add_argument(
        "--url",
        default="http://localhost:9000",
        help="TheHive URL (default: http://localhost:9000)"
    )
    parser.add_argument(
        "--api-key",
        required=True,
        help="TheHive API key (required)"
    )
    parser.add_argument(
        "--test-only",
        action="store_true",
        help="Only test connection, don't create templates"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify existing templates"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("TheHive Case Template Setup - AIRDFP")
    print("=" * 60)

    setup = TheHiveSetup(args.url, args.api_key)

    # Test connection
    if not setup.test_connection():
        print("\n❌ Cannot connect to TheHive. Please check:")
        print("   1. TheHive is running (docker-compose up -d)")
        print("   2. URL is correct")
        print("   3. API key is valid")
        return 1

    if args.test_only:
        print("\n✅ Connection test successful (--test-only mode)")
        return 0

    if args.verify:
        if setup.verify_setup():
            print("\n✅ Template verification successful")
            return 0
        else:
            print("\n⚠️ Template verification failed")
            return 1

    # Create templates
    setup.setup_templates()

    # Verify
    if setup.verify_setup():
        print("\n✅ Setup complete and verified!")
        print("\n📖 Next steps:")
        print("   1. Access TheHive UI: http://localhost:9000")
        print("   2. Login with default credentials (admin/password)")
        print("   3. View created templates in Cases section")
        print("   4. Test SIEM integration: python siem_integration.py")
        return 0
    else:
        print("\n⚠️ Setup completed but verification failed")
        return 1


if __name__ == "__main__":
    exit(main())
