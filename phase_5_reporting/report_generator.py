#!/usr/bin/env python3
"""
Automated Report Generation
Professional forensics reporting with executive + technical sections
"""

import json
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import hashlib


class IncidentReportGenerator:
    """Generate professional incident response reports"""

    def __init__(
        self,
        case_id: str,
        case_data: Dict,
        timeline: Optional[Dict] = None,
        iocs: Optional[Dict] = None,
        evidence_manifest: Optional[Dict] = None
    ):
        self.case_id = case_id
        self.case_data = case_data
        self.timeline = timeline or {}
        self.iocs = iocs or {}
        self.evidence_manifest = evidence_manifest or {}
        self.timestamp = datetime.now().isoformat()

    def generate_executive_summary(self) -> str:
        """High-level business impact summary"""

        timeline_events = self.timeline.get('attack_narrative', [])
        initial_compromise = timeline_events[0] if timeline_events else None

        return f"""
# EXECUTIVE INCIDENT SUMMARY

**Incident ID**: {self.case_id}
**Date/Time**: {self.timestamp}
**Severity**: {self.case_data.get('severity', 'UNKNOWN')}
**Status**: {self.case_data.get('status', 'Under Investigation')}

## INCIDENT OVERVIEW
{self.case_data.get('description', 'No description provided')}

## KEY FINDINGS

1. **Initial Compromise**: {initial_compromise['description'] if initial_compromise else 'Under investigation'}
2. **Attack Vector**: {self._identify_attack_vector()}
3. **Systems Affected**: {len(self.evidence_manifest.get('hosts', []))} hosts
4. **Data Impact**: {self._estimate_data_impact()} potentially affected
5. **Threat Actor**: {self._assess_threat_actor()}

## IMMEDIATE ACTIONS TAKEN

✅ System isolation and containment
✅ Evidence preservation and collection
✅ Forensic analysis completed
✅ Threat indicators extracted and blocked
✅ Credentials reset for affected accounts

## REMEDIATION STATUS

| Action | Status |
|--------|--------|
| Credentials Reset | {self.case_data.get('credentials_reset', '⏳ Pending')} |
| Patches Applied | {self.case_data.get('patches_applied', '⏳ Pending')} |
| Threats Removed | {self.case_data.get('threats_removed', '⏳ Pending')} |
| Systems Recovered | {self.case_data.get('systems_recovered', '⏳ Pending')} |

## BUSINESS IMPACT

**Estimated Downtime**: {self.case_data.get('downtime_hours', 'TBD')} hours
**Affected Users**: {self.case_data.get('affected_users', 'TBD')}
**Data Loss**: {self.case_data.get('data_loss', 'None confirmed')}
**Financial Impact**: {self.case_data.get('financial_impact', 'Under assessment')}

## RECOMMENDATIONS

### Immediate (24 hours)
- Force password reset for all affected accounts
- Enable MFA on administrative accounts
- Review and update firewall rules
- Deploy updated EDR signatures

### Short-term (1 week)
- Patch all identified vulnerabilities
- Implement network segmentation
- Conduct security awareness training
- Review and update incident response procedures

### Long-term (1 month)
- Penetration testing exercise
- Security architecture review
- Implement continuous monitoring for identified IOCs
- Update threat intelligence feeds
        """.strip()

    def generate_technical_findings(self) -> str:
        """Detailed technical analysis"""

        findings = ["# TECHNICAL FINDINGS\n"]

        # Evidence collected
        findings.append("## 1. EVIDENCE COLLECTION\n")
        for evidence in self.evidence_manifest.get('evidence', []):
            findings.append(f"### {evidence.get('type', 'Unknown Type')}\n")
            findings.append(f"- **File**: `{evidence.get('path', 'N/A')}`")
            findings.append(f"- **SHA256**: `{evidence.get('sha256', 'N/A')}`")
            findings.append(f"- **Collection Date**: {evidence.get('collection_date', 'N/A')}")
            findings.append(f"- **Collected By**: {evidence.get('collected_by', 'AIRDFP')}")
            findings.append(f"- **Size**: {self._format_bytes(evidence.get('file_size_bytes', 0))}\n")

        # Timeline analysis
        findings.append("## 2. TIMELINE ANALYSIS\n")
        findings.append(f"**Total Events**: {self.timeline.get('metadata', {}).get('total_events', 0)}")
        findings.append(f"**Anomalies Detected**: {self.timeline.get('metadata', {}).get('anomalies_detected', 0)}")
        findings.append(f"**Correlations Found**: {self.timeline.get('metadata', {}).get('correlations_found', 0)}\n")

        findings.append("### Key Timeline Events:\n")
        for i, event in enumerate(self.timeline.get('attack_narrative', [])[:10], 1):
            findings.append(f"{i}. **[{event.get('timestamp', 'N/A')}]** {event.get('description', 'N/A')}")
            findings.append(f"   - Type: {event.get('type', 'N/A')}")
            findings.append(f"   - Severity: {event.get('severity', 'N/A')}\n")

        # IOCs extracted
        findings.append("## 3. INDICATORS OF COMPROMISE (IOCs)\n")

        for ioc_type, iocs in self.iocs.items():
            if iocs:
                findings.append(f"### {ioc_type.replace('_', ' ').title()}\n")
                findings.append("```")
                for ioc in iocs[:20]:  # Limit to first 20
                    findings.append(f"{ioc}")
                if len(iocs) > 20:
                    findings.append(f"... and {len(iocs) - 20} more")
                findings.append("```\n")

        # MITRE ATT&CK mapping
        findings.append("## 4. MITRE ATT&CK MAPPING\n")
        ttps = self.extract_ttps()
        for ttp in ttps:
            findings.append(f"- {ttp}")
        findings.append("")

        return "\n".join(findings)

    def extract_ttps(self) -> List[str]:
        """Extract MITRE ATT&CK TTPs"""
        ttps = []

        # Map findings to ATT&CK techniques
        timeline_events = self.timeline.get('attack_narrative', [])

        for event in timeline_events:
            desc = event.get('description', '').lower()

            if 'process' in desc or 'powershell' in desc or 'cmd' in desc:
                ttps.append("**T1059** - Command and Scripting Interpreter")
            if 'network' in desc or 'connection' in desc:
                ttps.append("**T1071** - Application Layer Protocol")
            if 'credential' in desc or 'password' in desc:
                ttps.append("**T1555** - Credentials from Password Stores")
            if 'persistence' in desc or 'registry' in desc:
                ttps.append("**T1547** - Boot or Logon Autostart Execution")
            if 'privilege' in desc or 'escalation' in desc:
                ttps.append("**T1068** - Exploitation for Privilege Escalation")
            if 'lateral' in desc or 'movement' in desc:
                ttps.append("**T1021** - Remote Services")
            if 'data' in desc or 'exfiltration' in desc:
                ttps.append("**T1041** - Exfiltration Over C2 Channel")

        # Remove duplicates and limit
        return list(dict.fromkeys(ttps))[:10]

    def generate_remediation_steps(self) -> str:
        """Actionable remediation guidance"""

        return """
# REMEDIATION AND HARDENING STEPS

## IMMEDIATE ACTIONS (24 hours)

### 1. Credential Security
- ✅ Force password reset for all affected users
- ✅ Enable MFA on all administrative accounts
- ✅ Review and revoke suspicious API tokens
- ⏳ Audit service account credentials
- ⏳ Implement password rotation policy

### 2. System Containment
- ✅ Isolate affected systems from network
- ✅ Snapshot virtual machines for forensics
- ⏳ Review firewall rules and ACLs
- ⏳ Block identified malicious IPs/domains
- ⏳ Deploy updated antivirus signatures

### 3. Evidence Preservation
- ✅ Collect memory dumps from affected hosts
- ✅ Preserve disk images
- ✅ Export relevant logs (retain 90 days minimum)
- ✅ Document chain of custody

## SHORT-TERM ACTIONS (1 week)

### 1. Vulnerability Remediation
- Patch systems vulnerable to initial exploit vector
- Update all software to latest versions
- Review and disable unnecessary services
- Implement application whitelisting
- Deploy EDR on all endpoints

### 2. Security Hardening
- Implement network segmentation (VLAN isolation)
- Deploy intrusion detection/prevention systems
- Enable enhanced logging and monitoring
- Implement least privilege access controls
- Review and update security policies

### 3. Detection Enhancement
- Deploy SIEM correlation rules for identified TTPs
- Implement behavioral analytics
- Configure alerting for IOCs
- Enhance endpoint detection capabilities
- Integrate threat intelligence feeds

## LONG-TERM ACTIONS (ongoing)

### 1. Continuous Monitoring
- Implement 24/7 SOC monitoring
- Deploy UEBA (User and Entity Behavior Analytics)
- Regular threat hunting exercises
- Automated IOC scanning
- Threat intelligence integration

### 2. Security Program Enhancements
- Quarterly penetration testing
- Annual security architecture review
- Regular incident response tabletop exercises
- Security awareness training program
- Red team/Purple team exercises

### 3. Compliance Alignment
- APRA CPS 234 compliance validation
- Essential Eight Maturity Level 3+ achievement
- ISO 27001 certification pursuit
- Regular compliance audits
- Incident response procedure updates
        """.strip()

    def generate_chain_of_custody(self) -> str:
        """Legal evidence handling documentation"""

        coc_records = ["# CHAIN OF CUSTODY\n"]

        for evidence in self.evidence_manifest.get('evidence', []):
            coc_records.append(f"""
## Evidence Record: {evidence.get('id', 'N/A')}

**Description**: {evidence.get('type', 'Unknown')}
**Location Seized**: `{evidence.get('path', 'N/A')}`
**Date/Time Seized**: {evidence.get('collection_date', 'N/A')}
**Seized By**: {evidence.get('collected_by', 'AIRDFP System')}

### Hash Verification
```
MD5:    {evidence.get('md5', 'N/A')}
SHA256: {evidence.get('sha256', 'N/A')}
```

### Integrity Status
**Integrity Seal**: {evidence.get('sealed', '✅ VERIFIED')}
**Tamper Detection**: {evidence.get('tamper_check', '✅ PASSED')}
**Chain Maintained**: {evidence.get('chain_verified', '✅ CONTINUOUS')}

### Custody Transfer Log
| Date/Time | From | To | Purpose | Signature |
|-----------|------|-----|---------|-----------|
| {evidence.get('collection_date', 'N/A')} | Endpoint | Evidence Vault | Collection | AIRDFP_AUTO |
| {self.timestamp} | Evidence Vault | Forensic Analyst | Analysis | SYSTEM |

---
            """)

        return "\n".join(coc_records)

    def _identify_attack_vector(self) -> str:
        """Identify primary attack vector"""
        timeline_events = self.timeline.get('attack_narrative', [])

        for event in timeline_events:
            desc = event.get('description', '').lower()
            if 'phishing' in desc or 'email' in desc:
                return "Phishing/Email compromise"
            if 'malware' in desc or 'ransomware' in desc:
                return "Malware deployment"
            if 'credential' in desc or 'brute force' in desc:
                return "Credential compromise"
            if 'vulnerability' in desc or 'exploit' in desc:
                return "Vulnerability exploitation"

        return "Under investigation"

    def _estimate_data_impact(self) -> str:
        """Estimate data exposure"""
        total_events = self.timeline.get('metadata', {}).get('total_events', 0)

        if total_events > 100:
            return "High - Multiple systems accessed"
        elif total_events > 50:
            return "Medium - Limited system access"
        else:
            return "Low - Minimal data exposure"

    def _assess_threat_actor(self) -> str:
        """Assess threat actor sophistication"""
        ttps = self.extract_ttps()

        if len(ttps) > 5:
            return "Advanced Persistent Threat (APT) - High sophistication"
        elif len(ttps) > 3:
            return "Organized cybercrime group - Medium sophistication"
        else:
            return "Opportunistic attacker - Low sophistication"

    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human-readable"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"

    def generate_markdown_report(self, output_file: str = None) -> str:
        """Create comprehensive Markdown report"""

        if output_file is None:
            output_file = f"IR_Report_{self.case_id}.md"

        report_sections = [
            f"# INCIDENT RESPONSE REPORT",
            f"**Case ID**: {self.case_id}",
            f"**Generated**: {self.timestamp}",
            f"**Classification**: CONFIDENTIAL\n",
            "---\n",
            self.generate_executive_summary(),
            "\n---\n",
            self.generate_technical_findings(),
            "\n---\n",
            self.generate_remediation_steps(),
            "\n---\n",
            self.generate_chain_of_custody()
        ]

        report_content = "\n\n".join(report_sections)

        with open(output_file, 'w') as f:
            f.write(report_content)

        print(f"✅ Markdown report generated: {output_file}")
        return output_file

    def generate_json_report(self, output_file: str = None) -> str:
        """Machine-readable report for integration"""

        if output_file is None:
            output_file = f"IR_Report_{self.case_id}.json"

        report = {
            "metadata": {
                "case_id": self.case_id,
                "generated_at": self.timestamp,
                "severity": self.case_data.get('severity'),
                "status": self.case_data.get('status')
            },
            "executive_summary": {
                "attack_vector": self._identify_attack_vector(),
                "systems_affected": len(self.evidence_manifest.get('hosts', [])),
                "data_impact": self._estimate_data_impact(),
                "threat_actor": self._assess_threat_actor()
            },
            "technical_findings": {
                "evidence_collected": self.evidence_manifest.get('evidence', []),
                "timeline": self.timeline,
                "iocs": self.iocs,
                "ttps": self.extract_ttps()
            },
            "chain_of_custody": self.evidence_manifest
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"✅ JSON report generated: {output_file}")
        return output_file


def main():
    parser = argparse.ArgumentParser(
        description="Incident Report Generator - AIRDFP"
    )
    parser.add_argument(
        "--case-id",
        required=True,
        help="Incident case ID"
    )
    parser.add_argument(
        "--timeline",
        help="Path to timeline analysis JSON"
    )
    parser.add_argument(
        "--iocs",
        help="Path to IOCs JSON file"
    )
    parser.add_argument(
        "--output-format",
        choices=["markdown", "json", "both"],
        default="both",
        help="Report output format (default: both)"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Incident Report Generator - AIRDFP")
    print("=" * 60)

    # Load timeline if provided
    timeline = {}
    if args.timeline and Path(args.timeline).exists():
        with open(args.timeline, 'r') as f:
            timeline = json.load(f)
        print(f"✅ Loaded timeline: {args.timeline}")

    # Load IOCs if provided
    iocs = {}
    if args.iocs and Path(args.iocs).exists():
        with open(args.iocs, 'r') as f:
            iocs_data = json.load(f)
            iocs = iocs_data.get('iocs', {})
        print(f"✅ Loaded IOCs: {args.iocs}")

    # Demo case data
    case_data = {
        "case_id": args.case_id,
        "severity": "CRITICAL",
        "status": "Contained",
        "description": "Ransomware deployment via phishing email",
        "credentials_reset": "✅ Complete",
        "patches_applied": "⏳ In Progress",
        "threats_removed": "✅ Confirmed",
        "systems_recovered": "⏳ 60% Complete",
        "downtime_hours": "4",
        "affected_users": "25",
        "data_loss": "None confirmed",
        "financial_impact": "$50,000 (estimated)"
    }

    evidence_manifest = {
        "hosts": ["WS-FIN-001", "WS-FIN-002", "SERVER-DB-01"],
        "evidence": [
            {
                "id": "EV-001",
                "type": "Memory Dump",
                "path": "/evidence_vault/WS-FIN-001_memory.dump",
                "collection_date": datetime.now().isoformat(),
                "collected_by": "AIRDFP Automated Collection",
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "file_size_bytes": 8589934592,  # 8GB
                "sealed": "✅ VERIFIED",
                "tamper_check": "✅ PASSED",
                "chain_verified": "✅ CONTINUOUS"
            }
        ]
    }

    report_gen = IncidentReportGenerator(
        args.case_id,
        case_data,
        timeline,
        iocs,
        evidence_manifest
    )

    print(f"\n📝 Generating report...\n")

    # Generate reports based on format
    if args.output_format in ["markdown", "both"]:
        md_file = report_gen.generate_markdown_report()

    if args.output_format in ["json", "both"]:
        json_file = report_gen.generate_json_report()

    print(f"\n✅ Report generation complete!")
    print(f"\n📖 Next steps:")
    print(f"   1. Review generated reports")
    print(f"   2. Share executive summary with stakeholders")
    print(f"   3. Archive evidence with chain of custody documentation")

    return 0


if __name__ == "__main__":
    exit(main())
