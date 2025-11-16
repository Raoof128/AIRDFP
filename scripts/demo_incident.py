#!/usr/bin/env python3
"""
AIRDFP Demo Incident Script

Demonstrates the complete AIRDFP workflow with a simulated ransomware incident:
1. SIEM alert ingestion
2. Case creation
3. Evidence collection simulation
4. Memory forensics analysis
5. Timeline generation
6. Automated report creation

This is a demonstration script that simulates the workflow without requiring
actual endpoints or evidence files.
"""

import json
import time
from datetime import datetime
from typing import Dict, List

# Terminal colors
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_header():
    """Print demo header"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}")
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║                                                               ║")
    print("║              AIRDFP Demo - Ransomware Incident                ║")
    print("║                                                               ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print(f"{Colors.END}\n")


def print_step(step_num: int, total_steps: int, description: str):
    """Print step header"""
    print(f"\n{Colors.BOLD}[Step {step_num}/{total_steps}] {description}{Colors.END}")
    print("─" * 65)


def print_success(message: str):
    """Print success message"""
    print(f"{Colors.GREEN}✓{Colors.END} {message}")


def print_info(message: str):
    """Print info message"""
    print(f"  {message}")


def print_warning(message: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠{Colors.END} {message}")


def simulate_delay(seconds: float = 1.0):
    """Simulate processing time"""
    time.sleep(seconds)


def step_1_siem_alert():
    """Simulate SIEM alert ingestion"""
    print_step(1, 7, "SIEM Alert Ingestion")

    alert = {
        "rule_name": "Ransomware Encryption Activity Detected",
        "alert_type": "ransomware_active",
        "severity": "CRITICAL",
        "hostname": "WS-FINANCE-001",
        "user": "jsmith",
        "source_ip": "192.168.1.105",
        "timestamp": datetime.now().isoformat(),
        "indicators": {
            "suspicious_process": "cryptolocker.exe",
            "mass_file_encryption": True,
            "shadow_copy_deletion": True,
            "ransom_note_detected": True
        }
    }

    print_info("Receiving alert from SIEM...")
    simulate_delay(0.5)
    print_success("Alert received and validated")

    print_info(f"Rule: {alert['rule_name']}")
    print_info(f"Severity: {alert['severity']}")
    print_info(f"Affected Host: {alert['hostname']}")
    print_info(f"User: {alert['user']}")

    # ML Classification
    simulate_delay(0.3)
    print_info("Running ML severity classification...")
    print_success("Classification: CRITICAL (Confidence: 97.3%)")
    print_success("Template selected: RANSOMWARE_ACTIVE")

    return alert


def step_2_case_creation(alert: Dict):
    """Simulate case creation in TheHive"""
    print_step(2, 7, "Automated Case Creation")

    print_info("Creating case in TheHive...")
    simulate_delay(0.5)

    case = {
        "id": "CASE-2024-001",
        "title": f"[CRITICAL] {alert['rule_name']}",
        "severity": 3,
        "status": "Open",
        "hostname": alert['hostname'],
        "created_at": datetime.now().isoformat()
    }

    print_success(f"Case created: {case['id']}")
    print_info(f"Title: {case['title']}")
    print_info(f"Status: {case['status']}")

    # Trigger playbook
    simulate_delay(0.3)
    print_info("Triggering incident response playbook...")
    print_success("Playbook: RANSOMWARE_ACTIVE initiated")

    return case


def step_3_evidence_collection(hostname: str):
    """Simulate evidence collection"""
    print_step(3, 7, "Automated Evidence Collection")

    print_info(f"Initiating collection on {hostname}...")
    simulate_delay(0.5)

    collection_profile = "comprehensive"
    artifacts = [
        "Memory dump (8 GB)",
        "MFT and NTFS artifacts",
        "Windows Event Logs",
        "Registry hives",
        "Prefetch files",
        "Recent file activity"
    ]

    print_success(f"Collection profile: {collection_profile}")
    print_info("Collecting artifacts:")

    for artifact in artifacts:
        simulate_delay(0.3)
        print_success(f"  • {artifact}")

    simulate_delay(0.5)
    print_success("Evidence collection completed in 4m 32s")
    print_info("Evidence package: evidence_WS-FINANCE-001_1699956285.zip")
    print_info("Package size: 10.3 GB")
    print_success("Evidence cryptographically sealed (SHA256)")

    return "evidence_WS-FINANCE-001_1699956285.zip"


def step_4_memory_forensics(evidence_file: str):
    """Simulate memory forensics analysis"""
    print_step(4, 7, "Memory Forensics Analysis")

    print_info("Extracting memory dump from evidence package...")
    simulate_delay(0.5)
    print_success("Memory dump extracted: memory.dump (8 GB)")

    print_info("Running Volatility 3 analysis...")

    plugins = [
        ("windows.info", "OS information"),
        ("windows.pslist", "Process enumeration"),
        ("windows.pstree", "Process tree"),
        ("windows.netscan", "Network connections"),
        ("windows.malfind", "Code injection detection"),
        ("windows.cmdline", "Command line arguments")
    ]

    for plugin, description in plugins:
        simulate_delay(0.4)
        print_success(f"  • {plugin}: {description}")

    simulate_delay(0.5)
    print_success("Memory analysis completed in 3m 47s")

    # Display findings
    print_info("\nKey Findings:")
    findings = {
        "Total processes": 87,
        "Suspicious processes": 3,
        "Network connections": 45,
        "C2 candidates": 2,
        "Code injections detected": 2
    }

    for key, value in findings.items():
        if isinstance(value, int) and value > 0 and key != "Total processes":
            print_warning(f"  • {key}: {value}")
        else:
            print_info(f"  • {key}: {value}")

    # IOCs
    print_info("\nExtracted IOCs:")
    iocs = {
        "Malicious processes": ["cryptolocker.exe", "vssadmin.exe"],
        "C2 IP addresses": ["203.0.113.50", "198.51.100.25"],
        "Malicious DLLs": ["inject.dll", "crypto.dll"]
    }

    for category, items in iocs.items():
        print_info(f"  • {category}:")
        for item in items:
            print_warning(f"    - {item}")

    return findings, iocs


def step_5_timeline_analysis():
    """Simulate timeline analysis"""
    print_step(5, 7, "Timeline Analysis & Correlation")

    print_info("Generating super timeline from evidence sources...")
    simulate_delay(0.5)

    sources = [
        "Memory analysis artifacts",
        "Windows Event Logs",
        "MFT timeline",
        "Registry modifications",
        "Prefetch execution history"
    ]

    for source in sources:
        simulate_delay(0.3)
        print_success(f"  • Parsed: {source}")

    simulate_delay(0.5)
    print_success("Timeline generated: 12,473 events")

    print_info("Running ML anomaly detection...")
    simulate_delay(0.7)
    print_success("Anomaly detection completed (Isolation Forest)")
    print_info("  • Anomalies detected: 23")
    print_info("  • High-severity: 8")
    print_info("  • Correlations found: 5")

    # Attack narrative
    print_info("\nReconstructed Attack Timeline:")
    timeline_events = [
        ("2024-11-15 09:15:32", "INITIAL ACCESS", "User opened phishing email attachment"),
        ("2024-11-15 09:16:45", "EXECUTION", "Malicious payload executed (cryptolocker.exe)"),
        ("2024-11-15 09:17:12", "PERSISTENCE", "Registry Run key created"),
        ("2024-11-15 09:18:30", "PRIVILEGE ESCALATION", "UAC bypass attempted"),
        ("2024-11-15 09:20:15", "DEFENSE EVASION", "Shadow copies deleted (vssadmin.exe)"),
        ("2024-11-15 09:22:00", "C2 COMMUNICATION", "Outbound connection to 203.0.113.50"),
        ("2024-11-15 09:25:00", "IMPACT", "Mass file encryption initiated"),
    ]

    for timestamp, tactic, description in timeline_events:
        simulate_delay(0.2)
        print_warning(f"  [{timestamp}] {tactic}: {description}")

    # MITRE ATT&CK mapping
    print_info("\nMITRE ATT&CK Mapping:")
    ttps = [
        "T1566.001 - Phishing: Spearphishing Attachment",
        "T1204.002 - User Execution: Malicious File",
        "T1547.001 - Registry Run Keys / Startup Folder",
        "T1490 - Inhibit System Recovery",
        "T1486 - Data Encrypted for Impact"
    ]

    for ttp in ttps:
        simulate_delay(0.2)
        print_info(f"  • {ttp}")


def step_6_report_generation(case: Dict, iocs: Dict):
    """Simulate report generation"""
    print_step(6, 7, "Automated Report Generation")

    print_info("Generating incident report...")
    simulate_delay(0.5)

    sections = [
        "Executive Summary",
        "Incident Overview",
        "Technical Analysis",
        "Attack Timeline",
        "IOC List",
        "Evidence Inventory",
        "Chain of Custody",
        "Recommendations",
        "MITRE ATT&CK Mapping"
    ]

    for section in sections:
        simulate_delay(0.2)
        print_success(f"  • Generated: {section}")

    simulate_delay(0.5)
    report_file = f"IR_Report_{case['id']}_ransomware.md"
    print_success(f"Report generated: {report_file}")
    print_info("Format: Markdown")
    print_info("Length: 2,847 words")

    # Chain of custody
    print_info("\nChain of Custody Verification:")
    simulate_delay(0.3)
    print_success("  • Evidence integrity: VERIFIED")
    print_success("  • Cryptographic seal: INTACT")
    print_success("  • Access log: COMPLETE")
    print_info("  • Court-admissible: YES")


def step_7_summary():
    """Print demo summary"""
    print_step(7, 7, "Incident Response Summary")

    metrics = {
        "Total response time": "12 minutes 34 seconds",
        "Evidence collection": "4m 32s",
        "Memory analysis": "3m 47s",
        "Timeline generation": "2m 15s",
        "Report generation": "48s",
        "Traditional MTTR": "3-5 days",
        "AIRDFP MTTR": "12 minutes",
        "Improvement": "99.6%"
    }

    for key, value in metrics.items():
        if "AIRDFP" in key or "Improvement" in key:
            print_success(f"{key}: {Colors.BOLD}{value}{Colors.END}")
        else:
            print_info(f"{key}: {value}")

    print_info("\nKey Achievements:")
    achievements = [
        "✓ Automated evidence collection from compromised endpoint",
        "✓ Comprehensive memory forensics with IOC extraction",
        "✓ Attack timeline reconstruction with ML anomaly detection",
        "✓ MITRE ATT&CK TTP mapping",
        "✓ Court-admissible evidence chain of custody",
        "✓ Executive and technical reporting",
        "✓ 99.6% reduction in mean time to remediation"
    ]

    for achievement in achievements:
        simulate_delay(0.1)
        print_success(achievement)


def print_footer():
    """Print demo footer"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}")
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║                                                               ║")
    print("║                   Demo Completed Successfully                 ║")
    print("║                                                               ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print(f"{Colors.END}\n")

    print(f"{Colors.BOLD}This demonstration showcased:{Colors.END}")
    print("  • End-to-end automated incident response")
    print("  • Integration of multiple forensic tools")
    print("  • ML-powered analysis and detection")
    print("  • Compliance-ready documentation")
    print("")

    print(f"{Colors.BOLD}For a real deployment:{Colors.END}")
    print("  1. Configure SIEM integration (docs/DEPLOYMENT.md)")
    print("  2. Deploy Velociraptor agents to endpoints")
    print("  3. Customize playbooks for your environment")
    print("  4. Set up proper authentication and SSL/TLS")
    print("")

    print(f"{Colors.BOLD}Learn more:{Colors.END}")
    print("  • Architecture: docs/ARCHITECTURE.md")
    print("  • API docs: docs/API_DOCUMENTATION.md")
    print("  • FAQ: docs/FAQ.md")
    print("")


def main():
    """Run the complete demo"""
    try:
        print_header()

        # Execute demo steps
        alert = step_1_siem_alert()
        case = step_2_case_creation(alert)
        evidence_file = step_3_evidence_collection(alert['hostname'])
        findings, iocs = step_4_memory_forensics(evidence_file)
        step_5_timeline_analysis()
        step_6_report_generation(case, iocs)
        step_7_summary()

        print_footer()

    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Demo interrupted by user{Colors.END}")
        return 1
    except Exception as e:
        print(f"\n\n{Colors.RED}Error running demo: {e}{Colors.END}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
