#!/usr/bin/env python3
"""
Unit Tests for AIRDFP Core Functionality
Tests integration points, error handling, and key features
"""

import unittest
import json
import tempfile
from pathlib import Path
from datetime import datetime
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestTheHiveIntegration(unittest.TestCase):
    """Test TheHive setup and integration"""

    def test_case_template_structure(self):
        """Verify case template data structure"""
        from phase_1_foundation.thehive_setup import TheHiveSetup

        # Test with dummy credentials
        setup = TheHiveSetup("http://localhost:9000", "test_key")
        templates = setup.get_case_templates()

        # Should have 4 templates
        self.assertEqual(len(templates), 4)

        # Each template should have required fields
        required_fields = ['title', 'severity', 'description', 'tags', 'tasks']
        for template in templates:
            for field in required_fields:
                self.assertIn(field, template, f"Template missing field: {field}")

            # Tasks should be a list
            self.assertIsInstance(template['tasks'], list)
            self.assertGreater(len(template['tasks']), 0)

    def test_severity_levels(self):
        """Test severity level mapping"""
        from phase_1_foundation.thehive_setup import TheHiveSetup

        setup = TheHiveSetup("http://localhost:9000", "test_key")
        templates = setup.get_case_templates()

        # Verify severity levels are valid (1-4)
        for template in templates:
            severity = template['severity']
            self.assertIn(severity, [1, 2, 3, 4], f"Invalid severity: {severity}")


class TestSIEMIntegration(unittest.TestCase):
    """Test SIEM alert processing"""

    def test_severity_classification(self):
        """Test ML-based severity classification"""
        from phase_1_foundation.siem_integration import SIEMIntegration

        integration = SIEMIntegration(
            "http://localhost:9000",
            "test_key",
            "http://localhost:3000"
        )

        # Test known alert types
        test_cases = [
            ("ransomware_detection", 3),  # Critical
            ("lateral_movement", 2),       # High
            ("account_compromise", 2),     # High
            ("brute_force_attempt", 1)     # Low/Medium
        ]

        for alert_type, expected_level in test_cases:
            result = integration.classify_severity(alert_type)
            self.assertEqual(result['level'], expected_level,
                           f"Wrong severity for {alert_type}")

    def test_alert_description_generation(self):
        """Test alert description formatting"""
        from phase_1_foundation.siem_integration import SIEMIntegration

        integration = SIEMIntegration(
            "http://localhost:9000",
            "test_key",
            None
        )

        alert = {
            "rule_name": "Test Alert",
            "alert_type": "test",
            "source_ip": "192.168.1.100",
            "hostname": "test-host",
            "timestamp": datetime.now().isoformat()
        }

        description = integration._build_description(alert)

        # Should contain key information
        self.assertIn("Test Alert", description)
        self.assertIn("192.168.1.100", description)
        self.assertIn("test-host", description)


class TestPlaybookExecution(unittest.TestCase):
    """Test playbook executor"""

    def test_playbook_loading(self):
        """Test YAML playbook loading"""
        from phase_2_collection.playbook_executor import PlaybookExecutor

        playbook_file = "phase_2_collection/incident_playbooks.yml"
        executor = PlaybookExecutor(playbook_file, dry_run=True)

        # Should load playbooks successfully
        self.assertIn('playbooks', executor.playbooks)
        self.assertGreater(len(executor.playbooks['playbooks']), 0)

    def test_step_execution_dry_run(self):
        """Test playbook step execution in dry-run mode"""
        from phase_2_collection.playbook_executor import PlaybookExecutor

        playbook_file = "phase_2_collection/incident_playbooks.yml"
        executor = PlaybookExecutor(playbook_file, dry_run=True)

        step = {
            "name": "Test Step",
            "action": "test_action"
        }

        result = executor.execute_step(step, {"hostname": "test"})

        # Dry run should always succeed
        self.assertTrue(result['success'])
        self.assertTrue(result['dry_run'])


class TestVolatilityAnalysis(unittest.TestCase):
    """Test Volatility analysis automation"""

    def test_analyze_process_tree(self):
        """Test process tree analysis"""
        from phase_3_forensics.volatility_analysis import VolatilityAnalyzer

        # Create dummy memory dump for testing
        with tempfile.NamedTemporaryFile(delete=False, suffix='.dump') as f:
            f.write(b'\x00' * 1024)  # 1KB dummy file
            dump_path = f.name

        try:
            analyzer = VolatilityAnalyzer(dump_path)
            analyzer.analyses = {
                'process_tree': [
                    {'PID': 1, 'Name': 'init'},
                    {'PID': 2, 'Name': 'powershell.exe', 'Suspicious': True}
                ]
            }

            result = analyzer.analyze_process_tree()

            self.assertEqual(result['total_processes'], 2)
            self.assertEqual(result['suspicious_count'], 1)

        finally:
            Path(dump_path).unlink()

    def test_ioc_generation(self):
        """Test IOC extraction"""
        from phase_3_forensics.volatility_analysis import VolatilityAnalyzer

        with tempfile.NamedTemporaryFile(delete=False, suffix='.dump') as f:
            f.write(b'\x00' * 1024)
            dump_path = f.name

        try:
            analyzer = VolatilityAnalyzer(dump_path)
            analyzer.analyses = {
                'process_tree': [
                    {'Name': 'malware.exe', 'Suspicious': True}
                ],
                'network_connections': [],
                'services': []
            }

            iocs = analyzer.generate_iocs()

            self.assertIn('process_names', iocs)
            self.assertIn('network_ips', iocs)
            self.assertIsInstance(iocs['process_names'], list)

        finally:
            Path(dump_path).unlink()


class TestTimelineAnalysis(unittest.TestCase):
    """Test timeline analysis and correlation"""

    def test_rule_based_anomaly_detection(self):
        """Test rule-based anomaly detection (fallback)"""
        from phase_4_timeline.timeline_analysis import TimelineAnalyzer

        # Create test events
        evidence = [
            {"path": "/tmp/test.json", "type": "log"}
        ]

        analyzer = TimelineAnalyzer(evidence)
        analyzer.timeline_events = [
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'process_execution',
                'severity': 'critical',
                'description': 'Suspicious process'
            },
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'network_connection',
                'severity': 'high',
                'description': 'External connection'
            }
        ]

        # Test rule-based detection
        anomalies = analyzer._detect_anomalies_rules()

        # Should detect both as anomalies
        self.assertGreater(len(anomalies), 0)

    def test_correlation_by_user(self):
        """Test user-based event correlation"""
        from phase_4_timeline.timeline_analysis import TimelineAnalyzer

        evidence = []
        analyzer = TimelineAnalyzer(evidence)
        analyzer.timeline_events = [
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'login',
                'details': {'user': 'testuser'}
            },
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'file_access',
                'details': {'user': 'testuser'}
            },
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'network',
                'details': {'user': 'testuser'}
            },
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'logout',
                'details': {'user': 'testuser'}
            }
        ]

        correlations = analyzer.correlate_artifacts()

        # Should find high activity volume correlation
        self.assertGreater(len(correlations), 0)


class TestReportGeneration(unittest.TestCase):
    """Test automated report generation"""

    def test_ttp_extraction(self):
        """Test MITRE ATT&CK TTP extraction"""
        from phase_5_reporting.report_generator import IncidentReportGenerator

        timeline = {
            'attack_narrative': [
                {'description': 'PowerShell execution detected'},
                {'description': 'Network connection established'},
                {'description': 'Credential dumping attempted'}
            ]
        }

        report_gen = IncidentReportGenerator(
            "TEST-001",
            {"severity": "HIGH"},
            timeline,
            {},
            {}
        )

        ttps = report_gen.extract_ttps()

        # Should extract relevant TTPs
        self.assertIsInstance(ttps, list)
        self.assertGreater(len(ttps), 0)

    def test_json_report_structure(self):
        """Test JSON report structure"""
        from phase_5_reporting.report_generator import IncidentReportGenerator

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "test_report.json"

            report_gen = IncidentReportGenerator(
                "TEST-001",
                {"severity": "HIGH"},
                {},
                {},
                {"evidence": []}
            )

            report_gen.generate_json_report(str(output_file))

            # Verify file was created and is valid JSON
            self.assertTrue(output_file.exists())

            with open(output_file) as f:
                data = json.load(f)

            # Should have required sections
            self.assertIn('metadata', data)
            self.assertIn('executive_summary', data)
            self.assertIn('technical_findings', data)


class TestEvidenceIntegrity(unittest.TestCase):
    """Test evidence integrity verification"""

    def test_hash_computation(self):
        """Test hash computation"""
        from phase_5_reporting.evidence_integrity import EvidenceIntegrity
        from cryptography.fernet import Fernet

        key = Fernet.generate_key()
        integrity = EvidenceIntegrity(key)

        # Create test file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            test_data = b"test evidence data"
            f.write(test_data)
            test_file = f.name

        try:
            # Compute hash
            hash_value = integrity.compute_hash(test_file, 'sha256')

            # Should be valid SHA256 (64 hex characters)
            self.assertEqual(len(hash_value), 64)
            self.assertTrue(all(c in '0123456789abcdef' for c in hash_value))

        finally:
            Path(test_file).unlink()

    def test_seal_and_unseal(self):
        """Test evidence sealing and unsealing"""
        from phase_5_reporting.evidence_integrity import EvidenceIntegrity
        from cryptography.fernet import Fernet

        key = Fernet.generate_key()
        integrity = EvidenceIntegrity(key)

        # Create test file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            test_data = b"test evidence data"
            f.write(test_data)
            test_file = f.name

        try:
            # Seal evidence
            seal_file = integrity.seal_evidence(test_file)

            # Seal file should exist
            self.assertTrue(Path(seal_file).exists())

            # Unseal and verify
            seal_data = integrity.unseal_evidence(seal_file)

            # Should succeed
            self.assertIsNotNone(seal_data)
            self.assertEqual(seal_data['file'], test_file)

        finally:
            Path(test_file).unlink()
            if Path(seal_file).exists():
                Path(seal_file).unlink()


def run_tests():
    """Run all tests"""
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Return exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
