#!/usr/bin/env python3
"""
Timeline Analysis with ML Anomaly Detection
Super timeline creation and attack narrative reconstruction
"""

import json
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import hashlib

# Optional ML dependencies - graceful degradation if not available
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("⚠️ NumPy/scikit-learn not installed. ML anomaly detection will use rule-based fallback.")


class TimelineAnalyzer:
    """Super timeline creation with ML anomaly detection"""

    def __init__(self, evidence_sources: List[Dict[str, str]]):
        self.evidence_sources = evidence_sources
        self.timeline_events = []

        # Initialize ML model if available
        if ML_AVAILABLE:
            self.ml_model = IsolationForest(
                contamination=0.1,  # Expect 10% anomalies
                random_state=42
            )
        else:
            self.ml_model = None

    def generate_super_timeline(self) -> List[Dict]:
        """Create master timeline across all evidence sources"""

        print("🔗 Generating super timeline...\n")

        for source in self.evidence_sources:
            print(f"  Processing: {source['type']} - {Path(source['path']).name}")

            if source['type'] == 'memory':
                events = self._parse_memory_analysis(source['path'])
            elif source['type'] == 'log':
                events = self._parse_logs(source['path'])
            elif source['type'] == 'disk':
                events = self._parse_disk_artifacts(source['path'])
            elif source['type'] == 'forensic_report':
                events = self._parse_forensic_report(source['path'])
            else:
                print(f"    ⚠️ Unknown source type: {source['type']}")
                events = []

            self.timeline_events.extend(events)
            print(f"    Added {len(events)} events")

        # Sort chronologically
        self.timeline_events.sort(key=lambda x: x.get('timestamp', datetime.now().isoformat()))

        print(f"\n✅ Timeline created with {len(self.timeline_events)} events")
        return self.timeline_events

    def _parse_memory_analysis(self, path: str) -> List[Dict]:
        """Parse Volatility analysis output"""
        try:
            with open(path, 'r') as f:
                data = json.load(f)

            events = []

            # Extract process events
            if 'detailed_analysis' in data and 'processes' in data['detailed_analysis']:
                for proc in data['detailed_analysis']['processes'].get('suspicious', []):
                    events.append({
                        'timestamp': datetime.now().isoformat(),  # In production, use actual timestamps
                        'event_type': 'process_execution',
                        'source': 'memory_forensics',
                        'description': f"Suspicious process: {proc.get('Name')}",
                        'details': proc,
                        'severity': 'high'
                    })

            # Extract network events
            if 'detailed_analysis' in data and 'network' in data['detailed_analysis']:
                for conn in data['detailed_analysis']['network'].get('c2_candidates', []):
                    events.append({
                        'timestamp': datetime.now().isoformat(),
                        'event_type': 'network_connection',
                        'source': 'memory_forensics',
                        'description': f"Suspicious connection to {conn.get('ForeignAddr')}",
                        'details': conn,
                        'severity': 'critical'
                    })

            return events

        except Exception as e:
            print(f"    ⚠️ Error parsing memory analysis: {e}")
            return []

    def _parse_logs(self, path: str) -> List[Dict]:
        """Parse log files (EVTX, syslog, etc.)"""
        # Simulate log parsing for demonstration
        events = []

        # In production, use actual log parsing (e.g., python-evtx for Windows Event Logs)
        simulated_events = [
            {
                'timestamp': (datetime.now() - timedelta(hours=2)).isoformat(),
                'event_type': 'authentication',
                'source': 'windows_security_log',
                'description': 'User login from unusual location',
                'details': {'event_id': 4624, 'user': 'admin', 'source_ip': '203.0.113.50'},
                'severity': 'medium'
            },
            {
                'timestamp': (datetime.now() - timedelta(hours=1, minutes=30)).isoformat(),
                'event_type': 'privilege_escalation',
                'source': 'windows_security_log',
                'description': 'Privilege escalation detected',
                'details': {'event_id': 4672, 'user': 'admin'},
                'severity': 'high'
            }
        ]

        return simulated_events

    def _parse_disk_artifacts(self, path: str) -> List[Dict]:
        """Parse disk forensics artifacts (MFT, registry, etc.)"""
        # Simulate disk artifact parsing
        simulated_events = [
            {
                'timestamp': (datetime.now() - timedelta(hours=3)).isoformat(),
                'event_type': 'file_creation',
                'source': 'mft_analysis',
                'description': 'Suspicious file created: malware.exe',
                'details': {'file_path': 'C:\\Temp\\malware.exe', 'size': 524288},
                'severity': 'critical'
            },
            {
                'timestamp': (datetime.now() - timedelta(hours=2, minutes=45)).isoformat(),
                'event_type': 'registry_modification',
                'source': 'registry_analysis',
                'description': 'Persistence mechanism: Run key modified',
                'details': {'key': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'},
                'severity': 'high'
            }
        ]

        return simulated_events

    def _parse_forensic_report(self, path: str) -> List[Dict]:
        """Parse existing forensic reports"""
        try:
            with open(path, 'r') as f:
                data = json.load(f)

            events = []

            # Extract IOCs as timeline events
            if 'iocs' in data:
                for ioc_type, iocs in data['iocs'].items():
                    for ioc in iocs:
                        events.append({
                            'timestamp': data.get('metadata', {}).get('analysis_date', datetime.now().isoformat()),
                            'event_type': 'ioc_detection',
                            'source': 'forensic_report',
                            'description': f"IOC detected: {ioc_type} = {ioc}",
                            'details': {'ioc_type': ioc_type, 'value': ioc},
                            'severity': 'medium'
                        })

            return events

        except Exception as e:
            print(f"    ⚠️ Error parsing forensic report: {e}")
            return []

    def detect_anomalies(self) -> List[Dict]:
        """ML-based anomaly detection in timeline (with rule-based fallback)"""

        if len(self.timeline_events) < 10:
            print("⚠️ Not enough events for analysis (minimum 10 required)")
            return []

        # Use ML if available, otherwise use rule-based detection
        if ML_AVAILABLE and self.ml_model is not None:
            return self._detect_anomalies_ml()
        else:
            return self._detect_anomalies_rules()

    def _detect_anomalies_ml(self) -> List[Dict]:
        """ML-based anomaly detection"""
        print("\n🤖 Running ML anomaly detection...\n")

        # Extract features from timeline events
        features = []
        for event in self.timeline_events:
            feature_vector = self._extract_features(event)
            features.append(feature_vector)

        features_array = np.array(features)

        # Train model and detect anomalies
        try:
            self.ml_model.fit(features_array)
            anomaly_scores = self.ml_model.decision_function(features_array)
            predictions = self.ml_model.predict(features_array)

            anomalous_events = []
            for i, (event, pred, score) in enumerate(zip(self.timeline_events, predictions, anomaly_scores)):
                if pred == -1:  # Anomaly
                    anomalous_events.append({
                        "event": event,
                        "anomaly_score": float(score),
                        "severity": self._score_to_severity(score)
                    })

            print(f"✅ Detected {len(anomalous_events)} anomalies\n")

            # Sort by anomaly score (most anomalous first)
            anomalous_events.sort(key=lambda x: x['anomaly_score'])

            return anomalous_events

        except Exception as e:
            print(f"❌ ML analysis failed: {e}, falling back to rules")
            return self._detect_anomalies_rules()

    def _detect_anomalies_rules(self) -> List[Dict]:
        """Rule-based anomaly detection (fallback when ML not available)"""
        print("\n🔍 Running rule-based anomaly detection...\n")

        anomalous_events = []

        for event in self.timeline_events:
            score = 0.0
            reasons = []

            # Rule 1: Critical severity events are always anomalous
            if event.get('severity') == 'critical':
                score -= 1.5
                reasons.append("Critical severity")

            # Rule 2: High severity events
            if event.get('severity') == 'high':
                score -= 1.0
                reasons.append("High severity")

            # Rule 3: Network connections to external IPs
            if event.get('event_type') == 'network_connection':
                score -= 0.8
                reasons.append("External network connection")

            # Rule 4: Process execution events
            if event.get('event_type') == 'process_execution':
                score -= 0.6
                reasons.append("Process execution")

            # Rule 5: File creation/modification
            if event.get('event_type') in ['file_creation', 'file_modification']:
                score -= 0.4
                reasons.append("File system change")

            # If score indicates anomaly, add to list
            if score < -0.5:  # Threshold
                anomalous_events.append({
                    "event": event,
                    "anomaly_score": score,
                    "severity": self._score_to_severity(score),
                    "detection_method": "rule-based",
                    "reasons": reasons
                })

        print(f"✅ Detected {len(anomalous_events)} anomalies\n")

        # Sort by anomaly score
        anomalous_events.sort(key=lambda x: x['anomaly_score'])

        return anomalous_events

    def _extract_features(self, event: Dict) -> List[float]:
        """Extract numerical features from event for ML"""

        # Convert event attributes to numerical features
        features = [
            # Event type encoding (hash-based)
            hash(event.get('event_type', 'unknown')) % 1000 / 1000,

            # Severity encoding
            {'low': 0.25, 'medium': 0.5, 'high': 0.75, 'critical': 1.0}.get(
                event.get('severity', 'medium'), 0.5
            ),

            # Source encoding
            hash(event.get('source', 'unknown')) % 1000 / 1000,

            # Description length (normalized)
            len(event.get('description', '')) / 200,

            # Has details flag
            1.0 if event.get('details') else 0.0
        ]

        return features

    def _score_to_severity(self, score: float) -> str:
        """Convert anomaly score to severity"""
        if score < -1.0:
            return "CRITICAL"
        elif score < -0.5:
            return "HIGH"
        elif score < 0:
            return "MEDIUM"
        else:
            return "LOW"

    def correlate_artifacts(self) -> List[Dict]:
        """Link related events across systems"""

        print("🔀 Correlating artifacts...\n")

        correlations = []

        # Group by user
        user_events = {}
        for event in self.timeline_events:
            details = event.get('details', {})
            user = details.get('user', 'unknown')

            if user not in user_events:
                user_events[user] = []
            user_events[user].append(event)

        # Find suspicious user activity patterns
        for user, events in user_events.items():
            if user != 'unknown' and len(events) > 3:  # Unusual activity volume
                correlations.append({
                    "type": "HIGH_ACTIVITY_VOLUME",
                    "user": user,
                    "event_count": len(events),
                    "severity": "HIGH" if len(events) > 10 else "MEDIUM",
                    "events": events[:5]  # First 5
                })

        # Correlate network and file events (potential exfiltration)
        network_events = [e for e in self.timeline_events if e['event_type'] == 'network_connection']
        file_events = [e for e in self.timeline_events if e['event_type'] == 'file_creation']

        if network_events and file_events:
            correlations.append({
                "type": "POTENTIAL_EXFILTRATION",
                "description": "File creation followed by network activity",
                "severity": "HIGH",
                "file_events": len(file_events),
                "network_events": len(network_events)
            })

        print(f"✅ Found {len(correlations)} correlations\n")
        return correlations

    def reconstruct_attack_narrative(
        self,
        anomalies: List[Dict],
        correlations: List[Dict]
    ) -> List[Dict]:
        """Build chronological incident narrative"""

        print(f"{'='*60}")
        print("📖 ATTACK NARRATIVE RECONSTRUCTION")
        print(f"{'='*60}\n")

        narrative_events = []

        # Add anomalies
        for anomaly in anomalies[:10]:  # Top 10
            narrative_events.append({
                "timestamp": anomaly['event']['timestamp'],
                "type": "ANOMALY",
                "severity": anomaly['severity'],
                "description": anomaly['event']['description'],
                "details": anomaly['event']
            })

        # Add correlations
        for correlation in correlations[:5]:  # Top 5
            # Use first event timestamp if available
            if correlation.get('events'):
                timestamp = correlation['events'][0].get('timestamp', datetime.now().isoformat())
            else:
                timestamp = datetime.now().isoformat()

            narrative_events.append({
                "timestamp": timestamp,
                "type": "CORRELATION",
                "severity": correlation.get('severity', 'MEDIUM'),
                "description": correlation['type'],
                "details": correlation
            })

        # Sort chronologically
        narrative_events.sort(key=lambda x: x['timestamp'])

        # Print narrative
        for i, event in enumerate(narrative_events, 1):
            print(f"{i}. [{event['timestamp']}] {event['type']} - {event['severity']}")
            print(f"   {event['description']}")
            print()

        print(f"{'='*60}\n")

        return narrative_events

    def export_timeline(self, output_file: str = "master_timeline.json") -> Dict:
        """Export timeline for SIEM/reporting"""

        anomalies = self.detect_anomalies()
        correlations = self.correlate_artifacts()
        narrative = self.reconstruct_attack_narrative(anomalies, correlations)

        output = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_events": len(self.timeline_events),
                "sources": len(self.evidence_sources),
                "anomalies_detected": len(anomalies),
                "correlations_found": len(correlations)
            },
            "timeline_events": self.timeline_events,
            "anomalies": anomalies,
            "correlations": correlations,
            "attack_narrative": narrative
        }

        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)

        print(f"📄 Timeline exported: {output_file}")
        return output


def main():
    parser = argparse.ArgumentParser(
        description="Timeline Analysis with ML - AIRDFP"
    )
    parser.add_argument(
        "--memory-report",
        help="Path to Volatility analysis JSON report"
    )
    parser.add_argument(
        "--log-file",
        help="Path to log file"
    )
    parser.add_argument(
        "--disk-artifacts",
        help="Path to disk forensics artifacts"
    )
    parser.add_argument(
        "--output",
        default="master_timeline.json",
        help="Output timeline file (default: master_timeline.json)"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Timeline Analysis with ML Anomaly Detection - AIRDFP")
    print("=" * 60)

    # Build evidence sources list
    evidence_sources = []

    if args.memory_report:
        evidence_sources.append({"path": args.memory_report, "type": "forensic_report"})

    if args.log_file:
        evidence_sources.append({"path": args.log_file, "type": "log"})

    if args.disk_artifacts:
        evidence_sources.append({"path": args.disk_artifacts, "type": "disk"})

    if not evidence_sources:
        print("\n⚠️ No evidence sources provided. Using demo mode.\n")
        # Demo mode with simulated data
        evidence_sources = [
            {"path": "/tmp/demo_memory.json", "type": "log"},
            {"path": "/tmp/demo_disk.json", "type": "disk"}
        ]

    analyzer = TimelineAnalyzer(evidence_sources)

    # Generate timeline
    timeline = analyzer.generate_super_timeline()

    # Export
    output = analyzer.export_timeline(args.output)

    print(f"\n✅ Timeline analysis complete!")
    print(f"\n📊 Summary:")
    print(f"   Total events: {output['metadata']['total_events']}")
    print(f"   Anomalies detected: {output['metadata']['anomalies_detected']}")
    print(f"   Correlations found: {output['metadata']['correlations_found']}")
    print(f"\n📖 Next steps:")
    print(f"   1. Review timeline: {args.output}")
    print(f"   2. Generate report: python phase_5_reporting/report_generator.py --timeline {args.output}")

    return 0


if __name__ == "__main__":
    exit(main())
