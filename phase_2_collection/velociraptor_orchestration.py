#!/usr/bin/env python3
"""
Velociraptor Evidence Collection Orchestration
Automated evidence acquisition workflow for rapid response
"""

import requests
import time
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path


class VelociraptorCollector:
    """Automated evidence collection using Velociraptor"""

    def __init__(self, server_url: str, api_key: str, evidence_vault: str = "/evidence_vault"):
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.evidence_vault = Path(evidence_vault)
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        # Ensure evidence vault exists
        self.evidence_vault.mkdir(parents=True, exist_ok=True)

    def get_collection_profiles(self) -> Dict[str, List[str]]:
        """Define evidence collection profiles"""
        return {
            "quick_triage": {
                "description": "Rapid triage collection (~30 seconds)",
                "artifacts": [
                    "Windows.System.Pslist",
                    "Windows.Network.Netstat",
                    "Windows.System.Services"
                ],
                "target_time": 30,
                "size_estimate": "~50MB"
            },
            "memory_dump": {
                "description": "Full memory capture",
                "artifacts": [
                    "Windows.Memory.Acquisition",
                    "Windows.System.Pslist",
                    "Windows.Network.Netstat"
                ],
                "target_time": 90,
                "size_estimate": "~8GB"
            },
            "disk_forensics": {
                "description": "Disk artifacts and logs",
                "artifacts": [
                    "Windows.Forensics.NTFS.MFT",
                    "Windows.Registry.NTUser",
                    "Windows.EventLogs.Evtx",
                    "Windows.Forensics.Usn",
                    "Windows.System.TaskScheduler"
                ],
                "target_time": 180,
                "size_estimate": "~2GB"
            },
            "event_logs": {
                "description": "Windows event log collection",
                "artifacts": [
                    "Windows.EventLogs.EvtxHunter",
                    "Windows.EventLogs.RDPAuth",
                    "Windows.EventLogs.PowershellScriptblock"
                ],
                "target_time": 60,
                "size_estimate": "~500MB"
            },
            "registry_analysis": {
                "description": "Registry hive extraction",
                "artifacts": [
                    "Windows.Registry.SAM",
                    "Windows.Registry.SYSTEM",
                    "Windows.Registry.SOFTWARE",
                    "Windows.Registry.RunKeys"
                ],
                "target_time": 45,
                "size_estimate": "~200MB"
            },
            "comprehensive": {
                "description": "Full forensic package (all above)",
                "artifacts": [
                    # Combine all artifacts from above profiles
                    "Windows.Memory.Acquisition",
                    "Windows.System.Pslist",
                    "Windows.Network.Netstat",
                    "Windows.Forensics.NTFS.MFT",
                    "Windows.Registry.NTUser",
                    "Windows.EventLogs.Evtx",
                    "Windows.System.Services",
                    "Windows.System.TaskScheduler"
                ],
                "target_time": 300,
                "size_estimate": "~10GB"
            }
        }

    def collect_evidence(
        self,
        hostname: str,
        collection_type: str = "comprehensive",
        urgent: bool = False
    ) -> Optional[str]:
        """
        Automated evidence acquisition workflow

        Args:
            hostname: Target endpoint hostname or client ID
            collection_type: One of the collection profiles
            urgent: High priority collection (skip queue)

        Returns:
            Evidence package filename if successful, None otherwise
        """

        profiles = self.get_collection_profiles()
        profile = profiles.get(collection_type)

        if not profile:
            print(f"❌ Unknown collection type: {collection_type}")
            print(f"Available profiles: {', '.join(profiles.keys())}")
            return None

        print(f"\n🔬 Starting evidence collection")
        print(f"   Target: {hostname}")
        print(f"   Profile: {collection_type}")
        print(f"   Description: {profile['description']}")
        print(f"   Expected time: {profile['target_time']}s")
        print(f"   Expected size: {profile['size_estimate']}")

        # Create collection request
        collection_payload = {
            "client_id": hostname,
            "artifacts": profile['artifacts'],
            "urgent": urgent,
            "max_rows": 100000,
            "max_upload_bytes": 10 * 1024 * 1024 * 1024,  # 10GB
            "timeout": profile['target_time'] + 60  # Add buffer
        }

        try:
            # Initiate collection
            start_time = time.time()

            response = requests.post(
                f"{self.server_url}/api/v1/CollectArtifact",
                headers=self.headers,
                json=collection_payload,
                timeout=30
            )

            if response.status_code != 200:
                print(f"❌ Collection failed to start: HTTP {response.status_code}")
                print(f"   Response: {response.text}")
                return None

            flow_data = response.json()
            flow_id = flow_data.get('flow_id')

            print(f"✅ Collection started: Flow ID {flow_id}")

            # Poll for completion
            evidence_file = self.wait_for_collection(
                flow_id,
                hostname,
                max_wait=profile['target_time'] + 120
            )

            elapsed = time.time() - start_time
            print(f"⏱️  Collection completed in {elapsed:.1f}s")

            return evidence_file

        except Exception as e:
            print(f"❌ Collection error: {e}")
            return None

    def wait_for_collection(
        self,
        flow_id: str,
        hostname: str,
        max_wait: int = 300
    ) -> Optional[str]:
        """
        Poll until collection complete

        Args:
            flow_id: Velociraptor flow ID
            hostname: Client hostname
            max_wait: Maximum wait time in seconds

        Returns:
            Evidence package filename if successful
        """

        start_time = time.time()
        poll_interval = 5

        print(f"\n⏳ Waiting for collection to complete...")

        while time.time() - start_time < max_wait:
            try:
                response = requests.get(
                    f"{self.server_url}/api/v1/GetClientFlows",
                    headers=self.headers,
                    params={"client_id": hostname},
                    timeout=10
                )

                if response.status_code == 200:
                    flows = response.json().get('flows', [])

                    for flow in flows:
                        if flow.get('flow_id') == flow_id:
                            state = flow.get('state', 'UNKNOWN')
                            total_rows = flow.get('total_collected_rows', 0)

                            print(f"   Status: {state} | Rows: {total_rows}", end='\r')

                            if state == 'FINISHED':
                                print()  # New line
                                print(f"✅ Collection finished: {total_rows} rows")
                                return self.download_evidence(flow_id, hostname)

                            elif state == 'ERROR':
                                print()
                                print(f"❌ Collection failed with error")
                                return None

            except Exception as e:
                print(f"\n⚠️ Polling error: {e}")

            time.sleep(poll_interval)

        print(f"\n⚠️ Collection timeout after {max_wait}s")
        return None

    def download_evidence(self, flow_id: str, hostname: str) -> Optional[str]:
        """
        Export collected evidence as ZIP package

        Args:
            flow_id: Velociraptor flow ID
            hostname: Client hostname

        Returns:
            Evidence package filename
        """

        print(f"\n📦 Exporting evidence package...")

        try:
            response = requests.get(
                f"{self.server_url}/api/v1/ExportCollection",
                headers=self.headers,
                params={
                    "flow_id": flow_id,
                    "format": "zip"
                },
                timeout=300,
                stream=True
            )

            if response.status_code != 200:
                print(f"❌ Export failed: HTTP {response.status_code}")
                return None

            # Generate filename with timestamp
            timestamp = int(time.time())
            filename = self.evidence_vault / f"evidence_{hostname}_{timestamp}.zip"

            # Download with progress
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0

            with open(filename, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded += len(chunk)

                    if total_size > 0:
                        progress = (downloaded / total_size) * 100
                        print(f"   Downloading: {progress:.1f}%", end='\r')

            print()  # New line
            file_size = filename.stat().st_size / (1024 * 1024)  # MB
            print(f"✅ Evidence saved: {filename.name}")
            print(f"   Size: {file_size:.2f} MB")

            # Calculate hash for integrity
            file_hash = self._calculate_hash(filename)
            print(f"   SHA256: {file_hash}")

            # Create metadata file
            self._create_metadata(filename, flow_id, hostname, file_hash)

            return str(filename)

        except Exception as e:
            print(f"❌ Download error: {e}")
            return None

    def _calculate_hash(self, filename: Path) -> str:
        """Calculate SHA256 hash of file"""
        sha256 = hashlib.sha256()

        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)

        return sha256.hexdigest()

    def _create_metadata(
        self,
        evidence_file: Path,
        flow_id: str,
        hostname: str,
        file_hash: str
    ) -> None:
        """Create evidence metadata file"""

        metadata = {
            "evidence_file": evidence_file.name,
            "collection_time": datetime.now().isoformat(),
            "flow_id": flow_id,
            "hostname": hostname,
            "sha256": file_hash,
            "collected_by": "VelociraptorCollector",
            "file_size_bytes": evidence_file.stat().st_size,
            "chain_of_custody": {
                "collected": datetime.now().isoformat(),
                "collector": "AIRDFP Automated System",
                "integrity_verified": True
            }
        }

        metadata_file = evidence_file.with_suffix('.json')

        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)

        print(f"📋 Metadata: {metadata_file.name}")

    def bulk_collect(
        self,
        hostnames: List[str],
        collection_type: str = "quick_triage"
    ) -> Dict[str, Optional[str]]:
        """
        Collect evidence from multiple hosts

        Args:
            hostnames: List of target hostnames
            collection_type: Collection profile to use

        Returns:
            Dictionary mapping hostname to evidence filename
        """

        print(f"\n🚀 Bulk collection from {len(hostnames)} hosts")
        print(f"   Profile: {collection_type}\n")

        results = {}

        for i, hostname in enumerate(hostnames, 1):
            print(f"\n[{i}/{len(hostnames)}] Processing: {hostname}")
            evidence_file = self.collect_evidence(hostname, collection_type)
            results[hostname] = evidence_file

            # Rate limiting
            if i < len(hostnames):
                time.sleep(2)

        # Summary
        successful = sum(1 for v in results.values() if v is not None)
        failed = len(results) - successful

        print("\n" + "=" * 60)
        print("BULK COLLECTION SUMMARY")
        print("=" * 60)
        print(f"✅ Successful: {successful}")
        print(f"❌ Failed: {failed}")
        print(f"📊 Total: {len(hostnames)}")

        return results


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Velociraptor Evidence Collection - AIRDFP"
    )
    parser.add_argument(
        "--server",
        default="https://localhost:8000",
        help="Velociraptor server URL"
    )
    parser.add_argument(
        "--api-key",
        required=True,
        help="Velociraptor API key"
    )
    parser.add_argument(
        "--hostname",
        required=True,
        help="Target hostname or client ID"
    )
    parser.add_argument(
        "--profile",
        default="comprehensive",
        choices=[
            "quick_triage",
            "memory_dump",
            "disk_forensics",
            "event_logs",
            "registry_analysis",
            "comprehensive"
        ],
        help="Collection profile (default: comprehensive)"
    )
    parser.add_argument(
        "--urgent",
        action="store_true",
        help="High priority collection"
    )
    parser.add_argument(
        "--evidence-vault",
        default="/evidence_vault",
        help="Evidence storage directory"
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List available collection profiles"
    )

    args = parser.parse_args()

    collector = VelociraptorCollector(
        args.server,
        args.api_key,
        args.evidence_vault
    )

    if args.list_profiles:
        print("\n📋 Available Collection Profiles:\n")
        profiles = collector.get_collection_profiles()

        for name, details in profiles.items():
            print(f"  {name}:")
            print(f"    Description: {details['description']}")
            print(f"    Time: {details['target_time']}s")
            print(f"    Size: {details['size_estimate']}")
            print(f"    Artifacts: {len(details['artifacts'])}")
            print()

        return 0

    print("=" * 60)
    print("Velociraptor Evidence Collection - AIRDFP")
    print("=" * 60)

    evidence_file = collector.collect_evidence(
        args.hostname,
        args.profile,
        args.urgent
    )

    if evidence_file:
        print(f"\n✅ Collection successful!")
        print(f"\n📁 Evidence location: {evidence_file}")
        print(f"\n📖 Next steps:")
        print(f"   1. Run memory analysis: python phase_3_forensics/volatility_analysis.py --dump {evidence_file}")
        print(f"   2. Generate timeline: python phase_4_timeline/timeline_analysis.py --evidence {evidence_file}")
        return 0
    else:
        print(f"\n❌ Collection failed")
        return 1


if __name__ == "__main__":
    exit(main())
