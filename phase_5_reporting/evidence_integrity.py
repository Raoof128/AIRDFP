#!/usr/bin/env python3
"""
Evidence Integrity & Chain of Custody
Cryptographic verification and tamper-evident sealing
"""

import hashlib
import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional
from cryptography.fernet import Fernet


class EvidenceIntegrity:
    """Cryptographic evidence integrity verification"""

    def __init__(self, secret_key: Optional[bytes] = None, evidence_vault: str = "/evidence_vault"):
        if secret_key is None:
            # Generate new key (in production, use key management system)
            secret_key = Fernet.generate_key()

        self.secret_key = secret_key
        self.cipher = Fernet(secret_key)
        self.evidence_vault = Path(evidence_vault)
        self.integrity_log = []

        # Ensure evidence vault exists
        self.evidence_vault.mkdir(parents=True, exist_ok=True)

    def compute_hash(self, file_path: str, algorithm: str = 'sha256') -> str:
        """Compute cryptographic hash of evidence file"""

        print(f"  🔢 Computing {algorithm.upper()} hash...")

        hash_obj = hashlib.new(algorithm)
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        bytes_processed = 0
        file_size = file_path.stat().st_size

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hash_obj.update(chunk)
                bytes_processed += len(chunk)

                # Progress indicator for large files
                if file_size > 100 * 1024 * 1024:  # >100MB
                    progress = (bytes_processed / file_size) * 100
                    print(f"     Progress: {progress:.1f}%", end='\r')

        if file_size > 100 * 1024 * 1024:
            print()  # New line after progress

        hash_value = hash_obj.hexdigest()
        print(f"  ✅ Hash: {hash_value}")

        return hash_value

    def verify_integrity(self, file_path: str, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """Verify evidence hasn't been tampered with"""

        print(f"\n🔍 Verifying integrity: {Path(file_path).name}")

        computed_hash = self.compute_hash(file_path, algorithm)

        if computed_hash == expected_hash:
            print(f"  ✅ Integrity verified")
            return True
        else:
            print(f"  ❌ INTEGRITY FAILURE!")
            print(f"     Expected:  {expected_hash}")
            print(f"     Computed:  {computed_hash}")
            print(f"  ⚠️  EVIDENCE MAY HAVE BEEN TAMPERED WITH")
            return False

    def seal_evidence(self, file_path: str, metadata: Optional[Dict] = None) -> str:
        """
        Create tamper-evident cryptographic seal

        Args:
            file_path: Path to evidence file
            metadata: Optional metadata to include in seal

        Returns:
            Path to seal file
        """

        print(f"\n🔐 Sealing evidence: {Path(file_path).name}")

        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Evidence file not found: {file_path}")

        # Compute multiple hashes for verification
        md5_hash = self.compute_hash(file_path, 'md5')
        sha256_hash = self.compute_hash(file_path, 'sha256')

        seal_data = {
            "file": str(file_path),
            "file_name": file_path.name,
            "file_size_bytes": file_path.stat().st_size,
            "hashes": {
                "md5": md5_hash,
                "sha256": sha256_hash
            },
            "sealed_at": datetime.now().isoformat(),
            "sealed_by": "AIRDFP Evidence Integrity System",
            "metadata": metadata or {}
        }

        # Encrypt seal data
        seal_json = json.dumps(seal_data, indent=2)
        encrypted_seal = self.cipher.encrypt(seal_json.encode())

        # Write seal file
        seal_file = file_path.with_suffix(file_path.suffix + '.seal')
        with open(seal_file, 'wb') as f:
            f.write(encrypted_seal)

        # Log sealing action
        self.integrity_log.append({
            "action": "SEAL",
            "file": str(file_path),
            "timestamp": datetime.now().isoformat(),
            "sha256": sha256_hash
        })

        print(f"  ✅ Evidence sealed: {seal_file.name}")
        print(f"  📊 File size: {self._format_bytes(file_path.stat().st_size)}")

        return str(seal_file)

    def unseal_evidence(self, seal_file: str) -> Optional[Dict]:
        """
        Verify and unseal evidence

        Args:
            seal_file: Path to seal file

        Returns:
            Seal data if verification successful, None otherwise
        """

        print(f"\n🔓 Unsealing evidence: {Path(seal_file).name}")

        seal_file = Path(seal_file)

        if not seal_file.exists():
            print(f"  ❌ Seal file not found: {seal_file}")
            return None

        try:
            # Read and decrypt seal
            with open(seal_file, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = self.cipher.decrypt(encrypted_data)
            seal_data = json.loads(decrypted_data)

            print(f"  ✅ Seal decrypted successfully")
            print(f"  📅 Sealed: {seal_data['sealed_at']}")
            print(f"  👤 Sealed by: {seal_data['sealed_by']}")

            # Verify file integrity
            file_path = seal_data['file']
            expected_sha256 = seal_data['hashes']['sha256']

            if not Path(file_path).exists():
                print(f"  ⚠️  Evidence file not found: {file_path}")
                return seal_data

            verified = self.verify_integrity(file_path, expected_sha256, 'sha256')

            if verified:
                self.integrity_log.append({
                    "action": "UNSEAL_VERIFIED",
                    "file": file_path,
                    "timestamp": datetime.now().isoformat()
                })
                print(f"  ✅ Evidence verified and unsealed")
                return seal_data
            else:
                self.integrity_log.append({
                    "action": "UNSEAL_FAILED",
                    "file": file_path,
                    "timestamp": datetime.now().isoformat(),
                    "reason": "Hash mismatch"
                })
                print(f"  ❌ VERIFICATION FAILED")
                return None

        except Exception as e:
            print(f"  ❌ Unseal failed: {e}")
            self.integrity_log.append({
                "action": "UNSEAL_ERROR",
                "file": str(seal_file),
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return None

    def generate_coc_report(self, output_file: str = "chain_of_custody.json") -> Dict:
        """Generate chain of custody report"""

        print(f"\n📋 Generating chain of custody report...")

        coc_report = {
            "generated_at": datetime.now().isoformat(),
            "generated_by": "AIRDFP Evidence Integrity System",
            "total_operations": len(self.integrity_log),
            "integrity_checks": self.integrity_log,
            "status": self._assess_coc_status()
        }

        # Add summary statistics
        seal_count = sum(1 for log in self.integrity_log if log['action'] == 'SEAL')
        unseal_verified = sum(1 for log in self.integrity_log if log['action'] == 'UNSEAL_VERIFIED')
        unseal_failed = sum(1 for log in self.integrity_log if log['action'] == 'UNSEAL_FAILED')

        coc_report['summary'] = {
            "total_seals": seal_count,
            "successful_verifications": unseal_verified,
            "failed_verifications": unseal_failed,
            "verification_success_rate": (unseal_verified / max(seal_count, 1)) * 100
        }

        with open(output_file, 'w') as f:
            json.dump(coc_report, f, indent=2)

        print(f"  ✅ Report saved: {output_file}")
        print(f"  📊 Total operations: {len(self.integrity_log)}")
        print(f"  📊 Seals created: {seal_count}")
        print(f"  📊 Verifications: {unseal_verified} passed, {unseal_failed} failed")

        return coc_report

    def _assess_coc_status(self) -> str:
        """Assess overall chain of custody status"""

        failed_operations = sum(
            1 for log in self.integrity_log
            if log.get('action') in ['UNSEAL_FAILED', 'UNSEAL_ERROR']
        )

        if failed_operations == 0:
            return "✅ VERIFIED - All integrity checks passed"
        elif failed_operations < 3:
            return "⚠️ PARTIAL - Some integrity checks failed"
        else:
            return "❌ FAILED - Multiple integrity violations detected"

    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human-readable"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"

    def bulk_seal(self, evidence_files: list) -> Dict[str, str]:
        """Seal multiple evidence files"""

        print(f"\n🔐 Bulk sealing {len(evidence_files)} evidence files...\n")

        results = {}

        for i, file_path in enumerate(evidence_files, 1):
            print(f"[{i}/{len(evidence_files)}] Processing: {Path(file_path).name}")

            try:
                seal_file = self.seal_evidence(file_path)
                results[file_path] = seal_file
            except Exception as e:
                print(f"  ❌ Failed: {e}")
                results[file_path] = None

        # Summary
        successful = sum(1 for v in results.values() if v is not None)
        failed = len(results) - successful

        print(f"\n{'='*60}")
        print(f"BULK SEAL SUMMARY")
        print(f"{'='*60}")
        print(f"✅ Successful: {successful}")
        print(f"❌ Failed: {failed}")
        print(f"📊 Total: {len(evidence_files)}")

        return results


def main():
    parser = argparse.ArgumentParser(
        description="Evidence Integrity Verification - AIRDFP"
    )
    parser.add_argument(
        "--seal",
        help="Seal evidence file"
    )
    parser.add_argument(
        "--unseal",
        help="Unseal and verify evidence"
    )
    parser.add_argument(
        "--verify",
        help="Verify evidence integrity"
    )
    parser.add_argument(
        "--expected-hash",
        help="Expected hash for verification"
    )
    parser.add_argument(
        "--generate-coc",
        action="store_true",
        help="Generate chain of custody report"
    )
    parser.add_argument(
        "--key-file",
        help="Path to encryption key file (optional)"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Evidence Integrity Verification - AIRDFP")
    print("=" * 60)

    # Load or generate key
    if args.key_file and Path(args.key_file).exists():
        with open(args.key_file, 'rb') as f:
            secret_key = f.read()
        print(f"✅ Loaded encryption key from {args.key_file}")
    else:
        secret_key = Fernet.generate_key()
        print(f"✅ Generated new encryption key")

        # Save key for future use
        key_file = "evidence_vault_key.bin"
        with open(key_file, 'wb') as f:
            f.write(secret_key)
        print(f"  💾 Key saved to: {key_file}")
        print(f"  ⚠️  IMPORTANT: Protect this key file!")

    integrity = EvidenceIntegrity(secret_key)

    # Execute requested operation
    if args.seal:
        seal_file = integrity.seal_evidence(args.seal)
        print(f"\n✅ Evidence sealed successfully")
        print(f"  📁 Seal file: {seal_file}")

    elif args.unseal:
        seal_data = integrity.unseal_evidence(args.unseal)

        if seal_data:
            print(f"\n✅ Evidence unsealed and verified")
            print(f"\n📋 Seal Information:")
            print(json.dumps(seal_data, indent=2))
        else:
            print(f"\n❌ Unsealing failed or verification failed")
            return 1

    elif args.verify and args.expected_hash:
        verified = integrity.verify_integrity(args.verify, args.expected_hash)

        if verified:
            print(f"\n✅ Integrity verification successful")
            return 0
        else:
            print(f"\n❌ Integrity verification FAILED")
            return 1

    elif args.generate_coc:
        coc_report = integrity.generate_coc_report()
        print(f"\n📄 Chain of custody report generated")

    else:
        parser.print_help()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
