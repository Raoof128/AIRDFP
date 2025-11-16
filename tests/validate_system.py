#!/usr/bin/env python3
"""
System Validation and Health Check Script
Validates AIRDFP installation and configuration
"""

import sys
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Tuple
import importlib.util


class AIRDFPValidator:
    """Comprehensive system validation"""

    def __init__(self):
        self.results = {
            "passed": [],
            "failed": [],
            "warnings": []
        }
        self.base_path = Path("/home/user/AIRDFP")

    def check_python_version(self) -> bool:
        """Verify Python version >= 3.8"""
        version = sys.version_info
        if version.major >= 3 and version.minor >= 8:
            self.results["passed"].append(f"✅ Python version: {version.major}.{version.minor}.{version.micro}")
            return True
        else:
            self.results["failed"].append(f"❌ Python version {version.major}.{version.minor} < 3.8")
            return False

    def check_required_packages(self) -> bool:
        """Check if required Python packages are importable"""
        required_packages = {
            "requests": "HTTP client",
            "yaml": "YAML parser (PyYAML)",
            "cryptography": "Cryptographic operations",
            "json": "JSON parsing (built-in)",
            "argparse": "Argument parsing (built-in)",
            "pathlib": "Path operations (built-in)",
            "hashlib": "Hashing (built-in)",
            "datetime": "Date/time (built-in)"
        }

        optional_packages = {
            "numpy": "Numerical computing (optional - for ML features)",
            "sklearn": "Machine learning (optional - for ML anomaly detection)"
        }

        all_ok = True

        # Check required packages
        for package, description in required_packages.items():
            try:
                # Handle special case for yaml (package is PyYAML, import is yaml)
                if package == "yaml":
                    import yaml
                else:
                    __import__(package)
                self.results["passed"].append(f"✅ Package '{package}': {description}")
            except ImportError:
                self.results["failed"].append(f"❌ Package '{package}' not found: {description}")
                all_ok = False

        # Check optional packages (warnings only)
        for package, description in optional_packages.items():
            try:
                if package == "sklearn":
                    import sklearn
                else:
                    __import__(package)
                self.results["passed"].append(f"✅ Package '{package}': {description}")
            except ImportError:
                self.results["warnings"].append(f"⚠️ Package '{package}' not found: {description} - Will use fallback")

        return all_ok

    def check_file_structure(self) -> bool:
        """Verify all required files exist"""
        required_files = [
            "README.md",
            "ARCHITECTURE.md",
            "DEPLOYMENT.md",
            "LICENSE",
            "requirements.txt",
            ".gitignore",
            "phase_1_foundation/docker-compose.yml",
            "phase_1_foundation/thehive_setup.py",
            "phase_1_foundation/siem_integration.py",
            "phase_2_collection/velociraptor_orchestration.py",
            "phase_2_collection/playbook_executor.py",
            "phase_2_collection/incident_playbooks.yml",
            "phase_3_forensics/volatility_analysis.py",
            "phase_4_timeline/timeline_analysis.py",
            "phase_5_reporting/report_generator.py",
            "phase_5_reporting/evidence_integrity.py",
            "examples/ransomware_incident_response.md"
        ]

        all_ok = True
        for file_path in required_files:
            full_path = self.base_path / file_path
            if full_path.exists():
                self.results["passed"].append(f"✅ File exists: {file_path}")
            else:
                self.results["failed"].append(f"❌ File missing: {file_path}")
                all_ok = False

        return all_ok

    def check_python_syntax(self) -> bool:
        """Validate Python syntax for all scripts"""
        python_files = [
            "phase_1_foundation/thehive_setup.py",
            "phase_1_foundation/siem_integration.py",
            "phase_2_collection/velociraptor_orchestration.py",
            "phase_2_collection/playbook_executor.py",
            "phase_3_forensics/volatility_analysis.py",
            "phase_4_timeline/timeline_analysis.py",
            "phase_5_reporting/report_generator.py",
            "phase_5_reporting/evidence_integrity.py"
        ]

        all_ok = True
        for py_file in python_files:
            full_path = self.base_path / py_file
            try:
                with open(full_path, 'r') as f:
                    compile(f.read(), py_file, 'exec')
                self.results["passed"].append(f"✅ Syntax valid: {py_file}")
            except SyntaxError as e:
                self.results["failed"].append(f"❌ Syntax error in {py_file}: {e}")
                all_ok = False
            except FileNotFoundError:
                self.results["failed"].append(f"❌ File not found: {py_file}")
                all_ok = False

        return all_ok

    def check_executables(self) -> bool:
        """Check if Python scripts are executable"""
        python_files = [
            "phase_1_foundation/thehive_setup.py",
            "phase_1_foundation/siem_integration.py",
            "phase_2_collection/velociraptor_orchestration.py",
            "phase_2_collection/playbook_executor.py",
            "phase_3_forensics/volatility_analysis.py",
            "phase_4_timeline/timeline_analysis.py",
            "phase_5_reporting/report_generator.py",
            "phase_5_reporting/evidence_integrity.py"
        ]

        all_ok = True
        for py_file in python_files:
            full_path = self.base_path / py_file
            if full_path.exists():
                # Check shebang
                with open(full_path, 'r') as f:
                    first_line = f.readline().strip()
                    if first_line.startswith('#!'):
                        self.results["passed"].append(f"✅ Shebang present: {py_file}")
                    else:
                        self.results["warnings"].append(f"⚠️ No shebang: {py_file}")
                        all_ok = False

        return all_ok

    def check_yaml_syntax(self) -> bool:
        """Validate YAML files"""
        try:
            import yaml
        except ImportError:
            self.results["warnings"].append("⚠️ PyYAML not installed, skipping YAML validation")
            return True

        yaml_files = [
            "phase_1_foundation/docker-compose.yml",
            "phase_2_collection/incident_playbooks.yml"
        ]

        all_ok = True
        for yaml_file in yaml_files:
            full_path = self.base_path / yaml_file
            try:
                with open(full_path, 'r') as f:
                    yaml.safe_load(f)
                self.results["passed"].append(f"✅ YAML valid: {yaml_file}")
            except yaml.YAMLError as e:
                self.results["failed"].append(f"❌ YAML error in {yaml_file}: {e}")
                all_ok = False
            except FileNotFoundError:
                self.results["failed"].append(f"❌ File not found: {yaml_file}")
                all_ok = False

        return all_ok

    def check_documentation_quality(self) -> bool:
        """Verify documentation completeness"""
        checks = []

        # Check README.md
        readme = self.base_path / "README.md"
        if readme.exists():
            content = readme.read_text()
            if len(content) > 5000:
                checks.append("✅ README.md is comprehensive (>5000 chars)")
            else:
                checks.append("⚠️ README.md may be too brief")

            required_sections = ["Quick Start", "Architecture", "Installation", "Usage"]
            for section in required_sections:
                if section in content:
                    checks.append(f"✅ README contains '{section}' section")
                else:
                    checks.append(f"⚠️ README missing '{section}' section")

        # Check ARCHITECTURE.md
        arch = self.base_path / "ARCHITECTURE.md"
        if arch.exists():
            content = arch.read_text()
            if "data flow" in content.lower() or "architecture" in content.lower():
                checks.append("✅ ARCHITECTURE.md contains design documentation")
            else:
                checks.append("⚠️ ARCHITECTURE.md may lack detail")

        # Check DEPLOYMENT.md
        deploy = self.base_path / "DEPLOYMENT.md"
        if deploy.exists():
            content = deploy.read_text()
            if "docker-compose" in content.lower() or "installation" in content.lower():
                checks.append("✅ DEPLOYMENT.md contains installation steps")
            else:
                checks.append("⚠️ DEPLOYMENT.md may lack deployment instructions")

        for check in checks:
            if check.startswith("✅"):
                self.results["passed"].append(check)
            else:
                self.results["warnings"].append(check)

        return True

    def check_docker_availability(self) -> bool:
        """Check if Docker is installed"""
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                self.results["passed"].append(f"✅ Docker: {version}")
                return True
            else:
                self.results["warnings"].append("⚠️ Docker not responding")
                return False
        except FileNotFoundError:
            self.results["warnings"].append("⚠️ Docker not installed (optional)")
            return False
        except Exception as e:
            self.results["warnings"].append(f"⚠️ Docker check failed: {e}")
            return False

    def check_evidence_vault(self) -> bool:
        """Check evidence vault directory structure"""
        vault_path = Path("/evidence_vault")

        if vault_path.exists():
            if vault_path.is_dir():
                self.results["passed"].append("✅ Evidence vault directory exists")
                return True
            else:
                self.results["warnings"].append("⚠️ /evidence_vault exists but is not a directory")
                return False
        else:
            self.results["warnings"].append("⚠️ Evidence vault not created (will be created on first use)")
            return True  # Not critical

    def run_all_checks(self) -> bool:
        """Run all validation checks"""
        print("=" * 70)
        print("AIRDFP System Validation")
        print("=" * 70)
        print()

        checks = [
            ("Python Version", self.check_python_version),
            ("Required Packages", self.check_required_packages),
            ("File Structure", self.check_file_structure),
            ("Python Syntax", self.check_python_syntax),
            ("Executable Scripts", self.check_executables),
            ("YAML Syntax", self.check_yaml_syntax),
            ("Documentation Quality", self.check_documentation_quality),
            ("Docker Availability", self.check_docker_availability),
            ("Evidence Vault", self.check_evidence_vault)
        ]

        for check_name, check_func in checks:
            print(f"Running: {check_name}...")
            try:
                check_func()
            except Exception as e:
                self.results["failed"].append(f"❌ {check_name} raised exception: {e}")

        return len(self.results["failed"]) == 0

    def print_results(self):
        """Print validation results"""
        print()
        print("=" * 70)
        print("VALIDATION RESULTS")
        print("=" * 70)
        print()

        if self.results["passed"]:
            print(f"✅ PASSED ({len(self.results['passed'])} checks)")
            print("-" * 70)
            for item in self.results["passed"]:
                print(f"  {item}")
            print()

        if self.results["warnings"]:
            print(f"⚠️ WARNINGS ({len(self.results['warnings'])} items)")
            print("-" * 70)
            for item in self.results["warnings"]:
                print(f"  {item}")
            print()

        if self.results["failed"]:
            print(f"❌ FAILED ({len(self.results['failed'])} checks)")
            print("-" * 70)
            for item in self.results["failed"]:
                print(f"  {item}")
            print()

        # Summary
        total = len(self.results["passed"]) + len(self.results["warnings"]) + len(self.results["failed"])
        passed_pct = (len(self.results["passed"]) / total * 100) if total > 0 else 0

        print("=" * 70)
        print(f"SUMMARY: {len(self.results['passed'])}/{total} checks passed ({passed_pct:.1f}%)")
        print("=" * 70)

        if len(self.results["failed"]) == 0:
            print("\n✅ System validation PASSED - AIRDFP is ready to deploy!")
            return True
        else:
            print("\n❌ System validation FAILED - Please fix the errors above")
            return False


def main():
    """Main validation entry point"""
    validator = AIRDFPValidator()
    success = validator.run_all_checks()
    validator.print_results()

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
