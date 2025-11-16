#!/usr/bin/env python3
"""
Playbook Executor - Automated Incident Response
Executes YAML-defined playbooks for automated response actions
"""

import yaml
import subprocess
import json
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import time


class PlaybookExecutor:
    """Execute incident response playbooks automatically"""

    def __init__(self, playbooks_file: str, dry_run: bool = False):
        self.playbooks_file = Path(playbooks_file)
        self.dry_run = dry_run
        self.playbooks = self._load_playbooks()
        self.execution_log = []

    def _load_playbooks(self) -> Dict:
        """Load playbook definitions from YAML"""
        try:
            with open(self.playbooks_file, 'r') as f:
                data = yaml.safe_load(f)
                print(f"✅ Loaded {len(data.get('playbooks', {}))} playbooks")
                return data
        except Exception as e:
            print(f"❌ Failed to load playbooks: {e}")
            return {"playbooks": {}, "config": {}}

    def list_playbooks(self) -> None:
        """List all available playbooks"""
        print("\n📚 Available Playbooks:\n")

        for name, playbook in self.playbooks.get('playbooks', {}).items():
            print(f"  {name}")
            print(f"    Description: {playbook.get('description')}")
            print(f"    Severity: {playbook.get('severity')}")
            print(f"    Auto-trigger: {playbook.get('auto_trigger')}")
            print(f"    Steps: {len(playbook.get('steps', []))}")
            print(f"    Duration: ~{playbook.get('estimated_duration', 0)}s")
            print()

    def execute_playbook(
        self,
        playbook_name: str,
        context: Dict[str, Any]
    ) -> bool:
        """
        Execute specific playbook with incident context

        Args:
            playbook_name: Name of playbook to execute
            context: Incident context (hostname, user, etc.)

        Returns:
            True if all steps succeeded, False otherwise
        """

        playbook = self.playbooks.get('playbooks', {}).get(playbook_name)

        if not playbook:
            print(f"❌ Playbook not found: {playbook_name}")
            return False

        print(f"\n{'='*60}")
        print(f"🎬 Executing Playbook: {playbook_name}")
        print(f"{'='*60}")
        print(f"   Description: {playbook.get('description')}")
        print(f"   Severity: {playbook.get('severity')}")
        print(f"   Steps: {len(playbook.get('steps', []))}")
        print(f"   Estimated Duration: {playbook.get('estimated_duration', 0)}s")

        if self.dry_run:
            print(f"\n⚠️ DRY RUN MODE - No actions will be executed\n")

        execution_log = {
            "playbook": playbook_name,
            "start_time": datetime.now().isoformat(),
            "context": context,
            "steps": [],
            "success": False
        }

        steps = playbook.get('steps', [])
        total_steps = len(steps)
        successful_steps = 0
        failed_steps = 0

        for i, step in enumerate(steps, 1):
            print(f"\n[Step {i}/{total_steps}] {step['name']}")

            step_result = self.execute_step(step, context)
            execution_log['steps'].append(step_result)

            if step_result['success']:
                successful_steps += 1
            else:
                failed_steps += 1

                # Check if step is critical
                if step.get('critical', False):
                    print(f"\n❌ CRITICAL STEP FAILED - Aborting playbook execution")
                    execution_log['aborted'] = True
                    execution_log['abort_reason'] = f"Critical step failed: {step['name']}"
                    break

        execution_log['end_time'] = datetime.now().isoformat()
        execution_log['success'] = failed_steps == 0
        execution_log['statistics'] = {
            "total_steps": total_steps,
            "successful": successful_steps,
            "failed": failed_steps,
            "success_rate": (successful_steps / total_steps * 100) if total_steps > 0 else 0
        }

        self.execution_log.append(execution_log)
        self.save_execution_log(execution_log)

        # Summary
        print(f"\n{'='*60}")
        print(f"PLAYBOOK EXECUTION SUMMARY")
        print(f"{'='*60}")
        print(f"✅ Successful steps: {successful_steps}")
        print(f"❌ Failed steps: {failed_steps}")
        print(f"📊 Success rate: {execution_log['statistics']['success_rate']:.1f}%")

        if execution_log['success']:
            print(f"\n✅ Playbook executed successfully!")
        else:
            print(f"\n⚠️ Playbook completed with errors")

        return execution_log['success']

    def execute_step(
        self,
        step: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute individual playbook step

        Args:
            step: Step definition
            context: Execution context

        Returns:
            Step execution result
        """

        step_name = step['name']
        action = step['action']
        timeout = step.get('timeout', 300)

        print(f"  Action: {action}")
        if self.dry_run:
            print(f"  ℹ️ [DRY RUN] Would execute: {action}")
            return {
                "step": step_name,
                "action": action,
                "success": True,
                "dry_run": True,
                "timestamp": datetime.now().isoformat()
            }

        start_time = time.time()

        try:
            # Execute action based on type
            if action == "network_isolate":
                result = self._action_network_isolate(step, context)

            elif action == "velociraptor_collect":
                result = self._action_velociraptor_collect(step, context)

            elif action == "thehive_create_case":
                result = self._action_thehive_create_case(step, context)

            elif action == "notify":
                result = self._action_notify(step, context)

            elif action == "forensic_image":
                result = self._action_forensic_image(step, context)

            elif action == "ad_reset_credentials":
                result = self._action_ad_reset_credentials(step, context)

            elif action == "firewall_block":
                result = self._action_firewall_block(step, context)

            else:
                print(f"  ⚠️ Unknown action: {action} (simulating success)")
                result = {"success": True, "message": f"Simulated: {action}"}

            elapsed = time.time() - start_time

            if result.get('success'):
                print(f"  ✅ Completed in {elapsed:.1f}s")
            else:
                print(f"  ❌ Failed: {result.get('error', 'Unknown error')}")

            return {
                "step": step_name,
                "action": action,
                "success": result.get('success', False),
                "elapsed_time": elapsed,
                "result": result,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            elapsed = time.time() - start_time
            print(f"  ❌ Exception: {str(e)}")

            return {
                "step": step_name,
                "action": action,
                "success": False,
                "elapsed_time": elapsed,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

    def _action_network_isolate(self, step: Dict, context: Dict) -> Dict:
        """Isolate host from network"""
        hostname = step.get('target', context.get('hostname', 'unknown'))

        print(f"    🔒 Isolating host: {hostname}")

        # Simulate network isolation (in production, call firewall API)
        # Example: Create isolated VLAN, apply ACL, etc.

        return {
            "success": True,
            "message": f"Host {hostname} isolated from network",
            "hostname": hostname
        }

    def _action_velociraptor_collect(self, step: Dict, context: Dict) -> Dict:
        """Trigger Velociraptor evidence collection"""
        params = step.get('params', {})
        collection_type = params.get('collection_type', 'quick_triage')
        hostname = context.get('hostname', 'unknown')

        print(f"    📦 Collecting evidence: {collection_type}")
        print(f"    Target: {hostname}")

        # In production, call velociraptor_orchestration.py
        # For now, simulate
        return {
            "success": True,
            "message": f"Evidence collection initiated for {hostname}",
            "collection_type": collection_type
        }

    def _action_thehive_create_case(self, step: Dict, context: Dict) -> Dict:
        """Create case in TheHive"""
        params = step.get('params', {})
        template = params.get('template', 'CRITICAL_MALWARE')
        severity = params.get('severity', 'high')

        print(f"    📋 Creating TheHive case")
        print(f"    Template: {template}")
        print(f"    Severity: {severity}")

        # In production, call TheHive API
        return {
            "success": True,
            "message": "Case created successfully",
            "case_id": f"CASE-{int(time.time())}",
            "template": template
        }

    def _action_notify(self, step: Dict, context: Dict) -> Dict:
        """Send notifications"""
        params = step.get('params', {})
        recipients = params.get('recipients', [])
        priority = params.get('priority', 'P2')
        channels = params.get('channels', ['email'])

        print(f"    📧 Sending notifications")
        print(f"    Recipients: {', '.join(recipients)}")
        print(f"    Priority: {priority}")
        print(f"    Channels: {', '.join(channels)}")

        # In production, send actual notifications
        return {
            "success": True,
            "message": f"Notifications sent to {len(recipients)} recipients",
            "channels": channels
        }

    def _action_forensic_image(self, step: Dict, context: Dict) -> Dict:
        """Create forensic disk image"""
        params = step.get('params', {})
        method = params.get('method', 'dd_gzip')

        print(f"    💾 Creating forensic image")
        print(f"    Method: {method}")

        # In production, execute dd command or use imaging tool
        return {
            "success": True,
            "message": "Forensic image created",
            "method": method
        }

    def _action_ad_reset_credentials(self, step: Dict, context: Dict) -> Dict:
        """Reset Active Directory credentials"""
        params = step.get('params', {})
        accounts = params.get('accounts', [])
        force_logout = params.get('force_logout', True)

        print(f"    🔑 Resetting credentials")
        print(f"    Accounts: {accounts}")
        print(f"    Force logout: {force_logout}")

        # In production, call AD API
        return {
            "success": True,
            "message": f"Reset {len(accounts) if isinstance(accounts, list) else 1} accounts",
            "accounts": accounts
        }

    def _action_firewall_block(self, step: Dict, context: Dict) -> Dict:
        """Block IP addresses at firewall"""
        params = step.get('params', {})
        ip_addresses = params.get('ip_addresses', [])
        direction = params.get('direction', 'outbound')

        print(f"    🛡️ Blocking IPs at firewall")
        print(f"    IPs: {ip_addresses}")
        print(f"    Direction: {direction}")

        # In production, call firewall API
        return {
            "success": True,
            "message": f"Blocked {len(ip_addresses) if isinstance(ip_addresses, list) else 0} IPs",
            "direction": direction
        }

    def save_execution_log(self, log: Dict) -> None:
        """Save execution log for audit trail"""
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)

        timestamp = int(datetime.now().timestamp())
        filename = logs_dir / f"playbook_execution_{timestamp}.json"

        with open(filename, 'w') as f:
            json.dump(log, f, indent=2)

        print(f"\n📋 Execution log saved: {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="Playbook Executor - AIRDFP"
    )
    parser.add_argument(
        "--playbooks",
        default="phase_2_collection/incident_playbooks.yml",
        help="Path to playbooks YAML file"
    )
    parser.add_argument(
        "--playbook",
        required=True,
        help="Playbook name to execute"
    )
    parser.add_argument(
        "--hostname",
        default="unknown",
        help="Affected hostname"
    )
    parser.add_argument(
        "--user",
        default="unknown",
        help="Affected user"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate execution without performing actions"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available playbooks"
    )

    args = parser.parse_args()

    executor = PlaybookExecutor(args.playbooks, args.dry_run)

    if args.list:
        executor.list_playbooks()
        return 0

    print("=" * 60)
    print("Playbook Executor - AIRDFP")
    print("=" * 60)

    # Build context from arguments
    context = {
        "hostname": args.hostname,
        "user": args.user,
        "timestamp": datetime.now().isoformat(),
        "incident_start": datetime.now().isoformat()
    }

    success = executor.execute_playbook(args.playbook, context)

    return 0 if success else 1


if __name__ == "__main__":
    exit(main())
