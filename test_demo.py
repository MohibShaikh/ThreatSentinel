#!/usr/bin/env python3
"""
SOC Agent Demo - Simulation showing autonomous investigation via SOCAgentPlanner.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List

from agent.planner import SOCAgentPlanner

logging.basicConfig(level=logging.WARNING)


class SOCAgentDemo:
    """SOC Agent demonstration using the real SOCAgentPlanner."""

    def __init__(self):
        config = {
            "api_keys": {},
            "memory": {"db_path": ":memory:"},
            "reporting": {"output_dir": "/tmp/threatsentinel_demo_reports"},
            "confidence_threshold": 0.7,
            "emergency_threshold": 0.8,
        }
        self.planner = SOCAgentPlanner(config)
        self.demo_count = 0

    def print_banner(self):
        print("=" * 72)
        print("  SOC AGENT - AUTONOMOUS SECURITY INVESTIGATION DEMONSTRATION")
        print("=" * 72)
        print("Simulating threat analysis and autonomous decision making\n")

    async def run_comprehensive_demo(self):
        self.print_banner()

        scenarios: List[tuple] = [
            ("Basic Threat Detection", self._scenario_brute_force()),
            ("Advanced Malware Analysis", self._scenario_malware()),
            ("Multi-Vector Attack", self._scenario_multi_vector()),
            ("Insider Threat Detection", self._scenario_insider()),
            ("Emergency Response", self._scenario_emergency()),
        ]

        print(f"Scenarios: {len(scenarios)}\n")
        for i, (name, _) in enumerate(scenarios, 1):
            print(f"  {i}. {name}")
        print()

        for name, coro in scenarios:
            self.demo_count += 1
            print("-" * 72)
            print(f"SCENARIO {self.demo_count}: {name}")
            print("-" * 72)
            result = await coro
            self._display_result(result)
            print()

        print("=" * 72)
        print("DEMONSTRATION COMPLETE")
        print(f"Scenarios executed: {self.demo_count}")
        print("=" * 72)

    async def _scenario_brute_force(self) -> Dict:
        return await self.planner.investigate_incident({
            "event_type": "suspicious_ip",
            "source_ip": "192.168.1.100",
            "payload": {
                "failed_login_attempts": 25,
                "accessed_endpoints": ["/admin", "/login", "/api/users"],
                "time_window": "10 minutes",
            },
        })

    async def _scenario_malware(self) -> Dict:
        return await self.planner.investigate_incident({
            "event_type": "malware_detection",
            "source_ip": "10.0.5.87",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb924",
            "payload": {
                "file_name": "invoice_urgent.pdf.exe",
                "threat_name": "Trojan:Win32/Emotet.variant",
                "c2_servers": ["185.159.157.123:443", "94.102.49.190:8080"],
            },
        })

    async def _scenario_multi_vector(self) -> Dict:
        events = [
            {"event_type": "suspicious_url", "source_ip": "203.0.113.45", "url": "http://evil-domain.com/verify"},
            {"event_type": "malware_detection", "source_ip": "192.168.1.205", "payload": {"file_name": "update.exe"}},
            {"event_type": "ddos_signs", "source_ip": "198.51.100.200", "payload": {"requests_per_second": 1500}},
        ]
        results = []
        for ev in events:
            results.append(await self.planner.investigate_incident(ev))
        combined = results[-1]
        combined["sub_investigations"] = len(results)
        return combined

    async def _scenario_insider(self) -> Dict:
        return await self.planner.investigate_incident({
            "event_type": "login_anomaly",
            "source_ip": "192.168.1.205",
            "payload": {
                "username": "sarah.davidson",
                "login_time": "2024-01-15T23:30:00Z",
                "data_accessed": ["payroll_database", "customer_financials"],
                "download_volume": "1.8 GB",
            },
        })

    async def _scenario_emergency(self) -> Dict:
        return await self.planner.investigate_incident(
            {
                "event_type": "malware_detection",
                "source_ip": "10.0.100.55",
                "payload": {
                    "threat_name": "Ransomware.Conti.v3",
                    "affected_systems": 23,
                    "business_impact": "critical",
                },
            },
            emergency_mode=True,
        )

    def _display_result(self, result: Dict):
        status = result.get("status", "unknown")
        print(f"  Status: {status}")

        risk = result.get("risk_assessment")
        if risk:
            print(f"  Risk Score: {risk.get('risk_score', 0):.3f}")
            print(f"  Risk Level: {risk.get('risk_level', 'unknown').upper()}")
            print(f"  Confidence: {risk.get('confidence', 0):.2f}")

        actions = result.get("recommended_actions", [])
        if actions:
            print(f"  Recommended Actions: {len(actions)}")
            for a in actions[:3]:
                print(f"    [{a['priority']}] {a['action_type']}: {a['description']}")

        if result.get("review_request"):
            rr = result["review_request"]
            print(f"  ** ESCALATED FOR HUMAN REVIEW: {rr.get('reason')}")

        reasoning = result.get("reasoning_log", [])
        if reasoning:
            print(f"  Reasoning steps: {len(reasoning)}")


async def main():
    demo = SOCAgentDemo()
    await demo.run_comprehensive_demo()


if __name__ == "__main__":
    asyncio.run(main())
