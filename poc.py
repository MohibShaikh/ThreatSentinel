#!/usr/bin/env python3
"""
ThreatSentinel Proof-of-Concept — End-to-End Pipeline Demo

Exercises the REAL pipeline: planner -> threat intel (real or mock) ->
LLM analysis (GLM-4 / Claude / GPT / etc) -> risk scoring -> action
execution -> report generation -> memory storage.

Usage:
    python poc.py                          # Mock intel, no LLM
    python poc.py --llm                    # Mock intel + LLM analysis
    python poc.py --llm --provider openai  # Use OpenAI instead of GLM
    python poc.py --with-api               # Real threat intel APIs
    python poc.py --with-api --llm         # Full pipeline

Env vars:
    LLM_API_KEY          API key for the LLM provider
    LLM_PROVIDER         glm | openai | anthropic | gemini | deepseek | ...
    LLM_MODEL            Model override (optional)
    VIRUSTOTAL_API_KEY   VirusTotal API key (optional)
    ABUSEIPDB_API_KEY    AbuseIPDB API key (optional)
    SHODAN_API_KEY       Shodan API key (optional)
"""

import asyncio
import logging
import os
import sys
import time
from pathlib import Path
from typing import Dict, Any

sys.path.insert(0, str(Path(__file__).parent))

from agent.planner import SOCAgentPlanner


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("poc")


SCENARIOS = {
    "brute_force": {
        "event_type": "suspicious_ip",
        "source_ip": "185.220.101.34",  # known Tor exit node
        "user_agent": "python-requests/2.28.0",
        "payload": {
            "failed_login_attempts": 47,
            "accessed_endpoints": ["/admin", "/wp-login.php", "/api/v1/auth"],
            "time_window_seconds": 120,
        },
    },
    "malware_c2": {
        "event_type": "malware_detection",
        "source_ip": "10.0.5.87",
        "file_hash": "44d88612fea8a8f36de82e1278abb02f",  # EICAR test hash
        "payload": {
            "file_name": "invoice_urgent.pdf.exe",
            "threat_name": "Trojan:Win32/Emotet.variant",
            "c2_servers": ["185.159.157.123:443"],
        },
    },
    "phishing": {
        "event_type": "phishing_attempt",
        "source_ip": "203.0.113.45",
        "url": "http://g00gle-security-alert.com/verify",
        "payload": {
            "sender": "security@g00gle-alert.com",
            "subject": "Urgent: Account Verification Required",
            "targets": 23,
        },
    },
    "ddos": {
        "event_type": "ddos_signs",
        "source_ip": "198.51.100.200",
        "payload": {
            "requests_per_second": 15000,
            "unique_sources": 340,
            "target_endpoint": "/api/v1/search",
            "duration_seconds": 180,
        },
    },
    "insider_threat": {
        "event_type": "login_anomaly",
        "source_ip": "192.168.1.205",
        "internal_source": True,
        "payload": {
            "username": "sarah.davidson",
            "login_time": "2024-01-15T03:30:00Z",
            "data_accessed": ["payroll_database", "customer_financials", "ssh_keys"],
            "download_volume_mb": 1800,
            "failed_login_attempts": 0,
        },
    },
}


def build_config(use_api_keys: bool = False, use_llm: bool = False,
                  llm_provider: str = "glm", slack_webhook: str = None) -> Dict[str, Any]:
    """Build planner config with optional real APIs, LLM, and integrations."""
    api_keys = {}
    if use_api_keys:
        api_keys = {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY', ''),
            'abuseipdb': os.getenv('ABUSEIPDB_API_KEY', ''),
            'shodan': os.getenv('SHODAN_API_KEY', ''),
        }
        api_keys = {k: v for k, v in api_keys.items() if v}

    llm_config = {}
    if use_llm:
        llm_key = os.getenv('LLM_API_KEY', '')
        if not llm_key:
            print("ERROR: --llm requires LLM_API_KEY env var")
            sys.exit(1)
        llm_config = {
            'provider': os.getenv('LLM_PROVIDER', llm_provider),
            'api_key': llm_key,
            'model': os.getenv('LLM_MODEL'),
            'temperature': 0.3,
            'max_tokens': 2048,
        }

    integrations_config = {}
    if slack_webhook:
        integrations_config = {
            "integrations": {
                "slack": {
                    "webhook_url": slack_webhook,
                    "default_channel": "#security-alerts",
                }
            }
        }

    return {
        'api_keys': api_keys,
        'memory': {'memory_dir': 'data/poc_memory'},
        'reporting': {'reports_dir': 'reports/poc', 'auto_save': True},
        'llm': llm_config,
        'confidence_threshold': 0.7,
        'emergency_threshold': 0.8,
        'max_investigation_time': 300,
        'integrations_config': integrations_config,
    }


def print_section(title: str, char: str = "="):
    width = 72
    print(f"\n{char * width}")
    print(f"  {title}")
    print(f"{char * width}")


def print_result(result: Dict[str, Any]):
    """Pretty-print investigation result."""

    status = result.get("status", "unknown")
    risk = result.get("risk_assessment", {})
    actions = result.get("recommended_actions", [])
    actions_executed = result.get("actions_executed", [])
    reasoning = result.get("reasoning_log", [])

    print(f"\n  Status:       {status}")
    print(f"  Risk Score:   {risk.get('risk_score', 0):.3f} / 1.0")
    print(f"  Risk Level:   {risk.get('risk_level', 'unknown').upper()}")
    print(f"  Confidence:   {risk.get('confidence', 0):.1%}")
    print(f"  Base Risk:    {risk.get('base_risk', 0):.3f}")
    print(f"  Intel Risk:   {risk.get('intel_risk', 0):.3f}")
    print(f"  Pattern Risk: {risk.get('pattern_risk', 0):.3f}")

    # Intel sources
    intel = result.get("intelligence_data", {})
    sources = intel.get("sources", [])
    indicators = intel.get("threat_indicators", [])
    if sources:
        print(f"\n  Threat Intel Sources: {', '.join(sources)}")
        print(f"  Reputation Score:    {intel.get('reputation_score', 0):.3f}")
        for ind in indicators[:8]:
            print(f"    - {ind}")
    else:
        print("\n  Threat Intel: No sources returned")

    # LLM analysis
    llm = risk.get("llm_analysis")
    if llm and isinstance(llm, dict):
        print("\n  LLM Analysis:")
        print(f"    Classification: {llm.get('attack_classification', 'N/A')}")
        print(f"    Urgency:        {llm.get('urgency', 'N/A')}")
        print(f"    Risk Modifier:  {llm.get('risk_modifier', 0)}")
        print(f"    LLM Confidence: {llm.get('confidence', 0)}")
        findings = llm.get("key_findings", [])
        if findings:
            print("    Key Findings:")
            for f in findings[:5]:
                print(f"      - {f}")
        mitre = llm.get("mitre_tactics", [])
        if mitre:
            print(f"    MITRE Tactics: {', '.join(mitre)}")
        ioc = llm.get("ioc_analysis", {})
        mal = ioc.get("malicious_indicators", [])
        if mal:
            print(f"    Malicious IOCs: {', '.join(mal[:3])}")

    # Recommended actions
    if actions:
        print(f"\n  Recommended Actions ({len(actions)}):")
        for a in actions:
            print(f"    [{a['priority']}] {a['action_type']}: {a['description']}")

    # Executed actions
    if actions_executed:
        print(f"\n  Actions Executed ({len(actions_executed)}):")
        for ae in actions_executed:
            s = "OK" if ae.get('success') else "FAIL"
            integrations = ', '.join(ae.get('integrations_used', [])) or ae.get('error', 'N/A')
            print(f"    {ae['action']}: {s} via [{integrations}]")

    # Escalation
    review = result.get("review_request")
    if review:
        print("\n  *** ESCALATED FOR HUMAN REVIEW ***")
        print(f"  Reason: {review.get('reason')}")
        print(f"  Priority: {review.get('priority')}")

    # Reasoning trace
    if reasoning:
        print(f"\n  Reasoning Trace ({len(reasoning)} steps):")
        for step in reasoning:
            print(f"    {step}")

    # Report saved?
    getattr(result.get("report"), '__class__', None)
    if isinstance(result.get("report"), dict):
        md = result["report"].get("formats", {}).get("markdown", "")
        if md:
            print(f"\n  Report: {len(md)} chars of Markdown generated")


async def run_poc():
    use_api = "--with-api" in sys.argv
    use_llm = "--llm" in sys.argv

    llm_provider = "glm"
    if "--provider" in sys.argv:
        idx = sys.argv.index("--provider")
        if idx + 1 < len(sys.argv):
            llm_provider = sys.argv[idx + 1]

    slack_webhook = None
    if "--with-slack" in sys.argv:
        slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
        if not slack_webhook:
            print("ERROR: --with-slack requires SLACK_WEBHOOK_URL env var")
            sys.exit(1)

    config = build_config(
        use_api_keys=use_api, use_llm=use_llm,
        llm_provider=llm_provider, slack_webhook=slack_webhook
    )

    intel_mode = "LIVE APIs" if use_api else "MOCK threat intel"
    llm_info = f"{config['llm'].get('provider', 'none')}/{config['llm'].get('model', 'default')}" if use_llm else "disabled"

    print_section("ThreatSentinel POC — End-to-End Pipeline")
    print(f"\n  Intel Mode:   {intel_mode}")
    print(f"  LLM:          {llm_info}")
    print(f"  API keys:     {list(config['api_keys'].keys()) or ['none (using mocks)']}")
    print(f"  Integrations: {bool(config['integrations_config'])}")
    print(f"  Scenarios:    {len(SCENARIOS)}")

    planner = SOCAgentPlanner(config)

    # Connect integrations if configured
    if config['integrations_config']:
        await planner.integrations.connect_all()

    results = {}
    total_start = time.monotonic()

    for name, event_data in SCENARIOS.items():
        print_section(f"Scenario: {name}", "-")
        print(f"  Event Type: {event_data['event_type']}")
        print(f"  Source IP:  {event_data.get('source_ip', 'N/A')}")

        start = time.monotonic()
        emergency = name == "ddos"
        result = await planner.investigate_incident(event_data, emergency_mode=emergency)
        elapsed = time.monotonic() - start

        print(f"  Duration:   {elapsed:.2f}s")
        print_result(result)
        results[name] = result

    total_elapsed = time.monotonic() - total_start

    # Disconnect integrations
    if config['integrations_config']:
        await planner.integrations.disconnect_all()

    # Summary
    print_section("POC Summary")
    print(f"\n  Total time: {total_elapsed:.2f}s")
    print(f"  Scenarios:  {len(results)}")
    print()

    for name, r in results.items():
        risk = r.get("risk_assessment", {})
        status = r.get("status", "?")
        level = risk.get("risk_level", "?").upper()
        score = risk.get("risk_score", 0)
        print(f"  {name:20s}  {status:25s}  {level:10s}  {score:.3f}")

    # Memory stats
    mem_stats = await planner.memory.get_memory_stats()
    print(f"\n  Memory: {mem_stats.get('total_investigations', 0)} investigations stored")
    print(f"  Patterns: {mem_stats.get('patterns_learned', 0)} patterns learned")

    # Reports saved
    reports_dir = Path("reports/poc")
    if reports_dir.exists():
        report_files = list(reports_dir.glob("*.md"))
        print(f"  Reports: {len(report_files)} markdown reports saved to {reports_dir}/")

    print(f"\n{'=' * 72}")
    print("  POC COMPLETE — Pipeline works end-to-end.")
    if not use_api:
        print("  Add --with-api with .env keys to hit real threat intel APIs.")
    if not use_llm:
        print("  Add --llm with LLM_API_KEY to enable AI-powered analysis.")
    print(f"{'=' * 72}\n")


if __name__ == "__main__":
    asyncio.run(run_poc())
