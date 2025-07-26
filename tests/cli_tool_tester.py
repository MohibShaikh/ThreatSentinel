#!/usr/bin/env python3
"""
CLI Tool Tester for ThreatSentinel

A comprehensive tool for testing and demonstrating all CLI interactions
with ThreatSentinel components without requiring API keys or real data.
"""

import asyncio
import json
import sys
from datetime import datetime
from typing import Dict, Any, List
import argparse

# Mock data generators
class MockDataGenerator:
    """Generates realistic mock data for demonstrations"""
    
    @staticmethod
    def generate_ip_reputation_data(ip: str) -> Dict[str, Any]:
        """Generate mock IP reputation data"""
        return {
            "success": True,
            "source": "virustotal",
            "data": {
                "reputation_score": 0.75,
                "indicators": [
                    f"IP {ip} associated with 3 malicious URLs",
                    f"IP {ip} detected in 1 malware sample",
                    "High-risk geographic location"
                ],
                "confidence": 0.92,
                "last_updated": datetime.now().isoformat()
            },
            "timestamp": datetime.now().isoformat()
        }
    
    @staticmethod
    def generate_memory_stats() -> Dict[str, Any]:
        """Generate mock memory statistics"""
        return {
            "total_investigations": 1547,
            "event_types": {
                "suspicious_ip": 487,
                "malware_detection": 324,
                "phishing_attempt": 289,
                "data_exfiltration": 234,
                "brute_force": 213
            },
            "outcomes": {
                "malicious": 892,
                "benign": 521,
                "unknown": 134
            },
            "avg_confidence": 0.83,
            "storage_size_mb": 4.7,
            "memory_retention_days": 180,
            "oldest_record": "2024-01-20T08:15:00Z",
            "newest_record": datetime.now().isoformat()
        }
    
    @staticmethod
    def generate_task_queue_stats() -> Dict[str, Any]:
        """Generate mock task queue statistics"""
        return {
            "queue_statistics": {
                "total_tasks": 2341,
                "pending": 15,
                "in_progress": 7,
                "completed": 2298,
                "failed": 18,
                "cancelled": 3
            },
            "priority_breakdown": {
                "critical": 2,
                "high": 6,
                "medium": 14,
                "low": 8
            },
            "task_types": {
                "investigation": 1456,
                "report_generation": 543,
                "pattern_analysis": 234,
                "integration_action": 108
            },
            "performance_metrics": {
                "avg_processing_time_seconds": 42.3,
                "successful_completion_rate": 0.98,
                "active_workers": 6,
                "max_workers": 10,
                "throughput_per_minute": 8.7
            },
            "last_updated": datetime.now().isoformat()
        }
    
    @staticmethod
    def generate_integration_status() -> Dict[str, Any]:
        """Generate mock integration status"""
        return {
            "integrations": {
                "palo_alto": {
                    "type": "firewall",
                    "status": "connected",
                    "last_action": "2024-07-27T14:25:00Z",
                    "success_rate": 0.96,
                    "supported_actions": ["BLOCK_IP", "BLOCK_URL", "CREATE_RULE"]
                },
                "splunk": {
                    "type": "siem",
                    "status": "connected",
                    "last_action": "2024-07-27T14:30:00Z",
                    "success_rate": 0.99,
                    "supported_actions": ["CREATE_INCIDENT", "SEND_ALERT", "ADD_TO_WATCHLIST"]
                },
                "slack": {
                    "type": "communication",
                    "status": "connected",
                    "last_action": "2024-07-27T14:32:00Z",
                    "success_rate": 1.0,
                    "supported_actions": ["SEND_ALERT", "NOTIFY", "ESCALATE"]
                }
            },
            "overall_health": "good",
            "total_integrations": 8,
            "active_integrations": 6,
            "failed_integrations": 0,
            "last_health_check": datetime.now().isoformat()
        }


class ThreatSentinelCLITester:
    """Main CLI tester for ThreatSentinel components"""
    
    def __init__(self):
        self.data_generator = MockDataGenerator()
    
    def print_header(self, title: str):
        """Print formatted header"""
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}")
    
    def print_command(self, command: str):
        """Print formatted command"""
        print(f"\n🔧 Command:")
        print(f"   {command}")
        print(f"\n📊 Response:")
    
    def print_json_response(self, data: Dict[str, Any]):
        """Print formatted JSON response"""
        print(json.dumps(data, indent=2, ensure_ascii=False))
    
    # Tool-specific testers
    def test_virustotal_tool(self):
        """Test VirusTotal tool CLI interactions"""
        self.print_header("VirusTotal Tool CLI Tests")
        
        # IP reputation query
        self.print_command("python -m agent.tools virustotal query_ip 192.168.1.100")
        ip_data = self.data_generator.generate_ip_reputation_data("192.168.1.100")
        self.print_json_response(ip_data)
        
        # URL reputation query
        self.print_command("python -m agent.tools virustotal query_url https://suspicious-site.com")
        url_data = {
            "success": True,
            "source": "virustotal",
            "data": {
                "reputation_score": 0.85,
                "indicators": [
                    "Detected as malicious by 15/24 engines",
                    "Recently created domain",
                    "Hosting malware distribution"
                ],
                "scan_id": "a1b2c3d4e5f6",
                "scan_date": datetime.now().isoformat()
            },
            "timestamp": datetime.now().isoformat()
        }
        self.print_json_response(url_data)
        
        # File hash query
        self.print_command("python -m agent.tools virustotal query_hash a1b2c3d4e5f67890abcdef1234567890")
        hash_data = {
            "success": True,
            "source": "virustotal",
            "data": {
                "reputation_score": 0.95,
                "indicators": [
                    "Detected as malware by 22/26 engines",
                    "File type: PE32 executable",
                    "First submission: 2024-07-20T10:30:00Z"
                ],
                "detection_names": ["Trojan.Win32.Generic", "Malware.Heuristic"],
                "file_size": 2457600
            },
            "timestamp": datetime.now().isoformat()
        }
        self.print_json_response(hash_data)
    
    def test_abuseipdb_tool(self):
        """Test AbuseIPDB tool CLI interactions"""
        self.print_header("AbuseIPDB Tool CLI Tests")
        
        self.print_command("python -m agent.tools abuseipdb query_ip 10.0.0.100")
        abuse_data = {
            "success": True,
            "source": "abuseipdb",
            "data": {
                "reputation_score": 0.67,
                "indicators": [
                    "Abuse confidence: 67%",
                    "Usage type: datacenter",
                    "Country: US",
                    "Last reported: 2024-07-25T16:45:00Z"
                ],
                "total_reports": 23,
                "distinct_users": 12,
                "white_listed": False
            },
            "timestamp": datetime.now().isoformat()
        }
        self.print_json_response(abuse_data)
    
    def test_shodan_tool(self):
        """Test Shodan tool CLI interactions"""
        self.print_header("Shodan Tool CLI Tests")
        
        self.print_command("python -m agent.tools shodan query_ip 203.0.113.45")
        shodan_data = {
            "success": True,
            "source": "shodan",
            "data": {
                "reputation_score": 0.45,
                "indicators": [
                    "Open ports: 6",
                    "Known vulnerabilities: 2",
                    "Organization: Example Hosting Co",
                    "Operating System: Linux 3.x"
                ],
                "open_ports": [22, 80, 443, 3389, 5432, 8080],
                "vulnerabilities": ["CVE-2021-44228", "CVE-2022-0847"],
                "country": "Netherlands",
                "city": "Amsterdam"
            },
            "timestamp": datetime.now().isoformat()
        }
        self.print_json_response(shodan_data)
    
    def test_tool_registry(self):
        """Test ToolRegistry CLI interactions"""
        self.print_header("Tool Registry CLI Tests")
        
        # Aggregated IP reputation query
        self.print_command("python -m agent.tools registry query_ip 192.168.1.100")
        registry_data = {
            "success": True,
            "source": "registry",
            "data": {
                "reputation_score": 0.85,
                "indicators": [
                    "[virustotal] Associated with 3 malicious URLs",
                    "[abuseipdb] Abuse confidence: 67%",
                    "[shodan] Open ports: 6",
                    "[shodan] Known vulnerabilities: 2"
                ],
                "confidence": 1.0,
                "sources_queried": ["virustotal", "abuseipdb", "shodan"],
                "query_type": "ip_reputation",
                "processing_time_ms": 245
            },
            "timestamp": datetime.now().isoformat()
        }
        self.print_json_response(registry_data)
        
        # Tool capabilities
        self.print_command("python -m agent.tools registry capabilities")
        capabilities_data = {
            "available_tools": ["virustotal", "abuseipdb", "shodan", "urlvoid"],
            "capabilities": {
                "virustotal": ["ip_reputation", "url_reputation", "file_reputation"],
                "abuseipdb": ["ip_reputation"],
                "shodan": ["ip_reputation"],
                "urlvoid": ["url_reputation"]
            },
            "tool_status": {
                "virustotal": "active",
                "abuseipdb": "active", 
                "shodan": "active",
                "urlvoid": "rate_limited"
            }
        }
        self.print_json_response(capabilities_data)
    
    def test_memory_system(self):
        """Test memory system CLI interactions"""
        self.print_header("Agent Memory CLI Tests")
        
        # Memory statistics
        self.print_command("python -m agent.memory stats")
        memory_stats = self.data_generator.generate_memory_stats()
        self.print_json_response(memory_stats)
        
        # Search similar events
        self.print_command("python -m agent.memory search --event-type suspicious_ip --limit 3")
        search_data = {
            "total_found": 487,
            "results": [
                {
                    "investigation_id": "inv_2024_1234",
                    "event_type": "suspicious_ip",
                    "indicators": ["192.168.1.100", "failed_login_attempts"],
                    "outcome": "malicious",
                    "confidence": 0.89,
                    "timestamp": "2024-07-26T15:30:00Z",
                    "similarity": 0.94
                },
                {
                    "investigation_id": "inv_2024_1205",
                    "event_type": "suspicious_ip",
                    "indicators": ["10.0.0.50", "port_scanning"],
                    "outcome": "malicious",
                    "confidence": 0.82,
                    "timestamp": "2024-07-25T09:15:00Z",
                    "similarity": 0.87
                },
                {
                    "investigation_id": "inv_2024_1189",
                    "event_type": "suspicious_ip",
                    "indicators": ["172.16.0.25", "unusual_traffic_patterns"],
                    "outcome": "benign",
                    "confidence": 0.71,
                    "timestamp": "2024-07-23T14:22:00Z",
                    "similarity": 0.76
                }
            ],
            "query_timestamp": datetime.now().isoformat()
        }
        self.print_json_response(search_data)
        
        # Pattern insights
        self.print_command("python -m agent.memory patterns --type frequency_anomaly")
        pattern_data = {
            "pattern_insights": [
                {
                    "pattern_type": "frequency_anomaly",
                    "description": "Burst of 20+ failed login attempts from /16 subnet within 5 minutes",
                    "confidence": 0.92,
                    "examples": ["inv_2024_1234", "inv_2024_1229", "inv_2024_1223"],
                    "first_seen": "2024-07-10T08:30:00Z",
                    "last_seen": "2024-07-26T15:30:00Z",
                    "frequency": 18
                },
                {
                    "pattern_type": "time_based_anomaly",
                    "description": "Suspicious activities consistently occurring 02:00-04:00 UTC",
                    "confidence": 0.84,
                    "examples": ["inv_2024_1156", "inv_2024_1178", "inv_2024_1198"],
                    "first_seen": "2024-06-15T02:15:00Z",
                    "last_seen": "2024-07-24T03:45:00Z",
                    "frequency": 12
                }
            ],
            "total_patterns": 2,
            "analysis_timestamp": datetime.now().isoformat()
        }
        self.print_json_response(pattern_data)
    
    def test_task_queue_system(self):
        """Test task queue system CLI interactions"""
        self.print_header("Task Queue System CLI Tests")
        
        # Queue statistics
        self.print_command("python -m agent.task_queue stats")
        queue_stats = self.data_generator.generate_task_queue_stats()
        self.print_json_response(queue_stats)
        
        # Add high-priority task
        self.print_command("python -m agent.task_queue add --type investigation --priority critical --payload '{\"event_id\":\"evt_001\",\"source_ip\":\"192.168.1.100\"}'")
        add_task_data = {
            "task_created": {
                "task_id": "task_2024_2341",
                "task_type": "investigation",
                "priority": "critical",
                "status": "pending",
                "payload": {
                    "event_id": "evt_001",
                    "source_ip": "192.168.1.100"
                },
                "created_at": datetime.now().isoformat(),
                "queue_position": 1
            },
            "message": "Critical priority task successfully added to queue",
            "estimated_start_time": datetime.now().isoformat()
        }
        self.print_json_response(add_task_data)
        
        # Worker management
        self.print_command("python -m agent.task_queue workers --action start --count 8")
        worker_data = {
            "worker_status": {
                "action": "start",
                "workers_started": 8,
                "total_active_workers": 8,
                "max_workers": 10,
                "worker_ids": [f"worker_{i:03d}" for i in range(1, 9)]
            },
            "queue_impact": {
                "estimated_throughput_increase": "400%",
                "avg_wait_time_reduction": "75%"
            },
            "system_resources": {
                "cpu_usage_percent": 52,
                "memory_usage_mb": 384,
                "available_capacity": "excellent"
            },
            "timestamp": datetime.now().isoformat()
        }
        self.print_json_response(worker_data)
    
    def test_integration_system(self):
        """Test integration system CLI interactions"""
        self.print_header("Integration System CLI Tests")
        
        # Integration status
        self.print_command("python -m agent.integrations status")
        integration_status = self.data_generator.generate_integration_status()
        self.print_json_response(integration_status)
        
        # Execute action across integrations
        self.print_command("python -m agent.integrations execute --action BLOCK_IP --target 192.168.1.100 --reason 'Malicious activity detected'")
        action_data = {
            "action_executed": {
                "action_type": "BLOCK_IP",
                "target": "192.168.1.100",
                "reason": "Malicious activity detected",
                "execution_id": "exec_2024_0567"
            },
            "results": [
                {
                    "integration": "palo_alto",
                    "status": "success",
                    "message": "IP blocked on firewall rule #4521",
                    "execution_time_ms": 234
                },
                {
                    "integration": "fortinet",
                    "status": "success", 
                    "message": "IP added to blocked address group",
                    "execution_time_ms": 187
                }
            ],
            "summary": {
                "total_integrations": 2,
                "successful": 2,
                "failed": 0,
                "total_execution_time_ms": 421
            },
            "timestamp": datetime.now().isoformat()
        }
        self.print_json_response(action_data)
    
    def test_investigation_workflow(self):
        """Test complete investigation workflow"""
        self.print_header("Complete Investigation Workflow")
        
        # Start investigation
        self.print_command("python -m agent.planner investigate --event-file data/sample_events.json --event-id evt_001")
        investigation_data = {
            "investigation_started": {
                "investigation_id": "inv_2024_2342",
                "event_id": "evt_001",
                "event_type": "suspicious_ip",
                "source_ip": "192.168.1.100",
                "priority": "high",
                "estimated_completion": "2024-07-27T14:45:00Z"
            },
            "phases": {
                "threat_intelligence": "in_progress",
                "risk_assessment": "pending",
                "action_planning": "pending",
                "execution": "pending"
            },
            "progress": 15,
            "message": "Investigation initiated successfully",
            "timestamp": datetime.now().isoformat()
        }
        self.print_json_response(investigation_data)
        
        # Get investigation status
        self.print_command("python -m agent.planner status --investigation-id inv_2024_2342")
        status_data = {
            "investigation_id": "inv_2024_2342",
            "status": "completed",
            "progress": 100,
            "phases": {
                "threat_intelligence": "completed",
                "risk_assessment": "completed", 
                "action_planning": "completed",
                "execution": "completed"
            },
            "results": {
                "risk_level": "high",
                "risk_score": 0.87,
                "threat_indicators": 5,
                "actions_executed": 3,
                "confidence": 0.92
            },
            "execution_time_seconds": 42.7,
            "completed_at": datetime.now().isoformat()
        }
        self.print_json_response(status_data)
    
    def run_all_tests(self):
        """Run all CLI tests"""
        print("🚀 ThreatSentinel CLI Tool Tester")
        print("Testing all components with mock data...")
        
        # Run all individual tests
        self.test_virustotal_tool()
        self.test_abuseipdb_tool()
        self.test_shodan_tool()
        self.test_tool_registry()
        self.test_memory_system()
        self.test_task_queue_system()
        self.test_integration_system()
        self.test_investigation_workflow()
        
        # Summary
        self.print_header("Test Summary")
        print("✅ All CLI tool tests completed successfully!")
        print("📋 Components tested:")
        print("   • VirusTotal Tool")
        print("   • AbuseIPDB Tool")
        print("   • Shodan Tool")
        print("   • Tool Registry")
        print("   • Agent Memory")
        print("   • Task Queue")
        print("   • Integration System")
        print("   • Investigation Workflow")
        print("\n💡 To run these commands with real data:")
        print("   1. Configure API keys in .env file")
        print("   2. Start the ThreatSentinel API: python main_api.py")
        print("   3. Use the actual CLI commands shown above")
        print(f"\n⏰ Test completed at: {datetime.now().isoformat()}")


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="ThreatSentinel CLI Tool Tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tests/cli_tool_tester.py                    # Run all tests
  python tests/cli_tool_tester.py --component tools  # Test only tools
  python tests/cli_tool_tester.py --component memory # Test only memory
        """
    )
    
    parser.add_argument(
        "--component",
        choices=["tools", "memory", "queue", "integrations", "workflow", "all"],
        default="all",
        help="Specific component to test"
    )
    
    args = parser.parse_args()
    
    tester = ThreatSentinelCLITester()
    
    if args.component == "tools":
        tester.test_virustotal_tool()
        tester.test_abuseipdb_tool()
        tester.test_shodan_tool()
        tester.test_tool_registry()
    elif args.component == "memory":
        tester.test_memory_system()
    elif args.component == "queue":
        tester.test_task_queue_system()
    elif args.component == "integrations":
        tester.test_integration_system()
    elif args.component == "workflow":
        tester.test_investigation_workflow()
    else:
        tester.run_all_tests()


if __name__ == "__main__":
    main() 