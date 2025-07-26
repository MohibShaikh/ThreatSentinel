"""
Unit tests for agent/memory.py

Tests the agent's memory system including investigation storage,
pattern analysis, and cross-session memory retention.
"""

import pytest
import asyncio
import tempfile
import os
import sqlite3
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from agent.memory import (
    AgentMemory, InvestigationMemory, PatternInsight,
    InvestigationContext
)
from agent.planner import SecurityEvent, ThreatIntelligence, RiskAssessment


class TestInvestigationMemory:
    """Test InvestigationMemory dataclass"""
    
    def test_investigation_memory_creation(self):
        """Test creating InvestigationMemory instance"""
        memory = InvestigationMemory(
            investigation_id="test_123",
            event_type="suspicious_ip",
            indicators=["192.168.1.1"],
            outcome="malicious",
            confidence=0.85,
            timestamp=datetime.now()
        )
        
        assert memory.investigation_id == "test_123"
        assert memory.event_type == "suspicious_ip"
        assert "192.168.1.1" in memory.indicators
        assert memory.outcome == "malicious"
        assert memory.confidence == 0.85


class TestPatternInsight:
    """Test PatternInsight dataclass"""
    
    def test_pattern_insight_creation(self):
        """Test creating PatternInsight instance"""
        insight = PatternInsight(
            pattern_type="frequency_anomaly",
            description="Unusual login frequency detected",
            confidence=0.75,
            examples=["login_burst_1", "login_burst_2"]
        )
        
        assert insight.pattern_type == "frequency_anomaly"
        assert "frequency" in insight.description
        assert insight.confidence == 0.75
        assert len(insight.examples) == 2


class TestAgentMemory:
    """Test AgentMemory functionality"""
    
    @pytest.fixture
    def temp_memory_dir(self):
        """Create temporary directory for test databases"""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    @pytest.fixture
    def memory(self, temp_memory_dir):
        """Create AgentMemory instance with temporary storage"""
        return AgentMemory(storage_path=temp_memory_dir)
    
    @pytest.fixture
    def sample_context(self):
        """Create sample investigation context for testing"""
        event = SecurityEvent(
            event_id="test_001",
            event_type="suspicious_ip",
            source_ip="192.168.1.100",
            timestamp=datetime.now(),
            severity="medium",
            description="Suspicious IP activity detected"
        )
        
        threat_intel = ThreatIntelligence(
            source="virustotal",
            reputation_score=0.75,
            indicators=["Known malicious IP", "Associated with malware"],
            raw_data={"vt_data": "test"}
        )
        
        risk = RiskAssessment(
            risk_level="high",
            risk_score=0.8,
            factors=["High reputation score", "Multiple indicators"],
            confidence=0.9
        )
        
        context = InvestigationContext(
            event=event,
            threat_intelligence=[threat_intel],
            risk_assessment=risk
        )
        
        return context
    
    def test_memory_initialization(self, memory):
        """Test memory system initialization"""
        assert memory.db_path.endswith("investigations.db")
        assert memory.patterns_file.endswith("patterns.json")
        assert os.path.exists(memory.db_path)
    
    @pytest.mark.asyncio
    async def test_store_investigation(self, memory, sample_context):
        """Test storing investigation in memory"""
        investigation_id = "test_investigation_001"
        
        await memory.store_investigation(investigation_id, sample_context, "malicious", 0.85)
        
        # Verify data was stored
        conn = sqlite3.connect(memory.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM investigations WHERE investigation_id = ?", (investigation_id,))
        result = cursor.fetchone()
        conn.close()
        
        assert result is not None
        assert result[1] == investigation_id  # investigation_id column
        assert result[2] == "suspicious_ip"   # event_type column
    
    @pytest.mark.asyncio
    async def test_find_similar_events(self, memory, sample_context):
        """Test finding similar events from memory"""
        # Store a few investigations first
        await memory.store_investigation("test_001", sample_context, "malicious", 0.85)
        
        # Modify context slightly for second investigation
        sample_context.event.source_ip = "192.168.1.101"
        await memory.store_investigation("test_002", sample_context, "benign", 0.3)
        
        # Find similar events
        similar = await memory.find_similar_events(sample_context.event, limit=5)
        
        assert len(similar) >= 1
        assert similar[0].event_type == "suspicious_ip"
    
    @pytest.mark.asyncio
    async def test_update_investigation_outcome(self, memory, sample_context):
        """Test updating investigation outcome"""
        investigation_id = "test_update_001"
        
        # Store initial investigation
        await memory.store_investigation(investigation_id, sample_context, "unknown", 0.5)
        
        # Update outcome
        await memory.update_investigation_outcome(investigation_id, "malicious", 0.9)
        
        # Verify update
        conn = sqlite3.connect(memory.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT outcome, confidence FROM investigations WHERE investigation_id = ?", 
                      (investigation_id,))
        result = cursor.fetchone()
        conn.close()
        
        assert result[0] == "malicious"
        assert abs(result[1] - 0.9) < 0.01
    
    @pytest.mark.asyncio
    async def test_get_pattern_insights(self, memory, sample_context):
        """Test pattern insight generation"""
        # Store multiple similar investigations to create patterns
        for i in range(5):
            context_copy = sample_context
            context_copy.event.source_ip = f"192.168.1.{100 + i}"
            context_copy.event.event_id = f"test_{i:03d}"
            await memory.store_investigation(f"investigation_{i:03d}", context_copy, "malicious", 0.8)
        
        insights = await memory.get_pattern_insights(sample_context.event)
        
        assert len(insights) > 0
        # Should detect frequency pattern from multiple similar events
        frequency_insights = [i for i in insights if i.pattern_type == "frequency_anomaly"]
        assert len(frequency_insights) > 0
    
    @pytest.mark.asyncio
    async def test_get_memory_stats(self, memory, sample_context):
        """Test memory statistics retrieval"""
        # Store some investigations
        for i in range(3):
            await memory.store_investigation(f"test_{i}", sample_context, "malicious", 0.8)
        
        stats = await memory.get_memory_stats()
        
        assert "total_investigations" in stats
        assert "event_types" in stats
        assert "outcomes" in stats
        assert stats["total_investigations"] >= 3
    
    @pytest.mark.asyncio
    async def test_cleanup_old_memories(self, memory, sample_context):
        """Test cleanup of old investigation memories"""
        # Store old investigation (simulate old timestamp)
        old_timestamp = datetime.now() - timedelta(days=200)
        
        conn = sqlite3.connect(memory.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO investigations 
            (investigation_id, event_type, indicators, outcome, confidence, timestamp, context_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, ("old_test", "suspicious_ip", "192.168.1.1", "malicious", 0.8, 
              old_timestamp.isoformat(), "test_hash"))
        conn.commit()
        conn.close()
        
        # Store recent investigation
        await memory.store_investigation("recent_test", sample_context, "malicious", 0.8)
        
        # Cleanup old memories (older than 180 days)
        deleted_count = await memory.cleanup_old_memories(days=180)
        
        assert deleted_count >= 1
        
        # Verify old investigation was deleted
        conn = sqlite3.connect(memory.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM investigations WHERE investigation_id = ?", ("old_test",))
        count = cursor.fetchone()[0]
        conn.close()
        
        assert count == 0
    
    def test_generate_embedding_hash(self, memory):
        """Test embedding hash generation for events"""
        event1 = SecurityEvent(
            event_id="test_1",
            event_type="suspicious_ip",
            source_ip="192.168.1.1",
            timestamp=datetime.now(),
            severity="high",
            description="Test event"
        )
        
        event2 = SecurityEvent(
            event_id="test_2",
            event_type="suspicious_ip", 
            source_ip="192.168.1.1",
            timestamp=datetime.now(),
            severity="high",
            description="Test event"
        )
        
        hash1 = memory._generate_embedding_hash(event1)
        hash2 = memory._generate_embedding_hash(event2)
        
        # Same events should produce same hash
        assert hash1 == hash2
        
        # Different event should produce different hash
        event2.source_ip = "192.168.1.2"
        hash3 = memory._generate_embedding_hash(event2)
        assert hash1 != hash3
    
    def test_calculate_similarity(self, memory):
        """Test similarity calculation between events"""
        event1 = SecurityEvent(
            event_id="test_1",
            event_type="suspicious_ip",
            source_ip="192.168.1.1",
            timestamp=datetime.now(),
            severity="high",
            description="Suspicious activity"
        )
        
        event2 = SecurityEvent(
            event_id="test_2",
            event_type="suspicious_ip",
            source_ip="192.168.1.2", 
            timestamp=datetime.now(),
            severity="high",
            description="Suspicious activity"
        )
        
        similarity = memory._calculate_similarity(event1, event2)
        
        # Similar events should have high similarity
        assert similarity > 0.5
        
        # Completely different event
        event3 = SecurityEvent(
            event_id="test_3",
            event_type="malware_detection",
            source_ip="10.0.0.1",
            timestamp=datetime.now(),
            severity="low",
            description="Different activity"
        )
        
        similarity2 = memory._calculate_similarity(event1, event3)
        assert similarity2 < similarity  # Should be less similar
    
    @pytest.mark.asyncio
    async def test_pattern_file_operations(self, memory):
        """Test pattern file save/load operations"""
        # Create test patterns
        patterns = [
            PatternInsight(
                pattern_type="test_pattern",
                description="Test pattern description",
                confidence=0.8,
                examples=["example1", "example2"]
            )
        ]
        
        # Save patterns
        await memory._save_patterns(patterns)
        
        # Verify file was created and contains correct data
        assert os.path.exists(memory.patterns_file)
        
        with open(memory.patterns_file, 'r') as f:
            data = json.load(f)
        
        assert len(data) == 1
        assert data[0]["pattern_type"] == "test_pattern"
        assert data[0]["confidence"] == 0.8
    
    @pytest.mark.asyncio
    async def test_concurrent_memory_operations(self, memory, sample_context):
        """Test concurrent memory operations"""
        # Create multiple concurrent store operations
        tasks = []
        for i in range(10):
            context_copy = sample_context
            context_copy.event.event_id = f"concurrent_{i:03d}"
            task = memory.store_investigation(f"concurrent_{i:03d}", context_copy, "malicious", 0.8)
            tasks.append(task)
        
        # Execute all tasks concurrently
        await asyncio.gather(*tasks)
        
        # Verify all investigations were stored
        stats = await memory.get_memory_stats()
        assert stats["total_investigations"] >= 10


class TestMemoryIntegration:
    """Integration tests for memory system"""
    
    @pytest.mark.asyncio
    async def test_memory_persistence_across_instances(self, temp_memory_dir):
        """Test that memory persists across different AgentMemory instances"""
        # Create first memory instance and store data
        memory1 = AgentMemory(storage_path=temp_memory_dir)
        
        event = SecurityEvent(
            event_id="persistence_test",
            event_type="suspicious_ip",
            source_ip="192.168.1.1",
            timestamp=datetime.now(),
            severity="high",
            description="Test persistence"
        )
        
        context = InvestigationContext(event=event)
        await memory1.store_investigation("persist_001", context, "malicious", 0.9)
        
        # Create second memory instance (simulating restart)
        memory2 = AgentMemory(storage_path=temp_memory_dir)
        
        # Verify data persists
        similar = await memory2.find_similar_events(event, limit=5)
        assert len(similar) >= 1
        assert similar[0].investigation_id == "persist_001"
    
    @pytest.mark.asyncio 
    async def test_memory_with_real_investigation_flow(self, temp_memory_dir):
        """Test memory system with realistic investigation workflow"""
        memory = AgentMemory(storage_path=temp_memory_dir)
        
        # Simulate investigation sequence
        event = SecurityEvent(
            event_id="real_flow_001",
            event_type="suspicious_ip",
            source_ip="10.0.0.100",
            timestamp=datetime.now(),
            severity="medium",
            description="Repeated failed login attempts"
        )
        
        # Initial investigation
        context = InvestigationContext(event=event)
        await memory.store_investigation("flow_001", context, "unknown", 0.5)
        
        # Find similar events (should be empty initially)
        similar = await memory.find_similar_events(event, limit=5)
        assert len(similar) == 1  # Only the one we just stored
        
        # Update after further investigation
        await memory.update_investigation_outcome("flow_001", "malicious", 0.85)
        
        # Store related event
        event2 = SecurityEvent(
            event_id="real_flow_002",
            event_type="suspicious_ip",
            source_ip="10.0.0.101",
            timestamp=datetime.now(),
            severity="medium", 
            description="Repeated failed login attempts"
        )
        
        context2 = InvestigationContext(event=event2)
        await memory.store_investigation("flow_002", context2, "malicious", 0.9)
        
        # Now similar events should return both
        similar = await memory.find_similar_events(event, limit=5)
        assert len(similar) >= 2
        
        # Generate insights (should detect pattern)
        insights = await memory.get_pattern_insights(event)
        assert len(insights) > 0


# CLI Mock Demonstrations
class TestMemoryCLIMockInteractions:
    """Mock CLI interactions for memory system testing"""
    
    @pytest.mark.mock
    def test_memory_stats_cli_mock(self):
        """Mock CLI interaction for memory statistics"""
        print("\n=== Memory Stats CLI Mock Demo ===")
        print("Command: python -m agent.memory stats")
        print("Response:")
        print(json.dumps({
            "total_investigations": 150,
            "event_types": {
                "suspicious_ip": 45,
                "malware_detection": 32,
                "phishing_attempt": 28,
                "data_exfiltration": 25,
                "brute_force": 20
            },
            "outcomes": {
                "malicious": 89,
                "benign": 45,
                "unknown": 16
            },
            "avg_confidence": 0.78,
            "storage_size_mb": 2.4,
            "oldest_record": "2024-01-15T10:30:00Z",
            "newest_record": "2024-07-27T14:25:00Z"
        }, indent=2))
    
    @pytest.mark.mock
    def test_memory_search_cli_mock(self):
        """Mock CLI interaction for memory search"""
        print("\n=== Memory Search CLI Mock Demo ===")
        print("Command: python -m agent.memory search --event-type suspicious_ip --limit 3")
        print("Response:")
        print(json.dumps({
            "total_found": 45,
            "results": [
                {
                    "investigation_id": "inv_2024_0145",
                    "event_type": "suspicious_ip",
                    "indicators": ["192.168.1.100", "failed_login"],
                    "outcome": "malicious",
                    "confidence": 0.85,
                    "timestamp": "2024-07-26T15:30:00Z",
                    "similarity": 0.92
                },
                {
                    "investigation_id": "inv_2024_0138",
                    "event_type": "suspicious_ip", 
                    "indicators": ["10.0.0.50", "port_scan"],
                    "outcome": "malicious",
                    "confidence": 0.78,
                    "timestamp": "2024-07-25T09:15:00Z",
                    "similarity": 0.87
                },
                {
                    "investigation_id": "inv_2024_0125",
                    "event_type": "suspicious_ip",
                    "indicators": ["172.16.0.25", "unusual_traffic"],
                    "outcome": "benign", 
                    "confidence": 0.65,
                    "timestamp": "2024-07-20T11:45:00Z",
                    "similarity": 0.74
                }
            ]
        }, indent=2))
    
    @pytest.mark.mock
    def test_memory_patterns_cli_mock(self):
        """Mock CLI interaction for pattern insights"""
        print("\n=== Memory Patterns CLI Mock Demo ===")
        print("Command: python -m agent.memory patterns --pattern-type frequency_anomaly")
        print("Response:")
        print(json.dumps({
            "pattern_insights": [
                {
                    "pattern_type": "frequency_anomaly",
                    "description": "Burst of 15+ login attempts from same IP range within 10 minutes",
                    "confidence": 0.89,
                    "examples": ["inv_2024_0145", "inv_2024_0142", "inv_2024_0139"],
                    "first_seen": "2024-07-15T08:30:00Z",
                    "last_seen": "2024-07-26T15:30:00Z",
                    "frequency": 12
                },
                {
                    "pattern_type": "time_based_anomaly",
                    "description": "Suspicious activities occurring consistently between 2-4 AM",
                    "confidence": 0.76,
                    "examples": ["inv_2024_0098", "inv_2024_0115", "inv_2024_0133"],
                    "first_seen": "2024-06-20T02:15:00Z",
                    "last_seen": "2024-07-25T03:45:00Z",
                    "frequency": 8
                }
            ],
            "total_patterns": 2,
            "analysis_timestamp": "2024-07-27T14:30:00Z"
        }, indent=2)) 