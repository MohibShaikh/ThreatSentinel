"""
Unit tests for agent/memory.py
"""

import pytest
import tempfile
import sqlite3
from datetime import datetime, timedelta
from types import SimpleNamespace

from agent.memory import AgentMemory, InvestigationMemory, PatternInsight


class TestInvestigationMemory:
    def test_creation(self):
        mem = InvestigationMemory(
            event_id="evt_001",
            event_type="suspicious_ip",
            event_data={"source_ip": "1.2.3.4"},
            risk_score=0.8,
            risk_level="high",
            intelligence_sources=["virustotal"],
            actions_taken=[],
            investigation_duration=12.5,
            timestamp=datetime.now(),
        )
        assert mem.event_id == "evt_001"
        assert mem.risk_score == 0.8

    def test_timestamp_string_parsing(self):
        ts = "2024-07-01T12:00:00"
        mem = InvestigationMemory(
            event_id="evt_002",
            event_type="malware_detection",
            event_data={},
            risk_score=0.5,
            risk_level="medium",
            intelligence_sources=[],
            actions_taken=[],
            investigation_duration=5.0,
            timestamp=ts,
        )
        assert isinstance(mem.timestamp, datetime)


class TestPatternInsight:
    def test_creation(self):
        insight = PatternInsight(
            pattern_type="ip_frequency",
            description="IP seen 10 times",
            confidence=0.9,
            supporting_events=["evt_1", "evt_2"],
            recommendation="Block",
        )
        assert insight.confidence == 0.9
        assert len(insight.supporting_events) == 2


class TestAgentMemory:
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield d

    @pytest.fixture
    def memory(self, temp_dir):
        return AgentMemory({"memory_dir": temp_dir})

    def test_initialization(self, memory, temp_dir):
        assert (memory.memory_dir / "investigations.db").exists()

    @pytest.mark.asyncio
    async def test_store_investigation(self, memory):
        ctx = SimpleNamespace(
            event_id="evt_store_001",
            event_data={"event_type": "suspicious_ip", "source_ip": "10.0.0.1"},
            risk_assessment={"risk_score": 0.7, "risk_level": "high"},
            intelligence_data={"sources": ["vt"]},
            recommended_actions=[{"action_type": "BLOCK"}],
            start_time=datetime.utcnow(),
        )
        result = await memory.store_investigation(ctx)
        assert result is True

        with sqlite3.connect(memory.db_path) as conn:
            row = conn.execute(
                "SELECT event_type FROM investigations WHERE event_id = ?",
                ("evt_store_001",),
            ).fetchone()
        assert row[0] == "suspicious_ip"

    @pytest.mark.asyncio
    async def test_find_similar_events(self, memory):
        ctx = SimpleNamespace(
            event_id="evt_sim_001",
            event_data={"event_type": "suspicious_ip", "source_ip": "10.0.0.1"},
            risk_assessment={"risk_score": 0.6, "risk_level": "medium"},
            intelligence_data={"sources": []},
            recommended_actions=[],
            start_time=datetime.utcnow(),
        )
        await memory.store_investigation(ctx)

        similar = await memory.find_similar_events(
            {"event_type": "suspicious_ip", "source_ip": "10.0.0.1"}
        )
        assert len(similar) >= 1

    @pytest.mark.asyncio
    async def test_get_memory_stats(self, memory):
        ctx = SimpleNamespace(
            event_id="evt_stats_001",
            event_data={"event_type": "suspicious_ip", "source_ip": "1.1.1.1"},
            risk_assessment={"risk_score": 0.5, "risk_level": "medium"},
            intelligence_data={"sources": []},
            recommended_actions=[],
            start_time=datetime.utcnow(),
        )
        await memory.store_investigation(ctx)

        stats = await memory.get_memory_stats()
        assert stats["total_investigations"] >= 1

    @pytest.mark.asyncio
    async def test_update_investigation_outcome(self, memory):
        ctx = SimpleNamespace(
            event_id="evt_outcome_001",
            event_data={"event_type": "login_anomaly"},
            risk_assessment={"risk_score": 0.3, "risk_level": "low"},
            intelligence_data={"sources": []},
            recommended_actions=[],
            start_time=datetime.utcnow(),
        )
        await memory.store_investigation(ctx)
        result = await memory.update_investigation_outcome("evt_outcome_001", "benign")
        assert result is True

    @pytest.mark.asyncio
    async def test_mark_false_positive(self, memory):
        ctx = SimpleNamespace(
            event_id="evt_fp_001",
            event_data={"event_type": "suspicious_ip"},
            risk_assessment={"risk_score": 0.4, "risk_level": "medium"},
            intelligence_data={"sources": []},
            recommended_actions=[],
            start_time=datetime.utcnow(),
        )
        await memory.store_investigation(ctx)
        result = await memory.mark_false_positive("evt_fp_001", "false alarm")
        assert result is True

    @pytest.mark.asyncio
    async def test_cleanup_old_memories(self, memory):
        ctx = SimpleNamespace(
            event_id="evt_old_001",
            event_data={"event_type": "suspicious_ip"},
            risk_assessment={"risk_score": 0.5, "risk_level": "medium"},
            intelligence_data={"sources": []},
            recommended_actions=[],
            start_time=datetime.utcnow(),
        )
        await memory.store_investigation(ctx)

        old_ts = (datetime.utcnow() - timedelta(days=400)).isoformat()
        with sqlite3.connect(memory.db_path) as conn:
            conn.execute(
                "UPDATE investigations SET timestamp = ? WHERE event_id = ?",
                (old_ts, "evt_old_001"),
            )

        deleted = await memory.cleanup_old_memories(days_to_keep=365)
        assert deleted >= 1

    def test_generate_embedding_hash(self, memory):
        data1 = {"event_type": "suspicious_ip", "source_ip": "10.0.0.1"}
        data2 = {"event_type": "suspicious_ip", "source_ip": "10.0.0.1"}
        data3 = {"event_type": "malware_detection", "source_ip": "10.0.0.2"}

        h1 = memory._generate_embedding_hash(data1)
        h2 = memory._generate_embedding_hash(data2)
        h3 = memory._generate_embedding_hash(data3)

        assert h1 == h2
        assert h1 != h3

    def test_calculate_similarity(self, memory):
        e1 = {"event_type": "suspicious_ip", "source_ip": "10.0.0.1"}
        e2 = {"event_type": "suspicious_ip", "source_ip": "10.0.0.1"}
        e3 = {"event_type": "malware_detection", "source_ip": "192.168.1.1"}

        sim_same = memory._calculate_similarity(e1, e2)
        sim_diff = memory._calculate_similarity(e1, e3)
        assert sim_same > sim_diff
