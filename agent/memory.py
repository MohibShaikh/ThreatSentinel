"""
SOC Agent Memory - investigation history and pattern learning.

Similarity search is a local TF-IDF + cosine model built with the standard
library only, blended with exact IOC overlap. No embeddings service and no
API keys.
"""

import hashlib
import json
import logging
import math
import re
import sqlite3
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set

from .detectors import extract_iocs

CANDIDATE_LIMIT = 500
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_\-\.]{1,40}")
_STOPWORDS = {
    "the", "and", "for", "from", "with", "this", "that", "was", "were", "are", "has", "have",
    "not", "but", "you", "your", "into", "via", "of", "to", "in", "on", "at", "by", "an", "is",
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ensure_aware(dt: Optional[datetime]) -> datetime:
    if dt is None:
        return utcnow()
    if isinstance(dt, str):
        dt = datetime.fromisoformat(dt)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass
class InvestigationMemory:
    """Structured memory of a security investigation"""
    event_id: str
    event_type: str
    event_data: Dict[str, Any]
    risk_score: float
    risk_level: str
    intelligence_sources: List[str]
    actions_taken: List[Dict[str, Any]]
    investigation_duration: float
    timestamp: datetime
    outcome: Optional[str] = None
    false_positive: bool = False
    similarity: float = 0.0
    tags: Optional[List[str]] = None

    def __post_init__(self):
        self.timestamp = ensure_aware(self.timestamp)
        if self.tags is None:
            self.tags = []


@dataclass
class PatternInsight:
    """Pattern-based insight derived from historical data"""
    pattern_type: str
    description: str
    confidence: float
    supporting_events: List[str]
    recommendation: str


def _tokens_from_text(text: str, prefix: str = "") -> List[str]:
    out = []
    for tok in _TOKEN_RE.findall(text.lower()):
        if tok in _STOPWORDS or tok.isdigit():
            continue
        out.append(f"{prefix}{tok}" if prefix else tok)
        if len(out) >= 200:
            break
    return out


def featurize(event_data: Dict[str, Any], tags: Optional[List[str]] = None) -> List[str]:
    """Turn an event into a bag of tokens for TF-IDF."""
    tokens: List[str] = []
    event_type = str(event_data.get("event_type", "unknown"))
    tokens += [f"type:{event_type}"] * 3
    for key in ("source_ip", "destination_ip", "dest_ip", "user_id", "username", "file_hash", "file_name"):
        value = event_data.get(key)
        if value:
            tokens += [f"{key}:{str(value).lower()}"] * 2
    if event_data.get("user_agent"):
        tokens += _tokens_from_text(str(event_data["user_agent"]), "ua:")
    if event_data.get("url"):
        tokens += _tokens_from_text(str(event_data["url"]), "url:")
    if event_data.get("raw_data"):
        tokens += _tokens_from_text(str(event_data["raw_data"]))

    def _walk(obj: Any, path: str, depth: int) -> None:
        if depth > 4:
            return
        if isinstance(obj, dict):
            for k, v in list(obj.items())[:100]:
                key = str(k).lower()
                tokens.append(f"key:{key}")
                _walk(v, key, depth + 1)
        elif isinstance(obj, list):
            for v in obj[:50]:
                _walk(v, path, depth + 1)
        elif isinstance(obj, bool):
            if obj:
                tokens.append(f"{path}:true")
        elif isinstance(obj, (int, float)):
            magnitude = 0 if obj <= 0 else int(math.log10(obj + 1))
            tokens.append(f"{path}:mag{magnitude}")
        elif isinstance(obj, str):
            tokens.extend(_tokens_from_text(obj))

    _walk(event_data.get("payload", {}), "payload", 0)
    for tag in tags or event_data.get("_tags", []) or []:
        tokens += [f"tag:{str(tag).lower()}"] * 2
    return tokens


def _ioc_set(event_data: Dict[str, Any]) -> Set[str]:
    iocs = extract_iocs(event_data)
    out: Set[str] = set()
    for kind in ("ips", "urls", "domains", "md5", "sha1", "sha256", "cves", "emails"):
        out.update(f"{kind}:{v}" for v in iocs.get(kind, []))
    return out


class TfidfIndex:
    """Tiny TF-IDF model over a candidate set, cosine similarity."""

    def __init__(self, documents: List[List[str]]):
        self.n = len(documents)
        df: Counter = Counter()
        for doc in documents:
            df.update(set(doc))
        self.idf = {t: math.log((self.n + 1) / (c + 1)) + 1.0 for t, c in df.items()}

    def vector(self, tokens: List[str]) -> Dict[str, float]:
        if not tokens:
            return {}
        counts = Counter(tokens)
        total = len(tokens)
        default_idf = math.log(self.n + 1) + 1.0
        return {t: (c / total) * self.idf.get(t, default_idf) for t, c in counts.items()}

    @staticmethod
    def cosine(a: Dict[str, float], b: Dict[str, float]) -> float:
        if not a or not b:
            return 0.0
        if len(a) > len(b):
            a, b = b, a
        dot = sum(w * b.get(t, 0.0) for t, w in a.items())
        na = math.sqrt(sum(w * w for w in a.values()))
        nb = math.sqrt(sum(w * w for w in b.values()))
        return dot / (na * nb) if na and nb else 0.0


class AgentMemory:
    """Persistent investigation memory with local similarity search."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        self.memory_dir = Path(self.config.get("memory_dir", "data/memory"))
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.memory_dir / "investigations.db"
        self.patterns_path = self.memory_dir / "patterns.json"

        self.max_memories = int(self.config.get("max_memories", 10000))
        self.similarity_threshold = float(self.config.get("similarity_threshold", 0.35))
        self.pattern_min_occurrences = int(self.config.get("pattern_min_occurrences", 3))
        self.candidate_limit = int(self.config.get("candidate_limit", CANDIDATE_LIMIT))

        self._init_database()
        self._load_patterns()
        self.logger.info(f"Agent memory initialized at {self.memory_dir}")

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_database(self):
        with self._db() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute('''
                CREATE TABLE IF NOT EXISTS investigations (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    event_data TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    intelligence_sources TEXT NOT NULL,
                    actions_taken TEXT NOT NULL,
                    investigation_duration REAL NOT NULL,
                    timestamp TEXT NOT NULL,
                    outcome TEXT,
                    false_positive INTEGER DEFAULT 0,
                    embedding_hash TEXT,
                    tags TEXT
                )
            ''')
            columns = {row[1] for row in conn.execute("PRAGMA table_info(investigations)")}
            if "tags" not in columns:
                conn.execute("ALTER TABLE investigations ADD COLUMN tags TEXT")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON investigations(event_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON investigations(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_level ON investigations(risk_level)")

    def _load_patterns(self):
        self.patterns: Dict[str, Any] = {}
        if self.patterns_path.exists():
            try:
                self.patterns = json.loads(self.patterns_path.read_text())
                self.logger.info(f"Loaded {len(self.patterns)} learned patterns")
            except Exception as e:
                self.logger.error(f"Failed to load patterns: {e}")
                self.patterns = {}

    def _save_patterns(self):
        try:
            tmp = self.patterns_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self.patterns, indent=2, default=str))
            tmp.replace(self.patterns_path)
        except Exception as e:
            self.logger.error(f"Failed to save patterns: {e}")

    @staticmethod
    def _context_tags(context) -> List[str]:
        tags: Set[str] = set()
        detection = getattr(context, "detection_assessment", None) or {}
        if isinstance(detection, dict):
            for key in ("mitre_attack", "mitre_atlas", "owasp_llm"):
                tags.update(detection.get(key, []) or [])
        return sorted(tags)

    async def store_investigation(self, context) -> bool:
        try:
            risk = getattr(context, "risk_assessment", None) or {}
            intel = getattr(context, "intelligence_data", None) or {}
            start = ensure_aware(getattr(context, "start_time", None))
            memory = InvestigationMemory(
                event_id=context.event_id,
                event_type=context.event_data.get("event_type", "unknown"),
                event_data=context.event_data,
                risk_score=float(risk.get("risk_score", 0.0) or 0.0),
                risk_level=risk.get("risk_level", "low"),
                intelligence_sources=intel.get("sources", []),
                actions_taken=getattr(context, "recommended_actions", None) or [],
                investigation_duration=(utcnow() - start).total_seconds(),
                timestamp=start,
                false_positive=bool(getattr(context, "false_positive", False)),
                tags=self._context_tags(context),
            )

            with self._db() as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO investigations
                    (event_id, event_type, event_data, risk_score, risk_level,
                     intelligence_sources, actions_taken, investigation_duration,
                     timestamp, false_positive, embedding_hash, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    memory.event_id, memory.event_type,
                    json.dumps(memory.event_data, default=str),
                    memory.risk_score, memory.risk_level,
                    json.dumps(memory.intelligence_sources, default=str),
                    json.dumps(memory.actions_taken, default=str),
                    memory.investigation_duration, memory.timestamp.isoformat(),
                    int(memory.false_positive),
                    self._generate_embedding_hash(memory.event_data),
                    json.dumps(memory.tags),
                ))
                if self.max_memories > 0:
                    conn.execute('''
                        DELETE FROM investigations WHERE event_id IN (
                            SELECT event_id FROM investigations
                            ORDER BY timestamp DESC LIMIT -1 OFFSET ?
                        )
                    ''', (self.max_memories,))

            await self._update_patterns(memory)
            self.logger.info(f"Stored investigation memory: {memory.event_id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to store investigation: {e}")
            return False

    def _row_to_memory(self, row: Dict[str, Any], similarity: float = 0.0) -> InvestigationMemory:
        return InvestigationMemory(
            event_id=row["event_id"],
            event_type=row["event_type"],
            event_data=json.loads(row["event_data"]),
            risk_score=row["risk_score"],
            risk_level=row["risk_level"],
            intelligence_sources=json.loads(row["intelligence_sources"]),
            actions_taken=json.loads(row["actions_taken"]),
            investigation_duration=row["investigation_duration"],
            timestamp=row["timestamp"],
            outcome=row.get("outcome"),
            false_positive=bool(row.get("false_positive", 0)),
            similarity=round(similarity, 4),
            tags=json.loads(row["tags"]) if row.get("tags") else [],
        )

    async def find_similar_events(self, event_data: Dict[str, Any],
                                  limit: int = 10,
                                  time_window_days: int = 90,
                                  exclude_event_id: Optional[str] = None) -> List[InvestigationMemory]:
        """Rank recent investigations by TF-IDF cosine blended with IOC overlap."""
        cutoff = (utcnow() - timedelta(days=time_window_days)).isoformat()
        with self._db() as conn:
            conn.row_factory = sqlite3.Row
            rows = [dict(r) for r in conn.execute('''
                SELECT * FROM investigations
                WHERE timestamp > ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (cutoff, self.candidate_limit)).fetchall()]
        if exclude_event_id:
            rows = [r for r in rows if r["event_id"] != exclude_event_id]
        if not rows:
            return []

        stored = [json.loads(r["event_data"]) for r in rows]
        stored_tags = [json.loads(r["tags"]) if r.get("tags") else [] for r in rows]
        docs = [featurize(d, t) for d, t in zip(stored, stored_tags, strict=True)]
        query_tokens = featurize(event_data)
        index = TfidfIndex(docs + [query_tokens])
        query_vec = index.vector(query_tokens)
        query_iocs = _ioc_set(event_data)

        scored = []
        for row, data, tokens in zip(rows, stored, docs, strict=True):
            similarity = self._blend(index.cosine(query_vec, index.vector(tokens)), query_iocs, _ioc_set(data))
            if similarity >= self.similarity_threshold:
                scored.append((similarity, row))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        results = [self._row_to_memory(row, sim) for sim, row in scored[:limit]]
        self.logger.debug(f"Found {len(results)} similar events from {len(rows)} candidates")
        return results

    @staticmethod
    def _blend(cosine: float, iocs_a: Set[str], iocs_b: Set[str]) -> float:
        if iocs_a and iocs_b:
            overlap = len(iocs_a & iocs_b) / len(iocs_a | iocs_b)
            return 0.7 * cosine + 0.3 * overlap
        return cosine

    async def get_pattern_insights(self, event_data: Dict[str, Any]) -> List[PatternInsight]:
        insights: List[PatternInsight] = []
        event_type = event_data.get("event_type", "unknown")

        for pattern_key, pattern_data in self.patterns.items():
            if pattern_key != event_type and "global" not in pattern_key:
                continue

            ip = event_data.get("source_ip")
            ip_stats = (pattern_data.get("ip_patterns") or {}).get(ip) if ip else None
            if ip_stats:
                fp = ip_stats.get("false_positive_count", 0)
                insights.append(PatternInsight(
                    pattern_type="ip_frequency",
                    description=(f"IP {ip} seen {ip_stats['count']} times before "
                                 f"(avg risk {ip_stats.get('avg_risk', 0):.2f}"
                                 + (f", {fp} marked false positive" if fp else "") + ")"),
                    confidence=min(ip_stats["count"] / 10.0, 1.0),
                    supporting_events=ip_stats.get("event_ids", [])[-10:],
                    recommendation=("Likely benign recurring source" if fp and fp * 2 >= ip_stats["count"]
                                    else "Consider blocking if count > 5 and risk_score > 0.6"),
                ))

            hour_stats = (pattern_data.get("time_patterns") or {}).get(str(utcnow().hour), {})
            if hour_stats and hour_stats.get("risk_multiplier", 1.0) > 1.2:
                insights.append(PatternInsight(
                    pattern_type="temporal_anomaly",
                    description=(f"Activity at {utcnow().hour}:00 UTC is "
                                 f"{hour_stats['risk_multiplier']:.1f}x more likely to be malicious"),
                    confidence=hour_stats.get("confidence", 0.5),
                    supporting_events=hour_stats.get("event_ids", [])[-10:],
                    recommendation="Increase monitoring during off-hours activity",
                ))

            if "payload" in event_data:
                payload = str(event_data["payload"]).lower()
                for pattern, stats in (pattern_data.get("payload_patterns") or {}).items():
                    if pattern.lower() in payload and "confidence" in stats:
                        insights.append(PatternInsight(
                            pattern_type="payload_pattern",
                            description=f"Payload contains historically risky keyword: {pattern}",
                            confidence=stats.get("confidence", 0.5),
                            supporting_events=stats.get("event_ids", [])[-10:],
                            recommendation=stats.get("recommendation", "Investigate"),
                        ))
        return insights

    async def update_investigation_outcome(self, event_id: str, outcome: str,
                                           false_positive: bool = False) -> bool:
        try:
            with self._db() as conn:
                conn.execute(
                    "UPDATE investigations SET outcome = ?, false_positive = ? WHERE event_id = ?",
                    (outcome, int(false_positive), event_id),
                )
            if false_positive:
                self._record_false_positive(event_id)
            self.logger.info(f"Updated outcome for {event_id}: {outcome}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to update investigation outcome: {e}")
            return False

    async def get_memory_stats(self) -> Dict[str, Any]:
        try:
            with self._db() as conn:
                total_count = conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
                type_counts = conn.execute(
                    "SELECT event_type, COUNT(*) FROM investigations GROUP BY event_type").fetchall()
                risk_counts = conn.execute(
                    "SELECT risk_level, COUNT(*) FROM investigations GROUP BY risk_level").fetchall()
                recent_cutoff = (utcnow() - timedelta(days=7)).isoformat()
                recent_count = conn.execute(
                    "SELECT COUNT(*) FROM investigations WHERE timestamp > ?", (recent_cutoff,)).fetchone()[0]
                avg_duration = conn.execute(
                    "SELECT AVG(investigation_duration) FROM investigations").fetchone()[0] or 0.0
                fp_count = conn.execute(
                    "SELECT COUNT(*) FROM investigations WHERE false_positive = 1").fetchone()[0]
            return {
                "total_investigations": total_count,
                "by_event_type": dict(type_counts),
                "by_risk_level": dict(risk_counts),
                "recent_activity_7_days": recent_count,
                "avg_investigation_duration_seconds": avg_duration,
                "false_positives": fp_count,
                "patterns_learned": len(self.patterns),
                "memory_dir": str(self.memory_dir),
            }
        except Exception as e:
            self.logger.error(f"Failed to get memory stats: {e}")
            return {}

    def _generate_embedding_hash(self, event_data: Dict[str, Any]) -> str:
        """Stable SHA-256 fingerprint of an event's identifying features."""
        features = {
            "event_type": event_data.get("event_type", ""),
            "source_ip": event_data.get("source_ip", ""),
            "user_agent": event_data.get("user_agent", ""),
            "payload_type": type(event_data.get("payload", {})).__name__,
        }
        return hashlib.sha256(json.dumps(features, sort_keys=True).encode()).hexdigest()

    def _calculate_similarity(self, event1: Dict[str, Any], event2: Dict[str, Any]) -> float:
        """Pairwise similarity using the same TF-IDF + IOC blend as search."""
        t1, t2 = featurize(event1), featurize(event2)
        index = TfidfIndex([t1, t2])
        return self._blend(index.cosine(index.vector(t1), index.vector(t2)), _ioc_set(event1), _ioc_set(event2))

    def _event_bucket(self, event_type: str) -> Dict[str, Any]:
        if event_type not in self.patterns:
            self.patterns[event_type] = {
                "ip_patterns": {}, "time_patterns": {}, "payload_patterns": {}, "risk_patterns": {},
                "false_positive_count": 0,
            }
        bucket = self.patterns[event_type]
        bucket.setdefault("false_positive_count", 0)
        return bucket

    async def _update_patterns(self, memory: InvestigationMemory):
        patterns = self._event_bucket(memory.event_type)
        high_risk = memory.risk_score > 0.6 and not memory.false_positive

        if memory.event_data.get("source_ip"):
            ip = memory.event_data["source_ip"]
            stats = patterns["ip_patterns"].setdefault(
                ip, {"count": 0, "total_risk": 0.0, "event_ids": [], "false_positive_count": 0})
            stats["count"] += 1
            stats["total_risk"] += 0.0 if memory.false_positive else memory.risk_score
            stats.setdefault("false_positive_count", 0)
            if memory.false_positive:
                stats["false_positive_count"] += 1
            stats["event_ids"] = (stats["event_ids"] + [memory.event_id])[-50:]
            stats["avg_risk"] = stats["total_risk"] / stats["count"]

        hour = str(memory.timestamp.hour)
        hour_pattern = patterns["time_patterns"].setdefault(
            hour, {"count": 0, "high_risk_count": 0, "event_ids": []})
        hour_pattern["count"] += 1
        hour_pattern["event_ids"] = (hour_pattern["event_ids"] + [memory.event_id])[-50:]
        if high_risk:
            hour_pattern["high_risk_count"] += 1
        if hour_pattern["count"] >= 3:
            risk_rate = hour_pattern["high_risk_count"] / hour_pattern["count"]
            hour_pattern["risk_multiplier"] = risk_rate / 0.3
            hour_pattern["confidence"] = min(hour_pattern["count"] / 10.0, 1.0)

        if "payload" in memory.event_data:
            payload = str(memory.event_data["payload"]).lower()
            for keyword in ("admin", "login", "password", "script", "eval", "exec", "cmd",
                            "ignore previous", "system prompt", "curl", "base64"):
                if keyword not in payload:
                    continue
                pdata = patterns["payload_patterns"].setdefault(
                    keyword, {"count": 0, "high_risk_count": 0, "event_ids": []})
                pdata["count"] += 1
                pdata["event_ids"] = (pdata["event_ids"] + [memory.event_id])[-50:]
                if high_risk:
                    pdata["high_risk_count"] += 1
                if pdata["count"] >= self.pattern_min_occurrences:
                    risk_rate = pdata["high_risk_count"] / pdata["count"]
                    pdata["confidence"] = risk_rate
                    pdata["recommendation"] = (
                        "Block immediately" if risk_rate > 0.8 else
                        "Investigate immediately" if risk_rate > 0.5 else
                        "Monitor closely"
                    )

        self._save_patterns()

    def _record_false_positive(self, event_id: str) -> None:
        with self._db() as conn:
            row = conn.execute("SELECT event_type, event_data FROM investigations WHERE event_id = ?",
                               (event_id,)).fetchone()
        if not row:
            return
        bucket = self._event_bucket(row[0])
        bucket["false_positive_count"] += 1
        ip = json.loads(row[1]).get("source_ip")
        if ip and ip in bucket["ip_patterns"]:
            stats = bucket["ip_patterns"][ip]
            stats["false_positive_count"] = stats.get("false_positive_count", 0) + 1
        self._save_patterns()

    async def mark_false_positive(self, investigation_id: str, notes: str = "") -> bool:
        try:
            with self._db() as conn:
                cur = conn.execute(
                    "UPDATE investigations SET false_positive = 1, outcome = ? WHERE event_id = ?",
                    (f"false_positive: {notes}", investigation_id),
                )
                updated = cur.rowcount
            if updated:
                self._record_false_positive(investigation_id)
            self.logger.info(f"Marked {investigation_id} as false positive")
            return True
        except Exception as e:
            self.logger.error(f"Failed to mark false positive: {e}")
            return False

    async def add_missed_indicators(self, investigation_id: str, indicators: list) -> bool:
        try:
            with self._db() as conn:
                row = conn.execute("SELECT event_data FROM investigations WHERE event_id = ?",
                                   (investigation_id,)).fetchone()
                if row:
                    data = json.loads(row[0])
                    data["missed_indicators"] = indicators
                    conn.execute("UPDATE investigations SET event_data = ? WHERE event_id = ?",
                                 (json.dumps(data, default=str), investigation_id))
            self.logger.info(f"Added {len(indicators)} missed indicators to {investigation_id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to add missed indicators: {e}")
            return False

    async def cleanup_old_memories(self, days_to_keep: int = 365) -> int:
        try:
            cutoff = (utcnow() - timedelta(days=days_to_keep)).isoformat()
            with self._db() as conn:
                deleted = conn.execute("DELETE FROM investigations WHERE timestamp < ?", (cutoff,)).rowcount
            self.logger.info(f"Cleaned up {deleted} old investigation memories")
            return deleted
        except Exception as e:
            self.logger.error(f"Failed to cleanup old memories: {e}")
            return 0
