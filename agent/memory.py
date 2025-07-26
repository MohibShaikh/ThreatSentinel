"""
SOC Agent Memory - Vector Memory and Pattern Learning System

This module implements the agent's memory system for storing investigation
histories, learning from patterns, and providing contextual intelligence
for future investigations.
"""

import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
import numpy as np
from collections import defaultdict, Counter


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
    
    def __post_init__(self):
        if isinstance(self.timestamp, str):
            self.timestamp = datetime.fromisoformat(self.timestamp)


@dataclass 
class PatternInsight:
    """Pattern-based insight derived from historical data"""
    pattern_type: str
    description: str
    confidence: float
    supporting_events: List[str]
    recommendation: str


class AgentMemory:
    """
    Vector Memory System for SOC Agent
    
    Provides persistent storage and retrieval of investigation histories,
    pattern recognition, and contextual learning capabilities.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Memory storage paths
        self.memory_dir = Path(config.get('memory_dir', 'data/memory'))
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        
        self.db_path = self.memory_dir / 'investigations.db'
        self.patterns_path = self.memory_dir / 'patterns.json'
        
        # Memory configuration
        self.max_memories = config.get('max_memories', 10000)
        self.similarity_threshold = config.get('similarity_threshold', 0.7)
        self.pattern_min_occurrences = config.get('pattern_min_occurrences', 3)
        
        # Initialize storage
        self._init_database()
        self._load_patterns()
        
        self.logger.info(f"Agent memory initialized at {self.memory_dir}")
    
    def _init_database(self):
        """Initialize SQLite database for investigation storage"""
        with sqlite3.connect(self.db_path) as conn:
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
                    embedding_hash TEXT
                )
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_event_type ON investigations(event_type)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_timestamp ON investigations(timestamp)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_risk_level ON investigations(risk_level)
            ''')
            
            conn.commit()
    
    def _load_patterns(self):
        """Load learned patterns from storage"""
        self.patterns = {}
        
        if self.patterns_path.exists():
            try:
                with open(self.patterns_path, 'r') as f:
                    self.patterns = json.load(f)
                self.logger.info(f"Loaded {len(self.patterns)} learned patterns")
            except Exception as e:
                self.logger.error(f"Failed to load patterns: {e}")
                self.patterns = {}
    
    def _save_patterns(self):
        """Save learned patterns to storage"""
        try:
            with open(self.patterns_path, 'w') as f:
                json.dump(self.patterns, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Failed to save patterns: {e}")
    
    async def store_investigation(self, context) -> bool:
        """
        Store completed investigation in memory
        
        Args:
            context: InvestigationContext from the planner
            
        Returns:
            bool: Success status
        """
        try:
            memory = InvestigationMemory(
                event_id=context.event_id,
                event_type=context.event_data.get('event_type', 'unknown'),
                event_data=context.event_data,
                risk_score=context.risk_assessment.get('risk_score', 0.0),
                risk_level=context.risk_assessment.get('risk_level', 'low'),
                intelligence_sources=context.intelligence_data.get('sources', []),
                actions_taken=context.recommended_actions or [],
                investigation_duration=(datetime.utcnow() - context.start_time).total_seconds(),
                timestamp=context.start_time
            )
            
            # Generate embedding hash for similarity matching
            embedding_hash = self._generate_embedding_hash(memory.event_data)
            
            # Store in database
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO investigations 
                    (event_id, event_type, event_data, risk_score, risk_level,
                     intelligence_sources, actions_taken, investigation_duration,
                     timestamp, embedding_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    memory.event_id,
                    memory.event_type,
                    json.dumps(memory.event_data),
                    memory.risk_score,
                    memory.risk_level,
                    json.dumps(memory.intelligence_sources),
                    json.dumps(memory.actions_taken, default=str),
                    memory.investigation_duration,
                    memory.timestamp.isoformat(),
                    embedding_hash
                ))
                conn.commit()
            
            # Update learned patterns
            await self._update_patterns(memory)
            
            self.logger.info(f"Stored investigation memory: {memory.event_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store investigation: {e}")
            return False
    
    async def find_similar_events(self, event_data: Dict[str, Any], 
                                limit: int = 10, 
                                time_window_days: int = 90) -> List[InvestigationMemory]:
        """
        Find similar events from memory based on event characteristics
        
        Args:
            event_data: Current event to find similarities for
            limit: Maximum number of similar events to return
            time_window_days: Only consider events within this time window
            
        Returns:
            List of similar investigation memories
        """
        try:
            target_hash = self._generate_embedding_hash(event_data)
            cutoff_date = (datetime.utcnow() - timedelta(days=time_window_days)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                # Find events with similar characteristics
                cursor = conn.execute('''
                    SELECT * FROM investigations 
                    WHERE timestamp > ? 
                    AND event_type = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (cutoff_date, event_data.get('event_type', 'unknown'), limit * 2))
                
                rows = cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]
            
            similar_events = []
            
            for row in rows:
                row_dict = dict(zip(columns, row))
                
                # Calculate similarity score
                stored_data = json.loads(row_dict['event_data'])
                similarity = self._calculate_similarity(event_data, stored_data)
                
                if similarity >= self.similarity_threshold:
                    memory = InvestigationMemory(
                        event_id=row_dict['event_id'],
                        event_type=row_dict['event_type'],
                        event_data=stored_data,
                        risk_score=row_dict['risk_score'],
                        risk_level=row_dict['risk_level'],
                        intelligence_sources=json.loads(row_dict['intelligence_sources']),
                        actions_taken=json.loads(row_dict['actions_taken']),
                        investigation_duration=row_dict['investigation_duration'],
                        timestamp=datetime.fromisoformat(row_dict['timestamp']),
                        outcome=row_dict.get('outcome'),
                        false_positive=bool(row_dict.get('false_positive', 0))
                    )
                    similar_events.append(memory)
                
                if len(similar_events) >= limit:
                    break
            
            self.logger.info(f"Found {len(similar_events)} similar events")
            return similar_events
            
        except Exception as e:
            self.logger.error(f"Failed to find similar events: {e}")
            return []
    
    async def get_pattern_insights(self, event_data: Dict[str, Any]) -> List[PatternInsight]:
        """
        Get pattern-based insights for the current event
        
        Args:
            event_data: Current event data
            
        Returns:
            List of relevant pattern insights
        """
        insights = []
        event_type = event_data.get('event_type', 'unknown')
        
        # Check for relevant patterns
        for pattern_key, pattern_data in self.patterns.items():
            if event_type in pattern_key or 'global' in pattern_key:
                
                # IP address patterns
                if 'source_ip' in event_data and 'ip_patterns' in pattern_data:
                    ip = event_data['source_ip']
                    if ip in pattern_data['ip_patterns']:
                        ip_stats = pattern_data['ip_patterns'][ip]
                        insights.append(PatternInsight(
                            pattern_type='ip_frequency',
                            description=f"IP {ip} has been seen {ip_stats['count']} times in past {ip_stats.get('time_span', 'unknown')}",
                            confidence=min(ip_stats['count'] / 10.0, 1.0),
                            supporting_events=ip_stats.get('event_ids', []),
                            recommendation="Consider blocking if count > 5 and risk_score > 0.6"
                        ))
                
                # Time-based patterns
                if 'time_patterns' in pattern_data:
                    current_hour = datetime.utcnow().hour
                    hour_stats = pattern_data['time_patterns'].get(str(current_hour), {})
                    if hour_stats and hour_stats.get('risk_multiplier', 1.0) > 1.2:
                        insights.append(PatternInsight(
                            pattern_type='temporal_anomaly',
                            description=f"Activity at {current_hour}:00 is {hour_stats['risk_multiplier']:.1f}x more likely to be malicious",
                            confidence=hour_stats.get('confidence', 0.5),
                            supporting_events=hour_stats.get('event_ids', []),
                            recommendation="Increase monitoring during off-hours activity"
                        ))
                
                # Payload patterns
                if 'payload' in event_data and 'payload_patterns' in pattern_data:
                    payload = str(event_data['payload'])
                    for pattern, pattern_stats in pattern_data['payload_patterns'].items():
                        if pattern.lower() in payload.lower():
                            insights.append(PatternInsight(
                                pattern_type='payload_pattern',
                                description=f"Payload contains known attack pattern: {pattern}",
                                confidence=pattern_stats.get('confidence', 0.8),
                                supporting_events=pattern_stats.get('event_ids', []),
                                recommendation=pattern_stats.get('recommendation', 'Block immediately')
                            ))
        
        return insights
    
    async def update_investigation_outcome(self, event_id: str, outcome: str, 
                                         false_positive: bool = False) -> bool:
        """
        Update the outcome of a stored investigation
        
        Args:
            event_id: Investigation ID to update
            outcome: Description of the final outcome
            false_positive: Whether this was determined to be a false positive
            
        Returns:
            bool: Success status
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    UPDATE investigations 
                    SET outcome = ?, false_positive = ?
                    WHERE event_id = ?
                ''', (outcome, int(false_positive), event_id))
                conn.commit()
            
            self.logger.info(f"Updated outcome for {event_id}: {outcome}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update investigation outcome: {e}")
            return False
    
    async def get_memory_stats(self) -> Dict[str, Any]:
        """Get statistics about stored memories"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Total investigations
                total_count = conn.execute('SELECT COUNT(*) FROM investigations').fetchone()[0]
                
                # By event type
                type_counts = conn.execute('''
                    SELECT event_type, COUNT(*) 
                    FROM investigations 
                    GROUP BY event_type
                ''').fetchall()
                
                # By risk level
                risk_counts = conn.execute('''
                    SELECT risk_level, COUNT(*) 
                    FROM investigations 
                    GROUP BY risk_level
                ''').fetchall()
                
                # Recent activity (last 7 days)
                recent_cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat()
                recent_count = conn.execute('''
                    SELECT COUNT(*) FROM investigations 
                    WHERE timestamp > ?
                ''', (recent_cutoff,)).fetchone()[0]
                
                # Average investigation duration
                avg_duration = conn.execute('''
                    SELECT AVG(investigation_duration) FROM investigations
                ''').fetchone()[0] or 0.0
            
            return {
                'total_investigations': total_count,
                'by_event_type': dict(type_counts),
                'by_risk_level': dict(risk_counts),
                'recent_activity_7_days': recent_count,
                'avg_investigation_duration_seconds': avg_duration,
                'patterns_learned': len(self.patterns),
                'memory_dir': str(self.memory_dir)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get memory stats: {e}")
            return {}
    
    def _generate_embedding_hash(self, event_data: Dict[str, Any]) -> str:
        """Generate a hash for event similarity matching"""
        # Extract key features for similarity
        features = {
            'event_type': event_data.get('event_type', ''),
            'source_ip': event_data.get('source_ip', ''),
            'user_agent': event_data.get('user_agent', ''),
            'payload_type': type(event_data.get('payload', {})).__name__,
        }
        
        # Create hash from normalized features
        feature_string = json.dumps(features, sort_keys=True)
        return hashlib.md5(feature_string.encode()).hexdigest()
    
    def _calculate_similarity(self, event1: Dict[str, Any], event2: Dict[str, Any]) -> float:
        """Calculate similarity score between two events"""
        score = 0.0
        factors = 0
        
        # Event type match (high weight)
        if event1.get('event_type') == event2.get('event_type'):
            score += 0.4
        factors += 0.4
        
        # IP address match
        if event1.get('source_ip') == event2.get('source_ip') and event1.get('source_ip'):
            score += 0.3
        factors += 0.3
        
        # User agent similarity
        ua1 = event1.get('user_agent', '')
        ua2 = event2.get('user_agent', '')
        if ua1 and ua2:
            # Simple string similarity
            similarity = len(set(ua1.split()) & set(ua2.split())) / len(set(ua1.split()) | set(ua2.split()))
            score += similarity * 0.2
        factors += 0.2
        
        # Payload characteristics
        p1 = event1.get('payload', {})
        p2 = event2.get('payload', {})
        if isinstance(p1, dict) and isinstance(p2, dict):
            common_keys = set(p1.keys()) & set(p2.keys())
            total_keys = set(p1.keys()) | set(p2.keys())
            if total_keys:
                payload_sim = len(common_keys) / len(total_keys)
                score += payload_sim * 0.1
        factors += 0.1
        
        return score / factors if factors > 0 else 0.0
    
    async def _update_patterns(self, memory: InvestigationMemory):
        """Update learned patterns based on new investigation"""
        event_type = memory.event_type
        
        # Initialize pattern storage for this event type
        if event_type not in self.patterns:
            self.patterns[event_type] = {
                'ip_patterns': {},
                'time_patterns': {},
                'payload_patterns': {},
                'risk_patterns': {}
            }
        
        patterns = self.patterns[event_type]
        
        # Update IP patterns
        if 'source_ip' in memory.event_data:
            ip = memory.event_data['source_ip']
            if ip not in patterns['ip_patterns']:
                patterns['ip_patterns'][ip] = {
                    'count': 0,
                    'total_risk': 0.0,
                    'event_ids': []
                }
            
            patterns['ip_patterns'][ip]['count'] += 1
            patterns['ip_patterns'][ip]['total_risk'] += memory.risk_score
            patterns['ip_patterns'][ip]['event_ids'].append(memory.event_id)
            patterns['ip_patterns'][ip]['avg_risk'] = (
                patterns['ip_patterns'][ip]['total_risk'] / patterns['ip_patterns'][ip]['count']
            )
        
        # Update time patterns
        hour = memory.timestamp.hour
        if str(hour) not in patterns['time_patterns']:
            patterns['time_patterns'][str(hour)] = {
                'count': 0,
                'high_risk_count': 0,
                'event_ids': []
            }
        
        patterns['time_patterns'][str(hour)]['count'] += 1
        patterns['time_patterns'][str(hour)]['event_ids'].append(memory.event_id)
        
        if memory.risk_score > 0.6:
            patterns['time_patterns'][str(hour)]['high_risk_count'] += 1
        
        # Calculate risk multiplier for this hour
        hour_pattern = patterns['time_patterns'][str(hour)]
        if hour_pattern['count'] >= 3:
            risk_rate = hour_pattern['high_risk_count'] / hour_pattern['count']
            # Compare to global average (simplified)
            global_risk_rate = 0.3  # Assume 30% baseline
            hour_pattern['risk_multiplier'] = risk_rate / global_risk_rate if global_risk_rate > 0 else 1.0
            hour_pattern['confidence'] = min(hour_pattern['count'] / 10.0, 1.0)
        
        # Update payload patterns
        if 'payload' in memory.event_data:
            payload = str(memory.event_data['payload']).lower()
            
            # Look for suspicious patterns in payload
            suspicious_keywords = ['admin', 'login', 'password', 'script', 'eval', 'exec', 'cmd']
            for keyword in suspicious_keywords:
                if keyword in payload:
                    if keyword not in patterns['payload_patterns']:
                        patterns['payload_patterns'][keyword] = {
                            'count': 0,
                            'high_risk_count': 0,
                            'event_ids': []
                        }
                    
                    patterns['payload_patterns'][keyword]['count'] += 1
                    patterns['payload_patterns'][keyword]['event_ids'].append(memory.event_id)
                    
                    if memory.risk_score > 0.6:
                        patterns['payload_patterns'][keyword]['high_risk_count'] += 1
                    
                    # Calculate confidence for this pattern
                    pattern_data = patterns['payload_patterns'][keyword]
                    if pattern_data['count'] >= self.pattern_min_occurrences:
                        risk_rate = pattern_data['high_risk_count'] / pattern_data['count']
                        pattern_data['confidence'] = risk_rate
                        pattern_data['recommendation'] = (
                            "Block immediately" if risk_rate > 0.8 else
                            "Investigate immediately" if risk_rate > 0.5 else
                            "Monitor closely"
                        )
        
        # Save updated patterns
        self._save_patterns()
        
        self.logger.debug(f"Updated patterns for {event_type}")
    
    async def cleanup_old_memories(self, days_to_keep: int = 365) -> int:
        """Clean up old memories to manage storage"""
        try:
            cutoff_date = (datetime.utcnow() - timedelta(days=days_to_keep)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    DELETE FROM investigations 
                    WHERE timestamp < ?
                ''', (cutoff_date,))
                deleted_count = cursor.rowcount
                conn.commit()
            
            self.logger.info(f"Cleaned up {deleted_count} old investigation memories")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old memories: {e}")
            return 0 