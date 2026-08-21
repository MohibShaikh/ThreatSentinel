"""
SOC Agent Planner - Core decision-making and orchestration engine

This module implements the main agent reasoning loop using a combination of
rule-based logic and LLM-powered decision making for complex scenarios.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

from .tools import ToolRegistry
from .memory import AgentMemory
from .reporter import IncidentReporter
from .action_logger import ActionLogger, ActionType, ActionStatus, LogLevel
from .integrations.registry import IntegrationRegistry
from .integrations.base import ActionType as IntegrationActionType
from .llm import create_llm_provider, build_analysis_prompt, BaseLLMProvider


class InvestigationPhase(Enum):
    """Phases of security incident investigation"""
    INITIAL_ASSESSMENT = "initial_assessment"
    INTELLIGENCE_GATHERING = "intelligence_gathering"
    RISK_ANALYSIS = "risk_analysis"
    ACTION_PLANNING = "action_planning"
    REPORTING = "reporting"
    MEMORY_UPDATE = "memory_update"


@dataclass
class InvestigationContext:
    """Context maintained throughout an investigation"""
    event_id: str
    event_data: Dict[str, Any]
    phase: InvestigationPhase
    intelligence_data: Dict[str, Any]
    risk_assessment: Optional[Dict[str, Any]] = None
    recommended_actions: List[Dict[str, Any]] = None
    actions_executed: List[Dict[str, Any]] = None
    reasoning_log: List[str] = None
    start_time: datetime = None
    phases_completed: List[str] = None

    def __post_init__(self):
        if self.reasoning_log is None:
            self.reasoning_log = []
        if self.start_time is None:
            self.start_time = datetime.utcnow()
        if self.phases_completed is None:
            self.phases_completed = []

    def complete_phase(self):
        """Mark the current phase as completed"""
        if self.phase and self.phase.value not in self.phases_completed:
            self.phases_completed.append(self.phase.value)


class SOCAgentPlanner:
    """
    Core SOC Agent Planner - Autonomous Security Incident Investigation

    This planner implements a sophisticated reasoning loop that:
    1. Assesses incoming security events
    2. Plans and executes tool usage for intelligence gathering
    3. Performs risk analysis with contextual reasoning
    4. Generates prioritized action recommendations
    5. Updates memory with learned patterns
    6. Triggers human review for high-risk/ambiguous cases

    The planner operates autonomously but escalates to human analysts
    when confidence thresholds are not met or risk levels are critical.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Initialize core components
        self.tools = ToolRegistry(config.get('api_keys', {}))
        self.memory = AgentMemory(config.get('memory', {}))
        self.reporter = IncidentReporter(config.get('reporting', {}))
        self.integrations = IntegrationRegistry(config.get('integrations_config', {}))

        # LLM provider for intelligent analysis (optional)
        self.llm: Optional[BaseLLMProvider] = None
        llm_config = config.get('llm', {})
        if llm_config.get('api_key'):
            try:
                self.llm = create_llm_provider(
                    provider=llm_config.get('provider', 'glm'),
                    api_key=llm_config['api_key'],
                    model=llm_config.get('model'),
                    config=llm_config,
                )
                self.logger.info(f"LLM enabled: {self.llm.provider_name}/{self.llm.model}")
            except Exception as e:
                self.logger.warning(f"Failed to initialize LLM: {e}")

        # Planning parameters
        self.confidence_threshold = config.get('confidence_threshold', 0.7)
        self.emergency_threshold = config.get('emergency_threshold', 0.8)
        # Added to the final score when no intel source answered, so an
        # agent that cannot see never scores as if it looked and saw clean.
        self.INTEL_UNCERTAINTY_FLOOR = 0.25
        self.max_investigation_time = config.get('max_investigation_time', 300)

        self.review_threshold = config.get('review_threshold', 0.6)
        self.escalation_rules = self._load_escalation_rules()
        self.audit_trail = []

        audit_config = config.get('audit', {})
        self.action_logger = ActionLogger(audit_config.get('db_path', 'data/action_logs.db'))

        self.logger.info("SOC Agent Planner initialized with human review capabilities")

    def _load_escalation_rules(self) -> List[Dict[str, Any]]:
        """Load escalation rules for human review"""
        default_rules = [
            {
                "name": "high_risk_threshold",
                "condition": lambda risk, confidence, context: risk >= 0.8,
                "reason": "Risk score exceeds high threshold",
                "priority": "high"
            },
            {
                "name": "low_confidence",
                "condition": lambda risk, confidence, context: confidence < 0.5,
                "reason": "Analysis confidence below threshold",
                "priority": "medium"
            },
            {
                "name": "critical_infrastructure",
                "condition": lambda risk, confidence, context: context.get("asset_criticality") == "critical",
                "reason": "Critical infrastructure asset involved",
                "priority": "critical"
            },
            {
                "name": "unknown_threat_signature",
                "condition": lambda risk, confidence, context: context.get("unknown_indicators", 0) > 3,
                "reason": "Multiple unknown threat indicators detected",
                "priority": "high"
            }
        ]
        return default_rules

    async def _check_escalation_triggers(self, context, risk_assessment: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if investigation should be escalated for human review"""
        escalation_triggers = []
        priority = "low"

        risk_score = risk_assessment.get('risk_score', 0)
        confidence = risk_assessment.get('confidence', 1.0)

        # Check each escalation rule
        for rule in self.escalation_rules:
            try:
                if rule["condition"](risk_score, confidence, context.__dict__):
                    escalation_triggers.append(rule["name"])
                    if rule["priority"] in ["critical", "high"] and priority not in ["critical"]:
                        priority = rule["priority"]
                    elif rule["priority"] == "critical":
                        priority = "critical"
            except Exception as e:
                self.logger.warning(f"Error evaluating escalation rule {rule['name']}: {e}")

        if escalation_triggers:
            return {
                "should_escalate": True,
                "triggers": escalation_triggers,
                "priority": priority,
                "risk_score": risk_score,
                "confidence_score": confidence,
                "reason": f"Triggered rules: {', '.join(escalation_triggers)}"
            }

        return None

    async def _create_audit_entry(self, investigation_id: str, event_type: str,
                                action: str, details: Dict[str, Any], actor: str = "system"):
        """Create audit trail entry"""
        audit_entry = {
            "investigation_id": investigation_id,
            "event_type": event_type,
            "actor": actor,
            "action": action,
            "details": details,
            "timestamp": datetime.utcnow().isoformat()
        }

        self.audit_trail.append(audit_entry)

        try:
            action_type = ActionType(event_type)
        except ValueError:
            action_type = ActionType.SYSTEM_EVENT
        failed = event_type == "investigation_failed"
        self.action_logger.log_action(
            action_type=action_type,
            component="SOCAgentPlanner",
            description=f"{event_type}: {action}",
            investigation_id=investigation_id,
            status=ActionStatus.FAILED if failed else ActionStatus.SUCCESS,
            level=LogLevel.ERROR if failed else LogLevel.INFO,
            details={"actor": actor, **details},
        )

        self.logger.info(f"Audit: {event_type} - {action} by {actor}")

    async def investigate_incident(self, event_data: Dict[str, Any],
                                  emergency_mode: bool = False,
                                  investigation_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Main investigation orchestration method with human review integration
        """
        event_id = f"evt_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{hash(str(event_data)) % 10000}"
        audit_id = investigation_id or event_id

        context = InvestigationContext(
            event_id=event_id,
            event_data=event_data,
            phase=InvestigationPhase.INITIAL_ASSESSMENT,
            intelligence_data={}
        )

        await self._create_audit_entry(
            audit_id, "investigation_started", "automatic_investigation_initiated",
            {"event_type": event_data.get("event_type"), "emergency_mode": emergency_mode}
        )

        try:
            # Phase 1: Initial Assessment
            await self._initial_assessment(context, emergency_mode)
            context.complete_phase()

            # Phase 2: Intelligence Gathering
            await self._intelligence_gathering(context, emergency_mode)
            context.complete_phase()

            # Phase 2.5: LLM-Powered Analysis (if configured)
            await self._llm_analysis(context)

            # Phase 3: Risk Analysis
            await self._risk_analysis(context, emergency_mode)
            context.complete_phase()

            escalation_check = await self._check_escalation_triggers(context, context.risk_assessment)

            if escalation_check and escalation_check["should_escalate"] and not emergency_mode:
                # Create human review request
                context.requires_human_review = True
                context.escalation_details = escalation_check
                context.recommended_actions = []

                await self._create_audit_entry(
                    audit_id, "human_review_requested", "escalation_triggered",
                    escalation_check
                )

                self.logger.warning(f"Investigation {event_id} escalated for human review: {escalation_check['reason']}")

                # Return partial results with review request
                return {
                    **context.__dict__,
                    "status": "pending_human_review",
                    "review_request": escalation_check,
                    "partial_analysis": True
                }

            # Phase 4: Action Planning
            await self._action_planning(context, emergency_mode)
            context.complete_phase()

            # Phase 4.5: Execute Actions via Integrations
            await self._execute_actions(context)

            # Phase 5: Generate Report
            await self._generate_report(context)
            context.complete_phase()

            # Phase 6: Update Memory
            await self._update_memory(context)
            context.complete_phase()

            await self._create_audit_entry(
                audit_id, "investigation_completed", "autonomous_analysis_finished",
                {"risk_score": context.risk_assessment.get('risk_score')}
            )

            return {
                **context.__dict__,
                "status": "completed",
                "audit_trail": self.audit_trail
            }

        except Exception as e:
            await self._create_audit_entry(
                audit_id, "investigation_failed", "error_occurred",
                {"error": str(e), "phase": context.phase.value}
            )
            return await self._handle_investigation_failure(context, e)

    async def process_analyst_feedback(self, investigation_id: str, feedback: Dict[str, Any]) -> Dict[str, Any]:
        """Process feedback from human analyst for continuous learning"""

        await self._create_audit_entry(
            investigation_id, "analyst_feedback_received", "human_review_completed",
            {
                "analyst_id": feedback.get("analyst_id"),
                "review_status": feedback.get("review_status"),
                "accuracy_rating": feedback.get("accuracy_rating"),
                "false_positive": feedback.get("false_positive", False)
            },
            actor=feedback.get("analyst_id", "unknown_analyst")
        )

        # Update memory with analyst corrections
        if feedback.get("false_positive"):
            await self.memory.mark_false_positive(investigation_id, feedback.get("learning_notes", ""))

        if feedback.get("missed_indicators"):
            await self.memory.add_missed_indicators(investigation_id, feedback["missed_indicators"])

        # Adjust future confidence based on feedback
        accuracy_rating = feedback.get("accuracy_rating", 3)
        if accuracy_rating <= 2:
            self.confidence_threshold = min(self.confidence_threshold + 0.05, 0.9)
        elif accuracy_rating >= 4:
            self.confidence_threshold = max(self.confidence_threshold - 0.02, 0.5)

        self.logger.info(f"Processed analyst feedback for {investigation_id}, adjusted confidence threshold to {self.confidence_threshold}")

        return {
            "status": "feedback_processed",
            "investigation_id": investigation_id,
            "learning_applied": True,
            "new_confidence_threshold": self.confidence_threshold
        }

    async def _initial_assessment(self, context: InvestigationContext, emergency_mode: bool):
        """Phase 1: Assess the event and determine investigation strategy"""
        context.phase = InvestigationPhase.INITIAL_ASSESSMENT
        context.reasoning_log.append("=== INITIAL ASSESSMENT ===")

        event_data = context.event_data
        event_type = event_data.get('event_type', 'unknown')

        # Classify event severity
        base_severity = self._classify_event_severity(event_data)
        context.reasoning_log.append(f"Event type: {event_type}, Base severity: {base_severity}")

        # Check memory for similar events
        similar_events = await self.memory.find_similar_events(event_data)
        if similar_events:
            context.reasoning_log.append(f"Found {len(similar_events)} similar historical events")

        # Determine investigation depth based on severity and mode
        if emergency_mode or base_severity >= self.emergency_threshold:
            context.reasoning_log.append("EMERGENCY MODE: Prioritizing speed over thoroughness")

        self.logger.info(f"Initial assessment complete for {context.event_id}")

    async def _intelligence_gathering(self, context: InvestigationContext, emergency_mode: bool):
        """Phase 2: Gather threat intelligence using available tools"""
        context.phase = InvestigationPhase.INTELLIGENCE_GATHERING
        context.reasoning_log.append("=== INTELLIGENCE GATHERING ===")

        event_data = context.event_data
        intel_tasks = []

        # Determine which tools to use based on event type and data
        if 'source_ip' in event_data:
            intel_tasks.append(self.tools.query_ip_reputation(event_data['source_ip']))
            context.reasoning_log.append(f"Querying IP reputation for: {event_data['source_ip']}")

        if 'url' in event_data:
            intel_tasks.append(self.tools.query_url_reputation(event_data['url']))
            context.reasoning_log.append(f"Querying URL reputation for: {event_data['url']}")

        if 'file_hash' in event_data:
            intel_tasks.append(self.tools.query_file_reputation(event_data['file_hash']))
            context.reasoning_log.append(f"Querying file reputation for: {event_data['file_hash']}")

        # Execute intelligence gathering concurrently
        if intel_tasks:
            if emergency_mode:
                # In emergency mode, set shorter timeout
                intel_results = await asyncio.wait_for(
                    asyncio.gather(*intel_tasks, return_exceptions=True),
                    timeout=30
                )
            else:
                intel_results = await asyncio.gather(*intel_tasks, return_exceptions=True)

            # Process intelligence results
            context.intelligence_data = self._process_intelligence_results(intel_results)
            context.reasoning_log.append(f"Gathered intelligence from {len([r for r in intel_results if not isinstance(r, Exception)])} sources")

        self.logger.info(f"Intelligence gathering complete for {context.event_id}")

    async def _llm_analysis(self, context: InvestigationContext):
        """Phase 2.5: Use LLM for intelligent threat analysis"""
        if self.llm is None:
            return

        context.reasoning_log.append("=== LLM ANALYSIS ===")
        context.reasoning_log.append(f"Provider: {self.llm.provider_name}/{self.llm.model}")

        messages = build_analysis_prompt(context.event_data, context.intelligence_data)

        try:
            response = await self.llm.chat(messages)

            if not response.success:
                context.reasoning_log.append(f"LLM analysis failed: {response.error}")
                context.llm_analysis = None
                return

            import json
            content = response.content.strip()
            if content.startswith("```"):
                content = content.split("\n", 1)[1].rsplit("```", 1)[0].strip()

            try:
                analysis = json.loads(content)
            except json.JSONDecodeError:
                context.reasoning_log.append("LLM returned non-JSON response, using raw text")
                analysis = {"threat_assessment": content, "risk_modifier": 0.0, "confidence": 0.3}

            context.llm_analysis = analysis

            context.reasoning_log.append(f"Threat: {analysis.get('threat_assessment', 'N/A')[:120]}")
            context.reasoning_log.append(f"LLM risk modifier: {analysis.get('risk_modifier', 0)}")
            context.reasoning_log.append(f"LLM confidence: {analysis.get('confidence', 0)}")
            context.reasoning_log.append(f"Classification: {analysis.get('attack_classification', 'unknown')}")
            context.reasoning_log.append(f"Urgency: {analysis.get('urgency', 'unknown')}")
            context.reasoning_log.append(
                f"Tokens used: {response.usage.get('total_tokens', 0)}"
            )

            self.logger.info(
                f"LLM analysis complete for {context.event_id}: "
                f"{analysis.get('attack_classification', 'unknown')} "
                f"({response.usage.get('total_tokens', 0)} tokens)"
            )

        except Exception as e:
            context.reasoning_log.append(f"LLM analysis error: {e}")
            context.llm_analysis = None
            self.logger.warning(f"LLM analysis failed: {e}")

    async def _risk_analysis(self, context: InvestigationContext, emergency_mode: bool):
        """Phase 3: Analyze risk based on event data and intelligence"""
        context.phase = InvestigationPhase.RISK_ANALYSIS
        context.reasoning_log.append("=== RISK ANALYSIS ===")

        # Calculate base risk from event characteristics
        base_risk = self._calculate_base_risk(context.event_data)
        context.reasoning_log.append(f"Base risk score: {base_risk:.2f}")

        # Incorporate threat intelligence
        intel_risk = self._calculate_intel_risk(context.intelligence_data)
        if intel_risk is None:
            context.reasoning_log.append(
                "Intelligence unavailable: weight redistributed to event "
                "evidence with uncertainty floor"
            )
        else:
            context.reasoning_log.append(f"Intelligence risk modifier: {intel_risk:.2f}")

        # Consider historical patterns
        pattern_risk = await self._calculate_pattern_risk(context)
        context.reasoning_log.append(f"Pattern analysis risk: {pattern_risk:.2f}")

        # Incorporate LLM risk modifier if available
        llm_risk = 0.0
        llm_analysis = getattr(context, 'llm_analysis', None)
        if llm_analysis and isinstance(llm_analysis, dict):
            llm_risk = float(llm_analysis.get('risk_modifier', 0.0))
            context.reasoning_log.append(f"LLM risk modifier applied: {llm_risk:.2f}")

        if intel_risk is None:
            # Blind on intel: lean on event evidence, never score as if clean.
            if llm_analysis:
                final_risk = (base_risk * 0.45) + (pattern_risk * 0.15) \
                    + (llm_risk * 0.3) + self.INTEL_UNCERTAINTY_FLOOR
            else:
                final_risk = (base_risk * 0.7) + (pattern_risk * 0.1) \
                    + self.INTEL_UNCERTAINTY_FLOOR
        elif llm_analysis:
            final_risk = (base_risk * 0.2) + (intel_risk * 0.35) + (pattern_risk * 0.15) + (llm_risk * 0.3)
        else:
            final_risk = (base_risk * 0.3) + (intel_risk * 0.5) + (pattern_risk * 0.2)

        final_risk = min(final_risk, 1.0)
        risk_level = self._determine_risk_level(final_risk)

        context.risk_assessment = {
            'risk_score': final_risk,
            'risk_level': risk_level,
            'base_risk': base_risk,
            'intel_risk': intel_risk,
            'intel_available': intel_risk is not None,
            'pattern_risk': pattern_risk,
            'llm_risk': llm_risk,
            'llm_analysis': llm_analysis,
            'confidence': self._calculate_confidence(context)
        }

        context.reasoning_log.append(f"Final risk assessment: {risk_level.upper()} ({final_risk:.2f})")
        self.logger.info(f"Risk analysis complete for {context.event_id}: {risk_level}")

    async def _action_planning(self, context: InvestigationContext, emergency_mode: bool):
        """Phase 4: Plan prioritized response actions"""
        context.phase = InvestigationPhase.ACTION_PLANNING
        context.reasoning_log.append("=== ACTION PLANNING ===")

        risk_level = context.risk_assessment['risk_level']
        event_type = context.event_data.get('event_type')

        # Generate actions based on risk level and event type
        actions = self._generate_response_actions(risk_level, event_type, context)

        # Prioritize actions
        prioritized_actions = self._prioritize_actions(actions, emergency_mode)

        context.recommended_actions = prioritized_actions
        context.reasoning_log.append(f"Generated {len(prioritized_actions)} prioritized actions")

        # Log top priority actions
        for i, action in enumerate(prioritized_actions[:3]):
            context.reasoning_log.append(f"Priority {i+1}: {action['action_type']} - {action['description']}")

        self.logger.info(f"Action planning complete for {context.event_id}")

    async def _execute_actions(self, context: InvestigationContext):
        """Phase 4.5: Execute recommended actions through the integration layer"""
        if not context.recommended_actions:
            return

        if not self.integrations.active_integrations:
            context.reasoning_log.append("No active integrations configured, actions are recommendations only")
            context.actions_executed = []
            return

        context.reasoning_log.append("=== ACTION EXECUTION ===")
        executed = []

        action_type_map = {
            'BLOCK': IntegrationActionType.BLOCK_IP,
            'ESCALATE': IntegrationActionType.ESCALATE,
            'ALERT': IntegrationActionType.SEND_ALERT,
            'MONITOR': IntegrationActionType.ADD_TO_WATCHLIST,
            'INVESTIGATE': IntegrationActionType.CREATE_INCIDENT,
        }

        source_ip = context.event_data.get('source_ip', '')

        for action in context.recommended_actions:
            action_key = action.get('action_type', '')
            integration_action = action_type_map.get(action_key)
            if not integration_action:
                continue

            target = source_ip or context.event_id
            action_context = {
                'event_id': context.event_id,
                'risk_level': context.risk_assessment.get('risk_level', 'unknown'),
                'description': action.get('description', ''),
            }

            try:
                response = await self.integrations.execute_action(
                    action_type=integration_action,
                    target=target,
                    context=action_context
                )
                executed.append({
                    'action': action_key,
                    'integration_action': integration_action.value,
                    'target': target,
                    'success': response.success,
                    'integrations_used': response.metadata.get('integration_names', []),
                })
                status_str = "SUCCESS" if response.success else "FAILED"
                context.reasoning_log.append(
                    f"Action {action_key} -> {integration_action.value} on {target}: {status_str}"
                )
            except Exception as e:
                self.logger.warning(f"Failed to execute {action_key}: {e}")
                executed.append({
                    'action': action_key,
                    'target': target,
                    'success': False,
                    'error': str(e),
                })
                context.reasoning_log.append(f"Action {action_key} FAILED: {e}")

        context.actions_executed = executed

    async def _generate_report(self, context: InvestigationContext):
        """Phase 5: Generate incident report"""
        context.phase = InvestigationPhase.REPORTING

        report = await self.reporter.generate_report(context)
        context.report = report

        self.logger.info(f"Report generated for {context.event_id}")

    async def _update_memory(self, context: InvestigationContext):
        """Phase 6: Update agent memory with investigation learnings"""
        context.phase = InvestigationPhase.MEMORY_UPDATE

        await self.memory.store_investigation(context)
        context.reasoning_log.append("Investigation stored in agent memory for future learning")

        self.logger.info(f"Memory updated for {context.event_id}")

    def _classify_event_severity(self, event_data: Dict[str, Any]) -> float:
        """Classify initial event severity based on type and characteristics"""
        event_type = event_data.get('event_type', 'unknown')

        # Base severity by event type
        severity_map = {
            'malware_detection': 0.8,
            'ddos_signs': 0.7,
            'suspicious_ip': 0.5,
            'login_anomaly': 0.4,
            'suspicious_url': 0.6,
            'phishing_attempt': 0.7,
            'unknown': 0.3
        }

        base_severity = severity_map.get(event_type, 0.3)

        # Adjust based on event characteristics
        attempts = event_data.get('payload', {}).get('failed_login_attempts', 0)
        if attempts > 50:
            base_severity += 0.3
        elif attempts > 10:
            base_severity += 0.2
        elif attempts > 3:
            base_severity += 0.1

        if event_data.get('internal_source', False):
            base_severity += 0.1  # Internal threats often more serious

        return min(base_severity, 1.0)

    def _process_intelligence_results(self, intel_results: List) -> Dict[str, Any]:
        """Process and structure threat intelligence results"""
        processed = {
            'sources': [],
            'reputation_score': 0.0,
            'threat_indicators': [],
            'confidence': 0.0
        }

        valid_results = [r for r in intel_results if not isinstance(r, Exception)]

        for result in valid_results:
            if result is None:
                continue
            # Handle both dict and ToolResult dataclass objects
            success = result.get('success') if isinstance(result, dict) else getattr(result, 'success', False)
            source = result.get('source', 'unknown') if isinstance(result, dict) else getattr(result, 'source', 'unknown')
            data = result if isinstance(result, dict) else getattr(result, 'data', {})

            if success:
                processed['sources'].append(source)
                rep_score = data.get('reputation_score', 0) if isinstance(data, dict) else 0
                if rep_score:
                    processed['reputation_score'] = max(processed['reputation_score'], rep_score)
                indicators = data.get('indicators', []) if isinstance(data, dict) else []
                if indicators:
                    processed['threat_indicators'].extend(indicators)

        if valid_results:
            error_count = len([r for r in intel_results if isinstance(r, Exception)])
            processed['confidence'] = len(valid_results) / (len(valid_results) + error_count)

        return processed

    def _calculate_base_risk(self, event_data: Dict[str, Any]) -> float:
        """Calculate base risk score from event characteristics"""
        return self._classify_event_severity(event_data)

    def _calculate_intel_risk(self, intel_data: Dict[str, Any]) -> Optional[float]:
        """Calculate risk modifier from threat intelligence.

        Returns None when no source answered. Absence of intelligence is
        uncertainty, not safety: callers must not treat it as a clean
        reputation score of zero.
        """
        if not intel_data or not intel_data.get('sources'):
            return None

        reputation_score = intel_data.get('reputation_score', 0.0)
        num_indicators = len(intel_data.get('threat_indicators', []))

        # Higher reputation score and more indicators = higher risk
        intel_risk = reputation_score + (num_indicators * 0.1)

        return min(intel_risk, 1.0)

    async def _calculate_pattern_risk(self, context: InvestigationContext) -> float:
        """Calculate risk based on historical patterns"""
        similar_events = await self.memory.find_similar_events(context.event_data, limit=10)

        if not similar_events:
            return 0.0

        # Analyze patterns in similar events
        high_risk_count = sum(1 for event in similar_events
                             if event.risk_score > 0.7)

        pattern_risk = high_risk_count / len(similar_events)

        return pattern_risk

    def _determine_risk_level(self, risk_score: float) -> str:
        """Convert numeric risk score to categorical level"""
        if risk_score >= 0.8:
            return 'critical'
        elif risk_score >= 0.6:
            return 'high'
        elif risk_score >= 0.3:
            return 'medium'
        else:
            return 'low'

    def _calculate_confidence(self, context: InvestigationContext) -> float:
        """Calculate confidence in the risk assessment"""
        confidence = 0.5

        intel_sources = len(context.intelligence_data.get('sources', []))
        confidence += min(intel_sources * 0.1, 0.3)

        if context.intelligence_data.get('confidence', 0) > 0:
            confidence += 0.1

        llm_analysis = getattr(context, 'llm_analysis', None)
        if llm_analysis and isinstance(llm_analysis, dict):
            llm_conf = float(llm_analysis.get('confidence', 0))
            confidence += llm_conf * 0.2

        return min(confidence, 1.0)

    def _generate_response_actions(self, risk_level: str, event_type: str,
                                 context: InvestigationContext) -> List[Dict[str, Any]]:
        """Generate appropriate response actions based on risk and event type"""
        actions = []

        # Critical risk actions
        if risk_level == 'critical':
            actions.extend([
                {
                    'action_type': 'BLOCK',
                    'priority': 1,
                    'description': 'Immediately block malicious indicator',
                    'estimated_effort': '5 minutes'
                },
                {
                    'action_type': 'ESCALATE',
                    'priority': 1,
                    'description': 'Escalate to security team immediately',
                    'estimated_effort': '2 minutes'
                }
            ])

        # High risk actions
        elif risk_level == 'high':
            actions.extend([
                {
                    'action_type': 'INVESTIGATE',
                    'priority': 2,
                    'description': 'Conduct detailed investigation',
                    'estimated_effort': '30 minutes'
                },
                {
                    'action_type': 'MONITOR',
                    'priority': 3,
                    'description': 'Enhanced monitoring for 24 hours',
                    'estimated_effort': '10 minutes setup'
                }
            ])

        # Medium risk actions
        elif risk_level == 'medium':
            actions.extend([
                {
                    'action_type': 'MONITOR',
                    'priority': 3,
                    'description': 'Monitor for suspicious activity',
                    'estimated_effort': '5 minutes'
                },
                {
                    'action_type': 'ALERT',
                    'priority': 4,
                    'description': 'Send alert to administrators',
                    'estimated_effort': '2 minutes'
                }
            ])

        # Low risk actions
        else:
            actions.append({
                'action_type': 'ALERT',
                'priority': 5,
                'description': 'Log event for review',
                'estimated_effort': '1 minute'
            })

        return actions

    def _prioritize_actions(self, actions: List[Dict[str, Any]],
                          emergency_mode: bool) -> List[Dict[str, Any]]:
        """Sort actions by priority and emergency mode considerations"""
        if emergency_mode:
            # In emergency mode, prioritize immediate actions
            actions = [a for a in actions if a['priority'] <= 2]

        return sorted(actions, key=lambda x: x['priority'])

    async def _handle_investigation_failure(self, context: InvestigationContext,
                                          error: Exception) -> Dict[str, Any]:
        """Handle investigation failures gracefully"""
        self.logger.error(f"Investigation failed: {str(error)}")

        # Return minimal safe response
        return {
            'event_id': context.event_id,
            'status': 'failed',
            'error': str(error),
            'recommended_actions': [{
                'action_type': 'ESCALATE',
                'priority': 1,
                'description': 'Manual investigation required due to system error',
                'estimated_effort': '60 minutes'
            }]
        }
