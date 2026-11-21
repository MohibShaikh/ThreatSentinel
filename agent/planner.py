"""
SOC Agent Planner - core decision-making and orchestration engine.

Pipeline: initial assessment (deterministic detection + guardrails + memory),
intelligence gathering (local forensics, keyless public intel, keyed intel),
optional LLM analysis on redacted, nonce-isolated data, risk analysis,
escalation checks, action planning/execution, reporting and memory update.
"""

import asyncio
import inspect
import json
import logging
import uuid
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlsplit

from .action_logger import ActionLogger, ActionStatus, ActionType, LogLevel
from .detectors import EVENT_TYPE_BASELINE, analyze_event
from .environment import AgentEnvironment, ToolCallRecord
from .guardrails import (is_public_ip, parse_llm_analysis, redact_sensitive_data, scan_prompt_injection,
                         wrap_untrusted_data)
from .integrations.base import ActionType as IntegrationActionType
from .integrations.registry import IntegrationRegistry
from .llm import (LOCAL_PROVIDERS, TOOL_USE_INSTRUCTIONS, BaseLLMProvider, LLMResponse, build_analysis_prompt,
                  create_llm_provider, tools_unsupported)
from .memory import AgentMemory
from .reporter import IncidentReporter
from .scoring import INTEL_UNCERTAINTY_FLOOR, clamp01, combine_risk
from .tools import ToolRegistry, is_configured_api_key

PRIORITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
PROMPT_INJECTION_RISK_FLOOR = 0.6
DEFAULT_MAX_TOOL_STEPS = 5
MAX_TOOL_STEPS_CAP = 10
DEFAULT_TOOL_LOOP_TIMEOUT = 180.0
TOOL_RESULT_CHAR_LIMIT = 6000
PIVOT_LIMITS = {"ips": 4, "urls": 4, "file_hashes": 3}

# Classic actions the planner can execute through integrations, and what they need
EXECUTABLE_ACTIONS = {
    "BLOCK": (IntegrationActionType.BLOCK_IP, IntegrationActionType.BLOCK_URL),
    "MONITOR": (IntegrationActionType.ADD_TO_WATCHLIST,),
    "ESCALATE": (IntegrationActionType.ESCALATE,),
    "ALERT": (IntegrationActionType.SEND_ALERT,),
    "INVESTIGATE": (IntegrationActionType.CREATE_INCIDENT,),
}

# Threat-aware playbook actions keyed by detection category / event type.
# These are analyst playbook steps: no integration executes them automatically.
THREAT_PLAYBOOKS = {
    "secret_leak": ("ROTATE_CREDENTIALS", "Revoke and rotate every exposed credential, then audit its use"),
    "prompt_injection": ("APPLY_GUARDRAIL_BLOCK",
                         "Block the injected content source at the AI input guardrail and review tool permissions"),
    "agent_tool_abuse": ("QUARANTINE_TOOL", "Suspend the abused agent tool and require human approval for its use"),
    "mcp_tool_poisoning": ("QUARANTINE_TOOL", "Disable the MCP server/tool and pin reviewed tool definitions"),
    "rag_poisoning": ("PURGE_RAG_CHUNKS", "Remove poisoned chunks and re-index from trusted sources"),
    "model_dos": ("RATE_LIMIT", "Apply per-user token and request limits on the AI endpoint"),
    "ddos": ("RATE_LIMIT", "Rate-limit or scrub the flooding sources upstream"),
    "ddos_signs": ("RATE_LIMIT", "Rate-limit or scrub the flooding sources upstream"),
    "supply_chain_compromise": ("QUARANTINE_ARTIFACT",
                                "Pull the package/image, pin known-good versions, rotate CI secrets"),
    "malware": ("QUARANTINE_ARTIFACT", "Quarantine the malicious file and isolate affected hosts"),
    "malware_detection": ("QUARANTINE_ARTIFACT", "Quarantine the malicious file and isolate affected hosts"),
    "data_exfiltration": ("CONTAIN_HOST", "Isolate the source host and block the exfiltration destination"),
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class InvestigationPhase(Enum):
    """Phases of security incident investigation"""
    INITIAL_ASSESSMENT = "initial_assessment"
    INTELLIGENCE_GATHERING = "intelligence_gathering"
    LLM_ANALYSIS = "llm_analysis"
    RISK_ANALYSIS = "risk_analysis"
    ACTION_PLANNING = "action_planning"
    REPORTING = "reporting"
    MEMORY_UPDATE = "memory_update"


@dataclass
class InvestigationContext:
    """State carried through one investigation. Never shared between investigations."""
    event_id: str
    event_data: Dict[str, Any]
    phase: InvestigationPhase
    intelligence_data: Dict[str, Any]
    risk_assessment: Optional[Dict[str, Any]] = None
    recommended_actions: Optional[List[Dict[str, Any]]] = None
    actions_executed: Optional[List[Dict[str, Any]]] = None
    reasoning_log: Optional[List[str]] = None
    start_time: Optional[datetime] = None
    phases_completed: Optional[List[str]] = None
    investigation_id: Optional[str] = None
    detection_assessment: Optional[Dict[str, Any]] = None
    prompt_injection_scan: Optional[Dict[str, Any]] = None
    pattern_insights: List[Dict[str, Any]] = field(default_factory=list)
    similar_events: List[Dict[str, Any]] = field(default_factory=list)
    llm_analysis: Optional[Dict[str, Any]] = None
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "in_progress"
    requires_human_review: bool = False
    escalation_details: Optional[Dict[str, Any]] = None
    proposed_actions: List[Dict[str, Any]] = field(default_factory=list)
    report: Optional[Dict[str, Any]] = None
    emergency_mode: bool = False
    tool_trace: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        if self.reasoning_log is None:
            self.reasoning_log = []
        if self.start_time is None:
            self.start_time = _utcnow()
        elif self.start_time.tzinfo is None:
            self.start_time = self.start_time.replace(tzinfo=timezone.utc)
        if self.phases_completed is None:
            self.phases_completed = []
        if self.investigation_id is None:
            self.investigation_id = self.event_id

    def complete_phase(self):
        """Mark the current phase as completed"""
        if self.phase and self.phase.value not in self.phases_completed:
            self.phases_completed.append(self.phase.value)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if isinstance(value, Enum):
                value = value.value
            elif isinstance(value, datetime):
                value = value.isoformat()
            out[f.name] = value
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InvestigationContext":
        known = {f.name for f in fields(cls)}
        kwargs = {k: v for k, v in data.items() if k in known}
        phase = kwargs.get("phase", InvestigationPhase.RISK_ANALYSIS.value)
        try:
            kwargs["phase"] = InvestigationPhase(phase) if not isinstance(phase, InvestigationPhase) else phase
        except ValueError:
            kwargs["phase"] = InvestigationPhase.RISK_ANALYSIS
        if isinstance(kwargs.get("start_time"), str):
            kwargs["start_time"] = datetime.fromisoformat(kwargs["start_time"])
        kwargs.setdefault("event_id", data.get("investigation_id") or f"evt_{uuid.uuid4().hex[:12]}")
        kwargs.setdefault("event_data", {})
        kwargs.setdefault("intelligence_data", {})
        return cls(**kwargs)


def _as_dict(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: getattr(obj, f.name) for f in fields(obj)}
    return obj


class SOCAgentPlanner:
    """Autonomous SOC investigation planner with human-in-the-loop escalation."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        tools_config = dict(self.config.get("tools", {}))
        tools_config.setdefault("enable_keyless_intel", self.config.get("enable_keyless_intel", True))
        self.tools = ToolRegistry(self.config.get("api_keys", {}), tools_config)
        self.memory = AgentMemory(self.config.get("memory", {}))
        self.reporter = IncidentReporter(self.config.get("reporting", {}))
        self.integrations = IntegrationRegistry(self.config.get("integrations_config", {}))
        self.environment = AgentEnvironment(tools=self.tools, memory=self.memory, integrations=self.integrations)

        self.llm: Optional[BaseLLMProvider] = None
        llm_config = dict(self.config.get("llm", {}) or {})
        self.llm_redact_secrets = bool(llm_config.get("redact_secrets", True))
        steps = self.config.get("llm_max_tool_steps", llm_config.get("max_tool_steps", DEFAULT_MAX_TOOL_STEPS))
        try:
            steps = int(steps)
        except (TypeError, ValueError):
            steps = DEFAULT_MAX_TOOL_STEPS
        self.llm_max_tool_steps = max(0, min(steps, MAX_TOOL_STEPS_CAP))
        self.llm_tool_loop_timeout = float(self.config.get("llm_tool_loop_timeout", DEFAULT_TOOL_LOOP_TIMEOUT))
        provider = (llm_config.get("provider") or "").lower()
        api_key = llm_config.get("api_key")
        has_key = is_configured_api_key(api_key)
        if provider and (has_key or provider in LOCAL_PROVIDERS):
            try:
                if llm_config.get("base_url") and not llm_config.get("endpoint"):
                    llm_config["endpoint"] = llm_config["base_url"]
                self.llm = create_llm_provider(
                    provider=provider,
                    api_key=api_key if has_key else "",
                    model=llm_config.get("model"),
                    config=llm_config,
                )
                self.logger.info(f"LLM enabled: {self.llm.provider_name}/{self.llm.model}")
            except Exception as e:
                self.logger.warning(f"Failed to initialize LLM: {e}")

        self.confidence_threshold = self.config.get("confidence_threshold", 0.7)
        self.emergency_threshold = self.config.get("emergency_threshold", 0.8)
        self.INTEL_UNCERTAINTY_FLOOR = INTEL_UNCERTAINTY_FLOOR
        self.max_investigation_time = self.config.get("max_investigation_time", 300)
        self.review_threshold = self.config.get("review_threshold", 0.6)
        self.escalation_rules = self._load_escalation_rules()

        audit_config = self.config.get("audit", {})
        self.action_logger = ActionLogger(audit_config.get("db_path", "data/action_logs.db"))
        self.logger.info("SOC Agent Planner initialized with human review capabilities")

    # ------------------------------------------------------------------ escalation

    def _load_escalation_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "high_risk_threshold",
                "condition": lambda risk, confidence, ctx: risk >= 0.8,
                "reason": "Risk score exceeds high threshold",
                "priority": "high",
            },
            {
                "name": "low_confidence",
                "condition": lambda risk, confidence, ctx: confidence < 0.5,
                "reason": "Analysis confidence below threshold",
                "priority": "medium",
            },
            {
                "name": "critical_infrastructure",
                "condition": lambda risk, confidence, ctx: str(ctx.get("asset_criticality", "")).lower() == "critical",
                "reason": "Critical infrastructure asset involved",
                "priority": "critical",
            },
            {
                "name": "unknown_threat_signature",
                "condition": lambda risk, confidence, ctx: ctx.get("unknown_indicators", 0) > 3,
                "reason": "Multiple indicators without any reputation coverage",
                "priority": "high",
            },
            {
                "name": "prompt_injection_detected",
                "condition": lambda risk, confidence, ctx: bool(ctx.get("prompt_injection_detected")),
                "reason": "Prompt injection content found in telemetry; AI-assisted analysis may be manipulated",
                "priority": "high",
            },
        ]

    def _escalation_context(self, context: InvestigationContext) -> Dict[str, Any]:
        event = context.event_data or {}
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        detection = context.detection_assessment or {}
        iocs = detection.get("extracted_iocs", {}) or {}

        indicators = set()
        for ip in iocs.get("ips", []):
            if is_public_ip(ip):
                indicators.add(ip)
        for key in ("urls", "domains", "md5", "sha1", "sha256"):
            indicators.update(iocs.get(key, []) or [])
        covered = set()
        intel = context.intelligence_data or {}
        if intel.get("sources"):
            pivoted = intel.get("pivoted_indicators") or {}
            for key in ("source_ip", "url", "file_hash", "destination_ip"):
                if event.get(key):
                    covered.add(str(event[key]).lower() if key == "file_hash" else str(event[key]))
            covered.update(pivoted.get("ips", []) or [])
            covered.update(str(h).lower() for h in pivoted.get("file_hashes", []) or [])
            for url in ([event["url"]] if event.get("url") else []) + list(pivoted.get("urls", []) or []):
                covered.add(str(url))
                host = urlsplit(str(url)).hostname
                if host:
                    covered.add(host)
        return {
            "asset_criticality": event.get("asset_criticality") or payload.get("asset_criticality"),
            "unknown_indicators": len(indicators - covered),
            "prompt_injection_detected": bool((context.prompt_injection_scan or {}).get("detected")),
            "event_type": event.get("event_type"),
        }

    async def _check_escalation_triggers(self, context: InvestigationContext,
                                         risk_assessment: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        triggers: List[str] = []
        reasons: List[str] = []
        priority = "low"
        risk_score = risk_assessment.get("risk_score", 0)
        confidence = risk_assessment.get("confidence", 1.0)
        rule_ctx = self._escalation_context(context)

        for rule in self.escalation_rules:
            try:
                if rule["condition"](risk_score, confidence, rule_ctx):
                    triggers.append(rule["name"])
                    reasons.append(rule["reason"])
                    if PRIORITY_RANK.get(rule["priority"], 0) > PRIORITY_RANK[priority]:
                        priority = rule["priority"]
            except Exception as e:
                self.logger.warning(f"Error evaluating escalation rule {rule['name']}: {e}")

        if not triggers:
            return None
        return {
            "should_escalate": True,
            "triggers": triggers,
            "reasons": reasons,
            "priority": priority,
            "risk_score": risk_score,
            "confidence_score": confidence,
            "unknown_indicators": rule_ctx["unknown_indicators"],
            "reason": f"Triggered rules: {', '.join(triggers)}",
        }

    # ------------------------------------------------------------------ audit

    async def _create_audit_entry(self, investigation_id: str, event_type: str, action: str,
                                  details: Dict[str, Any], actor: str = "system",
                                  context: Optional[InvestigationContext] = None):
        entry = {
            "investigation_id": investigation_id,
            "event_type": event_type,
            "actor": actor,
            "action": action,
            "details": details,
            "timestamp": _utcnow().isoformat(),
        }
        if context is not None:
            context.audit_trail.append(entry)

        try:
            action_type = ActionType(event_type)
        except ValueError:
            action_type = ActionType.SYSTEM_EVENT
        failed = event_type == "investigation_failed"
        try:
            self.action_logger.log_action(
                action_type=action_type,
                component="SOCAgentPlanner",
                description=f"{event_type}: {action}",
                investigation_id=investigation_id,
                status=ActionStatus.FAILED if failed else ActionStatus.SUCCESS,
                level=LogLevel.ERROR if failed else LogLevel.INFO,
                details={"actor": actor, **details},
            )
        except Exception as e:  # audit failures must be visible but never abort an investigation
            self.logger.error(f"Audit log write failed: {e}")

    # ------------------------------------------------------------------ main loop

    async def investigate_incident(self, event_data: Dict[str, Any],
                                   emergency_mode: bool = False,
                                   investigation_id: Optional[str] = None) -> Dict[str, Any]:
        event_id = investigation_id or f"evt_{uuid.uuid4().hex[:12]}"
        context = InvestigationContext(
            event_id=event_id,
            event_data=event_data,
            phase=InvestigationPhase.INITIAL_ASSESSMENT,
            intelligence_data={},
            investigation_id=event_id,
            emergency_mode=emergency_mode,
        )

        await self._create_audit_entry(
            event_id, "investigation_started", "automatic_investigation_initiated",
            {"event_type": event_data.get("event_type"), "emergency_mode": emergency_mode}, context=context,
        )

        try:
            await self._initial_assessment(context, emergency_mode)
            context.complete_phase()

            await self._intelligence_gathering(context, emergency_mode)
            context.complete_phase()

            await self._llm_analysis(context)

            await self._risk_analysis(context, emergency_mode)
            context.complete_phase()

            escalation = await self._check_escalation_triggers(context, context.risk_assessment)
            if escalation and escalation["should_escalate"] and not emergency_mode:
                context.requires_human_review = True
                context.escalation_details = escalation
                context.status = "pending_human_review"
                # Plan but do not execute: the analyst approves first
                await self._action_planning(context, emergency_mode)
                context.complete_phase()
                context.proposed_actions = context.recommended_actions or []
                context.recommended_actions = []
                context.actions_executed = []
                context.reasoning_log.append(
                    f"Escalated for human review ({escalation['priority']}): {escalation['reason']}")

                await self._create_audit_entry(event_id, "human_review_requested", "escalation_triggered",
                                               escalation, context=context)
                await self._generate_report(context)
                context.complete_phase()
                await self._update_memory(context)
                context.complete_phase()
                self.logger.warning(f"Investigation {event_id} escalated for human review: {escalation['reason']}")
                return {
                    **context.to_dict(),
                    "status": "pending_human_review",
                    "review_request": escalation,
                    "partial_analysis": True,
                }

            await self._action_planning(context, emergency_mode)
            context.complete_phase()

            await self._execute_actions(context)

            context.status = "completed"
            await self._generate_report(context)
            context.complete_phase()

            await self._update_memory(context)
            context.complete_phase()

            await self._create_audit_entry(
                event_id, "investigation_completed", "autonomous_analysis_finished",
                {"risk_score": context.risk_assessment.get("risk_score")}, context=context,
            )
            return {**context.to_dict(), "status": "completed"}

        except Exception as e:
            await self._create_audit_entry(
                event_id, "investigation_failed", "error_occurred",
                {"error": f"{type(e).__name__}: {e}"[:500], "phase": context.phase.value}, context=context,
            )
            return await self._handle_investigation_failure(context, e)

    async def process_analyst_feedback(self, investigation_id: str, feedback: Dict[str, Any]) -> Dict[str, Any]:
        """Apply analyst feedback for continuous learning."""
        await self._create_audit_entry(
            investigation_id, "analyst_feedback_received", "human_review_completed",
            {
                "analyst_id": feedback.get("analyst_id"),
                "review_status": str(feedback.get("review_status")),
                "accuracy_rating": feedback.get("accuracy_rating"),
                "false_positive": feedback.get("false_positive", False),
            },
            actor=str(feedback.get("analyst_id", "unknown_analyst")),
        )

        if feedback.get("false_positive"):
            await self.memory.mark_false_positive(investigation_id, feedback.get("learning_notes", ""))
        elif feedback.get("review_status"):
            await self.memory.update_investigation_outcome(
                investigation_id, f"analyst_{feedback.get('review_status')}", false_positive=False)

        if feedback.get("missed_indicators"):
            await self.memory.add_missed_indicators(investigation_id, feedback["missed_indicators"])

        accuracy_rating = feedback.get("accuracy_rating", 3) or 3
        if accuracy_rating <= 2:
            self.confidence_threshold = min(self.confidence_threshold + 0.05, 0.9)
        elif accuracy_rating >= 4:
            self.confidence_threshold = max(self.confidence_threshold - 0.02, 0.5)

        self.logger.info(f"Processed analyst feedback for {investigation_id}, "
                         f"confidence threshold now {self.confidence_threshold}")
        return {
            "status": "feedback_processed",
            "investigation_id": investigation_id,
            "learning_applied": True,
            "new_confidence_threshold": self.confidence_threshold,
        }

    async def execute_approved_actions(self, context_or_data: Union[InvestigationContext, Dict[str, Any]]
                                       ) -> Dict[str, Any]:
        """Execute the actions of an investigation an analyst has approved."""
        context = (context_or_data if isinstance(context_or_data, InvestigationContext)
                   else InvestigationContext.from_dict(context_or_data))
        if not context.recommended_actions:
            if context.proposed_actions:
                context.recommended_actions = list(context.proposed_actions)
            elif context.risk_assessment:
                await self._action_planning(context, emergency_mode=False)
        await self._execute_actions(context)
        await self._create_audit_entry(
            context.investigation_id or context.event_id, "integration_execution", "analyst_approved_actions",
            {"actions": [a.get("action_type") for a in context.recommended_actions or []],
             "executed": len(context.actions_executed or [])},
            actor="analyst", context=context,
        )
        return {
            "investigation_id": context.investigation_id,
            "recommended_actions": context.recommended_actions or [],
            "actions_executed": context.actions_executed or [],
        }

    # ------------------------------------------------------------------ phases

    async def _initial_assessment(self, context: InvestigationContext, emergency_mode: bool):
        context.phase = InvestigationPhase.INITIAL_ASSESSMENT
        context.reasoning_log.append("=== INITIAL ASSESSMENT ===")
        event_data = context.event_data
        event_type = event_data.get("event_type", "unknown")

        detection = analyze_event(event_data)
        context.detection_assessment = detection.to_dict()
        scan = scan_prompt_injection(event_data)
        context.prompt_injection_scan = {**scan.to_dict(), "source": "event_data" if scan.detected else None}

        base_severity = self._classify_event_severity(event_data)
        context.reasoning_log.append(
            f"Event type: {event_type}, type severity: {base_severity:.2f}, "
            f"detection severity: {detection.severity_score:.2f}")
        for finding in detection.findings[:5]:
            context.reasoning_log.append(
                f"Detection {finding['rule_id']}: {finding['title']} ({finding['severity']:.2f})")
        if detection.mitre_attack or detection.mitre_atlas or detection.owasp_llm:
            context.reasoning_log.append(
                f"Mapped: ATT&CK {detection.mitre_attack or '-'}; ATLAS {detection.mitre_atlas or '-'}; "
                f"OWASP LLM {detection.owasp_llm or '-'}")
        if scan.detected:
            context.reasoning_log.append(
                f"PROMPT INJECTION detected in event data (score {scan.score:.2f}, rules: "
                f"{', '.join(scan.matched_rules)}). Data will be isolated and risk floored.")
        if detection.redacted_secret_types:
            context.reasoning_log.append(
                f"Secrets present in telemetry: {', '.join(detection.redacted_secret_types)} "
                "(redacted before any LLM egress)")

        similar = await self.memory.find_similar_events(event_data)
        context.similar_events = [{
            "event_id": m.event_id, "event_type": m.event_type, "risk_score": m.risk_score,
            "risk_level": m.risk_level, "false_positive": m.false_positive,
            "similarity": getattr(m, "similarity", 0.0),
        } for m in (similar or []) if getattr(m, "event_id", None) != context.event_id]
        if context.similar_events:
            context.reasoning_log.append(f"Found {len(context.similar_events)} similar historical events")

        insights = await self.memory.get_pattern_insights(event_data)
        context.pattern_insights = [_as_dict(i) for i in insights or []]
        for insight in context.pattern_insights[:3]:
            context.reasoning_log.append(f"Pattern: {insight.get('description')}")

        if emergency_mode or max(base_severity, detection.severity_score) >= self.emergency_threshold:
            context.reasoning_log.append("EMERGENCY MODE: Prioritizing speed over thoroughness")
        self.logger.info(f"Initial assessment complete for {context.event_id}")

    # ------------------------------------------------------------------ tool environment

    @staticmethod
    def _compact(data: Any, limit: int = 4000) -> Any:
        text = json.dumps(data, default=str)
        return data if len(text) <= limit else {"truncated": True, "preview": text[:limit]}

    def _trace(self, context: InvestigationContext, record) -> None:
        entry = record.to_dict()
        entry["data"] = self._compact(entry.get("data"))
        context.tool_trace.append(entry)

    def _merge_injection_scan(self, context: InvestigationContext, scan, origin: str) -> None:
        merged = dict(context.prompt_injection_scan or {})
        previous = merged.get("source") if merged.get("detected") else None
        merged.update({
            "detected": True,
            "score": max(merged.get("score", 0.0), scan.score),
            "matched_rules": sorted(set(merged.get("matched_rules", [])) | set(scan.matched_rules)),
            "owasp_categories": sorted(set(merged.get("owasp_categories", [])) | set(scan.owasp_categories)),
            "mitre_atlas_ids": sorted(set(merged.get("mitre_atlas_ids", [])) | set(scan.mitre_atlas_ids)),
            "evidence": (merged.get("evidence", []) + scan.evidence)[:10],
            "source": origin if not previous or origin in previous.split("+") else f"{previous}+{origin}",
        })
        context.prompt_injection_scan = merged

    @staticmethod
    def _pick(first: Any, rest: Any, limit: int, *, fold_case: bool = False) -> List[str]:
        out: List[str] = []
        seen = set()
        for value in ([first] if first else []) + list(rest or []):
            value = str(value).strip()
            key = value.lower() if fold_case else value
            if value and key not in seen:
                seen.add(key)
                out.append(value)
            if len(out) >= limit:
                break
        return out

    def _pivot_targets(self, context: InvestigationContext) -> Dict[str, List[str]]:
        """Indicators worth inspecting: top-level fields first, then IOCs found anywhere in the event."""
        event = context.event_data
        iocs = (context.detection_assessment or {}).get("extracted_iocs", {}) or {}
        hashes = list(iocs.get("sha256", []) or []) + list(iocs.get("sha1", []) or []) + list(iocs.get("md5", []) or [])
        return {
            "ips": self._pick(event.get("source_ip"), iocs.get("ips"), PIVOT_LIMITS["ips"]),
            "urls": self._pick(event.get("url"), iocs.get("urls"), PIVOT_LIMITS["urls"]),
            "file_hashes": self._pick(event.get("file_hash"), hashes, PIVOT_LIMITS["file_hashes"], fold_case=True),
        }

    async def _intelligence_gathering(self, context: InvestigationContext, emergency_mode: bool):
        context.phase = InvestigationPhase.INTELLIGENCE_GATHERING
        context.reasoning_log.append("=== INTELLIGENCE GATHERING ===")
        targets = self._pivot_targets(context)
        top_level = {str(context.event_data.get(k)) for k in ("source_ip", "url", "file_hash")
                     if context.event_data.get(k)}

        calls: List[tuple] = []
        for ip in targets["ips"]:
            if self.environment.get("inspect_ip"):
                calls.append(("inspect_ip", {"ip": ip}))
                scope = "external + local" if is_public_ip(ip) else "local forensics only (non-public IP)"
                origin = "" if ip in top_level else " (pivot: found in event data)"
                context.reasoning_log.append(f"Querying IP intelligence for {ip} [{scope}]{origin}")
        for url in targets["urls"]:
            if self.environment.get("inspect_url"):
                calls.append(("inspect_url", {"url": url}))
                origin = "" if url in top_level else " (pivot: found in event data)"
                context.reasoning_log.append(f"Querying URL intelligence for: {url}{origin}")
        for file_hash in targets["file_hashes"]:
            if self.environment.get("inspect_file_hash"):
                calls.append(("inspect_file_hash", {"file_hash": file_hash}))
                origin = "" if file_hash in top_level else " (pivot: found in event data)"
                context.reasoning_log.append(f"Querying file intelligence for: {file_hash}{origin}")

        timeout = 30 if emergency_mode else self.max_investigation_time
        records: List[Any] = []
        if calls:
            base = len(context.tool_trace)
            try:
                records = await asyncio.wait_for(asyncio.gather(*[
                    self.environment.execute_tool(name, args, step=base + i + 1, actor="planner")
                    for i, (name, args) in enumerate(calls)
                ]), timeout=timeout)
            except asyncio.TimeoutError:
                context.reasoning_log.append(f"Intelligence gathering timed out after {timeout}s")
        for record in records:
            self._trace(context, record)

        def _as_result(record) -> Any:
            return record.data if isinstance(record.data, dict) and record.data else RuntimeError(record.error)

        results: List[Any] = [_as_result(r) for r in records]

        cves = set((context.detection_assessment or {}).get("extracted_iocs", {}).get("cves", []) or [])
        for data in results:
            if isinstance(data, dict):
                cves.update(str(c).upper() for c in data.get("cves", []) or [])
        if cves and self.environment.get("check_cve_kev") and self.environment._intel_sources("cve"):
            try:
                record = await asyncio.wait_for(self.environment.execute_tool(
                    "check_cve_kev", {"cves": sorted(cves)[:50]}, step=len(context.tool_trace) + 1,
                    actor="planner"), timeout=40)
                self._trace(context, record)
                results.append(_as_result(record))
                context.reasoning_log.append(f"Checked {len(cves)} CVE(s) against CISA KEV")
            except asyncio.TimeoutError:
                context.reasoning_log.append("CISA KEV lookup timed out")

        context.intelligence_data = self._process_intelligence_results(results)
        intel = context.intelligence_data
        intel["pivoted_indicators"] = {**targets, "cves": sorted(cves)}
        context.reasoning_log.append(
            f"External reputation sources answered: {intel['sources'] or 'none'}; "
            f"local forensics: {intel.get('local_sources') or 'none'}")

        intel_scan = scan_prompt_injection(intel.get("threat_indicators", []))
        if intel_scan.detected:
            self._merge_injection_scan(context, intel_scan, "intel_data")
            context.reasoning_log.append("PROMPT INJECTION detected inside threat intelligence results (indirect)")
        self.logger.info(f"Intelligence gathering complete for {context.event_id}")

    def _llm_supports_tools(self) -> bool:
        if self.llm is None or self.llm_max_tool_steps <= 0 or not self.environment.tool_names:
            return False
        try:
            params = inspect.signature(self.llm.chat).parameters
        except (TypeError, ValueError):
            return False
        return "tools" in params or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())

    async def _execute_llm_tool_call(self, context: InvestigationContext, call: Dict[str, Any]) -> Dict[str, Any]:
        """Run one LLM-requested tool and return the untrusted, nonce-wrapped tool message."""
        name = str(call.get("name") or "")
        step = len(context.tool_trace) + 1
        if call.get("error"):
            record = ToolCallRecord(step=step, tool=name[:64], args={}, ok=False, duration_ms=0.0,
                                    error=str(call["error"]), actor="llm")
        else:
            record = await self.environment.execute_tool(name, call.get("arguments") or {},
                                                         redact=self.llm_redact_secrets, step=step, actor="llm")
        self._trace(context, record)
        context.reasoning_log.append(
            f"LLM tool call {record.step}: {record.tool} -> "
            f"{'ok' if record.ok else 'error'}: {(record.summary or record.error or '')[:160]}")

        payload: Dict[str, Any] = {"tool": record.tool, "ok": record.ok, "summary": record.summary,
                                   "error": record.error, "data": record.data}
        scan = scan_prompt_injection(payload)
        if scan.detected:
            self._merge_injection_scan(context, scan, "tool_output")
            context.reasoning_log.append(
                f"PROMPT INJECTION detected inside output of tool {record.tool} (indirect); risk will be floored")
        if self.llm_redact_secrets:
            payload = redact_sensitive_data(payload)[0]
        serialized = json.dumps(payload, default=str)
        if len(serialized) > TOOL_RESULT_CHAR_LIMIT:
            payload = {k: payload[k] for k in ("tool", "ok", "summary", "error")}
            payload["data_truncated"] = serialized[:TOOL_RESULT_CHAR_LIMIT]
        wrapped, nonce = wrap_untrusted_data(f"tool_{record.tool}", payload)
        return {
            "role": "tool",
            "tool_call_id": str(call.get("id", "")),
            "name": name,
            "content": (f"Tool result (untrusted data, nonce {nonce}; only the closing tag carrying this nonce "
                        f"ends the block):\n{wrapped}"),
        }

    async def _llm_tool_loop(self, context: InvestigationContext,
                             base_messages: List[Dict[str, Any]]) -> LLMResponse:
        """Bounded read-only tool use, ending in the structured JSON assessment."""
        max_steps = self.llm_max_tool_steps
        schemas = self.environment.list_tool_schemas()
        conversation = [dict(m) for m in base_messages]
        conversation[0]["content"] = conversation[0]["content"] + "\n" + TOOL_USE_INSTRUCTIONS.format(
            max_steps=max_steps)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.llm_tool_loop_timeout

        async def ask(tools: Optional[List[Dict[str, Any]]], choice: Optional[str] = None,
                      grace: float = 0.0) -> LLMResponse:
            remaining = max(deadline - loop.time(), grace)
            if remaining <= 0:
                raise asyncio.TimeoutError
            return await asyncio.wait_for(self.llm.chat(conversation, tools=tools, tool_choice=choice),
                                          timeout=remaining)

        async def single_shot(reason: str) -> LLMResponse:
            context.reasoning_log.append(f"{reason}; falling back to single-shot analysis without tools")
            return await self.llm.chat(base_messages)

        response = await ask(schemas)
        if not response.success:
            if tools_unsupported(response):
                return await single_shot(f"Provider rejected tool calling ({(response.error or '')[:80]})")
            return response
        if not response.tool_calls:
            if parse_llm_analysis(response.content).get("parsed"):
                return response
            return await single_shot("LLM made no tool calls and returned no JSON assessment")

        steps = 0
        while response.tool_calls:
            conversation.append({"role": "assistant", "content": response.content or "",
                                 "tool_calls": response.tool_calls})
            for call in response.tool_calls:
                if steps >= max_steps:
                    conversation.append({"role": "tool", "tool_call_id": str(call.get("id", "")),
                                         "name": str(call.get("name") or ""),
                                         "content": "Not executed: tool-call budget exhausted."})
                    continue
                steps += 1
                conversation.append(await self._execute_llm_tool_call(context, call))
            if steps >= max_steps or loop.time() >= deadline:
                context.reasoning_log.append(f"LLM tool budget reached ({steps}/{max_steps} calls)")
                conversation.append({"role": "user", "content": "Tool budget exhausted. Return your final JSON "
                                                                "assessment now without calling any tools."})
                return await ask(schemas, "none", grace=30.0)
            response = await ask(schemas)
            if not response.success:
                return response
        return response

    async def _llm_analysis(self, context: InvestigationContext):
        if self.llm is None:
            return
        context.phase = InvestigationPhase.LLM_ANALYSIS
        context.reasoning_log.append("=== LLM ANALYSIS ===")
        context.reasoning_log.append(f"Provider: {self.llm.provider_name}/{self.llm.model}")
        detection = context.detection_assessment or {}
        messages = build_analysis_prompt(
            context.event_data, context.intelligence_data,
            redact_secrets=self.llm_redact_secrets,
            detection_context={
                "severity_score": detection.get("severity_score"),
                "findings": [f.get("title") for f in detection.get("findings", [])][:10],
                "mitre_attack": detection.get("mitre_attack", []),
                "mitre_atlas": detection.get("mitre_atlas", []),
                "owasp_llm": detection.get("owasp_llm", []),
                "prompt_injection_detected": bool((context.prompt_injection_scan or {}).get("detected")),
            },
        )
        try:
            if self._llm_supports_tools():
                context.reasoning_log.append(
                    f"Agentic mode: {len(self.environment.tool_names)} read-only tools, "
                    f"budget {self.llm_max_tool_steps} call(s)")
                response = await self._llm_tool_loop(context, messages)
            else:
                response = await self.llm.chat(messages)
            if not response.success:
                context.reasoning_log.append(f"LLM analysis failed: {response.error}")
                context.llm_analysis = None
                return
            analysis = parse_llm_analysis(response.content)
            analysis["provider"] = response.provider
            analysis["model"] = response.model
            analysis["tokens"] = response.usage.get("total_tokens", 0)
            analysis["tool_calls"] = sum(1 for t in context.tool_trace if t.get("actor") == "llm")
            if not analysis.get("parsed"):
                context.reasoning_log.append("LLM returned non-JSON output; treated as low-confidence text")
            if (context.prompt_injection_scan or {}).get("detected") and analysis["risk_modifier"] < 0.5:
                analysis["possible_injection_influence"] = True
                context.reasoning_log.append(
                    "LLM risk estimate is low despite detected injection; deterministic floor enforced")
            context.llm_analysis = analysis
            context.reasoning_log.append(f"Threat: {analysis.get('threat_assessment', '')[:120]}")
            context.reasoning_log.append(
                f"LLM risk modifier {analysis['risk_modifier']:.2f}, confidence {analysis['confidence']:.2f}, "
                f"classification {analysis.get('attack_classification')}, urgency {analysis.get('urgency')}")
            context.reasoning_log.append(f"Tokens used: {analysis['tokens']}")
        except asyncio.TimeoutError:
            context.reasoning_log.append(f"LLM analysis timed out after {self.llm_tool_loop_timeout:g}s")
            context.llm_analysis = None
        except Exception as e:
            context.reasoning_log.append(f"LLM analysis error: {type(e).__name__}")
            context.llm_analysis = None
            self.logger.warning(f"LLM analysis failed: {e}")

    async def _risk_analysis(self, context: InvestigationContext, emergency_mode: bool):
        context.phase = InvestigationPhase.RISK_ANALYSIS
        context.reasoning_log.append("=== RISK ANALYSIS ===")

        detection = context.detection_assessment or {}
        type_severity = self._calculate_base_risk(context.event_data)
        detection_severity = clamp01(detection.get("severity_score", 0.0))
        local_risk = clamp01((context.intelligence_data or {}).get("local_risk", 0.0))
        base_risk = max(type_severity, detection_severity, local_risk)
        context.reasoning_log.append(
            f"Base risk {base_risk:.2f} (type {type_severity:.2f}, detection {detection_severity:.2f}, "
            f"local forensics {local_risk:.2f})")

        intel_risk = self._calculate_intel_risk(context.intelligence_data)
        if intel_risk is None:
            context.reasoning_log.append(
                "Intelligence unavailable: weight redistributed to event evidence with uncertainty floor")
        else:
            context.reasoning_log.append(f"Intelligence risk: {intel_risk:.2f}")

        pattern_risk = await self._calculate_pattern_risk(context)
        context.reasoning_log.append(f"Pattern analysis risk: {pattern_risk:.2f}")

        llm_analysis = context.llm_analysis if isinstance(context.llm_analysis, dict) else None
        llm_risk = clamp01(llm_analysis.get("risk_modifier")) if llm_analysis else None
        if llm_risk is not None:
            context.reasoning_log.append(f"LLM risk modifier applied: {llm_risk:.2f}")

        combined = combine_risk(base_risk, intel_risk, pattern_risk, llm_risk)
        final_risk = combined["score"]
        floor_applied = None
        if (context.prompt_injection_scan or {}).get("detected") and final_risk < PROMPT_INJECTION_RISK_FLOOR:
            floor_applied = {"reason": "prompt_injection_detected", "value": PROMPT_INJECTION_RISK_FLOOR}
            final_risk = PROMPT_INJECTION_RISK_FLOOR
            context.reasoning_log.append(f"Risk floored to {PROMPT_INJECTION_RISK_FLOOR} (prompt injection)")
        final_risk = clamp01(final_risk)
        risk_level = self._determine_risk_level(final_risk)

        context.risk_assessment = {
            "risk_score": round(final_risk, 4),
            "risk_level": risk_level,
            "base_risk": round(base_risk, 4),
            "detection_severity": detection_severity,
            "local_forensic_risk": local_risk,
            "intel_risk": None if intel_risk is None else round(intel_risk, 4),
            "intel_available": intel_risk is not None,
            "pattern_risk": round(pattern_risk, 4),
            "llm_risk": 0.0 if llm_risk is None else round(llm_risk, 4),
            "llm_analysis": llm_analysis,
            "weights": {k: v for k, v in combined.items() if k != "score"},
            "risk_floor_applied": floor_applied,
            "confidence": self._calculate_confidence(context),
            "mitre_attack": detection.get("mitre_attack", []),
            "mitre_atlas": detection.get("mitre_atlas", []),
            "owasp_llm": detection.get("owasp_llm", []),
        }
        context.reasoning_log.append(f"Final risk assessment: {risk_level.upper()} ({final_risk:.2f})")
        self.logger.info(f"Risk analysis complete for {context.event_id}: {risk_level}")

    async def _action_planning(self, context: InvestigationContext, emergency_mode: bool):
        context.phase = InvestigationPhase.ACTION_PLANNING
        context.reasoning_log.append("=== ACTION PLANNING ===")
        risk_level = (context.risk_assessment or {}).get("risk_level", "low")
        event_type = context.event_data.get("event_type")
        actions = self._generate_response_actions(risk_level, event_type, context)
        context.recommended_actions = self._prioritize_actions(actions, emergency_mode)
        context.reasoning_log.append(f"Generated {len(context.recommended_actions)} prioritized actions")
        for i, action in enumerate(context.recommended_actions[:3]):
            context.reasoning_log.append(f"Priority {i + 1}: {action['action_type']} - {action['description']}")

    def _threat_summary(self, context: InvestigationContext) -> str:
        detection = context.detection_assessment or {}
        titles = [f.get("title") for f in detection.get("findings", [])][:3]
        intel = context.intelligence_data or {}
        parts = []
        if titles:
            parts.append("Detections: " + "; ".join(titles))
        if intel.get("sources"):
            parts.append(f"Intel reputation {float(intel.get('reputation_score', 0)):.2f} "
                         f"from {', '.join(intel['sources'])}")
        else:
            parts.append("No external reputation data")
        if (context.prompt_injection_scan or {}).get("detected"):
            parts.append("Prompt injection content present")
        return ". ".join(parts)

    def _action_targets(self, action_key: str, context: InvestigationContext) -> List[tuple]:
        """Return (integration_action, target, indicator_type) tuples for one planned action."""
        event = context.event_data
        source_ip = str(event.get("source_ip") or "")
        url = str(event.get("url") or "")
        file_hash = str(event.get("file_hash") or "")
        title = (f"[ThreatSentinel] {str((context.risk_assessment or {}).get('risk_level', 'unknown')).upper()} "
                 f"{event.get('event_type', 'event')} - {context.investigation_id}")

        if action_key == "BLOCK":
            targets = []
            if url:
                targets.append((IntegrationActionType.BLOCK_URL, url, "url"))
            if source_ip and is_public_ip(source_ip):
                targets.append((IntegrationActionType.BLOCK_IP, source_ip, "ip"))
            return targets
        if action_key == "MONITOR":
            indicator = (source_ip, "ip") if source_ip else (url, "url") if url else (file_hash, "hash")
            return [(IntegrationActionType.ADD_TO_WATCHLIST, indicator[0], indicator[1])] if indicator[0] else []
        mapping = {
            "ESCALATE": IntegrationActionType.ESCALATE,
            "ALERT": IntegrationActionType.SEND_ALERT,
            "INVESTIGATE": IntegrationActionType.CREATE_INCIDENT,
        }
        if action_key in mapping:
            return [(mapping[action_key], title, "message")]
        return []

    async def _execute_actions(self, context: InvestigationContext):
        if not context.recommended_actions:
            return
        if not self.integrations.active_integrations:
            context.reasoning_log.append("No active integrations configured, actions are recommendations only")
            context.actions_executed = []
            return

        context.reasoning_log.append("=== ACTION EXECUTION ===")
        executed = []
        risk = context.risk_assessment or {}
        base_context = {
            "investigation_id": context.investigation_id,
            "event_id": context.event_id,
            "event_type": context.event_data.get("event_type"),
            "risk_score": risk.get("risk_score"),
            "risk_level": risk.get("risk_level", "unknown"),
            "severity": risk.get("risk_level", "medium"),
            "source_ip": context.event_data.get("source_ip"),
            "threat_summary": self._threat_summary(context),
            "actions": [a.get("description", "") for a in context.recommended_actions],
            "timestamp": _utcnow().isoformat(),
        }

        for action in context.recommended_actions:
            action_key = action.get("action_type", "")
            targets = self._action_targets(action_key, context)
            if not targets and action_key == "BLOCK":
                context.reasoning_log.append("BLOCK skipped: no public IP or URL to block")
            for integration_action, target, indicator_type in targets:
                action_context = {
                    **base_context,
                    "description": action.get("description", ""),
                    "reason": action.get("description", "Security threat"),
                    "indicator_type": indicator_type,
                    "threat_level": risk.get("risk_level", "medium"),
                }
                try:
                    response = await self.integrations.execute_action(
                        action_type=integration_action, target=target, context=action_context)
                    executed.append({
                        "action": action_key,
                        "integration_action": integration_action.value,
                        "target": target,
                        "success": response.success,
                        "integrations_used": response.metadata.get("integration_names", []),
                    })
                    context.reasoning_log.append(
                        f"Action {action_key} -> {integration_action.value} on {target}: "
                        f"{'SUCCESS' if response.success else 'FAILED'}")
                except Exception as e:
                    self.logger.warning(f"Failed to execute {action_key}: {e}")
                    executed.append({"action": action_key, "integration_action": integration_action.value,
                                     "target": target, "success": False, "error": str(e)[:300]})
                    context.reasoning_log.append(f"Action {action_key} FAILED: {type(e).__name__}")
        context.actions_executed = executed

    async def _generate_report(self, context: InvestigationContext):
        context.phase = InvestigationPhase.REPORTING
        context.report = await self.reporter.generate_report(context)
        self.logger.info(f"Report generated for {context.event_id}")

    async def _update_memory(self, context: InvestigationContext):
        context.phase = InvestigationPhase.MEMORY_UPDATE
        await self.memory.store_investigation(context)
        context.reasoning_log.append("Investigation stored in agent memory for future learning")

    # ------------------------------------------------------------------ scoring helpers

    def _classify_event_severity(self, event_data: Dict[str, Any]) -> float:
        event_type = event_data.get("event_type", "unknown")
        severity = EVENT_TYPE_BASELINE.get(event_type, EVENT_TYPE_BASELINE["unknown"])
        payload = event_data.get("payload") if isinstance(event_data.get("payload"), dict) else {}
        try:
            attempts = float(payload.get("failed_login_attempts", 0) or 0)
        except (TypeError, ValueError):
            attempts = 0
        if attempts > 50:
            severity += 0.3
        elif attempts > 10:
            severity += 0.2
        elif attempts > 3:
            severity += 0.1
        if event_data.get("internal_source", False):
            severity += 0.1
        return min(severity, 1.0)

    def _process_intelligence_results(self, intel_results: List) -> Dict[str, Any]:
        processed: Dict[str, Any] = {
            "sources": [], "reputation_score": 0.0, "threat_indicators": [], "confidence": 0.0,
            "local_sources": [], "local_risk": 0.0, "sources_queried": [], "individual_results": [],
            "cves": [], "kev_matches": [], "errors": {},
        }
        valid = [r for r in intel_results if r is not None and not isinstance(r, BaseException)]
        for result in valid:
            if isinstance(result, dict):
                success, source, data = result.get("success"), result.get("source", "unknown"), result
            else:
                success = getattr(result, "success", False)
                source = getattr(result, "source", "unknown")
                data = getattr(result, "data", {}) or {}
            if not success:
                if isinstance(data, dict) and data.get("errors"):
                    processed["errors"].update(data["errors"])
                continue

            if source == "registry":
                rep_sources = data.get("reputation_sources", [])
                processed["sources"].extend(s for s in rep_sources if s not in processed["sources"])
                processed["local_sources"].extend(
                    s for s in data.get("local_sources", []) if s not in processed["local_sources"])
                processed["sources_queried"].extend(data.get("sources_queried", []))
                if rep_sources:
                    processed["reputation_score"] = max(processed["reputation_score"],
                                                        float(data.get("reputation_score", 0) or 0))
                processed["local_risk"] = max(processed["local_risk"], float(data.get("local_risk", 0) or 0))
                processed["individual_results"].extend(data.get("individual_results", []))
                processed["errors"].update(data.get("errors", {}) or {})
                for item in data.get("individual_results", []):
                    processed["kev_matches"].extend(item.get("kev_matches", []) or [])
            else:
                if source not in processed["sources"]:
                    processed["sources"].append(source)
                processed["reputation_score"] = max(processed["reputation_score"],
                                                    float(data.get("reputation_score", 0) or 0))
            processed["threat_indicators"].extend(data.get("indicators", []) or [])
            processed["cves"].extend(c for c in data.get("cves", []) or [] if c not in processed["cves"])

        if valid:
            errors = len([r for r in intel_results if isinstance(r, BaseException)])
            processed["confidence"] = len(valid) / (len(valid) + errors)
        return processed

    def _calculate_base_risk(self, event_data: Dict[str, Any]) -> float:
        return self._classify_event_severity(event_data)

    def _calculate_intel_risk(self, intel_data: Dict[str, Any]) -> Optional[float]:
        """Risk from external reputation, or None when no reputation source answered.

        Absence of intelligence is uncertainty, not safety. Enrichment-only
        sources (RDAP) and local forensics never count as reputation.
        """
        if not intel_data or not intel_data.get("sources"):
            return None
        score = float(intel_data.get("reputation_score", 0.0) or 0.0)
        if intel_data.get("kev_matches"):
            score = max(score, 0.8)
        return clamp01(score)

    async def _calculate_pattern_risk(self, context: InvestigationContext) -> float:
        """Share of similar past events that were high risk, discounted by false positives."""
        similar = context.similar_events
        if not similar:
            found = await self.memory.find_similar_events(context.event_data, limit=10)
            similar = [{"event_id": m.event_id, "risk_score": m.risk_score, "false_positive": m.false_positive,
                        "similarity": getattr(m, "similarity", 1.0)}
                       for m in found or [] if m.event_id != context.event_id]
        if not similar:
            return 0.0

        weights = [max(float(e.get("similarity", 1.0) or 1.0), 0.05) for e in similar]
        total = sum(weights)
        high = sum(w for e, w in zip(similar, weights, strict=True)
                   if not e.get("false_positive") and float(e.get("risk_score", 0)) > 0.7)
        fp_weight = sum(w for e, w in zip(similar, weights, strict=True) if e.get("false_positive"))
        pattern_risk = high / total if total else 0.0
        fp_ratio = fp_weight / total if total else 0.0
        if fp_ratio > 0.5:
            pattern_risk *= (1.0 - fp_ratio)
            context.reasoning_log.append(
                f"{fp_ratio:.0%} of similar past events were analyst-confirmed false positives; "
                "pattern risk discounted")
        return clamp01(pattern_risk)

    def _determine_risk_level(self, risk_score: float) -> str:
        if risk_score >= 0.8:
            return "critical"
        if risk_score >= 0.6:
            return "high"
        if risk_score >= 0.3:
            return "medium"
        return "low"

    def _calculate_confidence(self, context: InvestigationContext) -> float:
        confidence = 0.5
        intel = context.intelligence_data or {}
        confidence += min(len(intel.get("sources", [])) * 0.1, 0.3)
        if intel.get("confidence", 0) > 0:
            confidence += 0.1
        if (context.detection_assessment or {}).get("findings"):
            confidence += 0.05
        llm_analysis = context.llm_analysis if isinstance(context.llm_analysis, dict) else None
        if llm_analysis:
            confidence += clamp01(llm_analysis.get("confidence", 0)) * 0.2
        return round(clamp01(confidence), 4)

    def _generate_response_actions(self, risk_level: str, event_type: str,
                                   context: InvestigationContext) -> List[Dict[str, Any]]:
        actions: List[Dict[str, Any]] = []
        if risk_level == "critical":
            actions += [
                {"action_type": "BLOCK", "priority": 1, "description": "Immediately block malicious indicator",
                 "estimated_effort": "5 minutes"},
                {"action_type": "ESCALATE", "priority": 1, "description": "Escalate to security team immediately",
                 "estimated_effort": "2 minutes"},
            ]
        elif risk_level == "high":
            actions += [
                {"action_type": "INVESTIGATE", "priority": 2, "description": "Conduct detailed investigation",
                 "estimated_effort": "30 minutes"},
                {"action_type": "MONITOR", "priority": 3, "description": "Enhanced monitoring for 24 hours",
                 "estimated_effort": "10 minutes setup"},
            ]
        elif risk_level == "medium":
            actions += [
                {"action_type": "MONITOR", "priority": 3, "description": "Monitor for suspicious activity",
                 "estimated_effort": "5 minutes"},
                {"action_type": "ALERT", "priority": 4, "description": "Send alert to administrators",
                 "estimated_effort": "2 minutes"},
            ]
        else:
            actions.append({"action_type": "ALERT", "priority": 5, "description": "Log event for review",
                            "estimated_effort": "1 minute"})

        return self._enrich_actions(actions, risk_level, event_type, context)

    def _integration_capabilities(self) -> Dict[str, List[str]]:
        """Live map of integration action -> active integrations that support it."""
        capabilities: Dict[str, List[str]] = {}
        for name, integration in (self.integrations.active_integrations or {}).items():
            try:
                supported = integration.get_supported_actions()
            except Exception as e:  # an integration that cannot describe itself supports nothing
                self.logger.debug(f"Integration {name} did not report capabilities: {type(e).__name__}")
                supported = []
            for action in supported:
                capabilities.setdefault(getattr(action, "value", str(action)), []).append(name)
        return capabilities

    def _threat_triggers(self, risk_level: str, event_type: str,
                         context: InvestigationContext) -> List[Dict[str, Any]]:
        """Categories the evidence supports, strongest first."""
        triggers: List[Dict[str, Any]] = []
        findings = sorted((context.detection_assessment or {}).get("findings", []) or [],
                          key=lambda f: -float(f.get("severity", 0) or 0))
        if (context.prompt_injection_scan or {}).get("detected"):
            triggers.append({"category": "prompt_injection", "source": "guardrail_scan"})
        for finding in findings:
            if float(finding.get("severity", 0) or 0) >= 0.5:
                triggers.append({"category": finding.get("category"), "source": "detection",
                                 "rule_id": finding.get("rule_id"),
                                 "owasp_llm": finding.get("owasp_llm", []),
                                 "mitre_attack": finding.get("mitre_attack", []),
                                 "mitre_atlas": finding.get("mitre_atlas", [])})
        # A claimed event type alone only counts once risk is at least medium
        if risk_level != "low" and event_type:
            triggers.append({"category": event_type, "source": "event_type"})
        return triggers

    def _enrich_actions(self, actions: List[Dict[str, Any]], risk_level: str, event_type: str,
                        context: InvestigationContext) -> List[Dict[str, Any]]:
        capabilities = self._integration_capabilities()
        for action in actions:
            needed = EXECUTABLE_ACTIONS.get(action["action_type"], ())
            capable = sorted({n for a in needed for n in capabilities.get(a.value, [])})
            action["automated_capable"] = bool(capable)
            action["capable_integrations"] = capable

        priority = {"critical": 1, "high": 1, "medium": 2}.get(risk_level, 3)
        seen = {a["action_type"] for a in actions}
        for trigger in self._threat_triggers(risk_level, event_type, context):
            playbook = THREAT_PLAYBOOKS.get(str(trigger.get("category")))
            if not playbook or playbook[0] in seen:
                continue
            action_type, description = playbook
            seen.add(action_type)
            action = {"action_type": action_type, "priority": priority, "description": description,
                      "estimated_effort": "15-60 minutes", "trigger": trigger["category"],
                      "trigger_source": trigger["source"], "automated_capable": False,
                      "capable_integrations": [], "execution": "analyst_playbook"}
            for key in ("rule_id", "owasp_llm", "mitre_attack", "mitre_atlas"):
                if trigger.get(key):
                    action[key] = trigger[key]
            actions.append(action)
        return actions

    def _prioritize_actions(self, actions: List[Dict[str, Any]], emergency_mode: bool) -> List[Dict[str, Any]]:
        if emergency_mode:
            actions = [a for a in actions if a["priority"] <= 2]
        return sorted(actions, key=lambda x: x["priority"])

    async def _handle_investigation_failure(self, context: InvestigationContext,
                                            error: Exception) -> Dict[str, Any]:
        self.logger.error(f"Investigation failed: {type(error).__name__}: {error}")
        return {
            "event_id": context.event_id,
            "investigation_id": context.investigation_id,
            "status": "failed",
            "error": f"{type(error).__name__}: {str(error)[:300]}",
            "phase": context.phase.value,
            "audit_trail": context.audit_trail,
            "recommended_actions": [{
                "action_type": "ESCALATE",
                "priority": 1,
                "description": "Manual investigation required due to system error",
                "estimated_effort": "60 minutes",
            }],
        }
