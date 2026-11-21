"""
SOC Agent Reporter - incident report generation.

Outputs JSON, Markdown, XSS-safe HTML and a STIX 2.1 bundle from an
investigation context. Context objects may be partial (e.g. rebuilt from the
API store), so every field is read defensively.
"""

import ipaddress
import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, select_autoescape

from .guardrails import is_public_ip
from .scoring import risk_weights

STIX_SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
THREATSENTINEL_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "threatsentinel.local")
_SAFE_FILE_ID = re.compile(r"[^\w\-]")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Any) -> datetime:
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except ValueError:
            return _utcnow()
    if not isinstance(dt, datetime):
        return _utcnow()
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _stix_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def defang(value: str, ioc_type: str = "") -> str:
    """Make an IOC non-clickable for safe sharing."""
    text = str(value)
    text = re.sub(r"^http", "hxxp", text, flags=re.IGNORECASE)
    text = re.sub(r"^ftp", "fxp", text, flags=re.IGNORECASE)
    if ioc_type in ("md5", "sha1", "sha256", "cve", "hash"):
        return text
    if ":" in text and ioc_type in ("ip", "ipv6"):
        return text.replace(":", "[:]")
    return text.replace(".", "[.]").replace("@", "[@]")


def _md_inline(value: Any) -> str:
    """Neutralize text for use inside a Markdown code span."""
    return str(value).replace("`", "'").replace("\n", " ")[:300]


def _md_cell(value: Any) -> str:
    """Neutralize text for use inside a Markdown table cell."""
    return _md_inline(value).replace("|", "\\|").replace("\r", " ")


@dataclass
class ReportSection:
    """Structured section of an investigation report"""
    title: str
    content: str
    severity: str = "info"  # info, warning, error, critical
    data: Optional[Dict[str, Any]] = None


MARKDOWN_TEMPLATE = """
# Security Incident Investigation Report

**Event ID:** {{ event_id }}
**Investigation Date:** {{ timestamp }}
**Duration:** {{ duration_minutes }} minutes
**Risk Level:** {{ risk_level | upper }}
**Status:** {{ status }}

## Executive Summary

{{ executive_summary }}

## Event Details

**Event Type:** {{ event_type }}
**Source IP:** {{ source_ip }}
**Detection Time:** {{ detection_time }}

{{ event_details }}

## Detection Engine Findings

{% if findings -%}
{% for f in findings -%}
- **{{ f.title }}** (`{{ f.rule_id }}`, severity {{ '%.2f' | format(f.severity) }}){% if f.evidence %}: {{ f.evidence | join('; ') }}{% endif %}
{% endfor %}
{% else -%}
No deterministic detection rules fired.
{% endif %}

| Framework | Mapped IDs |
|-----------|-----------|
| MITRE ATT&CK | {{ mitre_attack | join(', ') if mitre_attack else 'None' }} |
| MITRE ATLAS | {{ mitre_atlas | join(', ') if mitre_atlas else 'None' }} |
| OWASP LLM Top 10 (2025) | {{ owasp_llm | join(', ') if owasp_llm else 'None' }} |

## LLM Guardrails

- **Prompt injection in telemetry:** {{ 'DETECTED' if guardrails.prompt_injection_detected else 'not detected' }}{% if guardrails.score %} (score {{ '%.2f' | format(guardrails.score) }}){% endif %}
{% if guardrails.matched_rules -%}
- **Matched rules:** {{ guardrails.matched_rules | join(', ') }}
{% endif -%}
- **Secrets redacted before LLM egress:** {{ guardrails.redacted_secret_types | join(', ') if guardrails.redacted_secret_types else 'none found' }}
- **Untrusted data isolation:** nonce-tagged blocks, LLM output clamped to [0, 1]

## LLM Analysis

{% if llm_analysis -%}
**Classification:** {{ llm_analysis.attack_classification or 'unknown' }} | **Urgency:** {{ llm_analysis.urgency or 'unknown' }} | **Confidence:** {{ llm_analysis.confidence }}

{{ llm_analysis.threat_assessment }}

{% for finding in llm_analysis.key_findings or [] -%}
- {{ finding }}
{% endfor %}
{% else -%}
No LLM analysis was performed (no provider configured or the call failed). Scoring used deterministic evidence only.
{% endif %}

## Threat Intelligence Analysis

{{ threat_intelligence_summary }}

{% for source in intelligence_sources -%}
- **{{ source.name }}**: {{ source.summary }}
{% endfor %}

## Risk Assessment

**Overall Risk Score:** {{ risk_score }}/1.0 ({{ risk_level | upper }})

| Component | Score | Weight | Contribution |
|-----------|-------|--------|--------------|
{% for row in risk_rows -%}
| {{ row.name }} | {{ row.score }} | {{ row.weight }} | {{ row.contribution }} |
{% endfor %}

**Confidence Level:** {{ confidence }}%

{{ risk_explanation }}

## Recommended Actions

{% for action in recommended_actions -%}
### {{ loop.index }}. {{ action.action_type }} (Priority {{ action.priority }})

**Description:** {{ action.description }}
**Estimated Effort:** {{ action.estimated_effort }}
{% if action.technical_details -%}
**Technical Details:** {{ action.technical_details }}
{% endif %}

{% if action.trigger -%}
**Triggered by:** {{ action.trigger }}{% if action.rule_id %} (`{{ action.rule_id }}`){% endif %}
{% endif -%}
**Automation:** {{ ('available via ' ~ action.capable_integrations | join(', ')) if action.automated_capable else 'manual / analyst playbook' }}

{% else -%}
No automated actions recommended{% if status == 'pending_human_review' %} (awaiting analyst review){% endif %}.
{% endfor %}

## Agent Tool Trace

{% if tool_trace -%}
Read-only tools the agent chose to call during this investigation.

| # | Actor | Tool | Arguments | Result | Time (ms) |
|---|-------|------|-----------|--------|-----------|
{% for t in tool_trace -%}
| {{ t.step }} | {{ t.actor }} | {{ t.tool_md }} | `{{ t.args_md }}` | {{ 'ok' if t.ok else 'error' }}: {{ t.result_md }} | {{ t.duration_ms }} |
{% endfor %}
{% else -%}
No tools were called.
{% endif %}

## Pattern Insights

{% if pattern_insights -%}
{% for insight in pattern_insights -%}
- **{{ insight.pattern_type }}**: {{ insight.description }} (Confidence: {{ (insight.confidence * 100) | round(1) }}%)
{% endfor %}
{% else -%}
No historical patterns matched.
{% endif %}

## Indicators of Compromise (IoCs)

{% if iocs -%}
| Type | Defanged | Raw | Source |
|------|----------|-----|--------|
{% for ioc in iocs -%}
| {{ ioc.type }} | `{{ ioc.defanged }}` | `{{ ioc.value_md }}` | {{ ioc.source }} |
{% endfor %}
{% else -%}
No specific indicators of compromise identified.
{% endif %}

## Investigation Timeline

{% for step in reasoning_log -%}
- {{ step }}
{% endfor %}

{% if include_raw_data -%}
## Appendix: Raw Intelligence Data
```json
{{ raw_data | tojson(indent=2) }}
```
{% endif %}

---
*Report generated by ThreatSentinel SOC Agent v{{ agent_version }}*
*Classification: {{ classification }}*
"""

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<title>ThreatSentinel Report {{ event_id }}</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:2rem auto;max-width:960px;color:#1b1f24;line-height:1.5;padding:0 1rem}
 h1{border-bottom:3px solid #1b1f24;padding-bottom:.4rem}
 h2{margin-top:2rem;border-bottom:1px solid #d0d7de;padding-bottom:.2rem}
 table{border-collapse:collapse;width:100%;margin:.8rem 0}
 th,td{border:1px solid #d0d7de;padding:.35rem .6rem;text-align:left;vertical-align:top;font-size:.92rem}
 th{background:#f6f8fa}
 code{background:#f6f8fa;padding:.1rem .3rem;border-radius:4px;word-break:break-all}
 .badge{display:inline-block;padding:.15rem .6rem;border-radius:999px;color:#fff;font-weight:600}
 .critical{background:#a40e26}.high{background:#d1242f}.medium{background:#bf8700}.low{background:#1a7f37}.unknown{background:#57606a}
 .muted{color:#57606a}
 ul.timeline li{font-family:ui-monospace,monospace;font-size:.85rem}
</style>
</head>
<body>
<h1>Security Incident Investigation Report</h1>
<p><strong>Event ID:</strong> <code>{{ event_id }}</code> &middot; <strong>Generated:</strong> {{ timestamp }}
&middot; <strong>Status:</strong> {{ status }}</p>
<p><span class="badge {{ risk_level_class }}">{{ risk_level | upper }}</span>
 &nbsp;Risk score <strong>{{ risk_score }}</strong> / 1.0 &middot; Confidence {{ confidence }}%</p>

<h2>Executive Summary</h2>
{% for para in executive_summary_paragraphs %}<p>{{ para }}</p>{% endfor %}

<h2>Event</h2>
<table>
<tr><th>Event type</th><td>{{ event_type }}</td></tr>
<tr><th>Source IP</th><td><code>{{ source_ip }}</code></td></tr>
<tr><th>Detection time</th><td>{{ detection_time }}</td></tr>
{% for key, value in event_fields %}<tr><th>{{ key }}</th><td><code>{{ value }}</code></td></tr>{% endfor %}
</table>

<h2>Detection Engine</h2>
{% if findings %}<ul>{% for f in findings %}<li><strong>{{ f.title }}</strong> <code>{{ f.rule_id }}</code>
 (severity {{ '%.2f' | format(f.severity) }}){% if f.evidence %}: {{ f.evidence | join('; ') }}{% endif %}</li>{% endfor %}</ul>
{% else %}<p class="muted">No deterministic detection rules fired.</p>{% endif %}
<table>
<tr><th>MITRE ATT&amp;CK</th><td>{{ mitre_attack | join(', ') if mitre_attack else 'None' }}</td></tr>
<tr><th>MITRE ATLAS</th><td>{{ mitre_atlas | join(', ') if mitre_atlas else 'None' }}</td></tr>
<tr><th>OWASP LLM Top 10 (2025)</th><td>{{ owasp_llm | join(', ') if owasp_llm else 'None' }}</td></tr>
</table>

<h2>LLM Guardrails</h2>
<table>
<tr><th>Prompt injection in telemetry</th><td>{{ 'DETECTED' if guardrails.prompt_injection_detected else 'not detected' }}
{% if guardrails.matched_rules %}({{ guardrails.matched_rules | join(', ') }}){% endif %}</td></tr>
<tr><th>Secrets redacted before LLM egress</th><td>{{ guardrails.redacted_secret_types | join(', ') if guardrails.redacted_secret_types else 'none found' }}</td></tr>
</table>

<h2>LLM Analysis</h2>
{% if llm_analysis %}<p><strong>{{ llm_analysis.attack_classification or 'unknown' }}</strong>, urgency {{ llm_analysis.urgency }},
 confidence {{ llm_analysis.confidence }}</p><p>{{ llm_analysis.threat_assessment }}</p>
<ul>{% for item in llm_analysis.key_findings or [] %}<li>{{ item }}</li>{% endfor %}</ul>
{% else %}<p class="muted">No LLM analysis performed; deterministic evidence only.</p>{% endif %}

<h2>Threat Intelligence</h2>
<p>{{ threat_intelligence_summary }}</p>
<ul>{% for i in intel_indicators %}<li>{{ i }}</li>{% endfor %}</ul>

<h2>Risk Breakdown</h2>
<table><tr><th>Component</th><th>Score</th><th>Weight</th><th>Contribution</th></tr>
{% for row in risk_rows %}<tr><td>{{ row.name }}</td><td>{{ row.score }}</td><td>{{ row.weight }}</td><td>{{ row.contribution }}</td></tr>{% endfor %}
</table>
<p>{{ risk_explanation }}</p>

<h2>Recommended Actions</h2>
{% if recommended_actions %}<ol>{% for a in recommended_actions %}<li><strong>{{ a.action_type }}</strong>
 (priority {{ a.priority }}, {{ a.urgency }}): {{ a.description }}</li>{% endfor %}</ol>
{% else %}<p class="muted">No automated actions recommended.</p>{% endif %}

<h2>Agent Tool Trace</h2>
{% if tool_trace %}<table><tr><th>#</th><th>Actor</th><th>Tool</th><th>Arguments</th><th>Result</th><th>ms</th></tr>
{% for t in tool_trace %}<tr><td>{{ t.step }}</td><td>{{ t.actor }}</td><td><code>{{ t.tool }}</code></td>
<td><code>{{ t.args_text }}</code></td><td>{{ 'ok' if t.ok else 'error' }}: {{ t.result }}</td><td>{{ t.duration_ms }}</td></tr>{% endfor %}
</table>{% else %}<p class="muted">No tools were called.</p>{% endif %}

<h2>Pattern Insights</h2>
{% if pattern_insights %}<ul>{% for p in pattern_insights %}<li><strong>{{ p.pattern_type }}</strong>: {{ p.description }}</li>{% endfor %}</ul>
{% else %}<p class="muted">No historical patterns matched.</p>{% endif %}

<h2>Indicators of Compromise</h2>
{% if iocs %}<table><tr><th>Type</th><th>Defanged</th><th>Source</th></tr>
{% for ioc in iocs %}<tr><td>{{ ioc.type }}</td><td><code>{{ ioc.defanged }}</code></td><td>{{ ioc.source }}</td></tr>{% endfor %}
</table>{% else %}<p class="muted">No indicators of compromise identified.</p>{% endif %}

<h2>Investigation Timeline</h2>
<ul class="timeline">{% for step in reasoning_log %}<li>{{ step }}</li>{% endfor %}</ul>

<hr><p class="muted">Generated by ThreatSentinel SOC Agent v{{ agent_version }} &middot; {{ classification }}</p>
</body>
</html>
"""


class IncidentReporter:
    """Incident report generator (JSON, Markdown, HTML, STIX 2.1)."""

    AGENT_VERSION = "2.1.0"

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        self.reports_dir = Path(self.config.get("reports_dir", "reports"))
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.include_raw_data = self.config.get("include_raw_data", False)
        self.auto_save = self.config.get("auto_save", True)

        self._init_templates()
        self.logger.info(f"Incident reporter initialized - reports: {self.reports_dir}")

    def _init_templates(self):
        # Markdown is plain text: autoescape off. HTML: autoescape forced on.
        md_env = Environment(autoescape=False, trim_blocks=False)  # noqa: S701 - Markdown output, not HTML
        html_env = Environment(autoescape=select_autoescape(enabled_extensions=("html",), default_for_string=True,
                                                            default=True))
        self.markdown_template = md_env.from_string(MARKDOWN_TEMPLATE)
        self.html_template = html_env.from_string(HTML_TEMPLATE)

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _ctx(context, name: str, default: Any = None) -> Any:
        value = getattr(context, name, default)
        return default if value is None else value

    def _detection(self, context) -> Dict[str, Any]:
        detection = self._ctx(context, "detection_assessment", {})
        if hasattr(detection, "to_dict"):
            detection = detection.to_dict()
        return detection if isinstance(detection, dict) else {}

    def _guardrails(self, context) -> Dict[str, Any]:
        scan = self._ctx(context, "prompt_injection_scan", {})
        if hasattr(scan, "to_dict"):
            scan = scan.to_dict()
        scan = scan if isinstance(scan, dict) else {}
        detection = self._detection(context)
        return {
            "prompt_injection_detected": bool(scan.get("detected") or detection.get("prompt_injection_detected")),
            "score": scan.get("score", 0.0),
            "matched_rules": scan.get("matched_rules", []),
            "owasp_categories": scan.get("owasp_categories", []),
            "mitre_atlas_ids": scan.get("mitre_atlas_ids", []),
            "redacted_secret_types": detection.get("redacted_secret_types", []),
        }

    def _llm_analysis(self, context) -> Optional[Dict[str, Any]]:
        risk = self._ctx(context, "risk_assessment", {})
        llm = risk.get("llm_analysis") or self._ctx(context, "llm_analysis", None)
        return llm if isinstance(llm, dict) else None

    def _pattern_insights(self, context) -> List[Dict[str, Any]]:
        out = []
        for insight in self._ctx(context, "pattern_insights", []) or []:
            if hasattr(insight, "__dataclass_fields__"):
                insight = {k: getattr(insight, k) for k in insight.__dataclass_fields__}
            if isinstance(insight, dict):
                out.append({
                    "pattern_type": insight.get("pattern_type", "pattern"),
                    "description": insight.get("description", ""),
                    "confidence": float(insight.get("confidence", 0.0) or 0.0),
                    "recommendation": insight.get("recommendation", ""),
                })
        return out

    def _tool_trace(self, context) -> List[Dict[str, Any]]:
        out = []
        for entry in self._ctx(context, "tool_trace", []) or []:
            if hasattr(entry, "to_dict"):
                entry = entry.to_dict()
            if not isinstance(entry, dict):
                continue
            out.append({
                "step": entry.get("step"),
                "actor": entry.get("actor", "planner"),
                "tool": str(entry.get("tool", ""))[:64],
                "args": entry.get("args") or {},
                "ok": bool(entry.get("ok")),
                "duration_ms": entry.get("duration_ms", 0),
                "summary": str(entry.get("summary") or "")[:300],
                "error": (str(entry["error"])[:300] if entry.get("error") else None),
            })
        return out

    # ------------------------------------------------------------------ main

    async def generate_report(self, context) -> Dict[str, Any]:
        try:
            start = _aware(self._ctx(context, "start_time", _utcnow()))
            duration_minutes = round((_utcnow() - start).total_seconds() / 60, 2)
            intelligence_data = self._ctx(context, "intelligence_data", {})

            report: Dict[str, Any] = {
                "metadata": self._generate_metadata(context, duration_minutes),
                "executive_summary": self._generate_executive_summary(context),
                "event_analysis": self._generate_event_analysis(context),
                "detection": self._detection(context),
                "guardrails": self._guardrails(context),
                "llm_analysis": self._llm_analysis(context),
                "threat_intelligence": self._generate_threat_intelligence_section(context),
                "risk_assessment": self._generate_risk_assessment_section(context),
                "recommended_actions": self._generate_actions_section(context),
                "pattern_insights": self._pattern_insights(context),
                "tool_trace": self._tool_trace(context),
                "investigation_timeline": list(self._ctx(context, "reasoning_log", [])),
                "technical_details": self._generate_technical_section(context),
                "indicators": self._extract_indicators(context),
                "raw_data": intelligence_data if self.include_raw_data else {},
            }

            report["formats"] = {
                "markdown": self._generate_markdown_report(report, context),
                "html": self._generate_html_report(report, context),
                "stix": json.dumps(self._generate_stix_bundle(report, context), indent=2),
            }
            report["formats"]["json"] = json.dumps(
                {k: v for k, v in report.items() if k != "formats"}, indent=2, default=str)

            if self.auto_save:
                await self._save_report(context.event_id, report)

            self.logger.info(f"Generated report for {context.event_id}")
            return report
        except Exception as e:
            self.logger.exception(f"Failed to generate report: {e}")
            return self._generate_error_report(context, e)

    def _generate_metadata(self, context, duration_minutes: float) -> Dict[str, Any]:
        return {
            "event_id": context.event_id,
            "investigation_id": self._ctx(context, "investigation_id", context.event_id),
            "report_version": "2.1",
            "generated_at": _utcnow().isoformat(),
            "investigation_duration_minutes": duration_minutes,
            "agent_version": self.AGENT_VERSION,
            "classification": "TLP:AMBER",
            "status": str(self._ctx(context, "status", "COMPLETED")).upper(),
        }

    def _generate_executive_summary(self, context) -> str:
        event_data = self._ctx(context, "event_data", {})
        risk = self._ctx(context, "risk_assessment", {})
        intel = self._ctx(context, "intelligence_data", {})
        event_type = event_data.get("event_type", "unknown")
        risk_level = risk.get("risk_level", "unknown")
        risk_score = float(risk.get("risk_score", 0.0) or 0.0)
        descriptions = {
            "low": "appears to be benign or poses minimal threat",
            "medium": "requires monitoring and investigation",
            "high": "poses significant security risk and requires immediate attention",
            "critical": "represents an imminent threat requiring emergency response",
        }
        source_ip = event_data.get("source_ip", "unknown")
        intel_sources = len(intel.get("sources", []))
        intel_phrase = (f"gathering reputation data from {intel_sources} external source(s)" if intel_sources
                        else "finding no external reputation data (scored with an uncertainty floor, not as clean)")
        summary = (
            f"This investigation analyzed a {event_type} security event involving source IP {source_ip}.\n"
            f"After {intel_phrase} and performing risk analysis, the event has been classified as "
            f"**{str(risk_level).upper()}** risk (score: {risk_score:.2f}/1.0).\n\n"
            f"The investigation determined that this event {descriptions.get(risk_level, 'requires further analysis')}."
        )
        detection = self._detection(context)
        if detection.get("findings"):
            top = detection["findings"][0]
            summary += f"\n\nTop detection: **{top.get('title')}** ({top.get('rule_id')})."
        if self._guardrails(context)["prompt_injection_detected"]:
            summary += ("\n\n**Prompt injection content was found in the telemetry.** It was isolated from the "
                        "LLM and raised the risk score.")
        if (intel.get("reputation_score") or 0) > 0.7:
            summary += "\n\n**High-confidence threat intelligence indicates malicious activity.**"
        actions = self._ctx(context, "recommended_actions", [])
        if actions:
            summary += f"\n\n**{len(actions)} prioritized response actions have been recommended.**"
        if self._ctx(context, "status", "") == "pending_human_review":
            summary += "\n\n**Escalated for analyst review before any automated response.**"
        return summary

    def _generate_event_analysis(self, context) -> Dict[str, Any]:
        event_data = self._ctx(context, "event_data", {})
        start = _aware(self._ctx(context, "start_time", _utcnow()))
        return {
            "event_type": event_data.get("event_type", "unknown"),
            "source_ip": event_data.get("source_ip"),
            "detection_time": event_data.get("timestamp", start.isoformat()),
            "user_agent": event_data.get("user_agent"),
            "payload_summary": self._summarize_payload(event_data.get("payload", {})),
            "event_characteristics": self._analyze_event_characteristics(event_data),
        }

    def _generate_threat_intelligence_section(self, context) -> Dict[str, Any]:
        intel = self._ctx(context, "intelligence_data", {})
        section = {
            "sources_consulted": intel.get("sources", []),
            "local_sources": intel.get("local_sources", []),
            "overall_reputation_score": intel.get("reputation_score", 0.0),
            "confidence": intel.get("confidence", 0.0),
            "threat_indicators": intel.get("threat_indicators", []),
            "kev_matches": intel.get("kev_matches", []),
            "source_details": [],
        }
        for result in intel.get("individual_results", []) or []:
            if (result.get("reputation_score") or 0) > 0 or result.get("indicators"):
                section["source_details"].append({
                    "source": result.get("source", "unknown"),
                    "reputation_score": result.get("reputation_score", 0),
                    "indicators": result.get("indicators", []),
                    "summary": self._summarize_source_result(result),
                })
        return section

    def _risk_components(self, context) -> Dict[str, Any]:
        risk = self._ctx(context, "risk_assessment", {})
        intel_risk = risk.get("intel_risk")
        llm_used = bool(risk.get("llm_analysis"))
        weights = risk.get("weights") or risk_weights(intel_risk is not None, llm_used)
        return {"risk": risk, "intel_risk": intel_risk, "llm_used": llm_used, "weights": weights}

    def _generate_risk_assessment_section(self, context) -> Dict[str, Any]:
        comp = self._risk_components(context)
        risk = comp["risk"]
        return {
            "overall_score": risk.get("risk_score", 0.0),
            "risk_level": risk.get("risk_level", "unknown"),
            "confidence": risk.get("confidence", 0.0),
            "component_scores": {
                "base_risk": risk.get("base_risk", 0.0),
                "intelligence_risk": comp["intel_risk"],
                "pattern_risk": risk.get("pattern_risk", 0.0),
                "llm_risk": risk.get("llm_risk") if comp["llm_used"] else None,
            },
            "weights": comp["weights"],
            "intel_available": comp["intel_risk"] is not None,
            "risk_factors": self._identify_risk_factors(context),
            "mitigating_factors": self._identify_mitigating_factors(context),
        }

    def _risk_rows(self, context) -> List[Dict[str, str]]:
        comp = self._risk_components(context)
        risk, w = comp["risk"], comp["weights"]

        def row(name: str, score: Optional[float], weight: float) -> Dict[str, str]:
            if score is None:
                return {"name": name, "score": "N/A", "weight": f"{int(round(weight * 100))}%",
                        "contribution": "0.000"}
            return {"name": name, "score": f"{float(score):.2f}", "weight": f"{int(round(weight * 100))}%",
                    "contribution": f"{float(score) * weight:.3f}"}

        rows = [
            row("Base Risk (event evidence)", risk.get("base_risk", 0.0) or 0.0, w.get("base", 0.0)),
            row("Intelligence Risk", comp["intel_risk"], w.get("intel", 0.0)),
            row("Pattern Risk", risk.get("pattern_risk", 0.0) or 0.0, w.get("pattern", 0.0)),
        ]
        if comp["llm_used"]:
            rows.append(row("LLM Modifier", risk.get("llm_risk", 0.0) or 0.0, w.get("llm", 0.0)))
        floor = w.get("uncertainty_floor", 0.0)
        if floor:
            rows.append({"name": f"Uncertainty Floor (+{floor:.2f})", "score": "-", "weight": "-",
                         "contribution": f"{floor:.3f}"})
        floor_applied = risk.get("risk_floor_applied")
        if floor_applied:
            rows.append({"name": f"Detection floor ({floor_applied.get('reason', 'rule')})", "score": "-",
                         "weight": "-", "contribution": f"min {floor_applied.get('value', 0):.2f}"})
        return rows

    def _generate_actions_section(self, context) -> List[Dict[str, Any]]:
        return [{
            "action_type": a.get("action_type", "UNKNOWN"),
            "priority": a.get("priority", 5),
            "description": a.get("description", ""),
            "estimated_effort": a.get("estimated_effort", "Unknown"),
            "technical_details": a.get("technical_details", ""),
            "urgency": self._determine_action_urgency(a),
            "automated_capable": bool(a.get("automated_capable", False)),
            "capable_integrations": list(a.get("capable_integrations", []) or []),
            "trigger": a.get("trigger"),
            "rule_id": a.get("rule_id"),
        } for a in (self._ctx(context, "recommended_actions", []) or [])]

    def _generate_technical_section(self, context) -> Dict[str, Any]:
        intel = self._ctx(context, "intelligence_data", {})
        return {
            "investigation_phases": list(self._ctx(context, "phases_completed", [])),
            "tools_used": intel.get("sources_queried", []) or intel.get("sources", []),
            "pattern_insights": self._pattern_insights(context),
            "network_analysis": self._analyze_network_indicators(context),
            "behavioral_analysis": self._analyze_behavioral_indicators(context),
        }

    def _extract_indicators(self, context) -> List[Dict[str, Any]]:
        event_data = self._ctx(context, "event_data", {})
        intel = self._ctx(context, "intelligence_data", {})
        reputation = float(intel.get("reputation_score", 0) or 0)
        indicators: List[Dict[str, Any]] = []
        seen = set()

        def add(ioc_type: str, value: str, confidence: float, source: str, description: str):
            key = (ioc_type, str(value).lower())
            if not value or key in seen:
                return
            seen.add(key)
            indicators.append({
                "type": ioc_type, "value": value, "defanged": defang(value, ioc_type),
                "confidence": round(confidence, 2), "source": source, "description": description,
            })

        if event_data.get("source_ip"):
            add("ip", event_data["source_ip"], reputation, "investigation",
                f"Source IP with reputation score {reputation:.2f}")
        if event_data.get("url"):
            add("url", event_data["url"], 0.5, "investigation", "Suspicious URL from event data")
        if event_data.get("file_hash"):
            fh = str(event_data["file_hash"]).lower()
            kind = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(fh), "hash")
            add(kind, fh, 0.6, "investigation", "File hash from event data")

        iocs = self._detection(context).get("extracted_iocs", {}) or {}
        mapping = {"ips": "ip", "urls": "url", "domains": "domain", "md5": "md5", "sha1": "sha1",
                   "sha256": "sha256", "cves": "cve", "emails": "email"}
        for key, ioc_type in mapping.items():
            for value in iocs.get(key, []) or []:
                add(ioc_type, value, 0.5, "detection_engine", f"{ioc_type.upper()} extracted from telemetry")

        for indicator_text in intel.get("threat_indicators", []) or []:
            indicators.append({
                "type": "intelligence", "value": indicator_text, "defanged": indicator_text,
                "confidence": 0.7, "source": "threat_intelligence", "description": "Threat intelligence indicator",
            })
        return indicators

    # ------------------------------------------------------------------ formats

    def _common_template_vars(self, report_data: Dict[str, Any], context) -> Dict[str, Any]:
        risk = self._ctx(context, "risk_assessment", {})
        event_data = self._ctx(context, "event_data", {})
        detection = report_data.get("detection") or {}
        iocs = [dict(i) for i in report_data["indicators"] if i["type"] != "intelligence"]
        for ioc in iocs:
            ioc["value_md"] = _md_inline(ioc["value"])
            ioc["defanged"] = _md_inline(ioc["defanged"])
        return {
            "event_id": context.event_id,
            "timestamp": _utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "duration_minutes": report_data["metadata"]["investigation_duration_minutes"],
            "status": self._ctx(context, "status", "completed"),
            "risk_level": risk.get("risk_level", "unknown"),
            "risk_score": f"{float(risk.get('risk_score', 0.0) or 0.0):.2f}",
            "executive_summary": report_data["executive_summary"],
            "event_type": event_data.get("event_type", "unknown"),
            "source_ip": event_data.get("source_ip", "N/A"),
            "detection_time": event_data.get("timestamp", "N/A"),
            "findings": detection.get("findings", []),
            "mitre_attack": detection.get("mitre_attack", []),
            "mitre_atlas": detection.get("mitre_atlas", []),
            "owasp_llm": detection.get("owasp_llm", []),
            "guardrails": report_data["guardrails"],
            "llm_analysis": report_data.get("llm_analysis"),
            "threat_intelligence_summary": self._format_threat_intelligence_summary(
                self._ctx(context, "intelligence_data", {})),
            "intelligence_sources": self._format_intelligence_sources(report_data["threat_intelligence"]),
            "risk_rows": self._risk_rows(context),
            "confidence": round(float(risk.get("confidence", 0.0) or 0.0) * 100, 1),
            "risk_explanation": self._generate_risk_explanation(context),
            "recommended_actions": report_data["recommended_actions"],
            "reasoning_log": list(self._ctx(context, "reasoning_log", [])),
            "pattern_insights": report_data.get("pattern_insights", []),
            "tool_trace": [{
                **t,
                "tool_md": _md_cell(t["tool"]),
                "args_text": json.dumps(t["args"], default=str)[:300],
                "args_md": _md_cell(json.dumps(t["args"], default=str)),
                "result": t["error"] or t["summary"],
                "result_md": _md_cell(t["error"] or t["summary"]),
            } for t in report_data.get("tool_trace", [])],
            "iocs": iocs,
            "include_raw_data": self.include_raw_data,
            "raw_data": report_data["raw_data"],
            "classification": report_data["metadata"]["classification"],
            "agent_version": self.AGENT_VERSION,
        }

    def _generate_markdown_report(self, report_data: Dict[str, Any], context) -> str:
        variables = self._common_template_vars(report_data, context)
        variables["event_details"] = self._format_event_details(self._ctx(context, "event_data", {}))
        return self.markdown_template.render(**variables)

    def _generate_html_report(self, report_data: Dict[str, Any], context) -> str:
        variables = self._common_template_vars(report_data, context)
        event_data = self._ctx(context, "event_data", {})
        variables["executive_summary_paragraphs"] = [
            p.replace("**", "") for p in report_data["executive_summary"].split("\n\n") if p.strip()]
        variables["event_fields"] = [
            (k.replace("_", " ").title(), json.dumps(v, default=str)[:500] if not isinstance(v, str) else v[:500])
            for k, v in event_data.items() if k not in ("event_type", "source_ip", "timestamp")
        ]
        variables["intel_indicators"] = self._ctx(context, "intelligence_data", {}).get("threat_indicators", [])
        level = str(variables["risk_level"]).lower()
        variables["risk_level_class"] = level if level in ("critical", "high", "medium", "low") else "unknown"
        return self.html_template.render(**variables)

    @staticmethod
    def _stix_pattern(ioc_type: str, value: str) -> Optional[str]:
        escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
        patterns = {
            "ip": "[{kind}:value = '{v}']",
            "domain": "[domain-name:value = '{v}']",
            "url": "[url:value = '{v}']",
            "email": "[email-addr:value = '{v}']",
            "md5": "[file:hashes.MD5 = '{v}']",
            "sha1": "[file:hashes.'SHA-1' = '{v}']",
            "sha256": "[file:hashes.'SHA-256' = '{v}']",
        }
        template = patterns.get(ioc_type)
        if template is None:
            return None
        kind = "ipv6-addr" if ioc_type == "ip" and ":" in str(value) else "ipv4-addr"
        return template.format(kind=kind, v=escaped)

    @staticmethod
    def _stix_sco(ioc_type: str, value: str) -> Optional[Dict[str, Any]]:
        if ioc_type == "ip":
            sco_type = "ipv6-addr" if ":" in value else "ipv4-addr"
            props: Dict[str, Any] = {"value": value}
        elif ioc_type == "domain":
            sco_type, props = "domain-name", {"value": value}
        elif ioc_type == "url":
            sco_type, props = "url", {"value": value}
        elif ioc_type == "email":
            sco_type, props = "email-addr", {"value": value}
        elif ioc_type in ("md5", "sha1", "sha256"):
            algo = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}[ioc_type]
            sco_type, props = "file", {"hashes": {algo: value}}
        else:
            return None
        sco_id = uuid.uuid5(STIX_SCO_NAMESPACE, json.dumps(props, sort_keys=True, separators=(",", ":")))
        return {"type": sco_type, "spec_version": "2.1", "id": f"{sco_type}--{sco_id}", **props}

    def _generate_stix_bundle(self, report_data: Dict[str, Any], context) -> Dict[str, Any]:
        now = _utcnow()
        ts = _stix_ts(now)
        start = _aware(self._ctx(context, "start_time", now))
        risk = self._ctx(context, "risk_assessment", {})
        event_data = self._ctx(context, "event_data", {})
        score = float(risk.get("risk_score", 0.0) or 0.0)
        identity_id = f"identity--{uuid.uuid5(THREATSENTINEL_NAMESPACE, 'identity')}"
        objects: List[Dict[str, Any]] = [{
            "type": "identity", "spec_version": "2.1", "id": identity_id,
            "created": "2024-01-01T00:00:00.000Z", "modified": "2024-01-01T00:00:00.000Z",
            "name": "ThreatSentinel SOC Agent", "identity_class": "system",
        }]
        indicator_ids: List[str] = []
        sco_ids: List[str] = []
        for ioc in report_data["indicators"]:
            ioc_type, value = ioc["type"], str(ioc["value"])
            sco = self._stix_sco(ioc_type, value)
            if sco and sco["id"] not in sco_ids:
                objects.append(sco)
                sco_ids.append(sco["id"])
            pattern = self._stix_pattern(ioc_type, value)
            if not pattern or (ioc_type == "ip" and not is_public_ip(value)):
                continue  # private addresses are observed, not shareable indicators
            indicator_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(indicator_id)
            objects.append({
                "type": "indicator", "spec_version": "2.1", "id": indicator_id,
                "created": ts, "modified": ts, "created_by_ref": identity_id,
                "name": f"{ioc_type.upper()} {defang(value, ioc_type)}",
                "description": ioc.get("description", ""),
                "indicator_types": ["malicious-activity"] if score >= 0.6 else ["anomalous-activity"],
                "pattern": pattern, "pattern_type": "stix", "pattern_version": "2.1",
                "valid_from": ts,
                "confidence": int(round(max(score, float(ioc.get("confidence", 0) or 0)) * 100)),
                "labels": [event_data.get("event_type", "unknown")],
            })

        attack_ids: List[str] = []
        detection = report_data.get("detection") or {}
        for technique in detection.get("mitre_attack", []) + detection.get("mitre_atlas", []):
            source = "mitre-atlas" if technique.startswith("AML.") else "mitre-attack"
            ap_id = f"attack-pattern--{uuid.uuid5(THREATSENTINEL_NAMESPACE, technique)}"
            attack_ids.append(ap_id)
            objects.append({
                "type": "attack-pattern", "spec_version": "2.1", "id": ap_id,
                "created": ts, "modified": ts, "name": technique,
                "external_references": [{"source_name": source, "external_id": technique}],
            })
            for indicator_id in indicator_ids:
                objects.append({
                    "type": "relationship", "spec_version": "2.1", "id": f"relationship--{uuid.uuid4()}",
                    "created": ts, "modified": ts, "relationship_type": "indicates",
                    "source_ref": indicator_id, "target_ref": ap_id,
                })

        observed_id = None
        if sco_ids:
            observed_id = f"observed-data--{uuid.uuid4()}"
            objects.append({
                "type": "observed-data", "spec_version": "2.1", "id": observed_id,
                "created": ts, "modified": ts, "created_by_ref": identity_id,
                "first_observed": _stix_ts(start), "last_observed": ts, "number_observed": 1,
                "object_refs": sco_ids,
            })

        report_refs = indicator_ids + attack_ids + ([observed_id] if observed_id else [])
        if not report_refs:
            report_refs = [identity_id]
        objects.append({
            "type": "report", "spec_version": "2.1", "id": f"report--{uuid.uuid4()}",
            "created": ts, "modified": ts, "created_by_ref": identity_id,
            "name": f"ThreatSentinel investigation {context.event_id}",
            "description": report_data["executive_summary"].replace("**", ""),
            "report_types": ["threat-report"], "published": ts,
            "object_refs": report_refs,
            "labels": [str(risk.get("risk_level", "unknown")), event_data.get("event_type", "unknown")],
            "confidence": int(round(float(risk.get("confidence", 0.0) or 0.0) * 100)),
        })
        return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}

    # ------------------------------------------------------------------ text helpers

    def _summarize_payload(self, payload: Any) -> str:
        if not payload:
            return "No payload data available"
        if isinstance(payload, dict):
            return f"Structured data with {len(payload)} fields"
        if isinstance(payload, str):
            return f"Text data ({len(payload)} characters)"
        return f"Data of type {type(payload).__name__}"

    def _analyze_event_characteristics(self, event_data: Dict[str, Any]) -> List[str]:
        characteristics = []
        if event_data.get("source_ip"):
            characteristics.append(f"Source IP: {event_data['source_ip']}")
        if event_data.get("user_agent"):
            characteristics.append("User agent present")
        if event_data.get("payload"):
            characteristics.append("Payload data included")
        if event_data.get("internal_source"):
            characteristics.append("Internal network source")
        return characteristics

    def _summarize_source_result(self, result: Dict[str, Any]) -> str:
        reputation = result.get("reputation_score", 0) or 0
        indicators = result.get("indicators", [])
        if reputation > 0.7:
            return f"High threat confidence ({reputation:.2f})"
        if reputation > 0.3:
            return f"Medium threat confidence ({reputation:.2f})"
        if indicators:
            return f"{len(indicators)} indicator(s): {indicators[0]}"
        return "No significant threats detected"

    def _identify_risk_factors(self, context) -> List[str]:
        factors = []
        intel = self._ctx(context, "intelligence_data", {})
        event_data = self._ctx(context, "event_data", {})
        if (intel.get("reputation_score") or 0) > 0.5:
            factors.append("External threat intelligence indicates malicious activity")
        payload = event_data.get("payload") if isinstance(event_data.get("payload"), dict) else {}
        if (payload.get("failed_login_attempts") or 0) > 5:
            factors.append("Multiple failed authentication attempts detected")
        if event_data.get("internal_source"):
            factors.append("Activity originated from internal network")
        event_type = event_data.get("event_type")
        if event_type in ("malware_detection", "ddos_signs", "supply_chain_compromise", "data_exfiltration",
                          "agent_tool_abuse", "mcp_tool_poisoning", "secret_leak"):
            factors.append(f"Event type ({event_type}) inherently high risk")
        for finding in (self._detection(context).get("findings") or [])[:5]:
            factors.append(f"{finding.get('title')} ({finding.get('rule_id')})")
        if self._guardrails(context)["prompt_injection_detected"]:
            factors.append("Prompt injection content targeting AI analysis")
        if intel.get("kev_matches"):
            factors.append("Actively exploited CVEs (CISA KEV) associated with the target")
        return factors

    def _identify_mitigating_factors(self, context) -> List[str]:
        intel = self._ctx(context, "intelligence_data", {})
        factors = []
        if (intel.get("confidence") or 0) < 0.5:
            factors.append("Low confidence in threat intelligence data")
        if not intel.get("threat_indicators"):
            factors.append("No specific threat indicators identified")
        if len(intel.get("sources", [])) < 2:
            factors.append("Limited external threat intelligence sources consulted")
        return factors

    def _determine_action_urgency(self, action: Dict[str, Any]) -> str:
        priority = action.get("priority", 5)
        if priority <= 1 or action.get("action_type") == "ESCALATE":
            return "IMMEDIATE"
        if priority <= 2:
            return "HIGH"
        if priority <= 3:
            return "MEDIUM"
        return "LOW"

    def _analyze_network_indicators(self, context) -> Dict[str, Any]:
        event_data = self._ctx(context, "event_data", {})
        intel = self._ctx(context, "intelligence_data", {})
        analysis: Dict[str, Any] = {"source_ip_analysis": {}, "geographic_indicators": {}, "network_behavior": []}
        source_ip = event_data.get("source_ip")
        if source_ip:
            try:
                ipaddress.ip_address(str(source_ip))
                public = is_public_ip(str(source_ip))
            except ValueError:
                public = False
            analysis["source_ip_analysis"] = {
                "ip": source_ip,
                "reputation_score": intel.get("reputation_score", 0),
                "is_internal": bool(event_data.get("internal_source")) or not public,
                "is_public": public,
            }
        return analysis

    def _analyze_behavioral_indicators(self, context) -> Dict[str, Any]:
        event_data = self._ctx(context, "event_data", {})
        analysis: Dict[str, Any] = {"user_agent_analysis": {}, "timing_analysis": {}, "payload_analysis": {}}
        user_agent = event_data.get("user_agent")
        if user_agent:
            analysis["user_agent_analysis"] = {
                "present": True, "value": user_agent,
                "suspicious_patterns": self._check_suspicious_user_agent(str(user_agent)),
            }
        return analysis

    def _check_suspicious_user_agent(self, user_agent: str) -> List[str]:
        ua = user_agent.lower()
        keywords = ["bot", "crawler", "scanner", "curl", "wget", "python", "sqlmap", "nikto", "nmap",
                    "masscan", "zgrab", "nuclei", "go-http-client"]
        return [f"Contains '{k}' keyword" for k in keywords if k in ua]

    def _format_event_details(self, event_data: Dict[str, Any]) -> str:
        details = []
        for key, value in event_data.items():
            if key in ("event_type", "source_ip", "timestamp"):
                continue
            rendered = value if isinstance(value, str) else json.dumps(value, default=str)
            details.append(f"**{key.replace('_', ' ').title()}:** `{_md_inline(rendered)}`")
        return "\n".join(details) if details else "No additional event details available."

    def _format_threat_intelligence_summary(self, intel_data: Dict[str, Any]) -> str:
        local = intel_data.get("local_sources") or []
        if not intel_data or not intel_data.get("sources"):
            text = "No external threat intelligence source returned reputation data."
            if local:
                text += f" Local forensic analysis ran ({', '.join(local)})."
            return text
        return (f"Consulted {len(intel_data.get('sources', []))} external reputation source(s) "
                f"({', '.join(intel_data.get('sources', []))}) with maximum reputation score of "
                f"{float(intel_data.get('reputation_score', 0) or 0):.2f} and overall confidence of "
                f"{float(intel_data.get('confidence', 0) or 0):.1%}.")

    def _format_intelligence_sources(self, section: Dict[str, Any]) -> List[Dict[str, str]]:
        return [{"name": str(d["source"]).title(), "summary": d["summary"]}
                for d in section.get("source_details", [])]

    def _generate_risk_explanation(self, context) -> str:
        risk = self._ctx(context, "risk_assessment", {})
        intel = self._ctx(context, "intelligence_data", {})
        explanations = {
            "low": "The event shows minimal indicators of malicious activity and poses low risk.",
            "medium": "The event contains suspicious characteristics that warrant monitoring and investigation.",
            "high": "The event demonstrates significant threat indicators and requires immediate attention.",
            "critical": "The event represents an imminent security threat requiring emergency response.",
        }
        text = explanations.get(risk.get("risk_level"), "Risk level assessment is inconclusive.")
        if risk.get("intel_risk") is None:
            text += (" No external reputation source answered, so intelligence weight was redistributed to "
                     "event evidence and an uncertainty floor was added.")
        if (intel.get("reputation_score") or 0) > 0.7:
            text += " External threat intelligence confirms malicious activity."
        return text

    async def _save_report(self, event_id: str, report: Dict[str, Any]) -> bool:
        """Persist as rpt_<timestamp>_<event_id>.{json,md,html,stix.json}."""
        try:
            safe_id = _SAFE_FILE_ID.sub("_", str(event_id))[:80] or "unknown"
            stem = f"rpt_{_utcnow().strftime('%Y%m%d_%H%M%S')}_{safe_id}"
            base = self.reports_dir.resolve()
            files = {
                f"{stem}.json": report["formats"]["json"],
                f"{stem}.md": report["formats"]["markdown"],
                f"{stem}.html": report["formats"]["html"],
            }
            for name, content in files.items():
                path = (base / name).resolve()
                if not path.is_relative_to(base):
                    raise ValueError("Report path escapes reports directory")
                path.write_text(content, encoding="utf-8")
            report.setdefault("metadata", {})["report_id"] = stem
            self.logger.info(f"Saved report files: {stem}.*")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save report: {e}")
            return False

    def _generate_error_report(self, context, error: Exception) -> Dict[str, Any]:
        report: Dict[str, Any] = {
            "metadata": {
                "event_id": getattr(context, "event_id", "unknown"),
                "status": "ERROR",
                "error": str(error),
                "generated_at": _utcnow().isoformat(),
            },
            "executive_summary": f"Report generation failed: {error}",
            "recommended_actions": [{
                "action_type": "ESCALATE",
                "priority": 1,
                "description": "Manual investigation required due to reporting system error",
                "estimated_effort": "30 minutes",
            }],
        }
        report["formats"] = {
            "markdown": f"# Investigation Report Error\n\nReport generation failed: {error}\n",
            "json": json.dumps(report, indent=2, default=str),
        }
        return report
