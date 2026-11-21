import React, { useState } from 'react';
import { useQuery } from 'react-query';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api, useThreatSentinel } from '../context/ThreatSentinelContext';
import {
  Chip, Empty, ErrorNote, Field, FORMAT_TO_EXT, HeadLink, Loading, PanelHead, Readout, RiskBadge, StatusBadge,
  Toggle, defang, fmtNum, fmtTime, saveBlob,
} from '../components/ui';

const ACTIVE = new Set(['pending', 'queued', 'running']);
const HAS_RESULT = new Set(['completed', 'pending_human_review']);
const REPORT_FORMATS = [['json', 'JSON'], ['markdown', 'MD'], ['html', 'HTML'], ['stix', 'STIX 2.1']];

const optional404 = (promise) =>
  promise.then((r) => r.data).catch((e) => {
    if (e?.response?.status === 404) return null;
    throw e;
  });

// ------------------------------------------------------------------ sections

const GuardrailBanner = ({ scan, redacted }) => {
  if (!scan?.detected && !redacted?.length) return null;
  return (
    <div className="panel border-critical/50">
      <div className="panel-head bg-critical/10">
        <h2 className="label text-critical">Guardrails triggered</h2>
        {scan?.detected && <span className="num text-xs text-critical">injection score {fmtNum(scan.score)}</span>}
      </div>
      <div className="px-4 py-3 space-y-2 text-sm">
        {scan?.detected && (
          <>
            <p>
              Prompt injection content found in <span className="num">{String(scan.source || 'event data').replace(/_/g, ' ')}</span>.
              The event was nonce-isolated as untrusted data for any LLM step and the risk floor was enforced.
            </p>
            <div className="flex flex-wrap gap-1">
              {(scan.matched_rules || []).map((r) => <Chip key={r}>{r}</Chip>)}
              {(scan.owasp_categories || []).map((r) => <Chip key={r} tone="owasp">{r}</Chip>)}
              {(scan.mitre_atlas_ids || []).map((r) => <Chip key={r} tone="atlas">{r}</Chip>)}
            </div>
            {(scan.evidence || []).length > 0 && (
              <ul className="num text-xs text-inksoft space-y-0.5">
                {scan.evidence.slice(0, 5).map((e, i) => <li key={i} className="truncate">› {String(e)}</li>)}
              </ul>
            )}
          </>
        )}
        {redacted?.length > 0 && (
          <p>
            Secrets in telemetry: <span className="num">{redacted.join(', ')}</span>. Redacted before any LLM egress.
          </p>
        )}
      </div>
    </div>
  );
};

const RiskBreakdown = ({ ra }) => {
  if (!ra) return null;
  const weights = ra.weights || {};
  const rows = [
    ['Base (event + detection + local)', ra.base_risk, weights.base],
    ['Detection severity', ra.detection_severity, null],
    ['Local forensics', ra.local_forensic_risk, null],
    ['Threat intel', ra.intel_risk, weights.intel],
    ['Historical patterns', ra.pattern_risk, weights.pattern],
    ['LLM modifier', ra.llm_analysis ? ra.llm_risk : null, weights.llm],
  ];
  return (
    <div className="panel">
      <PanelHead title="Risk breakdown & weights" />
      <table className="data-table">
        <thead><tr><th>Component</th><th className="w-1/3">Score</th><th>Weight</th></tr></thead>
        <tbody>
          {rows.map(([name, score, weight]) => (
            <tr key={name}>
              <td className="text-sm">{name}</td>
              <td>
                {typeof score === 'number' ? (
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 flex-1 bg-rule"><div className="h-full bg-ink" style={{ width: `${Math.min(100, score * 100)}%` }} /></div>
                    <span className="num text-xs w-10 text-right">{score.toFixed(2)}</span>
                  </div>
                ) : name === 'Threat intel' ? (
                  <span className="font-mono text-xs text-high">Unavailable / uncertainty floor</span>
                ) : <span className="text-muted text-xs">not used</span>}
              </td>
              <td className="num text-xs">{typeof weight === 'number' ? weight.toFixed(2) : '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {weights.uncertainty_floor > 0 && (
        <p className="px-4 py-2 border-t border-rule num text-xs text-high">
          Uncertainty floor +{weights.uncertainty_floor.toFixed(2)} added (intel unavailable)
        </p>
      )}
      {ra.risk_floor_applied && (
        <p className="px-4 py-2 border-t border-rule font-mono text-xs text-critical">
          Floor applied: {ra.risk_floor_applied.reason} → {fmtNum(ra.risk_floor_applied.value)}
        </p>
      )}
      {ra.intel_available === false && (
        <p className="px-4 py-2 border-t border-rule text-xs text-muted">
          No reputation source answered. Missing intel is scored as uncertainty, not as a clean reputation.
        </p>
      )}
    </div>
  );
};

const Detections = ({ detection, ra, llm }) => {
  const findings = detection?.findings || [];
  const attack = [...new Set([...(ra?.mitre_attack || detection?.mitre_attack || []), ...(llm?.mitre_techniques || [])])];
  const atlas = [...new Set([...(ra?.mitre_atlas || detection?.mitre_atlas || []), ...(llm?.mitre_atlas || [])])];
  const owasp = [...new Set([...(ra?.owasp_llm || detection?.owasp_llm || []), ...(llm?.owasp_llm || [])])];
  return (
    <div className="panel">
      <PanelHead title={`Detections & frameworks · ${findings.length}`}>
        {typeof detection?.severity_score === 'number' && (
          <span className="num text-xs text-inksoft">severity {detection.severity_score.toFixed(2)}</span>
        )}
      </PanelHead>
      <div className="px-4 py-3 border-b border-rule space-y-2">
        {[['MITRE ATT&CK', attack, 'attack'], ['MITRE ATLAS', atlas, 'atlas'], ['OWASP LLM 2025', owasp, 'owasp']].map(([label, list, tone]) => (
          <div key={label} className="flex flex-wrap items-center gap-1.5">
            <span className="label w-32 shrink-0">{label}</span>
            {list.length ? list.map((x) => <Chip key={x} tone={tone}>{x}</Chip>) : <span className="text-xs text-muted">none</span>}
          </div>
        ))}
      </div>
      {findings.length === 0 ? <Empty>No deterministic detector fired.</Empty> : (
        <ul className="divide-y divide-rule">
          {findings.map((f, i) => (
            <li key={f.rule_id || i} className="px-4 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <RiskBadge level={f.severity >= 0.8 ? 'critical' : f.severity >= 0.6 ? 'high' : f.severity >= 0.4 ? 'medium' : 'low'} score={f.severity} />
                <span className="text-sm font-medium">{f.title}</span>
                <span className="num text-[11px] text-muted">{f.rule_id} · {f.category}</span>
              </div>
              {(f.evidence || []).length > 0 && (
                <ul className="mt-1 num text-xs text-inksoft space-y-0.5">
                  {f.evidence.slice(0, 4).map((e, j) => <li key={j} className="truncate">› {String(e)}</li>)}
                </ul>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

const summarizeArgs = (args) => {
  if (!args || typeof args !== 'object') return '';
  return Object.entries(args)
    .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v).slice(0, 40) : defang(v)}`)
    .join(' ')
    .slice(0, 120);
};

const ToolTrace = ({ trace, intel, iocs }) => {
  const sources = [...(intel?.sources || []), ...(intel?.local_sources || [])];
  const iocEntries = Object.entries(iocs || {}).filter(([, v]) => Array.isArray(v) && v.length);
  const errors = Object.entries(intel?.errors || {});
  return (
    <div className="panel">
      <PanelHead title={`Agent tool trace · ${trace.length}`} />
      {trace.length === 0 ? (
        <Empty>No tool trace recorded for this investigation.</Empty>
      ) : (
        <div className="overflow-x-auto scrollbar-thin">
          <table className="data-table">
            <thead><tr><th>#</th><th>Tool</th><th>Args</th><th>Result</th><th>ms</th><th>Summary</th></tr></thead>
            <tbody>
              {trace.map((t, i) => (
                <tr key={i}>
                  <td className="num text-xs">{t.step ?? i + 1}</td>
                  <td className="num text-xs whitespace-nowrap">
                    {t.tool}
                    {t.actor && t.actor !== 'planner' && <span className="ml-1 text-info">[{t.actor}]</span>}
                  </td>
                  <td className="num text-[11px] text-inksoft max-w-[240px] truncate" title={summarizeArgs(t.args)}>{summarizeArgs(t.args)}</td>
                  <td><span className={`status-badge ${t.ok ? 'status-success' : 'status-critical'}`}>{t.ok ? 'ok' : 'fail'}</span></td>
                  <td className="num text-xs">{fmtNum(t.duration_ms, 0)}</td>
                  <td className="text-xs text-inksoft max-w-[320px]">{t.error || t.summary || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="border-t border-rule">
        <Readout rows={[
          ['Sources answered', sources.length ? sources.join(', ') : <span className="text-muted">none</span>],
          ['Reputation', `${fmtNum(intel?.reputation_score)} (confidence ${fmtNum(intel?.confidence)})`],
          ['KEV matches', (intel?.kev_matches || []).length ? intel.kev_matches.map((k) => k.cve_id || k.cveID || String(k)).join(', ') : 'none'],
          ...(errors.length ? [['Source errors', errors.map(([k, v]) => `${k}: ${v}`).join('; ')]] : []),
        ]} />
      </div>
      {iocEntries.length > 0 && (
        <div className="border-t border-rule px-4 py-3">
          <p className="label mb-2">Extracted IOCs (defanged)</p>
          <div className="space-y-1.5">
            {iocEntries.map(([type, values]) => (
              <div key={type} className="flex gap-3 text-xs">
                <span className="label w-20 shrink-0 pt-0.5">{type}</span>
                <span className="num text-inksoft break-all">{values.slice(0, 20).map(defang).join('  ')}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

const LLMPanel = ({ llm }) => (
  <div className="panel">
    <PanelHead title="LLM analysis">
      {llm && <span className="num text-xs text-inksoft">{llm.provider}/{llm.model} · {llm.tokens ?? 0} tok</span>}
    </PanelHead>
    {!llm ? (
      <p className="px-4 py-4 text-sm text-inksoft">
        No LLM ran for this investigation. Deterministic detectors, local forensics and keyless intel produced the verdict.
        Set <span className="num">LLM_PROVIDER</span> (for example a local Ollama) to add a model opinion.
      </p>
    ) : (
      <div className="px-4 py-3 space-y-3 text-sm">
        {llm.possible_injection_influence && (
          <p className="font-mono text-xs text-critical">Model risk was low despite detected injection; deterministic floor kept.</p>
        )}
        {!llm.parsed && <p className="font-mono text-xs text-high">Model output was not JSON; treated as low-confidence text.</p>}
        <p className="whitespace-pre-wrap">{llm.threat_assessment || '—'}</p>
        <div className="flex flex-wrap gap-4 num text-xs text-inksoft">
          <span>risk {fmtNum(llm.risk_modifier)}</span>
          <span>confidence {fmtNum(llm.confidence)}</span>
          <span>urgency {llm.urgency}</span>
          <span>class {llm.attack_classification}</span>
        </div>
        {(llm.key_findings || []).length > 0 && (
          <ul className="space-y-0.5 text-xs">{llm.key_findings.map((k, i) => <li key={i}>› {k}</li>)}</ul>
        )}
      </div>
    )}
  </div>
);

const ActionList = ({ title, actions }) => (
  <div>
    <p className="label mb-1.5">{title}</p>
    {actions.length === 0 ? <p className="text-xs text-muted">none</p> : (
      <ul className="divide-y divide-rule border border-rule">
        {actions.map((a, i) => (
          <li key={i} className="px-3 py-2 flex flex-wrap items-center gap-2 text-sm">
            <span className="num text-[10px] text-muted">P{a.priority ?? '-'}</span>
            <span className="font-mono text-xs uppercase">{a.action_type}</span>
            <span className="text-inksoft">{a.description}</span>
            {a.success !== undefined && <StatusBadge status={a.success ? 'success' : 'failed'} />}
          </li>
        ))}
      </ul>
    )}
  </div>
);

const ReviewPanel = ({ id, result }) => {
  const { submitFeedback } = useThreatSentinel();
  const pending = result.status === 'pending_human_review';
  const review = result.review_request || result.escalation_details || {};
  const [form, setForm] = useState({
    analyst_id: '',
    review_status: 'approved',
    accuracy_rating: 4,
    false_positive: false,
    execute_actions: false,
    feedback_text: '',
  });
  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));

  const submit = (e) => {
    e.preventDefault();
    submitFeedback.mutate({
      id,
      feedback: {
        ...form,
        accuracy_rating: Number(form.accuracy_rating),
        execute_actions: form.review_status === 'approved' && form.execute_actions && !form.false_positive,
      },
    });
  };

  const prior = result.feedback;
  return (
    <div className={`panel ${pending ? 'border-high/50' : ''}`}>
      <div className={`panel-head ${pending ? 'bg-high/10' : ''}`}>
        <h2 className={`label ${pending ? 'text-high' : ''}`}>
          {pending ? 'Human-in-the-loop review required' : 'Analyst feedback'}
        </h2>
        {result.review_status && <StatusBadge status={result.review_status} />}
      </div>
      <div className="px-4 py-4 space-y-4">
        {pending && (
          <>
            <p className="text-sm">{review.reason}</p>
            {(review.triggers || []).length > 0 && (
              <div className="flex flex-wrap gap-1">{review.triggers.map((t) => <Chip key={t} tone="atlas">{t}</Chip>)}</div>
            )}
            <ActionList title="Proposed actions (not executed)" actions={result.proposed_actions || []} />
          </>
        )}
        {!pending && <ActionList title="Actions executed" actions={result.actions_executed || []} />}

        {prior && (
          <p className="num text-xs text-inksoft border-l-2 border-rulehard pl-3">
            Last decision: {prior.review_status} by {prior.analyst_id} at {fmtTime(prior.reviewed_at)}
            {prior.execution ? ` · executed ${prior.execution.actions_executed?.length ?? 0} action(s)` : ''}
          </p>
        )}

        <form onSubmit={submit} className="grid grid-cols-1 md:grid-cols-2 gap-4 border-t border-rule pt-4">
          <Field label="Analyst ID">
            <input required maxLength={128} className="input-field w-full" value={form.analyst_id} onChange={(e) => set('analyst_id', e.target.value)} />
          </Field>
          <Field label="Decision">
            <select className="input-field w-full" value={form.review_status} onChange={(e) => set('review_status', e.target.value)}>
              <option value="approved">approved</option>
              <option value="rejected">rejected</option>
              <option value="needs_escalation">needs_escalation</option>
            </select>
          </Field>
          <Field label={`Accuracy rating · ${form.accuracy_rating}/5`}>
            <input type="range" min={1} max={5} className="w-full accent-ink" value={form.accuracy_rating} onChange={(e) => set('accuracy_rating', e.target.value)} />
          </Field>
          <div className="flex flex-col justify-end gap-2 pb-1">
            <Toggle checked={form.false_positive} onChange={(v) => set('false_positive', v)}>False positive</Toggle>
            {form.review_status === 'approved' && !form.false_positive && (
              <Toggle checked={form.execute_actions} onChange={(v) => set('execute_actions', v)}>Execute proposed actions</Toggle>
            )}
          </div>
          <div className="md:col-span-2">
            <Field label="Notes">
              <textarea maxLength={10000} className="input-field w-full h-20" value={form.feedback_text} onChange={(e) => set('feedback_text', e.target.value)} />
            </Field>
          </div>
          <div className="md:col-span-2 flex justify-end">
            <button type="submit" className={form.execute_actions && form.review_status === 'approved' ? 'btn-danger' : 'btn-primary'} disabled={submitFeedback.isLoading}>
              {submitFeedback.isLoading ? 'Submitting…' : form.execute_actions && form.review_status === 'approved' ? 'Approve & execute' : 'Submit decision'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

const Collapsible = ({ title, count, children, defaultOpen = false }) => {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="panel">
      <button type="button" onClick={() => setOpen(!open)} className="panel-head w-full text-left">
        <span className="label">{title}{count !== undefined ? ` · ${count}` : ''}</span>
        <span className="num text-xs text-muted">{open ? '−' : '+'}</span>
      </button>
      {open && children}
    </div>
  );
};

// ------------------------------------------------------------------ page

const InvestigationDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { generateReport } = useThreatSentinel();

  const statusQ = useQuery(['investigation', id, 'status'],
    () => api.get(`/investigations/${id}`).then((r) => r.data),
    { refetchInterval: (d) => (d && ACTIVE.has(d.status) ? 3000 : false) });
  const status = statusQ.data?.status;

  const resultQ = useQuery(['investigation', id, 'result', status],
    () => api.get(`/investigations/${id}/result`).then((r) => r.data),
    { enabled: HAS_RESULT.has(status) });

  const reportsQ = useQuery(['reports', 'investigation', id],
    () => optional404(api.get(`/reports/investigation/${id}`)), { enabled: Boolean(status) });
  const timelineQ = useQuery(['investigation', id, 'timeline', status],
    () => optional404(api.get(`/audit/investigations/${id}/timeline`)), { enabled: Boolean(status) });

  if (statusQ.isLoading) return <Loading what="investigation" />;
  if (statusQ.error) {
    return (
      <div className="space-y-4">
        <ErrorNote error={statusQ.error} what={`investigation ${id}`} />
        <Link to="/investigations" className="btn-secondary inline-block">All investigations</Link>
      </div>
    );
  }

  const s = statusQ.data;
  const r = resultQ.data;
  const ra = r?.risk_assessment;
  const detection = r?.detection_assessment;
  const trace = r?.tool_trace || [];
  const timeline = timelineQ.data?.timeline || [];
  const reports = reportsQ.data?.reports || [];

  const makeReport = (format) =>
    generateReport.mutate({ investigation_id: id, format }, {
      onSuccess: (res) => {
        if (res.file_path) navigate(`/reports/${res.report_id}?format=${FORMAT_TO_EXT[format]}`);
        else if (res.content) {
          const type = format === 'html' ? 'text/html' : format === 'markdown' ? 'text/markdown' : 'application/json';
          saveBlob(new Blob([res.content], { type }), `${res.report_id}.${FORMAT_TO_EXT[format]}`);
        }
      },
    });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="panel">
        <div className="px-4 py-4 flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="label"><Link to="/investigations" className="hover:text-ink">Investigations</Link> /</p>
            <h2 className="num text-lg mt-1 break-all">{id}</h2>
            <p className="text-sm text-inksoft mt-1">
              {r?.event_data?.title || r?.event_data?.event_type || s.current_phase}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={s.status} />
            <RiskBadge level={ra?.risk_level || s.preliminary_risk_level} score={ra?.risk_score} />
            {r?.emergency_mode && <span className="status-badge status-critical">emergency</span>}
          </div>
        </div>
        <div className="border-t border-rule px-4 py-3 flex flex-wrap items-center gap-x-6 gap-y-2">
          <span className="num text-xs text-inksoft">started {fmtTime(s.start_time)}</span>
          {ra && <span className="num text-xs text-inksoft">confidence {fmtNum(ra.confidence)}</span>}
          {ACTIVE.has(s.status) && (
            <span className="flex items-center gap-2 flex-1 min-w-[200px]">
              <span className="num text-xs">{s.current_phase}</span>
              <span className="h-1.5 flex-1 bg-rule"><span className="block h-full bg-signal" style={{ width: `${s.progress_percentage}%` }} /></span>
              <span className="num text-xs">{s.progress_percentage}%</span>
            </span>
          )}
          {r && (
            <span className="ml-auto flex flex-wrap items-center gap-2">
              <span className="label">Report</span>
              {REPORT_FORMATS.map(([f, label]) => (
                <button key={f} type="button" className="btn-secondary !px-2.5 !py-1" disabled={generateReport.isLoading} onClick={() => makeReport(f)}>
                  {label}
                </button>
              ))}
            </span>
          )}
        </div>
      </div>

      {ACTIVE.has(s.status) && (
        <div className="panel px-4 py-6 text-center">
          <p className="label">Agent working<span className="blink">_</span></p>
          <p className="text-sm text-muted mt-2">This page polls every 3 seconds.</p>
        </div>
      )}
      {['failed', 'cancelled'].includes(s.status) && (
        <div className="panel px-4 py-4 text-sm text-inksoft">Investigation {s.status}. No result is available.</div>
      )}
      {resultQ.error && <ErrorNote error={resultQ.error} what="result" />}

      {r && (
        <>
          <GuardrailBanner scan={r.prompt_injection_scan} redacted={detection?.redacted_secret_types} />

          {HAS_RESULT.has(s.status) && <ReviewPanel id={id} result={r} />}

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <RiskBreakdown ra={ra} />
            <Detections detection={detection} ra={ra} llm={r.llm_analysis} />
          </div>

          <ToolTrace trace={trace} intel={r.intelligence_data} iocs={detection?.extracted_iocs} />

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <LLMPanel llm={r.llm_analysis} />
            <div className="panel">
              <PanelHead title={`Reports · ${reports.length}`}><HeadLink to="/reports">All</HeadLink></PanelHead>
              {reports.length === 0 ? <Empty>No saved reports for this investigation.</Empty> : (
                <ul className="divide-y divide-rule">
                  {reports.map((rep) => (
                    <li key={rep.file_name} className="px-4 py-2 flex items-center justify-between gap-3">
                      <Link to={`/reports/${rep.report_id}?format=${rep.format}`} className="num text-xs truncate hover:text-signal hover:underline">{rep.file_name}</Link>
                      <span className="num text-[11px] text-muted">{fmtTime(rep.created_at)}</span>
                    </li>
                  ))}
                </ul>
              )}
              {s.status === 'completed' && (r.recommended_actions || []).length > 0 && (
                <div className="border-t border-rule px-4 py-3">
                  <ActionList title="Recommended actions" actions={r.recommended_actions} />
                </div>
              )}
            </div>
          </div>

          <Collapsible title="Reasoning log" count={(r.reasoning_log || []).length} defaultOpen>
            <pre className="px-4 py-3 num text-xs text-inksoft whitespace-pre-wrap max-h-[420px] overflow-auto scrollbar-thin">
              {(r.reasoning_log || []).join('\n') || '—'}
            </pre>
          </Collapsible>
        </>
      )}

      <Collapsible title="Audit timeline" count={timeline.length}>
        {timeline.length === 0 ? <Empty>No audit entries recorded.</Empty> : (
          <div className="overflow-x-auto scrollbar-thin">
            <table className="data-table">
              <thead><tr><th>Time</th><th>Component</th><th>Action</th><th>Status</th><th>Description</th><th>ms</th></tr></thead>
              <tbody>
                {timeline.map((t, i) => (
                  <tr key={i}>
                    <td className="num text-xs whitespace-nowrap">{fmtTime(t.timestamp)}</td>
                    <td className="num text-xs">{t.component}</td>
                    <td className="num text-xs">{t.action}</td>
                    <td><StatusBadge status={t.status} /></td>
                    <td className="text-xs text-inksoft">{t.description}</td>
                    <td className="num text-xs">{t.duration_ms ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="px-4 py-2 border-t border-rule"><HeadLink to={`/audit?investigation_id=${encodeURIComponent(id)}`}>Open in audit log</HeadLink></div>
      </Collapsible>
    </div>
  );
};

export default InvestigationDetail;
