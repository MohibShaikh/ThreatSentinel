import React from 'react';
import { Link } from 'react-router-dom';

// Shared presentational primitives. No data fetching, no cross-page state.

export const riskClass = (level) => {
  switch (String(level || '').toLowerCase()) {
    case 'critical': return 'status-critical';
    case 'high': return 'status-high';
    case 'medium': return 'status-medium';
    case 'low': return 'status-low';
    default: return 'status-info';
  }
};

const STATUS_TONE = {
  completed: 'status-success',
  success: 'status-success',
  approved: 'status-success',
  running: 'status-info',
  in_progress: 'status-info',
  pending: 'status-medium',
  queued: 'status-medium',
  retrying: 'status-warning',
  pending_human_review: 'status-high',
  needs_escalation: 'status-high',
  failed: 'status-critical',
  failure: 'status-critical',
  error: 'status-critical',
  rejected: 'status-critical',
  cancelled: 'status-info',
  warning: 'status-warning',
  critical: 'status-critical',
  info: 'status-info',
  debug: 'status-info',
};

export const statusClass = (s) => STATUS_TONE[String(s || '').toLowerCase()] || 'status-info';

export const RiskBadge = ({ level, score }) => (
  <span className={`status-badge ${riskClass(level)}`}>
    {level || 'unknown'}
    {typeof score === 'number' && <span className="opacity-70">{score.toFixed(2)}</span>}
  </span>
);

export const StatusBadge = ({ status }) => (
  <span className={`status-badge ${statusClass(status)}`}>{String(status || 'unknown').replace(/_/g, ' ')}</span>
);

export const Chip = ({ children, tone = 'neutral', title }) => {
  const tones = {
    neutral: 'border-rulehard text-inksoft',
    owasp: 'border-critical/40 text-critical',
    attack: 'border-info/40 text-info',
    atlas: 'border-high/40 text-high',
    signal: 'border-signal/40 text-signal',
  };
  return (
    <span title={title} className={`inline-block border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.08em] ${tones[tone] || tones.neutral}`}>
      {children}
    </span>
  );
};

// OWASP / MITRE / prompt-injection indicator chips for list rows
export const FrameworkChips = ({ owasp = [], mitre = [], injection = false, max = 2 }) => {
  const items = [
    ...owasp.map((x) => ['owasp', x]),
    ...mitre.map((x) => ['attack', x]),
  ];
  if (!items.length && !injection) return <span className="text-muted">—</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {injection && <Chip tone="owasp" title="Prompt injection detected">PI</Chip>}
      {items.slice(0, max).map(([tone, x]) => <Chip key={`${tone}-${x}`} tone={tone}>{x}</Chip>)}
      {items.length > max && <Chip>+{items.length - max}</Chip>}
    </span>
  );
};

export const StatCell = ({ label, value, tone, hint }) => (
  <div className="px-5 py-4 flex-1 min-w-[140px]">
    <p className="label">{label}</p>
    <p className={`num text-3xl mt-1.5 ${tone || 'text-ink'}`}>{value}</p>
    {hint && <p className="num text-[11px] text-muted mt-1">{hint}</p>}
  </div>
);

export const StatStrip = ({ children }) => (
  <div className="panel flex flex-wrap divide-x divide-rule">{children}</div>
);

export const PanelHead = ({ title, children }) => (
  <div className="panel-head gap-3">
    <h2 className="label">{title}</h2>
    {children && <div className="flex items-center gap-3">{children}</div>}
  </div>
);

export const HeadLink = ({ to, children }) => (
  <Link to={to} className="font-mono text-xs uppercase tracking-[0.1em] text-signal hover:underline">{children}</Link>
);

export const TextButton = ({ children, className = '', ...props }) => (
  <button
    type="button"
    className={`font-mono text-xs uppercase tracking-[0.1em] text-signal hover:underline disabled:text-muted disabled:no-underline ${className}`}
    {...props}
  >
    {children}
  </button>
);

export const Empty = ({ children }) => (
  <p className="px-4 py-10 text-center text-sm text-muted">{children}</p>
);

export const Loading = ({ what = 'data' }) => (
  <div className="panel px-6 py-16 text-center"><p className="label">Loading {what}<span className="blink">_</span></p></div>
);

export const ErrorNote = ({ error, what = 'data' }) => (
  <div className="panel border-critical/40 px-4 py-3">
    <p className="font-mono text-xs text-critical">
      Failed to load {what}: {errorMessage(error)}
    </p>
  </div>
);

export const Readout = ({ rows }) => (
  <dl className="px-4 py-1 divide-y divide-rule">
    {rows.map(([k, v]) => (
      <div key={k} className="flex items-start justify-between gap-4 py-2.5">
        <dt className="label pt-0.5 shrink-0">{k}</dt>
        <dd className="num text-sm text-right break-all">{v}</dd>
      </div>
    ))}
  </dl>
);

export const Field = ({ label, children, hint }) => (
  <label className="block">
    <span className="label block mb-1.5">{label}</span>
    {children}
    {hint && <span className="block mt-1 text-[11px] text-muted">{hint}</span>}
  </label>
);

export const Toggle = ({ checked, onChange, children }) => (
  <label className="inline-flex items-center gap-2 cursor-pointer select-none">
    <input type="checkbox" className="accent-ink w-3.5 h-3.5" checked={checked} onChange={(e) => onChange(e.target.checked)} />
    <span className="font-mono text-xs uppercase tracking-[0.1em] text-inksoft">{children}</span>
  </label>
);

// ------------------------------------------------------------------ helpers

export function errorMessage(error) {
  const data = error?.response?.data;
  if (data) {
    if (typeof data.detail === 'string') return data.detail;
    if (typeof data.error === 'string') return data.error;
    if (Array.isArray(data.validation_errors)) {
      return data.validation_errors.map((e) => `${(e.loc || []).join('.')}: ${e.msg}`).join('; ');
    }
  }
  return error?.message || 'unknown error';
}

export const fmtTime = (v) => {
  if (!v) return '—';
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? String(v) : d.toISOString().replace('T', ' ').slice(0, 19);
};

export const fmtNum = (v, digits = 2, fallback = '—') =>
  typeof v === 'number' && Number.isFinite(v) ? v.toFixed(digits) : fallback;

export const fmtBytes = (n) => {
  if (typeof n !== 'number') return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
};

// Display IOCs without making them clickable: hxxp, [.] and [:]
export const defang = (v) =>
  String(v ?? '')
    .replace(/^http/i, 'hxxp')
    .replace(/\./g, '[.]')
    .replace(/:\/\//, '[://]');

export function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// Backend report format names vs on-disk extensions
export const FORMAT_TO_EXT = { json: 'json', markdown: 'md', html: 'html', stix: 'stix' };
export const EXT_TO_FORMAT = { json: 'json', md: 'markdown', html: 'html', stix: 'stix' };
