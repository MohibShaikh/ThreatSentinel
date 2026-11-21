import React, { useState } from 'react';
import { useQuery } from 'react-query';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../context/ThreatSentinelContext';
import {
  Empty, ErrorNote, Field, PanelHead, StatCell, StatStrip, StatusBadge, fmtNum, fmtTime,
} from '../components/ui';

const LEVELS = ['', 'debug', 'info', 'warning', 'error', 'critical'];
const FILTER_KEYS = ['investigation_id', 'component', 'level', 'since_hours'];

const IntegrityPanel = () => {
  const { data, error, isFetching, refetch } = useQuery('auditIntegrity',
    () => api.get('/audit/integrity').then((r) => r.data), { staleTime: 60000 });
  const valid = data?.valid;
  const broken = data?.broken_links || [];

  return (
    <div className={`panel ${data ? (valid ? 'border-low/50' : 'border-critical/60') : ''}`}>
      <PanelHead title="SHA-256 hash-chain integrity">
        <button type="button" className="btn-secondary !px-3 !py-1" disabled={isFetching} onClick={() => refetch()}>
          {isFetching ? 'Verifying…' : 'Re-verify'}
        </button>
      </PanelHead>
      {error ? <div className="p-4"><ErrorNote error={error} what="integrity" /></div> : !data ? <Empty>Verifying…</Empty> : (
        <div className="px-4 py-4 flex flex-wrap items-center gap-x-10 gap-y-3">
          <p className={`display-xl text-4xl uppercase ${valid ? 'text-low' : 'text-critical'}`}>{valid ? 'Verified' : 'Tampered'}</p>
          <dl className="grid grid-cols-2 sm:grid-cols-4 gap-x-8 gap-y-1">
            {[
              ['Entries', data.total_entries],
              ['Chained', data.chained_entries],
              ['Legacy', data.legacy_unchained_entries],
              ['Broken links', broken.length],
            ].map(([k, v]) => (
              <div key={k}>
                <dt className="label">{k}</dt>
                <dd className={`num text-lg ${k === 'Broken links' && v > 0 ? 'text-critical' : ''}`}>{v ?? '—'}</dd>
              </div>
            ))}
          </dl>
          <div className="w-full num text-[11px] text-muted break-all">
            head {data.head_hash || '—'} · verified {fmtTime(data.verified_at)}
          </div>
          {broken.length > 0 && (
            <ul className="w-full border border-critical/40 divide-y divide-rule">
              {broken.slice(0, 10).map((b) => (
                <li key={`${b.id}-${b.rowid}`} className="px-3 py-1.5 num text-xs text-critical">
                  row {b.rowid} · {b.id} · {b.reason}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
};

const Audit = () => {
  const [params, setParams] = useSearchParams();
  const applied = Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) || '']));
  const [draft, setDraft] = useState({ ...applied, since_hours: applied.since_hours || '24' });

  const overviewQ = useQuery('auditOverview', () => api.get('/audit/statistics/overview').then((r) => r.data),
    { refetchInterval: 30000 });
  const componentsQ = useQuery('auditComponents', () => api.get('/audit/components/').then((r) => r.data),
    { refetchInterval: 30000 });
  const logsQ = useQuery(['auditLogs', applied],
    () => api.get('/audit/logs/search', {
      params: {
        ...Object.fromEntries(Object.entries(applied).filter(([, v]) => v)),
        since_hours: Number(applied.since_hours) || 24,
        limit: 200,
      },
    }).then((r) => r.data),
    { refetchInterval: 15000 });

  const search = (e) => {
    e.preventDefault();
    const next = new URLSearchParams();
    Object.entries(draft).forEach(([k, v]) => v && String(v).trim() && next.set(k, String(v).trim()));
    setParams(next, { replace: true });
  };

  const o = overviewQ.data || {};
  const logs = logsQ.data || [];
  const components = componentsQ.data || [];

  return (
    <div className="space-y-6">
      <StatStrip>
        <StatCell label="Investigations tracked" value={o.total_investigations_tracked ?? '—'} />
        <StatCell label="Actions logged" value={o.total_actions_logged ?? '—'} />
        <StatCell label="Actions 24h" value={o.recent_actions_24h ?? '—'} />
        <StatCell label="Errors 24h" value={o.recent_errors_24h ?? '—'} tone={(o.recent_errors_24h || 0) > 0 ? 'text-high' : 'text-ink'} />
        <StatCell label="Error rate" value={typeof o.error_rate_24h === 'number' ? `${o.error_rate_24h.toFixed(1)}%` : '—'} />
        <StatCell label="Audit health" value={o.audit_health || '—'}
          tone={o.audit_health === 'healthy' ? 'text-low' : o.audit_health ? 'text-high' : 'text-ink'} />
      </StatStrip>

      <IntegrityPanel />

      <div className="panel">
        <PanelHead title={`Action log · ${logs.length}`} />
        <form onSubmit={search} className="px-4 py-3 border-b border-rule grid grid-cols-2 md:grid-cols-5 gap-3 items-end">
          <Field label="Investigation ID">
            <input className="input-field w-full !py-1.5" value={draft.investigation_id} onChange={(e) => setDraft({ ...draft, investigation_id: e.target.value })} />
          </Field>
          <Field label="Component">
            <input className="input-field w-full !py-1.5" list="audit-components" value={draft.component} onChange={(e) => setDraft({ ...draft, component: e.target.value })} />
            <datalist id="audit-components">{components.map((c) => <option key={c.component} value={c.component} />)}</datalist>
          </Field>
          <Field label="Level">
            <select className="input-field w-full !py-1.5" value={draft.level} onChange={(e) => setDraft({ ...draft, level: e.target.value })}>
              {LEVELS.map((l) => <option key={l} value={l}>{l || 'any'}</option>)}
            </select>
          </Field>
          <Field label="Since (hours)">
            <input type="number" min={1} max={168} className="input-field w-full !py-1.5" value={draft.since_hours} onChange={(e) => setDraft({ ...draft, since_hours: e.target.value })} />
          </Field>
          <div className="flex gap-2">
            <button type="submit" className="btn-primary">Search</button>
            <button type="button" className="btn-secondary" onClick={() => { setDraft({ investigation_id: '', component: '', level: '', since_hours: '24' }); setParams({}, { replace: true }); }}>Reset</button>
          </div>
        </form>
        {logsQ.error ? <div className="p-4"><ErrorNote error={logsQ.error} what="audit logs" /></div>
          : logsQ.isLoading ? <Empty>Loading…</Empty>
          : logs.length === 0 ? <Empty>No audit entries match.</Empty>
          : (
            <div className="overflow-x-auto scrollbar-thin max-h-[640px]">
              <table className="data-table">
                <thead><tr><th>Time</th><th>Level</th><th>Status</th><th>Component</th><th>Action</th><th>Description</th><th>Investigation</th><th>ms</th></tr></thead>
                <tbody>
                  {logs.map((l) => (
                    <tr key={l.id}>
                      <td className="num text-xs whitespace-nowrap">{fmtTime(l.timestamp)}</td>
                      <td><StatusBadge status={l.level} /></td>
                      <td><StatusBadge status={l.status} /></td>
                      <td className="num text-xs">{l.component}</td>
                      <td className="num text-xs">{l.action_type}</td>
                      <td className="text-xs text-inksoft max-w-[360px]">
                        {l.description}
                        {l.error_message && <span className="block text-critical">{l.error_message}</span>}
                      </td>
                      <td className="num text-xs whitespace-nowrap">
                        {l.investigation_id
                          ? <Link to={`/investigations/${l.investigation_id}`} className="hover:text-signal hover:underline">{l.investigation_id}</Link>
                          : '—'}
                      </td>
                      <td className="num text-xs">{l.duration_ms ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </div>

      <div className="panel">
        <PanelHead title={`Active components 24h · ${components.length}`} />
        {componentsQ.error ? <div className="p-4"><ErrorNote error={componentsQ.error} what="components" /></div>
          : components.length === 0 ? <Empty>No component activity in the last 24 hours.</Empty>
          : (
            <table className="data-table">
              <thead><tr><th>Component</th><th>Actions</th><th>Errors</th><th>Error %</th><th>Last activity</th><th /></tr></thead>
              <tbody>
                {components.map((c) => (
                  <tr key={c.component}>
                    <td className="num text-sm">{c.component}</td>
                    <td className="num text-xs">{c.action_count}</td>
                    <td className={`num text-xs ${c.error_count ? 'text-critical' : ''}`}>{c.error_count}</td>
                    <td className="num text-xs">{c.action_count ? fmtNum((c.error_count / c.action_count) * 100, 1) : '0.0'}</td>
                    <td className="num text-xs text-muted">{fmtTime(c.last_activity)}</td>
                    <td className="text-right">
                      <button type="button" className="font-mono text-[11px] uppercase text-signal hover:underline"
                        onClick={() => { const d = { ...draft, component: c.component }; setDraft(d); setParams(Object.fromEntries(Object.entries(d).filter(([, v]) => v)), { replace: true }); }}>
                        Filter
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
      </div>
    </div>
  );
};

export default Audit;
