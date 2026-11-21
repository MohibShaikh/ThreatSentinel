import React, { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from 'react-query';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import toast from 'react-hot-toast';
import { api, useThreatSentinel } from '../context/ThreatSentinelContext';
import InvestigationForm from '../components/Investigations/InvestigationForm';
import {
  Empty, ErrorNote, FrameworkChips, PanelHead, RiskBadge, StatusBadge, errorMessage, fmtTime,
} from '../components/ui';

const STATUSES = ['all', 'pending', 'running', 'pending_human_review', 'completed', 'failed', 'cancelled'];
const RISKS = ['all', 'critical', 'high', 'medium', 'low'];
const ACTIVE = new Set(['pending', 'queued', 'running']);

const Investigations = () => {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { createInvestigation } = useThreatSentinel();
  const [search, setSearch] = useState('');
  const [risk, setRisk] = useState('all');

  // Filter and form state live in the URL, so every view is linkable and survives refresh
  const status = STATUSES.includes(params.get('status')) ? params.get('status') : 'all';
  const showForm = params.get('new') === '1';
  const setParam = (key, value) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value); else next.delete(key);
    setParams(next, { replace: true });
  };

  const { data, isLoading, error } = useQuery(
    ['investigations', 'list', status],
    () => api.get('/investigations/', { params: { limit: 200, ...(status !== 'all' ? { status } : {}) } })
      .then((r) => r.data),
    { refetchInterval: 5000 }
  );

  const cancel = useMutation((id) => api.delete(`/investigations/${id}`), {
    onSuccess: () => {
      toast.success('Investigation cancelled');
      queryClient.invalidateQueries('investigations');
      queryClient.invalidateQueries('agentStats');
    },
    onError: (e) => toast.error(`Cancel failed: ${errorMessage(e)}`),
  });

  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    return (data?.investigations || []).filter((inv) => {
      if (risk !== 'all' && inv.risk_level !== risk) return false;
      if (!q) return true;
      return [inv.investigation_id, inv.title, inv.event_type, inv.source_ip, ...(inv.owasp_categories || []),
        ...(inv.mitre_techniques || [])]
        .some((v) => String(v || '').toLowerCase().includes(q));
    });
  }, [data, search, risk]);

  const submit = (payload) =>
    createInvestigation.mutate(payload, {
      onSuccess: (res) => navigate(`/investigations/${res.investigation_id}`),
    });

  return (
    <div className="space-y-6">
      {showForm ? (
        <InvestigationForm onSubmit={submit} onCancel={() => setParam('new', null)} submitting={createInvestigation.isLoading} />
      ) : (
        <div className="flex justify-end">
          <button type="button" className="btn-primary" onClick={() => setParam('new', '1')}>New investigation</button>
        </div>
      )}

      <div className="panel">
        <PanelHead title={`Investigations · ${data?.total_count ?? '—'}`} />
        <div className="flex flex-wrap items-end gap-4 px-4 py-3 border-b border-rule">
          <div className="flex flex-wrap gap-px bg-rule border border-rule">
            {STATUSES.map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => setParam('status', s === 'all' ? null : s)}
                className={`px-2.5 py-1.5 font-mono text-[11px] uppercase tracking-[0.08em] ${
                  status === s ? 'bg-ink text-paper' : 'bg-panel text-inksoft hover:bg-paper'
                }`}
              >
                {s.replace(/_/g, ' ')}
              </button>
            ))}
          </div>
          <select className="input-field !py-1.5" value={risk} onChange={(e) => setRisk(e.target.value)} aria-label="Risk filter">
            {RISKS.map((r) => <option key={r} value={r}>{r === 'all' ? 'any risk' : r}</option>)}
          </select>
          <input
            className="input-field !py-1.5 flex-1 min-w-[200px]"
            placeholder="Search ID, title, IP, OWASP, MITRE…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        {error ? <div className="p-4"><ErrorNote error={error} what="investigations" /></div>
          : isLoading ? <Empty>Loading…</Empty>
          : rows.length === 0 ? <Empty>No investigations match.</Empty>
          : (
            <div className="overflow-x-auto scrollbar-thin">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>ID</th><th>Title / event</th><th>Source IP</th><th>Frameworks</th>
                    <th>Risk</th><th>Status</th><th>Created</th><th />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((inv) => (
                    <tr key={inv.investigation_id}>
                      <td className="num text-xs whitespace-nowrap">
                        <Link to={`/investigations/${inv.investigation_id}`} className="hover:text-signal hover:underline">
                          {inv.investigation_id}
                        </Link>
                        {inv.emergency_mode && <span className="ml-1.5 text-critical" title="Emergency mode">!</span>}
                      </td>
                      <td>
                        <p className="text-sm">{inv.title || inv.event_type || '—'}</p>
                        {inv.title && <p className="num text-[11px] text-muted">{inv.event_type}</p>}
                      </td>
                      <td className="num text-xs">{inv.source_ip || '—'}</td>
                      <td>
                        <FrameworkChips owasp={inv.owasp_categories || []} mitre={inv.mitre_techniques || []}
                          injection={inv.prompt_injection_detected} max={3} />
                      </td>
                      <td><RiskBadge level={inv.risk_level} score={inv.risk_score} /></td>
                      <td>
                        <StatusBadge status={inv.status} />
                        {ACTIVE.has(inv.status) && (
                          <span className="num text-[10px] text-muted ml-1.5">{inv.progress || 0}%</span>
                        )}
                      </td>
                      <td className="num text-xs text-muted whitespace-nowrap">{fmtTime(inv.created_at)}</td>
                      <td className="text-right">
                        {ACTIVE.has(inv.status) && (
                          <button
                            type="button"
                            className="font-mono text-[11px] uppercase text-critical hover:underline disabled:text-muted"
                            disabled={cancel.isLoading}
                            onClick={() => cancel.mutate(inv.investigation_id)}
                          >
                            Cancel
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </div>
    </div>
  );
};

export default Investigations;
