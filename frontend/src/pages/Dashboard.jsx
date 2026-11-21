import React from 'react';
import { useQuery } from 'react-query';
import { Link } from 'react-router-dom';
import { api, useThreatSentinel } from '../context/ThreatSentinelContext';
import {
  Empty, FrameworkChips, HeadLink, PanelHead, Readout, RiskBadge, StatCell, StatStrip, StatusBadge, fmtNum, fmtTime,
} from '../components/ui';

const Dashboard = () => {
  const { llmProvider, intelSources, statsData } = useThreatSentinel();

  const investigations = useQuery(['investigations', 'recent'],
    () => api.get('/investigations/?limit=8').then((r) => r.data), { refetchInterval: 15000 });
  const reports = useQuery(['reports', 'recent'],
    () => api.get('/reports/?limit=5').then((r) => r.data), { refetchInterval: 30000 });
  const metrics = useQuery('monitoringMetrics',
    () => api.get('/monitoring/metrics').then((r) => r.data), { refetchInterval: 15000 });
  const reviews = useQuery('pendingReviews',
    () => api.get('/investigations/reviews/pending').then((r) => r.data), { refetchInterval: 15000 });

  const m = metrics.data || {};
  const invList = investigations.data?.investigations || [];
  const reportList = reports.data?.reports || [];
  const reviewList = reviews.data?.reviews || [];
  const intelCalls = Object.entries(m.threat_intel_api_calls || {});

  return (
    <div className="space-y-6">
      <StatStrip>
        <StatCell label="Active now" value={m.active_investigations ?? '—'} />
        <StatCell label="Completed today" value={m.completed_investigations_today ?? '—'} />
        <StatCell
          label="Pending review"
          value={reviews.data ? reviews.data.total_count : '—'}
          tone={reviewList.length > 0 ? 'text-high' : 'text-ink'}
        />
        <StatCell
          label="High risk 24h"
          value={m.high_risk_events_today ?? '—'}
          tone={(m.high_risk_events_today || 0) > 0 ? 'text-high' : 'text-ink'}
        />
        <StatCell
          label="Error rate"
          value={typeof m.error_rate === 'number' ? `${m.error_rate.toFixed(1)}%` : '—'}
          tone={(m.error_rate || 0) > 5 ? 'text-critical' : 'text-ink'}
        />
        <StatCell
          label="Avg latency"
          value={typeof m.api_response_time === 'number' ? `${m.api_response_time.toFixed(0)}ms` : '—'}
        />
      </StatStrip>

      {reviewList.length > 0 && (
        <div className="panel border-high/50">
          <div className="panel-head bg-high/10">
            <h2 className="label text-high">Pending human review · {reviewList.length}</h2>
            <HeadLink to="/investigations?status=pending_human_review">Queue</HeadLink>
          </div>
          <ul className="divide-y divide-rule">
            {reviewList.slice(0, 5).map((r) => (
              <li key={r.investigation_id} className="px-4 py-2.5 flex flex-wrap items-center gap-3">
                <span className={`status-badge status-${r.priority === 'critical' ? 'critical' : r.priority === 'high' ? 'high' : 'medium'}`}>
                  {r.priority}
                </span>
                <Link to={`/investigations/${r.investigation_id}`} className="num text-xs hover:text-signal hover:underline">
                  {r.investigation_id}
                </Link>
                <span className="text-sm">{r.title || r.event_type}</span>
                <span className="text-xs text-muted truncate flex-1 min-w-[160px]">{r.reason}</span>
                <RiskBadge level={r.risk_level} score={r.risk_score} />
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-2 panel">
          <PanelHead title="Recent investigations"><HeadLink to="/investigations">All</HeadLink></PanelHead>
          {investigations.isLoading ? <Empty>Loading…</Empty> : invList.length === 0 ? (
            <div className="px-4 py-10 text-center">
              <p className="text-sm text-muted">No investigations yet. Try a preset; no API keys needed.</p>
              <Link to="/investigations?new=1" className="btn-secondary inline-block mt-4">Start one</Link>
            </div>
          ) : (
            <div className="overflow-x-auto scrollbar-thin">
              <table className="data-table">
                <thead>
                  <tr><th>ID</th><th>Event</th><th>Source IP</th><th>Frameworks</th><th>Risk</th><th>Status</th></tr>
                </thead>
                <tbody>
                  {invList.map((inv) => (
                    <tr key={inv.investigation_id}>
                      <td className="num text-xs whitespace-nowrap">
                        <Link to={`/investigations/${inv.investigation_id}`} className="hover:text-signal hover:underline">
                          {inv.investigation_id}
                        </Link>
                      </td>
                      <td className="text-sm">{inv.event_type || '—'}</td>
                      <td className="num text-xs">{inv.source_ip || '—'}</td>
                      <td>
                        <FrameworkChips owasp={inv.owasp_categories || []} mitre={inv.mitre_techniques || []}
                          injection={inv.prompt_injection_detected} />
                      </td>
                      <td><RiskBadge level={inv.risk_level} /></td>
                      <td><StatusBadge status={inv.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="space-y-6">
          <div className="panel">
            <PanelHead title="System & agent readout"><HeadLink to="/monitoring">Detail</HeadLink></PanelHead>
            <Readout rows={[
              ['Memory', typeof m.memory_usage_mb === 'number' ? `${m.memory_usage_mb.toFixed(0)} MB` : '—'],
              ['LLM', llmProvider || <span className="text-muted">Disabled / offline mode</span>],
              ['Intel sources', intelSources.length
                ? <span className="flex flex-wrap justify-end gap-1">{intelSources.map((s) => <span key={s} className="border border-rule px-1 text-[11px]">{s}</span>)}</span>
                : <span className="text-muted">—</span>],
              ['Intel calls', intelCalls.length ? intelCalls.map(([k, v]) => `${k}:${v}`).join('  ') : 'none yet'],
              ['Avg run', `${fmtNum(m.average_investigation_time, 1, '0.0')}s`],
              ['Reports stored', reports.data ? String(reports.data.total_count ?? reportList.length) : '—'],
              ['Memory records', String(statsData?.memory_stats?.total_investigations ?? '—')],
            ]} />
          </div>

          <div className="panel">
            <PanelHead title="Recent reports"><HeadLink to="/reports">All</HeadLink></PanelHead>
            {reportList.length === 0 ? <Empty>No reports generated yet.</Empty> : (
              <ul className="divide-y divide-rule">
                {reportList.map((r) => (
                  <li key={r.file_name || r.report_id} className="px-4 py-2.5 flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <Link to={`/reports/${r.report_id}?format=${r.format}`} className="num text-xs truncate block hover:text-signal hover:underline">
                        {r.report_id}
                      </Link>
                      <p className="num text-[11px] text-muted">{fmtTime(r.created_at)}</p>
                    </div>
                    <span className="status-badge status-info">{r.format}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
