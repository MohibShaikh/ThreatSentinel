import React from 'react';
import { useQuery } from 'react-query';
import { Link } from 'react-router-dom';
import { api } from '../context/ThreatSentinelContext';

const riskClass = (level) => {
  switch ((level || '').toLowerCase()) {
    case 'critical': return 'status-critical';
    case 'high': return 'status-high';
    case 'medium': return 'status-medium';
    case 'low': return 'status-low';
    default: return 'status-info';
  }
};

const StatCell = ({ label, value, tone }) => (
  <div className="px-5 py-4 flex-1 min-w-[140px]">
    <p className="label">{label}</p>
    <p className={`num text-3xl mt-1.5 ${tone || 'text-ink'}`}>{value}</p>
  </div>
);

const Dashboard = () => {
  const { data, isLoading } = useQuery(
    'dashboardData',
    async () => {
      const [investigations, reports, metrics] = await Promise.all([
        api.get('/investigations/?limit=8').then(res => res.data),
        api.get('/reports/').then(res => res.data),
        api.get('/monitoring/metrics').then(res => res.data),
      ]);
      return { investigations, reports, metrics };
    },
    { refetchInterval: 30000 }
  );

  if (isLoading) {
    return (
      <div className="panel px-6 py-16 text-center">
        <p className="label">Loading console</p>
      </div>
    );
  }

  const m = data?.metrics || {};
  const investigations = Array.isArray(data?.investigations)
    ? data.investigations
    : data?.investigations?.results || [];
  const reports = Array.isArray(data?.reports) ? data.reports : [];

  return (
    <div className="space-y-6">
      {/* Stat strip */}
      <div className="panel flex flex-wrap divide-x divide-rule">
        <StatCell label="Active now" value={m.active_investigations ?? 0} />
        <StatCell label="Completed today" value={m.completed_investigations_today ?? 0} />
        <StatCell
          label="High risk 24h"
          value={m.high_risk_events_today ?? 0}
          tone={(m.high_risk_events_today || 0) > 0 ? 'text-high' : 'text-ink'}
        />
        <StatCell
          label="Error rate"
          value={`${(m.error_rate ?? 0).toFixed(1)}%`}
          tone={(m.error_rate || 0) > 5 ? 'text-critical' : 'text-ink'}
        />
        <StatCell
          label="Avg investigation"
          value={`${(m.average_investigation_time ?? 0).toFixed(0)}s`}
        />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Recent investigations */}
        <div className="xl:col-span-2 panel">
          <div className="panel-head">
            <h2 className="label">Recent investigations</h2>
            <Link to="/investigations" className="font-mono text-xs uppercase tracking-[0.1em] text-signal hover:underline">
              All
            </Link>
          </div>
          {investigations.length === 0 ? (
            <div className="px-4 py-10 text-center">
              <p className="text-sm text-muted">No investigations yet.</p>
              <Link to="/investigations" className="btn-secondary inline-block mt-4">Start one</Link>
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Event</th>
                  <th>Source IP</th>
                  <th>Risk</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {investigations.slice(0, 8).map((inv) => (
                  <tr key={inv.investigation_id}>
                    <td className="num text-xs">
                      <Link to={`/investigations/${inv.investigation_id}`} className="hover:text-signal hover:underline">
                        {inv.investigation_id}
                      </Link>
                    </td>
                    <td>{inv.event_type || '—'}</td>
                    <td className="num text-xs">{inv.source_ip || '—'}</td>
                    <td>
                      <span className={`status-badge ${riskClass(inv.risk_level)}`}>
                        {inv.risk_level || 'unknown'}
                      </span>
                    </td>
                    <td className="num text-xs">{inv.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Right column */}
        <div className="space-y-6">
          {/* System readout */}
          <div className="panel">
            <div className="panel-head">
              <h2 className="label">System readout</h2>
              <Link to="/monitoring" className="font-mono text-xs uppercase tracking-[0.1em] text-signal hover:underline">
                Detail
              </Link>
            </div>
            <dl className="px-4 py-2 divide-y divide-rule">
              {[
                ['Memory usage', `${(m.memory_usage_mb ?? 0).toFixed(0)} MB`],
                ['Intel calls', Object.entries(m.threat_intel_api_calls || {})
                  .map(([k, v]) => `${k}:${v}`).join('  ') || 'none'],
                ['Reports stored', String(reports.length)],
              ].map(([k, v]) => (
                <div key={k} className="flex items-center justify-between py-2.5">
                  <dt className="label">{k}</dt>
                  <dd className="num text-sm">{v}</dd>
                </div>
              ))}
            </dl>
          </div>

          {/* Recent reports */}
          <div className="panel">
            <div className="panel-head">
              <h2 className="label">Recent reports</h2>
              <Link to="/reports" className="font-mono text-xs uppercase tracking-[0.1em] text-signal hover:underline">
                All
              </Link>
            </div>
            {reports.length === 0 ? (
              <p className="px-4 py-8 text-center text-sm text-muted">No reports generated yet.</p>
            ) : (
              <ul className="divide-y divide-rule">
                {reports.slice(0, 5).map((report, i) => (
                  <li key={i} className="px-4 py-2.5 flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <p className="text-sm truncate">{report.title || report.report_id}</p>
                      <p className="num text-[11px] text-muted">
                        {report.created_at ? new Date(report.created_at).toLocaleDateString() : ''}
                      </p>
                    </div>
                    <span className={`status-badge ${report.status === 'completed' ? 'status-success' : 'status-info'}`}>
                      {report.status || 'stored'}
                    </span>
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
