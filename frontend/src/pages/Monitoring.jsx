import React, { useState } from 'react';
import { useQuery } from 'react-query';
import {
  ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid,
} from 'recharts';
import { api } from '../context/ThreatSentinelContext';

const StatCell = ({ label, value, tone }) => (
  <div className="px-5 py-4 flex-1 min-w-[140px]">
    <p className="label">{label}</p>
    <p className={`num text-3xl mt-1.5 ${tone || 'text-ink'}`}>{value}</p>
  </div>
);

const chartTooltip = {
  backgroundColor: '#FBFAF6',
  border: '1px solid #DBD9CE',
  borderRadius: 0,
  fontSize: 12,
  fontFamily: 'IBM Plex Mono, monospace',
  color: '#1A1B17',
};

const Monitoring = () => {
  const [autoRefresh, setAutoRefresh] = useState(true);

  const { data: metrics, isLoading } = useQuery(
    'monitoringMetrics',
    () => api.get('/monitoring/metrics').then(res => res.data),
    { refetchInterval: autoRefresh ? 30000 : false }
  );

  const { data: history } = useQuery(
    'monitoringHistory',
    () => api.get('/monitoring/metrics/history?hours=24').then(res => res.data),
    { refetchInterval: autoRefresh ? 60000 : false }
  );

  const { data: alertData } = useQuery(
    'alerts',
    () => api.get('/monitoring/alerts/recent').then(res => res.data),
    { refetchInterval: autoRefresh ? 10000 : false }
  );

  if (isLoading) {
    return (
      <div className="panel px-6 py-16 text-center">
        <p className="label">Loading metrics</p>
      </div>
    );
  }

  const series = (history?.metrics || []).map(m => ({
    ...m,
    time: new Date(m.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
  }));
  const alerts = Array.isArray(alertData?.alerts) ? alertData.alerts : [];
  const errorRate = metrics?.error_rate ?? 0;

  return (
    <div className="space-y-6">
      {/* Stat strip */}
      <div className="panel flex flex-wrap divide-x divide-rule">
        <StatCell label="Active now" value={metrics?.active_investigations ?? 0} />
        <StatCell label="Completed today" value={metrics?.completed_investigations_today ?? 0} />
        <StatCell
          label="High risk 24h"
          value={metrics?.high_risk_events_today ?? 0}
          tone={(metrics?.high_risk_events_today || 0) > 0 ? 'text-high' : 'text-ink'}
        />
        <StatCell
          label="Error rate"
          value={`${errorRate.toFixed(1)}%`}
          tone={errorRate > 5 ? 'text-critical' : 'text-ink'}
        />
        <StatCell
          label="Memory"
          value={`${((metrics?.memory_usage_mb ?? 0) / 1024).toFixed(1)} GB`}
        />
      </div>

      {/* History charts */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="panel">
          <div className="panel-head">
            <h2 className="label">Memory usage 24h</h2>
            <span className="num text-[11px] text-muted">{series.length} samples</span>
          </div>
          <div className="h-56 px-3 py-4">
            {series.length < 2 ? (
              <p className="text-sm text-muted pt-16 text-center">
                Collecting samples. Points accrue as the console polls.
              </p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={series}>
                  <CartesianGrid stroke="#E7E5DC" vertical={false} />
                  <XAxis dataKey="time" tick={{ fill: '#75746A', fontSize: 10, fontFamily: 'IBM Plex Mono' }} tickLine={false} />
                  <YAxis tick={{ fill: '#75746A', fontSize: 10, fontFamily: 'IBM Plex Mono' }} tickLine={false} width={44} />
                  <Tooltip contentStyle={chartTooltip} />
                  <Line type="monotone" dataKey="memory_usage_mb" name="MB" stroke="#1A1B17" strokeWidth={1.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-head">
            <h2 className="label">Investigation activity 24h</h2>
            <span className="num text-[11px] text-muted">{history?.total_points ?? 0} pts</span>
          </div>
          <div className="h-56 px-3 py-4">
            {series.length < 2 ? (
              <p className="text-sm text-muted pt-16 text-center">No activity recorded yet.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={series}>
                  <CartesianGrid stroke="#E7E5DC" vertical={false} />
                  <XAxis dataKey="time" tick={{ fill: '#75746A', fontSize: 10, fontFamily: 'IBM Plex Mono' }} tickLine={false} />
                  <YAxis allowDecimals={false} tick={{ fill: '#75746A', fontSize: 10, fontFamily: 'IBM Plex Mono' }} tickLine={false} width={28} />
                  <Tooltip contentStyle={chartTooltip} />
                  <Line type="stepAfter" dataKey="active_investigations" name="Active" stroke="#16794C" strokeWidth={1.5} dot={false} />
                  <Line type="stepAfter" dataKey="high_risk_events_today" name="High risk" stroke="#BC5414" strokeWidth={1.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Alerts + intel calls */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-2 panel">
          <div className="panel-head">
            <h2 className="label">Recent alerts</h2>
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                className="accent-[#16794C]"
              />
              <span className="label !text-inksoft">Auto refresh</span>
            </label>
          </div>
          {alerts.length === 0 ? (
            <p className="px-4 py-10 text-center text-sm text-muted">
              No alerts. Threshold notifications appear here when risk crosses the configured level.
            </p>
          ) : (
            <table className="data-table">
              <thead>
                <tr><th>Time</th><th>Level</th><th>Message</th></tr>
              </thead>
              <tbody>
                {alerts.slice(0, 10).map((alert, i) => (
                  <tr key={i}>
                    <td className="num text-xs">{alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : '—'}</td>
                    <td><span className={`status-badge status-${(alert.level || 'info').toLowerCase()}`}>{alert.level || 'info'}</span></td>
                    <td>{alert.message || JSON.stringify(alert).slice(0, 80)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="panel">
          <div className="panel-head"><h2 className="label">Intel API calls today</h2></div>
          {Object.keys(metrics?.threat_intel_api_calls || {}).length === 0 ? (
            <p className="px-4 py-10 text-center text-sm text-muted">
              No threat intel lookups yet.
            </p>
          ) : (
            <dl className="px-4 py-2 divide-y divide-rule">
              {Object.entries(metrics.threat_intel_api_calls).map(([k, v]) => (
                <div key={k} className="flex items-center justify-between py-2.5">
                  <dt className="label">{k}</dt>
                  <dd className="num text-sm">{v}</dd>
                </div>
              ))}
            </dl>
          )}
        </div>
      </div>
    </div>
  );
};

export default Monitoring;
