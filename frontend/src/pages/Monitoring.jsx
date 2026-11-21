import React, { useEffect, useRef, useState } from 'react';
import { useQuery } from 'react-query';
import { Link } from 'react-router-dom';
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { API_BASE, api, getToken } from '../context/ThreatSentinelContext';
import {
  Chip, Empty, PanelHead, Readout, RiskBadge, StatCell, StatStrip, StatusBadge, Toggle, fmtNum, fmtTime,
} from '../components/ui';

const chartTooltip = {
  backgroundColor: '#FBFAF6',
  border: '1px solid #DBD9CE',
  borderRadius: 0,
  fontSize: 12,
  fontFamily: 'IBM Plex Mono, monospace',
  color: '#1A1B17',
};
const tick = { fill: '#75746A', fontSize: 10, fontFamily: 'IBM Plex Mono' };

function streamUrl() {
  const base = new URL(API_BASE, window.location.href);
  base.protocol = base.protocol === 'https:' ? 'wss:' : 'ws:';
  base.pathname = `${base.pathname.replace(/\/$/, '')}/monitoring/metrics/stream`;
  base.search = '';
  return base.toString();
}

// Live metrics over WebSocket. The token goes in the first message, never in the URL.
function useMetricsStream(enabled) {
  const [state, setState] = useState({ status: 'off', last: null, error: null });
  const wsRef = useRef(null);

  useEffect(() => {
    if (!enabled) {
      setState((s) => ({ ...s, status: 'off' }));
      return undefined;
    }
    let ws;
    try {
      ws = new WebSocket(streamUrl());
    } catch (e) {
      setState({ status: 'error', last: null, error: e.message });
      return undefined;
    }
    wsRef.current = ws;
    setState({ status: 'connecting', last: null, error: null });
    ws.onopen = () => ws.send(JSON.stringify({ type: 'auth', token: getToken() }));
    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      if (msg.type === 'auth_ok') setState((s) => ({ ...s, status: 'live' }));
      else if (msg.type === 'metrics') setState({ status: 'live', last: msg, error: null });
      else if (msg.type === 'error') setState((s) => ({ ...s, error: msg.error }));
    };
    ws.onclose = (ev) => setState((s) => ({
      ...s,
      status: ev.code === 4401 ? 'unauthorized' : 'closed',
    }));
    ws.onerror = () => setState((s) => ({ ...s, status: 'error' }));
    return () => ws.close();
  }, [enabled]);

  return state;
}

const Monitoring = () => {
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [live, setLive] = useState(false);
  const stream = useMetricsStream(live);

  const metricsQ = useQuery('monitoringMetrics',
    () => api.get('/monitoring/metrics').then((r) => r.data),
    { refetchInterval: autoRefresh && !live ? 15000 : false });
  const historyQ = useQuery('monitoringHistory',
    () => api.get('/monitoring/metrics/history', { params: { hours: 24, resolution: 'minute' } }).then((r) => r.data),
    { refetchInterval: autoRefresh ? 30000 : false });
  const alertsQ = useQuery('alerts',
    () => api.get('/monitoring/alerts/recent').then((r) => r.data),
    { refetchInterval: autoRefresh ? 10000 : false });
  const perfQ = useQuery('performanceStats',
    () => api.get('/monitoring/performance/stats').then((r) => r.data),
    { refetchInterval: autoRefresh ? 30000 : false });

  const m = (live && stream.last) || metricsQ.data || {};
  const series = (historyQ.data?.metrics || []).map((p) => ({
    ...p,
    time: new Date(p.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
  }));
  const alerts = alertsQ.data?.alerts || [];
  const intelCalls = Object.entries(m.threat_intel_api_calls || {});
  const latency = perfQ.data?.api_latency || {};
  const errorRate = m.error_rate;

  const streamTone = { live: 'text-low', connecting: 'text-medium', unauthorized: 'text-critical', error: 'text-critical' }[stream.status] || 'text-muted';

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-end gap-5">
        <Toggle checked={autoRefresh} onChange={setAutoRefresh}>Auto refresh</Toggle>
        <Toggle checked={live} onChange={setLive}>Live WebSocket stream</Toggle>
        <span className={`font-mono text-[11px] uppercase tracking-[0.1em] ${streamTone}`}>
          {stream.status === 'live' && <span className="inline-block w-1.5 h-1.5 mr-1.5 bg-current blink" />}
          {stream.status}
        </span>
        {stream.status === 'unauthorized' && (
          <span className="w-full text-right text-xs text-critical">
            The stream needs a valid token even in DEBUG mode. Set one under Session / Token.
          </span>
        )}
      </div>

      <StatStrip>
        <StatCell label="Active now" value={m.active_investigations ?? '—'} />
        <StatCell label="Completed today" value={m.completed_investigations_today ?? '—'} />
        <StatCell label="High risk 24h" value={m.high_risk_events_today ?? '—'}
          tone={(m.high_risk_events_today || 0) > 0 ? 'text-high' : 'text-ink'} />
        <StatCell label="Error rate" value={typeof errorRate === 'number' ? `${errorRate.toFixed(1)}%` : '—'}
          tone={(errorRate || 0) > 5 ? 'text-critical' : 'text-ink'} />
        <StatCell label="API latency"
          value={typeof m.api_response_time === 'number' ? `${m.api_response_time.toFixed(0)}ms` : '—'}
          hint={typeof m.api_response_time === 'number' ? 'avg last 200 requests' : 'no samples yet'} />
        <StatCell label="Process memory" value={typeof m.memory_usage_mb === 'number' ? `${m.memory_usage_mb.toFixed(0)}MB` : '—'} />
      </StatStrip>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="panel">
          <PanelHead title="API latency & memory 24h"><span className="num text-[11px] text-muted">{series.length} samples</span></PanelHead>
          <div className="h-56 px-3 py-4">
            {series.length < 2 ? (
              <p className="text-sm text-muted pt-16 text-center">Collecting samples. Points accrue each time metrics are read.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={series}>
                  <CartesianGrid stroke="#E7E5DC" vertical={false} />
                  <XAxis dataKey="time" tick={tick} tickLine={false} />
                  <YAxis yAxisId="ms" tick={tick} tickLine={false} width={40} />
                  <YAxis yAxisId="mb" orientation="right" tick={tick} tickLine={false} width={44} />
                  <Tooltip contentStyle={chartTooltip} />
                  <Line yAxisId="ms" type="monotone" dataKey="api_response_time" name="ms" stroke="#2F5FA8" strokeWidth={1.5} dot={false} connectNulls />
                  <Line yAxisId="mb" type="monotone" dataKey="memory_usage_mb" name="MB" stroke="#1A1B17" strokeWidth={1.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        <div className="panel">
          <PanelHead title="Investigation activity 24h"><span className="num text-[11px] text-muted">{historyQ.data?.total_points ?? 0} pts</span></PanelHead>
          <div className="h-56 px-3 py-4">
            {series.length < 2 ? (
              <p className="text-sm text-muted pt-16 text-center">No activity recorded yet.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={series}>
                  <CartesianGrid stroke="#E7E5DC" vertical={false} />
                  <XAxis dataKey="time" tick={tick} tickLine={false} />
                  <YAxis allowDecimals={false} tick={tick} tickLine={false} width={28} />
                  <Tooltip contentStyle={chartTooltip} />
                  <Line type="stepAfter" dataKey="active_investigations" name="Active" stroke="#16794C" strokeWidth={1.5} dot={false} />
                  <Line type="stepAfter" dataKey="high_risk_events_today" name="High risk" stroke="#BC5414" strokeWidth={1.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-2 panel">
          <PanelHead title={`Recent alerts · ${alerts.length}`}>
            <span className="num text-[11px] text-muted">high / critical, last 24h</span>
          </PanelHead>
          {alerts.length === 0 ? (
            <Empty>No high or critical investigations in the last 24 hours.</Empty>
          ) : (
            <div className="overflow-x-auto scrollbar-thin">
              <table className="data-table">
                <thead><tr><th>Triggered</th><th>Risk</th><th>Investigation</th><th>Message</th><th>OWASP</th><th>Status</th></tr></thead>
                <tbody>
                  {alerts.map((a) => (
                    <tr key={a.alert_id}>
                      <td className="num text-xs whitespace-nowrap">{fmtTime(a.triggered_at)}</td>
                      <td><RiskBadge level={a.risk_level} score={a.risk_score} /></td>
                      <td className="num text-xs">
                        <Link to={`/investigations/${a.investigation_id}`} className="hover:text-signal hover:underline">{a.investigation_id}</Link>
                      </td>
                      <td className="text-sm">
                        {a.alert_type === 'prompt_injection' && <span className="mr-1.5"><Chip tone="owasp">PI</Chip></span>}
                        {a.message}
                      </td>
                      <td><span className="flex flex-wrap gap-1">{(a.owasp_categories || []).map((o) => <Chip key={o} tone="owasp">{o}</Chip>)}</span></td>
                      <td><StatusBadge status={a.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="space-y-6">
          <div className="panel">
            <PanelHead title="Latency readout" />
            <Readout rows={[
              ['Average', typeof m.api_response_time === 'number' ? `${m.api_response_time.toFixed(1)} ms` : '—'],
              ...Object.entries(latency)
                .filter(([k, v]) => typeof v === 'number' && k !== 'average_ms')
                .map(([k, v]) => [k.replace(/_/g, ' '), Number.isInteger(v) ? String(v) : v.toFixed(1)]),
              ['Avg investigation', `${fmtNum(m.average_investigation_time, 1)} s`],
              ['Stream sockets', String(stream.last?.websocket_connections ?? '—')],
            ]} />
          </div>
          <div className="panel">
            <PanelHead title="Intel API calls since start" />
            {intelCalls.length === 0 ? <Empty>No external intel lookups yet.</Empty> : (
              <Readout rows={intelCalls.map(([k, v]) => [k, String(v)])} />
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Monitoring;
