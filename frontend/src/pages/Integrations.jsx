import React, { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from 'react-query';
import toast from 'react-hot-toast';
import { api, useThreatSentinel } from '../context/ThreatSentinelContext';
import {
  Chip, Empty, ErrorNote, Field, PanelHead, Readout, StatusBadge, TextButton, errorMessage, fmtNum, fmtTime,
} from '../components/ui';

const optional = (promise, fallback) =>
  promise.then((r) => r.data).catch((e) => {
    if ([404, 405, 501].includes(e?.response?.status)) return fallback;
    throw e;
  });

const ToolEnvironment = () => {
  const { llmProvider } = useThreatSentinel();
  const { data, error, isLoading } = useQuery('agentTools', () => optional(api.get('/tools'), null));
  const tools = Array.isArray(data) ? data : data?.tools || [];
  const llmEnabled = data && !Array.isArray(data) && 'llm_enabled' in data ? data.llm_enabled : Boolean(llmProvider);
  const [open, setOpen] = useState(null);

  return (
    <div className="panel">
      <PanelHead title={`Agent tool environment · ${tools.length}`}>
        <span className="status-badge status-success">read-only</span>
      </PanelHead>
      <div className="border-b border-rule">
        <Readout rows={[
          ['LLM tool use', llmEnabled ? (llmProvider || 'enabled') : <span className="text-muted">disabled · deterministic pivoting only</span>],
          ['Max tool steps', data?.max_tool_steps ?? '—'],
          ...(data?.llm_provider ? [['Provider', data.llm_provider]] : []),
        ]} />
      </div>
      {error ? <div className="p-4"><ErrorNote error={error} what="tools" /></div>
        : isLoading ? <Empty>Loading…</Empty>
        : tools.length === 0 ? (
          <Empty>The API did not return a tool catalog (GET /api/v1/tools). The agent still runs its built-in tools.</Empty>
        ) : (
          <ul className="divide-y divide-rule">
            {tools.map((t) => (
              <li key={t.name} className="px-4 py-2.5">
                <button type="button" className="w-full text-left" onClick={() => setOpen(open === t.name ? null : t.name)}>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="num text-sm font-medium">{t.name}</span>
                    {t.category && <Chip tone="attack">{t.category}</Chip>}
                    {t.read_only !== false
                      ? <Chip tone="signal">read-only</Chip>
                      : <Chip tone="owasp">mutating</Chip>}
                    <span className="ml-auto num text-[10px] text-muted">{open === t.name ? '−' : 'schema +'}</span>
                  </div>
                  <p className="text-xs text-inksoft mt-1">{t.description}</p>
                </button>
                {open === t.name && (
                  <pre className="mt-2 border border-rule bg-paper px-3 py-2 num text-[11px] text-inksoft overflow-auto max-h-60 scrollbar-thin">
                    {JSON.stringify(t.parameters || t.input_schema || {}, null, 2)}
                  </pre>
                )}
              </li>
            ))}
          </ul>
        )}
      <p className="px-4 py-2 border-t border-rule text-[11px] text-muted">
        Tools are self-describing JSON Schema and can only read. Response actions below stay behind risk scoring and human review.
      </p>
    </div>
  );
};

const SocIntegrations = () => {
  const queryClient = useQueryClient();
  const listQ = useQuery('integrations', () => api.get('/integrations/').then((r) => r.data));
  const typesQ = useQuery('integrationTypes', () => api.get('/integrations/types').then((r) => r.data));
  const [health, setHealth] = useState(null);
  const [tests, setTests] = useState({});

  const useRun = (fn, ok) => useMutation(fn, {
    onSuccess: (data) => {
      ok?.(data);
      queryClient.invalidateQueries('integrations');
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const connect = useRun(() => api.post('/integrations/connect').then((r) => r.data),
    (d) => toast.success(`Connected ${d.summary?.successful_connections ?? 0}/${d.summary?.total_integrations ?? 0}`));
  const disconnect = useRun(() => api.post('/integrations/disconnect').then((r) => r.data), () => toast.success('Disconnected'));
  const check = useRun(() => api.get('/integrations/health').then((r) => r.data), setHealth);
  const test = useRun((name) => api.post(`/integrations/${name}/test`).then((r) => r.data),
    (d) => setTests((t) => ({ ...t, [d.integration_name]: d })));

  const entries = Object.entries(listQ.data?.integrations || {});
  const types = Object.keys(typesQ.data || {});

  return (
    <div className="panel">
      <PanelHead title={`Configured SOC integrations · ${listQ.data?.summary?.total_active ?? 0}/${listQ.data?.summary?.total_configured ?? 0} active`}>
        <TextButton onClick={() => connect.mutate()} disabled={connect.isLoading || !entries.length}>Connect all</TextButton>
        <TextButton onClick={() => disconnect.mutate()} disabled={disconnect.isLoading || !entries.length}>Disconnect all</TextButton>
        <TextButton onClick={() => check.mutate()} disabled={check.isLoading}>Health check</TextButton>
      </PanelHead>
      {listQ.error ? <div className="p-4"><ErrorNote error={listQ.error} what="integrations" /></div>
        : entries.length === 0 ? (
          <div className="px-4 py-6 space-y-3 text-sm text-inksoft">
            <p>No integrations configured. Investigations still run fully; response actions are planned but have nowhere to go.</p>
            <p>
              Set <span className="num">INTEGRATIONS_CONFIG</span> to JSON with an <span className="num">integrations</span> object keyed by type, then restart the API:
            </p>
            <pre className="border border-rule bg-paper px-3 py-2 num text-[11px] overflow-auto">{`INTEGRATIONS_CONFIG='{"integrations":{"slack":{"webhook_url":"https://hooks.slack.com/services/..."}}}'`}</pre>
            {types.length > 0 && (
              <p className="flex flex-wrap items-center gap-1">
                <span className="label mr-1">Available types</span>
                {types.map((t) => <Chip key={t}>{t}</Chip>)}
              </p>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto scrollbar-thin">
            <table className="data-table">
              <thead><tr><th>Name</th><th>Type</th><th>State</th><th>Actions</th><th>Health</th><th /></tr></thead>
              <tbody>
                {entries.map(([name, info]) => {
                  const h = health?.health_results?.[name];
                  const t = tests[name];
                  return (
                    <tr key={name}>
                      <td className="num text-sm">{name}</td>
                      <td className="num text-xs">{info.type}</td>
                      <td><StatusBadge status={info.connected ? 'success' : 'pending'} /></td>
                      <td><span className="flex flex-wrap gap-1">{(info.supported_actions || []).map((a) => <Chip key={a}>{a}</Chip>)}</span></td>
                      <td className="num text-xs">
                        {h === undefined ? '—' : h ? <span className="text-low">healthy</span> : <span className="text-critical">unhealthy</span>}
                        {t && <span className="block text-[10px] text-muted">test: {JSON.stringify(t.test_result).slice(0, 60)}</span>}
                      </td>
                      <td className="text-right"><TextButton onClick={() => test.mutate(name)} disabled={test.isLoading}>Test</TextButton></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      {health && (
        <p className="px-4 py-2 border-t border-rule num text-[11px] text-muted">
          {health.healthy_integrations}/{health.total_integrations} healthy · checked {fmtTime(health.checked_at)}
        </p>
      )}
    </div>
  );
};

const ExecuteAction = () => {
  const { executeAction } = useThreatSentinel();
  const actionsQ = useQuery('actionTypes', () => api.get('/integrations/actions').then((r) => r.data));
  const actions = actionsQ.data || [];
  const [form, setForm] = useState({ action_type: '', target: '', context: '' });
  const [result, setResult] = useState(null);
  const [ctxError, setCtxError] = useState(null);

  const submit = (e) => {
    e.preventDefault();
    let context = {};
    if (form.context.trim()) {
      try {
        context = JSON.parse(form.context);
        if (!context || typeof context !== 'object' || Array.isArray(context)) throw new Error('not an object');
      } catch {
        setCtxError('Context must be a JSON object');
        return;
      }
    }
    setCtxError(null);
    executeAction.mutate(
      { action_type: form.action_type || actions[0], target: form.target.trim(), context },
      { onSuccess: setResult }
    );
  };

  const er = result?.execution_result;
  return (
    <div className="panel">
      <PanelHead title="Execute response action" />
      <form onSubmit={submit} className="px-4 py-4 space-y-4">
        <p className="text-xs text-high">Mutating: this calls your configured integrations directly. Every execution is audit-logged.</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <Field label="Action type">
            <select className="input-field w-full" value={form.action_type || actions[0] || ''} onChange={(e) => setForm({ ...form, action_type: e.target.value })}>
              {actions.map((a) => <option key={a} value={a}>{a}</option>)}
            </select>
          </Field>
          <Field label="Target">
            <input required maxLength={2048} className="input-field w-full" placeholder="203.0.113.10 / domain / incident id" value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })} />
          </Field>
        </div>
        <Field label="Context (JSON, optional)">
          <textarea className="input-field w-full h-20" spellCheck={false} placeholder='{"reason": "confirmed brute force", "investigation_id": "inv_..."}' value={form.context} onChange={(e) => setForm({ ...form, context: e.target.value })} />
        </Field>
        {ctxError && <p className="font-mono text-xs text-critical">{ctxError}</p>}
        <div className="flex justify-end">
          <button type="submit" className="btn-danger" disabled={executeAction.isLoading || !form.target.trim() || !actions.length}>
            {executeAction.isLoading ? 'Executing…' : 'Execute'}
          </button>
        </div>
      </form>
      {er && (
        <div className="border-t border-rule">
          <Readout rows={[
            ['Result', <StatusBadge key="s" status={er.success ? 'success' : 'failed'} />],
            ['Actions', `${er.successful_actions}/${er.actions_executed} succeeded`],
            ['Time', `${fmtNum(er.total_execution_time, 3)} s`],
            ...(er.error_details ? [['Error', er.error_details]] : []),
          ]} />
          {(result.details || []).length > 0 && (
            <table className="data-table border-t border-rule">
              <thead><tr><th>Action</th><th>Target</th><th>OK</th><th>Ref</th><th>Error</th></tr></thead>
              <tbody>
                {result.details.map((d, i) => (
                  <tr key={i}>
                    <td className="num text-xs">{d.action_type}</td>
                    <td className="num text-xs">{d.target}</td>
                    <td><StatusBadge status={d.success ? 'success' : 'failed'} /></td>
                    <td className="num text-xs">{d.reference_id || '—'}</td>
                    <td className="text-xs text-critical">{d.error_message || ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
};

const Integrations = () => (
  <div className="space-y-6">
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 items-start">
      <ToolEnvironment />
      <div className="space-y-6">
        <SocIntegrations />
        <ExecuteAction />
      </div>
    </div>
  </div>
);

export default Integrations;
