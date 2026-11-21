import React, { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from 'react-query';
import { Link } from 'react-router-dom';
import toast from 'react-hot-toast';
import { api } from '../context/ThreatSentinelContext';
import { ALL_EVENT_TYPES } from '../components/Investigations/InvestigationForm';
import {
  Empty, ErrorNote, Field, PanelHead, StatCell, StatStrip, StatusBadge, Toggle, errorMessage, fmtTime, riskClass,
} from '../components/ui';

const PRIORITIES = ['low', 'medium', 'high', 'critical', 'emergency'];
const CANCELLABLE = new Set(['pending', 'retrying', 'in_progress']);
const priorityClass = (p) => (p === 'emergency' ? 'status-critical' : riskClass(p));

const Tasks = () => {
  const queryClient = useQueryClient();
  const [form, setForm] = useState({
    event_type: 'suspicious_ip', title: '', source_ip: '', payload: '', priority: 'medium', emergency_mode: false,
  });
  const [payloadError, setPayloadError] = useState(null);

  const statsQ = useQuery(['tasks', 'stats'], () => api.get('/tasks/').then((r) => r.data), { refetchInterval: 5000 });
  const itemsQ = useQuery(['tasks', 'items'],
    () => api.get('/tasks/items', { params: { limit: 100 } }).then((r) => r.data).catch((e) => {
      if (e?.response?.status === 404) return null;
      throw e;
    }),
    { refetchInterval: 5000 });

  const invalidate = () => {
    queryClient.invalidateQueries('tasks');
    queryClient.invalidateQueries('agentStats');
  };
  const control = useMutation((path) => api.post(`/tasks/queue/${path}`).then((r) => r.data), {
    onSuccess: (d) => { toast.success(d.message); invalidate(); },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const cancel = useMutation((id) => api.delete(`/tasks/${id}`).then((r) => r.data), {
    onSuccess: (d) => { toast.success(d.message); invalidate(); },
    onError: (e) => toast.error(`Cancel failed: ${errorMessage(e)}`),
  });
  const enqueue = useMutation((body) => api.post('/tasks/investigations/', body).then((r) => r.data), {
    onSuccess: (t) => { toast.success(`Enqueued ${t.id}`); invalidate(); },
    onError: (e) => toast.error(`Enqueue failed: ${errorMessage(e)}`),
  });

  const submit = (e) => {
    e.preventDefault();
    const eventData = { event_type: form.event_type };
    if (form.title.trim()) eventData.title = form.title.trim();
    if (form.source_ip.trim()) eventData.source_ip = form.source_ip.trim();
    if (form.payload.trim()) {
      try {
        eventData.payload = JSON.parse(form.payload);
      } catch {
        setPayloadError('Payload must be valid JSON');
        return;
      }
    }
    setPayloadError(null);
    enqueue.mutate({
      task_type: 'investigation',
      payload: { event_data: eventData, emergency_mode: form.emergency_mode },
      priority: form.priority,
    });
  };

  const s = statsQ.data || {};
  const items = Array.isArray(itemsQ.data) ? itemsQ.data : itemsQ.data?.tasks || itemsQ.data?.items || [];
  const counts = s.status_counts || {};

  return (
    <div className="space-y-6">
      {statsQ.error && <ErrorNote error={statsQ.error} what="queue stats" />}
      <StatStrip>
        <StatCell label="Pending" value={s.pending_tasks ?? '—'} />
        <StatCell label="Active" value={s.active_tasks ?? '—'} />
        <StatCell label="Workers" value={s.max_workers !== undefined ? `${s.workers_running}/${s.max_workers}` : '—'}
          tone={s.max_workers && s.workers_running === 0 ? 'text-critical' : 'text-ink'} />
        <StatCell label="Completed" value={counts.completed ?? 0} />
        <StatCell label="Failed" value={counts.failed ?? 0} tone={(counts.failed || 0) > 0 ? 'text-critical' : 'text-ink'} />
      </StatStrip>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 items-start">
        <div className="panel">
          <PanelHead title="Worker controls" />
          <div className="px-4 py-4 flex flex-wrap gap-2">
            <button type="button" className="btn-primary" disabled={control.isLoading} onClick={() => control.mutate('start')}>Start workers</button>
            <button type="button" className="btn-secondary" disabled={control.isLoading} onClick={() => control.mutate('stop')}>Stop workers</button>
            <button type="button" className="btn-secondary" disabled={control.isLoading} onClick={() => control.mutate('cleanup')}>Cleanup old</button>
          </div>
          <p className="px-4 pb-4 text-xs text-muted">Cleanup removes finished tasks older than 30 days. Retries back off exponentially.</p>
          {Object.keys(s.task_type_counts || {}).length > 0 && (
            <div className="border-t border-rule px-4 py-2 num text-xs text-inksoft">
              {Object.entries(s.task_type_counts).map(([k, v]) => `${k}: ${v}`).join('  ·  ')}
            </div>
          )}
        </div>

        <form onSubmit={submit} className="panel xl:col-span-2">
          <PanelHead title="Enqueue investigation task" />
          <div className="px-4 py-4 grid grid-cols-1 md:grid-cols-3 gap-4">
            <Field label="Event type">
              <select className="input-field w-full" value={form.event_type} onChange={(e) => setForm({ ...form, event_type: e.target.value })}>
                {ALL_EVENT_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
            </Field>
            <Field label="Priority">
              <select className="input-field w-full" value={form.priority} onChange={(e) => setForm({ ...form, priority: e.target.value })}>
                {PRIORITIES.map((p) => <option key={p} value={p}>{p}</option>)}
              </select>
            </Field>
            <Field label="Source IP / target">
              <input className="input-field w-full" value={form.source_ip} onChange={(e) => setForm({ ...form, source_ip: e.target.value })} placeholder="203.0.113.10" />
            </Field>
            <div className="md:col-span-3">
              <Field label="Title">
                <input className="input-field w-full" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
              </Field>
            </div>
            <div className="md:col-span-3">
              <Field label="Payload (JSON, optional)">
                <textarea className="input-field w-full h-20" spellCheck={false} value={form.payload} onChange={(e) => setForm({ ...form, payload: e.target.value })} placeholder='{"failed_login_attempts": 40}' />
              </Field>
              {payloadError && <p className="mt-1 font-mono text-xs text-critical">{payloadError}</p>}
            </div>
            <div className="md:col-span-3 flex flex-wrap items-center justify-between gap-3">
              <Toggle checked={form.emergency_mode} onChange={(v) => setForm({ ...form, emergency_mode: v })}>Emergency mode</Toggle>
              <button type="submit" className="btn-primary" disabled={enqueue.isLoading}>{enqueue.isLoading ? 'Enqueuing…' : 'Enqueue'}</button>
            </div>
          </div>
        </form>
      </div>

      <div className="panel">
        <PanelHead title={`Tasks · ${items.length}`} />
        {itemsQ.error ? <div className="p-4"><ErrorNote error={itemsQ.error} what="tasks" /></div>
          : itemsQ.data === null ? <Empty>This API version does not list tasks (GET /api/v1/tasks/items). Queue stats above are live.</Empty>
          : items.length === 0 ? <Empty>No tasks in the queue.</Empty>
          : (
            <div className="overflow-x-auto scrollbar-thin">
              <table className="data-table">
                <thead><tr><th>ID</th><th>Type</th><th>Priority</th><th>Status</th><th>Retries</th><th>Next retry</th><th>Created</th><th>Result</th><th /></tr></thead>
                <tbody>
                  {items.map((t) => (
                    <tr key={t.id}>
                      <td className="num text-xs">{t.id}</td>
                      <td className="num text-xs">{t.task_type}</td>
                      <td><span className={`status-badge ${priorityClass(t.priority)}`}>{t.priority}</span></td>
                      <td><StatusBadge status={t.status} /></td>
                      <td className="num text-xs">{t.retry_count}/{t.max_retries}</td>
                      <td className="num text-xs text-muted">{t.next_retry_at ? fmtTime(t.next_retry_at) : '—'}</td>
                      <td className="num text-xs text-muted whitespace-nowrap">{fmtTime(t.created_at)}</td>
                      <td className="text-xs max-w-[240px]">
                        {t.result?.investigation_id
                          ? <Link to={`/investigations/${t.result.investigation_id}`} className="num text-signal hover:underline">{t.result.investigation_id}</Link>
                          : <span className="text-critical truncate block" title={t.error_message || ''}>{t.error_message || ''}</span>}
                      </td>
                      <td className="text-right">
                        {CANCELLABLE.has(t.status) && (
                          <button type="button" disabled={cancel.isLoading} onClick={() => cancel.mutate(t.id)}
                            className="font-mono text-[11px] uppercase text-critical hover:underline">Cancel</button>
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

export default Tasks;
