import React, { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from 'react-query';
import { Link, useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { api, useThreatSentinel } from '../context/ThreatSentinelContext';
import {
  Empty, ErrorNote, FORMAT_TO_EXT, PanelHead, Toggle, errorMessage, fmtBytes, fmtTime, saveBlob,
} from '../components/ui';

const FILTERS = ['all', 'json', 'md', 'html', 'stix'];

export async function downloadReport(reportId, format) {
  // Fetched through axios so the Bearer header is sent; a plain <a href> would not authenticate
  const res = await api.get(`/reports/${reportId}/download`, { params: format ? { format } : {}, responseType: 'blob' });
  saveBlob(res.data, `${reportId}.${format || 'json'}`);
}

const Reports = () => {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { generateReport } = useThreatSentinel();
  const [filter, setFilter] = useState('all');
  const [gen, setGen] = useState({ investigation_id: '', format: 'json', include_raw_data: false });

  const { data, isLoading, error } = useQuery(['reports', 'list', filter],
    () => api.get('/reports/', { params: { limit: 200, ...(filter !== 'all' ? { format: filter } : {}) } }).then((r) => r.data),
    { refetchInterval: 30000 });

  const invQ = useQuery(['investigations', 'reportable'],
    () => api.get('/investigations/', { params: { limit: 50 } }).then((r) => r.data));
  const reportable = (invQ.data?.investigations || []).filter((i) => ['completed', 'pending_human_review'].includes(i.status));

  const remove = useMutation((id) => api.delete(`/reports/${id}`), {
    onSuccess: () => {
      toast.success('Report deleted');
      queryClient.invalidateQueries('reports');
    },
    onError: (e) => toast.error(`Delete failed: ${errorMessage(e)}`),
  });

  const submit = (e) => {
    e.preventDefault();
    if (!gen.investigation_id) return;
    generateReport.mutate(gen, {
      onSuccess: (res) => {
        const ext = FORMAT_TO_EXT[gen.format];
        if (res.file_path) navigate(`/reports/${res.report_id}?format=${ext}`);
        else if (res.content) saveBlob(new Blob([res.content]), `${res.report_id}.${ext}`);
      },
    });
  };

  const download = (r) => downloadReport(r.report_id, r.format).catch((e) => toast.error(`Download failed: ${errorMessage(e)}`));
  const reports = data?.reports || [];

  return (
    <div className="space-y-6">
      <form onSubmit={submit} className="panel">
        <PanelHead title="Generate report" />
        <div className="px-4 py-3 flex flex-wrap items-end gap-3">
          <label className="flex-1 min-w-[260px]">
            <span className="label block mb-1.5">Investigation</span>
            <select className="input-field w-full" value={gen.investigation_id} onChange={(e) => setGen({ ...gen, investigation_id: e.target.value })}>
              <option value="">{reportable.length ? 'Select a finished investigation' : 'No finished investigations yet'}</option>
              {reportable.map((i) => (
                <option key={i.investigation_id} value={i.investigation_id}>
                  {i.investigation_id} · {i.title || i.event_type} · {i.risk_level || '?'}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span className="label block mb-1.5">Format</span>
            <select className="input-field" value={gen.format} onChange={(e) => setGen({ ...gen, format: e.target.value })}>
              <option value="json">json</option>
              <option value="markdown">markdown</option>
              <option value="html">html (sanitized)</option>
              <option value="stix">stix 2.1</option>
            </select>
          </label>
          <div className="pb-2"><Toggle checked={gen.include_raw_data} onChange={(v) => setGen({ ...gen, include_raw_data: v })}>Include raw</Toggle></div>
          <button type="submit" className="btn-primary" disabled={!gen.investigation_id || generateReport.isLoading}>
            {generateReport.isLoading ? 'Generating…' : 'Generate'}
          </button>
        </div>
      </form>

      <div className="panel">
        <PanelHead title={`Stored reports · ${data?.total_count ?? '—'}`}>
          <div className="flex gap-px bg-rule border border-rule">
            {FILTERS.map((f) => (
              <button key={f} type="button" onClick={() => setFilter(f)}
                className={`px-2.5 py-1 font-mono text-[11px] uppercase ${filter === f ? 'bg-ink text-paper' : 'bg-panel text-inksoft hover:bg-paper'}`}>
                {f}
              </button>
            ))}
          </div>
        </PanelHead>
        {error ? <div className="p-4"><ErrorNote error={error} what="reports" /></div>
          : isLoading ? <Empty>Loading…</Empty>
          : reports.length === 0 ? <Empty>No reports stored. Generate one above or from an investigation.</Empty>
          : (
            <div className="overflow-x-auto scrollbar-thin">
              <table className="data-table">
                <thead><tr><th>Report</th><th>Investigation</th><th>Format</th><th>Size</th><th>Created</th><th /></tr></thead>
                <tbody>
                  {reports.map((r) => (
                    <tr key={r.file_name}>
                      <td className="num text-xs">
                        <Link to={`/reports/${r.report_id}?format=${r.format}`} className="hover:text-signal hover:underline">{r.report_id}</Link>
                      </td>
                      <td className="num text-xs">
                        {r.investigation_id && r.investigation_id !== 'unknown'
                          ? <Link to={`/investigations/${r.investigation_id}`} className="hover:text-signal hover:underline">{r.investigation_id}</Link>
                          : '—'}
                      </td>
                      <td><span className="status-badge status-info">{r.format}</span></td>
                      <td className="num text-xs">{fmtBytes(r.file_size)}</td>
                      <td className="num text-xs text-muted whitespace-nowrap">{fmtTime(r.created_at)}</td>
                      <td className="text-right whitespace-nowrap space-x-3">
                        <Link to={`/reports/${r.report_id}?format=${r.format}`} className="font-mono text-[11px] uppercase text-signal hover:underline">View</Link>
                        <button type="button" onClick={() => download(r)} className="font-mono text-[11px] uppercase text-signal hover:underline">Download</button>
                        <button type="button" disabled={remove.isLoading}
                          onClick={() => window.confirm(`Delete every file of ${r.report_id}?`) && remove.mutate(r.report_id)}
                          className="font-mono text-[11px] uppercase text-critical hover:underline">Delete</button>
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

export default Reports;
