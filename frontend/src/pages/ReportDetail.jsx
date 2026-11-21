import React, { useMemo } from 'react';
import { useQuery } from 'react-query';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import toast from 'react-hot-toast';
import { api } from '../context/ThreatSentinelContext';
import { ErrorNote, Loading, errorMessage } from '../components/ui';
import { downloadReport } from './Reports';

const TABS = [['json', 'JSON'], ['md', 'Markdown'], ['html', 'HTML'], ['stix', 'STIX 2.1']];

const investigationFromReport = (id) => {
  const parts = String(id).split('_');
  return id.startsWith('rpt_') && parts.length > 3 ? parts.slice(3).join('_') : null;
};

const ReportDetail = () => {
  const { id } = useParams();
  const [params, setParams] = useSearchParams();
  const format = TABS.some(([f]) => f === params.get('format')) ? params.get('format') : 'json';
  const investigationId = investigationFromReport(id);

  const { data: content, isLoading, error } = useQuery(['report', id, format],
    () => api.get(`/reports/${id}`, { params: { format }, responseType: 'text', transformResponse: (d) => d })
      .then((r) => r.data));

  const pretty = useMemo(() => {
    if (content == null) return '';
    if (format === 'json' || format === 'stix') {
      try { return JSON.stringify(JSON.parse(content), null, 2); } catch { return content; }
    }
    return content;
  }, [content, format]);

  const copy = () => navigator.clipboard.writeText(pretty).then(
    () => toast.success('Copied'), () => toast.error('Clipboard unavailable'));
  const download = () => downloadReport(id, format).catch((e) => toast.error(`Download failed: ${errorMessage(e)}`));

  return (
    <div className="space-y-6">
      <div className="panel">
        <div className="px-4 py-4 flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="label"><Link to="/reports" className="hover:text-ink">Reports</Link> /</p>
            <h2 className="num text-lg mt-1 break-all">{id}</h2>
            {investigationId && (
              <Link to={`/investigations/${investigationId}`} className="num text-xs text-signal hover:underline">
                investigation {investigationId}
              </Link>
            )}
          </div>
          <div className="flex gap-2">
            <button type="button" className="btn-secondary" onClick={copy} disabled={!content}>Copy</button>
            <button type="button" className="btn-primary" onClick={download} disabled={!content}>Download</button>
          </div>
        </div>
        <div className="border-t border-rule flex">
          {TABS.map(([f, label]) => (
            <button key={f} type="button" onClick={() => setParams({ format: f }, { replace: true })}
              className={`px-4 py-2 font-mono text-xs uppercase tracking-[0.1em] border-r border-rule ${format === f ? 'bg-ink text-paper' : 'text-inksoft hover:bg-paper'}`}>
              {label}
            </button>
          ))}
        </div>
      </div>

      {isLoading ? <Loading what="report" />
        : error ? (
          error?.response?.status === 404
            ? <div className="panel px-4 py-6 text-sm text-inksoft">No <span className="num">{format}</span> file stored for this report. Try another tab.</div>
            : <ErrorNote error={error} what="report" />
        )
        : format === 'html' ? (
          // Empty sandbox: no scripts, no same-origin, no forms, no top navigation
          <div className="panel">
            <iframe title={`Report ${id}`} sandbox="" srcDoc={content} className="w-full h-[75vh] bg-panel" referrerPolicy="no-referrer" />
          </div>
        ) : (
          <div className="panel">
            <pre className={`px-4 py-4 text-xs leading-relaxed overflow-auto max-h-[75vh] scrollbar-thin ${format === 'md' ? 'font-mono whitespace-pre-wrap text-ink' : 'num text-inksoft'}`}>
              {pretty}
            </pre>
          </div>
        )}
    </div>
  );
};

export default ReportDetail;
