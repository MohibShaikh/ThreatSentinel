import React, { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useThreatSentinel } from '../../context/ThreatSentinelContext';
import AuthModal from './AuthModal';

// One flat level. Every page loads on its own from its URL.
const navigation = [
  { name: 'Overview', href: '/' },
  { name: 'Investigations', href: '/investigations' },
  { name: 'Reports', href: '/reports' },
  { name: 'Monitoring', href: '/monitoring' },
  { name: 'Integrations', href: '/integrations' },
  { name: 'Tasks', href: '/tasks' },
  { name: 'Audit', href: '/audit' },
];

const Clock = () => {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return <span className="num text-xs text-inksoft">{now.toISOString().slice(11, 19)} UTC</span>;
};

const CountBadge = ({ value, active, tone, title }) =>
  value > 0 ? (
    <span
      title={title}
      className={`num text-[10px] px-1 border ${active ? 'border-paper/40 text-paper' : tone || 'border-rulehard text-inksoft'}`}
    >
      {value}
    </span>
  ) : null;

const Layout = ({ children }) => {
  const location = useLocation();
  const {
    systemStatus, activeInvestigations, pendingTasks, pendingReviews, llmProvider, hasToken, openAuthModal,
  } = useThreatSentinel();

  const isActive = (href) => (href === '/' ? location.pathname === '/' : location.pathname.startsWith(href));
  const current = navigation.find((item) => isActive(item.href));

  const healthTone =
    systemStatus === 'healthy' ? 'text-low' :
    systemStatus === 'error' || systemStatus === 'unhealthy' ? 'text-critical' : 'text-muted';

  const badges = (name, active) => {
    if (name === 'Investigations') {
      return (
        <span className="ml-auto flex gap-1">
          <CountBadge value={pendingReviews} active={active} tone="border-high/50 text-high" title="Pending human review" />
          <CountBadge value={activeInvestigations} active={active} title="Active investigations" />
        </span>
      );
    }
    if (name === 'Tasks') {
      return <span className="ml-auto"><CountBadge value={pendingTasks} active={active} title="Pending tasks" /></span>;
    }
    return null;
  };

  return (
    <div className="min-h-screen flex">
      <aside className="hidden lg:flex flex-col w-[236px] shrink-0 bg-panel border-r border-rule">
        <div className="px-5 pt-6 pb-5 border-b border-rule">
          <p className="display-xl text-[15px] uppercase leading-none">Threat<span className="text-signal">Sentinel</span></p>
          <p className="label mt-2">SOC operations console</p>
        </div>

        <nav className="flex-1 py-3">
          {navigation.map((item, i) => {
            const active = isActive(item.href);
            return (
              <Link
                key={item.name}
                to={item.href}
                className={`flex items-baseline gap-3 px-5 py-2.5 text-sm transition-colors ${
                  active ? 'bg-ink text-paper' : 'text-inksoft hover:bg-ink/[0.04]'
                }`}
              >
                <span className={`num text-[10px] ${active ? 'text-paper/60' : 'text-muted'}`}>
                  {String(i + 1).padStart(2, '0')}
                </span>
                <span className="font-medium">{item.name}</span>
                {badges(item.name, active)}
              </Link>
            );
          })}
        </nav>

        <div className="px-5 py-4 border-t border-rule space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="label">System</span>
            <span className={`flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.12em] ${healthTone}`}>
              <span className="w-1.5 h-1.5 blink bg-current" />
              {systemStatus === 'healthy' ? 'Nominal' : systemStatus || 'Unknown'}
            </span>
          </div>
          <div className="flex items-center justify-between gap-2">
            <span className="label">LLM</span>
            <span className="num text-[10px] text-inksoft truncate" title={llmProvider || 'No LLM configured'}>
              {llmProvider || 'offline'}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span className="label">Time</span>
            <Clock />
          </div>
        </div>
      </aside>

      <div className="flex-1 min-w-0 flex flex-col">
        <header className="flex items-center justify-between gap-4 border-b border-rule bg-panel px-6 lg:px-8 py-3.5">
          <h1 className="display-xl text-lg uppercase">{current?.name || 'ThreatSentinel'}</h1>
          <div className="flex items-center gap-4">
            <span className="label hidden md:inline">v2.1.0</span>
            {pendingReviews > 0 && (
              <Link to="/investigations?status=pending_human_review" className="status-badge status-high hidden sm:inline-flex">
                {pendingReviews} awaiting review
              </Link>
            )}
            <button type="button" onClick={openAuthModal} className="btn-secondary">
              <span className={`inline-block w-1.5 h-1.5 mr-2 align-middle ${hasToken ? 'bg-signal' : 'bg-rulehard'}`} />
              Session / Token
            </button>
            <Link to="/investigations?new=1" className="btn-primary">New investigation</Link>
          </div>
        </header>

        <nav className="lg:hidden flex overflow-x-auto border-b border-rule bg-panel scrollbar-thin">
          {navigation.map((item) => (
            <Link
              key={item.name}
              to={item.href}
              className={`shrink-0 px-4 py-2.5 text-sm border-r border-rule ${
                isActive(item.href) ? 'bg-ink text-paper' : 'text-inksoft'
              }`}
            >
              {item.name}
            </Link>
          ))}
        </nav>

        <main className="flex-1 px-6 lg:px-8 py-7 max-w-[1400px] w-full mx-auto">{children}</main>
      </div>
      <AuthModal />
    </div>
  );
};

export default Layout;
