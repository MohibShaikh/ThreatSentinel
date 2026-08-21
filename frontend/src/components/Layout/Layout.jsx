import React, { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useThreatSentinel } from '../../context/ThreatSentinelContext';

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
  return (
    <span className="num text-xs text-inksoft">
      {now.toISOString().slice(11, 19)} UTC
    </span>
  );
};

const Layout = ({ children }) => {
  const location = useLocation();
  const { systemStatus, activeInvestigations, pendingTasks } = useThreatSentinel();

  const isActive = (href) =>
    href === '/' ? location.pathname === '/' : location.pathname.startsWith(href);

  const current = navigation.find((item) => isActive(item.href));

  const healthTone =
    systemStatus === 'healthy' ? 'text-low' :
    systemStatus === 'warning' ? 'text-high' :
    systemStatus === 'error' ? 'text-critical' : 'text-muted';

  return (
    <div className="min-h-screen flex">
      {/* Left rail */}
      <aside className="hidden lg:flex flex-col w-[236px] shrink-0 bg-panel border-r border-rule">
        <div className="px-5 pt-6 pb-5 border-b border-rule">
          <p className="display-xl text-[15px] uppercase leading-none">Threat<span className="text-signal">Sentinel</span></p>
          <p className="label mt-2">SOC operations console</p>
        </div>

        <nav className="flex-1 py-3">
          {navigation.map((item, i) => (
            <Link
              key={item.name}
              to={item.href}
              className={`flex items-baseline gap-3 px-5 py-2.5 text-sm transition-colors ${
                isActive(item.href)
                  ? 'bg-ink text-paper'
                  : 'text-inksoft hover:bg-ink/[0.04]'
              }`}
            >
              <span className={`num text-[10px] ${isActive(item.href) ? 'text-paper/60' : 'text-muted'}`}>
                {String(i + 1).padStart(2, '0')}
              </span>
              <span className="font-medium">{item.name}</span>
              {item.name === 'Investigations' && activeInvestigations > 0 && (
                <span className={`num ml-auto text-[10px] px-1 border ${
                  isActive(item.href) ? 'border-paper/40 text-paper' : 'border-rulehard text-inksoft'
                }`}>
                  {activeInvestigations}
                </span>
              )}
              {item.name === 'Tasks' && pendingTasks > 0 && (
                <span className={`num ml-auto text-[10px] px-1 border ${
                  isActive(item.href) ? 'border-paper/40 text-paper' : 'border-rulehard text-inksoft'
                }`}>
                  {pendingTasks}
                </span>
              )}
            </Link>
          ))}
        </nav>

        <div className="px-5 py-4 border-t border-rule space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="label">System</span>
            <span className={`flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.12em] ${healthTone}`}>
              <span className={`w-1.5 h-1.5 blink bg-current`} />
              {systemStatus === 'healthy' ? 'Nominal' : systemStatus || 'Unknown'}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span className="label">Time</span>
            <Clock />
          </div>
        </div>
      </aside>

      {/* Main column */}
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="flex items-center justify-between gap-4 border-b border-rule bg-panel px-6 lg:px-8 py-3.5">
          <h1 className="display-xl text-lg uppercase">{current?.name || 'Overview'}</h1>
          <div className="flex items-center gap-5">
            <span className="label hidden md:inline">v1.0.0</span>
            <Link to="/investigations" className="btn-primary">New investigation</Link>
          </div>
        </header>

        {/* Mobile nav */}
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

        <main className="flex-1 px-6 lg:px-8 py-7 max-w-[1400px] w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
};

export default Layout;
