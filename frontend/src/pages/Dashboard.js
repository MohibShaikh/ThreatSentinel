import React from 'react';
import { useQuery } from 'react-query';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  TrendingUp, 
  Activity,
  Search,
  FileText,
  Settings,
  Zap
} from 'lucide-react';
import { useThreatSentinel } from '../context/ThreatSentinelContext';
import { api } from '../context/ThreatSentinelContext';
import MetricCard from '../components/Dashboard/MetricCard';
import RecentInvestigations from '../components/Dashboard/RecentInvestigations';
import ThreatActivityChart from '../components/Dashboard/ThreatActivityChart';
import QuickActions from '../components/Dashboard/QuickActions';
import SystemStatus from '../components/Dashboard/SystemStatus';

const Dashboard = () => {
  const { systemStatus, activeInvestigations, pendingTasks } = useThreatSentinel();

  // Fetch dashboard data
  const { data: dashboardData, isLoading } = useQuery(
    'dashboardData',
    async () => {
      const [investigations, reports, metrics] = await Promise.all([
        api.get('/investigations/').then(res => res.data),
        api.get('/reports/').then(res => res.data),
        api.get('/monitoring/metrics').then(res => res.data),
      ]);
      return { investigations, reports, metrics };
    },
    {
      refetchInterval: 30000, // Refresh every 30 seconds
    }
  );

  const metrics = [
    {
      title: 'Active Investigations',
      value: activeInvestigations,
      change: '+12%',
      changeType: 'positive',
      icon: Search,
      color: 'primary',
    },
    {
      title: 'Pending Tasks',
      value: pendingTasks,
      change: '-5%',
      changeType: 'negative',
      icon: Clock,
      color: 'warning',
    },
    {
      title: 'Threats Blocked',
      value: dashboardData?.metrics?.threats_blocked || 0,
      change: '+8%',
      changeType: 'positive',
      icon: Shield,
      color: 'success',
    },
    {
      title: 'System Health',
      value: systemStatus === 'healthy' ? 'Operational' : 'Warning',
      change: systemStatus === 'healthy' ? 'Stable' : 'Issues Detected',
      changeType: systemStatus === 'healthy' ? 'positive' : 'negative',
      icon: Activity,
      color: systemStatus === 'healthy' ? 'success' : 'danger',
    },
  ];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Operations Dashboard</h1>
          <p className="text-gray-400 mt-1">Real-time threat monitoring and response</p>
        </div>
        <div className="flex items-center space-x-3">
          <span className="text-sm text-gray-400">Last updated: {new Date().toLocaleTimeString()}</span>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {metrics.map((metric, index) => (
          <MetricCard key={index} {...metric} />
        ))}
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column */}
        <div className="lg:col-span-2 space-y-6">
          {/* Threat Activity Chart */}
          <div className="card p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white">Threat Activity (24h)</h2>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-primary-500 rounded-full"></div>
                <span className="text-sm text-gray-400">Threats Detected</span>
              </div>
            </div>
            <ThreatActivityChart data={dashboardData?.metrics?.threat_activity || []} />
          </div>

          {/* Recent Investigations */}
          <div className="card p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white">Recent Investigations</h2>
              <button className="text-sm text-primary-400 hover:text-primary-300">
                View All
              </button>
            </div>
            <RecentInvestigations investigations={dashboardData?.investigations || []} />
          </div>
        </div>

        {/* Right Column */}
        <div className="space-y-6">
          {/* Quick Actions */}
          <QuickActions />

          {/* System Status */}
          <SystemStatus />

          {/* Recent Reports */}
          <div className="card p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white">Recent Reports</h2>
              <button className="text-sm text-primary-400 hover:text-primary-300">
                View All
              </button>
            </div>
            <div className="space-y-3">
              {dashboardData?.reports?.slice(0, 5).map((report, index) => (
                <div key={index} className="flex items-center space-x-3 p-3 bg-dark-700 rounded-lg">
                  <FileText className="w-5 h-5 text-gray-400" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-white truncate">
                      {report.title || `Report ${report.id}`}
                    </p>
                    <p className="text-xs text-gray-400">
                      {new Date(report.created_at).toLocaleDateString()}
                    </p>
                  </div>
                  <span className={`status-badge ${
                    report.status === 'completed' ? 'status-success' :
                    report.status === 'pending' ? 'status-warning' :
                    'status-info'
                  }`}>
                    {report.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard; 