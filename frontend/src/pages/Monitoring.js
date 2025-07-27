import React, { useState, useEffect } from 'react';
import { useQuery } from 'react-query';
import { 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  TrendingUp, 
  TrendingDown,
  RefreshCw,
  Bell,
  Settings,
  Download,
  Eye
} from 'lucide-react';
import { api } from '../context/ThreatSentinelContext';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';

const Monitoring = () => {
  const [selectedTimeRange, setSelectedTimeRange] = useState('24h');
  const [autoRefresh, setAutoRefresh] = useState(true);

  const { data: metrics, isLoading, refetch } = useQuery(
    ['monitoring', selectedTimeRange],
    async () => {
      const response = await api.get(`/monitoring/metrics?range=${selectedTimeRange}`);
      return response.data;
    },
    {
      refetchInterval: autoRefresh ? 30000 : false,
    }
  );

  const { data: alerts } = useQuery(
    'alerts',
    async () => {
      const response = await api.get('/monitoring/alerts/recent');
      return response.data;
    },
    {
      refetchInterval: autoRefresh ? 10000 : false,
    }
  );

  const timeRanges = [
    { value: '1h', label: '1 Hour' },
    { value: '24h', label: '24 Hours' },
    { value: '7d', label: '7 Days' },
    { value: '30d', label: '30 Days' },
  ];

  const systemMetrics = [
    {
      name: 'CPU Usage',
      value: metrics?.cpu_usage || '0%',
      trend: 'stable',
      status: 'healthy',
      color: 'text-blue-400'
    },
    {
      name: 'Memory Usage',
      value: metrics?.memory_usage || '0%',
      trend: 'increasing',
      status: 'warning',
      color: 'text-yellow-400'
    },
    {
      name: 'Disk Usage',
      value: metrics?.disk_usage || '0%',
      trend: 'stable',
      status: 'healthy',
      color: 'text-green-400'
    },
    {
      name: 'Network I/O',
      value: metrics?.network_io || '0 MB/s',
      trend: 'decreasing',
      status: 'healthy',
      color: 'text-purple-400'
    }
  ];

  const getTrendIcon = (trend) => {
    switch (trend) {
      case 'increasing':
        return <TrendingUp className="w-4 h-4 text-warning-400" />;
      case 'decreasing':
        return <TrendingDown className="w-4 h-4 text-success-400" />;
      default:
        return <Activity className="w-4 h-4 text-gray-400" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'healthy':
        return 'text-success-400';
      case 'warning':
        return 'text-warning-400';
      case 'error':
        return 'text-danger-400';
      default:
        return 'text-gray-400';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">System Monitoring</h1>
          <p className="text-gray-400 mt-1">Real-time system health and performance metrics</p>
        </div>
        <div className="flex items-center space-x-4">
          <button
            onClick={() => refetch()}
            className="btn-secondary flex items-center space-x-2"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Refresh</span>
          </button>
          <button className="btn-primary flex items-center space-x-2">
            <Download className="w-4 h-4" />
            <span>Export Data</span>
          </button>
        </div>
      </div>

      {/* Controls */}
      <div className="card p-6">
        <div className="flex flex-col md:flex-row gap-4 items-center justify-between">
          <div className="flex items-center space-x-4">
            <label className="text-sm font-medium text-gray-300">Time Range:</label>
            <select
              value={selectedTimeRange}
              onChange={(e) => setSelectedTimeRange(e.target.value)}
              className="input-field"
            >
              {timeRanges.map(range => (
                <option key={range.value} value={range.value}>
                  {range.label}
                </option>
              ))}
            </select>
          </div>
          
          <div className="flex items-center space-x-4">
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                className="rounded border-gray-600 bg-dark-700 text-primary-500 focus:ring-primary-500"
              />
              <span className="text-sm text-gray-300">Auto Refresh</span>
            </label>
          </div>
        </div>
      </div>

      {/* System Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {systemMetrics.map((metric, index) => (
          <div key={index} className="card p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-400">{metric.name}</p>
                <p className="text-2xl font-bold text-white mt-1">{metric.value}</p>
                <div className="flex items-center mt-2">
                  {getTrendIcon(metric.trend)}
                  <span className={`text-sm font-medium ml-1 ${getStatusColor(metric.status)}`}>
                    {metric.trend}
                  </span>
                </div>
              </div>
              <div className={`p-3 rounded-lg bg-dark-700`}>
                <Activity className={`w-6 h-6 ${metric.color}`} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Performance Chart */}
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white">System Performance</h2>
            <Settings className="w-5 h-5 text-gray-400" />
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={metrics?.performance_data || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis 
                  dataKey="time" 
                  stroke="#9ca3af"
                  tick={{ fill: '#9ca3af', fontSize: 12 }}
                />
                <YAxis 
                  stroke="#9ca3af"
                  tick={{ fill: '#9ca3af', fontSize: 12 }}
                />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#1e293b', 
                    border: '1px solid #374151',
                    borderRadius: '8px'
                  }}
                />
                <Line 
                  type="monotone" 
                  dataKey="cpu" 
                  stroke="#3b82f6" 
                  strokeWidth={2}
                  name="CPU"
                />
                <Line 
                  type="monotone" 
                  dataKey="memory" 
                  stroke="#f59e0b" 
                  strokeWidth={2}
                  name="Memory"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Activity Chart */}
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white">Threat Activity</h2>
            <AlertTriangle className="w-5 h-5 text-warning-400" />
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={metrics?.threat_data || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis 
                  dataKey="hour" 
                  stroke="#9ca3af"
                  tick={{ fill: '#9ca3af', fontSize: 12 }}
                />
                <YAxis 
                  stroke="#9ca3af"
                  tick={{ fill: '#9ca3af', fontSize: 12 }}
                />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#1e293b', 
                    border: '1px solid #374151',
                    borderRadius: '8px'
                  }}
                />
                <Bar dataKey="threats" fill="#ef4444" name="Threats" />
                <Bar dataKey="blocked" fill="#22c55e" name="Blocked" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">Recent Alerts</h2>
          <Bell className="w-5 h-5 text-gray-400" />
        </div>
        
        <div className="space-y-3">
          {alerts?.slice(0, 10).map((alert, index) => (
            <div key={index} className="flex items-center space-x-4 p-4 bg-dark-700 rounded-lg border border-dark-600">
              <div className="flex-shrink-0">
                <AlertTriangle className="w-5 h-5 text-warning-400" />
              </div>
              
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-medium text-white truncate">
                    {alert.title || `Alert ${alert.id}`}
                  </h3>
                  <span className="text-xs text-gray-400">
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <p className="text-sm text-gray-400 mt-1">
                  {alert.description || 'No description available'}
                </p>
                <div className="flex items-center space-x-4 mt-2 text-xs text-gray-400">
                  <span>Severity: {alert.severity}</span>
                  <span>Type: {alert.type}</span>
                  {alert.source && <span>Source: {alert.source}</span>}
                </div>
              </div>
              
              <div className="flex items-center space-x-2">
                <button className="text-primary-400 hover:text-primary-300">
                  <Eye className="w-4 h-4" />
                </button>
                <button className="text-gray-400 hover:text-gray-300">
                  <Settings className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
          
          {(!alerts || alerts.length === 0) && (
            <div className="text-center py-8">
              <CheckCircle className="w-12 h-12 text-success-400 mx-auto mb-4" />
              <p className="text-gray-400">No recent alerts</p>
              <p className="text-sm text-gray-500 mt-1">System is running smoothly</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Monitoring; 