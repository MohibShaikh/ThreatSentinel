import React from 'react';
import { 
  Activity, 
  Cpu, 
  HardDrive, 
  Wifi, 
  CheckCircle, 
  AlertTriangle, 
  XCircle 
} from 'lucide-react';

const SystemStatus = () => {
  const systemMetrics = [
    {
      name: 'CPU Usage',
      value: '23%',
      status: 'healthy',
      icon: Cpu,
      trend: 'stable'
    },
    {
      name: 'Memory Usage',
      value: '67%',
      status: 'warning',
      icon: Activity,
      trend: 'increasing'
    },
    {
      name: 'Disk Space',
      value: '45%',
      status: 'healthy',
      icon: HardDrive,
      trend: 'stable'
    },
    {
      name: 'Network',
      value: 'Active',
      status: 'healthy',
      icon: Wifi,
      trend: 'stable'
    }
  ];

  const getStatusIcon = (status) => {
    switch (status) {
      case 'healthy':
        return <CheckCircle className="w-4 h-4 text-success-400" />;
      case 'warning':
        return <AlertTriangle className="w-4 h-4 text-warning-400" />;
      case 'error':
        return <XCircle className="w-4 h-4 text-danger-400" />;
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

  const getTrendColor = (trend) => {
    switch (trend) {
      case 'increasing':
        return 'text-warning-400';
      case 'decreasing':
        return 'text-success-400';
      case 'stable':
        return 'text-gray-400';
      default:
        return 'text-gray-400';
    }
  };

  return (
    <div className="card p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-white">System Status</h2>
        <div className="flex items-center space-x-2">
          <div className="w-2 h-2 bg-success-400 rounded-full animate-pulse"></div>
          <span className="text-sm text-success-400">Operational</span>
        </div>
      </div>
      
      <div className="space-y-4">
        {systemMetrics.map((metric, index) => (
          <div key={index} className="flex items-center justify-between p-3 bg-dark-700 rounded-lg">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-dark-600 rounded-lg">
                <metric.icon className="w-4 h-4 text-gray-400" />
              </div>
              <div>
                <p className="text-sm font-medium text-white">{metric.name}</p>
                <p className="text-xs text-gray-400">
                  Trend: <span className={getTrendColor(metric.trend)}>{metric.trend}</span>
                </p>
              </div>
            </div>
            
            <div className="flex items-center space-x-2">
              <span className="text-sm font-medium text-white">{metric.value}</span>
              {getStatusIcon(metric.status)}
            </div>
          </div>
        ))}
      </div>
      
      <div className="mt-4 pt-4 border-t border-dark-700">
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-400">Last Updated</span>
          <span className="text-white">{new Date().toLocaleTimeString()}</span>
        </div>
        <div className="flex items-center justify-between text-sm mt-1">
          <span className="text-gray-400">Uptime</span>
          <span className="text-white">7d 14h 32m</span>
        </div>
      </div>
    </div>
  );
};

export default SystemStatus; 