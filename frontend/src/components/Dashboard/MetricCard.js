import React from 'react';
import { TrendingUp, TrendingDown } from 'lucide-react';

const MetricCard = ({ title, value, change, changeType, icon: Icon, color = 'primary' }) => {
  const getColorClasses = (color) => {
    switch (color) {
      case 'primary':
        return 'bg-primary-500/10 border-primary-500/20 text-primary-400';
      case 'success':
        return 'bg-success-500/10 border-success-500/20 text-success-400';
      case 'warning':
        return 'bg-warning-500/10 border-warning-500/20 text-warning-400';
      case 'danger':
        return 'bg-danger-500/10 border-danger-500/20 text-danger-400';
      default:
        return 'bg-gray-500/10 border-gray-500/20 text-gray-400';
    }
  };

  const getIconColor = (color) => {
    switch (color) {
      case 'primary':
        return 'text-primary-400';
      case 'success':
        return 'text-success-400';
      case 'warning':
        return 'text-warning-400';
      case 'danger':
        return 'text-danger-400';
      default:
        return 'text-gray-400';
    }
  };

  return (
    <div className="card p-6">
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-gray-400">{title}</p>
          <p className="text-2xl font-bold text-white mt-1">{value}</p>
          <div className="flex items-center mt-2">
            {changeType === 'positive' ? (
              <TrendingUp className="w-4 h-4 text-success-400 mr-1" />
            ) : (
              <TrendingDown className="w-4 h-4 text-danger-400 mr-1" />
            )}
            <span className={`text-sm font-medium ${
              changeType === 'positive' ? 'text-success-400' : 'text-danger-400'
            }`}>
              {change}
            </span>
            <span className="text-sm text-gray-400 ml-1">from last hour</span>
          </div>
        </div>
        <div className={`p-3 rounded-lg border ${getColorClasses(color)}`}>
          <Icon className={`w-6 h-6 ${getIconColor(color)}`} />
        </div>
      </div>
    </div>
  );
};

export default MetricCard; 