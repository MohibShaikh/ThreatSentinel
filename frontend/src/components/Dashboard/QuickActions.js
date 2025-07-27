import React from 'react';
import { Link } from 'react-router-dom';
import { 
  Search, 
  FileText, 
  Settings, 
  AlertTriangle, 
  Shield, 
  Activity,
  Plus
} from 'lucide-react';

const QuickActions = () => {
  const actions = [
    {
      title: 'New Investigation',
      description: 'Start investigating a security event',
      icon: Search,
      href: '/investigations',
      color: 'primary',
      badge: 'Quick'
    },
    {
      title: 'Generate Report',
      description: 'Create incident report',
      icon: FileText,
      href: '/reports',
      color: 'success'
    },
    {
      title: 'System Health',
      description: 'Check system status',
      icon: Activity,
      href: '/monitoring',
      color: 'info'
    },
    {
      title: 'Manage Integrations',
      description: 'Configure SOC tools',
      icon: Settings,
      href: '/integrations',
      color: 'warning'
    },
    {
      title: 'View Alerts',
      description: 'Check recent alerts',
      icon: AlertTriangle,
      href: '/monitoring',
      color: 'danger'
    },
    {
      title: 'Security Overview',
      description: 'Threat landscape',
      icon: Shield,
      href: '/',
      color: 'primary'
    }
  ];

  const getColorClasses = (color) => {
    switch (color) {
      case 'primary':
        return 'bg-primary-500/10 border-primary-500/20 text-primary-400 hover:bg-primary-500/20';
      case 'success':
        return 'bg-success-500/10 border-success-500/20 text-success-400 hover:bg-success-500/20';
      case 'warning':
        return 'bg-warning-500/10 border-warning-500/20 text-warning-400 hover:bg-warning-500/20';
      case 'danger':
        return 'bg-danger-500/10 border-danger-500/20 text-danger-400 hover:bg-danger-500/20';
      case 'info':
        return 'bg-blue-500/10 border-blue-500/20 text-blue-400 hover:bg-blue-500/20';
      default:
        return 'bg-gray-500/10 border-gray-500/20 text-gray-400 hover:bg-gray-500/20';
    }
  };

  return (
    <div className="card p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-white">Quick Actions</h2>
        <Plus className="w-5 h-5 text-gray-400" />
      </div>
      <div className="grid grid-cols-1 gap-3">
        {actions.map((action, index) => (
          <Link
            key={index}
            to={action.href}
            className={`flex items-center p-3 rounded-lg border transition-all duration-200 ${getColorClasses(action.color)}`}
          >
            <div className="flex-shrink-0">
              <action.icon className="w-5 h-5" />
            </div>
            <div className="ml-3 flex-1 min-w-0">
              <div className="flex items-center">
                <p className="text-sm font-medium text-white truncate">
                  {action.title}
                </p>
                {action.badge && (
                  <span className="ml-2 px-2 py-0.5 text-xs font-medium bg-primary-500 text-white rounded-full">
                    {action.badge}
                  </span>
                )}
              </div>
              <p className="text-xs text-gray-400 truncate">
                {action.description}
              </p>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
};

export default QuickActions; 