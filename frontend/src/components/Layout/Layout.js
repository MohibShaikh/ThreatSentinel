import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  Shield, 
  Search, 
  FileText, 
  Activity, 
  Settings, 
  ListTodo, 
  ClipboardList,
  Menu,
  X,
  Bell,
  User,
  Zap
} from 'lucide-react';
import { useThreatSentinel } from '../../context/ThreatSentinelContext';

const navigation = [
  { name: 'Dashboard', href: '/', icon: Shield },
  { name: 'Investigations', href: '/investigations', icon: Search },
  { name: 'Reports', href: '/reports', icon: FileText },
  { name: 'Monitoring', href: '/monitoring', icon: Activity },
  { name: 'Integrations', href: '/integrations', icon: Settings },
  { name: 'Tasks', href: '/tasks', icon: ListTodo },
  { name: 'Audit', href: '/audit', icon: ClipboardList },
];

const Layout = ({ children }) => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const location = useLocation();
  const { systemStatus, activeInvestigations, pendingTasks, notifications } = useThreatSentinel();

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

  const getStatusIcon = (status) => {
    switch (status) {
      case 'healthy':
        return <div className="w-2 h-2 bg-success-400 rounded-full animate-pulse"></div>;
      case 'warning':
        return <div className="w-2 h-2 bg-warning-400 rounded-full animate-pulse"></div>;
      case 'error':
        return <div className="w-2 h-2 bg-danger-400 rounded-full animate-pulse"></div>;
      default:
        return <div className="w-2 h-2 bg-gray-400 rounded-full"></div>;
    }
  };

  return (
    <div className="min-h-screen bg-dark-900">
      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 z-40 bg-black bg-opacity-50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <div className={`fixed inset-y-0 left-0 z-50 w-64 bg-dark-800 border-r border-dark-700 transform transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:inset-0 ${
        sidebarOpen ? 'translate-x-0' : '-translate-x-full'
      }`}>
        <div className="flex items-center justify-between h-16 px-6 border-b border-dark-700">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-gradient-to-br from-primary-500 to-primary-600 rounded-lg flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-white">ThreatSentinel</h1>
              <p className="text-xs text-gray-400">SOC Agent</p>
            </div>
          </div>
          <button
            onClick={() => setSidebarOpen(false)}
            className="lg:hidden p-1 rounded-md text-gray-400 hover:text-white hover:bg-dark-700"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* System Status */}
        <div className="px-6 py-4 border-b border-dark-700">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-gray-300">System Status</span>
            <div className="flex items-center space-x-2">
              {getStatusIcon(systemStatus)}
              <span className={`text-sm ${getStatusColor(systemStatus)}`}>
                {systemStatus === 'healthy' ? 'Operational' : 
                 systemStatus === 'warning' ? 'Warning' : 
                 systemStatus === 'error' ? 'Error' : 'Unknown'}
              </span>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-4 py-4 space-y-2">
          {navigation.map((item) => {
            const isActive = location.pathname === item.href;
            return (
              <Link
                key={item.name}
                to={item.href}
                className={`flex items-center px-3 py-2 text-sm font-medium rounded-lg transition-colors duration-200 ${
                  isActive
                    ? 'bg-primary-600 text-white'
                    : 'text-gray-300 hover:bg-dark-700 hover:text-white'
                }`}
                onClick={() => setSidebarOpen(false)}
              >
                <item.icon className="w-5 h-5 mr-3" />
                {item.name}
                {item.name === 'Investigations' && activeInvestigations > 0 && (
                  <span className="ml-auto bg-primary-500 text-white text-xs px-2 py-1 rounded-full">
                    {activeInvestigations}
                  </span>
                )}
                {item.name === 'Tasks' && pendingTasks > 0 && (
                  <span className="ml-auto bg-warning-500 text-white text-xs px-2 py-1 rounded-full">
                    {pendingTasks}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-dark-700">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-dark-700 rounded-full flex items-center justify-center">
              <User className="w-4 h-4 text-gray-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-white">SOC Analyst</p>
              <p className="text-xs text-gray-400">Active Session</p>
            </div>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="lg:pl-64">
        {/* Header */}
        <header className="bg-dark-800 border-b border-dark-700 h-16 flex items-center justify-between px-6">
          <div className="flex items-center space-x-4">
            <button
              onClick={() => setSidebarOpen(true)}
              className="lg:hidden p-2 rounded-md text-gray-400 hover:text-white hover:bg-dark-700"
            >
              <Menu className="w-5 h-5" />
            </button>
            <h2 className="text-xl font-semibold text-white">
              {navigation.find(item => item.href === location.pathname)?.name || 'Dashboard'}
            </h2>
          </div>

          <div className="flex items-center space-x-4">
            {/* Notifications */}
            <button className="relative p-2 text-gray-400 hover:text-white hover:bg-dark-700 rounded-lg">
              <Bell className="w-5 h-5" />
              {notifications.length > 0 && (
                <span className="absolute -top-1 -right-1 w-4 h-4 bg-danger-500 text-white text-xs rounded-full flex items-center justify-center">
                  {notifications.length}
                </span>
              )}
            </button>

            {/* Quick Actions */}
            <button className="flex items-center space-x-2 bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg transition-colors duration-200">
              <Zap className="w-4 h-4" />
              <span className="text-sm font-medium">New Investigation</span>
            </button>
          </div>
        </header>

        {/* Page content */}
        <main className="p-6">
          {children}
        </main>
      </div>
    </div>
  );
};

export default Layout; 