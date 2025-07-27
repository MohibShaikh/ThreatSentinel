import React from 'react';
import { Link } from 'react-router-dom';
import { 
  Clock, 
  CheckCircle, 
  AlertTriangle, 
  XCircle, 
  Eye,
  ExternalLink
} from 'lucide-react';

const RecentInvestigations = ({ investigations = [] }) => {
  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-success-400" />;
      case 'in_progress':
        return <Clock className="w-4 h-4 text-warning-400" />;
      case 'pending':
        return <AlertTriangle className="w-4 h-4 text-warning-400" />;
      case 'failed':
        return <XCircle className="w-4 h-4 text-danger-400" />;
      default:
        return <Clock className="w-4 h-4 text-gray-400" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed':
        return 'status-success';
      case 'in_progress':
        return 'status-warning';
      case 'pending':
        return 'status-info';
      case 'failed':
        return 'status-critical';
      default:
        return 'status-info';
    }
  };

  const getRiskColor = (risk) => {
    switch (risk?.toLowerCase()) {
      case 'critical':
        return 'text-danger-400';
      case 'high':
        return 'text-warning-400';
      case 'medium':
        return 'text-yellow-400';
      case 'low':
        return 'text-success-400';
      default:
        return 'text-gray-400';
    }
  };

  // Generate sample data if none provided
  const sampleInvestigations = [
    {
      id: 'inv-001',
      title: 'Suspicious IP Activity Detected',
      status: 'completed',
      risk_level: 'high',
      created_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
      event_type: 'network_scan',
      source_ip: '192.168.1.100'
    },
    {
      id: 'inv-002',
      title: 'Failed Login Attempts',
      status: 'in_progress',
      risk_level: 'medium',
      created_at: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(),
      event_type: 'authentication',
      source_ip: '10.0.0.50'
    },
    {
      id: 'inv-003',
      title: 'Malware Detection Alert',
      status: 'pending',
      risk_level: 'critical',
      created_at: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
      event_type: 'malware',
      source_ip: '172.16.0.25'
    }
  ];

  const displayInvestigations = investigations.length > 0 ? investigations : sampleInvestigations;

  return (
    <div className="space-y-3">
      {displayInvestigations.slice(0, 5).map((investigation, index) => (
        <div key={investigation.id || index} className="flex items-center space-x-4 p-4 bg-dark-700 rounded-lg border border-dark-600 hover:border-dark-500 transition-colors duration-200">
          <div className="flex-shrink-0">
            {getStatusIcon(investigation.status)}
          </div>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-medium text-white truncate">
                {investigation.title || `Investigation ${investigation.id}`}
              </h3>
              <div className="flex items-center space-x-2">
                <span className={`status-badge ${getStatusColor(investigation.status)}`}>
                  {investigation.status?.replace('_', ' ') || 'unknown'}
                </span>
                <span className={`text-xs font-medium ${getRiskColor(investigation.risk_level)}`}>
                  {investigation.risk_level?.toUpperCase() || 'UNKNOWN'}
                </span>
              </div>
            </div>
            
            <div className="mt-1 flex items-center space-x-4 text-xs text-gray-400">
              <span>ID: {investigation.id}</span>
              <span>Type: {investigation.event_type?.replace('_', ' ') || 'unknown'}</span>
              {investigation.source_ip && (
                <span>IP: {investigation.source_ip}</span>
              )}
              <span>
                {new Date(investigation.created_at).toLocaleString()}
              </span>
            </div>
          </div>
          
          <div className="flex items-center space-x-2">
            <Link
              to={`/investigations/${investigation.id}`}
              className="p-2 text-gray-400 hover:text-white hover:bg-dark-600 rounded-lg transition-colors duration-200"
              title="View Details"
            >
              <Eye className="w-4 h-4" />
            </Link>
            <button
              className="p-2 text-gray-400 hover:text-white hover:bg-dark-600 rounded-lg transition-colors duration-200"
              title="Open Report"
            >
              <ExternalLink className="w-4 h-4" />
            </button>
          </div>
        </div>
      ))}
      
      {displayInvestigations.length === 0 && (
        <div className="text-center py-8">
          <Clock className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <p className="text-gray-400">No recent investigations</p>
          <p className="text-sm text-gray-500 mt-1">New security events will appear here</p>
        </div>
      )}
    </div>
  );
};

export default RecentInvestigations; 