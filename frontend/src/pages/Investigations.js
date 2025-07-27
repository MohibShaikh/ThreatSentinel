import React, { useState } from 'react';
import { useQuery } from 'react-query';
import { Link } from 'react-router-dom';
import { 
  Search, 
  Filter, 
  Plus, 
  Eye, 
  Clock, 
  CheckCircle, 
  AlertTriangle, 
  XCircle,
  Download,
  MoreHorizontal
} from 'lucide-react';
import { useThreatSentinel } from '../context/ThreatSentinelContext';
import { api } from '../context/ThreatSentinelContext';
import InvestigationForm from '../components/Investigations/InvestigationForm';

const Investigations = () => {
  const [showForm, setShowForm] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [riskFilter, setRiskFilter] = useState('all');
  const { createInvestigation } = useThreatSentinel();

  const { data: investigations = [], isLoading, refetch } = useQuery(
    'investigations',
    async () => {
      const response = await api.get('/investigations/');
      return response.data;
    },
    {
      refetchInterval: 30000, // Refresh every 30 seconds
    }
  );

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

  const filteredInvestigations = investigations.filter(investigation => {
    const matchesSearch = investigation.title?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         investigation.id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         investigation.source_ip?.includes(searchTerm);
    const matchesStatus = statusFilter === 'all' || investigation.status === statusFilter;
    const matchesRisk = riskFilter === 'all' || investigation.risk_level?.toLowerCase() === riskFilter;
    
    return matchesSearch && matchesStatus && matchesRisk;
  });

  const handleCreateInvestigation = async (data) => {
    await createInvestigation.mutateAsync(data);
    setShowForm(false);
    refetch();
  };

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
          <h1 className="text-2xl font-bold text-white">Investigations</h1>
          <p className="text-gray-400 mt-1">Manage security incident investigations</p>
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="btn-primary flex items-center space-x-2"
        >
          <Plus className="w-4 h-4" />
          <span>New Investigation</span>
        </button>
      </div>

      {/* Filters */}
      <div className="card p-6">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search investigations..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="input-field pl-10 w-full"
              />
            </div>
          </div>
          
          <div className="flex gap-4">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="input-field"
            >
              <option value="all">All Status</option>
              <option value="pending">Pending</option>
              <option value="in_progress">In Progress</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
            </select>
            
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="input-field"
            >
              <option value="all">All Risk Levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>
      </div>

      {/* Investigations Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-dark-700">
            <thead className="bg-dark-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Investigation
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Risk Level
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Event Type
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Created
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-dark-800 divide-y divide-dark-700">
              {filteredInvestigations.map((investigation) => (
                <tr key={investigation.id} className="hover:bg-dark-700 transition-colors duration-200">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div>
                      <div className="text-sm font-medium text-white">
                        {investigation.title || `Investigation ${investigation.id}`}
                      </div>
                      <div className="text-sm text-gray-400">ID: {investigation.id}</div>
                      {investigation.source_ip && (
                        <div className="text-sm text-gray-400">IP: {investigation.source_ip}</div>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center space-x-2">
                      {getStatusIcon(investigation.status)}
                      <span className={`status-badge ${getStatusColor(investigation.status)}`}>
                        {investigation.status?.replace('_', ' ') || 'unknown'}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`text-sm font-medium ${getRiskColor(investigation.risk_level)}`}>
                      {investigation.risk_level?.toUpperCase() || 'UNKNOWN'}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    {investigation.event_type?.replace('_', ' ') || 'Unknown'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    {new Date(investigation.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <div className="flex items-center space-x-2">
                      <Link
                        to={`/investigations/${investigation.id}`}
                        className="text-primary-400 hover:text-primary-300"
                        title="View Details"
                      >
                        <Eye className="w-4 h-4" />
                      </Link>
                      <button
                        className="text-gray-400 hover:text-gray-300"
                        title="Download Report"
                      >
                        <Download className="w-4 h-4" />
                      </button>
                      <button
                        className="text-gray-400 hover:text-gray-300"
                        title="More Actions"
                      >
                        <MoreHorizontal className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        {filteredInvestigations.length === 0 && (
          <div className="text-center py-12">
            <Search className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-400">No investigations found</p>
            <p className="text-sm text-gray-500 mt-1">
              {searchTerm || statusFilter !== 'all' || riskFilter !== 'all' 
                ? 'Try adjusting your filters' 
                : 'Create your first investigation to get started'}
            </p>
          </div>
        )}
      </div>

      {/* Create Investigation Modal */}
      {showForm && (
        <InvestigationForm
          onSubmit={handleCreateInvestigation}
          onCancel={() => setShowForm(false)}
          isLoading={createInvestigation.isLoading}
        />
      )}
    </div>
  );
};

export default Investigations; 