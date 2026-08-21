import React, { useState } from 'react';
import { useForm } from 'react-hook-form';
import { X, AlertTriangle, Shield, Globe, User, FileText } from 'lucide-react';

const InvestigationForm = ({ onSubmit, onCancel, isLoading }) => {
  const [selectedEventType, setSelectedEventType] = useState('');
  const { register, handleSubmit, formState: { errors }, watch } = useForm();

  const eventTypes = [
    { value: 'network_scan', label: 'Network Scan', icon: Globe, description: 'Port scanning or network reconnaissance activity' },
    { value: 'authentication', label: 'Authentication Failure', icon: User, description: 'Failed login attempts or credential abuse' },
    { value: 'malware', label: 'Malware Detection', icon: AlertTriangle, description: 'Suspicious files or malicious activity' },
    { value: 'data_exfiltration', label: 'Data Exfiltration', icon: FileText, description: 'Unauthorized data access or transfer' },
    { value: 'ddos', label: 'DDoS Attack', icon: Shield, description: 'Distributed denial of service activity' },
    { value: 'phishing', label: 'Phishing Attempt', icon: AlertTriangle, description: 'Suspicious emails or social engineering' },
  ];

  const riskLevels = [
    { value: 'low', label: 'Low', color: 'text-success-400' },
    { value: 'medium', label: 'Medium', color: 'text-yellow-400' },
    { value: 'high', label: 'High', color: 'text-warning-400' },
    { value: 'critical', label: 'Critical', color: 'text-danger-400' },
  ];

  const handleFormSubmit = (data) => {
    const formData = {
      ...data,
      event_type: selectedEventType,
      created_at: new Date().toISOString(),
    };
    onSubmit(formData);
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-dark-800 rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-6 border-b border-dark-700">
          <h2 className="text-xl font-semibold text-white">Create New Investigation</h2>
          <button
            onClick={onCancel}
            className="text-gray-400 hover:text-white transition-colors duration-200"
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        <form onSubmit={handleSubmit(handleFormSubmit)} className="p-6 space-y-6">
          {/* Basic Information */}
          <div>
            <h3 className="text-lg font-medium text-white mb-4">Basic Information</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Investigation Title
                </label>
                <input
                  type="text"
                  {...register('title', { required: 'Title is required' })}
                  className="input-field w-full"
                  placeholder="Enter investigation title..."
                />
                {errors.title && (
                  <p className="text-danger-400 text-sm mt-1">{errors.title.message}</p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Description
                </label>
                <textarea
                  {...register('description')}
                  rows={3}
                  className="input-field w-full"
                  placeholder="Describe the security event..."
                />
              </div>
            </div>
          </div>

          {/* Event Type Selection */}
          <div>
            <h3 className="text-lg font-medium text-white mb-4">Event Type</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {eventTypes.map((type) => (
                <button
                  key={type.value}
                  type="button"
                  onClick={() => setSelectedEventType(type.value)}
                  className={`p-4 rounded-lg border transition-all duration-200 text-left ${
                    selectedEventType === type.value
                      ? 'border-primary-500 bg-primary-500/10'
                      : 'border-dark-600 bg-dark-700 hover:border-dark-500'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <type.icon className="w-5 h-5 text-gray-400" />
                    <div>
                      <p className="font-medium text-white">{type.label}</p>
                      <p className="text-sm text-gray-400">{type.description}</p>
                    </div>
                  </div>
                </button>
              ))}
            </div>
            {!selectedEventType && (
              <p className="text-warning-400 text-sm mt-2">Please select an event type</p>
            )}
          </div>

          {/* Event Details */}
          <div>
            <h3 className="text-lg font-medium text-white mb-4">Event Details</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Source IP Address
                </label>
                <input
                  type="text"
                  {...register('source_ip')}
                  className="input-field w-full"
                  placeholder="192.168.1.100"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Target IP Address
                </label>
                <input
                  type="text"
                  {...register('target_ip')}
                  className="input-field w-full"
                  placeholder="10.0.0.1"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  URL (if applicable)
                </label>
                <input
                  type="url"
                  {...register('url')}
                  className="input-field w-full"
                  placeholder="https://example.com"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  User Agent
                </label>
                <input
                  type="text"
                  {...register('user_agent')}
                  className="input-field w-full"
                  placeholder="Mozilla/5.0..."
                />
              </div>
            </div>
          </div>

          {/* Risk Assessment */}
          <div>
            <h3 className="text-lg font-medium text-white mb-4">Risk Assessment</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {riskLevels.map((level) => (
                <button
                  key={level.value}
                  type="button"
                  {...register('risk_level', { required: 'Risk level is required' })}
                  value={level.value}
                  className={`p-3 rounded-lg border transition-all duration-200 ${
                    watch('risk_level') === level.value
                      ? 'border-primary-500 bg-primary-500/10'
                      : 'border-dark-600 bg-dark-700 hover:border-dark-500'
                  }`}
                >
                  <p className={`font-medium ${level.color}`}>{level.label}</p>
                </button>
              ))}
            </div>
            {errors.risk_level && (
              <p className="text-danger-400 text-sm mt-2">{errors.risk_level.message}</p>
            )}
          </div>

          {/* Additional Context */}
          <div>
            <h3 className="text-lg font-medium text-white mb-4">Additional Context</h3>
            <textarea
              {...register('context')}
              rows={4}
              className="input-field w-full"
              placeholder="Additional context, logs, or evidence..."
            />
          </div>

          {/* Form Actions */}
          <div className="flex items-center justify-end space-x-4 pt-6 border-t border-dark-700">
            <button
              type="button"
              onClick={onCancel}
              className="btn-secondary"
              disabled={isLoading}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn-primary"
              disabled={isLoading || !selectedEventType}
            >
              {isLoading ? (
                <div className="flex items-center space-x-2">
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                  <span>Creating...</span>
                </div>
              ) : (
                'Create Investigation'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default InvestigationForm; 