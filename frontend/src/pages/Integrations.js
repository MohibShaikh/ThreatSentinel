import React from 'react';
import { Settings, Shield, Activity } from 'lucide-react';

const Integrations = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Integrations</h1>
          <p className="text-gray-400 mt-1">Manage SOC tool connections and configurations</p>
        </div>
        <button className="btn-primary flex items-center space-x-2">
          <Settings className="w-4 h-4" />
          <span>Add Integration</span>
        </button>
      </div>
      
      <div className="card p-6">
        <div className="text-center py-12">
          <Shield className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-white mb-2">Integrations Coming Soon</h2>
          <p className="text-gray-400">Manage firewall, SIEM, and other SOC tool integrations.</p>
        </div>
      </div>
    </div>
  );
};

export default Integrations; 