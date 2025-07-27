import React from 'react';
import { ClipboardList, FileText, Download } from 'lucide-react';

const Audit = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Audit & Compliance</h1>
          <p className="text-gray-400 mt-1">Comprehensive audit trails and compliance reporting</p>
        </div>
        <button className="btn-primary flex items-center space-x-2">
          <Download className="w-4 h-4" />
          <span>Export Audit Log</span>
        </button>
      </div>
      
      <div className="card p-6">
        <div className="text-center py-12">
          <ClipboardList className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-white mb-2">Audit Features Coming Soon</h2>
          <p className="text-gray-400">Comprehensive audit trails, compliance reporting, and action logging.</p>
        </div>
      </div>
    </div>
  );
};

export default Audit; 