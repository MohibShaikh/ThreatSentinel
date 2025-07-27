import React from 'react';
import { FileText, Download, Eye, Plus } from 'lucide-react';

const Reports = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Reports</h1>
          <p className="text-gray-400 mt-1">Generated investigation reports and analytics</p>
        </div>
        <button className="btn-primary flex items-center space-x-2">
          <Plus className="w-4 h-4" />
          <span>Generate Report</span>
        </button>
      </div>
      
      <div className="card p-6">
        <div className="text-center py-12">
          <FileText className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-white mb-2">Reports Coming Soon</h2>
          <p className="text-gray-400">Advanced reporting and analytics features will be available here.</p>
        </div>
      </div>
    </div>
  );
};

export default Reports; 