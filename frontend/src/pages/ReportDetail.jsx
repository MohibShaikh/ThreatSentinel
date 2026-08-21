import React from 'react';
import { useParams } from 'react-router-dom';
import { ArrowLeft, FileText, Download, Share2 } from 'lucide-react';
import { Link } from 'react-router-dom';

const ReportDetail = () => {
  const { id } = useParams();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <Link to="/reports" className="btn-secondary">
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-white">Report {id}</h1>
            <p className="text-gray-400 mt-1">Generated investigation report and analysis</p>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <button className="btn-secondary">
            <Share2 className="w-4 h-4" />
          </button>
          <button className="btn-primary">
            <Download className="w-4 h-4" />
          </button>
        </div>
      </div>
      
      <div className="card p-6">
        <div className="text-center py-12">
          <FileText className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-white mb-2">Report Details Coming Soon</h2>
          <p className="text-gray-400">Detailed report view with findings, recommendations, and export options.</p>
        </div>
      </div>
    </div>
  );
};

export default ReportDetail; 