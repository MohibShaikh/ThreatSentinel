import React from 'react';
import { useParams } from 'react-router-dom';
import { ArrowLeft, Eye, Download, Share2 } from 'lucide-react';
import { Link } from 'react-router-dom';

const InvestigationDetail = () => {
  const { id } = useParams();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <Link to="/investigations" className="btn-secondary">
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-white">Investigation {id}</h1>
            <p className="text-gray-400 mt-1">Detailed investigation analysis and findings</p>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <button className="btn-secondary">
            <Share2 className="w-4 h-4" />
          </button>
          <button className="btn-secondary">
            <Download className="w-4 h-4" />
          </button>
        </div>
      </div>
      
      <div className="card p-6">
        <div className="text-center py-12">
          <Eye className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-white mb-2">Investigation Details Coming Soon</h2>
          <p className="text-gray-400">Detailed investigation view with timeline, findings, and actions.</p>
        </div>
      </div>
    </div>
  );
};

export default InvestigationDetail; 