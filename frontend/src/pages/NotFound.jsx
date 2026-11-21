import React from 'react';
import { Link, useLocation } from 'react-router-dom';

const NotFound = () => {
  const { pathname } = useLocation();
  return (
    <div className="panel px-6 py-16 text-center">
      <p className="label">404</p>
      <p className="mt-3 text-sm text-inksoft">No console page at <span className="num">{pathname}</span>.</p>
      <Link to="/" className="btn-secondary inline-block mt-6">Back to overview</Link>
    </div>
  );
};

export default NotFound;
