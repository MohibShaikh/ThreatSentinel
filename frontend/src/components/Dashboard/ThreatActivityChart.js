import React from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Area,
  AreaChart
} from 'recharts';

const ThreatActivityChart = ({ data = [] }) => {
  // Generate sample data if none provided
  const chartData = data.length > 0 ? data : Array.from({ length: 24 }, (_, i) => ({
    hour: i,
    threats: Math.floor(Math.random() * 50) + 10,
    blocked: Math.floor(Math.random() * 40) + 5,
    investigated: Math.floor(Math.random() * 20) + 2,
  }));

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-dark-800 border border-dark-700 rounded-lg p-3 shadow-lg">
          <p className="text-white font-medium mb-2">{`Hour ${label}:00`}</p>
          {payload.map((entry, index) => (
            <p key={index} className="text-sm" style={{ color: entry.color }}>
              {`${entry.name}: ${entry.value}`}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={chartData}>
          <defs>
            <linearGradient id="threatsGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
            </linearGradient>
            <linearGradient id="blockedGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3}/>
              <stop offset="95%" stopColor="#22c55e" stopOpacity={0}/>
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
          <XAxis 
            dataKey="hour" 
            stroke="#9ca3af"
            tick={{ fill: '#9ca3af', fontSize: 12 }}
            tickLine={{ stroke: '#374151' }}
          />
          <YAxis 
            stroke="#9ca3af"
            tick={{ fill: '#9ca3af', fontSize: 12 }}
            tickLine={{ stroke: '#374151' }}
          />
          <Tooltip content={<CustomTooltip />} />
          <Area
            type="monotone"
            dataKey="threats"
            stroke="#ef4444"
            fillOpacity={1}
            fill="url(#threatsGradient)"
            name="Threats Detected"
          />
          <Area
            type="monotone"
            dataKey="blocked"
            stroke="#22c55e"
            fillOpacity={1}
            fill="url(#blockedGradient)"
            name="Threats Blocked"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};

export default ThreatActivityChart; 