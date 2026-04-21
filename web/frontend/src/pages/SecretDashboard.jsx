import React, { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { Search, ShieldAlert, Key, Filter, Clock } from 'lucide-react';
import api from '../utils/api';
import clsx from 'clsx';

const COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280'
};

export default function SecretDashboard() {
  const [findings, setFindings] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filterSev, setFilterSev] = useState('ALL');

  const fetchFindings = async () => {
    try {
      const res = await api.get('/findings');
      setFindings(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
    const interval = setInterval(fetchFindings, 5000);
    return () => clearInterval(interval);
  }, []);

  const filteredFindings = findings.filter(f => filterSev === 'ALL' || f.severity.toUpperCase() === filterSev);

  const severityData = [
    { name: 'CRITICAL', value: findings.filter(f => f.severity.toLowerCase() === 'critical').length },
    { name: 'HIGH', value: findings.filter(f => f.severity.toLowerCase() === 'high').length },
    { name: 'MEDIUM', value: findings.filter(f => f.severity.toLowerCase() === 'medium').length },
    { name: 'LOW', value: findings.filter(f => f.severity.toLowerCase() === 'low').length }
  ].filter(d => d.value > 0);

  return (
    <div className="p-6 space-y-6 bg-slate-950 text-slate-200 min-h-screen">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-2">
            <Key className="w-8 h-8 text-blue-500" />
            Secret Intelligence Dashboard
          </h1>
          <p className="text-slate-400 mt-1">Real-time exposure analysis and validation</p>
        </div>
      </div>

      {loading ? (
        <div className="animate-pulse flex space-x-4">
          <div className="flex-1 space-y-4 py-1">
            <div className="h-4 bg-slate-800 rounded w-3/4"></div>
            <div className="space-y-2">
              <div className="h-4 bg-slate-800 rounded"></div>
              <div className="h-4 bg-slate-800 rounded w-5/6"></div>
            </div>
          </div>
        </div>
      ) : (
        <>
          {/* Top Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg">
              <div className="text-slate-400 text-sm">Total Secrets Detected</div>
              <div className="text-3xl font-bold mt-1 text-white">{findings.length}</div>
            </div>
            <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg">
              <div className="text-slate-400 text-sm">Critical Exposures</div>
              <div className="text-3xl font-bold mt-1 text-red-500">
                {findings.filter(f => f.severity.toLowerCase() === 'critical').length}
              </div>
            </div>
            <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg">
              <div className="text-slate-400 text-sm">AI Validated</div>
              <div className="text-3xl font-bold mt-1 text-blue-400">
                {findings.filter(f => f.raw?.ai_validated).length}
              </div>
            </div>
            <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg">
              <div className="text-slate-400 text-sm">False Positives Suppressed</div>
              <div className="text-3xl font-bold mt-1 text-green-500">
                {findings.filter(f => f.raw?.ai_validated && !f.raw?.ai_is_real).length}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Pie Chart */}
            <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg flex flex-col h-80">
              <h2 className="text-lg font-semibold text-white mb-2">Severity Distribution</h2>
              <div className="flex-1">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={severityData} cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                      {severityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[entry.name.toLowerCase()]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: 'none', color: '#fff' }} />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Findings Table */}
            <div className="col-span-2 bg-slate-900 border border-slate-800 p-4 rounded-lg flex flex-col h-80 overflow-hidden">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-lg font-semibold text-white">Live Findings Feed</h2>
                <div className="flex gap-2">
                  <Filter className="w-5 h-5 text-slate-400" />
                  <select 
                    value={filterSev} 
                    onChange={e => setFilterSev(e.target.value)}
                    className="bg-slate-800 border-none text-sm text-slate-200 rounded"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                  </select>
                </div>
              </div>
              <div className="overflow-y-auto flex-1 pr-2">
                {filteredFindings.map((f, i) => (
                  <div key={i} className="mb-3 p-3 bg-slate-800/50 rounded-md border border-slate-800/80">
                    <div className="flex justify-between items-start">
                      <div className="font-semibold text-slate-200 flex items-center gap-2">
                        <span className={clsx(
                          "px-2 py-0.5 text-xs rounded uppercase font-bold",
                          f.severity.toLowerCase() === 'critical' ? "bg-red-500/20 text-red-400" :
                          f.severity.toLowerCase() === 'high' ? "bg-orange-500/20 text-orange-400" :
                          f.severity.toLowerCase() === 'medium' ? "bg-yellow-500/20 text-yellow-400" :
                          "bg-blue-500/20 text-blue-400"
                        )}>
                          {f.severity}
                        </span>
                        {f.title}
                      </div>
                      <div className="text-xs text-slate-500 flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {new Date(f.created_at).toLocaleTimeString()}
                      </div>
                    </div>
                    <div className="mt-2 text-sm text-slate-400 truncate">
                      File: {f.url}
                    </div>
                    <div className="mt-1 text-xs font-mono bg-slate-950 p-2 rounded text-slate-300">
                      {f.payload}
                    </div>
                    {f.raw?.ai_validated && (
                      <div className="mt-2 text-xs text-blue-400 flex items-center gap-1">
                        <ShieldAlert className="w-3 h-3" />
                        AI Verified (Confidence: {(f.confidence * 100).toFixed(0)}%) - {f.raw?.ai_reasoning}
                      </div>
                    )}
                  </div>
                ))}
                {filteredFindings.length === 0 && (
                  <div className="text-center text-slate-500 mt-10">No findings to display.</div>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
