import React, { useState, useEffect } from 'react';
import { Share2, Globe, AlertTriangle, CheckCircle, Activity, ExternalLink } from 'lucide-react';
import api from '../../utils/api';
import clsx from 'clsx';

export default function MobileSitemap({ report, deviceId, onNavigate }) {
  const [liveTraffic, setTraffic] = useState([]);
  const endpoints = report?.api_discovery?.endpoints || [];

  useEffect(() => {
    if (!deviceId) return;
    const fetchTraffic = async () => {
      try {
        const r = await api.get(`/mobile/agent/traffic/${deviceId}?limit=200`);
        setTraffic(r.data || []);
      } catch {}
    };
    fetchTraffic();
    const t = setInterval(fetchTraffic, 5000);
    return () => clearInterval(t);
  }, [deviceId]);

  // Group endpoints by host/path
  const sitemap = endpoints.reduce((acc, ep) => {
    const url = ep.url || ep.path || '';
    const host = url.startsWith('http') ? new URL(url).hostname : 'Local/Relative';
    if (!acc[host]) acc[host] = [];
    
    // Enrich with live data
    const matches = liveTraffic.filter(t => (t.request?.url || '').includes(url));
    const lastStatus = matches.length > 0 ? matches[0].response?.status_code : null;
    
    acc[host].push({
      ...ep,
      live_calls: matches.length,
      last_status: lastStatus,
      risk_score: ep.severity === 'high' ? 9 : ep.severity === 'medium' ? 5 : 2
    });
    return acc;
  }, {});

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div className="flex items-center justify-between px-2">
        <div>
          <h3 className="text-lg font-black text-slate-100 uppercase tracking-tight">Risk-Weighted Sitemap</h3>
          <p className="text-[10px] text-slate-500 font-mono mt-1">Cross-referencing static discovery with live traffic patterns</p>
        </div>
        <div className="flex gap-4">
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-red-500" />
            <span className="text-[9px] font-bold text-slate-400 uppercase">High Risk</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-glow-cyan" />
            <span className="text-[9px] font-bold text-slate-400 uppercase">Live Active</span>
          </div>
        </div>
      </div>

      <div className="grid gap-6">
        {Object.entries(sitemap).map(([host, items]) => (
          <div key={host} className="glass-card overflow-hidden">
            <div className="px-5 py-3 bg-bg-secondary/50 border-b border-bg-border flex items-center gap-3">
              <Globe size={14} className="text-accent-primary" />
              <span className="text-xs font-black text-slate-200 font-mono">{host}</span>
              <span className="text-[9px] text-slate-600 bg-black/40 px-2 py-0.5 rounded-full border border-white/5">{items.length} Endpoints</span>
            </div>
            <div className="p-2 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
              {items.map((ep, i) => (
                <div 
                  key={i}
                  className={clsx(
                    "p-3 rounded-xl border transition-all group relative",
                    ep.live_calls > 0 ? "bg-accent-primary/5 border-accent-primary/30" : "bg-black/20 border-white/5"
                  )}
                >
                  <div className="flex justify-between items-start mb-2">
                    <span className="text-[9px] font-black text-purple-400 uppercase">{ep.method || 'GET'}</span>
                    <div className="flex gap-2">
                      {ep.last_status && (
                        <span className={clsx(
                          "text-[8px] font-bold px-1.5 py-0.5 rounded",
                          ep.last_status < 400 ? "bg-emerald-500/20 text-emerald-400" : "bg-red-500/20 text-red-400"
                        )}>
                          {ep.last_status}
                        </span>
                      )}
                      {ep.risk_score > 7 && <AlertTriangle size={10} className="text-red-500 animate-pulse" />}
                    </div>
                  </div>
                  <div className="text-[10px] font-mono text-slate-300 truncate mb-2">{ep.url || ep.path}</div>
                  <div className="flex items-center justify-between mt-auto">
                    <span className="text-[8px] font-bold text-slate-600 uppercase">
                      {ep.live_calls} calls observed
                    </span>
                    {ep.file && (
                      <button 
                        onClick={() => onNavigate?.('research', 'source', ep.file)}
                        className="p-1 hover:text-accent-primary transition-colors"
                        title="View Handler Code"
                      >
                        <ExternalLink size={10} />
                      </button>
                    )}
                  </div>
                  
                  {/* Risk Bar */}
                  <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-white/5 overflow-hidden rounded-b-xl">
                    <div 
                      className={clsx("h-full", ep.risk_score > 7 ? "bg-red-500" : ep.risk_score > 4 ? "bg-orange-500" : "bg-cyan-500")}
                      style={{ width: `${(ep.risk_score / 10) * 100}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {endpoints.length === 0 && (
        <div className="py-20 flex flex-col items-center justify-center opacity-30">
          <Share2 size={48} className="mb-4" />
          <p className="text-sm font-black uppercase">No Sitemap Data</p>
          <p className="text-[10px] font-mono mt-1">RUN_STATIC_ANALYSIS_TO_MAP_ENDPOINTS</p>
        </div>
      )}
    </div>
  );
}
