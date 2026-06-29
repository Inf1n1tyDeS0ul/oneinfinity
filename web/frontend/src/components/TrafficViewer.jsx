import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  Code, Search, Trash2, Download, RefreshCw, Filter, 
  ExternalLink, Maximize2, Minimize2, Copy, AlertCircle,
  Eye, CheckCircle, XCircle, Clock, Globe, Shield, Zap, ChevronRight, Binary, Activity as ActivityIcon
} from 'lucide-react';
import clsx from 'clsx';
import api from '../../utils/api';
import JSONViewer from './mobile/JSONViewer';
import './TrafficViewer.css';
export default function TrafficViewer({ deviceId, onViewCode }) {
  const [traffic, setTraffic] = useState([]);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [selectedEntry, setSelectedEntry] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [isFullScreen, setIsFullScreen] = useState(false);
  const [diffBase, setDiffBase] = useState(null); // ID for diff comparison

  const fetchTraffic = useCallback(async () => {
    if (!deviceId) return;
    try {
      const response = await api.get(`/mobile/agent/traffic/${deviceId}`, { params: { limit: 250 } });
      setTraffic(response.data);
    } catch (err) {
      console.error('Failed to fetch traffic:', err);
    }
  }, [deviceId]);

  useEffect(() => {
    fetchTraffic();
    if (autoRefresh) {
      const interval = setInterval(fetchTraffic, 3000);
      return () => clearInterval(interval);
    }
  }, [fetchTraffic, autoRefresh]);

  const filteredTraffic = useMemo(() => {
    return traffic.filter(entry => {
      const url = (entry.request?.url || '').toLowerCase();
      const method = (entry.request?.method || '').toLowerCase();
      const matchesSearch = url.includes(search.toLowerCase()) || method.includes(search.toLowerCase());
      
      if (!matchesSearch) return false;
      if (filter === 'all') return true;
      if (filter === 'http') return entry.request?.url?.startsWith('http://');
      if (filter === 'https') return entry.request?.url?.startsWith('https://');
      if (filter === 'findings') return entry.findings && entry.findings.length > 0;
      if (filter === 'decrypted') return entry.decrypted;
      return true;
    });
  }, [traffic, filter, search]);

  const getMethodColor = (method) => {
    const colors = {
      'GET': 'text-emerald-400',
      'POST': 'text-orange-400',
      'PUT': 'text-blue-400',
      'DELETE': 'text-red-400',
      'PATCH': 'text-purple-400'
    };
    return colors[method] || 'text-slate-400';
  };

  const getStatusColor = (status) => {
    if (status >= 200 && status < 300) return 'text-emerald-500';
    if (status >= 300 && status < 400) return 'text-blue-400';
    if (status >= 400 && status < 500) return 'text-orange-500';
    if (status >= 500) return 'text-red-500';
    return 'text-slate-500';
  };

  const clearTraffic = async () => {
    if (!window.confirm('Delete all captured traffic for this device?')) return;
    try {
      await api.delete(`/mobile/agent/traffic/${deviceId}`);
      setTraffic([]);
      setSelectedEntry(null);
    } catch {}
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    // Could add a notification here
  };

  const getDiagnosticHint = (url) => {
    if (url.includes('sdk/report')) return "Likely an analytics/crash reporting beacon. These endpoints typically return empty success responses (HTTP 204/202).";
    if (url.includes('google-analytics')) return "Google Analytics beacon. Minimal response body is normal.";
    if (url.includes('telemetry')) return "Telemetry endpoint. Often unidirectional with no return data.";
    return null;
  };

  const BodyInspector = ({ body, url }) => {
    if (!body || body.trim() === '') {
      const hint = getDiagnosticHint(url || '');
      return (
        <div className="flex flex-col items-center justify-center py-10">
          <div className="opacity-30 flex flex-col items-center">
            <Clock size={24} className="mb-2" />
            <div className="text-[10px] font-black uppercase tracking-widest text-slate-400">Empty Payload</div>
          </div>
          {hint && (
            <div className="mt-4 p-3 bg-blue-500/5 border border-blue-500/20 rounded-lg max-w-xs text-center">
               <span className="text-[9px] text-blue-400 leading-relaxed italic">💡 {hint}</span>
            </div>
          )}
        </div>
      );
    }
    
    // Check if it looks like Base64 (heuristic)
    const isBase64 = body.length > 20 && /^[a-zA-Z0-9+/]+={0,2}$/.test(body.substring(0, 100));
    
    // Try parsing JSON
    try {
      const parsed = JSON.parse(body);
      return <div className="json-viewer-container"><JSONViewer data={parsed} /></div>;
    } catch (e) {
      if (isBase64) {
        return (
          <div className="space-y-4">
            <div className="p-2 rounded bg-amber-500/10 border border-amber-500/20 text-[9px] text-amber-500 font-bold uppercase flex items-center gap-2">
              <Binary size={12} /> Binary / Base64 Data Detected
            </div>
            <div className="grid grid-cols-2 gap-2">
               <div className="p-3 bg-black/40 rounded border border-white/5 font-mono text-[9px] break-all opacity-60">
                 {body.substring(0, 200)}...
               </div>
               <div className="flex flex-col justify-center gap-2">
                  <button onClick={() => copyToClipboard(body)} className="px-3 py-1.5 bg-white/5 rounded text-[9px] font-black uppercase hover:bg-white/10 transition-all">Copy Base64</button>
                  <button className="px-3 py-1.5 bg-white/5 rounded text-[9px] font-black uppercase opacity-30 cursor-not-allowed">Hex Dump</button>
               </div>
            </div>
          </div>
        );
      }

      // Fallback to text
      return <pre className="text-slate-300 whitespace-pre-wrap break-all leading-relaxed font-mono text-[10px]">{body}</pre>;
    }
  };

  const [inspectorTab, setInspectorTab] = useState('pretty'); // pretty | headers | raw

  return (
    <div className={clsx("traffic-viewer-enhanced flex flex-col", isFullScreen && "fixed inset-0 z-50 bg-bg-primary p-6")}>
      {/* ── Dashboard Header ── */}
      <div className="flex items-center justify-between mb-4 px-2">
        <div className="flex items-center gap-3">
          <div className="p-1.5 rounded-lg bg-accent-primary/10 border border-accent-primary/20">
            <ActivityIcon size={16} className="text-accent-primary" />
          </div>
          <div>
            <h3 className="text-xs font-black text-slate-100 uppercase tracking-widest">Semantic Traffic Stream</h3>
            <p className="text-[9px] text-slate-500 font-mono uppercase tracking-tighter">Live forensic interception active</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative group">
            <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input 
              className="bg-black/40 border border-bg-border rounded-lg pl-8 pr-4 py-1.5 text-[10px] font-bold text-slate-300 outline-none focus:border-accent-primary/40 transition-all w-48"
              placeholder="Search URL / Method..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>

          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="bg-bg-secondary border border-bg-border rounded-lg px-3 py-1.5 text-[10px] font-black text-slate-400 outline-none uppercase"
          >
            <option value="all">All Traffic</option>
            <option value="findings">Findings Only</option>
            <option value="decrypted">Decrypted Only</option>
            <option value="https">HTTPS</option>
          </select>

          <button onClick={() => setAutoRefresh(!autoRefresh)} 
            className={clsx("p-2 rounded-lg border transition-all", autoRefresh ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400 shadow-glow-cyan/5" : "bg-black/20 border-bg-border text-slate-600")}>
            <RefreshCw size={14} className={clsx(autoRefresh && "animate-spin-slow")} />
          </button>

          <button onClick={clearTraffic} className="p-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-500 hover:bg-red-500 hover:text-black transition-all">
            <Trash2 size={14} />
          </button>

          <button onClick={() => setIsFullScreen(!isFullScreen)} className="p-2 rounded-lg bg-white/5 border border-white/10 text-slate-400 hover:text-white transition-all">
            {isFullScreen ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
          </button>
        </div>
      </div>

      {/* ── Main Layout ── */}
      <div className="flex-1 flex gap-4 overflow-hidden min-h-[400px]">
        {/* List View */}
        <div className="w-1/2 flex flex-col border border-bg-border rounded-xl bg-black/20 overflow-hidden shadow-inner">
          <div className="flex-1 overflow-y-auto scrollbar-none divide-y divide-white/5">
            {filteredTraffic.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center opacity-20 space-y-4">
                <Globe size={48} />
                <p className="text-[10px] font-black uppercase tracking-widest text-center">No traffic signals detected<br/>waiting for device...</p>
              </div>
            ) : filteredTraffic.slice().reverse().map((entry) => (
              <div
                key={entry.id}
                onClick={() => setSelectedEntry(entry)}
                className={clsx(
                  "p-3 cursor-pointer transition-all hover:bg-white/5 relative group",
                  selectedEntry?.id === entry.id ? "bg-accent-primary/5 border-l-2 border-l-accent-primary shadow-[inset_10px_0_15px_-10px_rgba(0,255,136,0.1)]" : "border-l-2 border-l-transparent"
                )}
              >
                <div className="flex justify-between items-start mb-1.5">
                  <div className="flex items-center gap-3">
                    <span className={clsx("text-[10px] font-black uppercase tracking-tighter w-8", getMethodColor(entry.request?.method))}>
                      {entry.request?.method}
                    </span>
                    <span className={clsx("text-[10px] font-bold font-mono", getStatusColor(entry.response?.status_code))}>
                      {entry.response?.status_code || '---'}
                    </span>
                  </div>
                  <span className="text-[8px] font-mono text-slate-600">{new Date(entry.timestamp * 1000).toLocaleTimeString()}</span>
                </div>
                
                <div className="text-[11px] font-mono text-slate-300 truncate w-full group-hover:text-white transition-colors">
                  {entry.request?.url}
                </div>

                <div className="mt-2 flex items-center gap-3">
                  <span className="text-[8px] font-black text-slate-600 uppercase flex items-center gap-1">
                    <Binary size={8} /> {entry.source}
                  </span>
                  {entry.decrypted && (
                    <span className="text-[8px] font-black text-emerald-500 uppercase flex items-center gap-1">
                      <Shield size={8} /> TLS Decrypted
                    </span>
                  )}
                  {entry.findings?.length > 0 && (
                    <span className="text-[8px] font-black text-red-500 uppercase flex items-center gap-1">
                      <AlertCircle size={8} /> {entry.findings.length} Vulnerabilities
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Inspector Pane */}
        <div className="flex-1 flex flex-col border border-bg-border rounded-xl bg-bg-secondary/40 overflow-hidden shadow-glow-cyan/5">
          {selectedEntry ? (
            <div className="flex-1 flex flex-col overflow-hidden">
              {/* Inspector Header */}
              <div className="p-4 border-b border-white/5 bg-black/20 flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className={clsx("px-2 py-0.5 rounded text-[9px] font-black uppercase", getStatusColor(selectedEntry.response?.status_code))}>
                    {selectedEntry.request.method} {selectedEntry.response?.status_code}
                  </div>
                  <span className="text-[10px] font-mono text-slate-400 truncate max-w-sm">{selectedEntry.request.url}</span>
                </div>
                <div className="flex items-center gap-2">
                   {onViewCode && (
                     <button onClick={() => onViewCode(selectedEntry)} className="p-1.5 rounded-lg bg-white/5 text-slate-400 hover:text-accent-primary transition-colors" title="Trace to Code">
                        <Code size={14} />
                     </button>
                   )}
                   <button onClick={() => copyToClipboard(selectedEntry.request.url)} className="p-1.5 rounded-lg bg-white/5 text-slate-400 hover:text-white transition-colors">
                      <Copy size={14} />
                   </button>
                </div>
              </div>

              {/* Inspector Content */}
              <div className="flex-1 overflow-y-auto p-4 scrollbar-thin">
                <div className="flex gap-4 border-b border-white/5 mb-6">
                  {['pretty', 'headers', 'raw'].map(t => (
                    <button 
                      key={t}
                      onClick={() => setInspectorTab(t)}
                      className={clsx(
                        "pb-2 text-[10px] font-black uppercase tracking-widest transition-all relative",
                        inspectorTab === t ? "text-accent-primary" : "text-slate-600 hover:text-slate-400"
                      )}
                    >
                      {t}
                      {inspectorTab === t && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-accent-primary" />}
                    </button>
                  ))}
                </div>

                {inspectorTab === 'pretty' && (
                  <div className="space-y-8 animate-in fade-in slide-in-from-right-1 duration-300">
                    {/* ── Request Section ── */}
                    <div className="space-y-4">
                       <h4 className="text-[10px] font-black text-accent-primary uppercase tracking-widest flex items-center gap-2">
                         <div className="w-1.5 h-1.5 rounded-full bg-accent-primary" /> Request Pipeline
                       </h4>
                       
                       <div className="grid grid-cols-2 gap-4">
                          <div className="p-3 rounded-lg bg-black/40 border border-white/5">
                            <label className="text-[8px] font-black text-slate-500 uppercase mb-2 block">Headers</label>
                            <div className="space-y-1.5 max-h-48 overflow-y-auto pr-2 scrollbar-none">
                              {Object.entries(selectedEntry.request.headers || {}).map(([k, v]) => (
                                <div key={k} className="flex flex-col border-b border-white/5 pb-1">
                                  <span className="text-[9px] font-black text-slate-400 truncate">{k}</span>
                                  <span className="text-[9px] font-mono text-slate-500 break-all">{v}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                          
                          <div className="p-3 rounded-lg bg-black/40 border border-white/5 flex flex-col">
                            <label className="text-[8px] font-black text-slate-500 uppercase mb-2 block">Payload / Body</label>
                            <div className="flex-1 overflow-y-auto text-[10px] pr-2 scrollbar-none">
                               <BodyInspector body={selectedEntry.request.body} url={selectedEntry.request.url} />
                            </div>

                          </div>
                       </div>
                    </div>

                    {/* ── Response Section ── */}
                    <div className="space-y-4">
                       <h4 className="text-[10px] font-black text-purple-400 uppercase tracking-widest flex items-center gap-2">
                         <div className="w-1.5 h-1.5 rounded-full bg-purple-400" /> Response Forensic
                       </h4>
                       
                       {selectedEntry.response ? (
                         <>
                           <div className="p-3 rounded-lg bg-black/40 border border-white/5 flex flex-col mb-4">
                               <div className="flex justify-between items-center mb-2">
                                 <label className="text-[8px] font-black text-slate-500 uppercase">Attributes</label>
                                 <span className="text-[8px] font-mono text-slate-600">{selectedEntry.duration_ms}ms</span>
                               </div>
                               <div className="flex gap-6">
                                  <div className="flex items-center gap-2 text-[10px]">
                                     <span className="text-slate-500 uppercase font-black text-[8px]">Size:</span>
                                     <span className="text-slate-300 font-mono">{selectedEntry.response.body?.length || 0} bytes</span>
                                  </div>
                                  <div className="flex items-center gap-2 text-[10px]">
                                     <span className="text-slate-500 uppercase font-black text-[8px]">Decrypted:</span>
                                     <span className={selectedEntry.decrypted ? "text-emerald-400" : "text-slate-600"}>{selectedEntry.decrypted ? 'YES' : 'NO'}</span>
                                  </div>
                                  <div className="flex items-center gap-2 text-[10px]">
                                     <span className="text-slate-500 uppercase font-black text-[8px]">Status:</span>
                                     <span className={clsx("font-black font-mono", getStatusColor(selectedEntry.response.status_code))}>
                                       {selectedEntry.response.status_code}
                                     </span>
                                  </div>
                               </div>
                           </div>

                           <div className="p-4 rounded-lg bg-black/40 border border-white/5 min-h-[150px]">
                              <div className="flex justify-between items-center mb-4">
                                <label className="text-[8px] font-black text-slate-500 uppercase tracking-widest">Computed Body</label>
                                <button onClick={() => copyToClipboard(selectedEntry.response.body)} className="text-slate-600 hover:text-white transition-colors">
                                   <Copy size={10} />
                                </button>
                              </div>
                              <div className="text-[10px] overflow-x-auto pr-2">
                                 <BodyInspector body={selectedEntry.response.body} url={selectedEntry.request.url} />
                              </div>
                           </div>
                         </>
                       ) : (
                         <div className="p-8 rounded-lg border border-dashed border-white/5 flex flex-col items-center justify-center text-center opacity-30">
                            <Clock size={24} className="mb-2" />
                            <p className="text-[10px] font-black uppercase tracking-widest">Awaiting Response</p>
                         </div>
                       )}
                    </div>

                    {/* ── Semantic Correlation (if exists) ── */}
                    {selectedEntry.correlation_chain && (
                       <div className="p-4 rounded-lg bg-indigo-500/5 border border-indigo-500/20">
                          <div className="flex justify-between items-center mb-4">
                            <h4 className="text-[10px] font-black text-indigo-400 uppercase tracking-widest">Semantic Execution Chain</h4>
                            {selectedEntry.correlation_chain.preceding_ui?.length > 0 && (
                              <button 
                                onClick={async () => {
                                  try {
                                    await api.post(`/mobile/agent/mirror_fuzz/${deviceId}`, { traffic_id: selectedEntry.id });
                                    alert('Mirror Fuzz Triggered');
                                  } catch(e) {}
                                }}
                                className="px-3 py-1 bg-indigo-500 text-white text-[9px] font-black uppercase rounded shadow-glow-indigo/10"
                              >
                                🪄 Mirror & Fuzz
                              </button>
                            )}
                          </div>
                          <div className="space-y-3 relative pl-4 before:absolute before:left-1 before:top-1 before:bottom-1 before:w-0.5 before:bg-indigo-500/20">
                             {selectedEntry.correlation_chain.preceding_ui?.map((ui, i) => (
                               <div key={i} className="text-[10px] relative">
                                 <div className="absolute -left-[18px] top-1 w-2 h-2 rounded-full bg-blue-400 shadow-glow-cyan/50" />
                                 <span className="text-blue-400 font-black uppercase mr-2">UI Click</span>
                                 <span className="text-slate-300">{ui.idName} ({ui.view})</span>
                               </div>
                             ))}
                             {selectedEntry.correlation_chain.preceding_frida?.map((f, i) => (
                               <div key={i} className="text-[10px] relative">
                                 <div className="absolute -left-[18px] top-1 w-2 h-2 rounded-full bg-red-400 shadow-glow-red/50" />
                                 <span className="text-red-400 font-black uppercase mr-2">Hook Hit</span>
                                 <span className="text-slate-300">{f.tag} ({f.script})</span>
                               </div>
                             ))}
                             <div className="text-[10px] relative">
                                <div className="absolute -left-[18px] top-1 w-2 h-2 rounded-full bg-emerald-400 shadow-glow-cyan" />
                                <span className="text-emerald-400 font-black uppercase mr-2">Network Trigger</span>
                                <span className="text-slate-400 font-mono">{selectedEntry.request.method}</span>
                             </div>
                          </div>
                       </div>
                    )}
                  </div>
                )}

                {inspectorTab === 'headers' && (
                   <div className="space-y-6 animate-in fade-in slide-in-from-right-1 duration-300">
                      <div className="space-y-2">
                        <label className="text-[9px] font-black text-accent-primary uppercase tracking-widest">Request Headers</label>
                        <div className="bg-black/40 rounded-xl border border-white/5 overflow-hidden">
                           <table className="w-full text-[10px] font-mono">
                              <tbody>
                                 {Object.entries(selectedEntry.request.headers || {}).map(([k, v]) => (
                                   <tr key={k} className="border-b border-white/5 last:border-0">
                                      <td className="p-2 text-slate-500 border-r border-white/5 w-1/3 truncate">{k}</td>
                                      <td className="p-2 text-slate-300 break-all">{v}</td>
                                   </tr>
                                 ))}
                              </tbody>
                           </table>
                        </div>
                      </div>

                      {selectedEntry.response && (
                        <div className="space-y-2">
                          <label className="text-[9px] font-black text-purple-400 uppercase tracking-widest">Response Headers</label>
                          <div className="bg-black/40 rounded-xl border border-white/5 overflow-hidden">
                            <table className="w-full text-[10px] font-mono">
                                <tbody>
                                  {Object.entries(selectedEntry.response.headers || {}).map(([k, v]) => (
                                    <tr key={k} className="border-b border-white/5 last:border-0">
                                        <td className="p-2 text-slate-500 border-r border-white/5 w-1/3 truncate">{k}</td>
                                        <td className="p-2 text-slate-300 break-all">{v}</td>
                                    </tr>
                                  ))}
                                </tbody>
                            </table>
                          </div>
                        </div>
                      )}
                   </div>
                )}

                {inspectorTab === 'raw' && (
                  <div className="animate-in fade-in slide-in-from-right-1 duration-300">
                    <JSONViewer data={selectedEntry} />
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center opacity-20 space-y-4">
              <Eye size={64} />
              <p className="text-sm font-black uppercase tracking-widest">Select entry to inspect</p>
              <p className="text-[10px] font-mono uppercase">REALTIME_FORENSIC_HUD_ACTIVE</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
