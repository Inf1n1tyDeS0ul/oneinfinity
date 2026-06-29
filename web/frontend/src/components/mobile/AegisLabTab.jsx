import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Shield, Activity, Zap, Search, Cpu, Database, Play, Square } from 'lucide-react';
import clsx from 'clsx';
import { endpoints } from '../../utils/api';

export default function AegisLabTab({ report, appId, deviceId }) {
  const [signals, setSignals] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [auditRunning, setAuditRunning] = useState(false);
  const [moduleStatus, setModuleStatus] = useState({
    logcat: 'standby',
    sandbox: 'standby',
    memory: 'standby',
    artifacts: 'standby'
  });
  const scrollRef = useRef(null);

  // Replay buffered signals on mount (signals fired before component mounted)
  useEffect(() => {
    if (!appId) return;
    endpoints.forensicSignals(appId).then(r => {
      const buffered = (r.data || []).map((s, i) => ({
        id: i + '_replay',
        timestamp: s.timestamp ? new Date(s.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString(),
        ...s
      }));
      if (buffered.length > 0) {
        setSignals(buffered.slice(0, 100).reverse());
        const last = buffered[buffered.length - 1];
        const msg = (last?.payload || '').toUpperCase();
        if (msg.includes('INITIALIZED')) setIsScanning(true);
        if (msg.includes('FINISHED') || msg.includes('TEARDOWN')) setIsScanning(false);
      }
    }).catch(() => {});
  }, [appId]);

  useEffect(() => {
    const handleSignal = (e) => {
      // Support both explicit FORENSIC_SIGNAL events and generic logs that might be forensic
      const signal = e.detail;
      if (signal.appId === appId || signal.scan_id === report?.scan_id || signal.source === 'aegis') {
        setSignals(prev => [
          {
            id: Date.now() + Math.random(),
            timestamp: new Date().toLocaleTimeString(),
            ...signal
          },
          ...prev
        ].slice(0, 100)); // Keep last 100

        // Update module status based on signal type or payload
        const type = signal.type?.toLowerCase();
        const msg = (signal.payload || signal.message || '').toUpperCase();

        if (type === 'logcat' || msg.includes('LOGCAT')) {
          setModuleStatus(prev => ({ ...prev, logcat: msg.includes('START') || msg.includes('ACTIVE') ? 'active' : msg.includes('COMPLETE') ? 'complete' : prev.logcat }));
        }
        if (type === 'sandbox' || msg.includes('SANDBOX')) {
          setModuleStatus(prev => ({ ...prev, sandbox: msg.includes('START') || msg.includes('ACTIVE') ? 'active' : msg.includes('COMPLETE') ? 'complete' : prev.sandbox }));
        }
        if (type === 'memory' || msg.includes('MEMORY')) {
          setModuleStatus(prev => ({ ...prev, memory: msg.includes('START') || msg.includes('ACTIVE') ? 'active' : msg.includes('COMPLETE') ? 'complete' : prev.memory }));
        }
        if (type === 'artifacts' || msg.includes('ARTIFACTS') || msg.includes('FILESYSTEM')) {
          setModuleStatus(prev => ({ ...prev, artifacts: msg.includes('START') || msg.includes('ACTIVE') ? 'active' : msg.includes('COMPLETE') ? 'complete' : prev.artifacts }));
        }
        
        // Handle generic SYSTEM signals that might indicate module state
        if (signal.type === 'SYSTEM') {
           if (msg.includes('INITIALIZED') || msg.includes('AUDIT_START')) { setIsScanning(true); setAuditRunning(true); }
           if (msg.includes('FINISHED') || msg.includes('TEARDOWN') || msg.includes('COMPLETE') || msg.includes('ERROR')) {
             setIsScanning(false);
             setAuditRunning(false);
           }
        }
      }
    };

    window.addEventListener('FORENSIC_SIGNAL', handleSignal);
    return () => window.removeEventListener('FORENSIC_SIGNAL', handleSignal);
  }, [appId, report]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = 0;
    }
  }, [signals]);

  const runAudit = async () => {
    if (!deviceId || !appId || auditRunning) return;
    setAuditRunning(true);
    setModuleStatus({ logcat: 'standby', sandbox: 'standby', memory: 'standby', artifacts: 'standby' });
    try {
      await endpoints.forensicAudit(appId, deviceId);
    } catch (err) {
      setAuditRunning(false);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-in fade-in duration-500">
      <div className="lg:col-span-2 flex flex-col gap-4">
        {/* Live Terminal */}
        <div className="flex flex-col h-[500px] glass-card bg-black/80 border-cyan-500/20 shadow-glow-cyan/5 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 bg-bg-secondary/50 border-b border-white/5">
            <div className="flex items-center gap-2">
              <Terminal size={14} className="text-cyan-400" />
              <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Live Forensic Sentinel</span>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5">
                <div className={clsx("w-1.5 h-1.5 rounded-full", (signals.length > 0 || isScanning) ? "bg-cyan-500 animate-pulse" : "bg-slate-700")} />
                <span className="text-[9px] font-mono text-slate-500 uppercase">
                  {(signals.length > 0 || isScanning) ? 'Streaming' : 'Standby'}
                </span>
              </div>
            </div>
          </div>

          <div 
            ref={scrollRef}
            className="flex-1 p-4 font-mono text-[11px] overflow-auto scrollbar-thin scrollbar-thumb-slate-800"
          >
            <div className="text-cyan-500/50 mb-4 flex items-center gap-2">
              <span className="px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-[9px] font-black">SYSTEM</span>
              AEGIS_DIAGNOSTIC_ENV_INITIALIZED
            </div>

            {signals.map((s) => (
              <div key={s.id} className="mb-2 group animate-in slide-in-from-left-2 duration-300">
                <div className="flex items-start gap-3">
                  <span className="text-slate-600 shrink-0 select-none">[{s.timestamp}]</span>
                  <div className={clsx(
                    "flex-1 pl-3 border-l-2 transition-colors",
                    s.level === 'error' ? "border-red-500/50 text-red-400" :
                    s.level === 'success' ? "border-emerald-500/50 text-emerald-400" :
                    s.level === 'warn' ? "border-orange-500/50 text-orange-400" :
                    "border-purple-500/50 text-slate-300"
                  )}>
                    <span className="font-black mr-2">[{s.type || 'SIGNAL'}]</span>
                    {s.payload || s.message}
                  </div>
                </div>
              </div>
            ))}

            {signals.length === 0 && (
              <div className="h-full flex flex-col items-center justify-center opacity-20">
                <Activity size={48} className="mb-4 text-cyan-500 animate-pulse" />
                <p className="text-sm font-bold uppercase tracking-[0.2em]">Waiting for forensic telemetry...</p>
                <p className="text-[10px] mt-2 text-slate-500">Attach device and start audit to begin capture</p>
              </div>
            )}
          </div>

          <div className="px-4 py-2 bg-black/40 border-t border-white/5 flex items-center justify-between">
            <div className="text-[9px] font-mono text-slate-600">
              Session ID: <span className="text-slate-400">{report?.scan_id || 'LOCAL-DEV'}</span>
            </div>
            <button 
              onClick={() => setSignals([])}
              className="text-[9px] font-black text-slate-500 hover:text-red-400 uppercase transition-colors"
            >
              Clear Buffer
            </button>
          </div>
        </div>
      </div>

      <div className="space-y-6">
        {/* Status HUD */}
        <div className="glass-card p-5 space-y-4">
          <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-2">
            <Shield size={12} className="text-cyan-400" /> Sentinel Status
          </h3>
          
          <div className="grid gap-2">
            <StatusItem label="Logcat Monitor" status={moduleStatus.logcat} />
            <StatusItem label="Sandbox Audit" status={moduleStatus.sandbox} />
            <StatusItem label="Memory Sentry" status={moduleStatus.memory} />
            <StatusItem label="Artifact Hunter" status={moduleStatus.artifacts} />
          </div>
        </div>


        {/* Quick Insights */}
        <div className="glass-card p-5 border-l-4 border-l-cyan-500 bg-cyan-500/5">
           <h3 className="text-[10px] font-black text-cyan-400 uppercase tracking-widest mb-4 flex items-center gap-2">
              <Zap size={12} /> Real-time Intel
           </h3>
           <div className="space-y-3">
              <div className="text-[11px] text-slate-300 leading-relaxed">
                The Aegis Lab tab provides a live view of forensic signals captured directly from the device.
              </div>
              <div className="p-3 rounded-lg bg-black/40 border border-white/5 font-mono text-[9px] text-slate-400">
                <div className="text-cyan-500 mb-1 font-bold">Heuristic Engine Active</div>
                Watching for: PII leaks, Auth tokens, Insecure IPC, Path traversal attempts.
              </div>
           </div>
        </div>

        <div className="glass-card p-5">
           <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3">Live Audit</h3>
           {deviceId ? (
             <button
               onClick={runAudit}
               disabled={auditRunning}
               className={clsx(
                 "w-full flex items-center justify-center gap-2 py-3 rounded-xl border font-black text-[10px] uppercase tracking-widest transition-all",
                 auditRunning
                   ? "border-cyan-500/30 bg-cyan-500/10 text-cyan-400 cursor-not-allowed animate-pulse"
                   : "border-cyan-500/40 bg-cyan-500/5 text-cyan-300 hover:bg-cyan-500/20 hover:border-cyan-400"
               )}
             >
               {auditRunning ? <><Square size={12} className="animate-spin" /> Audit Running...</> : <><Play size={12} /> Run Aegis Audit</>}
             </button>
           ) : (
             <div className="text-[10px] text-slate-600 text-center py-3">
               Select a device to enable live audit
             </div>
           )}
           <div className="grid grid-cols-2 gap-2 mt-3">
              <ToolButton icon={Search} label="Dump Log" />
              <ToolButton icon={Database} label="File Map" />
              <ToolButton icon={Cpu} label="Mem Check" />
              <ToolButton icon={Activity} label="Tracer" />
           </div>
        </div>
      </div>
    </div>
  );
}

function StatusItem({ label, status }) {
  return (
    <div className="flex items-center justify-between p-2 rounded bg-white/5 border border-white/5">
      <span className="text-[10px] font-bold text-slate-400 uppercase">{label}</span>
      <div className={clsx(
        "px-2 py-0.5 rounded text-[8px] font-black uppercase transition-all duration-300",
        status === 'active' ? "bg-cyan-500/20 text-cyan-400 animate-pulse shadow-[0_0_10px_rgba(34,211,238,0.2)]" : 
        status === 'complete' ? "bg-emerald-500/20 text-emerald-400" :
        "bg-slate-800 text-slate-600"
      )}>
        {status}
      </div>
    </div>
  );
}

function ToolButton({ icon: Icon, label }) {
  return (
    <button className="flex flex-col items-center gap-2 p-3 rounded-xl bg-bg-secondary/40 border border-white/5 hover:border-cyan-500/30 hover:bg-cyan-500/5 transition-all group">
      <Icon size={16} className="text-slate-500 group-hover:text-cyan-400 transition-colors" />
      <span className="text-[9px] font-black text-slate-600 group-hover:text-slate-400 uppercase tracking-tighter">{label}</span>
    </button>
  );
}
