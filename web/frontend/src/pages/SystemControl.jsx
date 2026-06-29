import React, { useState, useEffect } from 'react'
import { 
  Shield, Zap, Activity, Cpu, Lock, Terminal, 
  Settings, Save, RefreshCw, AlertCircle, Clock, 
  ChevronRight, Globe, Database, Network
} from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'
import IntelligenceLayout from '../components/Intelligence/IntelligenceLayout'
import StatCard from '../components/Intelligence/StatCard'

export default function SystemControl() {
  const { addNotification } = useStore()
  const [safety, setSafety] = useState({ safe_mode: true, rate_limit_delay: 1.0, rate_limit_rps: 10 })
  const [waf, setWaf] = useState({ detections: 0, mutations: 0, successes: 0, by_type: {}, recent_waf_targets: [] })
  const [loading, setLoading] = useState(true)

  const load = async () => {
    try {
      const [s, w] = await Promise.all([
        endpoints.getSafetyConfig(),
        endpoints.getWafStats()
      ])
      setSafety(s.data || { safe_mode: true, rate_limit_delay: 1.0, rate_limit_rps: 10 })
      setWaf(w.data || { detections: 0, mutations: 0, successes: 0, by_type: {}, recent_waf_targets: [] })
    } catch (e) {
      console.error('Load failed', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const int = setInterval(load, 10000)
    return () => clearInterval(int)
  }, [])

  const toggleSafeMode = async () => {
    try {
      const next = !safety.safe_mode
      await endpoints.updateSafetyConfig({ safe_mode: next })
      setSafety({ ...safety, safe_mode: next })
      addNotification(`Safe Mode ${next ? 'Enabled' : 'Disabled'}`, next ? 'success' : 'warn')
    } catch (e) { addNotification('Update failed', 'error') }
  }

  const updateRateLimit = async (val) => {
    try {
      const delay = parseFloat(val)
      await endpoints.updateSafetyConfig({ rate_limit_delay: delay })
      setSafety({ ...safety, rate_limit_delay: delay })
    } catch (e) { addNotification('Update failed', 'error') }
  }

  const handleSaveApiKey = () => {
    const val = document.getElementById('api-key-input')?.value?.trim()
    if (val) {
      localStorage.setItem('oneinfinity_api_key', val)
      addNotification('API key saved! Reloading...', 'success')
      setTimeout(() => window.location.reload(), 1000)
    } else {
      localStorage.removeItem('oneinfinity_api_key')
      addNotification('API key cleared!', 'info')
    }
  }

  if (loading && !safety.rate_limit_rps) {
    return <div className="flex items-center justify-center h-64 text-slate-500 font-mono animate-pulse uppercase tracking-widest text-xs">SYNCHRONIZING SYSTEM STATE...</div>
  }

  return (
    <div className="flex flex-col gap-8">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 px-2">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-accent-primary/10 border border-accent-primary/20 shadow-glow-cyan/5">
              <Settings size={20} className="text-accent-primary" />
            </div>
            <div>
              <h1 className="text-xl font-black text-slate-100 tracking-tighter uppercase">Platform Control</h1>
              <div className="flex items-center gap-2 mt-1">
                <span className="flex items-center gap-1.5 text-[9px] font-bold text-accent-purple uppercase tracking-widest">
                  <div className="w-1.5 h-1.5 rounded-full bg-accent-purple animate-pulse" />
                  Kernel Telemetry Active
                </span>
                <span className="text-[9px] text-slate-600 font-mono font-medium opacity-50 italic">NODE: CORE_PRIMARY_REPLICA</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <IntelligenceLayout>
        {/* Core Safety Controls */}
        <div className="card md:col-span-2 lg:col-span-2">
          <div className="card-header border-b border-white/5">
            <span className="card-title text-accent-success flex items-center gap-2">
              <Shield size={16} /> 
              Mission Safeguards
            </span>
          </div>
          <div className="card-body flex flex-col gap-6 py-6">
            <div className="flex items-center justify-between p-4 rounded-2xl bg-bg-primary/40 border border-bg-border group hover:border-accent-success/30 transition-all">
              <div className="flex-1">
                <p className="text-sm font-bold text-slate-200">Autonomous Safe Mode</p>
                <p className="text-[10px] text-slate-500 leading-relaxed max-w-xs mt-1">
                  Prevents destructive payloads (rm, drop, format) from being dispatched by autonomous agents.
                </p>
              </div>
              <button 
                onClick={toggleSafeMode}
                className={clsx(
                  "relative w-14 h-7 rounded-full transition-all duration-500",
                  safety?.safe_mode ? 'bg-accent-success' : 'bg-red-950/40 border border-red-500/50'
                )}
              >
                <div className={clsx(
                  "absolute top-1 w-5 h-5 rounded-full transition-all duration-500 shadow-xl",
                  safety?.safe_mode ? 'left-8 bg-white' : 'left-1 bg-red-500'
                )} />
              </button>
            </div>
            
            <div className="space-y-4 px-2">
              <div className="flex justify-between items-end">
                 <label className="text-[10px] font-black uppercase tracking-widest text-slate-500">Rate Limit Delay</label>
                 <span className="text-xs font-mono font-bold text-accent-primary bg-accent-primary/10 px-2 py-0.5 rounded border border-accent-primary/20">
                    {safety?.rate_limit_delay ?? 1.0}s
                 </span>
              </div>
              <input 
                type="range" min="0.1" max="5.0" step="0.1" 
                value={safety?.rate_limit_delay ?? 1.0}
                onChange={(e) => updateRateLimit(e.target.value)}
                className="w-full h-1.5 bg-bg-elevated rounded-lg appearance-none cursor-pointer accent-accent-primary"
              />
              <div className="flex justify-between text-[9px] text-slate-600 font-bold uppercase tracking-tighter italic">
                <span>Fast / Aggressive</span>
                <span>Stealth / Throttled</span>
              </div>
            </div>
          </div>
        </div>

        {/* WAF Telemetry */}
        <div className="card md:col-span-2 lg:col-span-2">
          <div className="card-header border-b border-white/5">
             <span className="card-title text-accent-warn flex items-center gap-2">
               <Activity size={16} /> 
               WAF Evasion Telemetry
             </span>
          </div>
          <div className="card-body grid grid-cols-3 gap-3 py-6">
            <div className="flex flex-col items-center justify-center p-3 bg-bg-primary/40 border border-bg-border rounded-2xl group hover:border-red-500/30 transition-all">
              <span className="text-[9px] text-slate-600 font-black uppercase mb-1">Detections</span>
              <span className="text-2xl font-black text-red-500 group-hover:scale-110 transition-transform">{waf?.detections ?? 0}</span>
            </div>
            <div className="flex flex-col items-center justify-center p-3 bg-bg-primary/40 border border-bg-border rounded-2xl group hover:border-accent-purple/30 transition-all">
              <span className="text-[9px] text-slate-600 font-black uppercase mb-1">Mutations</span>
              <span className="text-2xl font-black text-accent-purple group-hover:scale-110 transition-transform">{waf?.mutations ?? 0}</span>
            </div>
            <div className="flex flex-col items-center justify-center p-3 bg-bg-primary/40 border border-bg-border rounded-2xl group hover:border-accent-success/30 transition-all">
              <span className="text-[9px] text-slate-600 font-black uppercase mb-1">Bypasses</span>
              <span className="text-2xl font-black text-accent-success group-hover:scale-110 transition-transform">{waf?.successes ?? 0}</span>
            </div>

            <div className="col-span-3 mt-2">
               <p className="text-[10px] font-black uppercase tracking-widest text-slate-500 mb-3 px-1 flex items-center gap-2">
                  <AlertCircle size={12} />
                  Target Friction History
               </p>
               {(!waf?.recent_waf_targets || waf.recent_waf_targets.length === 0) ? (
                 <div className="py-8 text-center text-[10px] text-slate-600 italic border border-dashed border-bg-border rounded-xl">
                    No interference detected in current session.
                 </div>
               ) : (
                 <div className="flex flex-col gap-1.5">
                   {waf.recent_waf_targets.slice(0, 4).map((t, i) => (
                     <div key={i} className="flex items-center gap-3 p-2 bg-bg-secondary/30 rounded-lg border border-bg-border/50 text-[11px] font-mono text-slate-400 group hover:border-accent-warn/20 transition-all">
                        <Globe size={12} className="text-slate-700" />
                        <span className="flex-1 truncate">{t}</span>
                        <ChevronRight size={12} className="text-slate-800 opacity-0 group-hover:opacity-100 transition-opacity" />
                     </div>
                   ))}
                 </div>
               )}
            </div>
          </div>
        </div>

        {/* System Credentials & Health */}
        <div className="card md:col-span-2 lg:col-span-1">
          <div className="card-header border-b border-white/5">
             <span className="card-title text-accent-primary flex items-center gap-2">
                <Lock size={16} /> 
                Terminal Auth
             </span>
          </div>
          <div className="card-body py-4 flex flex-col gap-4">
             <p className="text-[10px] text-slate-500 leading-relaxed italic">
                Framework uses Bearer Token authentication. If auto-sync fails, manual override is required.
             </p>
             <div className="relative group">
                <input
                  type="password"
                  defaultValue={localStorage.getItem('oneinfinity_api_key') || ''}
                  placeholder="X-API-KEY Override"
                  id="api-key-input"
                  className="w-full bg-bg-primary/50 border border-bg-border rounded-xl pl-10 pr-4 py-3 text-xs font-mono text-accent-primary focus:border-accent-primary outline-none transition-all shadow-inner"
                />
                <Lock size={14} className="absolute left-3 top-3.5 text-slate-600 group-focus-within:text-accent-primary transition-colors" />
             </div>
             <button
               onClick={handleSaveApiKey}
               className="btn-primary w-full justify-center h-10 rounded-xl"
             >
               <Save size={14} /> Synchronize Key
             </button>
          </div>
        </div>

        {/* Global Cluster Stats */}
        <div className="card md:col-span-2 lg:col-span-3">
          <div className="card-header border-b border-white/5">
             <span className="card-title text-slate-400 flex items-center gap-2">
                <Activity size={16} /> 
                Cluster Intelligence Infrastructure
             </span>
          </div>
          <div className="card-body py-6">
             <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
               <ClusterHealthItem label="API Interface" status="STABLE" icon={Globe} color="text-emerald-400" />
               <ClusterHealthItem label="Redis Bus" status="VIBRANT" icon={Network} color="text-cyan-400" />
               <ClusterHealthItem label="Postgres SQL" status="PERSISTED" icon={Database} color="text-accent-purple" />
               <ClusterHealthItem label="Neural Brain" status="EVOLVING" icon={Cpu} color="text-accent-warn" />
             </div>
          </div>
        </div>
      </IntelligenceLayout>
    </div>
  )
}

function ClusterHealthItem({ label, status, icon: Icon, color }) {
  return (
    <div className="relative p-4 rounded-2xl bg-bg-primary/20 border border-bg-border group hover:bg-bg-primary/40 transition-all overflow-hidden">
      <div className="flex flex-col gap-2 relative z-10">
        <Icon size={18} className={clsx("opacity-40", color)} />
        <span className="text-[9px] font-black text-slate-600 uppercase tracking-widest">{label}</span>
        <div className="flex items-center gap-2">
          <div className={clsx("w-1.5 h-1.5 rounded-full animate-pulse", color.replace('text-', 'bg-'))} />
          <span className={clsx("text-xs font-black uppercase font-mono tracking-tighter", color)}>{status}</span>
        </div>
      </div>
      <Icon size={80} className={clsx("absolute -right-6 -bottom-6 opacity-[0.03] transition-all group-hover:scale-110", color)} />
    </div>
  )
}
