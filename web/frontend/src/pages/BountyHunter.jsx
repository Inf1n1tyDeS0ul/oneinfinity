import React, { useState, useEffect, useMemo } from 'react'
import { Trophy, Play, Square, RefreshCw, Activity, Target, Zap, Bot, ShieldAlert, FileText, ChevronRight } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import { relativeTime } from '../utils/time'
import clsx from 'clsx'
import HunterHUD from '../components/BountyHunter/HunterHUD'
import PlatformGrid from '../components/BountyHunter/PlatformGrid'

const SEV_COLORS = { critical: 'text-red-500', high: 'text-orange-500', medium: 'text-yellow-500', low: 'text-blue-500', info: 'text-slate-500' }
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const DEPTHS = ['shallow', 'normal', 'deep']

// ── Tab: Control ─────────────────────────────────────────────────────────────
function ControlTab({ onSessionChange }) {
  const { addNotification } = useStore()
  const [platform, setPlatform] = useState('hackerone')
  const [handle, setHandle] = useState('')
  const [depth, setDepth] = useState('normal')
  const [starting, setStarting] = useState(false)
  const [sessions, setSessions] = useState([])
  const [loading, setLoading] = useState(false)
  const [stats, setStats] = useState(null)
  const [autoHunter, setAutoHunter] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const [statusRes, statsRes, configRes] = await Promise.all([
        endpoints.hunterStatus(),
        endpoints.hunterStats(),
        endpoints.getHunterConfig()
      ])
      const s = statusRes.data?.session
      setSessions(s ? [s] : [])
      setStats(statsRes.data)
      setAutoHunter(configRes.data?.auto_hunter ?? false)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const id = setInterval(load, 15000)
    return () => clearInterval(id)
  }, [])

  const handleStart = async () => {
    if (!handle.trim()) return addNotification('Enter a program handle', 'error')
    setStarting(true)
    try {
      await endpoints.hunterStart({ platform, handle: handle.trim(), scan_depth: depth })
      addNotification('Predator deployed!', 'success')
      setHandle('')
      load()
      onSessionChange && onSessionChange()
    } catch (e) { addNotification(`Failed: ${e.message}`, 'error') }
    finally { setStarting(false) }
  }

  const handleStop = async (sessionId) => {
    try {
      await endpoints.hunterStop(sessionId)
      addNotification('Hunt aborted', 'warn')
      load()
      onSessionChange && onSessionChange()
    } catch (e) { addNotification(`Failed: ${e.message}`, 'error') }
  }

  const toggleAutoHunter = async () => {
    try {
      const next = !autoHunter
      await endpoints.updateHunterConfig({ auto_hunter: next })
      setAutoHunter(next)
      addNotification(`Auto-Hunter ${next ? 'Active' : 'Disabled'}`, next ? 'success' : 'info')
    } catch (e) { addNotification('Update failed', 'error') }
  }

  return (
    <div className="flex flex-col gap-6">
      <HunterHUD stats={stats} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 flex flex-col gap-4">
           <div className="glass-card p-6">
              <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-6 flex items-center gap-2">
                 <Activity size={12} className="text-accent-primary" /> Target Selection
              </h3>
              <PlatformGrid selected={platform} onSelect={setPlatform} disabled={starting} />
              
              <div className="mt-6 flex flex-col gap-4">
                 <div className="flex gap-2">
                    <input 
                      className="input flex-1 h-11 bg-bg-primary/50 border border-bg-border focus:border-accent-primary text-sm font-bold placeholder:text-slate-600" 
                      placeholder="Enter Program Handle (e.g. ask-security)"
                      value={handle} onChange={e => setHandle(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && handleStart()}
                    />
                    <select className="bg-bg-primary/50 border border-bg-border rounded-xl px-4 text-[10px] font-black uppercase text-slate-400 outline-none focus:border-accent-primary"
                      value={depth} onChange={e => setDepth(e.target.value)}>
                      {DEPTHS.map(d => <option key={d} value={d}>{d} DEPTH</option>)}
                    </select>
                 </div>
                 
                 <div className="flex items-center justify-between gap-4">
                    <div className="flex items-center gap-2 px-1">
                       <button 
                         onClick={toggleAutoHunter}
                         className={clsx(
                           "relative w-10 h-5 rounded-full transition-all duration-500",
                           autoHunter ? 'bg-accent-primary' : 'bg-slate-800'
                         )}
                       >
                         <div className={clsx(
                           "absolute top-1 w-3 h-3 rounded-full transition-all duration-500",
                           autoHunter ? 'left-6 bg-white' : 'left-1 bg-slate-500'
                         )} />
                       </button>
                       <span className="text-[10px] font-black text-slate-500 uppercase tracking-tight">Auto-Hunter AI</span>
                    </div>
                    <button className="btn-primary flex-1 justify-center h-11 rounded-xl shadow-glow-cyan/10" onClick={handleStart} disabled={starting || !handle.trim()}>
                      <Zap size={14} className={clsx(starting && "animate-pulse")} />
                      {starting ? 'Deploying...' : 'Deploy Apex Predator'}
                    </button>
                 </div>
              </div>
           </div>
        </div>

        <div className="flex flex-col gap-4">
          <div className="glass-card p-6 flex-1 flex flex-col">
             <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-4 flex items-center gap-2">
                <Target size={12} className="text-accent-secondary" /> Live Mission Pulse
             </h3>
             
             {sessions.length === 0 ? (
               <div className="flex-1 flex flex-col items-center justify-center text-slate-600 opacity-40 italic">
                  <Bot size={48} className="mb-3" />
                  <p className="text-[10px] font-bold uppercase tracking-widest">No active deployments</p>
               </div>
             ) : (
               <div className="space-y-4">
                  {sessions.map(s => (
                    <div key={s.session_id || s.id} className="p-4 rounded-2xl bg-bg-primary/40 border border-slate-800 group hover:border-accent-primary/30 transition-all">
                       <div className="flex justify-between items-start mb-2">
                          <span className="text-[10px] font-black text-accent-primary uppercase tracking-tighter">{s.platform}</span>
                          <span className="text-[8px] font-mono text-slate-600">{relativeTime(s.started_at)}</span>
                       </div>
                       <div className="text-sm font-black text-slate-200 truncate group-hover:text-accent-primary transition-colors">{s.handle || s.program}</div>
                       <div className="mt-4 flex items-center justify-between">
                          <div className="flex items-center gap-2">
                             <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                             <span className="text-[9px] font-bold text-emerald-400 uppercase tracking-widest">{s.status}</span>
                          </div>
                          <button className="p-1.5 rounded-lg bg-red-500/10 text-red-500 border border-red-500/20 hover:bg-red-500/20" onClick={() => handleStop(s.session_id || s.id)}>
                             <Square size={12} />
                          </button>
                       </div>
                    </div>
                  ))}
               </div>
             )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Tab: Findings ─────────────────────────────────────────────────────────────
function FindingsTab() {
  const { addNotification } = useStore()
  const [sessions, setSessions] = useState([])
  const [selectedSession, setSelectedSession] = useState('')
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    endpoints.hunterSessions()
      .then(r => {
        const list = r.data?.sessions || []
        setSessions(list)
        if (list.length > 0 && !selectedSession) setSelectedSession(list[0].session_id || list[0].id)
      })
      .catch(() => {})
  }, [])

  const loadFindings = async () => {
    if (!selectedSession) return
    setLoading(true)
    try {
      const r = await endpoints.hunterFindings(selectedSession)
      setFindings(r.data?.findings || r.data || [])
    } catch (e) { 
      addNotification(`Failed to load findings: ${e.message}`, 'error') 
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadFindings() }, [selectedSession])

  const sortedFindings = useMemo(() => {
    return [...findings].sort((a, b) => {
      const aVal = SEV_ORDER[a.severity] ?? 99
      const bVal = SEV_ORDER[b.severity] ?? 99
      if (aVal !== bVal) return aVal - bVal
      return (b.bounty_score || 0) - (a.bounty_score || 0)
    })
  }, [findings])

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col md:flex-row md:items-center gap-3 bg-bg-secondary/40 border border-bg-border p-3 rounded-2xl">
        <div className="flex-1 flex items-center gap-3 px-3">
          <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Active Archives</span>
          <select className="bg-bg-primary/50 border border-bg-border rounded-xl px-3 py-2 text-[10px] font-bold uppercase text-slate-400 outline-none focus:border-accent-primary flex-1 max-w-md" 
            value={selectedSession} onChange={e => setSelectedSession(e.target.value)}>
            <option value="">— Select Hunt Sector —</option>
            {sessions.map(s => (
              <option key={s.session_id || s.id} value={s.session_id || s.id}>
                {s.platform.toUpperCase()} :: {s.handle || s.program}
              </option>
            ))}
          </select>
        </div>
        <button className="p-2.5 rounded-xl bg-bg-primary/50 border border-bg-border text-slate-500 hover:text-accent-primary transition-all shadow-sm" onClick={loadFindings}>
          <RefreshCw size={14} className={clsx(loading && 'animate-spin')} />
        </button>
      </div>

      <div className="grid grid-cols-1 gap-3">
        {sortedFindings.length === 0 ? (
          <div className="glass-card py-20 flex flex-col items-center justify-center opacity-40">
             <Bot size={48} className="mb-4 text-slate-700" />
             <p className="text-sm font-bold uppercase tracking-widest text-slate-500">
               {selectedSession ? 'No Bounty Artifacts Detected' : 'Sector Selection Required'}
             </p>
          </div>
        ) : (
          sortedFindings.map((f, i) => (
            <div key={i} className="glass-card p-5 group hover:border-slate-700 transition-all duration-300">
               <div className="flex flex-col lg:flex-row lg:items-center gap-6">
                  <div className="flex items-center gap-4 min-w-[150px]">
                     <span className={clsx(
                       "px-2.5 py-1 rounded-lg text-[10px] font-black uppercase border",
                       f.severity === 'critical' ? 'bg-red-500/10 text-red-500 border-red-500/20' : 
                       f.severity === 'high' ? 'bg-orange-500/10 text-orange-500 border-orange-500/20' :
                       f.severity === 'medium' ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' :
                       'bg-blue-500/10 text-blue-500 border-blue-500/20'
                     )}>
                       {f.severity}
                     </span>
                     <div className="flex flex-col">
                        <span className="text-[10px] font-mono text-slate-500 uppercase tracking-tighter">{f.type || f.vuln_type}</span>
                        <span className="text-[10px] font-black text-emerald-400 mt-0.5">{f.estimated_payout || '$TBD'}</span>
                     </div>
                  </div>

                  <div className="flex-1 min-w-0">
                     <div className="text-sm font-black text-slate-200 group-hover:text-accent-primary transition-colors truncate">{f.title || 'Vulnerability Pattern detected'}</div>
                     <div className="text-[10px] text-slate-500 font-mono mt-1 truncate">{f.endpoint || f.url}</div>
                  </div>

                  <div className="flex items-center gap-8">
                     <div className="flex flex-col items-end min-w-[100px]">
                        <span className="text-[9px] font-black text-slate-600 uppercase tracking-widest">Bounty Score</span>
                        <div className="w-24 h-1.5 bg-slate-900 rounded-full mt-1.5 overflow-hidden">
                           <div className="h-full bg-accent-primary shadow-glow-cyan" style={{ width: `${f.bounty_score || 0}%` }} />
                        </div>
                     </div>

                     <div className="flex items-center gap-2">
                        <button 
                          className="p-2 rounded-xl bg-bg-elevated border border-bg-border text-accent-primary hover:bg-accent-primary/10 hover:border-accent-primary transition-all"
                          onClick={() => endpoints.generateReport(f.id).then(() => addNotification('Report generated!', 'success'))}
                          title="Generate Submission Report"
                        >
                          <FileText size={16} />
                        </button>
                        <ChevronRight size={16} className="text-slate-700 group-hover:text-white transition-all group-hover:translate-x-1" />
                     </div>
                  </div>
               </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

// ── Tab: Programs ─────────────────────────────────────────────────────────────
function ProgramsTab() {
  const { addNotification } = useStore()
  const [programs, setPrograms] = useState([])
  const [scanning, setScanning] = useState({})
  const [loading, setLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const r = await endpoints.hunterPrograms()
      setPrograms(r.data?.programs || r.data || [])
    } catch (e) { 
      addNotification(`Failed to load programs: ${e.message}`, 'error') 
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const scanProgram = async (prog) => {
    const key = prog.handle || prog.id
    setScanning(s => ({ ...s, [key]: true }))
    try {
      await endpoints.hunterScan(prog.handle || prog.domain || prog.target, { platform: prog.platform })
      addNotification(`Scan started for ${key}`, 'success')
    } catch (e) { addNotification(`Failed: ${e.message}`, 'error') }
    finally { setScanning(s => ({ ...s, [key]: false })) }
  }

  return (
    <div className="flex flex-col gap-6">
       <div className="flex items-center justify-between px-2">
          <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Cached Program Intel ({programs.length})</span>
          <button className="p-2 rounded-xl bg-bg-secondary border border-bg-border text-slate-500 hover:text-white transition-all shadow-sm" onClick={load}>
            <RefreshCw size={14} className={clsx(loading && 'animate-spin')} />
          </button>
       </div>

       <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {programs.length === 0 ? (
            <div className="col-span-full glass-card py-20 flex flex-col items-center justify-center opacity-40">
               <ShieldAlert size={48} className="mb-4 text-slate-700" />
               <p className="text-sm font-bold uppercase tracking-widest text-slate-500">Discovery Engine Offline</p>
            </div>
          ) : (
            programs.map((p, i) => {
              const key = p.handle || p.id || i
              return (
                <div key={i} className="glass-card p-5 group hover:border-slate-700 transition-all flex flex-col gap-4">
                   <div className="flex justify-between items-start">
                      <span className="text-[9px] font-black text-slate-600 uppercase border border-slate-800 px-1.5 py-0.5 rounded">{p.platform}</span>
                      <span className="text-[9px] font-mono text-slate-600 italic">{relativeTime(p.last_scanned)}</span>
                   </div>
                   <div className="flex-1">
                      <div className="text-base font-black text-accent-primary tracking-tight uppercase truncate mb-1">{p.handle || p.name}</div>
                      <p className="text-[10px] text-slate-500 line-clamp-2 leading-relaxed">
                         {Array.isArray(p.scope) ? p.scope.join(', ') : (p.scope || 'Broad spectrum wildcard assets')}
                      </p>
                   </div>
                   <button 
                     className="btn-primary w-full justify-center h-10 rounded-xl"
                     onClick={() => scanProgram(p)} 
                     disabled={scanning[key]}
                   >
                     <Zap size={14} className={clsx(scanning[key] && "animate-spin")} />
                     {scanning[key] ? 'Analyzing...' : 'Execute Infiltration'}
                   </button>
                </div>
              )
            })
          )}
       </div>
    </div>
  )
}


// ── Main ─────────────────────────────────────────────────────────────────────
const TABS = [
  { id: 'control',  label: 'Mission Control', icon: Activity },
  { id: 'findings', label: 'Bounty Vault',    icon: Trophy },
  { id: 'programs', label: 'Infiltration Registry', icon: Target },
]

export default function BountyHunter() {
  const [tab, setTab] = useState('control')
  const [sessionRefresh, setSessionRefresh] = useState(0)

  return (
    <div className="flex flex-col gap-6">
      {/* Header Area */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 px-2">
        <div className="flex items-center gap-4">
           <div className="p-2.5 rounded-xl bg-accent-warn/10 border border-accent-warn/20 shadow-glow-orange/5">
              <Trophy size={20} className="text-accent-warn" />
           </div>
           <div>
              <h1 className="text-xl font-black text-slate-100 tracking-tighter uppercase">Apex Hunter Command</h1>
              <div className="flex items-center gap-2 mt-1">
                <span className="flex items-center gap-1.5 text-[9px] font-bold text-emerald-400 uppercase tracking-widest">
                  <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                  Asset Acquisition Active
                </span>
                <span className="text-[9px] text-slate-600 font-mono font-medium">MODE: AGGRESSIVE_DISCOVERY</span>
              </div>
           </div>
        </div>
      </div>

      {/* Navigation Capsule */}
      <div className="flex p-1 bg-bg-secondary/40 rounded-2xl border border-bg-border w-fit self-center md:self-start">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={clsx(
              "flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all duration-300",
              tab === t.id 
                ? "bg-bg-elevated text-accent-warn border border-slate-700/50 shadow-glow-orange/10" 
                : "text-slate-500 hover:text-slate-300"
            )}
          >
            <t.icon size={14} />
            <span className="hidden sm:inline">{t.label}</span>
          </button>
        ))}
      </div>

      <div className="animate-in fade-in slide-in-from-bottom-2 duration-500">
        {tab === 'control'  && <ControlTab onSessionChange={() => setSessionRefresh(n => n + 1)} />}
        {tab === 'findings' && <FindingsTab key={sessionRefresh} />}
        {tab === 'programs' && <ProgramsTab />}
      </div>
    </div>
  )
}
