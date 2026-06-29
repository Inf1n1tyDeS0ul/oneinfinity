import React, { useState, useEffect } from 'react'
import { Activity, Play, Square, Plus, RefreshCw, X } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import { relativeTime } from '../utils/time'
import clsx from 'clsx'

const EVENT_TYPE_COLORS = {
  VULNERABILITY_FOUND: 'bg-red-900/50 text-red-300',
  NEW_TARGET: 'bg-cyan-900/50 text-cyan-300',
  SCAN_PROGRESS: 'bg-blue-900/50 text-blue-300',
  EXPLOIT_ATTEMPTED: 'bg-orange-900/50 text-orange-300',
  HYPOTHESIS_CREATED: 'bg-purple-900/50 text-purple-300',
  AGENT_STATUS: 'bg-green-900/50 text-green-300',
}

// ── Tab: Daemon Control ──────────────────────────────────────────────────────
function DaemonControlTab() {
  const { addNotification } = useStore()
  const [status, setStatus] = useState(null)
  const [newTarget, setNewTarget] = useState('')
  const [loading, setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const r = await endpoints.daemonStatus()
      setStatus(r.data)
      setLastUpdated(new Date().toLocaleTimeString())
    } catch (e) { 
      addNotification(`Status load failed: ${e.message}`, 'error') 
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const handleStart = async () => {
    setLoading(true)
    try {
      await endpoints.daemonStart({})
      addNotification('Daemon started', 'success')
      load()
    } catch (e) { 
      addNotification(`Start failed: ${e.message}`, 'error') 
      setLoading(false)
    }
  }

  const handleStop = async () => {
    setLoading(true)
    try {
      await endpoints.daemonStop()
      addNotification('Daemon stopped', 'success')
      load()
    } catch (e) { 
      addNotification(`Stop failed: ${e.message}`, 'error') 
      setLoading(false)
    }
  }

  const handleAddTarget = async () => {
    if (!newTarget.trim()) return
    try {
      await endpoints.daemonAddTarget(newTarget.trim())
      addNotification(`Target added: ${newTarget.trim()}`, 'success')
      setNewTarget('')
      load()
    } catch (e) { addNotification(`Failed: ${e.message}`, 'error') }
  }

  const handleRemoveTarget = async (target) => {
    try {
      await endpoints.daemonRemoveTarget(target)
      addNotification(`Target removed: ${target}`, 'info')
      load()
    } catch (e) { addNotification(`Failed to remove: ${e.message}`, 'error') }
  }

  const running = status?.running || status?.status === 'running'

  return (
    <div className="flex flex-col gap-4">
      <div className="flex justify-between items-center">
        <button className="btn-secondary flex items-center gap-1.5" onClick={load} disabled={loading}>
          <RefreshCw size={11} className={clsx(loading && 'animate-spin')} /> Refresh
        </button>
        {lastUpdated && <span className="text-[10px] text-slate-500 font-mono">Last updated: {lastUpdated}</span>}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className={clsx('card p-4 flex flex-col', running ? 'border-accent-success/40' : '')}>
          <div className="flex items-center justify-between mb-4 gap-2">
            <span className="text-xs font-bold text-slate-300 uppercase tracking-tight truncate">Daemon Status</span>
            <span className={clsx('text-[10px] px-2 py-0.5 rounded-full uppercase font-bold flex-shrink-0', running ? 'bg-emerald-900/50 text-emerald-400' : 'bg-slate-700 text-slate-400')}>
              {running ? 'Running' : 'Stopped'}
            </span>
          </div>
          <div className="text-xs text-slate-500 mb-6 space-y-2">
            <div className="flex justify-between"><span>Targets:</span> <span className="text-slate-300 font-mono">{status?.targets?.length ?? 0}</span></div>
            <div className="flex justify-between"><span>Workers:</span> <span className="text-slate-300 font-mono">{status?.worker_count ?? 0}</span></div>
            <div className="flex justify-between"><span>Events:</span> <span className="text-slate-300 font-mono">{status?.events_processed ?? 0}</span></div>
          </div>
          <div className="mt-auto flex gap-2">
            <button className="btn-primary flex-1 flex items-center justify-center gap-1.5" onClick={handleStart} disabled={running || loading}>
              <Play size={11} /> Start
            </button>
            <button className="btn-danger flex-1 flex items-center justify-center gap-1.5" onClick={handleStop} disabled={!running || loading}>
              <Square size={11} /> Stop
            </button>
          </div>
        </div>

        <div className="card p-4 md:col-span-2">
          <div className="text-xs font-bold text-slate-300 mb-4 uppercase tracking-tight">Add Target to Pipeline</div>
          <div className="flex gap-2 mb-4">
            <input className="input flex-1" placeholder="e.g. example.com"
              value={newTarget} onChange={e => setNewTarget(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleAddTarget()} />
            <button className="btn-primary flex items-center gap-1.5 px-4" onClick={handleAddTarget} disabled={!newTarget.trim()}>
              <Plus size={12} /> Add
            </button>
          </div>
          <div className="bg-bg-primary/50 rounded-lg p-3 border border-bg-border/50">
            <div className="text-[10px] text-slate-600 font-bold uppercase mb-2">Active Targets</div>
            {status?.targets?.length > 0 ? (
              <div className="flex flex-wrap gap-1.5 max-h-32 overflow-auto scrollbar-thin">
                {status.targets.map((t, i) => (
                  <div key={i} className="group flex items-center gap-1.5 text-[10px] px-2 py-1 rounded bg-bg-secondary border border-bg-border text-accent-primary font-mono whitespace-nowrap">
                    {t}
                    <button onClick={() => handleRemoveTarget(t)} className="text-slate-500 hover:text-red-400 transition-colors ml-1 p-0.5" title="Remove target">
                      <X size={10} />
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-[10px] text-slate-500 italic py-2">No targets configured.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Tab: Workers ─────────────────────────────────────────────────────────────
function WorkersTab() {
  const { addNotification } = useStore()
  const [workers, setWorkers] = useState([])
  const [loading, setLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const r = await endpoints.daemonWorkers()
      setWorkers(r.data?.workers || r.data || [])
    } catch (e) { 
      addNotification(`Failed to load workers: ${e.message}`, 'error') 
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const toggle = async (name, enabled) => {
    try {
      if (enabled) await endpoints.daemonDisableWorker(name)
      else await endpoints.daemonEnableWorker(name)
      addNotification(`Worker ${name} ${enabled ? 'disabled' : 'enabled'}`, 'success')
      load()
    } catch (e) { addNotification(`Failed: ${e.message}`, 'error') }
  }

  const statusColor = (s) => {
    if (s === 'active' || s === 'running') return 'bg-emerald-900/50 text-emerald-400'
    if (s === 'idle') return 'bg-slate-700 text-slate-400'
    if (s === 'disabled') return 'bg-red-900/30 text-red-400'
    return 'bg-slate-700 text-slate-400'
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-500 font-medium">{workers.length} workers registered</span>
        <button className="btn-secondary flex items-center gap-1.5" onClick={load} disabled={loading}>
          <RefreshCw size={11} className={clsx(loading && 'animate-spin')} /> Refresh
        </button>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {workers.map((w, i) => (
          <div key={i} className="card p-4 border-l-2 border-l-bg-border transition-all hover:border-l-accent-primary flex flex-col">
            <div className="flex items-start justify-between mb-3 gap-2">
              <span className="text-xs font-bold text-slate-200 uppercase tracking-tight truncate leading-tight py-0.5" title={w.name}>{w.name}</span>
              <span className={clsx('text-[10px] px-2 py-0.5 rounded-full uppercase font-bold flex-shrink-0', statusColor(w.status))}>{w.status || 'unknown'}</span>
            </div>
            <div className="grid grid-cols-2 gap-y-1 gap-x-3 mb-4 text-[10px]">
              <div className="text-slate-500">Last run:</div>
              <div className="text-slate-400 text-right truncate">{relativeTime(w.last_run)}</div>
              <div className="text-slate-500">Findings:</div>
              <div className="text-slate-400 text-right">{w.findings ?? 0}</div>
            </div>
            <button
              className={clsx('text-[10px] px-2 py-2 rounded-lg uppercase font-bold w-full transition-all active:scale-[0.98]', w.status === 'disabled' ? 'bg-emerald-900/20 text-emerald-400 hover:bg-emerald-900/30 border border-emerald-900/50' : 'bg-bg-elevated text-slate-300 hover:bg-bg-muted border border-bg-border')}
              onClick={() => toggle(w.name, w.status !== 'disabled')}
            >
              {w.status === 'disabled' ? 'Enable Worker' : 'Disable Worker'}
            </button>
          </div>
        ))}
        {workers.length === 0 && (
          <div className="col-span-full text-xs text-slate-500 p-12 text-center bg-bg-secondary rounded-xl border border-bg-border border-dashed">
            {loading ? 'Discovering intelligence workers...' : 'No workers found. Start the daemon first.'}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Tab: Live Events ─────────────────────────────────────────────────────────
function LiveEventsTab() {
  const { addNotification } = useStore()
  const [events, setEvents] = useState([])
  const [stats, setStats] = useState({})
  const [typeFilter, setTypeFilter] = useState('')
  const [types, setTypes] = useState([])
  const [loading, setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const params = typeFilter ? { event_type: typeFilter, limit: 100 } : { limit: 100 }
      const [eRes, sRes] = await Promise.allSettled([
        endpoints.eventsRecent(params),
        endpoints.eventsStats(),
      ])
      if (eRes.status === 'fulfilled') setEvents(eRes.value.data?.events || eRes.value.data || [])
      if (sRes.status === 'fulfilled') setStats(sRes.value.data || {})
      setLastUpdated(new Date().toLocaleTimeString())
    } catch (e) { 
      addNotification(`Events load failed: ${e.message}`, 'error') 
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    endpoints.eventsTypes().then(r => setTypes(r.data?.types || r.data || [])).catch(() => {})
    load()
    const id = setInterval(load, 8000) // Slightly longer poll
    return () => clearInterval(id)
  }, [typeFilter])

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="stat-card p-4">
          <div className="stat-label">Total Events</div>
          <div className="stat-value text-2xl truncate" title={stats.total ?? 0}>{stats.total ?? 0}</div>
        </div>
        <div className="stat-card p-4">
          <div className="stat-label">Last Hour</div>
          <div className="stat-value text-2xl text-accent-primary truncate" title={stats.last_hour ?? 0}>{stats.last_hour ?? 0}</div>
        </div>
        <div className="stat-card p-4">
          <div className="stat-label">Event Types</div>
          <div className="stat-value text-2xl text-accent-purple truncate" title={stats.unique_types ?? types.length}>{stats.unique_types ?? types.length}</div>
        </div>
        <div className="stat-card p-4">
          <div className="stat-label">DLQ</div>
          <div className="stat-value text-2xl text-accent-danger truncate" title={stats.dlq_size ?? 0}>{stats.dlq_size ?? 0}</div>
        </div>
      </div>

      <div className="card overflow-hidden flex flex-col">
        <div className="flex items-center gap-3 p-4 border-b border-bg-border bg-bg-card/50">
          <select className="select w-48 bg-bg-secondary text-[10px] h-8 py-0" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
            <option value="">All Event Types</option>
            {types.map((t, i) => <option key={i} value={t}>{t}</option>)}
          </select>
          <button className="btn-secondary h-8 px-2" onClick={load} disabled={loading}>
            <RefreshCw size={11} className={clsx(loading && 'animate-spin')} />
          </button>
          {lastUpdated && <span className="text-[10px] text-slate-500 ml-auto uppercase font-mono tracking-tight">Updated: {lastUpdated}</span>}
        </div>
        <div className="overflow-auto max-h-[500px] scrollbar-thin">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="text-[10px] text-slate-500 uppercase tracking-wider bg-bg-primary/80 sticky top-0 z-10 backdrop-blur-sm border-b border-bg-border">
                <th className="py-3 px-4 font-bold w-48">Type</th>
                <th className="py-3 px-4 font-bold w-32">Source</th>
                <th className="py-3 px-4 font-bold w-32">Time</th>
                <th className="py-3 px-4 font-bold">Data Summary</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bg-border/50">
              {events.slice(0, 100).map((ev, i) => (
                <tr key={i} className="hover:bg-white/[0.03] transition-colors group">
                  <td className="py-2.5 px-4">
                    <span className={clsx('text-[10px] px-2 py-0.5 rounded font-mono font-bold flex-shrink-0 inline-block', EVENT_TYPE_COLORS[ev.event_type] || 'bg-slate-800 text-slate-400')}>
                      {ev.event_type || ev.type || '—'}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-slate-400 truncate max-w-[120px] text-[10px] uppercase font-bold tracking-tight">{ev.source || '—'}</td>
                  <td className="py-2.5 px-4 text-slate-500 whitespace-nowrap text-[10px] font-mono">{relativeTime(ev.timestamp)}</td>
                  <td className="py-2.5 px-4 text-slate-300 truncate max-w-md font-mono text-[10px] group-hover:text-slate-100">
                    {ev.data ? (typeof ev.data === 'string' ? ev.data : JSON.stringify(ev.data)).slice(0, 150) : '—'}
                  </td>
                </tr>
              ))}
              {events.length === 0 && (
                <tr><td colSpan={4} className="py-24 px-4 text-slate-600 text-center text-xs italic">{loading ? 'Intelligence feed initializing...' : 'No events yet. Start the daemon to begin collecting.'}</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}



// ── Main ─────────────────────────────────────────────────────────────────────
const TABS = ['Daemon Control', 'Workers', 'Live Events']

export default function LiveIntelligence() {
  const [tab, setTab] = useState(0)

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
        <Activity size={14} className="text-accent-primary" />
        Live Intelligence
      </h1>

      <div className="flex gap-1 border-b border-bg-border pb-1">
        {TABS.map((t, i) => (
          <button key={t} onClick={() => setTab(i)}
            className={clsx('px-3 py-1.5 text-xs rounded-t transition-colors',
              tab === i ? 'bg-accent-primary/20 text-accent-primary' : 'text-slate-400 hover:text-slate-200')}>
            {t}
          </button>
        ))}
      </div>

      {tab === 0 && <DaemonControlTab />}
      {tab === 1 && <WorkersTab />}
      {tab === 2 && <LiveEventsTab />}
    </div>
  )
}
