import React, { useState, useEffect } from 'react'
import { Activity, Play, Square, Plus, RefreshCw } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

function relativeTime(iso) {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

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

  const running = status?.running || status?.status === 'running'

  return (
    <div className="flex flex-col gap-4">
      <div className="flex justify-between items-center">
        <button className="btn-secondary flex items-center gap-1" onClick={load} disabled={loading}>
          <RefreshCw size={11} className={clsx(loading && 'animate-spin')} /> Refresh
        </button>
        {lastUpdated && <span className="text-[10px] text-slate-500">Last updated: {lastUpdated}</span>}
      </div>

      <div className="grid grid-cols-3 gap-3">
        <div className={clsx('card col-span-1', running ? 'border-green-600/40' : '')}>
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-semibold text-slate-300">Daemon Status</span>
            <span className={clsx('text-xs px-2 py-0.5 rounded-full', running ? 'bg-green-900/50 text-green-400' : 'bg-slate-700 text-slate-400')}>
              {running ? 'Running' : 'Stopped'}
            </span>
          </div>
          <div className="text-xs text-slate-500 mb-3 space-y-1">
            <div>Targets: <span className="text-slate-300 font-mono">{status?.targets?.length ?? 0}</span></div>
            <div>Workers: <span className="text-slate-300 font-mono">{status?.worker_count ?? 0}</span></div>
            <div>Events processed: <span className="text-slate-300 font-mono">{status?.events_processed ?? 0}</span></div>
          </div>
          <div className="flex gap-2">
            <button className="btn-primary flex items-center gap-1" onClick={handleStart} disabled={running || loading}>
              <Play size={11} /> Start
            </button>
            <button className="btn-danger flex items-center gap-1" onClick={handleStop} disabled={!running || loading}>
              <Square size={11} /> Stop
            </button>
          </div>
        </div>

        <div className="card col-span-2">
          <div className="text-xs font-semibold text-slate-300 mb-3 uppercase tracking-wider">Add Target to Pipeline</div>
          <div className="flex gap-2 mb-4">
            <input className="input flex-1" placeholder="e.g. example.com"
              value={newTarget} onChange={e => setNewTarget(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleAddTarget()} />
            <button className="btn-primary flex items-center gap-1" onClick={handleAddTarget} disabled={!newTarget.trim()}>
              <Plus size={11} /> Add
            </button>
          </div>
          {status?.targets?.length > 0 ? (
            <div className="flex flex-wrap gap-1.5 max-h-32 overflow-auto">
              {status.targets.map((t, i) => (
                <span key={i} className="text-[10px] px-2 py-1 rounded bg-bg-secondary border border-bg-border text-cyan-400 font-mono whitespace-nowrap">{t}</span>
              ))}
            </div>
          ) : (
            <div className="text-[10px] text-slate-500 italic">No targets configured.</div>
          )}
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
    if (s === 'active') return 'bg-green-900/50 text-green-400'
    if (s === 'idle') return 'bg-slate-700 text-slate-400'
    if (s === 'disabled') return 'bg-red-900/30 text-red-400'
    return 'bg-slate-700 text-slate-400'
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-400">{workers.length} workers registered</span>
        <button className="btn-secondary flex items-center gap-1" onClick={load} disabled={loading}>
          <RefreshCw size={11} className={clsx(loading && 'animate-spin')} /> Refresh
        </button>
      </div>
      <div className="grid grid-cols-3 gap-3">
        {workers.map((w, i) => (
          <div key={i} className="card border-l-2 border-l-bg-border transition-all hover:border-l-accent-primary">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-slate-300 uppercase">{w.name}</span>
              <span className={clsx('text-[10px] px-2 py-0.5 rounded-full uppercase font-bold', statusColor(w.status))}>{w.status || 'unknown'}</span>
            </div>
            <div className="text-[10px] text-slate-500 mb-3">
              Last run: <span className="text-slate-400">{relativeTime(w.last_run)}</span>
            </div>
            <button
              className={clsx('text-[10px] px-2 py-1 rounded uppercase font-bold w-full transition-colors', w.status === 'disabled' ? 'bg-green-900/40 text-green-400 hover:bg-green-900/60' : 'bg-slate-800 text-slate-300 hover:bg-slate-700')}
              onClick={() => toggle(w.name, w.status !== 'disabled')}
            >
              {w.status === 'disabled' ? 'Enable Worker' : 'Disable Worker'}
            </button>
          </div>
        ))}
        {workers.length === 0 && (
          <div className="col-span-3 text-xs text-slate-500 p-8 text-center bg-bg-secondary rounded border border-bg-border border-dashed">
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
    const id = setInterval(load, 5000) // Increased interval
    return () => clearInterval(id)
  }, [typeFilter])

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-4 gap-3">
        <div className="stat-card">
          <div className="stat-label">Total Events</div>
          <div className="stat-value">{stats.total ?? 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Last Hour</div>
          <div className="stat-value text-cyan-400">{stats.last_hour ?? 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Event Types</div>
          <div className="stat-value text-purple-400">{stats.unique_types ?? types.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">DLQ</div>
          <div className="stat-value text-red-400">{stats.dlq_size ?? 0}</div>
        </div>
      </div>

      <div className="card overflow-hidden">
        <div className="flex items-center gap-3 mb-3">
          <select className="select w-48" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
            <option value="">All Event Types</option>
            {types.map((t, i) => <option key={i} value={t}>{t}</option>)}
          </select>
          <button className="btn-secondary" onClick={load} disabled={loading}>
            <RefreshCw size={11} className={clsx(loading && 'animate-spin')} />
          </button>
          {lastUpdated && <span className="text-[10px] text-slate-500 ml-auto uppercase tracking-tighter">Last updated: {lastUpdated}</span>}
        </div>
        <div className="overflow-auto max-h-[500px]">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-slate-500 border-b border-bg-border sticky top-0 bg-bg-primary z-10">
                <th className="text-left py-2 px-3 w-40">Type</th>
                <th className="text-left py-2 px-3 w-32">Source</th>
                <th className="text-left py-2 px-3 w-24">Time</th>
                <th className="text-left py-2 px-3">Data Summary</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bg-border">
              {events.slice(0, 100).map((ev, i) => (
                <tr key={i} className="hover:bg-white/5 transition-colors">
                  <td className="py-1.5 px-3">
                    <span className={clsx('text-[10px] px-1.5 py-0.5 rounded font-mono font-bold', EVENT_TYPE_COLORS[ev.event_type] || 'bg-slate-700 text-slate-300')}>
                      {ev.event_type || ev.type || '—'}
                    </span>
                  </td>
                  <td className="py-1.5 px-3 text-slate-400 truncate max-w-[100px] text-[10px] uppercase font-semibold">{ev.source || '—'}</td>
                  <td className="py-1.5 px-3 text-slate-500 whitespace-nowrap text-[10px]">{relativeTime(ev.timestamp)}</td>
                  <td className="py-1.5 px-3 text-slate-400 truncate max-w-xs font-mono text-[10px] italic">
                    {ev.data ? (typeof ev.data === 'string' ? ev.data : JSON.stringify(ev.data)).slice(0, 150) : '—'}
                  </td>
                </tr>
              ))}
              {events.length === 0 && (
                <tr><td colSpan={4} className="py-12 px-3 text-slate-500 text-center">{loading ? 'Intelligence feed initializing...' : 'No events yet. Start the daemon to begin collecting.'}</td></tr>
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
