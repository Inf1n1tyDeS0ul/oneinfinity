import React, { useState, useEffect } from 'react'
import { Brain, Play, Square, RefreshCw, ChevronDown, ChevronUp } from 'lucide-react'
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

const SEV_COLORS = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low', info: 'badge-info' }

// ── Tab: Overview ────────────────────────────────────────────────────────────
function OverviewTab() {
  const { addNotification } = useStore()
  const [brain, setBrain] = useState(null)
  const [ede, setEde] = useState(null)
  const [fabric, setFabric] = useState(null)
  const [loading, setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const [b, e, f] = await Promise.allSettled([
        endpoints.brainStatus(), endpoints.edeStatus(), endpoints.fabricStatus(),
      ])
      if (b.status === 'fulfilled') setBrain(b.value.data)
      if (e.status === 'fulfilled') setEde(e.value.data)
      if (f.status === 'fulfilled') setFabric(f.value.data)
      setLastUpdated(new Date().toLocaleTimeString())
    } catch (err) {
      addNotification(`Failed to load brain status: ${err.message}`, 'error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const handleBrain = async (action) => {
    try {
      if (action === 'start') await endpoints.brainStart({})
      else await endpoints.brainStop()
      addNotification(`Brain ${action}ed`, 'success')
      load()
    } catch (e) { addNotification(`Failed: ${e.message}`, 'error') }
  }

  const handleEde = async (action) => {
    try {
      if (action === 'start') await endpoints.edeStart({})
      else await endpoints.edeStop()
      addNotification(`EDE ${action}ed`, 'success')
      load()
    } catch (e) { addNotification(`Failed: ${e.message}`, 'error') }
  }

  const running = brain?.running || brain?.status === 'running'
  const edeRunning = ede?.running || ede?.status === 'running'

  return (
    <div className="flex flex-col gap-4">
      <div className="flex justify-between items-center">
        <div className="flex gap-2">
          <button className="btn-secondary flex items-center gap-1" onClick={load} disabled={loading}>
            <RefreshCw size={11} className={clsx(loading && 'animate-spin')} /> Refresh
          </button>
        </div>
        {lastUpdated && <span className="text-[10px] text-slate-500">Last updated: {lastUpdated}</span>}
      </div>

      <div className="grid grid-cols-3 gap-3">
        <div className={clsx('card', running ? 'border-green-600/40' : '')}>
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-semibold text-slate-300">Attack Graph Brain</span>
            <span className={clsx('text-xs px-2 py-0.5 rounded-full', running ? 'bg-green-900/50 text-green-400' : 'bg-slate-700 text-slate-400')}>
              {running ? 'Running' : 'Stopped'}
            </span>
          </div>
          <div className="text-xs text-slate-500 mb-3 space-y-1">
            <div>Findings integrated: <span className="text-slate-300">{brain?.findings_integrated ?? 0}</span></div>
            <div>Queue depth: <span className="text-slate-300">{brain?.queue_size ?? 0}</span></div>
            <div>Targets: <span className="text-slate-300">{brain?.targets?.length ?? 0}</span></div>
          </div>
          <div className="flex gap-2">
            <button className="btn-primary flex items-center gap-1" onClick={() => handleBrain('start')} disabled={running || loading}>
              <Play size={11} /> Start
            </button>
            <button className="btn-danger flex items-center gap-1" onClick={() => handleBrain('stop')} disabled={!running || loading}>
              <Square size={11} /> Stop
            </button>
          </div>
        </div>

        <div className={clsx('card', edeRunning ? 'border-cyan-600/40' : '')}>
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-semibold text-slate-300">Event-Driven Engine</span>
            <span className={clsx('text-xs px-2 py-0.5 rounded-full', edeRunning ? 'bg-cyan-900/50 text-cyan-400' : 'bg-slate-700 text-slate-400')}>
              {edeRunning ? 'Running' : 'Stopped'}
            </span>
          </div>
          <div className="text-xs text-slate-500 mb-3 space-y-1">
            <div>Events routed: <span className="text-slate-300">{ede?.events_routed ?? 0}</span></div>
            <div>Dispatch interval: <span className="text-slate-300">{ede?.dispatch_interval ?? '1s'}</span></div>
          </div>
          <div className="flex gap-2">
            <button className="btn-primary flex items-center gap-1" onClick={() => handleEde('start')} disabled={edeRunning || loading}>
              <Play size={11} /> Start
            </button>
            <button className="btn-danger flex items-center gap-1" onClick={() => handleEde('stop')} disabled={!edeRunning || loading}>
              <Square size={11} /> Stop
            </button>
          </div>
        </div>

        <div className="card">
          <div className="text-xs font-semibold text-slate-300 mb-3">Agent Fabric</div>
          <div className="text-xs text-slate-500 space-y-1">
            <div>Workers active: <span className="text-slate-300">{fabric?.active_tasks ?? 0}</span></div>
            <div>Queued: <span className="text-slate-300">{fabric?.queue_size ?? 0}</span></div>
            <div>Max workers: <span className="text-slate-300">{fabric?.max_workers ?? 8}</span></div>
            <div>Agents registered: <span className="text-slate-300">{fabric?.agent_types?.length ?? 12}</span></div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Tab: Action Queue ────────────────────────────────────────────────────────
function QueueTab() {
  const { addNotification } = useStore()
  const [queue, setQueue] = useState([])
  const [loading, setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const r = await endpoints.brainQueue(50)
      setQueue(r.data?.actions || r.data || [])
      setLastUpdated(new Date().toLocaleTimeString())
    } catch (e) { 
      addNotification(`Queue load failed: ${e.message}`, 'error') 
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const id = setInterval(load, 10000) // Reduced frequency
    return () => clearInterval(id)
  }, [])

  return (
    <div className="card overflow-auto">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-300">Action Queue ({queue.length})</span>
          <button className="btn-secondary flex items-center gap-1" onClick={load} disabled={loading}>
            <RefreshCw size={11} className={clsx(loading && 'animate-spin')} /> Refresh
          </button>
        </div>
        {lastUpdated && <span className="text-[10px] text-slate-500">Last updated: {lastUpdated}</span>}
      </div>
      {queue.length === 0 ? (
        <div className="text-xs text-slate-500 p-4">{loading ? 'Loading queue...' : 'Queue is empty'}</div>
      ) : (
        <table className="w-full text-xs">
          <thead>
            <tr className="text-slate-500 border-b border-bg-border">
              <th className="text-left py-2 px-3">Agent</th>
              <th className="text-left py-2 px-3">Node</th>
              <th className="text-left py-2 px-3">Type</th>
              <th className="text-left py-2 px-3">Priority</th>
              <th className="text-left py-2 px-3">Reason</th>
              <th className="text-left py-2 px-3">Target</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-bg-border">
            {queue.map((a, i) => (
              <tr key={i} className="hover:bg-white/5">
                <td className="py-1.5 px-3 text-cyan-400">{a.agent_type || a.agent || '—'}</td>
                <td className="py-1.5 px-3 text-slate-300 font-mono truncate max-w-[150px]">{a.node_label || a.node || '—'}</td>
                <td className="py-1.5 px-3 text-slate-400">{a.node_type || '—'}</td>
                <td className="py-1.5 px-3">
                  <span className={clsx('font-mono', (a.priority || 0) > 7 ? 'text-red-400' : (a.priority || 0) > 4 ? 'text-yellow-400' : 'text-slate-400')}>
                    {typeof (a.priority_score ?? a.priority) === 'number' ? (a.priority_score ?? a.priority).toFixed(2) : (a.priority_score ?? a.priority) || '—'}
                  </span>
                </td>
                <td className="py-1.5 px-3 text-slate-500 truncate max-w-[200px]" title={a.decision_reason || a.reason}>{a.decision_reason || a.reason || '—'}</td>
                <td className="py-1.5 px-3 text-slate-400 truncate max-w-[150px]">{a.target || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

// ── Tab: Attack Paths ────────────────────────────────────────────────────────
function AttackPathsTab() {
  const { addNotification } = useStore()
  const [target, setTarget] = useState('')
  const [paths, setPaths] = useState([])
  const [loading, setLoading] = useState(false)
  const [expanded, setExpanded] = useState(null)

  const load = async () => {
    if (!target.trim()) return addNotification('Enter a target first', 'error')
    setLoading(true)
    try {
      const r = await endpoints.brainAttackPaths(target.trim())
      setPaths(r.data?.paths || r.data || [])
      if ((r.data?.paths || r.data || []).length === 0) {
        addNotification('No attack paths found for this target', 'info')
      }
    } catch (e) { 
      addNotification(`Failed to load attack paths: ${e.message}`, 'error') 
    } finally { 
      setLoading(false) 
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="card flex items-center gap-3">
        <input className="input flex-1" placeholder="Enter target (e.g. example.com)"
          value={target} onChange={e => setTarget(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && load()} />
        <button className="btn-primary" onClick={load} disabled={loading}>
          {loading ? 'Loading...' : 'Get Paths'}
        </button>
      </div>
      {paths.length > 0 && (
        <div className="flex flex-col gap-2">
          {paths.map((path, i) => (
            <div key={i} className="card">
              <div className="flex items-center justify-between cursor-pointer"
                onClick={() => setExpanded(expanded === i ? null : i)}>
                <div className="flex items-center gap-2">
                  {path.severity && <span className={clsx('text-xs px-2 py-0.5 rounded', SEV_COLORS[path.severity] || 'bg-slate-700 text-slate-300')}>{path.severity}</span>}
                  <span className="text-xs text-slate-300">{path.name || path.path_id || `Path ${i + 1}`}</span>
                  <span className="text-xs text-slate-500">({(path.nodes || path.steps || []).length} nodes)</span>
                </div>
                {expanded === i ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
              </div>
              {expanded === i && (
                <div className="mt-3 flex flex-wrap gap-2 items-center">
                  {(path.nodes || path.steps || []).map((node, ni) => (
                    <React.Fragment key={ni}>
                      <span className="text-xs px-2 py-1 rounded bg-bg-secondary border border-bg-border text-slate-300 font-mono">
                        {typeof node === 'string' ? node : node.label || node.name || JSON.stringify(node)}
                      </span>
                      {ni < (path.nodes || path.steps || []).length - 1 && (
                        <span className="text-slate-600">→</span>
                      )}
                    </React.Fragment>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
      {paths.length === 0 && !loading && target && (
        <div className="card text-xs text-slate-500 p-4">No attack paths found for this target.</div>
      )}
    </div>
  )
}

// ── Tab: Decisions ───────────────────────────────────────────────────────────
function DecisionsTab() {
  const { addNotification } = useStore()
  const [decisions, setDecisions] = useState([])
  const [loading, setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const r = await endpoints.brainDecisions(50)
      setDecisions(r.data?.decisions || r.data || [])
      setLastUpdated(new Date().toLocaleTimeString())
    } catch (e) { 
      addNotification(`Failed to load decisions: ${e.message}`, 'error') 
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  return (
    <div className="card overflow-auto">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-300">Recent Decisions</span>
          <button className="btn-secondary flex items-center gap-1" onClick={load} disabled={loading}>
            <RefreshCw size={11} className={clsx(loading && 'animate-spin')} /> Refresh
          </button>
        </div>
        {lastUpdated && <span className="text-[10px] text-slate-500">Last updated: {lastUpdated}</span>}
      </div>
      {decisions.length === 0 ? (
        <div className="text-xs text-slate-500 p-4">{loading ? 'Loading decisions...' : 'No decisions recorded yet'}</div>
      ) : (
        <table className="w-full text-xs">
          <thead>
            <tr className="text-slate-500 border-b border-bg-border">
              <th className="text-left py-2 px-3">Timestamp</th>
              <th className="text-left py-2 px-3">Agent</th>
              <th className="text-left py-2 px-3">Node</th>
              <th className="text-left py-2 px-3">Action</th>
              <th className="text-left py-2 px-3">Score</th>
              <th className="text-left py-2 px-3">Reason</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-bg-border">
            {decisions.map((d, i) => (
              <tr key={i} className="hover:bg-white/5">
                <td className="py-1.5 px-3 text-slate-500 whitespace-nowrap">{relativeTime(d.timestamp)}</td>
                <td className="py-1.5 px-3 text-cyan-400">{d.selected_agent || d.agent_type || d.agent || '—'}</td>
                <td className="py-1.5 px-3 font-mono text-slate-300 truncate max-w-[150px]">{d.node_label || d.node || '—'}</td>
                <td className="py-1.5 px-3 text-slate-400">{d.action || d.action_type || '—'}</td>
                <td className="py-1.5 px-3 font-mono text-slate-300">
                  {typeof (d.priority_score ?? d.score) === 'number' ? (d.priority_score ?? d.score).toFixed(3) : (d.priority_score ?? d.score) || '—'}
                </td>
                <td className="py-1.5 px-3 text-slate-500 truncate max-w-[200px]" title={d.decision_reason || d.reason}>
                  {d.decision_reason || d.reason || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

// ── Tab: Triggers ────────────────────────────────────────────────────────────
function TriggersTab() {
  const { addNotification } = useStore()
  const [rules, setRules] = useState([])
  const [history, setHistory] = useState([])
  const [triggerStats, setTriggerStats] = useState({})
  const [loading, setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const [r, h, s] = await Promise.allSettled([
        endpoints.triggerRules(), endpoints.triggerHistory(30), endpoints.triggerStats(),
      ])
      if (r.status === 'fulfilled') setRules(r.value.data?.rules || r.value.data || [])
      if (h.status === 'fulfilled') setHistory(h.value.data?.history || h.value.data || [])
      if (s.status === 'fulfilled') setTriggerStats(s.value.data || {})
      setLastUpdated(new Date().toLocaleTimeString())
    } catch (err) {
      addNotification(`Failed to load triggers: ${err.message}`, 'error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  return (
    <div className="flex flex-col gap-4">
      <div className="flex justify-between items-center">
        <button className="btn-secondary flex items-center gap-1" onClick={load} disabled={loading}>
          <RefreshCw size={11} className={clsx(loading && 'animate-spin')} /> Refresh
        </button>
        {lastUpdated && <span className="text-[10px] text-slate-500">Last updated: {lastUpdated}</span>}
      </div>

      <div className="grid grid-cols-3 gap-3">
        <div className="stat-card">
          <div className="stat-label">Total Rules</div>
          <div className="stat-value">{triggerStats.total_rules ?? rules.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Triggers Fired</div>
          <div className="stat-value">{triggerStats.total_fired ?? 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Last 24h</div>
          <div className="stat-value">{triggerStats.fired_24h ?? 0}</div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="card overflow-auto max-h-64">
          <div className="text-xs font-semibold text-slate-300 mb-2">Trigger Rules ({rules.length})</div>
          <div className="flex flex-col gap-1">
            {rules.map((r, i) => (
              <div key={i} className="flex items-center justify-between px-2 py-1.5 rounded bg-bg-secondary text-xs">
                <span className="text-slate-300">{r.name || r.condition || JSON.stringify(r)}</span>
                <span className="text-slate-500">{r.attack_types?.join(', ') || r.action || '—'}</span>
              </div>
            ))}
            {rules.length === 0 && <div className="text-slate-500 text-xs">{loading ? 'Loading rules...' : 'No rules loaded'}</div>}
          </div>
        </div>

        <div className="card overflow-auto max-h-64">
          <div className="text-xs font-semibold text-slate-300 mb-2">Recent Firings</div>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-slate-500 border-b border-bg-border">
                <th className="text-left py-1 px-2">Time</th>
                <th className="text-left py-1 px-2">Rule</th>
                <th className="text-left py-1 px-2">Node</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bg-border">
              {history.map((h, i) => (
                <tr key={i} className="hover:bg-white/5">
                  <td className="py-1 px-2 text-slate-500 whitespace-nowrap">{relativeTime(h.timestamp)}</td>
                  <td className="py-1 px-2 text-cyan-400">{h.rule || h.rule_name || '—'}</td>
                  <td className="py-1 px-2 text-slate-400 font-mono truncate max-w-[100px]">{h.node || h.node_label || '—'}</td>
                </tr>
              ))}
              {history.length === 0 && (
                <tr><td colSpan={3} className="py-2 px-2 text-slate-500 text-center">{loading ? 'Loading history...' : 'No trigger history'}</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}


// ── Main ─────────────────────────────────────────────────────────────────────
const TABS = ['Overview', 'Action Queue', 'Attack Paths', 'Decisions', 'Triggers']

export default function BrainDashboard() {
  const [tab, setTab] = useState(0)

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
        <Brain size={14} className="text-accent-primary" />
        Brain Dashboard
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

      {tab === 0 && <OverviewTab />}
      {tab === 1 && <QueueTab />}
      {tab === 2 && <AttackPathsTab />}
      {tab === 3 && <DecisionsTab />}
      {tab === 4 && <TriggersTab />}
    </div>
  )
}
