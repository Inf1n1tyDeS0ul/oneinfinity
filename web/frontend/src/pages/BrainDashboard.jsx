import React, { useState, useEffect, useRef } from 'react'
import { Brain, Play, Square, RefreshCw, ChevronDown, ChevronUp, Target } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import { relativeTime } from '../utils/time'
import clsx from 'clsx'

const SEV_COLORS = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low', info: 'badge-info' }

// ── Tab: Overview ────────────────────────────────────────────────────────────
function OverviewTab() {
  const { addNotification, scans } = useStore()
  const [brain, setBrain] = useState(null)
  const [ede, setEde] = useState(null)
  const [fabric, setFabric] = useState(null)
  const [loading, setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)
  const [showTargetInput, setShowTargetInput] = useState(false)
  const [manualTarget, setManualTarget] = useState('')
  const targetInputRef = useRef(null)

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

  // Derive unique targets from completed scans
  const knownTargets = [...new Set(scans.map(s => s.target).filter(Boolean))]

  const startBrain = async (targets) => {
    await endpoints.brainStart({ targets })
    addNotification(`Brain started for ${targets.length} target${targets.length > 1 ? 's' : ''}`, 'success')
    setShowTargetInput(false)
    setManualTarget('')
    load()
  }

  const handleBrain = async (action) => {
    try {
      if (action === 'start') {
        if (knownTargets.length > 0) {
          await startBrain(knownTargets)
        } else {
          // No known targets — show inline input
          setShowTargetInput(true)
          setTimeout(() => targetInputRef.current?.focus(), 50)
        }
      } else {
        await endpoints.brainStop()
        addNotification('Brain stopped', 'success')
        load()
      }
    } catch (e) { addNotification(`Failed: ${e.message}`, 'error') }
  }

  const handleManualStart = async () => {
    const t = manualTarget.trim()
    if (!t) { addNotification('Enter a target domain or IP', 'error'); return }
    try {
      await startBrain([t])
    } catch (e) { addNotification(`Failed: ${e.message}`, 'error') }
  }

  const handleEde = async (action) => {
    try {
      if (action === 'start') {
        const targets = knownTargets.length > 0 ? knownTargets : ['*']
        await endpoints.edeStart({ targets })
      } else {
        await endpoints.edeStop()
      }
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

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className={clsx('card p-4 flex flex-col justify-between', running ? 'border-green-600/40 ring-1 ring-green-600/20' : 'border-white/5')}>
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-sm font-bold text-slate-200">Attack Graph Brain</span>
              <span className={clsx('text-[10px] px-2 py-0.5 rounded-full font-bold uppercase tracking-wider', running ? 'bg-green-900/50 text-green-400' : 'bg-slate-800 text-slate-500')}>
                {running ? 'Online' : 'Offline'}
              </span>
            </div>
            <div className="space-y-2 mb-6">
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Findings Integrated</span>
                <span className="text-slate-300 font-mono font-bold">{brain?.findings_integrated ?? 0}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Queue Depth</span>
                <span className={clsx('font-mono font-bold', (brain?.queue_depth || 0) > 0 ? 'text-yellow-400' : 'text-slate-300')}>
                  {brain?.queue_depth ?? 0}
                </span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Active Targets</span>
                <span className="text-slate-300 font-mono font-bold">{brain?.targets?.length ?? 0}</span>
              </div>
            </div>
          </div>
          {/* Known targets hint */}
          {knownTargets.length > 0 && !running && (
            <div className="mt-2 mb-1 flex flex-wrap gap-1">
              {knownTargets.slice(0, 3).map(t => (
                <span key={t} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-bg-elevated border border-bg-border text-slate-500 truncate max-w-[100px]" title={t}>{t}</span>
              ))}
              {knownTargets.length > 3 && (
                <span className="text-[10px] text-slate-600">+{knownTargets.length - 3} more</span>
              )}
            </div>
          )}

          <div className="flex gap-2 pt-2 border-t border-white/5">
            <button className="btn-primary flex-1 py-1.5 text-[11px] flex items-center justify-center gap-1.5" onClick={() => handleBrain('start')} disabled={running || loading}>
              <Play size={10} fill="currentColor" /> Start
            </button>
            <button className="btn-danger flex-1 py-1.5 text-[11px] flex items-center justify-center gap-1.5" onClick={() => handleBrain('stop')} disabled={!running || loading}>
              <Square size={10} fill="currentColor" /> Stop
            </button>
          </div>

          {/* Inline target input — shown when no known targets */}
          {showTargetInput && (
            <div className="mt-2 flex gap-2">
              <div className="relative flex-1">
                <Target size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  ref={targetInputRef}
                  className="input pl-7 w-full text-xs"
                  placeholder="e.g. example.com"
                  value={manualTarget}
                  onChange={e => setManualTarget(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleManualStart()}
                />
              </div>
              <button className="btn-primary text-xs px-3" onClick={handleManualStart}>Go</button>
              <button className="btn-secondary text-xs px-2" onClick={() => setShowTargetInput(false)}>✕</button>
            </div>
          )}
        </div>

        <div className={clsx('card p-4 flex flex-col justify-between', edeRunning ? 'border-cyan-600/40 ring-1 ring-cyan-600/20' : 'border-white/5')}>
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-sm font-bold text-slate-200">Event Bus (EDE)</span>
              <span className={clsx('text-[10px] px-2 py-0.5 rounded-full font-bold uppercase tracking-wider', edeRunning ? 'bg-cyan-900/50 text-cyan-400' : 'bg-slate-800 text-slate-500')}>
                {edeRunning ? 'Active' : 'Idle'}
              </span>
            </div>
            <div className="space-y-2 mb-6">
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Events Received</span>
                <span className="text-slate-300 font-mono font-bold">{ede?.events_received ?? 0}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Actions Dispatched</span>
                <span className="text-slate-300 font-mono font-bold">{ede?.actions_sent ?? 0}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Iterations</span>
                <span className="text-slate-300 font-mono font-bold">{ede?.iterations ?? 0}</span>
              </div>
            </div>
          </div>
          <div className="flex gap-2 pt-2 border-t border-white/5">
            <button className="btn-primary flex-1 py-1.5 text-[11px] flex items-center justify-center gap-1.5" onClick={() => handleEde('start')} disabled={edeRunning || loading}>
              <Play size={10} fill="currentColor" /> Resume
            </button>
            <button className="btn-danger flex-1 py-1.5 text-[11px] flex items-center justify-center gap-1.5" onClick={() => handleEde('stop')} disabled={!edeRunning || loading}>
              <Square size={10} fill="currentColor" /> Pause
            </button>
          </div>
        </div>

        <div className="card p-4 flex flex-col justify-between border-white/5">
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-sm font-bold text-slate-200">Agent Fabric</span>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-indigo-900/30 text-indigo-400 font-bold uppercase tracking-wider">
                Cluster
              </span>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Active Tasks</span>
                <span className={clsx('font-mono font-bold', (fabric?.active_tasks || 0) > 0 ? 'text-indigo-400' : 'text-slate-300')}>
                  {fabric?.active_tasks ?? 0}
                </span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Task Queue</span>
                <span className="text-slate-300 font-mono font-bold">{fabric?.queue_depth ?? 0}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Provisioned Capacity</span>
                <span className="text-slate-300 font-mono">{fabric?.max_workers ?? 8} CPU</span>
              </div>
              <div className="flex justify-between text-xs pt-1 border-t border-white/5 mt-1">
                <span className="text-slate-500">Available Agents</span>
                <span className="text-slate-300 font-mono">{fabric?.agent_types?.length ?? 12}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Running Targets Panel */}
      {running && (
        <RunningTargetsPanel
          targets={brain?.targets ?? []}
          onAdd={async (t) => {
            try {
              await endpoints.brainAddTarget(t)
              addNotification(`Added target: ${t}`, 'success')
              load()
            } catch (e) { addNotification(`Failed to add target: ${e.message}`, 'error') }
          }}
        />
      )}
    </div>
  )
}

// ── Running Targets Panel ────────────────────────────────────────────────────
function RunningTargetsPanel({ targets, onAdd }) {
  const [addInput, setAddInput] = useState('')
  const [adding, setAdding] = useState(false)
  const inputRef = useRef(null)

  const handleAdd = async () => {
    const t = addInput.trim()
    if (!t) return
    setAdding(true)
    await onAdd(t)
    setAddInput('')
    setAdding(false)
  }

  return (
    <div className="card p-4 border-green-600/20 bg-green-950/10">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span className="text-xs font-semibold text-slate-200">Running Targets</span>
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-green-900/40 text-green-400 border border-green-700/30">
            {targets.length} active
          </span>
        </div>
        <span className="text-[10px] text-slate-500">Brain is autonomously monitoring these targets</span>
      </div>

      {targets.length === 0 ? (
        <p className="text-xs text-slate-500 italic mb-3">No targets registered yet.</p>
      ) : (
        <div className="flex flex-wrap gap-2 mb-3">
          {targets.map(t => (
            <div key={t} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-bg-elevated border border-green-700/30 text-xs font-mono text-green-300">
              <span className="w-1.5 h-1.5 rounded-full bg-green-400 flex-shrink-0" />
              {t}
            </div>
          ))}
        </div>
      )}

      {/* Add target inline */}
      <div className="flex gap-2 pt-3 border-t border-white/5">
        <div className="relative flex-1 max-w-xs">
          <Target size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            ref={inputRef}
            className="input pl-7 w-full text-xs"
            placeholder="Add target (e.g. api.example.com)"
            value={addInput}
            onChange={e => setAddInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleAdd()}
          />
        </div>
        <button
          className="btn-primary text-xs flex items-center gap-1.5"
          onClick={handleAdd}
          disabled={adding || !addInput.trim()}
        >
          {adding ? <RefreshCw size={11} className="animate-spin" /> : <Play size={11} fill="currentColor" />}
          Add Target
        </button>
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
    <div className="flex flex-col gap-4 flex-1 min-h-0">
      <div className="flex items-center justify-between flex-shrink-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-bold text-slate-200">Autonomous Action Queue ({queue.length})</span>
          <button className="btn-secondary flex items-center gap-1.5 px-2 py-1" onClick={load} disabled={loading}>
            <RefreshCw size={11} className={clsx(loading && 'animate-spin')} /> 
            <span className="text-[10px]">Refresh</span>
          </button>
        </div>
        {lastUpdated && <span className="text-[10px] text-slate-500 italic">Synced: {lastUpdated}</span>}
      </div>
      
      <div className="card flex-1 min-h-0 overflow-hidden flex flex-col border-white/5">
        <div className="overflow-x-auto overflow-y-auto flex-1 custom-scrollbar">
          {queue.length === 0 ? (
            <div className="text-xs text-slate-500 p-8 text-center">{loading ? 'Synchronizing queue...' : 'Brain queue is currently idle.'}</div>
          ) : (
            <table className="w-full text-xs border-collapse">
              <thead className="sticky top-0 bg-bg-secondary z-10">
                <tr className="text-slate-500 border-b border-white/5">
                  <th className="text-left py-3 px-4 font-bold uppercase tracking-widest text-[9px]">Agent</th>
                  <th className="text-left py-3 px-4 font-bold uppercase tracking-widest text-[9px]">Node</th>
                  <th className="text-left py-3 px-4 font-bold uppercase tracking-widest text-[9px]">Type</th>
                  <th className="text-left py-3 px-4 font-bold uppercase tracking-widest text-[9px]">Priority</th>
                  <th className="text-left py-3 px-4 font-bold uppercase tracking-widest text-[9px]">Hypothesis / Rationale</th>
                  <th className="text-left py-3 px-4 font-bold uppercase tracking-widest text-[9px]">Scope</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {queue.map((a, i) => (
                  <tr key={i} className="hover:bg-white/[0.02] transition-colors group">
                    <td className="py-2.5 px-4">
                      <span className="px-2 py-0.5 rounded bg-cyan-900/20 text-cyan-400 font-mono font-bold text-[10px] border border-cyan-500/20">
                        {a.agent_type || a.agent || '—'}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-300 font-mono text-[11px] truncate max-w-[180px]">{a.node_label || a.node || '—'}</td>
                    <td className="py-2.5 px-4 text-slate-500 italic text-[11px] capitalize">{a.node_type?.replace('_', ' ') || '—'}</td>
                    <td className="py-2.5 px-4">
                      <span className={clsx('font-mono font-bold text-[11px]', (a.priority || 0) > 7 ? 'text-red-400' : (a.priority || 0) > 4 ? 'text-yellow-400' : 'text-slate-400')}>
                        {typeof (a.priority_score ?? a.priority) === 'number' ? (a.priority_score ?? a.priority).toFixed(2) : (a.priority_score ?? a.priority) || '—'}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 text-[11px] leading-relaxed max-w-[350px]" title={a.reasoning || a.decision_reason || a.reason}>
                      <span className="line-clamp-1 group-hover:line-clamp-none">{a.reasoning || a.decision_reason || a.reason || '—'}</span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-500 font-mono text-[10px] truncate max-w-[120px]">{a.target || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
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
    <div className="flex flex-col gap-4 flex-1 min-h-0">
      <div className="flex items-center justify-between flex-shrink-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-bold text-slate-200">Historical Decisions ({decisions.length})</span>
          <button className="btn-secondary flex items-center gap-1.5 px-2 py-1" onClick={load} disabled={loading}>
            <RefreshCw size={11} className={clsx(loading && 'animate-spin')} /> 
            <span className="text-[10px]">Refresh</span>
          </button>
        </div>
        {lastUpdated && <span className="text-[10px] text-slate-500 italic">Synced: {lastUpdated}</span>}
      </div>

      <div className="card flex-1 min-h-0 overflow-hidden flex flex-col border-white/5">
        <div className="overflow-x-auto overflow-y-auto flex-1 custom-scrollbar">
          {decisions.length === 0 ? (
            <div className="text-xs text-slate-500 p-8 text-center">{loading ? 'Retrieving archive...' : 'No historical decisions found.'}</div>
          ) : (
            <table className="w-full text-xs border-collapse">
              <thead className="sticky top-0 bg-bg-secondary z-10">
                <tr className="text-slate-500 border-b border-white/5">
                  <th className="text-left py-3 px-4 font-bold uppercase tracking-widest text-[9px]">Timestamp</th>
                  <th className="text-left py-3 px-4 font-bold uppercase tracking-widest text-[9px]">Agent</th>
                  <th className="text-left py-3 px-4 font-bold uppercase tracking-widest text-[9px]">Node</th>
                  <th className="text-left py-3 px-4 font-bold uppercase tracking-widest text-[9px]">Action</th>
                  <th className="text-left py-3 px-4 font-bold uppercase tracking-widest text-[9px]">Confidence</th>
                  <th className="text-left py-3 px-4 font-bold uppercase tracking-widest text-[9px]">Justification</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {decisions.map((d, i) => {
                  // BrainDecision.to_dict() shape:
                  //   made_at (unix float), target, confidence, reasoning
                  //   action: { agent_type, node_label, node_id, action_id, priority }
                  const act = d.action && typeof d.action === 'object' ? d.action : null
                  const agent     = act?.agent_type   || d.selected_agent || d.agent_type || '—'
                  const nodeLabel = act?.node_label   || d.node_label     || d.node       || '—'
                  const actionId  = act?.action_id    || d.action_id      || '—'
                  const confidence = d.confidence     ?? d.priority_score ?? d.score
                  const reasoning  = d.reasoning      || d.decision_reason || d.reason    || '—'
                  const ts = d.made_at
                    ? (d.made_at > 1e10 ? new Date(d.made_at) : new Date(d.made_at * 1000))
                    : (d.timestamp ? new Date(d.timestamp) : null)

                  return (
                    <tr key={d.decision_id || i} className="hover:bg-white/[0.02] transition-colors group">
                      <td className="py-2.5 px-4 text-slate-500 whitespace-nowrap text-[10px]">
                        {ts ? relativeTime(ts.toISOString()) : '—'}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className="px-2 py-0.5 rounded bg-indigo-900/20 text-indigo-400 font-mono font-bold text-[10px] border border-indigo-500/20">
                          {agent}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-slate-300 font-mono text-[11px] truncate max-w-[150px]" title={nodeLabel}>
                        {nodeLabel}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] uppercase font-semibold">
                          {actionId}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-300 text-[11px]">
                        {typeof confidence === 'number' ? confidence.toFixed(3) : confidence || '—'}
                      </td>
                      <td className="py-2.5 px-4 text-slate-400 text-[11px] leading-relaxed max-w-[400px]" title={reasoning}>
                        <span className="line-clamp-1 group-hover:line-clamp-none">{reasoning}</span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
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
          <div className="stat-value">{triggerStats.rules ?? triggerStats.total_rules ?? rules.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Triggers Fired</div>
          <div className="stat-value">{triggerStats.total_fired ?? triggerStats.total_evaluated ?? 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">History Size</div>
          <div className="stat-value">{triggerStats.history_size ?? triggerStats.fired_24h ?? 0}</div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="card overflow-auto max-h-64">
          <div className="text-xs font-semibold text-slate-300 mb-2">Trigger Rules ({rules.length})</div>
          <div className="flex flex-col gap-1">
            {rules.map((r, i) => (
              <div key={i} className="flex items-center justify-between px-2 py-1.5 rounded bg-bg-secondary text-xs">
                <span className="text-slate-300">{r.name || r.condition || JSON.stringify(r)}</span>
                <span className="text-slate-500">{(r.agents || r.attack_types)?.join(', ') || r.action || '—'}</span>
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
