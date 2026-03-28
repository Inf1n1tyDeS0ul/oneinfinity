import React, { useState, useEffect, useRef } from 'react'
import { Users, Play, RefreshCw, Trash2 } from 'lucide-react'
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

const ALL_AGENTS = ['xss', 'sqli', 'ssrf', 'idor', 'auth', 'biz_logic', 'mobile', 'api']
const SEV_COLORS = { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-blue-400', info: 'text-slate-400' }

// ── Tab: Swarm Scan ──────────────────────────────────────────────────────────
function SwarmScanTab({ onNewSession }) {
  const { addNotification } = useStore()
  const [target, setTarget] = useState('')
  const [selectedAgents, setSelectedAgents] = useState(new Set(ALL_AGENTS))
  const [scanning, setScanning] = useState(false)
  const [sessionId, setSessionId] = useState(null)
  const [sessionStatus, setSessionStatus] = useState(null)
  const [loading, setLoading] = useState(false)
  const pollRef = useRef(null)

  const toggleAgent = (a) => {
    const next = new Set(selectedAgents)
    next.has(a) ? next.delete(a) : next.add(a)
    setSelectedAgents(next)
  }

  const startScan = async () => {
    if (!target.trim()) return addNotification('Enter a target', 'error')
    setScanning(true)
    setLoading(true)
    try {
      const r = await endpoints.swarmIntelScan({ target: target.trim(), agents: [...selectedAgents] })
      const id = r.data?.session_id || r.data?.id
      setSessionId(id)
      addNotification('Swarm scan started', 'success')
      onNewSession && onNewSession()
      pollRef.current = setInterval(async () => {
        try {
          const s = await endpoints.swarmIntelScanStatus(id)
          setSessionStatus(s.data)
          if (s.data?.status === 'completed' || s.data?.status === 'failed') {
            clearInterval(pollRef.current)
            setScanning(false)
            setLoading(false)
            if (s.data?.status === 'failed') {
              addNotification(`Scan failed: ${s.data?.error || 'Unknown error'}`, 'error')
            } else {
              addNotification('Swarm scan completed', 'success')
            }
          }
        } catch (err) {
          console.error('Status poll failed', err)
        }
      }, 5000) // Increased interval
    } catch (e) {
      addNotification(`Scan failed: ${e.message}`, 'error')
      setScanning(false)
      setLoading(false)
    }
  }

  useEffect(() => () => clearInterval(pollRef.current), [])

  const findings = sessionStatus?.findings || []

  return (
    <div className="flex flex-col gap-4">
      <div className="card">
        <div className="text-xs font-semibold text-slate-300 mb-3">Configure Swarm Scan</div>
        <input className="input w-full mb-3" placeholder="Target (e.g. https://example.com)"
          value={target} onChange={e => setTarget(e.target.value)} />
        <div className="flex flex-wrap gap-2 mb-4">
          {ALL_AGENTS.map(a => (
            <label key={a} className="flex items-center gap-1.5 cursor-pointer select-none">
              <input type="checkbox" checked={selectedAgents.has(a)} onChange={() => toggleAgent(a)}
                className="w-3 h-3 accent-cyan-400" />
              <span className="text-xs text-slate-300 uppercase">{a}</span>
            </label>
          ))}
        </div>
        <button className="btn-primary flex items-center gap-1.5" onClick={startScan} disabled={scanning}>
          <Play size={12} /> {scanning ? 'Scanning...' : 'Launch Swarm Scan'}
        </button>
      </div>

      {sessionStatus && (
        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <span className="text-xs font-semibold text-slate-300">Session: {sessionId}</span>
              <span className={clsx('text-xs px-2 py-0.5 rounded-full',
                sessionStatus.status === 'completed' ? 'bg-green-900/50 text-green-400' :
                sessionStatus.status === 'failed' ? 'bg-red-900/50 text-red-400' :
                'bg-blue-900/50 text-blue-400')}>
                {sessionStatus.status}
              </span>
              <span className="text-xs text-slate-500">{findings.length} findings</span>
            </div>
            <span className="text-[10px] text-slate-500">Last updated: {new Date().toLocaleTimeString()}</span>
          </div>
          {findings.length === 0 ? (
            <div className="text-xs text-slate-500 p-4">
              {scanning ? 'Scan in progress...' : 'No findings recorded for this session.'}
            </div>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="text-slate-500 border-b border-bg-border">
                  <th className="text-left py-2 px-3">Severity</th>
                  <th className="text-left py-2 px-3">Type</th>
                  <th className="text-left py-2 px-3">Endpoint</th>
                  <th className="text-left py-2 px-3">Agent</th>
                  <th className="text-left py-2 px-3">Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-bg-border">
                {findings.map((f, i) => (
                  <tr key={i} className="hover:bg-white/5">
                    <td className={clsx('py-1.5 px-3 font-semibold uppercase text-xs', SEV_COLORS[f.severity] || 'text-slate-400')}>{f.severity}</td>
                    <td className="py-1.5 px-3 text-slate-300">{f.type || f.vuln_type || '—'}</td>
                    <td className="py-1.5 px-3 font-mono text-slate-400 truncate max-w-xs">{f.endpoint || f.url || '—'}</td>
                    <td className="py-1.5 px-3 text-cyan-400">{f.selected_agent || f.agent_type || f.agent || '—'}</td>
                    <td className="py-1.5 px-3 font-mono text-slate-300">{typeof (f.priority_score ?? f.score) === 'number' ? (f.priority_score ?? f.score).toFixed(2) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}

// ── Tab: Attack Simulation ───────────────────────────────────────────────────
function SimulationTab() {
  const { addNotification } = useStore()
  const [target, setTarget] = useState('')
  const [iterations, setIterations] = useState(200)
  const [running, setRunning] = useState(false)
  const [sessionId, setSessionId] = useState(null)
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const pollRef = useRef(null)

  const launch = async () => {
    if (!target.trim()) return addNotification('Enter a target', 'error')
    setRunning(true)
    setLoading(true)
    try {
      const r = await endpoints.swarmIntelSimulate({ target: target.trim(), top_n: iterations })
      const id = r.data?.session_id || r.data?.id
      setSessionId(id)
      addNotification('Monte Carlo simulation started', 'success')
      pollRef.current = setInterval(async () => {
        try {
          const s = await endpoints.swarmIntelSimStatus(id)
          if (s.data?.status === 'completed' || s.data?.results || s.data?.status === 'failed') {
            setResults(s.data)
            clearInterval(pollRef.current)
            setRunning(false)
            setLoading(false)
            if (s.data?.status === 'failed') addNotification('Simulation failed', 'error')
            else addNotification('Simulation completed', 'success')
          }
        } catch (err) {
          console.error('Status poll failed', err)
        }
      }, 5000)
    } catch (e) {
      addNotification(`Simulation failed: ${e.message}`, 'error')
      setRunning(false)
      setLoading(false)
    }
  }

  useEffect(() => () => clearInterval(pollRef.current), [])

  const paths = results?.results || results?.paths || []

  return (
    <div className="flex flex-col gap-4">
      <div className="card">
        <div className="text-xs font-semibold text-slate-300 mb-3">Monte Carlo Attack Simulation</div>
        <div className="flex gap-3 mb-3">
          <input className="input flex-1" placeholder="Target" value={target} onChange={e => setTarget(e.target.value)} />
          <input className="input w-32" type="number" min={10} max={1000} value={iterations}
            onChange={e => setIterations(Number(e.target.value))} />
          <span className="text-xs text-slate-500 self-center">iterations</span>
        </div>
        <button className="btn-primary flex items-center gap-1.5" onClick={launch} disabled={running}>
          <Play size={12} /> {running ? 'Running...' : 'Launch Monte Carlo'}
        </button>
      </div>

      {results && (
        <div className="card overflow-auto">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-semibold text-slate-300">Ranked Attack Paths</span>
            <span className="text-[10px] text-slate-500">Last updated: {new Date().toLocaleTimeString()}</span>
          </div>
          {paths.length === 0 ? (
            <div className="text-xs text-slate-500 p-4">{running ? 'Simulation in progress...' : 'No paths generated.'}</div>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="text-slate-500 border-b border-bg-border">
                  <th className="text-left py-2 px-3">Attack Type</th>
                  <th className="text-left py-2 px-3 w-20">EV Score</th>
                  <th className="text-left py-2 px-3 w-20">Probability</th>
                  <th className="text-left py-2 px-3">Reasoning</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-bg-border">
                {paths.map((p, i) => (
                  <tr key={i} className="hover:bg-white/5">
                    <td className="py-1.5 px-3 text-slate-300">{p.attack_type || p.path_name || p.name || `Path ${i + 1}`}</td>
                    <td className="py-1.5 px-3 font-mono text-cyan-400">{typeof p.expected_value === 'number' ? p.expected_value.toFixed(3) : '—'}</td>
                    <td className="py-1.5 px-3 font-mono text-slate-300">{typeof p.success_probability === 'number' ? (p.success_probability * 100).toFixed(1) + '%' : '—'}</td>
                    <td className="py-1.5 px-3 text-slate-400 italic text-[11px]">{p.decision_reason || p.reasoning || (p.recommended ? 'Recommended' : '—')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}

// ── Tab: Workflow Attacks ────────────────────────────────────────────────────
function WorkflowTab() {
  const { addNotification } = useStore()
  const [target, setTarget] = useState('')
  const [workflow, setWorkflow] = useState('price_manipulation')
  const [running, setRunning] = useState(false)
  const [sessionId, setSessionId] = useState(null)
  const [results, setResults] = useState(null)
  const [workflows, setWorkflows] = useState([])
  const [loading, setLoading] = useState(false)
  const pollRef = useRef(null)

  useEffect(() => {
    setLoading(true)
    endpoints.swarmIntelWorkflows()
      .then(r => setWorkflows(r.data?.workflows || r.data || []))
      .catch(err => addNotification(`Failed to load workflows: ${err.message}`, 'error'))
      .finally(() => setLoading(false))
  }, [])

  const launch = async () => {
    if (!target.trim()) return addNotification('Enter a target', 'error')
    setRunning(true)
    try {
      const r = await endpoints.swarmIntelWorkflow({ workflow, base_url: target.trim() })
      const id = r.data?.session_id || r.data?.id
      setSessionId(id)
      addNotification('Workflow attack started', 'success')
      pollRef.current = setInterval(async () => {
        try {
          const s = await endpoints.swarmIntelWorkflowStatus(id)
          if (s.data?.status === 'completed' || s.data?.results || s.data?.status === 'failed') {
            setResults(s.data)
            clearInterval(pollRef.current)
            setRunning(false)
            if (s.data?.status === 'failed') addNotification('Workflow failed', 'error')
            else addNotification('Workflow attack completed', 'success')
          }
        } catch (err) {
          console.error('Status poll failed', err)
        }
      }, 5000)
    } catch (e) {
      addNotification(`Workflow failed: ${e.message}`, 'error')
      setRunning(false)
    }
  }

  useEffect(() => () => clearInterval(pollRef.current), [])

  const wfResults = results?.results || []
  const defaultWorkflows = ['price_manipulation', 'coupon_abuse', 'race_condition', 'payment_bypass']

  return (
    <div className="flex flex-col gap-4">
      <div className="card">
        <div className="text-xs font-semibold text-slate-300 mb-3">Workflow Attack Simulation</div>
        <div className="flex gap-3 mb-3">
          <input className="input flex-1" placeholder="Target" value={target} onChange={e => setTarget(e.target.value)} />
          <select className="select w-48" value={workflow} onChange={e => setWorkflow(e.target.value)} disabled={loading}>
            {(workflows.length > 0 ? workflows : defaultWorkflows).map((w, i) => (
              <option key={i} value={typeof w === 'string' ? w : w.name}>{typeof w === 'string' ? w : w.name}</option>
            ))}
          </select>
        </div>
        <button className="btn-primary flex items-center gap-1.5" onClick={launch} disabled={running}>
          <Play size={12} /> {running ? 'Running...' : 'Launch Workflow'}
        </button>
      </div>

      {results && (
        <div className="card overflow-auto">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-semibold text-slate-300">Results</span>
            <span className="text-[10px] text-slate-500">Last updated: {new Date().toLocaleTimeString()}</span>
          </div>
          {wfResults.length === 0 ? (
            <div className="text-xs text-slate-500 p-4">{running ? 'Attacking...' : 'No results found.'}</div>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="text-slate-500 border-b border-bg-border">
                  <th className="text-left py-2 px-3">Workflow</th>
                  <th className="text-left py-2 px-3 w-24">Attacks Run</th>
                  <th className="text-left py-2 px-3 w-24">Vulnerable</th>
                  <th className="text-left py-2 px-3 w-24">Findings</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-bg-border">
                {wfResults.map((c, i) => (
                  <tr key={i} className="hover:bg-white/5">
                    <td className="py-1.5 px-3 text-slate-300">{c.workflow || c.name || `Workflow ${i + 1}`}</td>
                    <td className="py-1.5 px-3 text-slate-400">{c.attacks_run ?? '—'}</td>
                    <td className={clsx('py-1.5 px-3', (c.vulnerable || 0) > 0 ? 'text-orange-400' : 'text-slate-400')}>
                      {c.vulnerable ?? 0}
                    </td>
                    <td className="py-1.5 px-3 text-slate-300">{c.findings_count ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}

// ── Tab: History ─────────────────────────────────────────────────────────────
function HistoryTab({ refresh }) {
  const { addNotification } = useStore()
  const [sessions, setSessions] = useState([])
  const [expanded, setExpanded] = useState(null)
  const [loading, setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const r = await endpoints.swarmIntelSessions()
      const d = r.data || {}
      const combined = [
        ...(d.swarm_sessions || []),
        ...(d.simulation_sessions || []),
        ...(d.workflow_sessions || []),
      ]
      setSessions(combined.sort((a,b) => new Date(b.started_at || b.created_at) - new Date(a.started_at || a.created_at)))
      setLastUpdated(new Date().toLocaleTimeString())
    } catch (e) { 
      addNotification(`Failed to load session history: ${e.message}`, 'error') 
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [refresh])

  const handleDelete = async (id) => {
    try {
      await endpoints.swarmIntelScanDelete(id)
      addNotification('Session deleted', 'success')
      load()
    } catch (e) { addNotification(`Failed: ${e.message}`, 'error') }
  }

  const statusColor = (s) => {
    if (s === 'completed') return 'bg-green-900/50 text-green-400'
    if (s === 'failed') return 'bg-red-900/50 text-red-400'
    if (s === 'running') return 'bg-blue-900/50 text-blue-400'
    return 'bg-slate-700 text-slate-400'
  }

  return (
    <div className="card overflow-auto">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-300">All Sessions ({sessions.length})</span>
          <button className="btn-secondary flex items-center gap-1" onClick={load} disabled={loading}>
            <RefreshCw size={11} className={clsx(loading && 'animate-spin')} /> Refresh
          </button>
        </div>
        {lastUpdated && <span className="text-[10px] text-slate-500">Last updated: {lastUpdated}</span>}
      </div>
      {sessions.length === 0 ? (
        <div className="text-xs text-slate-500 p-4">{loading ? 'Loading history...' : 'No sessions yet. Launch a scan or simulation.'}</div>
      ) : (
        <table className="w-full text-xs">
          <thead>
            <tr className="text-slate-500 border-b border-bg-border">
              <th className="text-left py-2 px-3">Type</th>
              <th className="text-left py-2 px-3">Target</th>
              <th className="text-left py-2 px-3">Started</th>
              <th className="text-left py-2 px-3 w-20">Status</th>
              <th className="text-left py-2 px-3 w-20">Findings</th>
              <th className="text-left py-2 px-3 w-16"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-bg-border">
            {sessions.map((s) => (
              <React.Fragment key={s.id}>
                <tr className="hover:bg-white/5 cursor-pointer" onClick={() => setExpanded(expanded === s.id ? null : s.id)}>
                  <td className="py-1.5 px-3 text-cyan-400 uppercase text-xs">{s.type || s.session_type || 'scan'}</td>
                  <td className="py-1.5 px-3 font-mono text-slate-300 truncate max-w-xs">{s.target || '—'}</td>
                  <td className="py-1.5 px-3 text-slate-500 whitespace-nowrap">{relativeTime(s.started_at || s.created_at)}</td>
                  <td className="py-1.5 px-3">
                    <span className={clsx('text-xs px-1.5 py-0.5 rounded-full', statusColor(s.status))}>{s.status}</span>
                  </td>
                  <td className="py-1.5 px-3 text-slate-300">{s.findings_count ?? s.findings?.length ?? 0}</td>
                  <td className="py-1.5 px-3">
                    <button className="p-1 rounded hover:bg-white/10" onClick={(e) => { e.stopPropagation(); handleDelete(s.session_id || s.id) }}>
                      <Trash2 size={11} className="text-red-400" />
                    </button>
                  </td>
                </tr>
                {expanded === s.id && (
                  <tr className="bg-bg-secondary">
                    <td colSpan={6} className="px-4 py-3">
                      <pre className="text-xs text-slate-400 font-mono whitespace-pre-wrap max-h-48 overflow-auto">
                        {JSON.stringify(s, null, 2)}
                      </pre>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}


// ── Main ─────────────────────────────────────────────────────────────────────
const TABS = ['Swarm Scan', 'Attack Simulation', 'Workflow Attacks', 'History']

export default function SwarmIntelligence() {
  const [tab, setTab] = useState(0)
  const [historyRefresh, setHistoryRefresh] = useState(0)
  const [agentGrid, setAgentGrid] = useState({})

  useEffect(() => {
    const refresh = async () => {
      try {
        const r = await endpoints.swarmIntelAgents()
        const map = {}
        ;(r.data || []).forEach(a => { map[a.type || a.name] = a })
        setAgentGrid(map)
      } catch {}
    }
    refresh()
    const t = setInterval(refresh, 4000)
    return () => clearInterval(t)
  }, [])

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
        <Users size={14} className="text-accent-primary" />
        Swarm Intelligence
      </h1>

      {/* Real-Time Agent Grid */}
      <div className="mb-6">
        <div className="section-header">
          <div>
            <h2 className="section-title">Agent Status</h2>
            <p className="section-sub">Live activity across all specialized agents</p>
          </div>
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {['xss', 'sqli', 'ssrf', 'idor', 'auth', 'biz_logic', 'mobile', 'api'].map(type => {
            const agent = agentGrid[type] || {}
            const status = agent.status || 'idle'
            const confidence = agent.confidence ?? null
            return (
              <div key={type} className="card p-4 flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wide">{type}</span>
                  <span className={clsx(
                    'status-dot',
                    status === 'running' ? 'status-dot-pulse' :
                    status === 'done'    ? 'status-dot-online' :
                    status === 'error'   ? 'status-dot-error'  : 'status-dot-idle'
                  )} />
                </div>
                <div className="text-[10px] text-slate-500 truncate">
                  {agent.last_target || 'No target'}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400">
                    {agent.findings_count ?? 0} findings
                  </span>
                  {confidence != null && (
                    <span className={clsx(
                      'badge',
                      confidence >= 80 ? 'badge-completed' :
                      confidence >= 50 ? 'badge-medium' : 'badge-failed'
                    )}>
                      {confidence}%
                    </span>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      <div className="flex gap-1 border-b border-bg-border pb-1">
        {TABS.map((t, i) => (
          <button key={t} onClick={() => setTab(i)}
            className={clsx('px-3 py-1.5 text-xs rounded-t transition-colors',
              tab === i ? 'bg-accent-primary/20 text-accent-primary' : 'text-slate-400 hover:text-slate-200')}>
            {t}
          </button>
        ))}
      </div>

      {tab === 0 && <SwarmScanTab onNewSession={() => setHistoryRefresh(n => n + 1)} />}
      {tab === 1 && <SimulationTab />}
      {tab === 2 && <WorkflowTab />}
      {tab === 3 && <HistoryTab refresh={historyRefresh} />}
    </div>
  )
}
