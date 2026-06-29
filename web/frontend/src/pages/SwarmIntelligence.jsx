import React, { useState, useEffect, useRef } from 'react'
import { Users, Play, RefreshCw, Trash2, Activity, ShieldAlert, Cpu } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import { relativeTime } from '../utils/time'
import clsx from 'clsx'
import AgentHoneycomb from '../components/Swarm/AgentHoneycomb'
import TelemetryTerminal from '../components/Swarm/TelemetryTerminal'
import RiskHeatmap from '../components/Swarm/RiskHeatmap'
import SessionTimeline from '../components/Swarm/SessionTimeline'
import FindingCard from '../components/Swarm/FindingCard'

const ALL_AGENTS = ['xss', 'sqli', 'ssrf', 'idor', 'auth', 'business_logic', 'mobile', 'api', 'deserialization', 'race_condition', 'file_upload', 'oauth', 'prototype_pollution', 'clickjacking']
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
  const [agentCatalogue, setAgentCatalogue] = useState([])
  const pollRef = useRef(null)

  useEffect(() => {
    endpoints.swarmIntelAgents().then(r => setAgentCatalogue(r.data?.agents || []))
  }, [])

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
      }, 5000)
    } catch (e) {
      addNotification(`Scan failed: ${e.message}`, 'error')
      setScanning(false)
      setLoading(false)
    }
  }

  useEffect(() => () => clearInterval(pollRef.current), [])

  const findings = sessionStatus?.findings || []

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Configuration Column */}
        <div className="flex flex-col gap-4">
          <div className="glass-card p-5">
            <h3 className="text-xs font-bold text-slate-400 mb-4 uppercase flex items-center gap-2">
              <Cpu size={14} className="text-cyan-400" />
              Configure Deployment
            </h3>
            <input className="input w-full mb-4" placeholder="Target (e.g. https://example.com)"
              value={target} onChange={e => setTarget(e.target.value)} disabled={scanning} />
            
            <div className="flex flex-wrap gap-2 mb-6">
              {ALL_AGENTS.map(a => (
                <button
                  key={a}
                  onClick={() => toggleAgent(a)}
                  disabled={scanning}
                  className={clsx(
                    "px-2.5 py-1 rounded-lg text-[10px] font-mono border transition-all",
                    selectedAgents.has(a) 
                      ? "bg-cyan-500/10 border-cyan-500/40 text-cyan-400" 
                      : "bg-slate-800/50 border-slate-700 text-slate-500 hover:border-slate-600"
                  )}
                >
                  {a.toUpperCase()}
                </button>
              ))}
            </div>

            <button className="btn-primary w-full justify-center h-10" onClick={startScan} disabled={scanning || !target.trim()}>
              {scanning ? (
                <RefreshCw size={14} className="animate-spin" />
              ) : (
                <Play size={14} />
              )}
              {scanning ? 'Deploying Swarm...' : 'Launch Swarm Scan'}
            </button>
          </div>

          <div className="glass-card p-5">
            <h3 className="text-xs font-bold text-slate-400 mb-4 uppercase flex items-center gap-2">
              <Activity size={14} className="text-indigo-400" />
              Deployment Pulse
            </h3>
            <AgentHoneycomb 
              agents={agentCatalogue.length > 0 ? agentCatalogue : ALL_AGENTS} 
              activeAgents={scanning ? [...selectedAgents] : []}
              findings={findings}
            />
          </div>
        </div>

        {/* Telemetry Column */}
        <div className="lg:col-span-2 flex flex-col gap-4">
          <div className="glass-card p-5 flex-1 min-h-[300px] flex flex-col">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-bold text-slate-400 uppercase flex items-center gap-2">
                <Activity size={14} className="text-emerald-400" />
                Live Telemetry
              </h3>
              {sessionStatus && (
                <span className="text-[10px] font-mono text-slate-500">ID: {sessionId}</span>
              )}
            </div>
            <TelemetryTerminal logs={sessionStatus?.log || []} />
            
            <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="bg-slate-950/40 border border-slate-800 rounded-xl p-3">
                <div className="text-[10px] text-slate-500 uppercase font-bold mb-1">Findings</div>
                <div className="text-xl font-bold text-emerald-400">{findings.length}</div>
              </div>
              <div className="bg-slate-950/40 border border-slate-800 rounded-xl p-3">
                <div className="text-[10px] text-slate-500 uppercase font-bold mb-1">Status</div>
                <div className={clsx("text-xs font-bold uppercase mt-1.5", 
                  sessionStatus?.status === 'completed' ? 'text-emerald-400' : 
                  sessionStatus?.status === 'failed' ? 'text-red-400' : 'text-cyan-400')}>
                  {sessionStatus?.status || 'Idle'}
                </div>
              </div>
              <div className="bg-slate-950/40 border border-slate-800 rounded-xl p-3">
                <div className="text-[10px] text-slate-500 uppercase font-bold mb-1">Progress</div>
                <div className="text-xl font-bold text-indigo-400">{sessionStatus?.progress || 0}%</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Findings Feed */}
      {(findings.length > 0 || sessionStatus?.status === 'completed') && (
        <div className="glass-card p-6">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-sm font-bold flex items-center gap-2">
              <ShieldAlert size={16} className="text-red-400" />
              Intelligence Findings Feed
            </h3>
          </div>
          
          {findings.length === 0 ? (
            <div className="text-center py-12 text-slate-500 italic text-sm">
              Scan completed with no vulnerabilities detected.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {findings.map((f, i) => (
                <FindingCard key={i} finding={f} />
              ))}
            </div>
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

  const heatmapData = paths.map(p => ({
    name: p.attack_type || p.name || p.path_name,
    probability: (p.success_probability || 0) * 100,
    impact: p.impact_score || 0,
    ev: (p.expected_value || 0) * 10
  }))

  return (
    <div className="flex flex-col gap-6">
      <div className="glass-card p-5">
        <h3 className="text-xs font-bold text-slate-400 mb-4 uppercase flex items-center gap-2">
          <Activity size={14} className="text-orange-400" />
          Monte Carlo Attack Simulation
        </h3>
        <div className="flex flex-col md:flex-row gap-3 mb-4">
          <input className="input flex-1" placeholder="Target (e.g. https://example.com)" value={target} onChange={e => setTarget(e.target.value)} />
          <div className="flex items-center gap-2 bg-slate-950/30 px-3 py-1 rounded-lg border border-slate-800">
            <input className="bg-transparent text-xs font-mono text-cyan-400 w-12 focus:outline-none" type="number" min={10} max={1000} value={iterations}
              onChange={e => setIterations(Number(e.target.value))} />
            <span className="text-[10px] text-slate-500 uppercase font-bold">iterations</span>
          </div>
        </div>
        <button className="btn-primary w-full md:w-fit justify-center h-10 px-6" onClick={launch} disabled={running}>
          {running ? <RefreshCw size={14} className="animate-spin" /> : <Play size={14} />}
          {running ? 'Simulating...' : 'Launch Monte Carlo'}
        </button>
      </div>

      {results && (
        <>
          <RiskHeatmap data={heatmapData} />
          <div className="glass-card overflow-hidden">
            <div className="flex items-center justify-between p-5 border-b border-slate-800/50">
              <h3 className="text-xs font-bold text-slate-400 uppercase flex items-center gap-2">
                <Users size={14} className="text-cyan-400" />
                Ranked Attack Paths
              </h3>
              <span className="text-[10px] text-slate-500 font-mono">Synced: {new Date().toLocaleTimeString()}</span>
            </div>
            {paths.length === 0 ? (
              <div className="text-center py-12 text-slate-500 italic text-sm">
                {running ? 'Simulation in progress...' : 'No attack paths generated.'}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-950/20">
                      <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-wider">Attack Type</th>
                      <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-wider w-24">EV Score</th>
                      <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-wider w-24">Probability</th>
                      <th className="py-3 px-5 text-[10px] font-bold text-slate-500 uppercase tracking-wider">Reasoning</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/30">
                    {paths.map((p, i) => (
                      <tr key={i} className="hover:bg-cyan-500/5 transition-colors group">
                        <td className="py-3 px-5 text-xs font-bold text-slate-200 group-hover:text-cyan-400 transition-colors">
                          {p.attack_type || p.path_name || p.name || `Path ${i + 1}`}
                        </td>
                        <td className="py-3 px-5 font-mono text-cyan-400 text-xs">
                          {typeof p.expected_value === 'number' ? p.expected_value.toFixed(3) : '—'}
                        </td>
                        <td className="py-3 px-5 font-mono text-slate-400 text-xs">
                          {typeof p.success_probability === 'number' ? (p.success_probability * 100).toFixed(1) + '%' : '—'}
                        </td>
                        <td className="py-3 px-5 text-[11px] text-slate-500 italic leading-relaxed">
                          {p.decision_reason || p.reasoning || (p.recommended ? 'Recommended path based on swarm heuristics.' : '—')}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
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
    <div className="flex flex-col gap-6">
      <div className="glass-card p-5">
        <h3 className="text-xs font-bold text-slate-400 mb-4 uppercase flex items-center gap-2">
          <Activity size={14} className="text-indigo-400" />
          Workflow Attack Simulation
        </h3>
        <div className="flex flex-col md:flex-row gap-3 mb-4">
          <input className="input flex-1" placeholder="Target (e.g. https://example.com)" value={target} onChange={e => setTarget(e.target.value)} />
          <div className="flex items-center gap-2 bg-slate-950/30 px-3 py-1 rounded-lg border border-slate-800">
            <select className="bg-transparent text-xs font-mono text-cyan-400 focus:outline-none min-w-[150px]" value={workflow} onChange={e => setWorkflow(e.target.value)} disabled={loading}>
              {(workflows.length > 0 ? workflows : defaultWorkflows).map((w, i) => (
                <option key={i} value={typeof w === 'string' ? w : w.name} className="bg-slate-900">{typeof w === 'string' ? w : w.name}</option>
              ))}
            </select>
          </div>
        </div>
        <button className="btn-primary w-full md:w-fit justify-center h-10 px-6" onClick={launch} disabled={running}>
          {running ? <RefreshCw size={14} className="animate-spin" /> : <Play size={14} />}
          {running ? 'Executing...' : 'Launch Workflow Attack'}
        </button>
      </div>

      {results && (
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between px-2">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-widest">Execution Results</span>
            <span className="text-[10px] text-slate-600 font-mono italic">Last sync: {new Date().toLocaleTimeString()}</span>
          </div>
          
          {wfResults.length === 0 ? (
            <div className="glass-card p-12 text-center text-slate-500 italic text-sm">
              {running ? 'Attacking...' : 'No results found.'}
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {wfResults.map((c, i) => (
                <div key={i} className="glass-card p-4 group hover:border-slate-600 transition-all">
                  <div className="flex justify-between items-start mb-3">
                    <span className={clsx(
                      "px-2 py-0.5 rounded text-[9px] font-bold uppercase border",
                      (c.vulnerable || 0) > 0 
                        ? "bg-red-500/10 text-red-400 border-red-500/30" 
                        : "bg-slate-500/10 text-slate-400 border-slate-500/30"
                    )}>
                      {(c.vulnerable || 0) > 0 ? 'Vulnerable' : 'Secure'}
                    </span>
                    <div className="text-[9px] font-mono text-cyan-500 bg-cyan-500/5 px-2 py-0.5 rounded-full border border-cyan-500/20">
                      {c.attacks_run ?? 0} ATTACKS
                    </div>
                  </div>
                  
                  <h4 className="text-sm font-bold text-slate-100 mb-4 group-hover:text-cyan-400 transition-colors uppercase tracking-tight">
                    {c.workflow || c.name || `Workflow ${i + 1}`}
                  </h4>
                  
                  <div className="flex justify-between items-center pt-3 border-t border-slate-800/50">
                    <div className="text-[9px] text-slate-600 uppercase font-bold tracking-wider">
                      Findings
                    </div>
                    <span className="text-xs font-mono text-slate-300">
                      {c.findings_count ?? 0}
                    </span>
                  </div>
                </div>
              ))}
            </div>
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
  const [expandedId, setExpandedId] = useState(null)
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

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between px-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-bold text-slate-400 uppercase tracking-widest">Session Archive ({sessions.length})</span>
          <button className="btn-ghost p-1" onClick={load} disabled={loading}>
            <RefreshCw size={12} className={clsx(loading && 'animate-spin')} />
          </button>
        </div>
        {lastUpdated && <span className="text-[10px] text-slate-600 font-mono">Synced: {lastUpdated}</span>}
      </div>

      {sessions.length === 0 ? (
        <div className="glass-card p-12 text-center text-slate-500 italic text-sm">
          {loading ? 'Decrypting history...' : 'No sessions found in the archive.'}
        </div>
      ) : (
        <SessionTimeline 
          sessions={sessions} 
          onDelete={handleDelete} 
          onExpand={(id) => setExpandedId(expandedId === id ? null : id)}
          expandedId={expandedId}
        />
      )}
    </div>
  )
}


// ── Main ─────────────────────────────────────────────────────────────────────
const TABS = ['Swarm Scan', 'Attack Simulation', 'Workflow Attacks', 'History']

export default function SwarmIntelligence() {
  const [tab, setTab] = useState(0)
  const [historyRefresh, setHistoryRefresh] = useState(0)

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
        <Users size={14} className="text-accent-primary" />
        Swarm Intelligence
      </h1>

      <div className="flex bg-slate-900/40 p-1 rounded-xl w-fit border border-slate-800/50 mb-4">
        {TABS.map((t, i) => (
          <button key={t} onClick={() => setTab(i)}
            className={clsx('px-4 py-1.5 text-[11px] font-bold rounded-lg transition-all',
              tab === i 
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-[0_0_15px_rgba(6,182,212,0.1)]' 
                : 'text-slate-500 hover:text-slate-300')}>
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
