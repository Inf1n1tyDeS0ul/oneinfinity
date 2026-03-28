import React, { useState, useEffect, useRef } from 'react'
import {
  Zap, Play, Square, RefreshCw, Terminal, Clock,
  ShieldAlert, Target, CheckCircle2, AlertTriangle,
  ChevronDown, ChevronUp, ChevronRight, Settings2, Activity,
  Flame, Brain, Users, Search, FileText
} from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import { useLocalStorage } from '../hooks/useLocalStorage'
import clsx from 'clsx'

const MISSION_ICONS = {
  foundation: Search,
  fullscan:   ShieldAlert,
  research:   Brain,
  swarm:      Users,
  chains:     Zap,
  report:     FileText,
}

const MISSION_STATUS_STYLE = {
  running:   'text-cyan-400 badge-running',
  complete:  'text-emerald-400 badge-completed',
  failed:    'text-red-400 badge-failed',
  pending:   'text-slate-500 badge-queued',
  skipped:   'text-slate-600 badge-info',
}

const TERM_REASONS = {
  convergence: { label: 'Converged',   color: 'text-emerald-400', icon: CheckCircle2 },
  time:        { label: 'Time Cap',    color: 'text-yellow-400',  icon: Clock },
  cap:         { label: 'Finding Cap', color: 'text-orange-400',  icon: ShieldAlert },
  stop:        { label: 'Stopped',     color: 'text-slate-400',   icon: Square },
  error:       { label: 'Error',       color: 'text-red-400',     icon: AlertTriangle },
  all_done:    { label: 'All Done',    color: 'text-emerald-400', icon: CheckCircle2 },
}

const MISSIONS = [
  { id: 'foundation', label: 'Foundation' },
  { id: 'fullscan',   label: 'Full Scan' },
  { id: 'research',   label: 'Research' },
  { id: 'swarm',      label: 'Swarm' },
  { id: 'chains',     label: 'Chains' },
  { id: 'report',     label: 'Report' },
]

function WhyPanel({ target }) {
  const [open, setOpen] = useLocalStorage('why-panel-open', false)
  const [priorities, setPriorities] = useState([])

  useEffect(() => {
    if (!target) return
    endpoints.brainPriorities(5)
      .then(r => setPriorities(r.data || []))
      .catch(() => {})
  }, [target])

  if (!target || priorities.length === 0) return null

  return (
    <div className="card mb-5">
      <button
        className="card-header w-full cursor-pointer hover:bg-white/[0.02] transition-colors"
        onClick={() => setOpen(!open)}
      >
        <span className="card-title">
          <Brain size={14} className="text-accent-secondary" />
          Adaptive Recon Intelligence
        </span>
        {open ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
      </button>
      {open && (
        <div className="card-body flex flex-col gap-2">
          {priorities.map((p, i) => (
            <div key={i} className="flex items-start gap-3 text-xs py-2 border-b border-bg-border last:border-0">
              <span className="text-accent-primary font-bold font-mono w-4 flex-shrink-0">#{i + 1}</span>
              <div className="flex-1">
                <p className="text-slate-200 font-medium">{p.target || p.label || p.name || String(p)}</p>
                {p.reasons && Array.isArray(p.reasons) && (
                  <ul className="mt-1 flex flex-col gap-0.5">
                    {p.reasons.map((r, j) => (
                      <li key={j} className="text-slate-500">· {r}</li>
                    ))}
                  </ul>
                )}
              </div>
              {p.score != null && (
                <span className="text-slate-400 font-mono">{Number(p.score).toFixed(2)}</span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function MissionRow({ mission, mData, status, isRunning, isLast, logLevelColor }) {
  const [expanded, setExpanded] = useLocalStorage(`gm-mission-${mission.id}`, false)

  return (
    <div className="flex gap-3">
      {/* Timeline spine */}
      <div className="flex flex-col items-center">
        <div className={clsx(
          'w-7 h-7 rounded-full border-2 flex items-center justify-center flex-shrink-0 text-xs font-bold transition-all',
          status === 'complete' || status === 'completed'
            ? 'border-emerald-500 bg-emerald-500/20 text-emerald-400'
            : isRunning
            ? 'border-cyan-400 bg-cyan-400/20 text-cyan-400 animate-pulse'
            : status === 'failed'
            ? 'border-red-500 bg-red-500/10 text-red-400'
            : 'border-bg-border bg-bg-elevated text-slate-600'
        )}>
          {(status === 'complete' || status === 'completed') ? '✓' : mission.label[0]}
        </div>
        {!isLast && (
          <div className={clsx(
            'w-px flex-1 my-1 min-h-4',
            (status === 'complete' || status === 'completed') ? 'bg-emerald-500/30' : 'bg-bg-border'
          )} />
        )}
      </div>

      {/* Mission content */}
      <div className="flex-1 pb-4">
        <button
          className="w-full flex items-center justify-between gap-2 text-left"
          onClick={() => setExpanded(!expanded)}
        >
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-slate-200">{mission.label}</span>
            <span className={clsx(
              'badge',
              (status === 'complete' || status === 'completed') ? 'badge-completed'
              : isRunning ? 'badge-running'
              : status === 'failed' ? 'badge-failed'
              : 'badge-queued'
            )}>
              {status}
            </span>
          </div>
          <div className="flex items-center gap-3 text-xs text-slate-500">
            {mData.findings_count != null && (
              <span>{mData.findings_count} findings</span>
            )}
            {mData.duration_s != null && (
              <span>{Number(mData.duration_s).toFixed(0)}s</span>
            )}
            <ChevronRight size={12} className={clsx('transition-transform flex-shrink-0', expanded && 'rotate-90')} />
          </div>
        </button>

        {expanded && mData.logs && mData.logs.length > 0 && (
          <div className="mt-2 terminal text-xs max-h-40 overflow-y-auto">
            {mData.logs.map((line, li) => (
              <div key={li} className={logLevelColor ? logLevelColor(line) : 'text-slate-400'}>{line}</div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function formatDuration(secs) {
  if (!secs && secs !== 0) return '—'
  const h = Math.floor(secs / 3600)
  const m = Math.floor((secs % 3600) / 60)
  const s = Math.floor(secs % 60)
  if (h > 0) return `${h}h ${m}m`
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}

export default function GodMode() {
  const { addNotification } = useStore()

  // Launch form
  const [target, setTarget]           = useState('')
  const [maxTime, setMaxTime]         = useState('2h')
  const [maxFindings, setMaxFindings] = useState(100)
  const [noSwarm, setNoSwarm]         = useState(false)
  const [noResearch, setNoResearch]   = useState(false)
  const [reportFmt, setReportFmt]     = useState('markdown')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [launching, setLaunching]     = useState(false)
  const [errors, setErrors]           = useState({})

  // Active session
  const [session, setSession]         = useState(null)
  const [sessions, setSessions]       = useState([])
  const [logs, setLogs]               = useState([])
  const [logsLoading, setLogsLoading] = useState(false)
  const [selectedSessionId, setSelectedSessionId] = useState(null)
  const [stopping, setStopping]       = useState(false)
  const [tab, setTab]                 = useState('status')

  const logBottomRef = useRef(null)
  const pollRef      = useRef(null)

  // ── Poll active session status every 5s ─────────────────────────────────────
  const refresh = async (scanId) => {
    try {
      const r = await endpoints.godModeStatus(scanId || selectedSessionId || undefined)
      const data = r.data
      if (data?.status !== 'no_session' && data?.status !== 'error') {
        setSession(data)
        if (!selectedSessionId && data?.scan_id) setSelectedSessionId(data.scan_id)
      }
    } catch (e) { /* backend not ready */ }
  }

  const refreshSessions = async () => {
    try {
      const r = await endpoints.godModeSessions()
      setSessions(r.data?.sessions || [])
    } catch (e) { setSessions([]) }
  }

  const refreshLogs = async (scanId) => {
    const id = scanId || selectedSessionId
    if (!id) return
    setLogsLoading(true)
    try {
      const r = await endpoints.godModeLogs(id, 200)
      setLogs(r.data?.lines || [])
    } catch (e) { /* no log yet */ }
    finally { setLogsLoading(false) }
  }

  useEffect(() => {
    refresh()
    refreshSessions()
    pollRef.current = setInterval(() => {
      if (session && !session.terminated_by) refresh()
    }, 5000)
    return () => clearInterval(pollRef.current)
  }, [])

  useEffect(() => {
    if (session && !session.terminated_by) {
      clearInterval(pollRef.current)
      pollRef.current = setInterval(() => refresh(), 5000)
    }
    return () => clearInterval(pollRef.current)
  }, [session?.terminated_by, selectedSessionId])

  useEffect(() => {
    if (tab === 'logs' && selectedSessionId) refreshLogs(selectedSessionId)
  }, [tab, selectedSessionId])

  useEffect(() => {
    logBottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  // ── Launch ───────────────────────────────────────────────────────────────────
  const handleLaunch = async () => {
    const e = {}
    if (!target.trim()) e.target = 'Target domain is required'
    if (Object.keys(e).length) { setErrors(e); return }
    setErrors({})
    setLaunching(true)
    try {
      const r = await endpoints.godModeRun({
        target: target.trim(),
        max_time: maxTime,
        max_findings: maxFindings,
        no_swarm: noSwarm,
        no_research: noResearch,
        report_fmt: reportFmt,
      })
      addNotification('GOD MODE launched — Stage 1 starting', 'success')
      setSession(null)
      setTimeout(() => { refresh(); refreshSessions() }, 1500)
    } catch (e) {
      addNotification('Launch failed: ' + (e.response?.data?.detail || e.message), 'error')
    } finally {
      setLaunching(false)
    }
  }

  // ── Stop ─────────────────────────────────────────────────────────────────────
  const handleStop = async () => {
    setStopping(true)
    try {
      const r = await endpoints.godModeStop(session?.scan_id || null)
      if (r.data?.stopped) {
        addNotification('Stop sentinel written — finalizing within 30s', 'success')
        setTimeout(refresh, 3000)
      } else {
        addNotification('No active session to stop', 'warn')
      }
    } catch (e) {
      addNotification('Stop failed: ' + e.message, 'error')
    } finally {
      setStopping(false) }
  }

  // ── Derived ──────────────────────────────────────────────────────────────────
  const isRunning = session && !session.terminated_by
  const missions  = Object.entries(session?.missions || {})
  const elapsed   = session?.elapsed_seconds ?? 0
  const maxSec    = session?.max_time_sec ?? 7200
  const progress  = Math.min(100, (elapsed / maxSec) * 100)
  const termReason = session?.terminated_by ? TERM_REASONS[session.terminated_by] : null

  const logLevelColor = (line) => {
    if (/ERROR|CRITICAL|\[-\]/i.test(line)) return 'text-red-400'
    if (/WARNING|\[!\]/i.test(line)) return 'text-yellow-400'
    if (/\[GOD MODE\]|\[+\]/i.test(line)) return 'text-cyan-400'
    if (/\[Stage|Mission|converge|unlock/i.test(line)) return 'text-purple-400'
    return 'text-slate-400'
  }

  return (
    <div className="flex flex-col gap-5">
      {/* Page header */}
      <div className="section-header">
        <div>
          <div className="section-title flex items-center gap-2.5">
            <Flame size={20} className="text-red-400" style={{ filter: 'drop-shadow(0 0 8px rgba(239,68,68,0.8))' }} />
            <span className="gradient-text" style={{ backgroundImage: 'linear-gradient(90deg,#ff4444,#ff8800,#ffcc00)' }}>
              GOD MODE
            </span>
          </div>
          <div className="text-xs text-slate-500">
            Full adaptive cascade — every capability, zero skip. Foundation → Scan → Research → Swarm → Chains → Report
          </div>
        </div>
        <button className="btn-secondary" onClick={() => { refresh(); refreshSessions() }}>
          <RefreshCw size={13} />Refresh
        </button>
      </div>

      <WhyPanel target={target} />

      {/* Active session banner */}
      {isRunning && (
        <div className="card border-orange-500/30 bg-orange-500/5 glow-orange p-4 flex items-center gap-4">
          <Flame size={18} className="text-orange-400 flex-shrink-0 animate-pulse" />
          <div className="flex-1 min-w-0">
            <div className="text-sm font-semibold text-orange-300">GOD MODE ACTIVE — {session.target}</div>
            <div className="text-xs text-orange-400/70 mt-0.5">
              Session: <span className="font-mono">{session.scan_id}</span> · Elapsed: {formatDuration(elapsed)} / {formatDuration(maxSec)} · Findings: {session.finding_count}
            </div>
            <div className="progress-bar mt-2" style={{ background: 'rgba(249,115,22,0.15)' }}>
              <div className="progress-fill" style={{ width: `${progress}%`, background: 'linear-gradient(90deg,#ff4444,#f97316)' }} />
            </div>
          </div>
          <button
            className="btn-danger flex-shrink-0"
            onClick={handleStop}
            disabled={stopping}
          >
            <Square size={12} />{stopping ? 'Stopping...' : 'Stop'}
          </button>
        </div>
      )}

      {/* Terminated banner */}
      {session?.terminated_by && termReason && (
        <div className="card border-emerald-500/20 bg-emerald-500/5 p-4 flex items-center gap-3">
          <termReason.icon size={16} className={termReason.color} />
          <div>
            <div className={clsx('text-sm font-semibold', termReason.color)}>
              Session Complete — {termReason.label}
            </div>
            <div className="text-xs text-slate-500 mt-0.5">
              {session.target} · {formatDuration(elapsed)} · {session.finding_count} findings
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-5 gap-4">
        {/* Left: Launch form */}
        <div className="col-span-2 flex flex-col gap-4">
          <div className="card">
            <div className="card-header">
              <span className="card-title">
                <Flame size={14} className="text-red-400" />
                Launch GOD MODE
              </span>
            </div>
            <div className="card-body flex flex-col gap-4">
              <div>
                <label className="label">Target</label>
                <input
                  className={`input ${errors.target ? 'input-error' : ''}`}
                  placeholder="target.com"
                  value={target}
                  onChange={e => { setTarget(e.target.value); if (errors.target) setErrors(p => ({...p, target: null})) }}
                />
                {errors.target && <p className="field-error">{errors.target}</p>}
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="label">Max Time</label>
                  <select className="select" value={maxTime} onChange={e => setMaxTime(e.target.value)}>
                    {['30m','1h','2h','4h','6h','12h'].map(t => <option key={t} value={t}>{t}</option>)}
                  </select>
                </div>
                <div>
                  <label className="label">Max Findings</label>
                  <input className="input" type="number" min={1} max={500} value={maxFindings} onChange={e => setMaxFindings(+e.target.value)} />
                </div>
              </div>

              <div>
                <label className="label">Report Format</label>
                <select className="select" value={reportFmt} onChange={e => setReportFmt(e.target.value)}>
                  {['markdown','html','json'].map(f => <option key={f} value={f}>{f}</option>)}
                </select>
              </div>

              {/* Advanced toggle */}
              <button
                className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-300 transition-colors"
                onClick={() => setShowAdvanced(!showAdvanced)}
              >
                <Settings2 size={12} />
                Advanced options
                {showAdvanced ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              </button>

              {showAdvanced && (
                <div className="flex flex-col gap-2 p-3 rounded-lg bg-bg-secondary border border-bg-border">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" checked={noSwarm} onChange={e => setNoSwarm(e.target.checked)} className="rounded" />
                    <span className="text-sm text-slate-300">--no-swarm <span className="text-slate-600 text-xs">(lighter mode)</span></span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" checked={noResearch} onChange={e => setNoResearch(e.target.checked)} className="rounded" />
                    <span className="text-sm text-slate-300">--no-research <span className="text-slate-600 text-xs">(faster mode)</span></span>
                  </label>
                </div>
              )}

              <button
                className={clsx(
                  'btn-lg justify-center rounded-xl font-semibold transition-all',
                  target.trim() && !launching && !isRunning
                    ? 'bg-gradient-to-r from-red-600/80 to-orange-500/80 border border-orange-500/50 text-white hover:from-red-500/80 hover:to-orange-400/80 active:scale-95'
                    : 'bg-bg-elevated border border-bg-border text-slate-500 cursor-not-allowed'
                )}
                onClick={handleLaunch}
                disabled={!target.trim() || launching || isRunning}
              >
                {isRunning ? (
                  <><Activity size={14} className="animate-pulse" />Running...</>
                ) : launching ? (
                  <><RefreshCw size={14} className="animate-spin" />Launching...</>
                ) : (
                  <><Flame size={14} />Activate GOD MODE</>
                )}
              </button>
            </div>
          </div>

          {/* Past sessions */}
          {sessions.length > 0 && (
            <div className="card">
              <div className="card-header">
                <span className="card-title"><Clock size={13} className="text-slate-400" />Session History</span>
              </div>
              <div className="divide-y divide-bg-border">
                {sessions.slice(0, 8).map((s, i) => (
                  <button
                    key={s.scan_id || i}
                    onClick={() => { setSelectedSessionId(s.scan_id); setSession(s); setTab('status') }}
                    className={clsx(
                      'w-full text-left flex items-center gap-3 px-4 py-2.5 hover:bg-white/[0.02] transition-colors',
                      selectedSessionId === s.scan_id && 'bg-accent-primary/5'
                    )}
                  >
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-medium text-slate-200 truncate">{s.target}</div>
                      <div className="text-[10px] text-slate-500 font-mono">{s.scan_id}</div>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <div className={clsx('text-[10px] font-semibold', TERM_REASONS[s.terminated_by]?.color || 'text-cyan-400')}>
                        {s.terminated_by ? TERM_REASONS[s.terminated_by]?.label : 'Running'}
                      </div>
                      <div className="text-[10px] text-slate-600">{s.finding_count ?? 0} findings</div>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right: Status / Logs */}
        <div className="col-span-3 flex flex-col gap-4">
          <div className="tab-bar">
            {[{ id: 'status', label: 'Mission Status' }, { id: 'logs', label: 'Live Logs' }].map(t => (
              <button key={t.id} onClick={() => setTab(t.id)} className={tab === t.id ? 'tab-active' : 'tab'}>{t.label}</button>
            ))}
            {tab === 'logs' && (
              <button className="ml-auto btn-ghost btn-sm" onClick={() => refreshLogs()}>
                <RefreshCw size={11} className={logsLoading ? 'animate-spin' : ''} />
              </button>
            )}
          </div>

          {tab === 'status' && (
            <div className="card flex-1">
              {session ? (
                <div className="card-body flex flex-col gap-5">
                  {/* Session meta */}
                  <div className="grid grid-cols-3 gap-3">
                    {[
                      { label: 'Target', value: session.target, mono: true },
                      { label: 'Session ID', value: session.scan_id, mono: true },
                      { label: 'Elapsed', value: formatDuration(session.elapsed_seconds) },
                      { label: 'Findings', value: `${session.finding_count ?? 0} / ${session.max_findings}` },
                      { label: 'Max Time', value: formatDuration(session.max_time_sec) },
                      { label: 'Status', value: session.terminated_by ? TERM_REASONS[session.terminated_by]?.label : 'Running' },
                    ].map(item => (
                      <div key={item.label} className="p-3 rounded-xl bg-bg-secondary border border-bg-border">
                        <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">{item.label}</div>
                        <div className={clsx('text-sm font-medium text-slate-200 truncate', item.mono && 'font-mono text-xs')}>{item.value}</div>
                      </div>
                    ))}
                  </div>

                  {/* Time progress */}
                  <div>
                    <div className="flex justify-between text-xs text-slate-500 mb-1.5">
                      <span>Time Progress</span>
                      <span>{formatDuration(elapsed)} / {formatDuration(maxSec)}</span>
                    </div>
                    <div className="h-2 bg-bg-muted rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-1000"
                        style={{ width: `${progress}%`, background: progress > 80 ? 'linear-gradient(90deg,#f97316,#ef4444)' : 'linear-gradient(90deg,#00d9ff,#6366f1)' }}
                      />
                    </div>
                  </div>

                  {/* Mission pipeline */}
                  <div className="card">
                    <div className="card-header">
                      <span className="card-title">Mission Pipeline</span>
                    </div>
                    <div className="p-4">
                      {MISSIONS.map((m, i) => {
                        const mData = session?.missions?.[m.id] || {}
                        const rawStatus = typeof mData === 'string' ? mData : (mData.status || 'pending')
                        const mDataObj = typeof mData === 'string' ? { status: mData } : mData
                        const isRowRunning = rawStatus === 'running'
                        return (
                          <MissionRow
                            key={m.id}
                            mission={m}
                            mData={mDataObj}
                            status={rawStatus}
                            isRunning={isRowRunning}
                            isLast={i === MISSIONS.length - 1}
                            logLevelColor={logLevelColor}
                          />
                        )
                      })}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="empty-state">
                  <div className="empty-icon">
                    <Flame size={20} className="text-slate-600" />
                  </div>
                  <div className="empty-title">No GOD MODE session</div>
                  <div className="empty-sub">Launch a session to see the mission pipeline status</div>
                </div>
              )}
            </div>
          )}

          {tab === 'logs' && (
            <div className="card flex-1 flex flex-col">
              <div className="card-header">
                <span className="card-title"><Terminal size={13} className="text-accent-primary" />Session Log</span>
                <span className="text-xs text-slate-600 font-mono">{selectedSessionId || '—'}</span>
              </div>
              <div className="flex-1 overflow-y-auto bg-bg-primary rounded-b-xl p-4 font-mono text-xs h-96 max-h-[60vh]">
                {logsLoading && <div className="text-slate-600">Loading logs...</div>}
                {!logsLoading && logs.length === 0 && (
                  <div className="text-slate-600">
                    {selectedSessionId ? '// No log lines yet — session may just be starting' : '// Select a session to view logs'}
                  </div>
                )}
                {logs.map((line, i) => (
                  <div key={i} className={clsx('leading-5 hover:bg-white/[0.02] px-1 -mx-1 rounded', logLevelColor(line))}>
                    {line}
                  </div>
                ))}
                <div ref={logBottomRef} />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
