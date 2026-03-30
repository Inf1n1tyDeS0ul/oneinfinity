import React, { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Zap, Play, Square, RefreshCw, Terminal, Clock,
  ShieldAlert, Target, CheckCircle2, AlertTriangle,
  ChevronDown, ChevronRight, Settings2, Activity,
  Flame, Brain, Users, Search, FileText, Trash2, ExternalLink
} from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

const MISSION_ICONS = {
  foundation: Search,
  full_scan:  ShieldAlert,
  research:   Brain,
  swarm:      Users,
  chains:     Zap,
  report:     FileText,
}

const MISSION_DISPLAY_NAMES = {
  foundation: 'Foundation',
  full_scan:  'Full Scan',
  research:   'Research',
  swarm:      'Swarm',
  chains:     'Chains',
  report:     'Report',
}

const MISSION_STATUS_STYLE = {
  running:   'text-cyan-400 badge-running',
  done:      'text-emerald-400 badge-completed',
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
  const navigate = useNavigate()

  // Launch form
  const [target, setTarget]           = useState('')
  const [maxTime, setMaxTime]         = useState('2h')
  const [maxFindings, setMaxFindings] = useState(100)
  const [noSwarm, setNoSwarm]         = useState(false)
  const [noResearch, setNoResearch]   = useState(false)
  const [reportFmt, setReportFmt]     = useState('markdown')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [launching, setLaunching]     = useState(false)
  // Authenticated scanning
  const [showAuth, setShowAuth]       = useState(false)
  const [authType, setAuthType]       = useState('none')   // none | cookie | bearer | header
  const [authValue, setAuthValue]     = useState('')

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

  // On mount: load latest session + session list
  useEffect(() => {
    refresh()
    refreshSessions()
  }, [])

  // Status polling: runs every 5s while a session is active, clears when done
  useEffect(() => {
    clearInterval(pollRef.current)
    if (session && !session.terminated_by) {
      pollRef.current = setInterval(() => refresh(), 5000)
    }
    return () => clearInterval(pollRef.current)
  }, [session?.terminated_by, selectedSessionId])

  // Log refresh: on tab switch + auto-refresh every 8s when scan is running
  useEffect(() => {
    if (tab === 'logs' && selectedSessionId) refreshLogs(selectedSessionId)
  }, [tab, selectedSessionId])

  useEffect(() => {
    const active = !!(session && !session.terminated_by)
    if (tab !== 'logs' || !selectedSessionId || !active) return
    const id = setInterval(() => refreshLogs(selectedSessionId), 8000)
    return () => clearInterval(id)
  }, [tab, selectedSessionId, session?.terminated_by])

  useEffect(() => {
    logBottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  // ── Launch ───────────────────────────────────────────────────────────────────
  const handleLaunch = async () => {
    if (!target.trim()) return
    setLaunching(true)
    try {
      const authPayload = {}
      if (authType === 'cookie' && authValue.trim()) {
        authPayload.session_cookie = authValue.trim()
      } else if (authType === 'bearer' && authValue.trim()) {
        authPayload.bearer_token = authValue.trim()
      } else if (authType === 'header' && authValue.trim()) {
        authPayload.auth_header = authValue.trim()
      }
      const r = await endpoints.godModeRun({
        target: target.trim(),
        max_time: maxTime,
        max_findings: maxFindings,
        no_swarm: noSwarm,
        no_research: noResearch,
        report_fmt: reportFmt,
        ...authPayload,
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

  const handleDelete = async (scanId, e) => {
    e.stopPropagation()
    if (!window.confirm('Delete this session state and logs?')) return
    try {
      await endpoints.godModeDelete(scanId)
      addNotification('Session deleted', 'success')
      if (selectedSessionId === scanId) {
        setSession(null)
        setSelectedSessionId(null)
      }
      refreshSessions()
    } catch (e) {
      addNotification('Delete failed: ' + e.message, 'error')
    }
  }

  // ── Derived ──────────────────────────────────────────────────────────────────
  const isRunning  = session && !session.terminated_by
  const missions   = Object.entries(session?.missions || {})
  const elapsed    = session?.elapsed_seconds ?? 0
  const maxSec     = session?.max_time_sec ?? 7200
  // Show 100% progress when scan is done, actual % while running
  const progress   = session?.terminated_by ? 100 : Math.min(100, (elapsed / maxSec) * 100)
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
          <div className="flex-1">
            <div className={clsx('text-sm font-semibold', termReason.color)}>
              Session Complete — {termReason.label}
            </div>
            <div className="text-xs text-slate-500 mt-0.5">
              {session.target} · Completed in {formatDuration(elapsed)} · {session.finding_count} findings
            </div>
          </div>
          <button
            className="btn-secondary flex-shrink-0"
            onClick={() => navigate('/results')}
          >
            <ExternalLink size={12} />View Findings
          </button>
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
                  className="input"
                  placeholder="target.com"
                  value={target}
                  onChange={e => setTarget(e.target.value)}
                />
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

              {/* Authentication — optional; unlocks authenticated scan coverage */}
              <button
                className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-300 transition-colors"
                onClick={() => setShowAuth(!showAuth)}
              >
                <ShieldAlert size={12} />
                Authentication <span className="text-slate-600">(optional — for deeper coverage)</span>
                {showAuth ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              </button>

              {showAuth && (
                <div className="flex flex-col gap-3 p-3 rounded-lg bg-bg-secondary border border-cyan-500/20">
                  <div className="text-xs text-cyan-400/80">
                    Providing credentials enables authenticated scanning: IDOR, privilege escalation, post-login business logic, and PII exposure in authenticated API responses.
                  </div>
                  <div>
                    <label className="label">Auth Type</label>
                    <select className="select" value={authType} onChange={e => { setAuthType(e.target.value); setAuthValue('') }}>
                      <option value="none">None (unauthenticated scan)</option>
                      <option value="cookie">Session Cookie</option>
                      <option value="bearer">Bearer Token (JWT)</option>
                      <option value="header">Raw Auth Header</option>
                    </select>
                  </div>
                  {authType !== 'none' && (
                    <div>
                      <label className="label">
                        {authType === 'cookie'  && 'Cookie Value (e.g. session=abc123; csrf=xyz)'}
                        {authType === 'bearer'  && 'Bearer Token (JWT — paste token only, no "Bearer" prefix)'}
                        {authType === 'header'  && 'Raw Header Value (e.g. Bearer eyJ... or Token abc123)'}
                      </label>
                      <input
                        className="input font-mono text-xs"
                        placeholder={
                          authType === 'cookie' ? 'session=abc123; _csrf=xyz789' :
                          authType === 'bearer' ? 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' :
                          'Bearer eyJhbGciOiJIUzI1NiJ9...'
                        }
                        value={authValue}
                        onChange={e => setAuthValue(e.target.value)}
                      />
                      {authValue && (
                        <div className="text-xs text-emerald-400 mt-1 flex items-center gap-1">
                          <CheckCircle2 size={10} /> Authenticated scanning enabled — IDOR, post-auth business logic, and PII checks will run with these credentials.
                        </div>
                      )}
                    </div>
                  )}
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
                  <div
                    key={s.scan_id || i}
                    onClick={() => { setSelectedSessionId(s.scan_id); setSession(s); setTab('status') }}
                    className={clsx(
                      'w-full text-left flex items-center gap-3 px-4 py-2.5 hover:bg-white/[0.02] transition-colors cursor-pointer group',
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
                    <button
                      className="btn-icon text-slate-600 hover:text-red-400 p-1 opacity-0 group-hover:opacity-100 transition-opacity"
                      onClick={(e) => handleDelete(s.scan_id, e)}
                      title="Delete session"
                    >
                      <Trash2 size={12} />
                    </button>
                  </div>
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
                      <span>
                        {session?.terminated_by
                          ? `Completed in ${formatDuration(elapsed)}`
                          : `${formatDuration(elapsed)} / ${formatDuration(maxSec)}`}
                      </span>
                    </div>
                    <div className="h-2 bg-bg-muted rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-1000"
                        style={{
                          width: `${progress}%`,
                          background: session?.terminated_by
                            ? 'linear-gradient(90deg,#10b981,#34d399)'
                            : progress > 80
                            ? 'linear-gradient(90deg,#f97316,#ef4444)'
                            : 'linear-gradient(90deg,#00d9ff,#6366f1)'
                        }}
                      />
                    </div>
                  </div>

                  {/* Mission pipeline */}
                  {missions.length > 0 && (
                    <div>
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Mission Pipeline</div>
                      <div className="flex flex-col gap-2">
                        {missions.map(([name, status], i) => {
                          const Icon = MISSION_ICONS[name] || Zap
                          const statusStyle = MISSION_STATUS_STYLE[status] || 'text-slate-500 badge-info'
                          const isActive = status === 'running'
                          const isDone   = status === 'done'
                          return (
                            <div
                              key={name}
                              className={clsx(
                                'flex items-center gap-3 p-3 rounded-xl border transition-all',
                                isActive
                                  ? 'border-cyan-500/30 bg-cyan-500/5'
                                  : isDone
                                  ? 'border-emerald-500/20 bg-emerald-500/5'
                                  : status === 'failed'
                                  ? 'border-red-500/20 bg-red-500/5'
                                  : 'border-bg-border bg-bg-secondary'
                              )}
                            >
                              {/* Step number */}
                              <div className={clsx(
                                'w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0',
                                isActive ? 'bg-cyan-500/20 text-cyan-400' :
                                isDone ? 'bg-emerald-500/20 text-emerald-400' :
                                'bg-bg-elevated text-slate-600'
                              )}>{i + 1}</div>
                              <Icon size={13} className={isActive ? 'text-cyan-400' : isDone ? 'text-emerald-400' : 'text-slate-600'} />
                              <div className="flex-1">
                                <span className={clsx('text-sm font-medium', isActive ? 'text-slate-100' : 'text-slate-400')}>
                                  {MISSION_DISPLAY_NAMES[name] || name} Mission
                                </span>
                              </div>
                              <span className={clsx('badge', statusStyle)}>
                                {isActive && <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse mr-1" />}
                                {status}
                              </span>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}
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
