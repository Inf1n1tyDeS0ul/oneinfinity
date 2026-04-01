import React, { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Zap, Square, RefreshCw, Terminal, Clock,
  ShieldAlert, CheckCircle2, AlertTriangle,
  ChevronDown, ChevronRight, Activity, Flame, Brain,
  Users, Search, FileText, Trash2, ExternalLink,
  Shield, GitMerge, Lock, Bot, Radar
} from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

// ── Constants ────────────────────────────────────────────────────────────────

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
  running: 'text-cyan-400 badge-running',
  done:    'text-emerald-400 badge-completed',
  failed:  'text-red-400 badge-failed',
  pending: 'text-slate-500 badge-queued',
  skipped: 'text-slate-600 badge-info',
}

const TERM_REASONS = {
  convergence: { label: 'Converged',   color: 'text-emerald-400', icon: CheckCircle2 },
  time:        { label: 'Time Cap',    color: 'text-yellow-400',  icon: Clock },
  cap:         { label: 'Finding Cap', color: 'text-orange-400',  icon: ShieldAlert },
  stop:        { label: 'Stopped',     color: 'text-slate-400',   icon: Square },
  error:       { label: 'Error',       color: 'text-red-400',     icon: AlertTriangle },
  all_done:    { label: 'All Done',    color: 'text-emerald-400', icon: CheckCircle2 },
}

// Modules — what God Mode runs. Swarm and Research are the two toggleable ones.
const ALL_MODULES = [
  { id: 'recon',          label: 'Recon',           icon: Radar,     desc: 'Subdomain enum, port scan, crawling, fingerprinting',           always: true },
  { id: 'vuln_scan',      label: 'Vuln Scan',       icon: ShieldAlert, desc: 'Nuclei, dalfox, sqlmap, CRLFUZZ, KXSS',                       always: true },
  { id: 'active_testing', label: 'Active Testing',  icon: Zap,       desc: 'Swarm agents: XSS, SQLi, SSRF, IDOR, CORS, JWT, Auth, IDOR',   key: 'swarm' },
  { id: 'auth',           label: 'Auth & Sessions', icon: Lock,      desc: 'Default creds, session reuse, CSRF, cookie checks',             always: true },
  { id: 'business_logic', label: 'Business Logic',  icon: GitMerge,  desc: 'Race conditions, price manipulation, workflow skips',            always: true },
  { id: 'chains',         label: 'Exploit Chains',  icon: GitMerge,  desc: 'Cross-finding chains: SSRF→RCE, XSS→ATO, SQLi→bypass',         always: true },
  { id: 'ai_hypothesis',  label: 'AI Hypothesis',   icon: Brain,     desc: 'AI-driven iterative hypothesis testing on uncovered classes',    key: 'research' },
  { id: 'ai_llm',         label: 'AI/LLM Testing',  icon: Bot,       desc: 'Prompt injection, jailbreaks, model attacks (AI product targets)', key: 'ai_llm', comingSoon: true },
]

// Presets — map to backend no_swarm / no_research flags
const PRESETS = [
  {
    id: 'quick',
    label: 'Quick',
    desc: 'Fast sweep, high/critical only',
    color: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
    activeColor: 'border-blue-400 bg-blue-500/20 text-blue-200',
    no_swarm: true,
    no_research: true,
    modules: ['recon', 'vuln_scan', 'auth', 'business_logic', 'chains'],
  },
  {
    id: 'standard',
    label: 'Standard',
    desc: 'Full pipeline + swarm + AI research',
    color: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300',
    activeColor: 'border-cyan-400 bg-cyan-500/20 text-cyan-200',
    no_swarm: false,
    no_research: false,
    modules: ['recon', 'vuln_scan', 'active_testing', 'auth', 'business_logic', 'chains', 'ai_hypothesis'],
  },
  // Deep runs the same modules as Standard; the distinction is depth/intensity enforced by the engine
  {
    id: 'deep',
    label: 'Deep',
    desc: 'Everything — swarm + AI research',
    color: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
    activeColor: 'border-orange-400 bg-orange-500/20 text-orange-200',
    no_swarm: false,
    no_research: false,
    modules: ['recon', 'vuln_scan', 'active_testing', 'auth', 'business_logic', 'chains', 'ai_hypothesis'],
  },
  {
    id: 'stealth',
    label: 'Stealth',
    desc: 'Passive recon only, zero active probes',
    color: 'border-slate-500/40 bg-slate-500/10 text-slate-300',
    activeColor: 'border-slate-400 bg-slate-500/20 text-slate-200',
    no_swarm: true,
    no_research: true,
    stealth: true,
    modules: ['recon'],
  },
  {
    id: 'custom',
    label: 'Custom',
    desc: 'Pick modules + intensity yourself',
    color: 'border-violet-500/40 bg-violet-500/10 text-violet-300',
    activeColor: 'border-violet-400 bg-violet-500/20 text-violet-200',
    no_swarm: false,
    no_research: false,
    modules: [],
  },
]

function formatDuration(secs) {
  if (!secs && secs !== 0) return '—'
  const h = Math.floor(secs / 3600)
  const m = Math.floor((secs % 3600) / 60)
  const s = Math.floor(secs % 60)
  if (h > 0) return `${h}h ${m}m`
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}

function detectTargetType(url) {
  if (!url || !url.includes('.')) return null
  const u = url.toLowerCase()
  if (u.endsWith('.apk') || u.endsWith('.ipa')) return 'mobile'
  if (u.includes('/api/') || u.includes('/graphql') ||
      u.match(/^https?:\/\/api\./) || u.match(/^https?:\/\/graphql\./)) return 'api'
  if (/\b(chat|llm|gpt|bot)\b/.test(u) || u.match(/^https?:\/\/ai\./)) return 'ai'
  return 'web'
}

const TYPE_TO_PRESET = {
  mobile: 'quick',
  api:    'standard',
  ai:     'standard',
  web:    'deep',
}

const INTENSITY_COLORS = {
  low:        'border-blue-500/40 text-blue-300',
  medium:     'border-cyan-500/40 text-cyan-300',
  high:       'border-orange-500/40 text-orange-300',
  aggressive: 'border-red-500/40 text-red-300',
}

// ── Component ────────────────────────────────────────────────────────────────

export default function GodMode() {
  const { addNotification } = useStore()
  const navigate = useNavigate()

  // Launch form state
  const [target, setTarget]       = useState('')
  const [preset, setPreset]       = useState('deep')
  const [reportFmt, setReportFmt] = useState('markdown')
  const [launching, setLaunching] = useState(false)
  const [showAuth, setShowAuth]   = useState(false)
  const [authType, setAuthType]   = useState('none')
  const [authValue, setAuthValue] = useState('')

  // Auto-detection state
  const [detectedType, setDetectedType]         = useState(null)   // 'web'|'api'|'mobile'|'ai'|null
  const [userPickedPreset, setUserPickedPreset] = useState(false)

  // Custom preset module configuration
  const [customModules, setCustomModules] = useState({
    recon:          { enabled: true,  intensity: 'medium' },
    vuln_scan:      { enabled: true,  intensity: 'medium' },
    active_testing: { enabled: false, intensity: 'medium' },
    auth:           { enabled: true,  intensity: 'medium' },
    business_logic: { enabled: false, intensity: 'medium' },
    chains:         { enabled: false, intensity: 'medium' },
    ai_hypothesis:  { enabled: false, intensity: 'medium' },
    ai_llm:        { enabled: false, intensity: 'medium' },
  })

  // Session state
  const [session, setSession]               = useState(null)
  const [sessions, setSessions]             = useState([])
  const [logs, setLogs]                     = useState([])
  const [logsLoading, setLogsLoading]       = useState(false)
  const [selectedSessionId, setSelectedSessionId] = useState(null)
  const [stopping, setStopping]             = useState(false)
  const [tab, setTab]                       = useState('status')

  const logBottomRef = useRef(null)
  const pollRef      = useRef(null)

  const activePreset = PRESETS.find(p => p.id === preset) || PRESETS.find(p => p.id === 'deep')

  // ── Data refresh ──────────────────────────────────────────────────────────
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

  useEffect(() => { refresh(); refreshSessions() }, [])

  useEffect(() => {
    clearInterval(pollRef.current)
    if (session && !session.terminated_by) {
      pollRef.current = setInterval(() => refresh(), 5000)
    }
    return () => clearInterval(pollRef.current)
  }, [session?.terminated_by, selectedSessionId])

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

  // URL auto-detection — runs 400ms after target changes
  useEffect(() => {
    if (!target.trim() || userPickedPreset) {
      if (!target.trim()) setDetectedType(null)
      return
    }
    const timer = setTimeout(() => {
      const type = detectTargetType(target.trim())
      setDetectedType(type)
      if (type) setPreset(TYPE_TO_PRESET[type])
    }, 400)
    return () => clearTimeout(timer)
  }, [target, userPickedPreset])

  // ── Launch ────────────────────────────────────────────────────────────────
  const handleLaunch = async () => {
    if (!target.trim()) return
    if (preset === 'custom') {
      const hasAny = Object.values(customModules).some(c => c.enabled)
      if (!hasAny) {
        addNotification('Select at least one module before launching', 'warn')
        return
      }
    }
    setLaunching(true)
    try {
      const authPayload = {}
      if (authType === 'cookie' && authValue.trim())  authPayload.session_cookie = authValue.trim()
      if (authType === 'bearer' && authValue.trim())  authPayload.bearer_token   = authValue.trim()
      if (authType === 'header' && authValue.trim())  authPayload.auth_header    = authValue.trim()

      const isCustom = preset === 'custom'
      const comingSoonIds = new Set(ALL_MODULES.filter(m => m.comingSoon).map(m => m.id))
      const enabledModules = isCustom
        ? Object.entries(customModules)
            .filter(([id, c]) => c.enabled && !comingSoonIds.has(id))
            .map(([id]) => id)
        : []
      const moduleIntensities = isCustom
        ? Object.fromEntries(
            Object.entries(customModules)
              .filter(([id, c]) => c.enabled && !comingSoonIds.has(id))
              .map(([id, c]) => [id, c.intensity])
          )
        : {}
      const launchLabel = isCustom
        ? `Custom (${enabledModules.length} modules)`
        : activePreset.label

      await endpoints.godModeRun({
        target:       target.trim(),
        max_time:     '0',
        max_findings: 0,
        no_swarm:     activePreset.no_swarm,
        no_research:  activePreset.no_research,
        report_fmt:   reportFmt,
        ...(isCustom && enabledModules.length > 0 && {
          modules:     enabledModules,
          intensities: moduleIntensities,
        }),
        ...authPayload,
      })
      addNotification(`GOD MODE launched (${launchLabel}) — Foundation starting`, 'success')
      setSession(null)
      setTimeout(() => { refresh(); refreshSessions() }, 1500)
    } catch (e) {
      addNotification('Launch failed: ' + (e.response?.data?.detail || e.message), 'error')
    } finally {
      setLaunching(false)
    }
  }

  // ── Stop / Delete ─────────────────────────────────────────────────────────
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
    } finally { setStopping(false) }
  }

  const handleDelete = async (scanId, e) => {
    e.stopPropagation()
    if (!window.confirm('Delete this session state and logs?')) return
    try {
      await endpoints.godModeDelete(scanId)
      addNotification('Session deleted', 'success')
      if (selectedSessionId === scanId) { setSession(null); setSelectedSessionId(null) }
      refreshSessions()
    } catch (e) {
      addNotification('Delete failed: ' + e.message, 'error')
    }
  }

  // ── Derived ───────────────────────────────────────────────────────────────
  const isRunning  = session && !session.terminated_by
  const missions   = Object.entries(session?.missions || {})
  const elapsed    = session?.elapsed_seconds ?? 0
  const termReason = session?.terminated_by ? TERM_REASONS[session.terminated_by] : null

  const logLevelColor = (line) => {
    if (/ERROR|CRITICAL|\[-\]/i.test(line)) return 'text-red-400'
    if (/WARNING|\[!\]/i.test(line)) return 'text-yellow-400'
    if (/\[GOD MODE\]|\[\+\]/i.test(line)) return 'text-cyan-400'
    if (/\[Stage|Mission|converge|unlock/i.test(line)) return 'text-purple-400'
    return 'text-slate-400'
  }

  // Summary for Custom preset card
  const customEnabledModules = Object.values(customModules).filter(c => c.enabled)
  const customIntensitySet   = [...new Set(customEnabledModules.map(c => c.intensity))]
  const customSummary = customEnabledModules.length === 0
    ? 'no modules selected'
    : `${customEnabledModules.length} module${customEnabledModules.length > 1 ? 's' : ''} · ${customIntensitySet.length > 1 ? 'Mixed intensity' : (customIntensitySet[0] ?? 'medium')}`

  return (
    <div className="flex flex-col gap-5">
      {/* Header */}
      <div className="section-header">
        <div>
          <div className="section-title flex items-center gap-2.5">
            <Flame size={20} className="text-red-400" style={{ filter: 'drop-shadow(0 0 8px rgba(239,68,68,0.8))' }} />
            <span className="gradient-text" style={{ backgroundImage: 'linear-gradient(90deg,#ff4444,#ff8800,#ffcc00)' }}>
              GOD MODE
            </span>
          </div>
          <div className="text-xs text-slate-500">
            Adaptive autonomous scanner — configure scope and modules, then launch
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
              Session: <span className="font-mono">{session.scan_id}</span> · Elapsed: {formatDuration(elapsed)} · Findings: {session.finding_count}
            </div>
            <div className="progress-bar mt-2" style={{ background: 'rgba(249,115,22,0.15)' }}>
              <div className="progress-fill animate-pulse" style={{ width: '100%', background: 'linear-gradient(90deg,#ff4444,#f97316)' }} />
            </div>
          </div>
          <button className="btn-danger flex-shrink-0" onClick={handleStop} disabled={stopping}>
            <Square size={12} />{stopping ? 'Stopping...' : 'Stop'}
          </button>
        </div>
      )}

      {/* Completed banner */}
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
          <button className="btn-secondary flex-shrink-0" onClick={() => navigate('/results')}>
            <ExternalLink size={12} />View Findings
          </button>
        </div>
      )}

      <div className="grid grid-cols-5 gap-4">
        {/* ── Left: Launch Form ─────────────────────────────────────────────── */}
        <div className="col-span-2 flex flex-col gap-4">
          <div className="card">
            <div className="card-header">
              <span className="card-title">
                <Flame size={14} className="text-red-400" />
                Launch Scan
              </span>
            </div>
            <div className="card-body flex flex-col gap-5">

              {/* Target */}
              <div>
                <label className="label">Target</label>
                <input
                  className={clsx('input', detectedType && !userPickedPreset && 'border-cyan-500/40 shadow-[0_0_0_2px_rgba(0,217,255,0.08)]')}
                  placeholder="https://target.com"
                  value={target}
                  onChange={e => { setTarget(e.target.value); setUserPickedPreset(false) }}
                  onKeyDown={e => e.key === 'Enter' && !isRunning && !launching && target.trim() && handleLaunch()}
                />
                {detectedType && !userPickedPreset && target.trim() && (
                  <div className="flex items-center gap-1.5 mt-1.5 text-[10px] text-cyan-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse flex-shrink-0" />
                    Detected: {detectedType.toUpperCase()} target — switched to {TYPE_TO_PRESET[detectedType]}
                  </div>
                )}
              </div>

              {/* Scope Presets */}
              <div>
                <label className="label">Scope</label>
                <div className="grid grid-cols-2 gap-2">
                  {PRESETS.map(p => (
                    <button
                      key={p.id}
                      onClick={() => { setPreset(p.id); setUserPickedPreset(true) }}
                      className={clsx(
                        'flex flex-col items-start gap-0.5 p-3 rounded-xl border text-left transition-all',
                        p.id === 'custom' && 'col-span-2',
                        preset === p.id ? p.activeColor : p.color + ' opacity-70 hover:opacity-100'
                      )}
                    >
                      <div className="flex items-center gap-2 w-full">
                        <span className="text-xs font-semibold">{p.label}</span>
                        {p.id === 'custom' && preset === 'custom' && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-violet-500/20 border border-violet-500/30 text-violet-300">
                            {customSummary}
                          </span>
                        )}
                      </div>
                      <span className="text-[10px] opacity-70 leading-tight">{p.desc}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Modules — badges for presets, interactive rows for Custom */}
              <div>
                <label className="label">
                  Modules
                  {preset === 'custom' && (
                    <span className="ml-2 text-[9px] text-slate-500 normal-case tracking-normal">
                      check to enable · set intensity per module
                    </span>
                  )}
                </label>

                {preset !== 'custom' ? (
                  <div className="flex flex-wrap gap-1.5">
                    {ALL_MODULES.map(m => {
                      const included = activePreset.modules.includes(m.id)
                      return (
                        <div
                          key={m.id}
                          title={m.desc}
                          className={clsx(
                            'flex items-center gap-1 px-2 py-1 rounded-lg border text-[10px] font-medium transition-all',
                            m.comingSoon
                              ? 'border-slate-700 text-slate-600 bg-transparent'
                              : included
                              ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300'
                              : 'border-slate-700 text-slate-600 bg-transparent line-through'
                          )}
                        >
                          <m.icon size={9} />
                          {m.label}
                          {m.comingSoon && <span className="text-[8px] text-slate-600 ml-0.5">soon</span>}
                        </div>
                      )
                    })}
                  </div>
                ) : (
                  <div className="flex flex-col gap-1.5">
                    {ALL_MODULES.filter(m => !m.comingSoon).map(m => {
                      const cfg = customModules[m.id]
                      const enabled = cfg?.enabled ?? false
                      const intensity = cfg?.intensity ?? 'medium'
                      return (
                        <div
                          key={m.id}
                          className={clsx(
                            'flex items-center gap-2.5 px-3 py-2 rounded-lg border transition-all',
                            enabled
                              ? 'border-cyan-500/20 bg-cyan-500/[0.04]'
                              : 'border-slate-700/60 bg-bg-secondary opacity-50'
                          )}
                        >
                          {/* Checkbox */}
                          <button
                            onClick={() => setCustomModules(prev => ({
                              ...prev,
                              [m.id]: { ...prev[m.id], enabled: !enabled }
                            }))}
                            className={clsx(
                              'w-4 h-4 rounded flex-shrink-0 flex items-center justify-center border transition-all',
                              enabled
                                ? 'bg-cyan-400 border-cyan-400 text-black'
                                : 'border-slate-600 bg-transparent'
                            )}
                          >
                            {enabled && <span className="text-[9px] font-black leading-none">✓</span>}
                          </button>

                          {/* Info */}
                          <div className="flex-1 min-w-0">
                            <div className="text-[11px] font-semibold text-slate-200">{m.label}</div>
                            <div className="text-[9px] text-slate-500 truncate">{m.desc}</div>
                          </div>

                          {/* Intensity selector */}
                          <select
                            disabled={!enabled}
                            value={intensity}
                            onChange={e => setCustomModules(prev => ({
                              ...prev,
                              [m.id]: { ...prev[m.id], intensity: e.target.value }
                            }))}
                            className={clsx(
                              'text-[10px] bg-bg-elevated border rounded-md px-1.5 py-1 flex-shrink-0 transition-all',
                              enabled
                                ? (INTENSITY_COLORS[intensity] ?? INTENSITY_COLORS.medium)
                                : 'border-slate-700 text-slate-600'
                            )}
                          >
                            <option value="low">Low</option>
                            <option value="medium">Medium</option>
                            <option value="high">High</option>
                            <option value="aggressive">Aggressive</option>
                          </select>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>

              {/* Report Format */}
              <div>
                <label className="label">Report Format</label>
                <select className="select" value={reportFmt} onChange={e => setReportFmt(e.target.value)}>
                  {['markdown', 'html', 'json', 'pdf'].map(f => <option key={f} value={f}>{f}</option>)}
                </select>
              </div>

              {/* Authentication */}
              <div>
                <button
                  className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-300 transition-colors w-full"
                  onClick={() => setShowAuth(!showAuth)}
                >
                  <Shield size={12} />
                  Authentication
                  <span className="text-slate-600 text-[10px]">(optional — deeper coverage)</span>
                  <span className="ml-auto">{showAuth ? <ChevronDown size={12} /> : <ChevronRight size={12} />}</span>
                </button>

                {showAuth && (
                  <div className="flex flex-col gap-3 mt-3 p-3 rounded-lg bg-bg-secondary border border-cyan-500/20">
                    <div className="text-[10px] text-cyan-400/80 leading-relaxed">
                      Enables authenticated scanning: IDOR, privilege escalation, post-login business logic, PII exposure.
                    </div>
                    <div>
                      <label className="label">Auth Type</label>
                      <select className="select" value={authType} onChange={e => { setAuthType(e.target.value); setAuthValue('') }}>
                        <option value="none">None (unauthenticated)</option>
                        <option value="cookie">Session Cookie</option>
                        <option value="bearer">Bearer Token (JWT)</option>
                        <option value="header">Raw Auth Header</option>
                      </select>
                    </div>
                    {authType !== 'none' && (
                      <div>
                        <label className="label">
                          {authType === 'cookie' && 'Cookie Value'}
                          {authType === 'bearer' && 'Bearer Token'}
                          {authType === 'header' && 'Raw Header Value'}
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
                          <div className="text-[10px] text-emerald-400 mt-1 flex items-center gap-1">
                            <CheckCircle2 size={9} /> Authenticated scanning enabled
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Launch button */}
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
                  <><Flame size={14} />Launch GOD MODE</>
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
                      onClick={e => handleDelete(s.scan_id, e)}
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

        {/* ── Right: Status / Logs ──────────────────────────────────────────── */}
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
                      { label: 'Target',       value: session.target,                         mono: true },
                      { label: 'Session ID',   value: session.scan_id,                        mono: true },
                      { label: 'Elapsed',      value: formatDuration(session.elapsed_seconds) },
                      { label: 'Findings',     value: `${session.finding_count ?? 0}` },
                      { label: 'Phases Done',  value: `${(session.phases_complete || []).length}` },
                      { label: 'Status',       value: session.terminated_by ? TERM_REASONS[session.terminated_by]?.label : 'Running' },
                    ].map(item => (
                      <div key={item.label} className="p-3 rounded-xl bg-bg-secondary border border-bg-border">
                        <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">{item.label}</div>
                        <div className={clsx('text-sm font-medium text-slate-200 truncate', item.mono && 'font-mono text-xs')}>{item.value}</div>
                      </div>
                    ))}
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
                                isActive  ? 'border-cyan-500/30 bg-cyan-500/5' :
                                isDone    ? 'border-emerald-500/20 bg-emerald-500/5' :
                                status === 'failed' ? 'border-red-500/20 bg-red-500/5' :
                                'border-bg-border bg-bg-secondary'
                              )}
                            >
                              <div className={clsx(
                                'w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0',
                                isActive ? 'bg-cyan-500/20 text-cyan-400' :
                                isDone   ? 'bg-emerald-500/20 text-emerald-400' :
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
                  <div className="empty-icon"><Flame size={20} className="text-slate-600" /></div>
                  <div className="empty-title">No active session</div>
                  <div className="empty-sub">Configure scope and launch a scan to see the mission pipeline</div>
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
