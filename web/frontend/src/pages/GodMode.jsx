import React, { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  RefreshCw, Terminal,
  CheckCircle2,
  Activity, Flame,
  Zap, X, Radar, Menu, Shield
} from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

// Components
import LaunchPad from '../components/GodMode/LaunchPad'
import VitalSignsHUD from '../components/GodMode/VitalSignsHUD'
import MissionPipeline from '../components/GodMode/MissionPipeline'
import InsightFeed from '../components/GodMode/InsightFeed'
import VulnChainGraph from '../components/Graph/VulnChainGraph'

// ── Constants ────────────────────────────────────────────────────────────────

const PRESETS = [
  { id: 'quick',    no_swarm: true,  no_research: true },
  { id: 'standard', no_swarm: false, no_research: false },
  { id: 'deep',     no_swarm: false, no_research: false },
  { id: 'stealth',  no_swarm: true,  no_research: true, stealth: true },
  { id: 'custom',   no_swarm: false, no_research: false },
]

const TYPE_TO_PRESET = {
  mobile: 'quick',
  api:    'standard',
  ai:     'standard',
  web:    'deep',
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

// ── Component ────────────────────────────────────────────────────────────────

export default function GodMode() {
  const { addNotification, setVulnerabilities } = useStore()
  const navigate = useNavigate()

  // Layout state
  const [showLogs, setShowLogs] = useState(false)
  const [showSidebar, setShowSidebar] = useState(true)

  // Launch form state
  const [target, setTarget]       = useState('')
  const [preset, setPreset]       = useState('deep')
  const [reportFmt, setReportFmt] = useState('markdown')
  const [launching, setLaunching] = useState(false)
  const [showAuth, setShowAuth]   = useState(false)
  const [authType, setAuthType]   = useState('none')
  const [authValue, setAuthValue] = useState('')
  const [savedSessions, setSavedSessions]         = useState([])
  const [authSessionId, setAuthSessionId]         = useState('')
  const [appContext, setAppContext]               = useState('')
  const [isRecording, setIsRecording]             = useState(false)
  const [recordingId, setRecordingId]             = useState(null)
  const [recordingWarning, setRecordingWarning]   = useState('')
  const [loginFormDetected, setLoginFormDetected]  = useState(null)

  // Safety Gate state
  const [approvalRequest, setApprovalRequest] = useState(null)

  // Auto-detection state
  const [detectedType, setDetectedType]         = useState(null)
  const [userPickedPreset, setUserPickedPreset] = useState(false)

  // Custom preset module configuration
  const [customModules, setCustomModules] = useState({
    recon:               { enabled: true,  intensity: 'medium' },
    vuln_scan:           { enabled: true,  intensity: 'medium' },
    active_testing:      { enabled: false, intensity: 'medium' },
    auth:                { enabled: true,  intensity: 'medium' },
    business_logic:      { enabled: false, intensity: 'medium' },
    chains:              { enabled: false, intensity: 'medium' },
    ai_hypothesis:       { enabled: false, intensity: 'medium' },
    ai_llm:              { enabled: false, intensity: 'medium' },
    adversarial_waf:     { enabled: false, intensity: 'medium' },
    browser_reasoning:   { enabled: false, intensity: 'medium' },
    attack_planner:      { enabled: false, intensity: 'medium' },
    api_abuse:           { enabled: false, intensity: 'medium' },
    graph_risk_analyzer: { enabled: false, intensity: 'medium' },
    ai_validation:       { enabled: false, intensity: 'medium' },
    poc_generator:       { enabled: false, intensity: 'medium' },
    // Phase 4 scan engines
    advanced_scan:       { enabled: false, intensity: 'medium' },
    ai_redteam:          { enabled: false, intensity: 'medium' },
    credential_spray:    { enabled: false, intensity: 'medium' },
  })

  // Session state
  const [session, setSession]               = useState(null)
  const [sessions, setSessions]             = useState([])
  const [logs, setLogs]                     = useState([])
  const [logsLoading, setLogsLoading]       = useState(false)
  const [selectedSessionId, setSelectedSessionId] = useState(null)
  const [stopping, setStopping]             = useState(false)
  const [tab, setTab]                       = useState('status')
  const [councilData, setCouncilData]       = useState(null)
  const [councilLoading, setCouncilLoading] = useState(false)
  const [liveFindingsCount, setLiveFindingsCount] = useState(0)

  const logBottomRef = useRef(null)
  const pollRef      = useRef(null)

  const activePreset = PRESETS.find(p => p.id === preset) || PRESETS.find(p => p.id === 'deep')

  // ── Data refresh ──────────────────────────────────────────────────────────
  const refresh = async (scanId) => {
    try {
      const r = await endpoints.godModeStatus(scanId || selectedSessionId || undefined)
      const data = r.data
      if (data?.status !== 'no_session' && data?.status !== 'error') {
        const prev = session
        setSession(data)
        if (prev && !prev.terminated_by && data?.terminated_by) {
          try {
            const vr = await endpoints.vulnerabilities()
            setVulnerabilities(vr.data || [])
          } catch (_) {}
          refreshSessions()
        }
      }
    } catch (e) {}
  }

  const refreshSessions = async () => {
    try {
      const r = await endpoints.godModeSessions()
      const list = r.data?.sessions || []
      setSessions(list)
      // Auto-select the most recent active (non-terminated) session so the
      // polling refresh uses the fast /status/{scan_id} endpoint.
      if (!selectedSessionId && list.length > 0) {
        const active = list.find(s => !s.terminated_by) || list[0]
        if (active?.scan_id) {
          setSelectedSessionId(active.scan_id)
        }
      }
    } catch (e) { setSessions([]) }
  }

  const refreshLogs = async (scanId) => {
    const id = scanId || selectedSessionId
    if (!id) return
    setLogsLoading(true)
    try {
      const r = await endpoints.godModeLogs(id, 200)
      setLogs(r.data?.lines || [])
    } catch (e) {}
    finally { setLogsLoading(false) }
  }

  useEffect(() => {
    const handleApprovalEvent = (e) => {
      console.log('GOD MODE Approval Request Received:', e.detail)
      setApprovalRequest(e.detail)
    }
    window.addEventListener('AWAITING_APPROVAL', handleApprovalEvent)
    return () => window.removeEventListener('AWAITING_APPROVAL', handleApprovalEvent)
  }, [])

  useEffect(() => {
    // Load sessions first, then auto-select the latest active one so polling
    // uses the fast /status/{scan_id} path instead of the slow find_latest() path.
    const init = async () => {
      await refreshSessions()
      refresh()
    }
    init()
  }, [])

  useEffect(() => {
    clearInterval(pollRef.current)
    if (session && !session.terminated_by) {
      pollRef.current = setInterval(() => refresh(), 5000)
    }
    return () => clearInterval(pollRef.current)
  }, [session?.terminated_by, selectedSessionId])

  useEffect(() => {
    if (showLogs && selectedSessionId) refreshLogs(selectedSessionId)
  }, [showLogs, selectedSessionId])

  useEffect(() => {
    const active = !!(session && !session.terminated_by)
    if (!showLogs || !selectedSessionId || !active) return
    const id = setInterval(() => refreshLogs(selectedSessionId), 8000)
    return () => clearInterval(id)
  }, [showLogs, selectedSessionId, session?.terminated_by])

  useEffect(() => {
    logBottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  // ── Council data fetch — only when ai_council phase appears ───────────────
  const fetchCouncilData = async (scanId) => {
    if (!scanId || councilLoading || councilData) return
    setCouncilLoading(true)
    try {
      const r = await endpoints.councilGet(scanId)
      setCouncilData(r.data)
    } catch (e) {
      // 404 = council not stored yet; silently ignore
    } finally {
      setCouncilLoading(false)
    }
  }

  useEffect(() => {
    const phases = session?.phases_complete || []
    if (phases.includes('ai_council') && session?.scan_id && !councilData) {
      fetchCouncilData(session.scan_id)
    }
  }, [session?.phases_complete?.length, session?.scan_id])


  // ── Live findings count — polls /api/scan/{id}/findings while scan is active ─
  useEffect(() => {
    const id = selectedSessionId
    if (!id || !session || session.terminated_by) {
      setLiveFindingsCount(0)
      return
    }
    let cancelled = false
    const poll = async () => {
      try {
        const r = await endpoints.scanFindings(id)
        if (!cancelled) {
          const items = Array.isArray(r.data) ? r.data : []
          setLiveFindingsCount(items.length)
        }
      } catch (_) {}
    }
    poll()
    const timer = setInterval(poll, 10000)
    return () => { cancelled = true; clearInterval(timer) }
  }, [selectedSessionId, session?.terminated_by])


  useEffect(() => {
    endpoints.authListSessions()
      .then(r => setSavedSessions(r.data || []))
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (!target.trim()) { setLoginFormDetected(null); return }
    const timer = setTimeout(() => {
      endpoints.authDetect({ target: target.trim() })
        .then(r => setLoginFormDetected(r.data?.has_login_form ?? false))
        .catch(() => setLoginFormDetected(false))
    }, 800)
    return () => clearTimeout(timer)
  }, [target])

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

  const handleRecordSession = async () => {
    if (!target.trim()) return
    setIsRecording(true)
    setRecordingWarning('')
    try {
      const r = await endpoints.authRecordStart({ target: target.trim(), name: '' })
      setRecordingId(r.data.session_id)
      addNotification('Browser opened — log in, then click "Done"', 'info')
    } catch (e) {
      addNotification('Could not start recording: ' + (e.response?.data?.detail || e.message), 'error')
      setIsRecording(false)
    }
  }

  const handleRecordDone = async () => {
    if (!recordingId) return
    try {
      const r = await endpoints.authRecordDone(recordingId, { name: target.trim() })
      const warning = r.data.warning || ''
      if (warning) {
        setRecordingWarning(warning)
        addNotification('Session saved with warning — check auth status', 'warning')
      } else {
        setRecordingWarning('')
        addNotification(`Session recorded — ${r.data.cookies_captured} cookies captured`, 'success')
      }
      setAuthSessionId(r.data.session_id)
      const list = await endpoints.authListSessions()
      setSavedSessions(list.data || [])
    } catch (e) {
      addNotification('Recording finalization failed: ' + (e.response?.data?.detail || e.message), 'error')
    } finally {
      setIsRecording(false)
      setRecordingId(null)
    }
  }

  const handleRecordCancel = async () => {
    if (!recordingId) { setIsRecording(false); return }
    try {
      await endpoints.authRecordCancel(recordingId)
    } catch (e) {} finally {
      setIsRecording(false)
      setRecordingId(null)
    }
  }

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
      const enabledModules = isCustom
        ? Object.entries(customModules)
            .filter(([id, c]) => c.enabled)
            .map(([id]) => id)
        : []
      const moduleIntensities = isCustom
        ? Object.fromEntries(
            Object.entries(customModules)
              .filter(([id, c]) => c.enabled)
              .map(([id, c]) => [id, c.intensity])
          )
        : {}

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
        ...(authSessionId ? { auth_session_id: authSessionId } : {}),
        ...(appContext.trim() ? { app_context: appContext.trim() } : {}),
      })
      addNotification(`GOD MODE launched — Foundation starting`, 'success')
      setSession(null)
      setTimeout(() => { refresh(); refreshSessions() }, 1500)
    } catch (e) {
      addNotification('Launch failed: ' + (e.response?.data?.detail || e.message), 'error')
    } finally {
      setLaunching(false)
    }
  }

  const handleStop = async () => {
    setStopping(true)
    try {
      const r = await endpoints.godModeStop(session?.scan_id || null)
      if (r.data?.stopped) {
        addNotification('Stop sentinel written — finalizing within 30s', 'success')
        setTimeout(refresh, 3000)
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

  const handleApproveAction = async (decision) => {
    if (!approvalRequest) return
    try {
      await endpoints.godModeApprove({
        scan_id: approvalRequest.scan_id || session?.scan_id,
        decision,
        action_id: approvalRequest.action_id
      })
      addNotification(`Action ${decision === 'allow' ? 'APPROVED' : 'DENIED'}`, decision === 'allow' ? 'success' : 'warn')
      setApprovalRequest(null)
    } catch (e) {
      addNotification('Approval failed: ' + (e.response?.data?.detail || e.message), 'error')
    }
  }

  const isRunning  = session && !session.terminated_by
  const activeStage = Object.entries(session?.missions || {}).find(([_, s]) => s === 'running')?.[0] || 
                     (session?.terminated_by ? 'complete' : 'foundation')
  
  const completedStages = Object.entries(session?.missions || {})
    .filter(([_, s]) => s === 'done')
    .map(([name]) => {
       if (name === 'full_scan') return 'scan'
       return name
    })

  const logLevelColor = (line) => {
    if (/ERROR|CRITICAL|\[-\]/i.test(line)) return 'text-red-400'
    if (/WARNING|\[!\]/i.test(line)) return 'text-yellow-400'
    if (/\[GOD MODE\]|\[\+\]/i.test(line)) return 'text-accent-primary'
    if (/\[Stage|Mission|converge|unlock/i.test(line)) return 'text-accent-purple'
    return 'text-slate-500'
  }

  return (
    <div className="flex h-[calc(100vh-64px)] -m-6 overflow-hidden bg-bg-primary relative">
      {/* Sidebar Toggle for Mobile */}
      <button 
        onClick={() => setShowSidebar(!showSidebar)}
        className="lg:hidden absolute top-4 left-4 z-[60] p-2 bg-bg-card border border-bg-border rounded-lg text-accent-primary"
      >
        <Menu size={20} />
      </button>

      {/* Aegis Sidebar: LaunchPad */}
      <div className={clsx(
        "absolute lg:relative inset-y-0 left-0 z-50 transition-all duration-300 transform",
        showSidebar ? "translate-x-0 w-80" : "-translate-x-full lg:translate-x-0 lg:w-0 overflow-hidden"
      )}>
        <LaunchPad 
          target={target} setTarget={setTarget}
          preset={preset} setPreset={setPreset}
          reportFmt={reportFmt} setReportFmt={setReportFmt}
          launching={launching} isRunning={isRunning}
          handleLaunch={handleLaunch}
          detectedType={detectedType} userPickedPreset={userPickedPreset} setUserPickedPreset={setUserPickedPreset}
          customModules={customModules} setCustomModules={setCustomModules}
          showAuth={showAuth} setShowAuth={setShowAuth}
          authType={authType} setAuthType={setAuthType}
          authValue={authValue} setAuthValue={setAuthValue}
          savedSessions={savedSessions}
          authSessionId={authSessionId} setAuthSessionId={setAuthSessionId}
          appContext={appContext} setAppContext={setAppContext}
          isRecording={isRecording} handleRecordSession={handleRecordSession} handleRecordDone={handleRecordDone} handleRecordCancel={handleRecordCancel}
          recordingWarning={recordingWarning} loginFormDetected={loginFormDetected}
          sessions={sessions} selectedSessionId={selectedSessionId} setSelectedSessionId={setSelectedSessionId} setSession={setSession} setTab={setTab}
          handleDelete={handleDelete}
        />
        {/* Close button for mobile sidebar overlay */}
        <button 
          onClick={() => setShowSidebar(false)}
          className="lg:hidden absolute top-4 right-4 text-slate-500 hover:text-white"
        >
          <X size={20} />
        </button>
      </div>

      {/* Overlay for mobile sidebar */}
      {showSidebar && (
        <div 
          className="lg:hidden absolute inset-0 bg-black/60 backdrop-blur-sm z-40"
          onClick={() => setShowSidebar(false)}
        />
      )}

      {/* Aegis Main Command Center */}
      <div className="flex-1 flex flex-col min-w-0 relative overflow-hidden">
        
        {/* Top HUD: VitalSignsHUD */}
        <div className={clsx(
          "transition-all duration-700 ease-in-out px-4",
          session ? "opacity-100 translate-y-0 pt-4 pb-2" : "opacity-0 -translate-y-4 h-0 p-0 overflow-hidden"
        )}>
          <VitalSignsHUD 
            findings={session?.finding_count || 0}
            assets={session?.asset_count || 0}
            coverage={session?.coverage_percent || 0}
            confidence={session?.confidence_score || 0}
            avgEma={session?.avg_ema || 0}
            activePersona={savedSessions.find(s => s.session_id === authSessionId)}
          />
        </div>

        {/* Central Body */}
        <div className="flex-1 flex flex-col gap-6 p-4 lg:p-6 pt-2 overflow-y-auto scrollbar-thin scrollbar-thumb-bg-border">
          
          {/* Mission Pipeline Section */}
          <div className={clsx(
            "transition-all duration-700 delay-100",
            session ? "opacity-100 translate-y-0" : "opacity-0 translate-y-4"
          )}>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-4 px-2 gap-4">
              <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-slate-500">Mission Pipeline</h3>
              {isRunning && (
                <div className="flex items-center gap-4 flex-wrap">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-accent-primary animate-ping" />
                    <span className="text-[10px] font-mono text-accent-primary uppercase tracking-widest font-bold">Live Execution</span>
                  </div>
                  <button onClick={handleStop} disabled={stopping} className="btn-danger btn-xs py-1 px-3 text-[10px] whitespace-nowrap">
                    {stopping ? 'Stopping...' : 'Abort Mission'}
                  </button>
                </div>
              )}
            </div>
            <div className="bg-bg-secondary/20 backdrop-blur-sm border border-bg-border rounded-2xl overflow-hidden shadow-inner">
               <MissionPipeline 
                 missions={session?.missions || {}}
                 phases_complete={session?.phases_complete || []}
                 recursionLayer={session?.recursion_layer || 0}
               />
            </div>
          </div>

          {/* Intelligence & Results Grid */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 flex-1 min-h-[500px]">
             
             {/* Insight Feed */}
             <div className={clsx(
               "flex flex-col gap-4 transition-all duration-700 delay-200 order-2 xl:order-1",
               session ? "opacity-100 translate-x-0" : "opacity-0 -translate-x-4"
             )}>
                <InsightFeed insights={session?.insights || []} />
             </div>

             {/* Live Telemetry / Session Info */}
             <div className={clsx(
               "flex flex-col gap-4 transition-all duration-700 delay-300 order-1 xl:order-2",
               session ? "opacity-100 translate-x-0" : "opacity-0 translate-x-4"
             )}>
                <div className="flex items-center justify-between px-2">
                  <div className="flex items-center gap-2 text-accent-purple">
                    <Activity size={18} />
                    <h3 className="text-sm font-bold uppercase tracking-[0.2em]">Live Telemetry</h3>
                  </div>
                  <button 
                    onClick={() => setShowLogs(!showLogs)}
                    className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-slate-500 hover:text-accent-primary transition-colors"
                  >
                    <Terminal size={12} />
                    {showLogs ? 'Hide Logs' : 'Show Logs'}
                  </button>
                </div>

                <div className="flex-1 bg-bg-secondary/20 backdrop-blur-sm border border-bg-border rounded-2xl p-6 flex flex-col gap-6">
                   {!session ? (
                     <div className="flex-1 flex flex-col items-center justify-center text-slate-600 italic">
                        <Radar size={48} className="opacity-10 mb-4 animate-pulse-slow" />
                        <p className="text-sm font-mono tracking-tighter">Awaiting scan initialization...</p>
                     </div>
                   ) : (
                     <>
                       <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                          <div className="p-4 rounded-xl bg-bg-primary/40 border border-bg-border">
                            <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-2 opacity-60">Engine Status</div>
                            <div className="flex items-center gap-3">
                               <div className={clsx(
                                 "w-2 h-2 rounded-full",
                                 isRunning ? "bg-accent-primary shadow-glow-cyan" : "bg-accent-success shadow-glow-green"
                               )} />
                               <span className="text-sm font-bold text-slate-200 uppercase tracking-tight">
                                 {session.terminated_by ? 'Terminated' : 'Operational'}
                               </span>
                            </div>
                          </div>
                          <div className="p-4 rounded-xl bg-bg-primary/40 border border-bg-border">
                            <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-2 opacity-60">Scan Identity</div>
                            <div className="text-xs font-mono text-accent-primary truncate">#{session.scan_id.slice(0, 12)}...</div>
                          </div>
                       </div>

                       {/* Live Finding Count — real-time update from /api/scan/{id}/findings */}
                       {isRunning && (
                         <div className="flex items-center justify-between p-3 rounded-xl bg-accent-primary/5 border border-accent-primary/20">
                           <div className="flex items-center gap-2 text-accent-primary">
                             <Activity size={12} className="animate-pulse" />
                             <span className="text-[10px] font-bold uppercase tracking-widest">Live Findings</span>
                           </div>
                           <div className="flex items-baseline gap-1">
                             <span className="text-xl font-black font-mono text-accent-primary tabular-nums">
                               {liveFindingsCount || session?.finding_count || 0}
                             </span>
                             <span className="text-[9px] text-slate-500 uppercase tracking-wide">found</span>
                           </div>
                         </div>
                       )}


                       <div className="flex-1 overflow-y-auto scrollbar-thin pr-2">
                          <div className="flex flex-col gap-4">
                             <div className="flex flex-col gap-1">
                                <span className="text-[10px] text-slate-500 font-bold uppercase tracking-widest opacity-60">Primary Target</span>
                                <div className="text-sm font-mono text-slate-200 break-all bg-bg-primary/30 p-2 rounded-lg border border-bg-border/50">
                                   {session.target}
                                </div>
                             </div>
                             
                             <div className="flex flex-col gap-2">
                                <span className="text-[10px] text-slate-500 font-bold uppercase tracking-widest opacity-60">Completed Phases</span>
                                <div className="flex flex-wrap gap-2">
                                   {(session.phases_complete || []).length === 0 && <span className="text-2xs text-slate-600 italic">No phases finalized</span>}
                                   {(session.phases_complete || []).map(p => (
                                     <span key={p} className="px-2 py-1 rounded bg-accent-success/10 border border-accent-success/30 text-[9px] font-bold text-accent-success uppercase tracking-wider flex items-center gap-1">
                                       <CheckCircle2 size={10} /> {p.replace(/_/g, ' ')}
                                     </span>
                                   ))}
                                </div>
                             </div>

                             {session.terminated_by && (
                               <div className="mt-4 p-4 rounded-xl bg-accent-success/5 border border-accent-success/20 animate-fade-in">
                                  <div className="flex items-center gap-2 text-accent-success mb-2">
                                     <CheckCircle2 size={16} />
                                     <span className="text-xs font-bold uppercase tracking-widest">Mission Complete</span>
                                  </div>
                                  <p className="text-xs text-slate-400 mb-4">Autonomous execution has converged. Exploit chains and findings are ready for review.</p>
                                  <div className="flex gap-2">
                                     <button onClick={() => navigate(`/chains/${session.scan_id}`)} className="btn-primary flex-1 text-[10px] py-2">Exploit Chains</button>
                                     <button onClick={() => navigate('/results')} className="btn-secondary flex-1 text-[10px] py-2">Findings</button>
                                  </div>
                               </div>
                             )}

                             {/* ── AI Council Results — shown inline when ai_council phase ran ── */}
                             {(session.phases_complete || []).includes('ai_council') && (
                               <div className="mt-4 p-4 rounded-xl bg-accent-purple/5 border border-accent-purple/30 animate-fade-in">
                                 <div className="flex items-center justify-between mb-3">
                                   <div className="flex items-center gap-2 text-accent-purple">
                                     <Shield size={14} />
                                     <span className="text-xs font-bold uppercase tracking-widest">AI Council Results</span>
                                   </div>
                                   {!councilData && !councilLoading && (
                                     <button
                                       onClick={() => fetchCouncilData(session.scan_id)}
                                       className="text-[9px] font-bold text-accent-purple hover:underline uppercase tracking-tighter flex items-center gap-1"
                                     >
                                       <RefreshCw size={9} /> Load
                                     </button>
                                   )}
                                 </div>

                                 {councilLoading && (
                                   <div className="flex items-center gap-2 text-slate-500 text-[10px]">
                                     <RefreshCw size={10} className="animate-spin" /> Fetching council data...
                                   </div>
                                 )}

                                 {councilData && (() => {
                                   const surface = councilData.surface_profile || {}
                                   const plan    = councilData.exploit_plan    || {}
                                   const trace   = councilData.exploit_trace   || {}
                                   const steps   = plan.steps || []
                                   return (
                                     <div className="flex flex-col gap-3">
                                       {/* Surface Profile */}
                                       <div className="grid grid-cols-2 gap-2 text-[10px]">
                                         <div className="p-2 rounded-lg bg-bg-primary/40 border border-bg-border">
                                           <div className="text-slate-600 font-bold uppercase tracking-wider mb-1">Output Type</div>
                                           <div className="text-slate-300 font-mono">{surface.output_type || '—'}</div>
                                         </div>
                                         <div className="p-2 rounded-lg bg-bg-primary/40 border border-bg-border">
                                           <div className="text-slate-600 font-bold uppercase tracking-wider mb-1">Model Hint</div>
                                           <div className="text-slate-300 font-mono truncate">{surface.model_hint || '—'}</div>
                                         </div>
                                         <div className="p-2 rounded-lg bg-bg-primary/40 border border-bg-border">
                                           <div className="text-slate-600 font-bold uppercase tracking-wider mb-1">Blocked KWs</div>
                                           <div className="text-slate-300 font-mono">{(surface.blocked_keywords || []).length}</div>
                                         </div>
                                         <div className="p-2 rounded-lg bg-bg-primary/40 border border-bg-border">
                                           <div className="text-slate-600 font-bold uppercase tracking-wider mb-1">Tools Found</div>
                                           <div className="text-slate-300 font-mono">{(surface.tool_list || []).length}</div>
                                         </div>
                                       </div>

                                       {/* Exploit Plan steps */}
                                       {steps.length > 0 && (
                                         <div>
                                           <div className="text-[9px] text-slate-600 font-bold uppercase tracking-widest mb-2">
                                             Exploit Plan — {steps.length} step{steps.length !== 1 ? 's' : ''}
                                           </div>
                                           <div className="flex flex-col gap-1 max-h-32 overflow-y-auto scrollbar-thin">
                                             {steps.map((s, i) => (
                                               <div key={s.step_id || i} className="flex items-start gap-2 text-[9px] p-1.5 rounded bg-bg-primary/30 border border-bg-border/50">
                                                 <span className="text-accent-purple font-mono font-bold shrink-0">{String(i + 1).padStart(2, '0')}</span>
                                                 <span className="text-slate-400 truncate">{s.action}</span>
                                               </div>
                                             ))}
                                           </div>
                                         </div>
                                       )}

                                       {/* Trace summary */}
                                       <div className="flex items-center gap-3 pt-1">
                                         <span className={clsx(
                                           'px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider border',
                                           trace.overall_success
                                             ? 'bg-accent-success/10 border-accent-success/30 text-accent-success'
                                             : 'bg-red-500/10 border-red-500/30 text-red-400'
                                         )}>
                                           {trace.overall_success ? 'Exploited' : 'No Exploit'}
                                         </span>
                                         <span className="text-[9px] text-slate-500">
                                           {trace.success_count ?? 0}/{trace.total_steps ?? 0} steps succeeded
                                         </span>
                                         {councilData.findings_count > 0 && (
                                           <span className="text-[9px] text-accent-warn font-bold">
                                             {councilData.findings_count} finding{councilData.findings_count !== 1 ? 's' : ''}
                                           </span>
                                         )}
                                       </div>
                                     </div>
                                   )
                                 })()}
                               </div>
                             )}
                          </div>
                       </div>
                     </>
                   )}
                </div>
             </div>
          </div>

          {/* Exploit Chain Graph — appears once a session is selected */}
          {session && (
            <div className={clsx(
              "transition-all duration-700 delay-200",
              session ? "opacity-100 translate-y-0" : "opacity-0 translate-y-4"
            )}>
              <div className="bg-bg-secondary/20 backdrop-blur-sm border border-bg-border rounded-2xl p-4">
                <VulnChainGraph scanId={selectedSessionId} height={320} />
              </div>
            </div>
          )}

        </div>

        {/* Live Logs Slide-out Overlay */}
        <div className={clsx(
          "absolute inset-y-0 right-0 w-[450px] bg-bg-card/95 backdrop-blur-2xl border-l border-bg-border shadow-2xl transition-all duration-500 ease-in-out z-50 transform",
          showLogs ? "translate-x-0" : "translate-x-full"
        )}>
           <div className="flex flex-col h-full">
              <div className="p-4 border-b border-bg-border flex items-center justify-between bg-bg-secondary/50">
                 <div className="flex items-center gap-3 text-accent-primary">
                    <Terminal size={18} />
                    <h3 className="text-xs font-bold uppercase tracking-[0.2em]">Core Execution Logs</h3>
                 </div>
                 <button 
                   onClick={() => setShowLogs(false)}
                   className="p-1 hover:bg-bg-elevated rounded-lg transition-colors text-slate-500 hover:text-white"
                 >
                   <X size={20} />
                 </button>
              </div>
              
              <div className="flex-1 overflow-y-auto p-6 font-mono text-[11px] leading-relaxed scrollbar-thin scrollbar-thumb-bg-border bg-black/40">
                 {logsLoading && logs.length === 0 ? (
                   <div className="flex items-center gap-3 text-slate-600">
                      <RefreshCw size={14} className="animate-spin" />
                      Initializing telemetry stream...
                   </div>
                 ) : logs.length === 0 ? (
                   <div className="text-slate-600 italic">// Awaiting log synchronization...</div>
                 ) : (
                   <div className="flex flex-col gap-1">
                      {logs.map((line, i) => (
                        <div key={i} className={clsx("whitespace-pre-wrap transition-colors duration-300 rounded px-1 -mx-1 hover:bg-white/5", logLevelColor(line))}>
                          {line}
                        </div>
                      ))}
                      <div ref={logBottomRef} />
                   </div>
                 )}
              </div>

              <div className="p-4 border-t border-bg-border bg-bg-secondary/50 flex items-center justify-between">
                 <div className="text-[10px] font-mono text-slate-600 uppercase tracking-widest">
                   Stream: Active · PID: Auto
                 </div>
                 <button onClick={() => refreshLogs()} className="text-[10px] font-bold text-accent-primary hover:underline uppercase tracking-tighter">
                    Force Reload
                 </button>
              </div>
           </div>
        </div>
        
        {/* Toggle Button for Logs (Visible when logs are hidden) */}
        {!showLogs && session && (
          <button 
            onClick={() => setShowLogs(true)}
            className="absolute bottom-6 right-6 w-12 h-12 rounded-full bg-bg-card border border-bg-border shadow-glow-cyan/10 flex items-center justify-center text-accent-primary hover:scale-110 active:scale-95 transition-all z-40 group"
          >
            <Terminal size={20} className="group-hover:animate-pulse" />
            <div className="absolute -top-1 -right-1 w-3 h-3 bg-accent-primary rounded-full animate-ping opacity-75" />
          </button>
        )}

        {/* Safety Gate: Approval Modal */}
        {approvalRequest && (
          <div className="absolute inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-md p-6">
            <div className="w-full max-w-lg bg-bg-card border-2 border-accent-warn shadow-[0_0_50px_rgba(234,179,8,0.2)] rounded-3xl overflow-hidden animate-in zoom-in duration-300">
              <div className="bg-accent-warn/10 p-6 border-b border-accent-warn/20 flex items-center gap-4">
                <div className="w-12 h-12 rounded-2xl bg-accent-warn/20 flex items-center justify-center text-accent-warn animate-pulse">
                  <ShieldAlert size={28} />
                </div>
                <div>
                  <h2 className="text-lg font-black uppercase tracking-widest text-accent-warn">Safety Gate Active</h2>
                  <p className="text-[10px] text-accent-warn/60 font-bold uppercase tracking-tighter">Human intervention required for high-risk action</p>
                </div>
              </div>
              
              <div className="p-8 flex flex-col gap-6">
                <div className="space-y-2">
                  <span className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">Proposed Action</span>
                  <div className="p-4 rounded-2xl bg-bg-primary/50 border border-bg-border font-mono text-sm text-slate-200 leading-relaxed italic">
                    "{approvalRequest.thought || approvalRequest.action_desc}"
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
                  <div className="space-y-1">
                    <span className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">Type</span>
                    <div className="text-xs font-bold text-slate-300 uppercase">{approvalRequest.action || 'destructive'}</div>
                  </div>
                  <div className="space-y-1">
                    <span className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">Target</span>
                    <div className="text-xs font-mono text-accent-primary truncate">{approvalRequest.target}</div>
                  </div>
                </div>

                <div className="flex gap-4 pt-4">
                  <button 
                    onClick={() => handleApproveAction('allow')}
                    className="flex-1 py-4 rounded-2xl bg-accent-success text-black font-black uppercase tracking-widest text-xs shadow-glow-green/20 hover:scale-[1.02] active:scale-95 transition-all"
                  >
                    Allow Action
                  </button>
                  <button 
                    onClick={() => handleApproveAction('deny')}
                    className="flex-1 py-4 rounded-2xl bg-bg-elevated border border-bg-border text-slate-300 font-black uppercase tracking-widest text-xs hover:bg-red-500/10 hover:border-red-500/50 hover:text-red-500 transition-all"
                  >
                    Deny Action
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
