import React from 'react'
import {
  Flame, Radar, ShieldAlert, Zap, Lock, GitMerge, Brain, Bot,
  Clock, Trash2, ChevronDown, ChevronRight, Shield, CheckCircle2,
  RefreshCw, Activity, Search, FileText
} from 'lucide-react'
import clsx from 'clsx'
import { formatDateTime } from '../../utils/time'
import { endpoints } from '../../utils/api'
import { useStore } from '../../store/useStore'

const ALL_MODULES = [
  { id: 'recon',              label: 'Recon',            icon: Radar,      desc: 'Subdomain enum, port scan, crawling, fingerprinting',              always: true },
  { id: 'vuln_scan',          label: 'Vuln Scan',        icon: ShieldAlert, desc: 'Nuclei, dalfox, sqlmap, CRLFUZZ, KXSS',                           always: true },
  { id: 'active_testing',     label: 'Active Testing',   icon: Zap,        desc: 'Swarm agents: XSS, SQLi, SSRF, IDOR, CORS, JWT, Auth, IDOR',       key: 'swarm' },
  { id: 'auth',               label: 'Auth & Sessions',  icon: Lock,       desc: 'Default creds, session reuse, CSRF, cookie checks',                always: true },
  { id: 'business_logic',     label: 'Business Logic',   icon: GitMerge,   desc: 'Race conditions, price manipulation, workflow skips',               always: true },
  { id: 'chains',             label: 'Exploit Chains',   icon: GitMerge,   desc: 'Cross-finding chains: SSRF→RCE, XSS→ATO, SQLi→bypass',             always: true },
  { id: 'ai_hypothesis',      label: 'AI Hypothesis',    icon: Brain,      desc: 'AI-driven iterative hypothesis testing on uncovered classes',       key: 'research' },
  { id: 'ai_llm',             label: 'AI/LLM Testing',   icon: Bot,        desc: 'Prompt injection, jailbreaks, model attacks (AI product targets)',  key: 'ai_llm', comingSoon: true },
  { id: 'autonomous_navigator', label: 'Shadow User',    icon: Bot,        desc: 'Autonomous DAST via AI navigation' },
  // New AI missions
  { id: 'adversarial_waf',    label: 'Adversarial WAF',  icon: Shield,     desc: 'Self-play WAF bypass engine — generates evasion payloads pre-scan' },
  { id: 'browser_reasoning',  label: 'Browser AI',       icon: Brain,      desc: 'SPA endpoint discovery via AI browser reasoning agent' },
  { id: 'attack_planner',     label: 'Attack Planner',   icon: Brain,      desc: 'Tree-of-Thoughts AI attack chain planning with LLM validation' },
  { id: 'api_abuse',          label: 'API Abuse',        icon: Zap,        desc: 'Mass assignment, rate limit bypass, BOLA/BFLA, parameter pollution' },
  { id: 'graph_risk_analyzer', label: 'Graph Risk',       icon: GitMerge,   desc: 'Neo4j attack graph risk scoring and cross-scan pattern analysis' },
  { id: 'ai_validation',      label: 'AI Validation',    icon: CheckCircle2, desc: 'LLM false-positive elimination with semantic diff tiebreaker' },
  { id: 'poc_generator',      label: 'PoC Generator',    icon: FileText,   desc: 'Auto-generate proof-of-concept scripts for confirmed findings' },
]

const PRESETS = [
  {
    id: 'quick',
    label: 'Quick',
    desc: 'Fast sweep, high/critical only',
    color: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
    activeColor: 'border-blue-400 bg-blue-500/20 text-blue-200',
    no_swarm: true,
    no_research: true,
    modules: ['recon', 'port_scan', 'vuln_scan', 'auth', 'business_logic', 'chains'],
  },
  {
    id: 'standard',
    label: 'Standard',
    desc: 'Full pipeline + port scan + param discovery + credential intel + auth tests + swarm + AI research',
    color: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300',
    activeColor: 'border-cyan-400 bg-cyan-500/20 text-cyan-200',
    no_swarm: false,
    no_research: false,
    modules: ['recon', 'port_scan', 'param_discovery', 'credential_spray', 'vuln_scan', 'active_testing', 'auth', 'authenticated_tests', 'business_logic', 'chains', 'ai_hypothesis'],
  },
  {
    id: 'deep',
    label: 'Deep',
    desc: 'Everything — port scan + param discovery + credential spray + authenticated testing + swarm + AI research',
    color: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
    activeColor: 'border-orange-400 bg-orange-500/20 text-orange-200',
    no_swarm: false,
    no_research: false,
    modules: ['recon', 'port_scan', 'param_discovery', 'credential_spray', 'vuln_scan', 'active_testing', 'auth', 'authenticated_tests', 'business_logic', 'chains', 'ai_hypothesis'],
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

const INTENSITY_COLORS = {
  low:        'border-blue-500/40 text-blue-300',
  medium:     'border-cyan-500/40 text-cyan-300',
  high:       'border-orange-500/40 text-orange-300',
  aggressive: 'border-red-500/40 text-red-300',
}

const TERM_REASONS = {
  convergence: { label: 'Converged',   color: 'text-emerald-400' },
  time:        { label: 'Time Cap',    color: 'text-yellow-400'  },
  cap:         { label: 'Finding Cap', color: 'text-orange-400'  },
  stop:        { label: 'Stopped',     color: 'text-slate-400'   },
  error:       { label: 'Error',       color: 'text-red-400'     },
  all_done:    { label: 'All Done',    color: 'text-emerald-400' },
}

export default function LaunchPad({
  target, setTarget,
  preset, setPreset,
  reportFmt, setReportFmt,
  launching, isRunning,
  handleLaunch,
  detectedType, userPickedPreset, setUserPickedPreset,
  customModules, setCustomModules,
  showAuth, setShowAuth,
  authType, setAuthType,
  authValue, setAuthValue,
  savedSessions,
  authSessionId, setAuthSessionId,
  isRecording, handleRecordSession, handleRecordDone, handleRecordCancel,
  recordingWarning, loginFormDetected,
  sessions, selectedSessionId, setSelectedSessionId, setSession, setTab,
  handleDelete,
  appContext, setAppContext,
}) {
  const { addNotification } = useStore()
  const activePreset = PRESETS.find(p => p.id === preset) || PRESETS.find(p => p.id === 'deep')

  const customEnabledModules = Object.values(customModules).filter(c => c.enabled)
  const customIntensitySet   = [...new Set(customEnabledModules.map(c => c.intensity))]
  const customSummary = customEnabledModules.length === 0
    ? 'no modules selected'
    : `${customEnabledModules.length} module${customEnabledModules.length > 1 ? 's' : ''} · ${customIntensitySet.length > 1 ? 'Mixed intensity' : (customIntensitySet[0] ?? 'medium')}`

  return (
    <div className="flex flex-col h-full bg-bg-secondary/30 backdrop-blur-xl border-r border-bg-border w-full overflow-y-auto scrollbar-thin scrollbar-thumb-bg-border">
      {/* Launch Control */}
      <div className="p-4 flex flex-col gap-6">
        <div className="flex items-center gap-2">
          <Flame size={18} className="text-red-500 animate-pulse" />
          <h2 className="text-xs font-bold uppercase tracking-[0.2em] text-slate-200">Mission Control</h2>
        </div>

        {/* Target Input */}
        <div className="flex flex-col gap-2">
          <label className="text-[10px] uppercase tracking-widest font-bold text-slate-500 px-1">Target Endpoint</label>
          <div className="relative group">
            <input
              className={clsx(
                'w-full bg-bg-primary/50 border border-bg-border rounded-lg px-3 py-2 text-sm font-mono transition-all focus:border-accent-primary focus:ring-1 focus:ring-accent-primary/20 outline-none',
                detectedType && !userPickedPreset && 'border-accent-primary/40 shadow-glow-cyan/5'
              )}
              placeholder="https://target.com"
              value={target}
              onChange={e => { setTarget(e.target.value); setUserPickedPreset(false) }}
              onKeyDown={e => e.key === 'Enter' && !isRunning && !launching && target.trim() && handleLaunch()}
            />
            {detectedType && !userPickedPreset && target.trim() && (
              <div className="absolute -bottom-5 right-0 flex items-center gap-1 text-[9px] text-accent-primary font-bold uppercase tracking-tighter">
                <span className="w-1.5 h-1.5 rounded-full bg-accent-primary animate-pulse" />
                {detectedType} detected
              </div>
            )}
          </div>
        </div>

        {/* Scope Presets */}
        <div className="flex flex-col gap-3 pt-2">
          <label className="text-[10px] uppercase tracking-widest font-bold text-slate-500 px-1">Scope Preset</label>
          <div className="grid grid-cols-2 gap-2">
            {PRESETS.map(p => (
              <button
                key={p.id}
                onClick={() => { setPreset(p.id); setUserPickedPreset(true) }}
                className={clsx(
                  'flex flex-col items-start gap-1 p-2 rounded-lg border text-left transition-all group',
                  p.id === 'custom' && 'col-span-2',
                  preset === p.id 
                    ? 'border-accent-primary bg-accent-primary/10 shadow-glow-cyan/5' 
                    : 'border-bg-border bg-bg-primary/30 hover:border-slate-500 opacity-60 hover:opacity-100'
                )}
              >
                <div className="flex items-center justify-between w-full">
                  <span className={clsx(
                    "text-[10px] font-bold uppercase tracking-wider",
                    preset === p.id ? "text-accent-primary" : "text-slate-300"
                  )}>{p.label}</span>
                  {p.id === 'custom' && preset === 'custom' && (
                    <Zap size={10} className="text-accent-purple" />
                  )}
                </div>
                <span className="text-[9px] text-slate-500 leading-tight group-hover:text-slate-400 transition-colors">{p.desc}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Modules List */}
        <div className="flex flex-col gap-2">
           <label className="text-[10px] uppercase tracking-widest font-bold text-slate-500 px-1">Modules</label>
           
           {preset !== 'custom' ? (
             <div className="grid grid-cols-2 gap-1.5">
               {ALL_MODULES.map(m => {
                 const included = activePreset.modules.includes(m.id)
                 if (!included) return null
                 return (
                   <div key={m.id} className="flex items-center gap-1.5 px-2 py-1 rounded bg-bg-primary/40 border border-bg-border/50 text-[9px] font-mono text-slate-400">
                     <m.icon size={10} className="text-accent-primary opacity-60" />
                     {m.label}
                   </div>
                 )
               })}
             </div>
           ) : (
             <div className="flex flex-col gap-1.5 max-h-48 overflow-y-auto pr-1 scrollbar-thin">
                {ALL_MODULES.filter(m => !m.comingSoon).map(m => {
                  const cfg = customModules[m.id]
                  const enabled = cfg?.enabled ?? false
                  const intensity = cfg?.intensity ?? 'medium'
                  return (
                    <div key={m.id} className={clsx(
                      "flex items-center gap-2 p-1.5 rounded border transition-all",
                      enabled ? "border-accent-primary/30 bg-accent-primary/5" : "border-bg-border bg-bg-primary/20 opacity-40"
                    )}>
                       <button
                         onClick={() => setCustomModules(prev => ({
                           ...prev,
                           [m.id]: { ...prev[m.id], enabled: !enabled }
                         }))}
                         className={clsx(
                           'w-3 h-3 rounded flex-shrink-0 flex items-center justify-center border transition-all',
                           enabled ? 'bg-accent-primary border-accent-primary text-black' : 'border-slate-600 bg-transparent'
                         )}
                       >
                         {enabled && <span className="text-[8px] font-black leading-none">✓</span>}
                       </button>
                       <div className="flex-1 min-w-0">
                         <div className="text-[10px] font-bold text-slate-300 truncate">{m.label}</div>
                       </div>
                       <select
                         disabled={!enabled}
                         value={intensity}
                         onChange={e => setCustomModules(prev => ({
                           ...prev,
                           [m.id]: { ...prev[m.id], intensity: e.target.value }
                         }))}
                         className="text-[8px] bg-bg-primary border border-bg-border rounded px-1 py-0.5 outline-none focus:border-accent-primary transition-colors"
                       >
                         <option value="low">Low</option>
                         <option value="medium">Med</option>
                         <option value="high">High</option>
                         <option value="aggressive">Agg</option>
                       </select>
                    </div>
                  )
                })}
             </div>
           )}
        </div>

        {/* Auth Settings */}
        <div className="flex flex-col gap-2">
           <button 
             onClick={() => setShowAuth(!showAuth)}
             className="flex items-center justify-between px-1 hover:text-accent-primary transition-colors"
           >
             <label className="text-[10px] uppercase tracking-widest font-bold text-slate-500 cursor-pointer">Infiltration Auth</label>
             {showAuth ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
           </button>
           
           {showAuth && (
             <div className="flex flex-col gap-3 p-3 rounded-xl bg-bg-primary/40 border border-bg-border shadow-inner">
                <select 
                  className="w-full bg-bg-primary border border-bg-border rounded-lg px-2 py-1.5 text-[10px] font-bold text-slate-300 outline-none focus:border-accent-primary transition-all"
                  value={authType} 
                  onChange={e => { setAuthType(e.target.value); setAuthValue('') }}
                >
                  <option value="none">UNAUTHENTICATED</option>
                  <option value="record">⏺ RECORD SESSION</option>
                  <option value="cookie">SESSION COOKIE</option>
                  <option value="bearer">BEARER TOKEN</option>
                </select>

                {authType === 'record' ? (
                  <div className="flex flex-col gap-2">
                    {!isRecording ? (
                      <button 
                        className="btn-secondary text-[10px] py-2 flex items-center justify-center gap-2"
                        onClick={handleRecordSession}
                        disabled={!target.trim()}
                      >
                         <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                         Start Recording
                      </button>
                    ) : (
                      <div className="flex flex-col gap-2">
                        <button className="btn-primary text-[10px] py-2" onClick={handleRecordDone}>Confirm Login</button>
                        <button className="btn-ghost text-[10px] py-1 text-slate-500" onClick={handleRecordCancel}>Cancel</button>
                      </div>
                    )}
                  </div>
                ) : authType !== 'none' && (
                  <input
                    className="w-full bg-bg-primary border border-bg-border rounded-lg px-2 py-1.5 text-[10px] font-mono text-accent-primary outline-none focus:border-accent-primary transition-all"
                    placeholder="Enter credentials..."
                    value={authValue}
                    onChange={e => setAuthValue(e.target.value)}
                  />
                )}

                {savedSessions.length > 0 && (
                   <div className="flex flex-col gap-2 border-t border-bg-border/50 pt-3 mt-1">
                      <div className="flex items-center justify-between px-1">
                        <span className="text-[9px] text-slate-500 font-bold uppercase tracking-tight text-glow-cyan/20">Active Personas</span>
                        <button className="text-[8px] text-slate-600 hover:text-slate-400 font-bold uppercase" onClick={() => setShowAuth(false)}>Close</button>
                      </div>
                      
                      <div className="grid grid-cols-1 gap-2 max-h-48 overflow-y-auto pr-1 scrollbar-thin">
                        {savedSessions.map(s => {
                          const isActive = authSessionId === s.session_id
                          return (
                            <div 
                              key={s.session_id} 
                              onClick={() => setAuthSessionId(isActive ? '' : s.session_id)}
                              className={clsx(
                                "group relative p-2 rounded-xl border transition-all cursor-pointer",
                                isActive 
                                  ? "border-accent-primary/50 bg-accent-primary/10 shadow-glow-cyan/5" 
                                  : "border-bg-border bg-bg-primary/20 hover:border-slate-700 opacity-70 hover:opacity-100"
                              )}
                            >
                               <div className="flex items-center gap-2 mb-1">
                                  <div className={clsx(
                                    "p-1 rounded bg-bg-elevated border",
                                    isActive ? "border-accent-primary/30 text-accent-primary" : "border-bg-border text-slate-600"
                                  )}>
                                     <Shield size={10} />
                                  </div>
                                  <div className="flex-1 min-w-0">
                                     <div className="text-[10px] font-bold text-slate-200 truncate">{s.name || s.session_id.slice(0, 8)}</div>
                                     <div className="text-[8px] text-slate-500 font-mono truncate">{s.target}</div>
                                  </div>
                                  {isActive && (
                                     <CheckCircle2 size={10} className="text-accent-primary animate-pulse" />
                                  )}
                               </div>
                               
                               <div className="flex items-center justify-between mt-1 pt-1 border-t border-white/5 opacity-0 group-hover:opacity-100 transition-opacity">
                                  <span className="text-[8px] text-slate-600 font-mono">{formatDateTime(s.recorded_at)}</span>
                                  <button 
                                    onClick={async (e) => {
                                      e.stopPropagation();
                                      try {
                                        const r = await endpoints.authSessionVerify(s.session_id);
                                        if (r.data?.valid) {
                                          addNotification(`Session VALID (HTTP ${r.data.status_code})\nEndpoint: ${r.data.url}`, 'success');
                                        } else {
                                          addNotification(`Session INVALID (HTTP ${r.data?.status_code || 'Error'})\nReason: ${r.data?.error || 'Possible redirect to login'}`, 'error');
                                        }
                                      } catch (err) {
                                        addNotification(`Error: ${err.message}`, 'error');
                                      }
                                    }}
                                    className="text-[8px] font-bold text-cyan-500 hover:text-cyan-400 uppercase tracking-tighter"
                                  >
                                    Verify
                                  </button>
                               </div>
                            </div>
                          )
                        })}
                      </div>
                      
                      <div className="flex items-center gap-2 px-1 mt-1">
                         <input type="checkbox" id="auto-inf" className="w-2.5 h-2.5 accent-accent-primary rounded" />
                         <label htmlFor="auto-inf" className="text-[9px] text-slate-400 font-bold uppercase cursor-pointer select-none">Auto-Infiltrate Defaults</label>
                      </div>
                   </div>
                )}
             </div>
           )}
        </div>

        {/* Business Rules (optional) */}
        <div className="mt-3">
          <label className="text-[9px] font-bold uppercase tracking-widest text-slate-500 mb-1 block">
            Business Rules <span className="text-slate-600 normal-case font-normal">(optional)</span>
          </label>
          <textarea
            value={appContext}
            onChange={e => setAppContext(e.target.value)}
            rows={3}
            placeholder={"Describe app workflows, e.g.:\n\"user creates agent → needs admin approval → becomes visible\""}
            className="w-full bg-bg-primary/60 border border-bg-border rounded-lg px-3 py-2 text-[10px] text-slate-300 placeholder-slate-600 font-mono resize-none focus:outline-none focus:border-accent-primary/50 scrollbar-thin scrollbar-thumb-bg-border"
          />
        </div>

        {/* Launch Button */}
        <button
          className={clsx(
            'w-full py-3 rounded-xl font-black uppercase tracking-[0.15em] text-xs transition-all flex items-center justify-center gap-2',
            target.trim() && !launching && !isRunning
              ? 'bg-accent-primary text-black shadow-glow-cyan/20 hover:scale-[1.02] active:scale-95'
              : 'bg-bg-elevated border border-bg-border text-slate-600 cursor-not-allowed'
          )}
          onClick={handleLaunch}
          disabled={!target.trim() || launching || isRunning}
        >
          {isRunning ? (
            <><Activity size={14} className="animate-pulse" /> System Active</>
          ) : launching ? (
            <><RefreshCw size={14} className="animate-spin" /> Initializing...</>
          ) : (
            <><Flame size={14} /> Ignite God Mode</>
          )}
        </button>
      </div>

      {/* Mission Archives */}
      <div className="mt-auto border-t border-bg-border">
        <div className="p-4 border-b border-bg-border bg-bg-primary/20">
          <div className="flex items-center gap-2">
            <Clock size={14} className="text-slate-500" />
            <h3 className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Mission Archives</h3>
          </div>
        </div>
        <div className="max-h-64 overflow-y-auto scrollbar-thin scrollbar-thumb-bg-border">
          {sessions.length === 0 ? (
            <div className="p-8 text-center opacity-30">
               <div className="text-[10px] font-mono italic">No archive data</div>
            </div>
          ) : (
            sessions.map((s) => (
              <div
                key={s.scan_id}
                onClick={() => { setSelectedSessionId(s.scan_id); setSession(s); setTab('status') }}
                className={clsx(
                  'group flex flex-col gap-1 p-3 border-b border-bg-border/50 cursor-pointer transition-all hover:bg-bg-primary/40',
                  selectedSessionId === s.scan_id && 'bg-accent-primary/5 border-l-2 border-l-accent-primary'
                )}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-slate-300 truncate w-32">{s.target}</span>
                  <div className={clsx(
                    'text-[8px] font-black uppercase px-1.5 py-0.5 rounded-sm bg-bg-primary border border-bg-border',
                    TERM_REASONS[s.terminated_by]?.color || 'text-accent-primary'
                  )}>
                    {s.terminated_by ? TERM_REASONS[s.terminated_by]?.label : 'Active'}
                  </div>
                </div>
                <div className="flex items-center justify-between text-[9px] text-slate-500 font-mono">
                  <span>{formatDateTime(s.started_at)}</span>
                  <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                    <span className="text-accent-warn">{s.finding_count || 0}F</span>
                    <button 
                      onClick={e => handleDelete(s.scan_id, e)}
                      className="hover:text-red-500 transition-colors"
                    >
                      <Trash2 size={10} />
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
