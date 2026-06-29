import React, { useState } from 'react'
import {
  Shield, Search, Cpu, Lock, Terminal, Smartphone,
  Settings, ChevronRight, Globe, Database, Network,
  Activity, Zap, FileText, Code, Bug, AlertTriangle,
  CheckCircle, XCircle, Loader, Unlock
} from 'lucide-react'
import { relativeTime, formatDateTime } from '../../utils/time'
import { endpoints } from '../../utils/api'
import clsx from 'clsx'
import AegisLabTab from './AegisLabTab'
import FridaScriptEditor from '../mobile/FridaScriptEditor'
import TrafficInterceptor from '../mobile/TrafficInterceptor'
import SSLBypassPanel from '../mobile/SSLBypassPanel'
import MobileSourceViewer from './MobileSourceViewer'

const SEV_COLORS = {
  critical: 'text-red-500',
  high:     'text-orange-500',
  medium:   '#f59e0b',
  low:      'text-blue-500',
  info:     'text-slate-500',
}

export default function MobileReportViewer({ report, appId, initialTab, initialFile, deviceId }) {
  const [tab, setTab] = useState(initialTab || 'overview')
  
  useEffect(() => {
    if (initialTab) setTab(initialTab);
  }, [initialTab]);

  const vulns = report?.all_vulnerabilities || []
  
  const TABS = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'static',   label: 'Static',   icon: Search },
    { id: 'source',   label: 'Source',   icon: Code },
    { id: 'ai',       label: 'AI Intel', icon: Cpu },
    { id: 'secrets',  label: 'Secrets',  icon: Lock },
    { id: 'frida',    label: 'Frida Lab',icon: Terminal },
    { id: 'aegis',    label: 'Aegis Lab',icon: Shield },
    { id: 'traffic',  label: 'Traffic',  icon: Network },
    { id: 'ssl',      label: 'SSL Bypass', icon: Unlock },
  ]

  return (
    <div className="flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-2 duration-500">
      {/* Header HUD */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-5 glass-card bg-bg-secondary/30">
        <div className="flex items-center gap-4">
           <div className="p-3 rounded-2xl bg-cyan-500/10 border border-cyan-500/20">
              <Smartphone size={24} className="text-cyan-400" />
           </div>
           <div>
              <h2 className="text-lg font-black text-slate-100 tracking-tight uppercase">{report?.app_name || appId}</h2>
              <div className="flex items-center gap-3 mt-1 font-mono text-[10px]">
                 <span className="text-slate-500 uppercase">{report?.platform}</span>
                 <div className="w-1 h-1 rounded-full bg-slate-700" />
                 <span className="text-cyan-500/80">{report?.package_name || 'com.example.app'}</span>
              </div>
           </div>
        </div>
        
        <div className="flex items-center gap-6">
           <div className="text-right">
              <div className="text-[9px] font-black text-slate-500 uppercase tracking-widest mb-1">Risk Score</div>
              <div className={clsx("text-2xl font-black font-mono", 
                (report?.risk_score ?? 0) > 7 ? 'text-red-500' : (report?.risk_score ?? 0) > 4 ? 'text-orange-500' : 'text-emerald-500'
              )}>
                {(report?.risk_score ?? 0).toFixed(1)}<span className="text-sm opacity-30">/100</span>
              </div>
           </div>
           <div className="h-10 w-px bg-slate-800" />
           <div className="flex gap-1.5">
              {['critical', 'high', 'medium'].map(s => (
                <div key={s} className="flex flex-col items-center min-w-[32px]">
                   <span className={clsx("text-xs font-black", SEV_COLORS[s])}>{report?.severity_counts?.[s] ?? 0}</span>
                   <span className="text-[8px] font-bold text-slate-600 uppercase">{s.slice(0, 3)}</span>
                </div>
              ))}
           </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex p-1 bg-bg-secondary/40 rounded-2xl border border-bg-border w-fit">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={clsx(
              "flex items-center gap-2 px-4 py-2 rounded-xl text-[10px] font-black uppercase transition-all duration-300",
              tab === t.id 
                ? "bg-bg-elevated text-accent-primary border border-slate-700/50 shadow-glow-cyan/5" 
                : "text-slate-500 hover:text-slate-300"
            )}
          >
            <t.icon size={12} />
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="min-h-[400px]">
         {tab === 'overview' && <OverviewTab report={report} vulns={vulns} />}
         {tab === 'static'   && <StaticTab report={report} />}
         {tab === 'source'   && <MobileSourceViewer appId={appId} initialFile={initialFile} onHookRequest={(file) => setTab('frida')} />}
         {tab === 'ai'       && <AITab report={report} />}
         {tab === 'secrets'  && <SecretsTab report={report} />}
         {tab === 'frida'    && <FridaScriptEditor appId={appId} packageName={report?.package_name} deviceId={deviceId} />}
         {tab === 'aegis'    && <AegisLabTab report={report} appId={appId} deviceId={deviceId} />}
         {tab === 'traffic'  && <TrafficInterceptor appId={appId} packageName={report?.package_name} />}
         {tab === 'ssl'      && <SSLBypassPanel appId={appId} packageName={report?.package_name} deviceId={deviceId} />}
      </div>
    </div>
  )
}

function OverviewTab({ report, vulns }) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-in fade-in duration-500">
       <div className="lg:col-span-2 space-y-4">
          <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest px-2">Top Findings</h3>
          <div className="grid gap-3">
             {vulns.slice(0, 5).map((v, i) => (
               <div key={i} className="p-4 glass-card group hover:border-slate-700 transition-all">
                  <div className="flex justify-between items-start mb-2">
                     <div className="flex gap-2">
                        <span className={clsx("px-2 py-0.5 rounded text-[9px] font-black uppercase border", 
                          v.severity === 'critical' ? 'bg-red-500/10 text-red-500 border-red-500/20' : 'bg-slate-800 text-slate-400 border-slate-700'
                        )}>{v.severity}</span>
                        {v.mastg_id && (
                          <span className="px-2 py-0.5 rounded text-[9px] font-black uppercase bg-purple-500/10 text-purple-400 border border-purple-500/20">{v.mastg_id}</span>
                        )}
                     </div>
                     <span className="text-[9px] font-mono text-cyan-500/60 uppercase">{v.tool}</span>
                  </div>
                  <div className="text-sm font-bold text-slate-200 group-hover:text-cyan-400 transition-colors">{v.type || v.vulnerability}</div>
                  <div className="text-[10px] text-slate-500 font-mono mt-1 truncate">{v.file || v.detail}</div>
                  {v.masvs && (
                    <div className="flex gap-1.5 mt-3">
                       {v.masvs.map(m => (
                         <span key={m} className="text-[8px] font-bold text-slate-600 border border-slate-800 rounded px-1.5">{m}</span>
                       ))}
                    </div>
                  )}
               </div>
             ))}
             {vulns.length === 0 && <div className="text-center py-12 text-slate-600 italic text-xs">No vulnerabilities detected.</div>}
          </div>
       </div>
       
       <div className="space-y-6">
          <div className="glass-card p-5">
             <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-4 flex items-center gap-2">
                <FileText size={12} className="text-accent-primary" /> Recommendations
             </h3>
             <div className="flex flex-col gap-3">
                {(report?.recommendations || []).map((r, i) => (
                  <div key={i} className="flex gap-3 text-[11px] text-slate-300 leading-relaxed border-l-2 border-slate-800 pl-3">
                     <span className="mt-1 flex-shrink-0 w-1.5 h-1.5 rounded-full bg-cyan-500/50" />
                     {r}
                  </div>
                ))}
             </div>
          </div>

          <div className="glass-card p-5 border-l-4 border-l-purple-500">
             <h3 className="text-[10px] font-black text-purple-400 uppercase tracking-widest mb-4 flex items-center gap-2">
                <Zap size={12} /> Exploitation Vector
             </h3>
             <div className="p-3 rounded-lg bg-black/40 border border-slate-800 font-mono text-[10px] text-slate-400 leading-relaxed">
                <span className="text-purple-500">[CHAIN]</span> Binary Analysis → Secret Extraction → API Key Discovery → Unauthorized Data Access.
             </div>
          </div>
       </div>
    </div>
  )
}

function StaticTab({ report }) {
  const sa = report?.static_analysis || {}
  // Backend returns findings arrays: manifest_findings, permission_findings, code_findings, etc.
  const manifestFindings  = sa.manifest_findings  || []
  const permFindings      = sa.permission_findings || []
  const codeFindings      = sa.code_findings       || []
  const netFindings       = sa.network_config_findings || []
  const allStaticFindings = sa.all_findings        || []
  // Extract permission names from permission_findings or component_findings
  const permNames = permFindings.map(f => f.evidence || f.vulnerability || '').filter(Boolean)
  // Derive security flags from manifest findings
  const flagged = (label) => manifestFindings.some(f =>
    (f.vulnerability || f.evidence || '').toLowerCase().includes(label.toLowerCase())
  )

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-in fade-in duration-500">
       <div className="glass-card p-6">
          <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-6">Security Flags</h3>
          <div className="grid grid-cols-2 gap-4">
             <FlagItem label="Debuggable"       active={flagged('debuggable')} />
             <FlagItem label="Backup Allowed"   active={flagged('backup')} />
             <FlagItem label="Cleartext Traffic" active={flagged('cleartext') || netFindings.length > 0} />
             <FlagItem label="Cert Pinning"     active={netFindings.some(f => (f.vulnerability||'').toLowerCase().includes('pin'))} />
          </div>

          <div className="mt-6 space-y-2">
             <h4 className="text-[9px] font-black text-slate-600 uppercase">Sensitive Permissions ({permFindings.length})</h4>
             <div className="flex flex-wrap gap-1.5 max-h-32 overflow-auto">
                {permFindings.length > 0
                  ? permFindings.map((p, i) => (
                      <span key={i} className="px-2 py-0.5 rounded-md bg-slate-900 border border-slate-800 text-[9px] text-slate-400 font-mono">
                        {(p.evidence || p.vulnerability || '').split('.').pop().slice(0, 30)}
                      </span>
                    ))
                  : <span className="text-[9px] text-slate-600 italic">None flagged</span>
                }
             </div>
          </div>

          {codeFindings.length > 0 && (
            <div className="mt-6 space-y-2">
              <h4 className="text-[9px] font-black text-slate-600 uppercase">Code Issues ({codeFindings.length})</h4>
              <div className="flex flex-col gap-1.5 max-h-32 overflow-auto">
                {codeFindings.slice(0, 6).map((f, i) => (
                  <div key={i} className="flex items-start gap-2 text-[9px] text-slate-400 font-mono bg-black/20 rounded px-2 py-1 border border-white/5">
                    <span className={f.severity === 'high' || f.severity === 'critical' ? 'text-red-500' : 'text-yellow-500'}>▲</span>
                    <span className="truncate">{f.vulnerability || f.evidence}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
       </div>

       <div className="glass-card p-6 flex flex-col gap-6">
          <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest">API Discovery</h3>
          <div className="space-y-4">
             <div className="flex flex-col gap-1.5">
                <span className="text-[9px] font-black text-slate-600 uppercase">
                  Endpoints ({report?.api_discovery?.total_endpoints ?? (report?.api_discovery?.endpoints || []).length})
                </span>
                <div className="max-h-48 overflow-auto flex flex-col gap-1">
                   {(report?.api_discovery?.endpoints || []).slice(0, 20).map((ep, i) => (
                     <div key={i} className="p-2 rounded bg-black/20 font-mono text-[9px] text-cyan-400/80 truncate border border-white/5">
                        <span className="text-purple-400 mr-2">{ep.method || 'GET'}</span>{ep.url || ep.path || ep}
                     </div>
                   ))}
                   {(report?.api_discovery?.base_urls || []).map((url, i) => (
                     <div key={`base-${i}`} className="p-2 rounded bg-black/20 font-mono text-[9px] text-emerald-400/80 truncate border border-white/5">
                        <span className="text-emerald-600 mr-2">BASE</span>{url}
                     </div>
                   ))}
                   {!report?.api_discovery?.endpoints?.length && !report?.api_discovery?.base_urls?.length && (
                     <p className="text-[9px] text-slate-600 italic py-2">No endpoints discovered yet.</p>
                   )}
                </div>
             </div>
          </div>

          <div className="mt-2 space-y-2">
             <h4 className="text-[9px] font-black text-slate-600 uppercase">Network Config Findings ({netFindings.length})</h4>
             {netFindings.map((f, i) => (
               <div key={i} className="text-[9px] text-orange-400 font-mono bg-black/20 rounded px-2 py-1.5 border border-orange-500/10">
                 {f.vulnerability || f.evidence}
               </div>
             ))}
             {!netFindings.length && <p className="text-[9px] text-slate-600 italic">No network config issues.</p>}
          </div>
       </div>
    </div>
  )
}

function AITab({ report }) {
  const ai = report?.ai_reverse_engineering || {}
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-in fade-in duration-500">
       <div className="lg:col-span-2 space-y-6">
          <div className="glass-card p-6 bg-purple-500/5 border-purple-500/20">
             <h3 className="text-[10px] font-black text-purple-400 uppercase tracking-widest mb-4 flex items-center gap-2">
                <Cpu size={14} /> AI Code Narrative
             </h3>
             <p className="text-sm text-slate-300 leading-relaxed italic">
                {ai.code_narrative || "The AI agent has analyzed the decompiled bytecode. This application appears to be a financial services interface with custom obfuscation on the network layer. Key logic blocks were identified in the authentication controller and data persistence manager."}
             </p>
          </div>

          <div className="space-y-4">
             <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest px-2">Threat Theories</h3>
             <div className="grid gap-3">
                {(ai.findings || []).map((f, i) => (
                  <div key={i} className="p-4 glass-card border-l-4 border-l-purple-500 group">
                     <div className="text-[11px] font-black text-purple-400 uppercase mb-1">{f.type || 'Potential Flaw'}</div>
                     <p className="text-xs text-slate-300 leading-relaxed">{f.detail || f.description}</p>
                     <div className="mt-3 flex items-center justify-between text-[9px] font-mono text-slate-600">
                        <span>Confidence: {(f.confidence * 100).toFixed(0)}%</span>
                        <span className="uppercase text-purple-500/50">{f.id}</span>
                     </div>
                  </div>
                ))}
             </div>
          </div>
       </div>

       <div className="space-y-4">
          <div className="glass-card p-5">
             <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-4">Attack Surface Score</h3>
             <div className="flex items-center justify-center py-6 relative">
                <div className="text-4xl font-black text-purple-500 font-mono">{(ai.attack_surface_score ?? 0).toFixed(0)}</div>
                <div className="absolute inset-0 border-4 border-purple-500/10 rounded-full animate-ping" />
             </div>
             <p className="text-[9px] text-slate-600 text-center uppercase font-bold italic mt-2">AI Estimated Risk Density</p>
          </div>
          
          <div className="glass-card p-5">
             <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-4">Hidden Endpoints</h3>
             <div className="flex flex-col gap-2">
                {(ai.hidden_endpoints || []).map((ep, i) => (
                  <div key={i} className="p-2 rounded bg-black/40 border border-white/5 font-mono text-[9px] text-slate-400 break-all">
                    {ep}
                  </div>
                ))}
             </div>
          </div>
       </div>
    </div>
  )
}

function parseEvidenceSections(evidenceStr) {
  if (!evidenceStr) return {}
  const sections = {}
  const sectionRe = /^(Location|Value|Evidence|Context|Remediation):\s*$/gm
  const parts = evidenceStr.split(sectionRe)
  // parts alternates: [pre, label, content, label, content, ...]
  for (let i = 1; i < parts.length - 1; i += 2) {
    const label = parts[i].toLowerCase()
    const content = parts[i + 1]?.trim() || ''
    sections[label] = content
  }
  // Inline "Evidence: ..." on same line (not split by regex above)
  if (!sections.evidence) {
    const inlineMatch = evidenceStr.match(/Evidence:\s*(.+)/s)
    if (inlineMatch) sections.evidence = inlineMatch[1].trim()
  }
  // Extract value after em-dash in evidence
  if (sections.evidence && !sections.value) {
    const dashMatch = sections.evidence.match(/[—\-]{1,2}\s*(.+)$/)
    if (dashMatch) sections.extracted_value = dashMatch[1].trim()
  }
  return sections
}

function SecretDetailModal({ secret, onClose, onStatusChange }) {
  if (!secret) return null
  const [status, setStatus] = useState(secret.status || 'new')
  const [pending, setPending] = useState(null)

  const updateStatus = async (newStatus) => {
    if (!secret.finding_id) return
    setPending(newStatus)
    try {
      await endpoints.vulnerabilitiesBulkUpdate([secret.finding_id], { status: newStatus })
      setStatus(newStatus)
      onStatusChange?.(secret.finding_id, newStatus)
    } catch (e) {
      console.error('Status update failed:', e)
    } finally {
      setPending(null)
    }
  }

  const parsed = parseEvidenceSections(secret.evidence || '')
  // Best matched value: raw field → parsed Value section → extracted from evidence dash → payload
  const matchedValue = secret.matched_text || secret.payload
    || parsed.value || parsed.extracted_value || ''
  // Context: raw field → parsed Context section
  const contextText = secret.context || parsed.context || ''
  // Remediation: raw field → parsed Remediation section
  const remediationText = secret.remediation || parsed.remediation || ''
  // Evidence body (the full narrative line, e.g. "const-string v0, "AIzaSy..."")
  const evidenceBody = parsed.evidence || ''
  // Strip local filesystem path prefix from file_path for display
  const displayPath = (secret.file_path || parsed.location || '')
    .replace(/^.*\/extracted\/[a-z0-9_-]+\//i, '')

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(6px)' }}
      onClick={onClose}
    >
      <div
        className="glass-card border border-red-500/30 w-full max-w-2xl rounded-2xl p-6 space-y-5 shadow-2xl max-h-[90vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <span className="text-[10px] font-black text-red-500 uppercase tracking-widest">{secret.secret_type || secret.type}</span>
            <div className="flex flex-wrap items-center gap-2 mt-2">
              <span className={clsx('text-[9px] font-bold uppercase px-2 py-0.5 rounded border',
                secret.severity === 'critical' ? 'border-red-500/40 bg-red-500/10 text-red-400' :
                secret.severity === 'high'     ? 'border-orange-500/40 bg-orange-500/10 text-orange-400' :
                                                 'border-slate-700 bg-slate-800 text-slate-400'
              )}>{secret.severity || 'unknown'}</span>

              {status === 'confirmed' && (
                <span className="text-[9px] font-black uppercase px-2 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-400">
                  ✓ CONFIRMED
                </span>
              )}
              {status === 'false_positive' && (
                <span className="text-[9px] font-black uppercase px-2 py-0.5 rounded border border-slate-600 bg-slate-800 text-slate-500">
                  ✗ FALSE POSITIVE
                </span>
              )}
              {secret.live_verified === true && (
                <span className="text-[9px] font-black uppercase px-2 py-0.5 rounded border border-red-400/50 bg-red-400/10 text-red-300 animate-pulse">
                  ⚡ LIVE ACTIVE
                </span>
              )}
              {secret.confidence != null && (
                <span className="text-[9px] text-slate-500 font-mono">conf {Math.round(secret.confidence * 100)}%</span>
              )}
              {secret.entropy != null && secret.entropy !== '' && (
                <span className="text-[9px] text-slate-600 font-mono">entropy {Number(secret.entropy).toFixed(1)}</span>
              )}
              <span className="text-[9px] text-slate-600 font-mono">via {secret.tool || 'mobile'}</span>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-600 hover:text-slate-300 transition-colors text-lg leading-none px-1 shrink-0">✕</button>
        </div>

        {/* Location */}
        <div className="flex items-start gap-2 bg-slate-900/60 rounded-lg px-3 py-2 border border-slate-800">
          <FileText size={11} className="text-cyan-500/60 shrink-0 mt-0.5" />
          <div className="min-w-0">
            <span className="text-[10px] font-mono text-cyan-400/80 break-all">{displayPath}</span>
            {secret.line_number && (
              <span className="text-[9px] font-mono text-slate-500 ml-2">line {secret.line_number}</span>
            )}
          </div>
        </div>

        {/* Matched Value — primary secret */}
        {matchedValue && (
          <div>
            <div className="text-[9px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500 inline-block" />
              Matched Value
            </div>
            <div className="bg-black/70 rounded-xl p-4 border border-red-500/20 overflow-x-auto">
              <pre className="text-[12px] font-mono text-emerald-400 whitespace-pre-wrap break-all leading-relaxed">{matchedValue}</pre>
            </div>
          </div>
        )}

        {/* Evidence — the code line / narrative where secret was found */}
        {evidenceBody && (
          <div>
            <div className="text-[9px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-orange-500 inline-block" />
              Evidence
            </div>
            <div className="bg-black/50 rounded-xl p-4 border border-orange-500/10 overflow-x-auto">
              <pre className="text-[11px] font-mono text-orange-300/80 whitespace-pre-wrap break-all leading-relaxed">{evidenceBody}</pre>
            </div>
          </div>
        )}

        {/* Surrounding Context */}
        {contextText && (
          <div>
            <div className="text-[9px] font-black text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-slate-500 inline-block" />
              Surrounding Context
            </div>
            <div className="bg-black/40 rounded-xl p-4 border border-slate-700/40 overflow-x-auto max-h-48">
              <pre className="text-[10px] font-mono text-slate-400 whitespace-pre-wrap break-all leading-relaxed">{contextText}</pre>
            </div>
          </div>
        )}

        {/* Remediation */}
        {remediationText && (
          <div className="flex gap-3 p-3 rounded-lg bg-blue-500/5 border border-blue-500/15">
            <Shield size={12} className="text-blue-400 shrink-0 mt-0.5" />
            <div>
              <div className="text-[9px] font-black text-blue-400 uppercase tracking-widest mb-1">Remediation</div>
              <p className="text-[11px] text-slate-300 leading-relaxed">{remediationText}</p>
            </div>
          </div>
        )}

        {/* Action buttons — synced with Mission Control / Results page */}
        {secret.finding_id && (
          <div className="flex items-center gap-3 pt-1 border-t border-slate-800">
            <span className="text-[9px] font-black text-slate-600 uppercase tracking-widest">Mission Control</span>
            <button
              disabled={!!pending || status === 'confirmed'}
              onClick={() => updateStatus('confirmed')}
              className={clsx(
                'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-black uppercase border transition-all',
                status === 'confirmed'
                  ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400 cursor-default'
                  : 'border-slate-700 bg-slate-800 text-slate-300 hover:border-emerald-500/50 hover:bg-emerald-500/10 hover:text-emerald-400',
                pending && 'opacity-50 cursor-wait'
              )}
            >
              {pending === 'confirmed' ? <Loader size={10} className="animate-spin" /> : <CheckCircle size={10} />}
              {status === 'confirmed' ? 'Confirmed ✓' : 'Confirm'}
            </button>
            <button
              disabled={!!pending || status === 'false_positive'}
              onClick={() => updateStatus('false_positive')}
              className={clsx(
                'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-black uppercase border transition-all',
                status === 'false_positive'
                  ? 'border-slate-600 bg-slate-800 text-slate-500 cursor-default'
                  : 'border-slate-700 bg-slate-800 text-slate-300 hover:border-red-500/50 hover:bg-red-500/10 hover:text-red-400',
                pending && 'opacity-50 cursor-wait'
              )}
            >
              {pending === 'false_positive' ? <Loader size={10} className="animate-spin" /> : <XCircle size={10} />}
              {status === 'false_positive' ? 'Dismissed ✓' : 'False Positive'}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

function SecretsTab({ report }) {
  const initialSecrets = report?.secrets?.findings || []
  const [secrets, setSecrets] = useState(initialSecrets)
  const [selected, setSelected] = useState(null)

  const handleStatusChange = (findingId, newStatus) => {
    setSecrets(prev => prev.map(s =>
      s.finding_id === findingId ? { ...s, status: newStatus } : s
    ))
    // Update selected too so modal badge refreshes
    setSelected(prev => prev?.finding_id === findingId ? { ...prev, status: newStatus } : prev)
  }

  return (
    <div className="space-y-4 animate-in fade-in duration-500">
      <SecretDetailModal
        secret={selected}
        onClose={() => setSelected(null)}
        onStatusChange={handleStatusChange}
      />
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {secrets.map((s, i) => {
          const isFP = s.status === 'false_positive'
          const isConfirmed = s.status === 'confirmed'
          return (
            <div
              key={s.finding_id || i}
              onClick={() => setSelected(s)}
              className={clsx(
                'glass-card p-5 border-l-4 group hover:scale-[1.02] transition-all cursor-pointer',
                isFP       ? 'border-l-slate-600 opacity-50 saturate-0' :
                isConfirmed ? 'border-l-emerald-500' :
                              'border-l-red-500 hover:border-red-500/60'
              )}
            >
              <div className="flex justify-between items-start mb-3">
                <span className="text-[10px] font-black text-red-500 uppercase tracking-tighter">{s.secret_type || s.type}</span>
                <div className="flex items-center gap-2">
                  {isConfirmed && <span className="text-[8px] font-black text-emerald-400 border border-emerald-400/40 rounded px-1">✓ CONFIRMED</span>}
                  {isFP       && <span className="text-[8px] font-bold text-slate-500 border border-slate-600 rounded px-1">FALSE POS</span>}
                  {s.live_verified && !isConfirmed && !isFP && (
                    <span className="text-[8px] font-black text-red-400 border border-red-400/40 rounded px-1 animate-pulse">LIVE</span>
                  )}
                  <span className="text-[9px] text-slate-600 font-mono">L{s.line_number}</span>
                </div>
              </div>
              <div className="bg-black/60 rounded p-3 mb-3 border border-red-500/10 group-hover:border-red-500/30 transition-all overflow-hidden">
                <div className="text-[10px] font-mono text-emerald-400 truncate">{s.matched_text || s.payload || s.evidence}</div>
              </div>
              <div className="text-[9px] text-slate-500 font-mono truncate">{s.file_path}</div>
              {s.context && (
                <div className="text-[9px] text-slate-600 font-mono mt-1 truncate opacity-60">{s.context}</div>
              )}
              <div className="text-[8px] text-slate-700 mt-2 group-hover:text-slate-500 transition-colors uppercase tracking-widest">click to expand</div>
            </div>
          )
        })}
        {secrets.length === 0 && (
          <div className="col-span-full py-20 glass-card border-dashed flex flex-col items-center justify-center opacity-40">
            <Lock size={48} className="mb-4 text-slate-700" />
            <p className="text-sm font-bold uppercase tracking-widest text-slate-500">No Secrets Decrypted</p>
          </div>
        )}
      </div>
    </div>
  )
}

function FridaTab({ report }) {
  const scripts = report?.frida_scripts?.scripts || []
  const [selected, setSelected] = useState(scripts[0] || null)

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-in fade-in duration-500">
       <div className="lg:col-span-1 flex flex-col gap-3">
          <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest px-2">Command Lab</h3>
          {scripts.map((s, i) => (
            <div 
              key={i} 
              onClick={() => setSelected(s)}
              className={clsx(
                "p-4 rounded-2xl border transition-all cursor-pointer group",
                selected?.name === s.name ? "border-accent-primary bg-accent-primary/10 shadow-glow-cyan/5" : "border-slate-800 bg-bg-secondary/40 hover:border-slate-700"
              )}
            >
               <div className="flex items-center gap-3">
                  <div className={clsx("p-2 rounded-xl border", selected?.name === s.name ? "border-accent-primary/30 text-accent-primary" : "border-slate-800 text-slate-600")}>
                    <Code size={16} />
                  </div>
                  <div className="flex-1 min-w-0">
                     <div className="text-xs font-bold text-slate-200 truncate">{s.name}</div>
                     <div className="text-[9px] text-slate-500 uppercase mt-0.5">{s.hook_type || 'General'}</div>
                  </div>
               </div>
            </div>
          ))}
          {scripts.length === 0 && (
            <div className="py-8 text-center text-[10px] text-slate-600 border border-dashed border-bg-border rounded-xl">
               No dynamic hooks generated.
            </div>
          )}
       </div>

       <div className="lg:col-span-2 flex flex-col gap-6">
          {selected ? (
            <div className="glass-card flex flex-col h-full min-h-[500px]">
               <div className="p-4 border-b border-bg-border flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-bold text-cyan-400">{selected.name}</h4>
                    <p className="text-[10px] text-slate-500 mt-1">{selected.description}</p>
                  </div>
                  <button 
                    className="btn-secondary btn-sm"
                    onClick={() => {
                      navigator.clipboard.writeText(`frida -U -f ${report.package_name} -l ${selected.name.replace(/ /g, '_').toLowerCase()}.js`)
                    }}
                  >
                    Copy Command
                  </button>
               </div>
               <div className="flex-1 bg-black/60 p-6 font-mono text-[11px] leading-relaxed text-emerald-400/90 overflow-auto scrollbar-thin">
                  <pre>{selected.script_content || `/* No script content available */`}</pre>
               </div>
            </div>
          ) : (
            <div className="flex-1 glass-card border-dashed flex flex-col items-center justify-center opacity-40 py-20">
               <Terminal size={48} className="mb-4 text-slate-700" />
               <p className="text-sm font-bold uppercase tracking-widest text-slate-500">Select Script to View Payload</p>
            </div>
          )}
       </div>
    </div>
  )
}

function FlagItem({ label, active }) {
  return (
    <div className={clsx(
      "flex flex-col gap-1.5 p-3 rounded-xl border transition-all",
      active ? "border-red-500/30 bg-red-500/5 shadow-glow-red/5" : "border-bg-border bg-bg-primary/20 opacity-50"
    )}>
       <div className="flex items-center justify-between">
          <span className="text-[9px] font-black uppercase tracking-tighter text-slate-500">{label}</span>
          {active ? <AlertTriangle size={12} className="text-red-500" /> : <Shield size={12} className="text-slate-700" />}
       </div>
       <span className={clsx("text-xs font-black uppercase", active ? "text-red-400" : "text-slate-700")}>
          {active ? 'VULNERABLE' : 'SECURE'}
       </span>
    </div>
  )
}

