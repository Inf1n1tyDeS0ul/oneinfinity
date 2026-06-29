import React, { useState, useEffect, useMemo } from 'react'
import {
  ShieldAlert, History, Search, ChevronDown, ChevronUp,
  CheckCircle2, XCircle, StopCircle, RefreshCw, Trash2, X, Zap,
  FileSearch, ScanLine, Filter, Download, MoreVertical,
  ExternalLink, MessageSquare, Tag, AlertTriangle, Eye, EyeOff
} from 'lucide-react'
import { Link, useLocation } from 'react-router-dom'
import { useStore } from '../store/useStore'
import { endpoints } from '../utils/api'
import { relativeTime, formatDateTime } from '../utils/time'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import clsx from 'clsx'
import { ValidationResultCard } from '../components/ValidationResultCard'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const STATUS_OPTIONS = [
  { id: 'new',            label: 'New',            icon: Zap,           color: 'text-cyan-400' },
  { id: 'confirmed',      label: 'Confirmed',      icon: CheckCircle2,  color: 'text-emerald-400' },
  { id: 'false_positive', label: 'False Positive', icon: XCircle,       color: 'text-red-400' },
  { id: 'remediated',     label: 'Remediated',     icon: ShieldAlert,   color: 'text-purple-400' },
  { id: 'risk_accepted',  label: 'Risk Accepted',  icon: AlertTriangle, color: 'text-orange-400' },
]

const SEV_COLORS = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#3b82f6',
  info:     '#6b7280',
}

// ─── Shared Components ────────────────────────────────────────────────────────

function DetailSection({ label, color = 'slate', children, icon: Icon }) {
  const colorMap = {
    slate:   'text-slate-500',
    yellow:  'text-yellow-500',
    blue:    'text-blue-500',
    green:   'text-green-500',
    emerald: 'text-emerald-500',
    red:     'text-red-500',
    purple:  'text-purple-500',
    cyan:    'text-cyan-500',
  }
  return (
    <div className="flex flex-col gap-2">
      <div className={clsx('text-[10px] font-black uppercase tracking-widest flex items-center gap-2', colorMap[color] ?? colorMap.slate)}>
        {Icon && <Icon size={12} />}
        {label}
      </div>
      <div className="bg-bg-primary/50 border border-bg-border/50 rounded-xl p-4 transition-all hover:border-slate-700">
        {children}
      </div>
    </div>
  )
}

function CodeBlock({ children, color = 'slate', maxH }) {
  const colorMap = {
    slate:   'text-slate-300',
    yellow:  'text-yellow-200',
    red:     'text-red-300',
    emerald: 'text-emerald-300',
    cyan:    'text-cyan-200',
  }
  return (
    <pre className={clsx(
      'text-xs font-mono whitespace-pre-wrap overflow-x-auto leading-relaxed scrollbar-thin',
      colorMap[color] ?? colorMap.slate,
      maxH ? `max-h-${maxH}` : 'max-h-96',
    )}>
      {children}
    </pre>
  )
}

// ─── Findings Tab ────────────────────────────────────────────────────────────

function FindingsTab({ scanFilter, onClearFilter, isMobile }) {
  const { vulnerabilities, setVulnerabilities, addNotification } = useStore()
  const [sevFilter, setSevFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [search, setSearch] = useState('')
  const [expanded, setExpanded] = useState(null)
  const [selected, setSelected] = useState(new Set())
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(false)
  const [updating, setUpdating] = useState(false)
  const [pendingId, setPendingId] = useState(null)
  const [retestPending, setRetestPending] = useState(null)
  const [retestStatus, setRetestStatus] = useState({})
  const [downloadingReport, setDownloadingReport] = useState(false)
  const [hitlFeedback, setHitlFeedback] = useState({})  // findingId → 'tp'|'fp'|null

  const handleHitlFeedback = async (findingId, isTrue) => {
    try {
      await endpoints.findingFeedback(findingId, { is_true_positive: isTrue, source: 'researcher' })
      setHitlFeedback(prev => ({ ...prev, [findingId]: isTrue ? 'tp' : 'fp' }))
      addNotification(isTrue ? 'Marked as true positive — model updated' : 'Marked as false positive — model updated', 'success')
    } catch (e) {
      addNotification(`Feedback failed: ${e.message}`, 'error')
    }
  }

  const updateFindingStatus = async (findingId, status) => {
    setPendingId(findingId)
    try {
      await endpoints.vulnerabilitiesBulkUpdate([findingId], { status })
      setVulnerabilities(vulnerabilities.map(v =>
        v.id === findingId ? { ...v, status } : v
      ))
      const labels = { confirmed: 'Confirmed', false_positive: 'Dismissed as false positive', remediated: 'Marked remediated', risk_accepted: 'Risk accepted' }
      addNotification(labels[status] || `Status → ${status}`, 'success')
      // Collapse the row so the updated status badge is visible in the list
      setExpanded(null)
    } catch (e) {
      addNotification(`Update failed: ${e.message}`, 'error')
    } finally {
      setPendingId(null)
    }
  }

  const handleRetest = async (findingId, target) => {
    setRetestPending(findingId)
    try {
      const res = await fetch(`/api/vulnerabilities/${findingId}/retest`, {
        method: 'POST',
        credentials: 'include',
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setRetestStatus(prev => ({ ...prev, [findingId]: 'queued' }))
      addNotification(`Retest queued (${data.retest_id})`, 'success')
      // Poll for completion
      const poll = setInterval(async () => {
        try {
          const r = await fetch(`/api/vulnerabilities/retests/${data.retest_id}`, { credentials: 'include' })
          if (!r.ok) return
          const s = await r.json()
          setRetestStatus(prev => ({ ...prev, [findingId]: s.status }))
          if (s.status === 'completed' || s.status === 'error') clearInterval(poll)
        } catch { clearInterval(poll) }
      }, 3000)
    } catch (e) {
      addNotification(`Retest failed: ${e.message}`, 'error')
    } finally {
      setRetestPending(null)
    }
  }

  const downloadBountyReport = async () => {
    setDownloadingReport(true)
    try {
      const target = scanFilter?.target || ''
      const url = `/api/findings/bounty-report${target ? `?target=${encodeURIComponent(target)}` : ''}`
      const res = await fetch(url, { credentials: 'include' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const text = await res.text()
      const blob = new Blob([text], { type: 'text/markdown' })
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = `bounty-report-${new Date().toISOString().slice(0,10)}.md`
      a.click()
      addNotification('Bounty report downloaded', 'success')
    } catch (e) {
      addNotification(`Report failed: ${e.message}`, 'error')
    } finally {
      setDownloadingReport(false)
    }
  }

  const load = async () => {
    setLoading(true)
    try {
      const [vRes, sRes] = await Promise.all([
        endpoints.vulnerabilities(scanFilter ? { target: scanFilter.target } : {}),
        endpoints.findingsStats()
      ])
      setVulnerabilities(vRes.data)
      setStats(sRes.data)
    } catch (e) {
      addNotification(`Failed to load findings: ${e.message}`, 'error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [scanFilter?.id])

  const filtered = useMemo(() => {
    return vulnerabilities.filter(v => {
      if (sevFilter && v.severity !== sevFilter) return false
      if (statusFilter && v.status !== statusFilter) return false
      if (sourceFilter) {
        const isMobile = v.source_type === 'mobile' || v.tool === 'mobile' || v.scan_id?.startsWith('mobile_')
        if (sourceFilter === 'mobile' && !isMobile) return false
        if (sourceFilter === 'web' && isMobile) return false
      }
      if (search) {
        const q = search.toLowerCase()
        return (
          v.title?.toLowerCase().includes(q) ||
          v.target?.toLowerCase().includes(q) ||
          v.tool?.toLowerCase().includes(q) ||
          v.attack_type?.toLowerCase().includes(q)
        )
      }
      return true
    })
  }, [vulnerabilities, sevFilter, statusFilter, sourceFilter, search])

  const handleBulkStatus = async (status) => {
    if (selected.size === 0) return
    setUpdating(true)
    try {
      await endpoints.vulnerabilitiesBulkUpdate([...selected], { status })
      addNotification(`Updated ${selected.size} findings`, 'success')
      setSelected(new Set())
      load()
    } catch (e) {
      addNotification(`Error: ${e.message}`, 'error')
    } finally {
      setUpdating(false)
    }
  }

  const toggleSelect = (id) => {
    const next = new Set(selected)
    next.has(id) ? next.delete(id) : next.add(id)
    setSelected(next)
  }

  const toggleSelectAll = () => {
    if (selected.size === filtered.length) setSelected(new Set())
    else setSelected(new Set(filtered.map(v => v.id)))
  }

  const pieData = useMemo(() => {
    if (!stats?.severity) return []
    return Object.entries(stats.severity).map(([name, value]) => ({ name, value }))
  }, [stats])

  return (
    <div className="flex flex-col gap-6">
      {/* Overview Stats */}
      {!scanFilter && stats && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          <div className="lg:col-span-3 glass-card p-6 flex items-center justify-between overflow-hidden relative group">
             <div className="flex flex-col gap-1 z-10">
                <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Intelligence Pulse</span>
                <div className="text-3xl font-black text-slate-100">{stats.total} <span className="text-sm font-bold text-slate-500">TOTAL FINDINGS</span></div>
                <div className="flex gap-4 mt-2">
                   {SEV_ORDER.map(s => (
                     <div key={s} className="flex flex-col">
                        <span className="text-[9px] font-bold uppercase text-slate-600">{s}</span>
                        <span className={clsx("text-sm font-black", 
                          s === 'critical' ? 'text-red-500' : 
                          s === 'high' ? 'text-orange-500' : 
                          s === 'medium' ? 'text-yellow-500' : 'text-blue-500'
                        )}>{stats.severity[s] || 0}</span>
                     </div>
                   ))}
                </div>
             </div>
             <div className="h-32 w-48 -mr-6 opacity-80 group-hover:opacity-100 transition-opacity">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={pieData} innerRadius={35} outerRadius={50} paddingAngle={5} dataKey="value">
                      {pieData.map((entry, i) => <Cell key={i} fill={SEV_COLORS[entry.name] || '#64748b'} />)}
                    </Pie>
                    <Tooltip contentStyle={{ background: '#0f172a', border: 'none', borderRadius: '8px', fontSize: '10px' }} />
                  </PieChart>
                </ResponsiveContainer>
             </div>
             <ShieldAlert size={120} className="absolute -right-8 -bottom-8 text-slate-900 opacity-20 pointer-events-none group-hover:scale-110 transition-transform" />
          </div>
          
          <div className="glass-card p-6 flex flex-col justify-between">
             <div>
                <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Confidence Score</span>
                <div className="text-2xl font-black text-emerald-400 mt-1">{(vulnerabilities.reduce((a, b) => a + (b.confidence || 0), 0) / (vulnerabilities.length || 1) * 100).toFixed(1)}%</div>
             </div>
             <div className="mt-4 flex gap-2">
                <div className="flex-1 h-1 bg-slate-800 rounded-full overflow-hidden">
                   <div className="h-full bg-emerald-500 shadow-glow-green" style={{ width: '88%' }} />
                </div>
             </div>
             <p className="text-[9px] text-slate-600 mt-2 font-bold uppercase italic">Aggregated across all vectors</p>
          </div>
        </div>
      )}

      {/* Control Bar */}
      <div className="flex flex-col md:flex-row md:items-center gap-3 bg-bg-secondary/40 border border-bg-border p-3 rounded-2xl">
        <div className="relative flex-1 group">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600 group-focus-within:text-accent-primary transition-colors" />
          <input
            className="w-full bg-bg-primary/50 border border-bg-border rounded-xl pl-10 pr-4 py-2 text-xs font-medium text-slate-300 focus:border-accent-primary outline-none transition-all shadow-inner"
            placeholder={isMobile ? "Search..." : "Search target, title, or vulnerability type..."}
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        
        <div className="flex flex-wrap items-center gap-2">
          <select className="flex-1 md:flex-none bg-bg-primary/50 border border-bg-border rounded-xl px-3 py-2 text-[10px] font-bold uppercase text-slate-400 outline-none focus:border-accent-primary"
            value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
            <option value="">{isMobile ? "Sev" : "All Severity"}</option>
            {SEV_ORDER.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          
          <select className="flex-1 md:flex-none bg-bg-primary/50 border border-bg-border rounded-xl px-3 py-2 text-[10px] font-bold uppercase text-slate-400 outline-none focus:border-accent-primary"
            value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
            <option value="">{isMobile ? "Status" : "All Status"}</option>
            {STATUS_OPTIONS.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>

          {!isMobile && (
            <select className="bg-bg-primary/50 border border-bg-border rounded-xl px-3 py-2 text-[10px] font-bold uppercase text-slate-400 outline-none focus:border-accent-primary"
              value={sourceFilter} onChange={e => setSourceFilter(e.target.value)}>
              <option value="">All Sources</option>
              <option value="web">Web</option>
              <option value="mobile">Mobile</option>
            </select>
          )}

          <button className="p-2.5 rounded-xl bg-bg-primary/50 border border-bg-border text-slate-500 hover:text-accent-primary transition-all shadow-sm" onClick={load}>
            <RefreshCw size={14} className={clsx(loading && 'animate-spin')} />
          </button>
          
          <button
            onClick={downloadBountyReport}
            disabled={downloadingReport}
            className="flex-1 md:flex-none flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px] font-black uppercase hover:bg-emerald-500/20 transition-all disabled:opacity-50"
            title="Download bounty report (confirmed findings only)"
          >
            <Download size={12} className={downloadingReport ? 'animate-bounce' : ''} />
            <span className="hidden sm:inline">Bounty Report</span>
            <span className="sm:hidden">Report</span>
          </button>
        </div>
      </div>

      {/* Bulk Actions HUD */}
      {selected.size > 0 && (
        <div className="flex items-center gap-4 px-5 py-3 bg-accent-primary/10 border border-accent-primary/30 rounded-2xl animate-in slide-in-from-top-2">
           <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded-lg bg-accent-primary flex items-center justify-center text-black font-black text-[10px]">
                {selected.size}
              </div>
              <span className="text-xs font-bold text-accent-primary uppercase tracking-tighter">Findings Selected</span>
           </div>
           
           <div className="h-6 w-px bg-accent-primary/20" />
           
           <div className="flex items-center gap-2">
              <button 
                onClick={() => handleBulkStatus('confirmed')}
                className="btn-ghost text-[10px] font-black uppercase text-emerald-400 hover:bg-emerald-500/10 px-3 py-1.5 rounded-lg border border-transparent hover:border-emerald-500/30 transition-all"
              >
                Confirm
              </button>
              <button 
                onClick={() => handleBulkStatus('false_positive')}
                className="btn-ghost text-[10px] font-black uppercase text-red-400 hover:bg-red-500/10 px-3 py-1.5 rounded-lg border border-transparent hover:border-red-500/30 transition-all"
              >
                Dismiss
              </button>
              <button 
                onClick={() => handleBulkStatus('remediated')}
                className="btn-ghost text-[10px] font-black uppercase text-purple-400 hover:bg-purple-500/10 px-3 py-1.5 rounded-lg border border-transparent hover:border-purple-500/30 transition-all"
              >
                Resolved
              </button>
           </div>
           
           <button className="ml-auto text-[10px] font-bold text-slate-500 hover:text-slate-300" onClick={() => setSelected(new Set())}>
             Cancel
           </button>
        </div>
      )}

      {/* Main Grid */}
      <div className="grid grid-cols-1 gap-3">
        {filtered.length === 0 && (
          <div className="glass-card py-20 flex flex-col items-center justify-center opacity-40">
             <FileSearch size={48} className="mb-4 text-slate-700" />
             <p className="text-sm font-bold uppercase tracking-widest text-slate-500">No Intelligence Matches Found</p>
          </div>
        )}
        
        {filtered.map(v => (
          <div key={v.id} className={clsx(
            "group relative glass-card transition-all duration-300 overflow-hidden",
            expanded === v.id ? "ring-1 ring-accent-primary/30 border-slate-700" : "hover:border-slate-700/50",
            v.status === 'false_positive' && "opacity-40 saturate-0",
            v.status === 'remediated' && "opacity-60"
          )}>
            <div className="flex flex-col lg:flex-row">
              {/* Select Toggle */}
              <div 
                onClick={() => toggleSelect(v.id)}
                className={clsx(
                  "absolute left-0 top-0 bottom-0 w-1 cursor-pointer transition-all",
                  selected.has(v.id) ? "bg-accent-primary" : "bg-transparent group-hover:bg-slate-800"
                )} 
              />

              <div className="flex-1 flex flex-col lg:flex-row lg:items-center p-4 gap-4">
                 <div className="flex items-center gap-4 min-w-[140px]">
                    <span className={clsx(
                      "px-2 py-0.5 rounded-lg text-[9px] font-black uppercase border",
                      v.severity === 'critical' ? 'bg-red-500/10 text-red-500 border-red-500/20' : 
                      v.severity === 'high' ? 'bg-orange-500/10 text-orange-500 border-orange-500/20' :
                      v.severity === 'medium' ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' :
                      'bg-blue-500/10 text-blue-500 border-blue-500/20'
                    )}>
                      {v.severity}
                    </span>
                    <div className="flex flex-col">
                       <span className="text-[10px] font-mono text-slate-500 uppercase tracking-tighter">{v.tool || 'Autonomous'}</span>
                       <span className="text-[8px] text-slate-600 font-mono italic">{relativeTime(v.created_at)}</span>
                    </div>
                 </div>

                 <div className="flex-1 min-w-0" onClick={() => setExpanded(expanded === v.id ? null : v.id)}>
                    <div className="flex items-center gap-2 mb-0.5">
                      <div className="text-sm font-bold text-slate-200 group-hover:text-accent-primary transition-colors truncate">{v.title || v.attack_type || 'Unspecified Finding'}</div>
                      {(v.source_type === 'mobile' || v.tool === 'mobile' || v.scan_id?.startsWith('mobile_')) && (
                        <span className="shrink-0 text-[8px] font-black uppercase px-1.5 py-0.5 rounded border border-purple-500/30 bg-purple-500/10 text-purple-400">Mobile</span>
                      )}
                    </div>
                    <div className="text-[10px] text-slate-500 font-mono truncate">{v.url || v.target}</div>
                 </div>

                 <div className="flex items-center gap-6">
                    <div className="flex flex-col items-end min-w-[80px]">
                       <span className="text-[9px] font-bold text-slate-600 uppercase tracking-widest">Confidence</span>
                       <span className="text-xs font-black text-slate-400 font-mono">{((v.confidence || 0.8) * 100).toFixed(0)}%</span>
                    </div>

                    <div className="flex flex-col items-end min-w-[100px]">
                       <span className="text-[9px] font-bold text-slate-600 uppercase tracking-widest">Lifecycle</span>
                       <div className="flex items-center gap-1.5 mt-0.5">
                          {(() => {
                            const status = STATUS_OPTIONS.find(s => s.id === v.status) || STATUS_OPTIONS[0]
                            return (
                              <>
                                <status.icon size={12} className={status.color} />
                                <span className={clsx("text-[10px] font-black uppercase tracking-tighter", status.color)}>{status.label}</span>
                              </>
                            )
                          })()}
                       </div>
                    </div>

                    <button 
                      onClick={() => setExpanded(expanded === v.id ? null : v.id)}
                      className="p-2 rounded-xl bg-bg-primary/50 text-slate-600 hover:text-white transition-all border border-transparent hover:border-slate-800"
                    >
                      {expanded === v.id ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                    </button>
                 </div>
              </div>
            </div>

            {/* Detailed Body */}
            {expanded === v.id && (
              <div className="border-t border-bg-border/50 bg-bg-secondary/30 p-6 animate-in slide-in-from-top-4 duration-500">
                <div className="grid grid-cols-1 xl:grid-cols-3 gap-8">

                  {/* Primary Intel */}
                  <div className="xl:col-span-2 flex flex-col gap-6">

                    {/* Metadata strip */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                      {[
                        { label: 'Scan ID',    value: v.scan_id },
                        { label: 'Type',       value: v.vuln_type || v.attack_type },
                        { label: 'Tool',       value: v.raw?.tool || v.tool },
                        { label: 'CVSS',       value: v.cvss != null ? v.cvss.toFixed(1) : '—' },
                        { label: 'Target',     value: v.target },
                        { label: 'URL / File', value: v.url },
                        { label: 'Confidence', value: v.confidence != null ? `${(v.confidence * 100).toFixed(0)}%` : '—' },
                        { label: 'Source',     value: v.source_type || 'tool' },
                      ].filter(r => r.value).map(({ label, value }) => (
                        <div key={label} className="bg-bg-primary/40 border border-bg-border/50 rounded-xl p-3">
                          <div className="text-[9px] font-black text-slate-600 uppercase tracking-widest mb-1">{label}</div>
                          <div className="text-[10px] font-mono text-slate-300 break-all leading-relaxed">{value}</div>
                        </div>
                      ))}
                    </div>

                    {/* Evidence — full, scrollable */}
                    <DetailSection label="Technical Evidence" color="slate" icon={FileSearch}>
                      <pre className="text-xs text-slate-300 font-mono whitespace-pre-wrap break-words leading-relaxed max-h-64 overflow-y-auto scrollbar-thin">
                        {v.evidence || v.raw?.evidence || 'No structural evidence captured for this vector.'}
                      </pre>
                    </DetailSection>

                    {/* Raw tool output — every key/value from the raw object */}
                    {v.raw && Object.keys(v.raw).filter(k => v.raw[k] && !['url','severity','confidence','vuln_type','title'].includes(k)).length > 0 && (
                      <DetailSection label="Raw Tool Output" color="cyan" icon={FileSearch}>
                        <div className="flex flex-col divide-y divide-bg-border/30">
                          {Object.entries(v.raw)
                            .filter(([, val]) => val !== '' && val != null)
                            .map(([key, val]) => (
                              <div key={key} className="flex gap-4 py-2 first:pt-0 last:pb-0">
                                <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest w-28 shrink-0 pt-0.5">{key.replace(/_/g,' ')}</span>
                                <pre className="text-[11px] font-mono text-slate-300 whitespace-pre-wrap break-all flex-1 leading-relaxed">
                                  {typeof val === 'object' ? JSON.stringify(val, null, 2) : String(val)}
                                </pre>
                              </div>
                            ))}
                        </div>
                      </DetailSection>
                    )}

                    {v.request_poc && (
                      <DetailSection label="Proof of Concept — Dynamic Request" color="yellow" icon={Zap}>
                        <CodeBlock color="yellow">{v.request_poc}</CodeBlock>
                      </DetailSection>
                    )}

                    {v.payload && (
                      <DetailSection label="Exploitation Payload / Remediation" color="red" icon={ShieldAlert}>
                        <CodeBlock color="red">{v.payload}</CodeBlock>
                      </DetailSection>
                    )}

                    {v.reproduction_steps && (
                      <DetailSection label="Reproduction Vector" color="purple" icon={History}>
                        <div className="flex flex-col gap-3">
                          {Array.isArray(v.reproduction_steps) ? v.reproduction_steps.map((step, idx) => (
                            <div key={idx} className="flex gap-4">
                              <span className="w-5 h-5 rounded bg-bg-elevated flex items-center justify-center text-[10px] font-black text-accent-purple border border-accent-purple/20">{idx + 1}</span>
                              <span className="text-xs text-slate-400 mt-0.5">{step}</span>
                            </div>
                          )) : (
                            <p className="text-xs text-slate-400 leading-relaxed whitespace-pre-wrap">{v.reproduction_steps}</p>
                          )}
                        </div>
                      </DetailSection>
                    )}
                  </div>

                  {/* Metadata & Actions */}
                  <div className="flex flex-col gap-6">
                    <DetailSection label="Mission Impact" color="emerald" icon={AlertTriangle}>
                      <div className="flex flex-col gap-4">
                        <div className="flex items-end gap-3">
                          <div>
                            <span className="text-[10px] font-black text-slate-600 uppercase">CVSS Score</span>
                            <div className={clsx('text-3xl font-black',
                              v.cvss >= 9 ? 'text-red-500' : v.cvss >= 7 ? 'text-orange-500' : v.cvss >= 4 ? 'text-yellow-500' : 'text-blue-500'
                            )}>{v.cvss != null ? v.cvss.toFixed(1) : '—'}</div>
                          </div>
                          <div>
                            <span className="text-[10px] font-black text-slate-600 uppercase">Confidence</span>
                            <div className="text-xl font-black text-emerald-400">{v.confidence != null ? `${(v.confidence*100).toFixed(0)}%` : '—'}</div>
                          </div>
                        </div>

                        {(v.remediation || v.raw?.payload || v.payload) && (
                          <div>
                            <span className="text-[10px] font-black text-slate-600 uppercase">Remediation Guide</span>
                            <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                              {v.remediation || v.raw?.payload || v.payload}
                            </p>
                          </div>
                        )}

                        {v.tags?.length > 0 && (
                          <div className="flex flex-wrap gap-2">
                            {v.tags.map(t => (
                              <span key={t} className="px-2 py-0.5 rounded-full bg-slate-900 border border-slate-800 text-[9px] font-bold text-slate-500 uppercase">{t}</span>
                            ))}
                          </div>
                        )}
                      </div>
                    </DetailSection>

                    {/* Validation Results */}
                    <DetailSection label="Validation Status" color="cyan" icon={ShieldAlert}>
                      <ValidationResultCard
                        findingId={v.finding_id || v.id}
                        onRetry={(result) => {
                          // Update finding confidence when validation completes
                          if (result.valid) {
                            addNotification(`Finding validated: ${(result.confidence * 100).toFixed(0)}% confidence`, 'success')
                          } else {
                            addNotification(`Validation failed: ${(result.confidence * 100).toFixed(0)}% confidence`, 'warning')
                          }
                        }}
                      />
                    </DetailSection>

                    <div className="flex flex-col gap-2">
                      <span className="text-[10px] font-black text-slate-600 uppercase tracking-widest px-1">Mission Control</span>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {/* Confirm */}
                        <button
                          disabled={pendingId === v.id || v.status === 'confirmed'}
                          onClick={() => updateFindingStatus(v.id, 'confirmed')}
                          className={clsx(
                            'flex items-center justify-center gap-2 p-2.5 rounded-xl text-[10px] font-black uppercase transition-all border',
                            v.status === 'confirmed'
                              ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300 cursor-default'
                              : 'bg-accent-success/10 border-accent-success/20 text-accent-success hover:bg-accent-success/20',
                            pendingId === v.id && 'opacity-50 cursor-wait'
                          )}
                        >
                          <CheckCircle2 size={12} />
                          {v.status === 'confirmed' ? 'Confirmed ✓' : 'Confirm'}
                        </button>

                        {/* False Positive */}
                        <button
                          disabled={pendingId === v.id || v.status === 'false_positive'}
                          onClick={() => updateFindingStatus(v.id, 'false_positive')}
                          className={clsx(
                            'flex items-center justify-center gap-2 p-2.5 rounded-xl text-[10px] font-black uppercase transition-all border',
                            v.status === 'false_positive'
                              ? 'bg-slate-700/50 border-slate-600 text-slate-400 cursor-default'
                              : 'bg-red-500/10 border-red-500/20 text-red-400 hover:bg-red-500/20',
                            pendingId === v.id && 'opacity-50 cursor-wait'
                          )}
                        >
                          <XCircle size={12} />
                          {v.status === 'false_positive' ? 'Dismissed ✓' : 'False Positive'}
                        </button>

                        {/* Remediated */}
                        <button
                          disabled={pendingId === v.id || v.status === 'remediated'}
                          onClick={() => updateFindingStatus(v.id, 'remediated')}
                          className={clsx(
                            'flex items-center justify-center gap-2 p-2.5 rounded-xl text-[10px] font-black uppercase transition-all border',
                            v.status === 'remediated'
                              ? 'bg-purple-500/20 border-purple-500/40 text-purple-300 cursor-default'
                              : 'bg-purple-500/10 border-purple-500/20 text-purple-400 hover:bg-purple-500/20',
                            pendingId === v.id && 'opacity-50 cursor-wait'
                          )}
                        >
                          <ShieldAlert size={12} />
                          {v.status === 'remediated' ? 'Remediated ✓' : 'Mark Remediated'}
                        </button>

                        {/* Retest */}
                        <button
                          disabled={pendingId === v.id || retestPending === v.id}
                          onClick={() => handleRetest(v.id, v.target)}
                          className={clsx(
                            'flex items-center justify-center gap-2 p-2.5 rounded-xl text-[10px] font-black uppercase transition-all border',
                            retestStatus[v.id]
                              ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300 cursor-default'
                              : 'bg-cyan-500/10 border-cyan-500/20 text-cyan-400 hover:bg-cyan-500/20',
                            retestPending === v.id && 'opacity-50 cursor-wait'
                          )}
                        >
                          <RefreshCw size={12} className={retestPending === v.id ? 'animate-spin' : ''} />
                          {retestStatus[v.id] ? `Retest: ${retestStatus[v.id]}` : 'Retest'}
                        </button>

                        {/* Export */}
                        <button
                          className="flex items-center justify-center gap-2 p-2.5 rounded-xl bg-accent-primary/10 border border-accent-primary/20 text-[10px] font-black text-accent-primary uppercase hover:bg-accent-primary/20 transition-all"
                          onClick={() => {
                            const blob = new Blob([JSON.stringify(v, null, 2)], { type: 'application/json' })
                            const a = document.createElement('a')
                            a.href = URL.createObjectURL(blob)
                            a.download = `finding-${v.finding_id || v.id}.json`
                            a.click()
                          }}
                        >
                          <Download size={12} /> Export JSON
                        </button>

                        {/* HITL Researcher Feedback */}
                        <button
                          onClick={() => handleHitlFeedback(v.finding_id || v.id, true)}
                          disabled={hitlFeedback[v.finding_id || v.id] === 'tp'}
                          className={clsx(
                            'flex items-center justify-center gap-2 p-2.5 rounded-xl text-[10px] font-black uppercase transition-all border',
                            hitlFeedback[v.finding_id || v.id] === 'tp'
                              ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300 cursor-default'
                              : 'bg-bg-elevated border-bg-border text-slate-400 hover:border-emerald-500/40 hover:text-emerald-400'
                          )}
                          title="True Positive — feeds HITL RL engine"
                        >
                          👍 TP
                        </button>
                        <button
                          onClick={() => handleHitlFeedback(v.finding_id || v.id, false)}
                          disabled={hitlFeedback[v.finding_id || v.id] === 'fp'}
                          className={clsx(
                            'flex items-center justify-center gap-2 p-2.5 rounded-xl text-[10px] font-black uppercase transition-all border',
                            hitlFeedback[v.finding_id || v.id] === 'fp'
                              ? 'bg-red-500/20 border-red-500/40 text-red-300 cursor-default'
                              : 'bg-bg-elevated border-bg-border text-slate-400 hover:border-red-500/40 hover:text-red-400'
                          )}
                          title="False Positive — calibrates threshold"
                        >
                          👎 FP
                        </button>

                        {/* PoC File Download */}
                        {v.poc_file && (
                          <a
                            href={`/api/findings/${v.finding_id || v.id}/poc`}
                            download
                            className="flex items-center justify-center gap-2 p-2.5 rounded-xl bg-yellow-500/10 border border-yellow-500/20 text-[10px] font-black text-yellow-400 uppercase hover:bg-yellow-500/20 transition-all col-span-2"
                          >
                            <Download size={12} /> Download PoC
                          </a>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Scan History Tab ─────────────────────────────────────────────────────────

function ScanHistoryTab({ onViewFindings, isMobile }) {
  const { scans, addNotification, setScans } = useStore()
  const [selected, setSelected] = useState(new Set())
  const [deleting, setDeleting] = useState(false)

  const allIds = scans.map(s => s.id)
  const allSelected = allIds.length > 0 && allIds.every(id => selected.has(id))

  const toggleAll  = () => setSelected(allSelected ? new Set() : new Set(allIds))
  const toggleOne  = (id) => setSelected(prev => {
    const next = new Set(prev)
    next.has(id) ? next.delete(id) : next.add(id)
    return next
  })

  const refreshScans = () =>
    endpoints.scans().then(r => setScans(r.data)).catch(e => addNotification(`Could not refresh scans: ${e.message}`, 'error'))

  const handleStop = async (id) => {
    try {
      await endpoints.stopScan(id)
      addNotification('Scan stopped', 'success')
      refreshScans()
    } catch (e) {
      addNotification(`Error: ${e.message}`, 'error')
    }
  }

  const handleDeleteSelected = async () => {
    if (selected.size === 0) return
    setDeleting(true)
    try {
      await endpoints.deleteScans([...selected])
      addNotification(`Deleted ${selected.size} scan${selected.size > 1 ? 's' : ''}`, 'success')
      setSelected(new Set())
      refreshScans()
    } catch (e) {
      addNotification(`Delete failed: ${e.message}`, 'error')
    } finally {
      setDeleting(false)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Bulk action toolbar */}
      {selected.size > 0 && (
        <div className="flex items-center gap-3 px-5 py-3 bg-red-500/10 border border-red-500/30 rounded-2xl animate-in slide-in-from-top-2">
          <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded-lg bg-red-500 flex items-center justify-center text-white font-black text-[10px]">
                {selected.size}
              </div>
              <span className="text-xs font-bold text-red-500 uppercase tracking-tighter">Scans Selected</span>
           </div>
          
          <div className="h-6 w-px bg-red-500/20" />

          <button
            className="flex items-center gap-2 px-4 py-1.5 rounded-xl text-[10px] font-black uppercase bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors disabled:opacity-50 border border-red-500/20"
            onClick={handleDeleteSelected}
            disabled={deleting}
          >
            <Trash2 size={12} />
            {deleting ? 'Purging…' : `Purge Scan Data`}
          </button>
          
          <button
            className="text-[10px] font-bold text-slate-500 hover:text-slate-300 transition-colors ml-auto uppercase"
            onClick={() => setSelected(new Set())}
          >
            Clear selection
          </button>
        </div>
      )}

      <div className="glass-card overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="bg-bg-elevated/50 text-slate-500 uppercase tracking-tighter border-b border-bg-border">
              <th className="px-5 py-4 w-10">
                <input
                  type="checkbox"
                  checked={allSelected}
                  onChange={toggleAll}
                  className="accent-accent-primary cursor-pointer w-3.5 h-3.5 rounded border-slate-700 bg-slate-900"
                />
              </th>
              <th className="px-4 py-4 font-bold text-left">Mission Target</th>
              <th className="px-4 py-4 font-bold text-left">Sector</th>
              <th className="px-4 py-4 font-bold text-center">Lifecycle</th>
              <th className="px-4 py-4 font-bold text-left">Timeline</th>
              <th className="px-4 py-4 font-bold text-center">Intel</th>
              <th className="px-4 py-4 font-bold text-left w-32">Efficiency</th>
              <th className="px-4 py-4 w-12" />
            </tr>
          </thead>
          <tbody className="divide-y divide-bg-border/30">
            {scans.length === 0 && (
              <tr>
                <td colSpan={9} className="px-4 py-20 text-center">
                  <div className="flex flex-col items-center gap-3 text-slate-600">
                    <ScanLine size={48} className="opacity-20" />
                    <span className="text-sm font-bold uppercase tracking-widest">No Historical Mission Records</span>
                  </div>
                </td>
              </tr>
            )}
            {scans.map(s => {
              const isSelected = selected.has(s.id)
              const isRunning = s.status === 'running'
              return (
                <tr
                  key={s.id}
                  className={clsx(
                    'transition-colors cursor-pointer group',
                    isSelected ? 'bg-accent-primary/5' : 'hover:bg-accent-primary/5'
                  )}
                  onClick={() => toggleOne(s.id)}
                >
                  <td className="px-5 py-4" onClick={e => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => toggleOne(s.id)}
                      className="accent-accent-primary cursor-pointer w-3.5 h-3.5 rounded border-slate-700 bg-slate-900"
                    />
                  </td>
                  <td className="px-4 py-4">
                    <div className="flex flex-col">
                       <span className="text-[11px] font-black text-slate-200 group-hover:text-accent-primary transition-colors truncate max-w-[200px]" title={s.target}>
                          {s.target}
                       </span>
                       <span className="text-[9px] text-slate-600 font-mono mt-0.5">{s.id.slice(0, 12)}</span>
                    </div>
                  </td>
                  <td className="px-4 py-4">
                     <span className={clsx(
                       "px-2 py-0.5 rounded border text-[9px] font-black uppercase tracking-tighter",
                       s.scan_type === 'mobile' || s.source === 'mobile'
                         ? 'bg-purple-500/10 border-purple-500/20 text-purple-400'
                         : 'bg-bg-elevated border-bg-border text-slate-500'
                     )}>
                        {s.scan_type || s.type || 'Standard'}
                     </span>
                  </td>
                  <td className="px-4 py-4 text-center">
                    <span className={clsx(
                      "px-2 py-0.5 rounded text-[9px] font-black uppercase border",
                      s.status === 'completed' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                      s.status === 'failed' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                      'bg-accent-primary/10 text-accent-primary border-accent-primary/20'
                    )}>
                       {s.status}
                    </span>
                  </td>
                  <td className="px-4 py-4">
                    <div className="flex flex-col">
                       <span className="text-[10px] text-slate-400 font-bold">{relativeTime(s.started_at)}</span>
                       <span className="text-[9px] text-slate-600 font-medium">DISPATCHED</span>
                    </div>
                  </td>
                  <td className="px-4 py-4 text-center">
                    <div className="flex items-center justify-center gap-2">
                      <button
                        className="w-8 h-8 rounded-lg bg-bg-primary border border-bg-border flex items-center justify-center text-accent-primary hover:border-accent-primary transition-all group/btn"
                        onClick={e => { e.stopPropagation(); onViewFindings(s) }}
                        title="View Intelligence"
                      >
                        <span className="text-[11px] font-black group-hover/btn:scale-110 transition-transform">{s.findings_count ?? s.findings ?? 0}</span>
                      </button>
                    </div>
                  </td>
                  <td className="px-4 py-4">
                    {isRunning ? (
                      <div className="flex flex-col gap-1.5 w-24">
                        <div className="w-full h-1 bg-bg-elevated rounded-full overflow-hidden border border-bg-border">
                          <div
                            className="h-full bg-accent-primary rounded-full transition-all duration-700 shadow-glow-cyan"
                            style={{ width: `${s.progress ?? 0}%` }}
                          />
                        </div>
                        <span className="text-[9px] text-slate-500 font-black uppercase tracking-tighter">{s.progress ?? 0}% SYNC</span>
                      </div>
                    ) : (
                      <span className="text-[9px] text-slate-700 font-black uppercase tracking-widest italic">ARCHIVED</span>
                    )}
                  </td>
                  <td className="px-4 py-4" onClick={e => e.stopPropagation()}>
                    <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                       {isRunning ? (
                         <button className="p-1.5 rounded-lg bg-red-500/10 text-red-500 border border-red-500/20 hover:bg-red-500/20 transition-all" onClick={() => handleStop(s.id)}>
                            <StopCircle size={14} />
                         </button>
                       ) : (
                         <button className="p-1.5 rounded-lg bg-bg-elevated text-slate-600 border border-bg-border hover:text-red-500 hover:border-red-500/30 transition-all" onClick={() => endpoints.deleteScan(s.id).then(refreshScans)}>
                            <Trash2 size={14} />
                         </button>
                       )}
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Results Page ─────────────────────────────────────────────────────────────

export default function Results() {
  const location = useLocation()
  const [tab, setTab] = useState(location.state?.scanFilter ? 'findings' : 'findings')
  const [scanFilter, setScanFilter] = useState(location.state?.scanFilter ?? null)
  const [isMobile, setIsMobile] = useState(window.innerWidth < 768)

  useEffect(() => {
    const h = () => setIsMobile(window.innerWidth < 768)
    window.addEventListener('resize', h)
    return () => window.removeEventListener('resize', h)
  }, [])

  const handleViewFindings = (scan) => {
    setScanFilter({ id: scan.id, target: scan.target })
    setTab('findings')
  }

  const handleClearFilter = () => setScanFilter(null)

  return (
    <div className="flex flex-col gap-6">
      {/* Page header + tabs */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 px-2">
        <div className="flex items-center gap-3 md:gap-4">
           <div className="p-2 md:p-2.5 rounded-xl bg-red-500/10 border border-red-500/20 shadow-glow-red/5">
              <ShieldAlert size={isMobile ? 18 : 20} className="text-red-500" />
           </div>
           <div>
              <h1 className="text-lg md:text-xl font-black text-slate-100 tracking-tighter uppercase">Intelligence Vault</h1>
              <div className="flex items-center gap-2 mt-0.5 md:mt-1">
                <span className="flex items-center gap-1.5 text-[8px] md:text-[9px] font-bold text-accent-purple uppercase tracking-widest">
                  <div className="w-1 md:w-1.5 h-1 md:h-1.5 rounded-full bg-accent-purple animate-pulse" />
                  Mission Archive Synchronized
                </span>
              </div>
           </div>
        </div>

        <div className="flex p-1 bg-bg-secondary/40 rounded-2xl border border-bg-border w-fit">
          <button
            className={clsx(
              'flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all duration-300',
              tab === 'findings'
                ? 'bg-bg-elevated text-accent-primary border border-slate-700/50 shadow-glow-cyan/10'
                : 'text-slate-500 hover:text-slate-300'
            )}
            onClick={() => setTab('findings')}
          >
            <ShieldAlert size={14} />
            Findings
          </button>
          <button
            className={clsx(
              'flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all duration-300',
              tab === 'history'
                ? 'bg-bg-elevated text-accent-primary border border-slate-700/50 shadow-glow-cyan/10'
                : 'text-slate-500 hover:text-slate-300'
            )}
            onClick={() => setTab('history')}
          >
            <History size={14} />
            Scan History
          </button>
        </div>
      </div>

      <div className="animate-in fade-in slide-in-from-bottom-2 duration-500">
        {tab === 'findings'
          ? <FindingsTab key={scanFilter?.id ?? 'all'} scanFilter={scanFilter} onClearFilter={handleClearFilter} isMobile={isMobile} />
          : <ScanHistoryTab onViewFindings={handleViewFindings} isMobile={isMobile} />
        }
      </div>
    </div>
  )
}
