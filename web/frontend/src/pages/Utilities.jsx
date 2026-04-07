import React, { useState } from 'react'
import { BarChart3, Calculator, ShieldAlert, BookOpen, CheckCircle2, Play, Copy, AlertTriangle } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

const CVSS_METRICS = {
  AV: { label: 'Attack Vector', options: ['N', 'A', 'L', 'P'], labels: ['Network', 'Adjacent', 'Local', 'Physical'] },
  AC: { label: 'Attack Complexity', options: ['L', 'H'], labels: ['Low', 'High'] },
  PR: { label: 'Privileges Required', options: ['N', 'L', 'H'], labels: ['None', 'Low', 'High'] },
  UI: { label: 'User Interaction', options: ['N', 'R'], labels: ['None', 'Required'] },
  S:  { label: 'Scope', options: ['U', 'C'], labels: ['Unchanged', 'Changed'] },
  C:  { label: 'Confidentiality', options: ['N', 'L', 'H'], labels: ['None', 'Low', 'High'] },
  I:  { label: 'Integrity', options: ['N', 'L', 'H'], labels: ['None', 'Low', 'High'] },
  A:  { label: 'Availability', options: ['N', 'L', 'H'], labels: ['None', 'Low', 'High'] },
}

const METHODOLOGY_CLASSES = ['xss', 'sqli', 'nosqli', 'ssrf', 'cors', 'jwt', 'auth', 'idor']
const WAF_TYPES = ['cloudflare', 'akamai', 'imperva', 'modsecurity', 'aws_waf', 'f5', 'sucuri']
const VULN_TYPES = ['xss', 'sqli', 'ssrf', 'lfi', 'rce', 'xxe', 'ssti', 'idor', 'open_redirect']
const PAYLOAD_TYPES = ['xss', 'sqli', 'xxe', 'ssti', 'ssrf', 'lfi', 'rce', 'open_redirect']

export default function Utilities() {
  const { addNotification } = useStore()
  const [tab, setTab] = useState('cvss')
  const [cvssMetrics, setCvssMetrics] = useState({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' })
  const [cvssResult, setCvssResult] = useState(null)
  const [cvssDesc, setCvssDesc] = useState('')
  const [cvssLoading, setCvssLoading] = useState(false)
  const [dedupTitle, setDedupTitle] = useState('')
  const [dedupResult, setDedupResult] = useState(null)
  const [payloadType, setPayloadType] = useState('xss')
  const [payloads, setPayloads] = useState([])
  const [waf, setWaf] = useState('cloudflare')
  const [vulnType, setVulnType] = useState('xss')
  const [wafPayloads, setWafPayloads] = useState([])
  const [methodology, setMethodology] = useState('sqli')
  const [methResult, setMethResult] = useState(null)

  const buildVector = () => `CVSS:3.1/AV:${cvssMetrics.AV}/AC:${cvssMetrics.AC}/PR:${cvssMetrics.PR}/UI:${cvssMetrics.UI}/S:${cvssMetrics.S}/C:${cvssMetrics.C}/I:${cvssMetrics.I}/A:${cvssMetrics.A}`

  const calcCVSS = async () => {
    setCvssLoading(true)
    try {
      const r = await endpoints.utilsCvss(buildVector(), cvssDesc)
      setCvssResult(r.data)
    } catch (e) { setCvssResult({ vector: buildVector(), error: e.message }) }
    finally { setCvssLoading(false) }
  }

  const checkDedup = async () => {
    if (!dedupTitle.trim()) return
    try {
      const r = await endpoints.utilsDedup(dedupTitle.trim())
      setDedupResult(r.data)
    } catch (e) { addNotification('Error: ' + e.message, 'error') }
  }

  const loadPayloads = async () => {
    try {
      const r = await endpoints.payloadLibrary(payloadType)
      setPayloads(r.data?.payloads || [])
    } catch (e) { addNotification('Error: ' + e.message, 'error') }
  }

  const loadWafBypass = async () => {
    try {
      const r = await endpoints.utilsWafBypass(waf, vulnType)
      setWafPayloads(r.data?.payloads || [])
    } catch (e) { addNotification('Error: ' + e.message, 'error') }
  }

  const loadMethodology = async () => {
    try {
      const r = await endpoints.utilsMethodology(methodology)
      setMethResult(r.data)
    } catch (e) { addNotification('Error: ' + e.message, 'error') }
  }

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => addNotification('Copied!', 'success'))
  }

  const scoreColor = (score) => {
    if (!score) return 'text-slate-400'
    if (score >= 9) return 'text-red-400'
    if (score >= 7) return 'text-orange-400'
    if (score >= 4) return 'text-yellow-400'
    return 'text-blue-400'
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="section-header">
        <div>
          <div className="section-title flex items-center gap-2">
            <BarChart3 size={18} className="text-cyan-400" />
            Utilities
          </div>
          <div className="section-sub">CVSS calculator, payload library, WAF bypass, methodologies, dedup checker</div>
        </div>
      </div>

      <div className="tab-bar">
        {[
          { id: 'cvss', label: 'CVSS 3.1 Calculator', icon: Calculator },
          { id: 'payloads', label: 'Payload Library', icon: ShieldAlert },
          { id: 'waf', label: 'WAF Bypass', icon: AlertTriangle },
          { id: 'methodology', label: 'Methodology', icon: BookOpen },
          { id: 'dedup', label: 'Dedup Checker', icon: CheckCircle2 },
        ].map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} className={tab === t.id ? 'tab-active' : 'tab'}>
            <t.icon size={11} className="inline mr-1.5" />{t.label}
          </button>
        ))}
      </div>

      {tab === 'cvss' && (
        <div className="grid grid-cols-3 gap-4">
          <div className="col-span-2 card">
            <div className="card-header"><span className="card-title"><Calculator size={14} className="text-cyan-400" />CVSS 3.1 Metrics</span></div>
            <div className="card-body grid grid-cols-2 gap-4">
              {Object.entries(CVSS_METRICS).map(([key, m]) => (
                <div key={key}>
                  <label className="label-sm">{m.label}</label>
                  <div className="flex gap-1.5 flex-wrap">
                    {m.options.map((opt, i) => (
                      <button
                        key={opt}
                        onClick={() => setCvssMetrics(prev => ({ ...prev, [key]: opt }))}
                        className={clsx(
                          'px-2.5 py-1 rounded-lg border text-xs transition-all',
                          cvssMetrics[key] === opt
                            ? 'border-accent-primary/50 bg-accent-primary/15 text-accent-primary font-medium'
                            : 'border-bg-border text-slate-400 hover:border-slate-500'
                        )}
                      >
                        {m.labels[i]}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
              <div className="col-span-2">
                <label className="label">Describe Vulnerability <span className="text-slate-600">(optional — for heuristic scoring)</span></label>
                <input className="input" placeholder="Remote code execution via unsafe deserialization..." value={cvssDesc} onChange={e => setCvssDesc(e.target.value)} />
              </div>
              <div className="col-span-2">
                <button className="btn-primary justify-center w-full" onClick={calcCVSS} disabled={cvssLoading}>
                  <Calculator size={13} />
                  {cvssLoading ? 'Calculating...' : 'Calculate Score'}
                </button>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="card-header"><span className="card-title">Score Result</span></div>
            <div className="card-body flex flex-col items-center gap-4 py-8">
              {cvssResult ? (
                <>
                  <div className={`text-6xl font-bold font-sans tabular-nums ${scoreColor(cvssResult?.score)}`}>
                    {cvssResult?.score ?? '—'}
                  </div>
                  <div className={clsx('badge text-sm px-4 py-1.5', `badge-${cvssResult?.severity?.toLowerCase() || 'info'}`)}>
                    {cvssResult?.severity || 'Unknown'}
                  </div>
                  <div className="font-mono text-xs text-slate-500 text-center break-all">{cvssResult?.vector || buildVector()}</div>
                  <button className="btn-ghost btn-sm" onClick={() => copyToClipboard(cvssResult?.vector || buildVector())}>
                    <Copy size={11} /> Copy Vector
                  </button>
                </>
              ) : (
                <>
                  <div className="text-6xl font-bold text-slate-700 font-sans">—</div>
                  <div className="text-xs text-slate-600">Set metrics and calculate</div>
                  <div className="font-mono text-[10px] text-slate-600 text-center break-all">{buildVector()}</div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {tab === 'payloads' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title"><ShieldAlert size={14} className="text-red-400" />Payload Library</span>
            <div className="flex items-center gap-2">
              <select className="select w-36" value={payloadType} onChange={e => setPayloadType(e.target.value)}>
                {PAYLOAD_TYPES.map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
              </select>
              <button className="btn-primary" onClick={loadPayloads}><Play size={12} />Load</button>
            </div>
          </div>
          <div className="card-body">
            {payloads.length > 0 ? (
              <div className="flex flex-col gap-1">
                {payloads.map((p, i) => (
                  <div key={i} className="flex items-center gap-2 p-2 rounded-lg bg-bg-secondary border border-bg-border group hover:border-slate-500 transition-colors">
                    <code className="flex-1 font-mono text-xs text-emerald-400 truncate">{p}</code>
                    <button className="btn-icon opacity-0 group-hover:opacity-100 transition-opacity" onClick={() => copyToClipboard(p)}>
                      <Copy size={11} />
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state">
                <div className="empty-icon"><ShieldAlert size={20} /></div>
                <div className="empty-title">Select type and load payloads</div>
              </div>
            )}
          </div>
        </div>
      )}

      {tab === 'waf' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title"><AlertTriangle size={14} className="text-orange-400" />WAF Bypass Payloads</span>
            <div className="flex items-center gap-2">
              <select className="select w-36" value={waf} onChange={e => setWaf(e.target.value)}>
                {WAF_TYPES.map(w => <option key={w} value={w}>{w}</option>)}
              </select>
              <select className="select w-28" value={vulnType} onChange={e => setVulnType(e.target.value)}>
                {VULN_TYPES.map(v => <option key={v} value={v}>{v.toUpperCase()}</option>)}
              </select>
              <button className="btn-primary" onClick={loadWafBypass}><Play size={12} />Load</button>
            </div>
          </div>
          <div className="card-body">
            {wafPayloads.length > 0 ? (
              <div className="flex flex-col gap-1">
                {wafPayloads.map((p, i) => (
                  <div key={i} className="flex items-center gap-2 p-2 rounded-lg bg-bg-secondary border border-bg-border group hover:border-slate-500 transition-colors">
                    <code className="flex-1 font-mono text-xs text-yellow-400 truncate">{p}</code>
                    <button className="btn-icon opacity-0 group-hover:opacity-100" onClick={() => copyToClipboard(p)}>
                      <Copy size={11} />
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state">
                <div className="empty-icon"><AlertTriangle size={20} /></div>
                <div className="empty-title">Select WAF and vuln type, then load</div>
              </div>
            )}
          </div>
        </div>
      )}

      {tab === 'methodology' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title"><BookOpen size={14} className="text-indigo-400" />Testing Methodology</span>
            <div className="flex items-center gap-2">
              <select className="select w-36" value={methodology} onChange={e => setMethodology(e.target.value)}>
                {METHODOLOGY_CLASSES.map(m => <option key={m} value={m}>{m.toUpperCase()}</option>)}
              </select>
              <button className="btn-primary" onClick={loadMethodology}><Play size={12} />Load</button>
            </div>
          </div>
          <div className="card-body">
            {methResult ? (
              <div className="flex flex-col gap-3">
                <h3 className="text-sm font-semibold text-slate-200">{methResult?.title || methodology.toUpperCase()} Methodology</h3>
                {methResult?.wstg_ids?.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {methResult.wstg_ids.map(id => (
                      <span key={id} className="badge badge-info text-[10px] px-2 py-0.5">{id}</span>
                    ))}
                  </div>
                )}
                {methResult?.tools?.length > 0 && (
                  <div className="text-xs text-slate-500">Tools: {methResult.tools.join(', ')}</div>
                )}
                {(methResult?.steps || []).map((step, i) => (
                  <div key={i} className="flex gap-3">
                    <span className="w-6 h-6 rounded-full bg-accent-primary/15 border border-accent-primary/20 flex items-center justify-center text-xs text-accent-primary font-bold flex-shrink-0">{i + 1}</span>
                    <div className="flex-1 text-sm text-slate-300 pt-0.5">{step}</div>
                  </div>
                ))}
                {!methResult?.steps && <pre className="terminal text-xs">{JSON.stringify(methResult, null, 2)}</pre>}
              </div>
            ) : (
              <div className="empty-state">
                <div className="empty-icon"><BookOpen size={20} /></div>
                <div className="empty-title">Select vulnerability class and load methodology</div>
              </div>
            )}
          </div>
        </div>
      )}

      {tab === 'dedup' && (
        <div className="card max-w-xl">
          <div className="card-header"><span className="card-title"><CheckCircle2 size={14} className="text-emerald-400" />Duplicate Finder</span></div>
          <div className="card-body flex flex-col gap-4">
            <div>
              <label className="label">Finding Title</label>
              <input className="input" placeholder="SQL Injection in /api/users endpoint..." value={dedupTitle} onChange={e => setDedupTitle(e.target.value)} />
            </div>
            <button className="btn-primary justify-center" onClick={checkDedup} disabled={!dedupTitle.trim()}>
              <CheckCircle2 size={13} />
              Check for Duplicates
            </button>
            {dedupResult && (
              <div className={clsx('p-4 rounded-xl border', dedupResult?.is_duplicate ? 'bg-yellow-500/10 border-yellow-500/30' : 'bg-emerald-500/10 border-emerald-500/30')}>
                <div className={clsx('text-sm font-semibold mb-1', dedupResult?.is_duplicate ? 'text-yellow-400' : 'text-emerald-400')}>
                  {dedupResult?.is_duplicate ? 'Likely Duplicate' : 'Appears Unique'}
                </div>
                {dedupResult?.similar_findings?.length > 0 && (
                  <div className="text-xs text-slate-400 mt-2">Similar: {dedupResult.similar_findings.join(', ')}</div>
                )}
                <div className="text-xs text-slate-500 mt-1">Confidence: {dedupResult?.confidence ?? '—'}</div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
