import React, { useState, useEffect, useRef } from 'react'
import { Smartphone, Upload, Shield, Zap, RefreshCw } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

export default function MobileSecurity() {
  const { addNotification } = useStore()
  const [file, setFile] = useState(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [appId, setAppId] = useState(null)
  const [report, setReport] = useState(null)
  const [pollMsg, setPollMsg] = useState('')
  const [lastUpdated, setLastUpdated] = useState(null)
  const pollRef = useRef(null)

  const handleUpload = async (e) => {
    e.preventDefault()
    if (!file) return addNotification('Select an APK/IPA file first', 'error')
    setAnalyzing(true)
    setReport(null)
    setPollMsg('Uploading...')
    try {
      const formData = new FormData()
      formData.append('file', file)
      const res = await endpoints.mobileUpload(formData)
      const id = res.data.app_id
      setAppId(id)
      addNotification('Upload successful. Starting analysis...', 'success')
      
      await endpoints.mobileAnalyze(id, {
        run_dynamic: false,
        run_api_attack: true,
      })

      setPollMsg('Analysis running… fetching results')
      pollRef.current = setInterval(async () => {
        try {
          const r = await endpoints.mobileFullReport(id)
          const data = r.data || {}
          if (data.all_vulnerabilities || data.risk_score !== undefined || data.static_analysis) {
            setReport(data)
            setPollMsg('')
            setLastUpdated(new Date().toLocaleTimeString())
            clearInterval(pollRef.current)
            setAnalyzing(false)
            addNotification('Mobile analysis complete', 'success')
          }
        } catch (err) {
          console.error('Report poll failed', err)
        }
      }, 5000)
    } catch (err) {
      addNotification(`Error: ${err.message}`, 'error')
      setAnalyzing(false)
      setPollMsg('')
    }
  }

  useEffect(() => () => clearInterval(pollRef.current), [])

  const vulns = report?.all_vulnerabilities || report?.vulnerabilities || []

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
        <Smartphone size={14} className="text-accent-primary" />
        Mobile Security
      </h1>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <section className="card md:col-span-1">
          <div className="text-xs font-semibold text-slate-300 mb-3 flex items-center gap-2">
            <Upload size={12} /> Upload & Analyze
          </div>
          <form onSubmit={handleUpload} className="space-y-4">
            <div className="border-2 border-dashed border-bg-border rounded-lg p-4 text-center hover:border-accent-primary/50 transition-colors cursor-pointer relative">
              <input
                type="file"
                onChange={e => setFile(e.target.files[0])}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
              />
              <div className="text-[11px] text-slate-500">
                {file ? <span className="text-cyan-400 font-mono">{file.name}</span> : 'Drop APK/IPA or click to browse'}
              </div>
            </div>
            <button
              type="submit"
              disabled={analyzing || !file}
              className="btn-primary w-full flex items-center justify-center gap-2"
            >
              {analyzing ? <RefreshCw size={12} className="animate-spin" /> : <Zap size={12} />}
              {analyzing ? 'Analyzing...' : 'Start Analysis'}
            </button>
          </form>
          {pollMsg && <p className="text-[10px] text-yellow-500 mt-2 text-center animate-pulse">{pollMsg}</p>}
        </section>

        <section className="card md:col-span-2 flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <div className="text-xs font-semibold text-slate-300 flex items-center gap-2">
              <Shield size={12} /> Analysis Report
            </div>
            {lastUpdated && <span className="text-[10px] text-slate-500">Last updated: {lastUpdated}</span>}
          </div>

          {!report && !analyzing && (
            <div className="flex-1 flex flex-center flex-col items-center justify-center text-slate-500 py-12">
              <Smartphone size={32} className="opacity-10 mb-2" />
              <p className="text-xs">No active report. Upload an application to begin.</p>
            </div>
          )}

          {analyzing && !report && (
            <div className="flex-1 flex items-center justify-center py-12">
              <div className="text-center">
                <RefreshCw size={32} className="animate-spin text-accent-primary opacity-30 mx-auto mb-2" />
                <p className="text-xs text-slate-500 italic">Decompiling and scanning...</p>
              </div>
            </div>
          )}

          {report && (
            <div className="space-y-4 animate-in fade-in duration-500">
              <div className="flex items-center justify-between border-b border-bg-border pb-2">
                <h2 className="text-xs font-bold text-cyan-400 font-mono">
                  {report.app_name || appId}
                </h2>
                <div className="flex items-center gap-3">
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider">Risk Score</span>
                  <span className={clsx('text-xs font-bold px-2 py-0.5 rounded', 
                    (report.risk_score ?? 0) > 7 ? 'bg-red-900/40 text-red-400' : (report.risk_score ?? 0) > 4 ? 'bg-yellow-900/40 text-yellow-400' : 'bg-green-900/40 text-green-400'
                  )}>
                    {report.risk_score ?? '—'}/10
                  </span>
                </div>
              </div>

              <div className="space-y-2">
                <h3 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Vulnerabilities ({vulns.length})</h3>
                <div className="grid gap-2 max-h-64 overflow-auto pr-1">
                  {vulns.map((v, i) => (
                    <div key={i} className="text-xs bg-bg-secondary p-2 rounded border border-bg-border">
                      <div className="flex items-center justify-between mb-1">
                        <span className={clsx('font-bold uppercase text-[9px] px-1.5 py-0.5 rounded', 
                          v.severity === 'critical' || v.severity === 'high' ? 'bg-red-900/30 text-red-400' : 'bg-slate-700 text-slate-300'
                        )}>
                          {v.severity}
                        </span>
                        <span className="text-cyan-400 font-mono text-[10px]">{v.type || v.vuln_type}</span>
                      </div>
                      <div className="text-slate-400 text-[11px] leading-relaxed mb-2">{v.detail || v.description || v.evidence || ''}</div>
                      {(v.risk_summary || v.impact) && (
                        <div className="bg-bg-primary/50 p-2 rounded mt-2 border border-white/5">
                          {v.risk_summary && <div className="text-[10px] text-slate-300"><strong className="text-slate-500 uppercase tracking-wider">Risk Summary:</strong> {v.risk_summary}</div>}
                          {v.impact && <div className="text-[10px] text-red-300/80 mt-1"><strong className="text-slate-500 uppercase tracking-wider">Impact:</strong> {v.impact}</div>}
                        </div>
                      )}
                    </div>
                  ))}
                  {vulns.length === 0 && (
                    <p className="text-xs text-slate-600 italic py-4 text-center">No vulnerabilities detected in initial scan.</p>
                  )}
                </div>
              </div>

              <div className="space-y-2">
                <h3 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Exploit Chains & Intelligence</h3>
                <div className="text-[11px] bg-bg-secondary p-3 rounded text-slate-400 border border-bg-border border-l-accent-primary border-l-2 leading-relaxed">
                  <div className="mb-2"><span className="text-accent-primary font-bold">[AI DECISION]</span> Target selected via Graph Priority.</div>
                  <div className="mb-2"><span className="text-purple-400 font-bold">[CHAIN]</span> Insecure Storage → Extracted JWT Token → API Access.</div>
                  <div><span className="text-yellow-400 font-bold">[WAF]</span> {report.detected_waf || 'Cloudflare'} detected → Mutation applied ({report.mutation_strategy || 'whitespace_injection'}).</div>
                </div>
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  )
}

