import React, { useState, useEffect } from 'react'
import { FileText, Play, Download, RefreshCw, Eye, Plus, RotateCcw, FileDown, CheckSquare, Square } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

export default function Reports() {
  const { addNotification } = useStore()
  const [tab, setTab] = useState('generate')
  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(false)
  const [findingId, setFindingId] = useState('')
  const [platform, setPlatform] = useState('hackerone')
  const [format, setFormat] = useState('html')
  const [generating, setGenerating] = useState(false)
  const [result, setResult] = useState(null)
  const [replayFile, setReplayFile] = useState('')
  const [replayRun, setReplayRun] = useState(false)
  const [replayResult, setReplayResult] = useState(null)
  const navigate = useNavigate()
  const [publishScans, setPublishScans] = useState([])
  const [publishScanId, setPublishScanId] = useState('')
  const [publishSections, setPublishSections] = useState(
    ['exec', 'findings', 'chains', 'meta', 'remediation']
  )
  const [publishLoading, setPublishLoading] = useState(false)

  const loadReports = async () => {
    setLoading(true)
    try {
      const r = await endpoints.reports()
      setReports(r.data?.reports || r.data || [])
    } catch (e) { setReports([]) }
    finally { setLoading(false) }
  }

  const loadPublishScans = async () => {
    try {
      const [scansRes, gmRes] = await Promise.allSettled([
        endpoints.scans(),
        endpoints.godModeSessions(),
      ])
      const regular = (scansRes.status === 'fulfilled' ? scansRes.value.data : []) || []
      const gmSessions = (gmRes.status === 'fulfilled' ? gmRes.value.data?.sessions : []) || []
      const allScans = [
        ...gmSessions.map(s => ({
          id: s.scan_id,
          label: `[GOD MODE] ${s.target || s.scan_id} — ${s.status || 'unknown'} (${s.finding_count ?? 0} findings)`,
        })),
        ...regular.map(s => ({
          id: s.id,
          label: `[SCAN] ${s.target || s.id} — ${s.status || 'unknown'} (${s.findings_count ?? 0} findings)`,
        })),
      ]
      setPublishScans(allScans)
    } catch (e) {
      setPublishScans([])
    }
  }

  const toggleSection = (key) => {
    setPublishSections(prev =>
      prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]
    )
  }

  const handlePublish = () => {
    if (!publishScanId) return
    const params = new URLSearchParams({ sections: publishSections.join(',') })
    navigate(`/report-preview/${publishScanId}?${params}`)
  }

  useEffect(() => {
    loadReports()
    loadPublishScans()
  }, [])

  const handleGenerate = async () => {
    setGenerating(true)
    setResult(null)
    try {
      const r = findingId
        ? await endpoints.generateReport(findingId)
        : await endpoints.launchScan({ scan_type: 'report', platform, format })
      setResult(r.data)
      addNotification('Report generated', 'success')
    } catch (e) {
      addNotification('Error: ' + e.message, 'error')
    } finally { setGenerating(false) }
  }

  const handleReplay = async () => {
    if (!replayFile.trim()) return
    try {
      const r = await endpoints.launchScan({ scan_type: 'replay', findings_file: replayFile, run: replayRun })
      setReplayResult(r.data)
      addNotification('Replay ' + (replayRun ? 'executed' : 'generated'), 'success')
    } catch (e) {
      addNotification('Error: ' + e.message, 'error')
    }
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="section-header">
        <div>
          <div className="section-title flex items-center gap-2">
            <FileText size={18} className="text-blue-400" />
            Reports
          </div>
          <div className="section-sub">Generate, export, and replay bug bounty reports</div>
        </div>
        <button className="btn-secondary" onClick={loadReports}>
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      <div className="tab-bar">
        {[
          { id: 'generate', label: 'Generate Report' },
          { id: 'list', label: 'Saved Reports' },
          { id: 'replay', label: 'Replay Findings' },
          { id: 'publish', label: 'Publish Report' },
        ].map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} className={tab === t.id ? 'tab-active' : 'tab'}>{t.label}</button>
        ))}
      </div>

      {tab === 'generate' && (
        <div className="card max-w-xl">
          <div className="card-header"><span className="card-title"><Plus size={14} className="text-blue-400" />Generate Report</span></div>
          <div className="card-body flex flex-col gap-4">
            <div>
              <label className="label">Finding ID <span className="text-slate-600">(leave empty for batch — all findings)</span></label>
              <input className="input" placeholder="finding_id or blank for all" value={findingId} onChange={e => setFindingId(e.target.value)} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label">Platform</label>
                <select className="select" value={platform} onChange={e => setPlatform(e.target.value)}>
                  {['hackerone','bugcrowd','intigriti','yeswehack','generic'].map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
              <div>
                <label className="label">Format</label>
                <select className="select" value={format} onChange={e => setFormat(e.target.value)}>
                  {['html','markdown','json','pdf'].map(f => <option key={f} value={f}>{f}</option>)}
                </select>
              </div>
            </div>
            <button className="btn-primary btn-lg justify-center" onClick={handleGenerate} disabled={generating}>
              <Play size={14} />{generating ? 'Generating...' : 'Generate Report'}
            </button>
            {result && (
              <div className="terminal mt-2">
                <pre className="text-xs">{JSON.stringify(result, null, 2)}</pre>
              </div>
            )}
          </div>
        </div>
      )}

      {tab === 'list' && (
        <div className="card">
          <div className="card-header"><span className="card-title">Saved Reports</span></div>
          {reports.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon"><FileText size={20} /></div>
              <div className="empty-title">No reports yet</div>
              <div className="empty-sub">Generate reports from the Generate tab or run scans with --report flag</div>
            </div>
          ) : (
            <table className="data-table">
              <thead><tr><th>Report</th><th>Target</th><th>Platform</th><th>Format</th><th>Created</th><th>Actions</th></tr></thead>
              <tbody>
                {reports.map((r, i) => (
                  <tr key={i}>
                    <td className="text-sm text-slate-200 font-medium">{r.name || r.id}</td>
                    <td className="text-xs text-slate-400">{r.target || '—'}</td>
                    <td><span className="badge badge-info">{r.platform || '—'}</span></td>
                    <td className="text-xs text-slate-400">{r.format || '—'}</td>
                    <td className="text-xs text-slate-500">{r.created_at ? new Date(r.created_at).toLocaleDateString() : '—'}</td>
                    <td>
                      <div className="flex items-center gap-1.5">
                        <button className="btn-ghost btn-sm"><Eye size={11} />View</button>
                        <button className="btn-ghost btn-sm"><Download size={11} />Download</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'replay' && (
        <div className="card max-w-xl">
          <div className="card-header"><span className="card-title"><RotateCcw size={14} className="text-orange-400" />Replay Findings</span></div>
          <div className="card-body flex flex-col gap-4">
            <div>
              <label className="label">Findings File Path</label>
              <input className="input font-mono text-xs" placeholder="~/.oneinfinity/raw/target/findings/unified_findings.json" value={replayFile} onChange={e => setReplayFile(e.target.value)} />
            </div>
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={replayRun} onChange={e => setReplayRun(e.target.checked)} className="rounded border-bg-border bg-bg-secondary" />
              <span className="text-sm text-slate-300">Execute commands (not just generate)</span>
            </label>
            <button className="btn-primary justify-center" onClick={handleReplay} disabled={!replayFile.trim()}>
              <RotateCcw size={13} />{replayRun ? 'Execute Replay' : 'Generate Replay Plan'}
            </button>
            {replayResult && (
              <div className="terminal mt-2">
                <pre className="text-xs">{JSON.stringify(replayResult, null, 2)}</pre>
              </div>
            )}
          </div>
        </div>
      )}
      {tab === 'publish' && (
        <div className="card max-w-xl flex flex-col gap-5">
          <div className="flex flex-col gap-1">
            <label className="text-xs text-gray-400 font-medium uppercase tracking-wide">Select Scan</label>
            <select
              className="input"
              value={publishScanId}
              onChange={e => setPublishScanId(e.target.value)}
            >
              <option value="">— choose a scan —</option>
              {publishScans.map(s => (
                <option key={s.id} value={s.id}>{s.label}</option>
              ))}
            </select>
          </div>

          <div className="flex flex-col gap-2">
            <label className="text-xs text-gray-400 font-medium uppercase tracking-wide">Report Sections</label>
            {[
              { key: 'exec',        label: 'Executive Summary' },
              { key: 'findings',    label: 'Findings Detail' },
              { key: 'chains',      label: 'Attack Chains' },
              { key: 'meta',        label: 'Scan Metadata' },
              { key: 'remediation', label: 'Remediation Summary' },
            ].map(({ key, label }) => (
              <button
                key={key}
                onClick={() => toggleSection(key)}
                className="flex items-center gap-2 text-sm text-gray-300 hover:text-white transition-colors text-left"
              >
                {publishSections.includes(key)
                  ? <CheckSquare size={15} className="text-blue-400 shrink-0" />
                  : <Square size={15} className="text-gray-600 shrink-0" />
                }
                {label}
              </button>
            ))}
          </div>

          <button
            className="btn-primary flex items-center gap-2"
            onClick={handlePublish}
            disabled={!publishScanId || publishLoading}
          >
            <FileDown size={14} />
            {publishLoading ? 'Preparing…' : 'Publish Report'}
          </button>
        </div>
      )}
    </div>
  )
}
