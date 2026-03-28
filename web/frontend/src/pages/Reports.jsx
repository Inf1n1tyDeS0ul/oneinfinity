import React, { useState, useEffect } from 'react'
import { FileText, Play, Download, RefreshCw, Eye, Plus, RotateCcw } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'
import { DataTable } from '../components/ui/DataTable'

const REPORT_COLUMNS = [
  { key: 'title',      label: 'Report',  sortable: true },
  { key: 'format',     label: 'Format',  sortable: true },
  { key: 'created_at', label: 'Created', sortable: true,
    render: (v) => v ? new Date(v).toLocaleDateString() : '—' },
]

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

  const loadReports = async () => {
    setLoading(true)
    try {
      const r = await endpoints.reports()
      setReports(r.data?.reports || r.data || [])
    } catch (e) { setReports([]) }
    finally { setLoading(false) }
  }

  useEffect(() => { loadReports() }, [])

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
        {[{ id: 'generate', label: 'Generate Report' }, { id: 'list', label: 'Saved Reports' }, { id: 'replay', label: 'Replay Findings' }].map(t => (
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
          <DataTable
            columns={REPORT_COLUMNS}
            data={reports}
            searchable
            loading={loading}
            emptyMessage="No reports yet"
            emptyAction={<div className="empty-sub mt-1">Generate reports from the Generate tab or run scans with --report flag</div>}
          />
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
    </div>
  )
}
