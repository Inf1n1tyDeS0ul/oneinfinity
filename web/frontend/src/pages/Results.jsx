import React, { useState } from 'react'
import {
  ShieldAlert, History, StopCircle, RefreshCw
} from 'lucide-react'
import { useStore } from '../store/useStore'
import { endpoints } from '../utils/api'
import clsx from 'clsx'
import { DataTable } from '../components/ui/DataTable'

const COLUMNS = [
  { key: 'title',    label: 'Finding',  sortable: true },
  { key: 'severity', label: 'Severity', sortable: true,
    render: (v) => v ? <span className={`badge badge-${v}`}>{v}</span> : '—' },
  { key: 'target',   label: 'Target',   sortable: true },
  { key: 'status',   label: 'Status',   sortable: true },
  { key: 'created_at', label: 'Found',  sortable: true,
    render: (v) => v ? new Date(v).toLocaleDateString() : '—' },
]

function relativeTime(iso) {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

// ─── Findings Tab ────────────────────────────────────────────────────────────

function FindingsTab() {
  const { vulnerabilities, setVulnerabilities, addNotification } = useStore()
  const [loading, setLoading] = useState(false)

  const total = vulnerabilities.length
  const critical = vulnerabilities.filter(v => v.severity === 'critical').length
  const high = vulnerabilities.filter(v => v.severity === 'high').length
  const confirmed = vulnerabilities.filter(v => v.status === 'confirmed').length

  const handleRefresh = () => {
    setLoading(true)
    endpoints.vulnerabilities()
      .then(r => { setVulnerabilities(r.data); setLoading(false) })
      .catch(e => { addNotification(`Refresh failed: ${e.message}`, 'error'); setLoading(false) })
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Stats cards */}
      <div className="grid grid-cols-4 gap-3">
        <div className="stat-card">
          <div className="stat-label">Total Findings</div>
          <div className="stat-value">{total}</div>
        </div>
        <div className="stat-card glow-red">
          <div className="stat-label">Critical</div>
          <div className="stat-value text-red-400">{critical}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">High</div>
          <div className="stat-value text-orange-400">{high}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Confirmed</div>
          <div className="stat-value text-emerald-400">{confirmed}</div>
        </div>
      </div>

      <div className="flex justify-end">
        <button className="btn-secondary flex items-center gap-1.5" onClick={handleRefresh}>
          <RefreshCw size={11} />
          Refresh
        </button>
      </div>

      <DataTable
        columns={COLUMNS}
        data={vulnerabilities}
        searchable
        loading={loading}
        emptyMessage="No findings yet"
        emptyAction={<p className="empty-sub mt-1">Run a scan to discover vulnerabilities</p>}
      />
    </div>
  )
}

// ─── Scan History Tab ─────────────────────────────────────────────────────────

function ScanHistoryTab() {
  const { scans } = useStore()
  const { addNotification, setScans } = useStore()

  const handleStop = async (id) => {
    try {
      await endpoints.stopScan(id)
      addNotification('Scan stopped', 'success')
      endpoints.scans().then(r => setScans(r.data)).catch(e => addNotification(`Could not refresh scans: ${e.message}`, 'error'))
    } catch (e) {
      addNotification(`Error: ${e.message}`, 'error')
    }
  }

  return (
    <div className="card overflow-hidden">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-bg-border text-slate-500 text-left">
            <th className="px-3 py-2 font-medium">Target</th>
            <th className="px-3 py-2 font-medium">Type</th>
            <th className="px-3 py-2 font-medium">Status</th>
            <th className="px-3 py-2 font-medium">Started</th>
            <th className="px-3 py-2 font-medium">Completed</th>
            <th className="px-3 py-2 font-medium">Findings</th>
            <th className="px-3 py-2 font-medium">Progress</th>
            <th className="px-3 py-2 font-medium" />
          </tr>
        </thead>
        <tbody className="divide-y divide-bg-border">
          {scans.length === 0 && (
            <tr>
              <td colSpan={8} className="px-3 py-8 text-center text-slate-500">
                No scan history yet.
              </td>
            </tr>
          )}
          {scans.map(s => (
            <tr key={s.id} className="hover:bg-white/3 transition-colors">
              <td className="px-3 py-2.5 text-slate-200 max-w-[160px] truncate">{s.target}</td>
              <td className="px-3 py-2.5 text-slate-400">{s.scan_type || s.type || '—'}</td>
              <td className="px-3 py-2.5">
                <span className={`badge-${s.status}`}>{s.status}</span>
              </td>
              <td className="px-3 py-2.5 text-slate-500">{relativeTime(s.started_at)}</td>
              <td className="px-3 py-2.5 text-slate-500">
                {s.completed_at ? relativeTime(s.completed_at) : '—'}
              </td>
              <td className="px-3 py-2.5 text-slate-400">{s.findings_count ?? s.findings ?? 0}</td>
              <td className="px-3 py-2.5 w-28">
                {s.status === 'running' ? (
                  <div className="w-full h-1.5 bg-bg-border rounded overflow-hidden">
                    <div
                      className="h-full bg-accent-primary rounded transition-all"
                      style={{ width: `${s.progress ?? 0}%` }}
                    />
                  </div>
                ) : (
                  <span className="text-slate-600">—</span>
                )}
              </td>
              <td className="px-3 py-2.5">
                {s.status === 'running' && (
                  <button
                    className="btn-danger flex items-center gap-1 text-[11px] py-0.5 px-2"
                    onClick={() => handleStop(s.id)}
                  >
                    <StopCircle size={10} />
                    Stop
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─── Results Page ─────────────────────────────────────────────────────────────

export default function Results() {
  const [tab, setTab] = useState('findings')

  return (
    <div className="flex flex-col gap-4">
      {/* Page header + tabs */}
      <div className="flex items-center gap-4">
        <h1 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <ShieldAlert size={15} className="text-red-400" />
          Results
        </h1>
        <div className="flex items-center gap-1 bg-bg-secondary border border-bg-border rounded p-0.5">
          <button
            className={clsx(
              'flex items-center gap-1.5 px-3 py-1 rounded text-xs transition-colors',
              tab === 'findings'
                ? 'bg-accent-primary/20 text-accent-primary'
                : 'text-slate-400 hover:text-slate-200'
            )}
            onClick={() => setTab('findings')}
          >
            <ShieldAlert size={11} />
            Findings
          </button>
          <button
            className={clsx(
              'flex items-center gap-1.5 px-3 py-1 rounded text-xs transition-colors',
              tab === 'history'
                ? 'bg-accent-primary/20 text-accent-primary'
                : 'text-slate-400 hover:text-slate-200'
            )}
            onClick={() => setTab('history')}
          >
            <History size={11} />
            Scan History
          </button>
        </div>
      </div>

      {tab === 'findings' ? <FindingsTab /> : <ScanHistoryTab />}
    </div>
  )
}
