import React, { useState, useEffect } from 'react'
import {
  ShieldAlert, History, Search, ChevronDown, ChevronUp,
  CheckCircle2, XCircle, StopCircle, RefreshCw, Trash2, X, Zap
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { useStore } from '../store/useStore'
import { endpoints } from '../utils/api'
import { relativeTime } from '../utils/time'
import clsx from 'clsx'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

// ─── Findings Tab ────────────────────────────────────────────────────────────

function FindingsTab({ scanFilter, onClearFilter }) {
  const { vulnerabilities, setVulnerabilities, addNotification } = useStore()
  const [sevFilter, setSevFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [search, setSearch] = useState('')
  const [expanded, setExpanded] = useState(null)
  const [scanFindings, setScanFindings] = useState(null) // null = not loaded, [] = loaded
  const [loadingFindings, setLoadingFindings] = useState(false)

  // When a scan filter is set, fetch findings directly from the per-scan endpoint
  useEffect(() => {
    if (!scanFilter) { setScanFindings(null); return }
    setLoadingFindings(true)
    endpoints.getScanFindings(scanFilter.id)
      .then(r => setScanFindings(r.data))
      .catch(() => setScanFindings([]))
      .finally(() => setLoadingFindings(false))
  }, [scanFilter?.id])

  // When filtered: use fetched per-scan findings; otherwise use global store
  const scoped = scanFilter
    ? (scanFindings ?? [])
    : vulnerabilities

  const filtered = scoped.filter(v => {
    if (sevFilter && v.severity !== sevFilter) return false
    if (statusFilter && v.status !== statusFilter) return false
    if (search) {
      const q = search.toLowerCase()
      if (
        !v.title?.toLowerCase().includes(q) &&
        !v.target?.toLowerCase().includes(q) &&
        !v.tool?.toLowerCase().includes(q)
      ) return false
    }
    return true
  })

  const total = scoped.length
  const critical = scoped.filter(v => v.severity === 'critical').length
  const high = scoped.filter(v => v.severity === 'high').length
  const confirmed = scoped.filter(v => v.status === 'confirmed').length

  const handleStatusChange = async (id, status) => {
    try {
      const r = await endpoints.updateVuln(id, { status })
      setVulnerabilities(vulnerabilities.map(v => v.id === id ? r.data : v))
      addNotification(`Marked as ${status}`, 'success')
    } catch (e) {
      addNotification(`Error: ${e.message}`, 'error')
    }
  }

  const handleRefresh = () => {
    if (scanFilter) {
      setLoadingFindings(true)
      endpoints.getScanFindings(scanFilter.id)
        .then(r => setScanFindings(r.data))
        .catch(() => setScanFindings([]))
        .finally(() => setLoadingFindings(false))
    } else {
      endpoints.vulnerabilities()
        .then(r => setVulnerabilities(r.data))
        .catch(e => addNotification(`Refresh failed: ${e.message}`, 'error'))
    }
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Scan context banner — shown when filtered to a specific scan */}
      {scanFilter && (
        <div className="flex items-center gap-2 px-3 py-2 rounded bg-accent-primary/10 border border-accent-primary/20 text-xs">
          <ShieldAlert size={11} className="text-accent-primary flex-shrink-0" />
          <span className="text-slate-300">
            Findings for <span className="text-slate-100 font-medium">{scanFilter.target}</span>
            <span className="text-slate-500 ml-1">({scanFilter.id})</span>
            {loadingFindings && <span className="text-slate-500 ml-2">Loading…</span>}
          </span>
          <button
            className="ml-auto flex items-center gap-1 text-slate-400 hover:text-slate-200 transition-colors"
            onClick={onClearFilter}
          >
            <X size={11} />
            All Scans
          </button>
        </div>
      )}

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

      {/* Filter bar */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1 max-w-xs">
          <Search size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            className="input pl-7 w-full"
            placeholder="Search title, target, tool..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <select className="select w-32" value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
          <option value="">All Severity</option>
          {SEV_ORDER.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="select w-36" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">All Status</option>
          {['new', 'confirmed', 'false_positive'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <button className="btn-secondary flex items-center gap-1.5 ml-auto" onClick={handleRefresh}>
          <RefreshCw size={11} />
          Refresh
        </button>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-bg-border text-slate-500 text-left">
              <th className="px-3 py-2 font-medium">Severity</th>
              <th className="px-3 py-2 font-medium">Title</th>
              <th className="px-3 py-2 font-medium">Target</th>
              <th className="px-3 py-2 font-medium">Tool</th>
              <th className="px-3 py-2 font-medium">Confidence</th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th className="px-3 py-2 font-medium">Found</th>
              <th className="px-3 py-2 w-6" />
            </tr>
          </thead>
          <tbody className="divide-y divide-bg-border">
            {filtered.length === 0 && (
              <tr>
                <td colSpan={8} className="px-3 py-8 text-center text-slate-500">
                  No findings match the current filters.
                </td>
              </tr>
            )}
            {filtered.map(v => (
              <React.Fragment key={v.id}>
                <tr
                  className={clsx(
                    'cursor-pointer hover:bg-white/3 transition-colors',
                    expanded === v.id && 'bg-accent-primary/5'
                  )}
                  onClick={() => setExpanded(expanded === v.id ? null : v.id)}
                >
                  <td className="px-3 py-2.5">
                    <span className={`badge-${v.severity}`}>{v.severity}</span>
                  </td>
                  <td className="px-3 py-2.5 max-w-xs">
                    <span className="text-slate-200 truncate block">{v.title}</span>
                  </td>
                  <td className="px-3 py-2.5 text-slate-400 max-w-[140px] truncate">{v.target}</td>
                  <td className="px-3 py-2.5 text-slate-400">{v.tool || '—'}</td>
                  <td className="px-3 py-2.5 text-slate-400">
                    {v.confidence != null ? `${(v.confidence * 100).toFixed(0)}%` : '—'}
                  </td>
                  <td className="px-3 py-2.5">
                    <span className={`badge-${v.status}`}>{v.status}</span>
                  </td>
                  <td className="px-3 py-2.5 text-slate-500">{relativeTime(v.created_at)}</td>
                  <td className="px-3 py-2.5 text-slate-500">
                    {expanded === v.id ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                  </td>
                </tr>

                {/* Expanded detail row */}
                {expanded === v.id && (
                  <tr className="bg-bg-secondary">
                    <td colSpan={8} className="px-4 py-3">
                      <div className="flex flex-col gap-3">
                        {v.impact_score && (
                          <div className="mb-1">
                            <span className="text-[10px] font-bold text-red-400 uppercase tracking-wider bg-red-900/30 px-2 py-0.5 rounded border border-red-500/30">
                              Impact: {v.impact_score}
                            </span>
                          </div>
                        )}
                        <div className="grid grid-cols-2 gap-3">
                          {v.request_poc && (
                            <div className="col-span-2">
                              <div className="text-[10px] text-yellow-400 uppercase tracking-wider mb-1">Proof of Concept — Request</div>
                              <pre className="text-xs text-yellow-200 font-mono whitespace-pre-wrap bg-bg-primary rounded p-2 overflow-x-auto border border-yellow-700/30">
                                {v.request_poc}
                              </pre>
                            </div>
                          )}
                          {v.evidence && (
                            <div>
                              <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Evidence</div>
                              <p className="text-xs text-slate-300 whitespace-pre-wrap">{v.evidence}</p>
                            </div>
                          )}
                          {v.payload && (
                            <div>
                              <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Payload</div>
                              <pre className="text-xs text-red-300 font-mono whitespace-pre-wrap bg-bg-primary rounded p-2 overflow-x-auto">
                                {v.payload}
                              </pre>
                            </div>
                          )}
                          {(v.how_exploited || v.why_selected) && (
                            <div>
                              <div className="text-[10px] text-blue-400 uppercase tracking-wider mb-1">How It Was Exploited</div>
                              {v.how_exploited && <p className="text-xs text-slate-300 mb-1">{v.how_exploited}</p>}
                              {v.why_selected && <p className="text-xs text-slate-400 italic"><strong className="not-italic text-slate-500">Why selected:</strong> {v.why_selected}</p>}
                            </div>
                          )}
                          {v.how_validated && (
                            <div>
                              <div className="text-[10px] text-green-400 uppercase tracking-wider mb-1">
                                How It Was Validated
                                {v.validation_status && (
                                  <span className={`ml-2 px-1.5 py-0.5 rounded text-[9px] font-bold ${v.validation_status === 'confirmed' ? 'bg-green-900/40 text-green-300' : 'bg-yellow-900/40 text-yellow-300'}`}>
                                    {v.validation_status}
                                  </span>
                                )}
                              </div>
                              <p className="text-xs text-slate-300 whitespace-pre-wrap">{v.how_validated}</p>
                            </div>
                          )}
                          {v.response_excerpt && (
                            <div className="col-span-2">
                              <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Response Excerpt</div>
                              <pre className="text-xs text-slate-400 font-mono whitespace-pre-wrap bg-bg-primary rounded p-2 overflow-x-auto max-h-32">
                                {v.response_excerpt}
                              </pre>
                            </div>
                          )}
                          {(v.data_exposed || v.attacker_gains) && (
                            <div>
                              <div className="text-[10px] text-purple-400 uppercase tracking-wider mb-1">Impact Analysis</div>
                              {v.data_exposed && <p className="text-xs text-slate-300 mb-1"><strong className="text-slate-400">Data Exposed:</strong> {v.data_exposed}</p>}
                              {v.attacker_gains && <p className="text-xs text-slate-300"><strong className="text-slate-400">Attacker Gains:</strong> {v.attacker_gains}</p>}
                            </div>
                          )}
                          {v.remediation && (
                            <div>
                              <div className="text-[10px] text-emerald-500 uppercase tracking-wider mb-1">Remediation</div>
                              <p className="text-xs text-slate-300 whitespace-pre-wrap">{v.remediation}</p>
                            </div>
                          )}
                          {v.suggested_fix && (
                            <div>
                              <div className="text-[10px] text-emerald-400 uppercase tracking-wider mb-1">Suggested Fix (Patch)</div>
                              <pre className="text-xs text-emerald-300 font-mono whitespace-pre-wrap bg-bg-primary rounded p-2 overflow-x-auto">
                                {v.suggested_fix}
                              </pre>
                            </div>
                          )}
                          {v.reproduction_steps && (
                            <div className="col-span-2">
                              <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Reproduction Steps</div>
                              <pre className="text-xs text-slate-300 font-mono whitespace-pre-wrap">{v.reproduction_steps}</pre>
                            </div>
                          )}
                        </div>
                        <div className="flex items-center gap-2 pt-1 border-t border-bg-border">
                          <button
                            className="btn-primary flex items-center gap-1.5"
                            onClick={() => handleStatusChange(v.id, 'confirmed')}
                          >
                            <CheckCircle2 size={11} />
                            Confirm
                          </button>
                          <button
                            className="btn-secondary flex items-center gap-1.5"
                            onClick={() => handleStatusChange(v.id, 'false_positive')}
                          >
                            <XCircle size={11} />
                            False Positive
                          </button>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Scan History Tab ─────────────────────────────────────────────────────────

function ScanHistoryTab({ onViewFindings }) {
  const { scans, addNotification, setScans } = useStore()
  const [selected, setSelected] = useState(new Set())
  const [deleting, setDeleting] = useState(false)

  const allIds = scans.map(s => s.id)
  const allSelected = allIds.length > 0 && allIds.every(id => selected.has(id))

  const toggleAll = () => {
    setSelected(allSelected ? new Set() : new Set(allIds))
  }

  const toggleOne = (id) => {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

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
    <div className="card overflow-hidden">
      {/* Bulk action toolbar — visible only when rows are selected */}
      {selected.size > 0 && (
        <div className="flex items-center gap-3 px-3 py-2 bg-red-500/10 border-b border-red-500/20">
          <span className="text-xs text-red-400 font-medium">
            {selected.size} selected
          </span>
          <button
            className="flex items-center gap-1.5 px-3 py-1 rounded text-xs bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors disabled:opacity-50"
            onClick={handleDeleteSelected}
            disabled={deleting}
          >
            <Trash2 size={11} />
            {deleting ? 'Deleting…' : `Delete ${selected.size}`}
          </button>
          <button
            className="text-xs text-slate-500 hover:text-slate-300 transition-colors ml-auto"
            onClick={() => setSelected(new Set())}
          >
            Clear selection
          </button>
        </div>
      )}

      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-bg-border text-slate-500 text-left">
            <th className="px-3 py-2">
              <input
                type="checkbox"
                checked={allSelected}
                onChange={toggleAll}
                className="accent-accent-primary cursor-pointer"
                title="Select all"
              />
            </th>
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
              <td colSpan={9} className="px-3 py-8 text-center text-slate-500">
                No scan history yet.
              </td>
            </tr>
          )}
          {scans.map(s => {
            const isSelected = selected.has(s.id)
            return (
              <tr
                key={s.id}
                className={clsx(
                  'transition-colors cursor-pointer',
                  isSelected ? 'bg-accent-primary/10' : 'hover:bg-white/3'
                )}
                onClick={() => toggleOne(s.id)}
              >
                <td className="px-3 py-2.5" onClick={e => e.stopPropagation()}>
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => toggleOne(s.id)}
                    className="accent-accent-primary cursor-pointer"
                  />
                </td>
                <td className="px-3 py-2.5 text-slate-200 max-w-[160px] truncate">{s.target}</td>
                <td className="px-3 py-2.5 text-slate-400">{s.scan_type || s.type || '—'}</td>
                <td className="px-3 py-2.5">
                  <span className={`badge-${s.status}`}>{s.status}</span>
                </td>
                <td className="px-3 py-2.5 text-slate-500">{relativeTime(s.started_at)}</td>
                <td className="px-3 py-2.5 text-slate-500">
                  {s.completed_at ? relativeTime(s.completed_at) : '—'}
                </td>
                <td className="px-3 py-2.5 text-slate-400">
                  <div className="flex items-center gap-2">
                    {(s.findings_count ?? s.findings ?? 0) > 0 ? (
                      <button
                        className="text-accent-primary hover:underline tabular-nums"
                        onClick={e => { e.stopPropagation(); onViewFindings(s) }}
                      >
                        {s.findings_count ?? s.findings}
                      </button>
                    ) : (
                      <span>0</span>
                    )}
                    {(s.findings_count ?? s.findings ?? 0) > 0 && (
                      <Link
                        to={`/chains/${s.id}`}
                        className="p-1 rounded hover:bg-white/10 text-slate-500 hover:text-accent-primary transition-colors"
                        onClick={e => e.stopPropagation()}
                        title="View Exploit Chain"
                      >
                        <Zap size={11} />
                      </Link>
                    )}
                  </div>
                </td>
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
                <td className="px-3 py-2.5" onClick={e => e.stopPropagation()}>
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
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// ─── Results Page ─────────────────────────────────────────────────────────────

export default function Results() {
  const [tab, setTab] = useState('findings')
  const [scanFilter, setScanFilter] = useState(null) // { id, target } | null

  const handleViewFindings = (scan) => {
    setScanFilter({ id: scan.id, target: scan.target })
    setTab('findings')
  }

  const handleClearFilter = () => setScanFilter(null)

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

      {tab === 'findings'
        ? <FindingsTab key={scanFilter?.id ?? 'all'} scanFilter={scanFilter} onClearFilter={handleClearFilter} />
        : <ScanHistoryTab onViewFindings={handleViewFindings} />
      }
    </div>
  )
}
