import React, { useState, useEffect } from 'react'
import { Terminal, RefreshCw, Flag, Play, Download, ChevronDown, ChevronUp } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

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

const METHOD_COLORS = {
  GET: 'text-cyan-400', POST: 'text-green-400', PUT: 'text-yellow-400',
  PATCH: 'text-orange-400', DELETE: 'text-red-400',
}

export default function TrafficExplorer() {
  const { addNotification } = useStore()
  const [traffic, setTraffic] = useState([])
  const [stats, setStats] = useState({})
  const [loading, setLoading] = useState(false)
  const [expanded, setExpanded] = useState(null)
  const [methodFilter, setMethodFilter] = useState('')
  const [hostSearch, setHostSearch] = useState('')
  const [statusMin, setStatusMin] = useState('')
  const [statusMax, setStatusMax] = useState('')
  const [lastUpdated, setLastUpdated] = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const params = {}
      if (methodFilter) params.method = methodFilter
      if (hostSearch) params.host = hostSearch
      if (statusMin) params.status_min = statusMin
      if (statusMax) params.status_max = statusMax
      const [tRes, sRes] = await Promise.allSettled([
        endpoints.traffic(params),
        endpoints.trafficStats(),
      ])
      if (tRes.status === 'fulfilled') setTraffic(tRes.value.data?.requests || tRes.value.data || [])
      if (sRes.status === 'fulfilled') setStats(sRes.value.data || {})
      setLastUpdated(new Date().toLocaleTimeString())
    } catch (e) {
      addNotification(`Traffic load failed: ${e.message}`, 'error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const handleReplay = async (id) => {
    try {
      await endpoints.replayTraffic(id, {})
      addNotification('Request replayed', 'success')
    } catch (e) {
      addNotification(`Replay failed: ${e.message}`, 'error')
    }
  }

  const handleFlag = async (id) => {
    try {
      await endpoints.flagTraffic(id, 'manual')
      addNotification('Request flagged', 'success')
      load()
    } catch (e) {
      addNotification(`Flag failed: ${e.message}`, 'error')
    }
  }

  const handleExport = async (fmt) => {
    try {
      const r = await endpoints.exportTraffic(fmt, {})
      const blob = new Blob([typeof r.data === 'string' ? r.data : JSON.stringify(r.data, null, 2)])
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = `traffic.${fmt}`; a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      addNotification(`Export failed: ${e.message}`, 'error')
    }
  }

  const statusColor = (s) => {
    if (!s) return 'text-slate-400'
    if (s < 300) return 'text-green-400'
    if (s < 400) return 'text-yellow-400'
    if (s < 500) return 'text-orange-400'
    return 'text-red-400'
  }

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
        <Terminal size={14} className="text-accent-primary" />
        Traffic Explorer
      </h1>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        <div className="stat-card">
          <div className="stat-label">Total Requests</div>
          <div className="stat-value">{stats.total ?? traffic.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Flagged</div>
          <div className="stat-value text-red-400">{stats.flagged ?? 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Unique Hosts</div>
          <div className="stat-value">{stats.unique_hosts ?? 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Avg Response Time</div>
          <div className="stat-value">{stats.avg_response_time ? `${stats.avg_response_time}ms` : '—'}</div>
        </div>
      </div>

      {/* Filter row */}
      <div className="card flex items-center gap-3 flex-wrap">
        <select className="select w-28" value={methodFilter} onChange={e => setMethodFilter(e.target.value)}>
          <option value="">All Methods</option>
          {['GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD'].map(m => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>
        <input className="input w-32" placeholder="Status min" type="number"
          value={statusMin} onChange={e => setStatusMin(e.target.value)} />
        <input className="input w-32" placeholder="Status max" type="number"
          value={statusMax} onChange={e => setStatusMax(e.target.value)} />
        <input className="input flex-1 min-w-48" placeholder="Search host..."
          value={hostSearch} onChange={e => setHostSearch(e.target.value)} />
        <button className="btn-primary flex items-center gap-1.5" onClick={load} disabled={loading}>
          <RefreshCw size={12} className={clsx(loading && 'animate-spin')} /> Filter
        </button>
        {lastUpdated && <span className="text-[10px] text-slate-500 whitespace-nowrap">Last updated: {lastUpdated}</span>}
        <div className="ml-auto flex items-center gap-2">
          {['json','csv','har'].map(fmt => (
            <button key={fmt} className="btn-secondary text-xs uppercase" onClick={() => handleExport(fmt)}>
              <Download size={11} className="inline mr-1" />{fmt}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="card overflow-auto">
        {traffic.length === 0 ? (
          <div className="text-xs text-slate-500 p-8 text-center">{loading ? 'Loading traffic...' : 'No traffic captured yet. Configure the proxy to intercept requests.'}</div>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="text-slate-500 border-b border-bg-border">
                <th className="text-left py-2 px-3 w-16">Method</th>
                <th className="text-left py-2 px-3">URL</th>
                <th className="text-left py-2 px-3 w-16">Status</th>
                <th className="text-left py-2 px-3 w-16">Size</th>
                <th className="text-left py-2 px-3 w-28">Content-Type</th>
                <th className="text-left py-2 px-3 w-20">Time</th>
                <th className="text-left py-2 px-3 w-20">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bg-border">
              {traffic.map((req) => {
                const isExploited = req.is_exploited || req.flagged;
                return (
                <React.Fragment key={req.id}>
                  <tr
                    className={clsx(
                      'cursor-pointer transition-colors',
                      isExploited ? 'bg-red-900/10 hover:bg-red-900/20 border-l-2 border-l-red-500' : 'hover:bg-white/5'
                    )}
                    onClick={() => setExpanded(expanded === req.id ? null : req.id)}
                  >
                    <td className={clsx('py-1.5 px-3 font-mono font-semibold', METHOD_COLORS[req.method] || 'text-slate-300')}>
                      {req.method}
                    </td>
                    <td className="py-1.5 px-3 font-mono text-slate-300 truncate max-w-xs">{req.url}</td>
                    <td className={clsx('py-1.5 px-3', statusColor(req.status))}>{req.status ?? '—'}</td>
                    <td className="py-1.5 px-3 text-slate-400">{req.size ? `${req.size}b` : '—'}</td>
                    <td className="py-1.5 px-3 text-slate-400 truncate max-w-xs">{req.content_type || '—'}</td>
                    <td className="py-1.5 px-3 text-slate-500">{relativeTime(req.timestamp)}</td>
                    <td className="py-1.5 px-3">
                      <div className="flex items-center gap-1" onClick={e => e.stopPropagation()}>
                        <button className="p-1 rounded hover:bg-white/10" title="Flag" onClick={() => handleFlag(req.id)}>
                          <Flag size={11} className={req.flagged ? 'text-red-400' : 'text-slate-500'} />
                        </button>
                        <button className="p-1 rounded hover:bg-white/10" title="Replay" onClick={() => handleReplay(req.id)}>
                          <Play size={11} className="text-slate-500" />
                        </button>
                        {expanded === req.id ? <ChevronUp size={11} className="text-slate-500" /> : <ChevronDown size={11} className="text-slate-500" />}
                      </div>
                    </td>
                  </tr>
                  {expanded === req.id && (
                    <tr className={clsx("bg-bg-secondary", isExploited && 'border-l-2 border-l-red-500')}>
                      <td colSpan={7} className="px-4 py-3">
                        {req.detected_waf && (
                          <div className="mb-4 bg-orange-900/20 border border-orange-500/30 p-2 rounded flex items-center justify-between">
                            <div className="flex items-center gap-3">
                              <span className="text-[10px] font-bold text-orange-400 uppercase tracking-wider">WAF Detected: {req.detected_waf}</span>
                              <span className="text-[10px] text-slate-400 italic">Strategy: {req.mutation_strategy || 'none'}</span>
                            </div>
                            <span className="text-[10px] text-slate-400">Retries: {req.retry_attempts || 0}</span>
                          </div>
                        )}
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <div className="text-slate-500 text-xs mb-1 font-semibold">REQUEST HEADERS</div>
                            <pre className="text-xs text-slate-300 font-mono bg-black/30 rounded p-2 overflow-auto max-h-32 whitespace-pre-wrap">
                              {req.request_headers ? JSON.stringify(req.request_headers, null, 2) : '—'}
                            </pre>
                            {req.request_body && (
                              <>
                                <div className="text-slate-500 text-xs mb-1 mt-2 font-semibold">REQUEST BODY</div>
                                <pre className="text-xs text-slate-300 font-mono bg-black/30 rounded p-2 overflow-auto max-h-24 whitespace-pre-wrap">{req.request_body}</pre>
                              </>
                            )}
                          </div>
                          <div>
                            <div className="text-slate-500 text-xs mb-1 font-semibold">RESPONSE HEADERS</div>
                            <pre className="text-xs text-slate-300 font-mono bg-black/30 rounded p-2 overflow-auto max-h-32 whitespace-pre-wrap">
                              {req.response_headers ? JSON.stringify(req.response_headers, null, 2) : '—'}
                            </pre>
                            {req.response_body && (
                              <>
                                <div className="text-slate-500 text-xs mb-1 mt-2 font-semibold">RESPONSE BODY</div>
                                <pre className="text-xs text-slate-300 font-mono bg-black/30 rounded p-2 overflow-auto max-h-24 whitespace-pre-wrap">{req.response_body}</pre>
                              </>
                            )}
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
