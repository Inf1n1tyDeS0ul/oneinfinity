import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Terminal, RefreshCw, Flag, Play, Download, ChevronDown, ChevronUp, Shield, ShieldOff, FastForward, XCircle, ChevronLeft, ChevronRight, Zap } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import { relativeTime } from '../utils/time'
import clsx from 'clsx'

const METHOD_COLORS = {
  GET: 'text-cyan-400', POST: 'text-green-400', PUT: 'text-yellow-400',
  PATCH: 'text-orange-400', DELETE: 'text-red-400',
}

export default function TrafficExplorer() {
  const navigate = useNavigate()
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
  const [replayModal, setReplayModal] = useState(null)
  const [replayData, setReplayData] = useState({})
  const [replayResult, setReplayResult] = useState(null)
  const [replayLoading, setReplayLoading] = useState(false)
  const [intercepting, setIntercepting] = useState(false)
  const [interceptedRequests, setInterceptedRequests] = useState([])
  const [activeIntercept, setActiveIntercept] = useState(null)
  const [interceptData, setInterceptData] = useState({
    method: '', url: '', headers: {}, body: ''
  })

  const handleSetActiveIntercept = (req) => {
    setActiveIntercept(req)
    setInterceptData({
      method: req.method,
      url: req.url,
      headers: req.request_headers || {},
      body: req.request_body || '',
    })
  }

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

  useEffect(() => {
    load()
    // Initial intercept check
    endpoints.proxyStatus().then(res => {
      if (res.data?.intercept?.enabled) setIntercepting(true)
    }).catch(() => {})
  }, [])

  useEffect(() => {
    let timer
    if (intercepting) {
      const poll = async () => {
        try {
          const res = await endpoints.interceptStatus()
          const reqs = res.data?.requests || res.data || []
          setInterceptedRequests(reqs)
          
          if (reqs.length > 0 && !activeIntercept) {
            handleSetActiveIntercept(reqs[0])
          }
        } catch (e) {
          console.error('Intercept poll failed', e)
        }
        timer = setTimeout(poll, 3000)
      }
      poll()
    } else {
      setInterceptedRequests([])
      setActiveIntercept(null)
    }
    return () => clearTimeout(timer)
  }, [intercepting, activeIntercept])

  const handleToggleIntercept = async () => {
    const newState = !intercepting
    try {
      await endpoints.interceptToggle(newState)
      setIntercepting(newState)
      addNotification(`Interception ${newState ? 'enabled' : 'disabled'}`, 'success')
    } catch (e) {
      addNotification(`Failed to toggle intercept: ${e.message}`, 'error')
    }
  }

  const handleForward = async () => {
    if (!activeIntercept) return
    try {
      await endpoints.interceptForward(activeIntercept.id, interceptData)
      addNotification('Request forwarded', 'success')
      const remaining = interceptedRequests.filter(r => r.id !== activeIntercept.id)
      setInterceptedRequests(remaining)
      if (remaining.length > 0) {
        handleSetActiveIntercept(remaining[0])
      } else {
        setActiveIntercept(null)
      }
      load() // Refresh list
    } catch (e) {
      addNotification(`Forward failed: ${e.message}`, 'error')
    }
  }

  const handleDrop = async () => {
    if (!activeIntercept) return
    try {
      await endpoints.interceptDrop(activeIntercept.id)
      addNotification('Request dropped', 'info')
      const remaining = interceptedRequests.filter(r => r.id !== activeIntercept.id)
      setInterceptedRequests(remaining)
      if (remaining.length > 0) {
        handleSetActiveIntercept(remaining[0])
      } else {
        setActiveIntercept(null)
      }
      load()
    } catch (e) {
      addNotification(`Drop failed: ${e.message}`, 'error')
    }
  }

  const openReplayModal = (req) => {
    setReplayModal(req)
    setReplayData({
      method: req.method,
      url: req.url,
      headers: req.request_headers || {},
      body: req.request_body || '',
    })
    setReplayResult(null)
  }

  const handleReplay = async () => {
    setReplayLoading(true)
    setReplayResult(null)
    try {
      const res = await endpoints.replayTraffic(replayModal.id, replayData)
      setReplayResult(res.data)
      addNotification('Request replayed', 'success')
      load() // Reload list to show new captured request
    } catch (e) {
      addNotification(`Replay failed: ${e.message}`, 'error')
    } finally {
      setReplayLoading(false)
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
      const url = URL.createObjectURL(r.data)
      const a = document.createElement('a')
      a.href = url
      a.download = `traffic_export.${fmt}`
      a.click()
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
        <button
          className={clsx(
            "btn flex items-center gap-1.5 text-xs",
            intercepting ? "bg-orange-600 hover:bg-orange-700 text-white" : "btn-secondary"
          )}
          onClick={handleToggleIntercept}
        >
          {intercepting ? <Shield size={12} /> : <ShieldOff size={12} />}
          {intercepting ? 'Intercept ON' : 'Intercept OFF'}
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

      {/* Intercept Pane */}
      {(intercepting || interceptedRequests.length > 0) && (
        <div className="card border-2 border-orange-500/50 bg-orange-900/5 overflow-hidden animate-in slide-in-from-top duration-300">
          <div className="flex items-center justify-between bg-orange-500/10 px-4 py-2 border-b border-orange-500/30">
            <div className="flex items-center gap-2">
              <Shield size={14} className="text-orange-400" />
              <span className="text-xs font-bold text-orange-400 uppercase tracking-wider">
                Intercepted Requests ({interceptedRequests.length})
              </span>
            </div>
            {interceptedRequests.length > 1 && (
              <div className="flex items-center gap-1">
                <button 
                  className="p-1 rounded hover:bg-orange-500/20 text-orange-400 disabled:opacity-30"
                  onClick={() => {
                    const idx = interceptedRequests.findIndex(r => r.id === activeIntercept.id)
                    if (idx > 0) handleSetActiveIntercept(interceptedRequests[idx-1])
                  }}
                  disabled={!activeIntercept || interceptedRequests.findIndex(r => r.id === activeIntercept.id) === 0}
                >
                  <ChevronLeft size={14} />
                </button>
                <span className="text-[10px] text-orange-400 font-mono">
                  {activeIntercept ? interceptedRequests.findIndex(r => r.id === activeIntercept.id) + 1 : 0} / {interceptedRequests.length}
                </span>
                <button 
                  className="p-1 rounded hover:bg-orange-500/20 text-orange-400 disabled:opacity-30"
                  onClick={() => {
                    const idx = interceptedRequests.findIndex(r => r.id === activeIntercept.id)
                    if (idx < interceptedRequests.length - 1) handleSetActiveIntercept(interceptedRequests[idx+1])
                  }}
                  disabled={!activeIntercept || interceptedRequests.findIndex(r => r.id === activeIntercept.id) === interceptedRequests.length - 1}
                >
                  <ChevronRight size={14} />
                </button>
              </div>
            )}
          </div>
          
          {activeIntercept ? (
            <div className="p-4 grid grid-cols-2 gap-4">
              <div className="space-y-3">
                <div className="grid grid-cols-[100px,1fr] gap-2">
                  <select
                    className="select text-xs border-orange-500/30 bg-orange-900/10 text-orange-200"
                    value={interceptData.method}
                    onChange={e => setInterceptData({...interceptData, method: e.target.value})}
                  >
                    {['GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD'].map(m => (
                      <option key={m} value={m}>{m}</option>
                    ))}
                  </select>
                  <input
                    className="input text-xs font-mono border-orange-500/30 bg-orange-900/10 text-orange-200"
                    value={interceptData.url}
                    onChange={e => setInterceptData({...interceptData, url: e.target.value})}
                  />
                </div>
                <div>
                  <label className="text-[10px] text-orange-400/70 mb-1 block font-bold uppercase">Headers</label>
                  <textarea
                    className="input text-xs font-mono h-32 resize-none border-orange-500/30 bg-orange-900/10 text-orange-200"
                    value={JSON.stringify(interceptData.headers, null, 2)}
                    onChange={e => {
                      try { setInterceptData({...interceptData, headers: JSON.parse(e.target.value)}) } catch {}
                    }}
                  />
                </div>
              </div>
              <div className="flex flex-col gap-3">
                <div className="flex-1 flex flex-col">
                  <label className="text-[10px] text-orange-400/70 mb-1 block font-bold uppercase">Body</label>
                  <textarea
                    className="input flex-1 text-xs font-mono resize-none border-orange-500/30 bg-orange-900/10 text-orange-200"
                    value={interceptData.body}
                    onChange={e => setInterceptData({...interceptData, body: e.target.value})}
                  />
                </div>
                <div className="flex items-center gap-2">
                  <button className="btn bg-green-600 hover:bg-green-700 text-white flex-1 flex items-center justify-center gap-2 py-2" onClick={handleForward}>
                    <FastForward size={14} /> Forward
                  </button>
                  <button className="btn bg-red-600 hover:bg-red-700 text-white flex-1 flex items-center justify-center gap-2 py-2" onClick={handleDrop}>
                    <XCircle size={14} /> Drop
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-8 text-center">
              <div className="text-xs text-orange-400/50 mb-1">Waiting for requests...</div>
              <div className="text-[10px] text-slate-500 italic">Interception is active. Incoming traffic matching scope will appear here.</div>
            </div>
          )}
        </div>
      )}

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
                        <button className="p-1 rounded hover:bg-white/10" title="Replay" onClick={() => openReplayModal(req)}>
                          <Play size={11} className="text-slate-500" />
                        </button>
                        <button className="p-1 rounded hover:bg-white/10" title="Send to Fuzzer" onClick={() => navigate(`/fuzzer/${req.id}`)}>
                          <Zap size={11} className="text-slate-500 hover:text-cyan-400" />
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

      {/* Replay Modal */}
      {replayModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => setReplayModal(null)}>
          <div className="bg-bg-primary border border-bg-border rounded-lg w-full max-w-3xl max-h-[80vh] overflow-auto m-4" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between border-b border-bg-border p-4">
              <h2 className="text-sm font-semibold text-slate-200">Replay & Modify Request</h2>
              <button onClick={() => setReplayModal(null)} className="text-slate-500 hover:text-slate-300">×</button>
            </div>
            <div className="p-4 space-y-3">
              {/* Method & URL */}
              <div className="grid grid-cols-[120px,1fr] gap-2">
                <select
                  className="select text-xs"
                  value={replayData.method}
                  onChange={e => setReplayData({...replayData, method: e.target.value})}
                >
                  {['GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD'].map(m => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
                <input
                  className="input text-xs font-mono"
                  value={replayData.url}
                  onChange={e => setReplayData({...replayData, url: e.target.value})}
                  placeholder="URL"
                />
              </div>

              {/* Headers */}
              <div>
                <label className="text-xs text-slate-500 mb-1 block font-semibold">Headers (JSON)</label>
                <textarea
                  className="input text-xs font-mono h-24 resize-none"
                  value={JSON.stringify(replayData.headers, null, 2)}
                  onChange={e => {
                    try {
                      setReplayData({...replayData, headers: JSON.parse(e.target.value)})
                    } catch {}
                  }}
                />
              </div>

              {/* Body */}
              <div>
                <label className="text-xs text-slate-500 mb-1 block font-semibold">Body</label>
                <textarea
                  className="input text-xs font-mono h-32 resize-none"
                  value={replayData.body}
                  onChange={e => setReplayData({...replayData, body: e.target.value})}
                  placeholder="Request body (JSON, form-data, etc.)"
                />
              </div>

              {/* Actions */}
              <div className="flex items-center gap-2">
                <button
                  className="btn-primary flex items-center gap-1.5 text-xs"
                  onClick={handleReplay}
                  disabled={replayLoading}
                >
                  <Play size={12} className={clsx(replayLoading && 'animate-pulse')} />
                  {replayLoading ? 'Replaying...' : 'Send Request'}
                </button>
                <button className="btn-secondary text-xs" onClick={() => setReplayModal(null)}>Cancel</button>
              </div>

              {/* Replay Result */}
              {replayResult && (
                <div className="border border-bg-border rounded p-3 space-y-2 bg-bg-secondary">
                  <div className="flex items-center gap-4">
                    <div className="text-xs">
                      <span className="text-slate-500">Status:</span>
                      <span className={clsx('ml-1 font-semibold', statusColor(replayResult.replayed_status))}>
                        {replayResult.replayed_status}
                      </span>
                      {replayResult.status_changed && (
                        <span className="ml-2 text-orange-400">⚠ Changed from {replayResult.original_status}</span>
                      )}
                    </div>
                    <div className="text-xs">
                      <span className="text-slate-500">Duration:</span>
                      <span className="ml-1 text-slate-300">{replayResult.duration_ms}ms</span>
                    </div>
                    <div className="text-xs">
                      <span className="text-slate-500">Size:</span>
                      <span className="ml-1 text-slate-300">{replayResult.replayed_body_len}B</span>
                      {replayResult.size_changed && (
                        <span className="ml-2 text-orange-400">⚠ Changed</span>
                      )}
                    </div>
                  </div>

                  {replayResult.suspicious && (
                    <div className="bg-red-900/20 border border-red-500/30 rounded px-2 py-1">
                      <span className="text-xs text-red-400 font-semibold">⚠ Suspicious Response</span>
                      {replayResult.flags && replayResult.flags.length > 0 && (
                        <span className="text-xs text-slate-400 ml-2">
                          Flags: {replayResult.flags.join(', ')}
                        </span>
                      )}
                    </div>
                  )}

                  {replayResult.reflections_found && replayResult.reflections_found.length > 0 && (
                    <div className="text-xs">
                      <span className="text-orange-400 font-semibold">Reflections:</span>
                      <span className="text-slate-300 ml-2 font-mono">{replayResult.reflections_found.join(', ')}</span>
                    </div>
                  )}

                  {replayResult.errors_found && replayResult.errors_found.length > 0 && (
                    <div className="text-xs">
                      <span className="text-red-400 font-semibold">Errors:</span>
                      <ul className="ml-4 mt-1 space-y-0.5">
                        {replayResult.errors_found.map(([msg, type], i) => (
                          <li key={i} className="text-slate-300 font-mono text-[10px]">
                            [{type}] {msg}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div>
                    <div className="text-xs text-slate-500 font-semibold mb-1">Response Body</div>
                    <pre className="text-[10px] text-slate-300 font-mono bg-black/30 rounded p-2 overflow-auto max-h-48 whitespace-pre-wrap">
                      {replayResult.response_body}
                    </pre>
                  </div>

                  {replayResult.diff && (
                    <div>
                      <div className="text-xs text-slate-500 font-semibold mb-1">Diff from Original</div>
                      <pre className="text-[10px] text-slate-300 font-mono bg-black/30 rounded p-2 overflow-auto max-h-32 whitespace-pre-wrap">
                        {replayResult.diff}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
