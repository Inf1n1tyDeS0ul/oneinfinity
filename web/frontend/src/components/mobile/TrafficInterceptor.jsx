import React, { useState, useEffect, useRef } from 'react'
import { Network, RefreshCw, Filter, Download, Search, Loader, Globe, Lock, Unlock } from 'lucide-react'
import { endpoints } from '../../utils/api'
import { useStore } from '../../store/useStore'
import { formatDateTime } from '../../utils/time'
import clsx from 'clsx'

const METHOD_COLORS = {
  GET: 'text-blue-400',
  POST: 'text-emerald-400',
  PUT: 'text-yellow-400',
  DELETE: 'text-red-400',
  PATCH: 'text-purple-400',
}

export default function TrafficInterceptor({ appId, packageName, autoRefresh = true }) {
  const { addNotification } = useStore()
  const [traffic, setTraffic] = useState([])
  const [loading, setLoading] = useState(false)
  const [selectedRequest, setSelectedRequest] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [methodFilter, setMethodFilter] = useState('ALL')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [sslOnly, setSslOnly] = useState(false)
  const pollInterval = useRef(null)

  const loadTraffic = async () => {
    if (!appId) return

    setLoading(true)
    try {
      const response = await endpoints.mobileGetTraffic(appId, 200)
      const requests = response.data.requests || []
      setTraffic(requests)
    } catch (error) {
      console.error('Failed to load traffic:', error)
      addNotification('Failed to load traffic', 'error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadTraffic()

    if (autoRefresh) {
      pollInterval.current = setInterval(loadTraffic, 3000) // Refresh every 3s
      return () => clearInterval(pollInterval.current)
    }
  }, [appId, autoRefresh])

  const handleExport = () => {
    const filtered = getFilteredTraffic()
    const data = JSON.stringify(filtered, null, 2)
    const blob = new Blob([data], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `traffic_${appId}_${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
    addNotification('Traffic exported', 'success')
  }

  const getFilteredTraffic = () => {
    return traffic.filter(req => {
      // Search filter
      if (searchQuery && !req.url.toLowerCase().includes(searchQuery.toLowerCase())) {
        return false
      }

      // Method filter
      if (methodFilter !== 'ALL' && req.method !== methodFilter) {
        return false
      }

      // Status filter
      if (statusFilter !== 'ALL') {
        const status = req.status_code
        if (statusFilter === '2xx' && (status < 200 || status >= 300)) return false
        if (statusFilter === '3xx' && (status < 300 || status >= 400)) return false
        if (statusFilter === '4xx' && (status < 400 || status >= 500)) return false
        if (statusFilter === '5xx' && (status < 500 || status >= 600)) return false
      }

      // SSL filter
      if (sslOnly && !req.url.startsWith('https://')) {
        return false
      }

      return true
    })
  }

  const filteredTraffic = getFilteredTraffic()

  const getStatusColor = (status) => {
    if (status >= 200 && status < 300) return 'text-emerald-400'
    if (status >= 300 && status < 400) return 'text-blue-400'
    if (status >= 400 && status < 500) return 'text-yellow-400'
    if (status >= 500) return 'text-red-400'
    return 'text-slate-500'
  }

  const formatBytes = (bytes) => {
    if (!bytes) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
  }

  return (
    <div className="flex flex-col gap-6 animate-in fade-in duration-500">
      {/* Header */}
      <div className="flex items-center justify-between p-5 glass-card bg-bg-secondary/30">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/20">
            <Network size={24} className="text-emerald-400" />
          </div>
          <div>
            <h2 className="text-lg font-black text-slate-100 uppercase tracking-tight">Traffic Interceptor</h2>
            <p className="text-[10px] text-slate-500 font-mono mt-1">
              {filteredTraffic.length} / {traffic.length} requests
              {autoRefresh && <span className="ml-2 text-emerald-500">● LIVE</span>}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setSslOnly(!sslOnly)}
            className={clsx(
              "px-3 py-2 rounded-lg border transition-all text-xs font-bold flex items-center gap-2",
              sslOnly
                ? "bg-emerald-500/20 border-emerald-500/30 text-emerald-400"
                : "bg-bg-primary/30 border-bg-border text-slate-500 hover:border-slate-600"
            )}
          >
            {sslOnly ? <Lock size={14} /> : <Unlock size={14} />}
            HTTPS
          </button>
          <button
            onClick={handleExport}
            disabled={filteredTraffic.length === 0}
            className="px-4 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 hover:bg-cyan-500/20 transition-all text-xs font-bold text-cyan-400 flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Download size={14} />
            Export
          </button>
          <button
            onClick={loadTraffic}
            disabled={loading}
            className="px-4 py-2 rounded-lg bg-accent-primary/10 border border-accent-primary/30 hover:bg-accent-primary/20 transition-all text-xs font-bold text-accent-primary flex items-center gap-2 disabled:opacity-50"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="grid lg:grid-cols-3 gap-4">
        {/* Search */}
        <div className="glass-card p-4">
          <label className="block text-xs font-bold text-slate-400 mb-2 uppercase tracking-wider">Search URL</label>
          <div className="relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-2 rounded-lg bg-bg-primary border border-bg-border text-slate-200 text-sm focus:outline-none focus:border-accent-primary transition-colors"
              placeholder="api.example.com"
            />
          </div>
        </div>

        {/* Method Filter */}
        <div className="glass-card p-4">
          <label className="block text-xs font-bold text-slate-400 mb-2 uppercase tracking-wider">Method</label>
          <select
            value={methodFilter}
            onChange={(e) => setMethodFilter(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-bg-primary border border-bg-border text-slate-200 text-sm focus:outline-none focus:border-accent-primary transition-colors"
          >
            <option value="ALL">All Methods</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
            <option value="PATCH">PATCH</option>
          </select>
        </div>

        {/* Status Filter */}
        <div className="glass-card p-4">
          <label className="block text-xs font-bold text-slate-400 mb-2 uppercase tracking-wider">Status</label>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-bg-primary border border-bg-border text-slate-200 text-sm focus:outline-none focus:border-accent-primary transition-colors"
          >
            <option value="ALL">All Statuses</option>
            <option value="2xx">2xx Success</option>
            <option value="3xx">3xx Redirect</option>
            <option value="4xx">4xx Client Error</option>
            <option value="5xx">5xx Server Error</option>
          </select>
        </div>
      </div>

      {/* Traffic List & Details */}
      <div className="grid lg:grid-cols-5 gap-6">
        {/* Request List */}
        <div className="lg:col-span-2 glass-card p-4 max-h-[600px] overflow-y-auto">
          <h3 className="text-xs font-black uppercase text-slate-400 mb-3 tracking-wider sticky top-0 bg-bg-secondary py-2 -my-2">
            Requests ({filteredTraffic.length})
          </h3>

          {loading && traffic.length === 0 ? (
            <div className="flex items-center justify-center py-12">
              <Loader size={24} className="animate-spin text-accent-primary" />
            </div>
          ) : filteredTraffic.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-slate-600">
              <Network size={32} className="mb-2 opacity-30" />
              <p className="text-xs">No traffic captured</p>
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              {filteredTraffic.map((req, idx) => (
                <button
                  key={req.id || idx}
                  onClick={() => setSelectedRequest(req)}
                  className={clsx(
                    "text-left p-3 rounded-lg border transition-all",
                    selectedRequest?.id === req.id
                      ? "border-accent-primary bg-accent-primary/10"
                      : "border-bg-border hover:border-slate-600 bg-bg-primary/20"
                  )}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span className={clsx("text-[10px] font-black", METHOD_COLORS[req.method] || 'text-slate-500')}>
                      {req.method}
                    </span>
                    <span className={clsx("text-[10px] font-bold", getStatusColor(req.status_code))}>
                      {req.status_code}
                    </span>
                    {req.url.startsWith('https://') && <Lock size={10} className="text-emerald-400" />}
                    <span className="ml-auto text-[9px] font-mono text-slate-600">
                      {formatBytes(req.size)}
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-400 font-mono truncate">{req.url}</p>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Request Details */}
        <div className="lg:col-span-3 glass-card p-4 max-h-[600px] overflow-y-auto">
          {selectedRequest ? (
            <div className="flex flex-col gap-4">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <span className={clsx("text-sm font-black", METHOD_COLORS[selectedRequest.method] || 'text-slate-500')}>
                    {selectedRequest.method}
                  </span>
                  <span className={clsx("text-sm font-bold", getStatusColor(selectedRequest.status_code))}>
                    {selectedRequest.status_code}
                  </span>
                  {selectedRequest.url.startsWith('https://') && (
                    <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 text-[9px] font-bold">HTTPS</span>
                  )}
                  <span className="ml-auto text-[10px] font-mono text-slate-600">
                    {selectedRequest.timestamp ? formatDateTime(new Date(selectedRequest.timestamp * 1000)) : ''}
                  </span>
                </div>
                <p className="text-xs text-slate-300 font-mono break-all">{selectedRequest.url}</p>
              </div>

              {/* Request Headers */}
              {selectedRequest.request_headers && Object.keys(selectedRequest.request_headers).length > 0 && (
                <div>
                  <h4 className="text-xs font-bold text-slate-400 mb-2 uppercase">Request Headers</h4>
                  <div className="p-3 rounded-lg bg-bg-primary border border-bg-border">
                    {Object.entries(selectedRequest.request_headers).map(([key, value]) => (
                      <div key={key} className="flex gap-2 text-[10px] font-mono mb-1">
                        <span className="text-cyan-400">{key}:</span>
                        <span className="text-slate-400 break-all">{value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Request Body */}
              {selectedRequest.request_body && (
                <div>
                  <h4 className="text-xs font-bold text-slate-400 mb-2 uppercase">Request Body</h4>
                  <pre className="p-3 rounded-lg bg-bg-primary border border-bg-border text-[10px] text-slate-400 font-mono overflow-x-auto max-h-48">
                    {selectedRequest.request_body}
                  </pre>
                </div>
              )}

              {/* Response Headers */}
              {selectedRequest.response_headers && Object.keys(selectedRequest.response_headers).length > 0 && (
                <div>
                  <h4 className="text-xs font-bold text-slate-400 mb-2 uppercase">Response Headers</h4>
                  <div className="p-3 rounded-lg bg-bg-primary border border-bg-border">
                    {Object.entries(selectedRequest.response_headers).map(([key, value]) => (
                      <div key={key} className="flex gap-2 text-[10px] font-mono mb-1">
                        <span className="text-purple-400">{key}:</span>
                        <span className="text-slate-400 break-all">{value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Response Body */}
              {selectedRequest.response_body && (
                <div>
                  <h4 className="text-xs font-bold text-slate-400 mb-2 uppercase">Response Body</h4>
                  <pre className="p-3 rounded-lg bg-bg-primary border border-bg-border text-[10px] text-slate-400 font-mono overflow-x-auto max-h-48">
                    {selectedRequest.response_body}
                  </pre>
                </div>
              )}
            </div>
          ) : (
            <div className="flex items-center justify-center h-full text-slate-600">
              <div className="text-center">
                <Globe size={48} className="mx-auto mb-3 opacity-20" />
                <p className="text-sm">Select a request to view details</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
