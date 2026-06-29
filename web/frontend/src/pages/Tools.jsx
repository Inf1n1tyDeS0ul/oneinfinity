import React, { useState, useEffect } from 'react'
import { Wrench, CheckCircle2, XCircle, RefreshCw, AlertTriangle, Activity, Clock, TrendingUp, Zap, Shield, Key, Database, Server, Github, ExternalLink, Star } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

export default function Tools() {
  const { addNotification } = useStore()
  const [tab, setTab] = useState('health')
  const [toolStatus, setToolStatus] = useState(null)
  const [metrics, setMetrics] = useState(null)
  const [health, setHealth] = useState(null)
  const [failures, setFailures] = useState(null)
  const [loading, setLoading] = useState(false)

  const loadToolStatus = async () => {
    setLoading(true)
    try {
      const r = await endpoints.toolsStatus()
      setToolStatus(r.data)
    } catch (e) {
      addNotification('Failed to load tool status: ' + e.message, 'error')
    } finally { setLoading(false) }
  }

  const loadMetrics = async () => {
    setLoading(true)
    try {
      const r = await endpoints.toolsMetrics()
      setMetrics(r.data)
    } catch (e) {
      addNotification('Failed to load metrics: ' + e.message, 'error')
    } finally { setLoading(false) }
  }

  const loadHealth = async () => {
    setLoading(true)
    try {
      const r = await endpoints.toolsHealth()
      setHealth(r.data)
    } catch (e) {
      addNotification('Failed to load health: ' + e.message, 'error')
    } finally { setLoading(false) }
  }

  const loadFailures = async () => {
    setLoading(true)
    try {
      const r = await endpoints.toolsFailures()
      setFailures(r.data)
    } catch (e) {
      addNotification('Failed to load failures: ' + e.message, 'error')
    } finally { setLoading(false) }
  }

  useEffect(() => {
    let cancelled = false

    const run = async () => {
      setLoading(true)
      try {
        if (tab === 'health') {
          const [r1, r2] = await Promise.all([endpoints.toolsStatus(), endpoints.toolsHealth()])
          if (!cancelled) { setToolStatus(r1.data); setHealth(r2.data) }
        } else if (tab === 'metrics') {
          const r = await endpoints.toolsMetrics()
          if (!cancelled) setMetrics(r.data)
        } else if (tab === 'failures') {
          const r = await endpoints.toolsFailures()
          if (!cancelled) setFailures(r.data)
        }
      } catch (e) {
        if (!cancelled) addNotification('Failed to load: ' + e.message, 'error')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    run()
    return () => { cancelled = true }
  }, [tab])

  const relativeTime = (timestamp) => {
    const seconds = Math.floor((Date.now() / 1000) - timestamp)
    if (seconds < 60) return `${seconds}s ago`
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
    return `${Math.floor(seconds / 86400)}d ago`
  }

  const getStars = (score) => {
    return Array(5).fill(0).map((_, i) => (
      <Star key={i} size={12} className={i < score ? 'text-yellow-400 fill-yellow-400' : 'text-slate-600'} />
    ))
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-yellow-900/50 to-orange-900/50 rounded-lg p-6 border border-yellow-500/30">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Wrench className="w-10 h-10 text-yellow-400" />
            <div>
              <h1 className="text-2xl font-bold">Tool Health Dashboard</h1>
              <p className="text-slate-400 mt-1">Monitor tool status, performance metrics, and service health</p>
            </div>
          </div>
          <button
            onClick={() => {
              // Clear cached data and re-trigger useEffect by forcing a tab re-mount
              setMetrics(null); setFailures(null); setHealth(null); setToolStatus(null)
              const cur = tab
              setTab('')
              requestAnimationFrame(() => setTab(cur))
            }}
            className="bg-yellow-600 hover:bg-yellow-700 rounded-lg px-4 py-2 font-semibold flex items-center gap-2"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-slate-700">
        {[
          { id: 'health', label: 'Health Monitor', icon: Activity },
          { id: 'metrics', label: 'Performance', icon: TrendingUp },
          { id: 'failures', label: 'Recent Failures', icon: AlertTriangle },
        ].map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={clsx(
              'px-4 py-2 font-medium text-sm flex items-center gap-2 border-b-2 transition-colors',
              tab === t.id
                ? 'border-yellow-500 text-yellow-400'
                : 'border-transparent text-slate-400 hover:text-slate-300'
            )}
          >
            <t.icon size={14} />
            {t.label}
          </button>
        ))}
      </div>

      {/* Health Monitor Tab */}
      {tab === 'health' && (
        <div className="space-y-6">
          {/* External Services Health */}
          <div className="bg-slate-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Server className="w-5 h-5 text-cyan-400" />
              External Services
            </h2>
            {loading && !health ? (
              <div className="text-center text-slate-500 py-8">Loading...</div>
            ) : health?.services ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {/* GitHub */}
                {health.services.github && (
                  <div className={clsx(
                    'border rounded-lg p-4',
                    health.services.github.status === 'healthy' ? 'border-green-500/30 bg-green-500/5' : 'border-red-500/30 bg-red-500/5'
                  )}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Github className="w-4 h-4 text-slate-400" />
                        <span className="font-semibold text-sm">GitHub API</span>
                      </div>
                      {health.services.github.status === 'healthy' ? (
                        <CheckCircle2 className="w-4 h-4 text-green-400" />
                      ) : (
                        <XCircle className="w-4 h-4 text-red-400" />
                      )}
                    </div>
                    {health.services.github.status === 'healthy' ? (
                      <div className="space-y-1">
                        <div className="text-xs text-slate-400">
                          {health.services.github.remaining}/{health.services.github.limit} requests remaining
                        </div>
                        <div className="w-full bg-slate-700 rounded-full h-1.5">
                          <div
                            className="bg-green-500 h-1.5 rounded-full"
                            style={{ width: `${(health.services.github.remaining / health.services.github.limit) * 100}%` }}
                          />
                        </div>
                      </div>
                    ) : (
                      <div className="text-xs text-red-400">{health.services.github.error}</div>
                    )}
                  </div>
                )}

                {/* Shodan */}
                {health.services.shodan && (
                  <div className={clsx(
                    'border rounded-lg p-4',
                    health.services.shodan.status === 'healthy' ? 'border-green-500/30 bg-green-500/5' :
                    health.services.shodan.status === 'not_configured' ? 'border-yellow-500/30 bg-yellow-500/5' :
                    'border-red-500/30 bg-red-500/5'
                  )}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Shield className="w-4 h-4 text-slate-400" />
                        <span className="font-semibold text-sm">Shodan API</span>
                      </div>
                      {health.services.shodan.status === 'healthy' ? (
                        <CheckCircle2 className="w-4 h-4 text-green-400" />
                      ) : health.services.shodan.status === 'not_configured' ? (
                        <AlertTriangle className="w-4 h-4 text-yellow-400" />
                      ) : (
                        <XCircle className="w-4 h-4 text-red-400" />
                      )}
                    </div>
                    {health.services.shodan.status === 'healthy' ? (
                      <div className="text-xs text-slate-400">
                        {health.services.shodan.query_credits} query credits
                      </div>
                    ) : health.services.shodan.status === 'not_configured' ? (
                      <a href="/settings" className="text-xs text-yellow-400 hover:underline">Configure API key</a>
                    ) : (
                      <div className="text-xs text-red-400">{health.services.shodan.error}</div>
                    )}
                  </div>
                )}

                {/* VirusTotal */}
                {health.services.virustotal && (
                  <div className={clsx(
                    'border rounded-lg p-4',
                    health.services.virustotal.status === 'configured' ? 'border-green-500/30 bg-green-500/5' : 'border-yellow-500/30 bg-yellow-500/5'
                  )}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Shield className="w-4 h-4 text-slate-400" />
                        <span className="font-semibold text-sm">VirusTotal</span>
                      </div>
                      {health.services.virustotal.status === 'configured' ? (
                        <CheckCircle2 className="w-4 h-4 text-green-400" />
                      ) : (
                        <AlertTriangle className="w-4 h-4 text-yellow-400" />
                      )}
                    </div>
                    {health.services.virustotal.status === 'configured' ? (
                      <div className="text-xs text-green-400">API key configured</div>
                    ) : (
                      <a href="/settings" className="text-xs text-yellow-400 hover:underline">Configure API key</a>
                    )}
                  </div>
                )}

                {/* Censys */}
                {health.services.censys && (
                  <div className={clsx(
                    'border rounded-lg p-4',
                    health.services.censys.status === 'configured' ? 'border-green-500/30 bg-green-500/5' : 'border-yellow-500/30 bg-yellow-500/5'
                  )}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Database className="w-4 h-4 text-slate-400" />
                        <span className="font-semibold text-sm">Censys</span>
                      </div>
                      {health.services.censys.status === 'configured' ? (
                        <CheckCircle2 className="w-4 h-4 text-green-400" />
                      ) : (
                        <AlertTriangle className="w-4 h-4 text-yellow-400" />
                      )}
                    </div>
                    {health.services.censys.status === 'configured' ? (
                      <div className="text-xs text-green-400">API credentials configured</div>
                    ) : (
                      <a href="/settings" className="text-xs text-yellow-400 hover:underline">Configure API credentials</a>
                    )}
                  </div>
                )}

                {/* MobSF */}
                {health.services.mobsf && (
                  <div className={clsx(
                    'border rounded-lg p-4',
                    health.services.mobsf.status === 'healthy' ? 'border-green-500/30 bg-green-500/5' : 'border-red-500/30 bg-red-500/5'
                  )}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Server className="w-4 h-4 text-slate-400" />
                        <span className="font-semibold text-sm">MobSF</span>
                      </div>
                      {health.services.mobsf.status === 'healthy' ? (
                        <CheckCircle2 className="w-4 h-4 text-green-400" />
                      ) : (
                        <XCircle className="w-4 h-4 text-red-400" />
                      )}
                    </div>
                    {health.services.mobsf.status === 'healthy' ? (
                      <div className="text-xs text-slate-400">
                        Response time: {(health.services.mobsf.response_time * 1000).toFixed(0)}ms
                      </div>
                    ) : (
                      <div className="text-xs text-red-400">Service offline</div>
                    )}
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center text-slate-500 py-8">No health data available</div>
            )}
          </div>

          {/* Tool Status */}
          <div className="bg-slate-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Wrench className="w-5 h-5 text-yellow-400" />
              Security Tools
              {toolStatus && (
                <span className="ml-auto text-sm text-slate-400">
                  {toolStatus.available}/{toolStatus.total} available
                </span>
              )}
            </h2>
            {loading && !toolStatus ? (
              <div className="text-center text-slate-500 py-8">Checking tools...</div>
            ) : toolStatus?.tools ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                {Object.entries(toolStatus.tools).map(([name, info]) => (
                  <div
                    key={name}
                    className={clsx(
                      'flex items-center gap-3 p-3 rounded-lg border',
                      info.available ? 'border-green-500/20 bg-green-500/5' : 'border-red-500/20 bg-red-500/5'
                    )}
                  >
                    {info.available ? (
                      <CheckCircle2 size={14} className="text-green-400 flex-shrink-0" />
                    ) : (
                      <XCircle size={14} className="text-red-400 flex-shrink-0" />
                    )}
                    <div className="min-w-0">
                      <div className="text-xs font-medium text-slate-200 truncate">{name}</div>
                      {info.version && <div className="text-[10px] text-slate-500">{info.version}</div>}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center text-slate-500 py-8">No tool data available</div>
            )}
          </div>
        </div>
      )}

      {/* Performance Metrics Tab */}
      {tab === 'metrics' && (
        <div className="bg-slate-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-cyan-400" />
            Last 30 Days Performance
          </h2>
          {loading && !metrics ? (
            <div className="text-center text-slate-500 py-8">Loading metrics...</div>
          ) : metrics?.metrics && Object.keys(metrics.metrics).length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="border-b border-slate-700">
                  <tr>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">Tool</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">Scans</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">Findings</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">Success Rate</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">Avg Duration</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">Value Score</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(metrics.metrics)
                    .sort((a, b) => b[1].value_score - a[1].value_score)
                    .map(([tool, data]) => (
                      <tr key={tool} className="border-b border-slate-700/50 hover:bg-slate-700/30">
                        <td className="py-3 px-4 font-mono text-sm text-cyan-400">{tool}</td>
                        <td className="py-3 px-4 text-sm text-slate-300">{data.scans}</td>
                        <td className="py-3 px-4 text-sm text-slate-300">{data.findings}</td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <div className="w-20 bg-slate-700 rounded-full h-1.5">
                              <div
                                className={clsx(
                                  'h-1.5 rounded-full',
                                  data.success_rate > 80 ? 'bg-green-500' :
                                  data.success_rate > 50 ? 'bg-yellow-500' : 'bg-red-500'
                                )}
                                style={{ width: `${data.success_rate}%` }}
                              />
                            </div>
                            <span className="text-xs text-slate-400">{data.success_rate}%</span>
                          </div>
                        </td>
                        <td className="py-3 px-4 text-sm text-slate-400">{data.avg_duration.toFixed(1)}s</td>
                        <td className="py-3 px-4">
                          <div className="flex gap-0.5">
                            {getStars(data.value_score)}
                          </div>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center text-slate-500 py-8">
              No metrics available yet. Run some scans to see performance data.
            </div>
          )}
        </div>
      )}

      {/* Recent Failures Tab */}
      {tab === 'failures' && (
        <div className="bg-slate-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            Last 24 Hours Failures
            {failures && (
              <span className="ml-auto text-sm text-slate-400">{failures.count} issues</span>
            )}
          </h2>
          {loading && !failures ? (
            <div className="text-center text-slate-500 py-8">Loading failures...</div>
          ) : failures?.failures && failures.failures.length > 0 ? (
            <div className="space-y-2">
              {failures.failures.map((failure, idx) => (
                <div
                  key={idx}
                  className={clsx(
                    'flex items-start gap-3 p-4 rounded-lg border',
                    failure.level === 'ERROR' ? 'border-red-500/30 bg-red-500/5' : 'border-yellow-500/30 bg-yellow-500/5'
                  )}
                >
                  {failure.level === 'ERROR' ? (
                    <XCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
                  )}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-sm text-cyan-400">{failure.tool}</span>
                      <span className="text-xs text-slate-500">{relativeTime(failure.timestamp)}</span>
                    </div>
                    <div className="text-sm text-slate-300">{failure.message}</div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center text-slate-500 py-8">
              <CheckCircle2 className="w-12 h-12 text-green-400 mx-auto mb-3" />
              <div className="text-lg font-semibold text-green-400">No failures in last 24 hours</div>
              <div className="text-sm text-slate-400 mt-1">All tools running smoothly</div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
