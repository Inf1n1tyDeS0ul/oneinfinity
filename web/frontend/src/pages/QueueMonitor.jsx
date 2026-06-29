import React, { useState, useEffect, useCallback } from 'react'
import api from '../utils/api'

const MODULE_COLORS = {
  pending: 'bg-blue-500',
  leased: 'bg-yellow-500',
  dlq: 'bg-red-500',
}

function StatCard({ label, value, color = 'text-white' }) {
  return (
    <div className="bg-gray-800 rounded-lg p-4 flex flex-col gap-1">
      <span className="text-gray-400 text-xs uppercase tracking-wide">{label}</span>
      <span className={`text-2xl font-bold ${color}`}>{value ?? '—'}</span>
    </div>
  )
}

function QueueBar({ name, stats }) {
  const total = (stats.pending || 0) + (stats.leased || 0) + (stats.dlq || 0)
  if (total === 0) return (
    <div className="flex items-center gap-3 py-2">
      <span className="text-gray-400 w-36 text-sm truncate">{name}</span>
      <span className="text-gray-600 text-xs">empty</span>
    </div>
  )
  return (
    <div className="flex items-center gap-3 py-2">
      <span className="text-gray-300 w-36 text-sm truncate font-mono">{name}</span>
      <div className="flex-1 flex h-5 rounded overflow-hidden bg-gray-700">
        {stats.pending > 0 && (
          <div
            className="bg-blue-500 flex items-center justify-center text-xs text-white"
            style={{ width: `${(stats.pending / total) * 100}%` }}
            title={`${stats.pending} pending`}
          >
            {stats.pending}
          </div>
        )}
        {stats.leased > 0 && (
          <div
            className="bg-yellow-500 flex items-center justify-center text-xs text-gray-900"
            style={{ width: `${(stats.leased / total) * 100}%` }}
            title={`${stats.leased} leased`}
          >
            {stats.leased}
          </div>
        )}
        {stats.dlq > 0 && (
          <div
            className="bg-red-500 flex items-center justify-center text-xs text-white"
            style={{ width: `${(stats.dlq / total) * 100}%` }}
            title={`${stats.dlq} in DLQ`}
          >
            {stats.dlq}
          </div>
        )}
      </div>
      <span className="text-gray-500 text-xs w-16 text-right">{total} total</span>
    </div>
  )
}

function WorkerCard({ worker }) {
  const lastHb = parseFloat(worker.last_heartbeat || 0)
  const ageSec = lastHb ? Math.round(Date.now() / 1000 - lastHb) : null
  const isAlive = ageSec !== null && ageSec < 90
  const caps = (() => { try { return JSON.parse(worker.capabilities || '[]') } catch { return [] } })()
  return (
    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
      <div className="flex items-center justify-between mb-2">
        <span className="text-white font-mono text-sm truncate">{worker.worker_id || worker.hostname}</span>
        <span className={`text-xs px-2 py-0.5 rounded-full ${isAlive ? 'bg-green-900 text-green-300' : 'bg-gray-700 text-gray-400'}`}>
          {isAlive ? 'alive' : 'offline'}
        </span>
      </div>
      <div className="text-gray-400 text-xs mb-1">
        Load: {worker.active_tasks || 0}/{worker.concurrency || '?'} &nbsp;·&nbsp;
        {ageSec !== null ? `heartbeat ${ageSec}s ago` : 'no heartbeat'}
      </div>
      <div className="flex flex-wrap gap-1">
        {caps.map(c => (
          <span key={c} className="bg-blue-900 text-blue-300 text-xs px-2 py-0.5 rounded">{c}</span>
        ))}
      </div>
    </div>
  )
}

export default function QueueMonitor() {
  const [queueStats, setQueueStats] = useState({})
  const [workers, setWorkers] = useState({})
  const [tasks, setTasks] = useState([])
  const [dlqItems, setDlqItems] = useState([])
  const [dlqModule, setDlqModule] = useState('default')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)

  const MODULES = ['recon', 'vuln_scan', 'exploit', 'ai_security', 'mobile', 'full_pipeline', 'default']

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, statusRes, tasksRes] = await Promise.allSettled([
        api.get('/swarm/queue-stats'),
        api.get('/swarm/status'),
        api.get('/swarm/tasks'),
      ])
      if (statsRes.status === 'fulfilled') setQueueStats(statsRes.value.data.queues || {})
      if (statusRes.status === 'fulfilled') setWorkers(statusRes.value.data.workers || {})
      if (tasksRes.status === 'fulfilled') setTasks(tasksRes.value.data.tasks || [])
      setLastRefresh(new Date().toLocaleTimeString())
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  const fetchDlq = useCallback(async () => {
    try {
      const res = await api.get(`/swarm/dlq?module=${dlqModule}&limit=50`)
      setDlqItems(res.data.tasks || [])
    } catch (e) {
      setDlqItems([])
    }
  }, [dlqModule])

  useEffect(() => {
    fetchData()
    fetchDlq()
    const id = setInterval(() => { fetchData(); fetchDlq() }, 5000)
    return () => clearInterval(id)
  }, [fetchData, fetchDlq])

  const retryDlqTask = async (taskId) => {
    try {
      await api.post(`/swarm/dlq/${dlqModule}/${taskId}/retry`)
      fetchDlq()
      fetchData()
    } catch (e) {
      alert(`Retry failed: ${e.message}`)
    }
  }

  const purgeDlq = async () => {
    if (!window.confirm(`Purge all DLQ tasks for module "${dlqModule}"?`)) return
    try {
      await api.delete(`/swarm/dlq/${dlqModule}`)
      fetchDlq()
      fetchData()
    } catch (e) {
      alert(`Purge failed: ${e.message}`)
    }
  }

  // Aggregate stats
  const totalPending = Object.values(queueStats).reduce((s, q) => s + (q.pending || 0), 0)
  const totalLeased  = Object.values(queueStats).reduce((s, q) => s + (q.leased || 0), 0)
  const totalDlq     = Object.values(queueStats).reduce((s, q) => s + (q.dlq || 0), 0)
  const workerList   = Object.values(workers)

  return (
    <div className="p-6 bg-gray-900 min-h-screen text-white">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold text-white">Queue Monitor</h1>
            <p className="text-gray-400 text-sm mt-1">
              Real-time distributed task queue visibility · auto-refreshes every 5s
              {lastRefresh && <span className="ml-2 text-gray-500">· last: {lastRefresh}</span>}
            </p>
          </div>
          <button
            onClick={() => { fetchData(); fetchDlq() }}
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded text-sm"
          >
            Refresh Now
          </button>
        </div>

        {error && (
          <div className="bg-red-900/50 border border-red-700 rounded p-4 mb-6 text-red-300 text-sm">
            {error}
          </div>
        )}

        {/* Summary Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
          <StatCard label="Pending Tasks" value={totalPending} color="text-blue-400" />
          <StatCard label="Leased (Running)" value={totalLeased} color="text-yellow-400" />
          <StatCard label="Dead Letter (DLQ)" value={totalDlq} color={totalDlq > 0 ? 'text-red-400' : 'text-gray-400'} />
          <StatCard label="Active Workers" value={workerList.length} color={workerList.length > 0 ? 'text-green-400' : 'text-gray-400'} />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          {/* Queue Depth Bars */}
          <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
            <h2 className="text-lg font-semibold mb-4">Queue Depths</h2>
            <div className="flex gap-4 text-xs mb-4 text-gray-400">
              <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-blue-500 inline-block" /> Pending</span>
              <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-yellow-500 inline-block" /> Leased</span>
              <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-red-500 inline-block" /> DLQ</span>
            </div>
            {loading ? (
              <div className="text-gray-500 text-sm">Loading…</div>
            ) : (
              MODULES.map(mod => (
                <QueueBar
                  key={mod}
                  name={mod}
                  stats={queueStats[mod] || { pending: 0, leased: 0, dlq: 0 }}
                />
              ))
            )}
          </div>

          {/* Workers */}
          <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
            <h2 className="text-lg font-semibold mb-4">Workers ({workerList.length})</h2>
            {workerList.length === 0 ? (
              <div className="text-gray-500 text-sm py-4">No workers registered. Start a worker with:<br/>
                <code className="text-xs bg-gray-900 px-2 py-1 rounded mt-2 block">docker compose --profile full up worker</code>
              </div>
            ) : (
              <div className="space-y-3 max-h-72 overflow-y-auto">
                {workerList.map((w, i) => <WorkerCard key={w.worker_id || i} worker={w} />)}
              </div>
            )}
          </div>
        </div>

        {/* Active Tasks */}
        {tasks.length > 0 && (
          <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700 mb-8">
            <h2 className="text-lg font-semibold mb-4">Active / Pending Tasks ({tasks.length})</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-gray-400 border-b border-gray-700">
                    <th className="text-left pb-2">Task ID</th>
                    <th className="text-left pb-2">Module</th>
                    <th className="text-left pb-2">Target</th>
                    <th className="text-left pb-2">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {tasks.map(t => (
                    <tr key={t.task_id} className="border-b border-gray-800 hover:bg-gray-700/30">
                      <td className="py-2 font-mono text-xs text-gray-400">{(t.task_id || '').slice(0, 12)}</td>
                      <td className="py-2">
                        <span className="bg-blue-900 text-blue-300 px-2 py-0.5 rounded text-xs">{t.module}</span>
                      </td>
                      <td className="py-2 text-gray-300 text-xs truncate max-w-xs">{t.target}</td>
                      <td className="py-2">
                        <span className={`px-2 py-0.5 rounded text-xs ${
                          t.status === 'running' ? 'bg-yellow-900 text-yellow-300' :
                          t.status === 'queued'  ? 'bg-blue-900 text-blue-300' :
                          'bg-gray-700 text-gray-400'
                        }`}>{t.status}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Dead-Letter Queue */}
        <div className="bg-gray-800/50 rounded-lg p-6 border border-red-900/50">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-red-400">Dead-Letter Queue</h2>
            <div className="flex items-center gap-3">
              <select
                value={dlqModule}
                onChange={e => setDlqModule(e.target.value)}
                className="bg-gray-700 border border-gray-600 rounded px-3 py-1 text-sm text-white"
              >
                {MODULES.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
              {dlqItems.length > 0 && (
                <button
                  onClick={purgeDlq}
                  className="bg-red-700 hover:bg-red-800 text-white px-3 py-1 rounded text-sm"
                >
                  Purge All ({dlqItems.length})
                </button>
              )}
            </div>
          </div>

          {dlqItems.length === 0 ? (
            <div className="text-gray-500 text-sm py-4">No dead-letter tasks for module "{dlqModule}" — system is healthy.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-gray-400 border-b border-gray-700">
                    <th className="text-left pb-2">Task ID</th>
                    <th className="text-left pb-2">Target</th>
                    <th className="text-left pb-2">Retries</th>
                    <th className="text-left pb-2">Last Error</th>
                    <th className="text-left pb-2">DLQ Time</th>
                    <th className="text-left pb-2">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {dlqItems.map(t => (
                    <tr key={t.task_id} className="border-b border-gray-800 hover:bg-gray-700/30">
                      <td className="py-2 font-mono text-xs text-gray-400">{(t.task_id || '').slice(0, 12)}</td>
                      <td className="py-2 text-gray-300 text-xs truncate max-w-xs">{t.target}</td>
                      <td className="py-2 text-center">
                        <span className="bg-red-900 text-red-300 px-2 py-0.5 rounded text-xs">{t._retry_count || 0}</span>
                      </td>
                      <td className="py-2 text-gray-400 text-xs max-w-xs truncate">{t._last_error || '—'}</td>
                      <td className="py-2 text-gray-500 text-xs">
                        {t._dlq_at ? new Date(t._dlq_at * 1000).toLocaleString() : '—'}
                      </td>
                      <td className="py-2">
                        <button
                          onClick={() => retryDlqTask(t.task_id)}
                          className="bg-blue-700 hover:bg-blue-800 text-white text-xs px-2 py-1 rounded"
                        >
                          Retry
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
