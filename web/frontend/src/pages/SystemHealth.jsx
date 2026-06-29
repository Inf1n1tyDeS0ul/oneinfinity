import React, { useState, useEffect, useCallback } from 'react'
import api from '../utils/api'

function ScoreBadge({ score }) {
  const val = typeof score === 'number' ? score : parseFloat(score)
  const color = isNaN(val) ? 'text-gray-400'
    : val >= 9   ? 'text-green-400'
    : val >= 7   ? 'text-yellow-400'
    : 'text-red-400'
  const bg    = isNaN(val) ? 'bg-gray-700'
    : val >= 9   ? 'bg-green-900/50'
    : val >= 7   ? 'bg-yellow-900/50'
    : 'bg-red-900/50'
  return (
    <div className={`${bg} rounded-xl p-8 flex flex-col items-center border ${
      isNaN(val) ? 'border-gray-700' : val >= 9 ? 'border-green-700' : val >= 7 ? 'border-yellow-700' : 'border-red-700'
    }`}>
      <span className={`text-7xl font-black ${color}`}>{isNaN(val) ? '?' : val.toFixed(1)}</span>
      <span className="text-gray-400 text-sm mt-2">Health Score / 10</span>
      <span className={`text-sm mt-2 font-semibold ${color}`}>
        {isNaN(val) ? 'Unknown' : val >= 9 ? 'Excellent' : val >= 7 ? 'Good' : val >= 5 ? 'Degraded' : 'Critical'}
      </span>
    </div>
  )
}

function CheckRow({ check }) {
  const status = (check.status || check.result || '').toLowerCase()
  const isPass = status.includes('pass') || status.includes('ok') || status === 'true'
  const isWarn = status.includes('warn') || status.includes('partial')
  return (
    <tr className="border-b border-gray-800 hover:bg-gray-700/20">
      <td className="py-3 pr-4 font-medium text-white">{check.name || check.check}</td>
      <td className="py-3 pr-4">
        <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
          isPass ? 'bg-green-900 text-green-300' :
          isWarn ? 'bg-yellow-900 text-yellow-300' :
          'bg-red-900 text-red-300'
        }`}>
          {isPass ? 'PASS' : isWarn ? 'WARN' : 'FAIL'}
        </span>
      </td>
      <td className="py-3 text-gray-400 text-sm">{check.details || check.message || check.description || ''}</td>
    </tr>
  )
}

function ServiceStatus({ name, status }) {
  const ok = (status.status || '').toLowerCase() === 'ok' || status.available === true
  return (
    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
      <div className="flex items-center justify-between">
        <span className="text-white font-medium">{name}</span>
        <span className={`w-2.5 h-2.5 rounded-full ${ok ? 'bg-green-400' : 'bg-red-400'}`} />
      </div>
      {status.error && <div className="text-red-400 text-xs mt-1 truncate">{status.error}</div>}
      {status.remaining !== undefined && (
        <div className="text-gray-400 text-xs mt-1">{status.remaining} requests remaining</div>
      )}
    </div>
  )
}

export default function SystemHealth() {
  const [report, setReport]         = useState(null)
  const [toolStatus, setToolStatus] = useState(null)
  const [services, setServices]     = useState(null)
  const [loading, setLoading]       = useState(true)
  const [deepRunId, setDeepRunId]   = useState(null)
  const [deepResult, setDeepResult] = useState(null)
  const [deepRunning, setDeepRunning] = useState(false)
  const [error, setError]           = useState(null)

  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const [docRes, toolRes, svcRes] = await Promise.allSettled([
        api.get('/doctor'),
        api.get('/tools/status'),
        api.get('/tools/health'),
      ])
      if (docRes.status === 'fulfilled')  setReport(docRes.value.data)
      if (toolRes.status === 'fulfilled') setToolStatus(toolRes.value.data)
      if (svcRes.status === 'fulfilled')  setServices(svcRes.value.data?.services)
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchData() }, [fetchData])

  // Poll deep run
  useEffect(() => {
    if (!deepRunId) return
    const id = setInterval(async () => {
      try {
        const res = await api.get(`/doctor/runs/${deepRunId}`)
        if (res.data.status !== 'running') {
          setDeepResult(res.data)
          setDeepRunning(false)
          clearInterval(id)
        }
      } catch { clearInterval(id) }
    }, 3000)
    return () => clearInterval(id)
  }, [deepRunId])

  const runDeep = async () => {
    setDeepRunning(true)
    setDeepResult(null)
    try {
      const res = await api.post('/doctor/deep')
      setDeepRunId(res.data.run_id)
    } catch (e) {
      setDeepRunning(false)
      alert(`Deep analysis failed: ${e.message}`)
    }
  }

  const checks = report?.checks || report?.results || []
  const score  = report?.score

  return (
    <div className="p-6 bg-gray-900 min-h-screen text-white">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold">System Health</h1>
            <p className="text-gray-400 text-sm mt-1">
              Platform QA, tool status, and service connectivity
            </p>
          </div>
          <div className="flex gap-3">
            <button
              onClick={fetchData}
              disabled={loading}
              className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded text-sm disabled:opacity-50"
            >
              {loading ? 'Checking…' : 'Refresh'}
            </button>
            <button
              onClick={runDeep}
              disabled={deepRunning}
              className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded text-sm disabled:opacity-50"
            >
              {deepRunning ? 'Running Deep Analysis…' : 'Run Deep Analysis'}
            </button>
          </div>
        </div>

        {error && (
          <div className="bg-red-900/30 border border-red-700 rounded p-3 text-red-300 text-sm mb-6">
            {error}
          </div>
        )}

        {/* Score + Quick Checks */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          <div className="flex flex-col gap-4">
            <ScoreBadge score={score} />
            {report?.error && (
              <div className="bg-red-900/30 border border-red-700 rounded p-3 text-red-300 text-sm">
                {report.error}
              </div>
            )}
          </div>

          <div className="lg:col-span-2 bg-gray-800/50 rounded-lg p-6 border border-gray-700">
            <h2 className="text-lg font-semibold mb-4">Health Checks</h2>
            {loading ? (
              <div className="text-gray-500 text-sm">Running checks…</div>
            ) : checks.length === 0 ? (
              <div className="text-gray-500 text-sm">
                No check data available. Doctor module may not be installed.
              </div>
            ) : (
              <div className="overflow-x-auto max-h-64 overflow-y-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-gray-400 border-b border-gray-700 sticky top-0 bg-gray-800">
                      <th className="text-left pb-2">Check</th>
                      <th className="text-left pb-2 w-20">Status</th>
                      <th className="text-left pb-2">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {checks.map((c, i) => <CheckRow key={i} check={c} />)}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Deep Analysis Result */}
        {deepResult && (
          <div className={`rounded-lg p-6 border mb-8 ${
            deepResult.status === 'completed' ? 'bg-green-900/20 border-green-700' : 'bg-red-900/20 border-red-700'
          }`}>
            <h2 className="text-lg font-semibold mb-3">Deep Analysis Result</h2>
            {deepResult.error ? (
              <div className="text-red-300 text-sm">{deepResult.error}</div>
            ) : (
              <div>
                <div className="text-white mb-2">Score: <strong>{deepResult.score ?? '?'}/10</strong></div>
                <div className="text-gray-400 text-sm">{(deepResult.checks || []).length} checks run</div>
              </div>
            )}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          {/* Service Connectivity */}
          {services && (
            <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
              <h2 className="text-lg font-semibold mb-4">Service Connectivity</h2>
              <div className="space-y-3">
                {Object.entries(services).map(([name, status]) => (
                  <ServiceStatus key={name} name={name} status={status} />
                ))}
              </div>
            </div>
          )}

          {/* Tool Status */}
          {toolStatus && (
            <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
              <h2 className="text-lg font-semibold mb-2">
                Tools
                <span className="text-sm text-gray-400 font-normal ml-2">
                  {toolStatus.available}/{toolStatus.total} available
                </span>
              </h2>
              <div className="w-full bg-gray-700 rounded-full h-2 mb-4">
                <div
                  className="bg-green-500 h-2 rounded-full"
                  style={{ width: `${(toolStatus.available / Math.max(toolStatus.total, 1)) * 100}%` }}
                />
              </div>
              <div className="grid grid-cols-2 gap-2 max-h-56 overflow-y-auto">
                {Object.entries(toolStatus.tools || {}).map(([name, info]) => (
                  <div key={name} className="flex items-center gap-2 text-sm">
                    <span className={`w-2 h-2 rounded-full flex-shrink-0 ${info.available ? 'bg-green-400' : 'bg-red-400'}`} />
                    <span className={`truncate ${info.available ? 'text-gray-300' : 'text-gray-500'}`}>{name}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
