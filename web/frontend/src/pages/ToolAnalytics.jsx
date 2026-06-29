import React, { useState, useEffect } from 'react'
import api from '../utils/api'

function SuccessBar({ rate }) {
  const pct = Math.round((rate || 0) * 100)
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 bg-gray-700 rounded-full h-2">
        <div
          className={`h-2 rounded-full ${pct >= 70 ? 'bg-green-500' : pct >= 40 ? 'bg-yellow-500' : 'bg-red-500'}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs text-gray-400 w-10 text-right">{pct}%</span>
    </div>
  )
}

function ToolRow({ tool, onSelect, selected }) {
  return (
    <tr
      onClick={() => onSelect(tool)}
      className={`border-b border-gray-800 hover:bg-gray-700/30 cursor-pointer ${selected ? 'bg-blue-900/20' : ''}`}
    >
      <td className="px-4 py-3 text-white font-mono text-sm">{tool.tool_name}</td>
      <td className="px-4 py-3 text-center text-gray-300">{tool.runs_total}</td>
      <td className="px-4 py-3">
        <SuccessBar rate={tool.success_rate} />
      </td>
      <td className="px-4 py-3 text-center text-yellow-400 font-bold">{tool.findings_total}</td>
      <td className="px-4 py-3 text-center text-gray-400 text-sm">{tool.avg_findings_per_run}</td>
      <td className="px-4 py-3 text-xs text-gray-500 truncate max-w-xs">
        {(tool.vuln_types || []).slice(0, 3).map(v => v.vuln_type).join(', ')}
      </td>
    </tr>
  )
}

export default function ToolAnalytics() {
  const [analytics, setAnalytics]   = useState(null)
  const [selectedTool, setSelected] = useState(null)
  const [vulnQuery, setVulnQuery]   = useState('')
  const [bestTools, setBestTools]   = useState(null)
  const [loading, setLoading]       = useState(true)
  const [sort, setSort]             = useState('findings_total')

  useEffect(() => {
    setLoading(true)
    api.get('/tools/analytics')
      .then(r => setAnalytics(r.data))
      .finally(() => setLoading(false))
  }, [])

  const searchBest = async () => {
    if (!vulnQuery.trim()) return
    try {
      const r = await api.get(`/tools/best-for/${encodeURIComponent(vulnQuery.trim())}`)
      setBestTools(r.data)
    } catch { setBestTools(null) }
  }

  const tools = (analytics?.tools || []).slice().sort((a, b) => (b[sort] || 0) - (a[sort] || 0))
  const totalRuns = analytics?.total_runs || 0
  const totalFindings = analytics?.total_findings || 0
  const totalTools = analytics?.total_tools || 0

  return (
    <div className="p-6 bg-gray-900 min-h-screen text-white">
      <div className="max-w-6xl mx-auto">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Tool Performance Analytics</h1>
            <p className="text-gray-400 text-sm mt-1">
              Historical performance data from all executed scans
            </p>
          </div>
          <button
            onClick={() => api.get('/tools/analytics').then(r => setAnalytics(r.data))}
            className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded text-sm"
          >Refresh</button>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          <div className="bg-gray-800 rounded-lg p-5 border border-gray-700">
            <div className="text-gray-400 text-xs uppercase">Tools Tracked</div>
            <div className="text-3xl font-black text-white mt-1">{totalTools}</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-5 border border-gray-700">
            <div className="text-gray-400 text-xs uppercase">Total Runs</div>
            <div className="text-3xl font-black text-blue-400 mt-1">{totalRuns.toLocaleString()}</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-5 border border-gray-700">
            <div className="text-gray-400 text-xs uppercase">Total Findings</div>
            <div className="text-3xl font-black text-yellow-400 mt-1">{totalFindings.toLocaleString()}</div>
          </div>
        </div>

        {/* Best Tool Search */}
        <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700 mb-6">
          <div className="flex gap-3 items-center">
            <input
              value={vulnQuery}
              onChange={e => setVulnQuery(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && searchBest()}
              placeholder="Find best tool for vuln type (e.g. xss, sqli, ssrf)"
              className="flex-1 bg-gray-900 border border-gray-700 rounded px-4 py-2 text-sm text-white placeholder-gray-500 outline-none"
            />
            <button
              onClick={searchBest}
              className="bg-green-700 hover:bg-green-600 text-white px-5 py-2 rounded text-sm"
            >Find Best Tool</button>
          </div>
          {bestTools && (
            <div className="mt-4">
              <div className="text-sm text-gray-400 mb-2">Best tools for: <strong className="text-white">{bestTools.vuln_type}</strong></div>
              <div className="flex flex-wrap gap-3">
                {bestTools.best_tools.length === 0 ? (
                  <span className="text-gray-500 text-sm">No historical data — run scans first</span>
                ) : (
                  bestTools.best_tools.map((t, i) => (
                    <div key={i} className="bg-gray-700 rounded-lg px-4 py-2 text-sm">
                      <span className="text-white font-semibold">{t.tool}</span>
                      <span className="text-gray-400 ml-2">{t.findings} findings</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Tools Table */}
          <div className="lg:col-span-2">
            <div className="bg-gray-800/50 rounded-lg border border-gray-700 overflow-hidden">
              <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
                <h2 className="font-semibold text-sm">Tool Leaderboard</h2>
                <select
                  value={sort}
                  onChange={e => setSort(e.target.value)}
                  className="bg-gray-700 border border-gray-600 rounded px-3 py-1 text-xs text-white"
                >
                  <option value="findings_total">By Findings</option>
                  <option value="runs_total">By Runs</option>
                  <option value="success_rate">By Success Rate</option>
                </select>
              </div>
              {loading ? (
                <div className="p-8 text-center text-gray-500">Loading analytics…</div>
              ) : tools.length === 0 ? (
                <div className="p-8 text-center text-gray-500">
                  No tool performance data yet.
                  Run scans to accumulate analytics.
                </div>
              ) : (
                <div className="overflow-x-auto max-h-96 overflow-y-auto">
                  <table className="w-full text-sm">
                    <thead className="sticky top-0 bg-gray-800">
                      <tr className="text-gray-400 border-b border-gray-700">
                        <th className="text-left px-4 py-2">Tool</th>
                        <th className="text-center px-4 py-2">Runs</th>
                        <th className="px-4 py-2">Success</th>
                        <th className="text-center px-4 py-2">Findings</th>
                        <th className="text-center px-4 py-2">Avg/Run</th>
                        <th className="text-left px-4 py-2">Top Vuln Types</th>
                      </tr>
                    </thead>
                    <tbody>
                      {tools.map((t, i) => (
                        <ToolRow key={i} tool={t} onSelect={setSelected} selected={selectedTool?.tool_name === t.tool_name} />
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>

          {/* Tool Detail */}
          <div>
            {selectedTool ? (
              <div className="bg-gray-800/50 rounded-lg p-5 border border-gray-700">
                <h3 className="font-bold text-white text-lg mb-3 font-mono">{selectedTool.tool_name}</h3>
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Total Runs</span>
                    <span className="text-white">{selectedTool.runs_total}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Successful</span>
                    <span className="text-green-400">{selectedTool.runs_success}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Success Rate</span>
                    <span className={selectedTool.success_rate >= 0.7 ? 'text-green-400' : 'text-yellow-400'}>
                      {Math.round(selectedTool.success_rate * 100)}%
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Total Findings</span>
                    <span className="text-yellow-400 font-bold">{selectedTool.findings_total}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Avg Findings/Run</span>
                    <span className="text-white">{selectedTool.avg_findings_per_run}</span>
                  </div>
                  {selectedTool.vuln_types?.length > 0 && (
                    <div>
                      <div className="text-gray-400 mb-2">Vuln Types Found</div>
                      <div className="space-y-1">
                        {selectedTool.vuln_types.map((v, i) => (
                          <div key={i} className="flex justify-between text-xs">
                            <span className="text-gray-300">{v.vuln_type || '(generic)'}</span>
                            <span className="text-yellow-400">{v.findings} findings</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="bg-gray-800/50 rounded-lg p-5 border border-gray-700 text-gray-500 text-sm text-center">
                Click a tool to see detailed analytics
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
