import React, { useState, useEffect } from 'react'
import api from '../utils/api'

function DecisionCard({ decision }) {
  const [expanded, setExpanded] = useState(false)
  const score = decision.score || 0
  const scoreColor = score >= 7 ? 'text-red-400' : score >= 5 ? 'text-yellow-400' : 'text-blue-400'
  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-4 mb-3">
      <div className="flex items-start gap-3">
        <div className={`text-2xl font-black ${scoreColor} w-14 text-center flex-shrink-0`}>
          {score.toFixed(1)}
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="bg-blue-900 text-blue-300 text-xs px-2 py-0.5 rounded">{decision.agent_type}</span>
            <span className="text-white font-medium text-sm">{decision.node_label}</span>
            <span className="text-gray-500 text-xs">({decision.node_type})</span>
          </div>
          <div className="text-gray-400 text-xs mt-1">
            Expected: <strong className="text-yellow-400">{decision.expected_impact}</strong>
            {decision.suggested_tool && <> · Tool: <strong className="text-green-400">{decision.suggested_tool}</strong></>}
            {decision.confidence !== undefined && <> · Confidence: {Math.round(decision.confidence * 100)}%</>}
          </div>
          {decision.rationale?.factors?.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1">
              {decision.rationale.factors.slice(0, 4).map((f, i) => (
                <span key={i} className="text-xs bg-gray-700 text-gray-300 px-2 py-0.5 rounded">{f}</span>
              ))}
            </div>
          )}
        </div>
        <button onClick={() => setExpanded(!expanded)} className="text-xs text-gray-500 hover:text-white flex-shrink-0">
          {expanded ? '▲' : '▼'}
        </button>
      </div>
      {expanded && decision.rationale && (
        <div className="mt-3 grid grid-cols-3 gap-3 text-xs border-t border-gray-700 pt-3">
          {Object.entries(decision.rationale).filter(([k]) => k !== 'factors').map(([k, v]) => (
            <div key={k}>
              <div className="text-gray-500 uppercase tracking-wide mb-1">{k.replace(/_/g, ' ')}</div>
              <div className="text-white font-mono">{typeof v === 'number' ? v.toFixed(3) : v}</div>
            </div>
          ))}
        </div>
      )}
      {expanded && decision.suggested_payload && (
        <div className="mt-2 text-xs">
          <div className="text-gray-500 mb-1">Suggested Payload</div>
          <code className="bg-black/30 px-3 py-1 rounded text-green-300 block font-mono">{decision.suggested_payload}</code>
        </div>
      )}
    </div>
  )
}

export default function AdaptivePlanning() {
  const [target, setTarget]       = useState('')
  const [maxDec, setMaxDec]       = useState(20)
  const [plan, setPlan]           = useState(null)
  const [brainStatus, setBrainStatus] = useState(null)
  const [outcomes, setOutcomes]   = useState({})
  const [loading, setLoading]     = useState(false)
  const [error, setError]         = useState(null)
  const [tab, setTab]             = useState('plan')

  useEffect(() => {
    api.get('/brain/status').then(r => setBrainStatus(r.data)).catch(() => {})
    api.get('/adaptive/outcomes').then(r => setOutcomes(r.data.outcomes || {})).catch(() => {})
  }, [])

  const generatePlan = async () => {
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    try {
      const r = await api.post('/adaptive/plan', { target: target.trim(), max_decisions: maxDec })
      setPlan(r.data)
    } catch (e) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  const topOutcomes = Object.entries(outcomes)
    .map(([k, v]) => ({ key: k, ...(typeof v === 'object' ? v : { value: v }) }))
    .slice(0, 20)

  return (
    <div className="p-6 bg-gray-900 min-h-screen text-white">
      <div className="max-w-5xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-bold">Adaptive Planning Intelligence</h1>
          <p className="text-gray-400 text-sm mt-1">
            AutonomousDecisionEngine — see why each tool, payload, and target was selected
          </p>
        </div>

        {/* Brain Status */}
        {brainStatus && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
            {[
              { label: 'Decisions Made', value: brainStatus.decisions_made },
              { label: 'Actions Dispatched', value: brainStatus.actions_dispatched },
              { label: 'Findings Integrated', value: brainStatus.findings_integrated },
              { label: 'Active Targets', value: (brainStatus.targets || []).length },
            ].map(({ label, value }) => (
              <div key={label} className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <div className="text-gray-400 text-xs uppercase tracking-wide">{label}</div>
                <div className="text-2xl font-bold text-white mt-1">{value ?? '—'}</div>
              </div>
            ))}
          </div>
        )}

        {/* Plan Generator */}
        <div className="bg-gray-800/50 rounded-lg p-5 border border-gray-700 mb-6">
          <div className="flex gap-3">
            <input
              value={target}
              onChange={e => setTarget(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && generatePlan()}
              placeholder="https://example.com"
              className="flex-1 bg-gray-900 border border-gray-700 rounded px-4 py-2 text-white placeholder-gray-500 outline-none focus:border-blue-500"
            />
            <select
              value={maxDec}
              onChange={e => setMaxDec(+e.target.value)}
              className="bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-white"
            >
              {[10, 20, 30, 50].map(n => <option key={n} value={n}>{n} decisions</option>)}
            </select>
            <button
              onClick={generatePlan}
              disabled={loading || !target.trim()}
              className="bg-blue-600 hover:bg-blue-700 text-white px-5 py-2 rounded disabled:opacity-50"
            >
              {loading ? 'Generating…' : 'Generate Plan'}
            </button>
          </div>
          {error && <div className="text-red-400 text-sm mt-2">{error}</div>}
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mb-4">
          {['plan', 'outcomes'].map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-2 rounded text-sm font-medium ${
                tab === t ? 'bg-blue-700 text-white' : 'bg-gray-700 text-gray-400 hover:text-white'
              }`}
            >
              {t === 'plan' ? 'Decision Plan' : 'Outcome History'}
            </button>
          ))}
        </div>

        {tab === 'plan' && (
          plan ? (
            <div>
              <div className="flex items-center gap-4 mb-4 text-sm text-gray-400">
                <span>Target: <strong className="text-white">{plan.target}</strong></span>
                <span>{plan.decisions?.length ?? 0} decisions</span>
              </div>
              {plan.decisions?.length === 0 ? (
                <div className="text-gray-500 text-center py-12">
                  No nodes found in graph for this target. Run a scan first to populate the attack graph.
                </div>
              ) : (
                plan.decisions?.map((d, i) => <DecisionCard key={i} decision={d} />)
              )}
            </div>
          ) : (
            <div className="text-gray-500 text-center py-24">
              Enter a target to generate an adaptive attack plan
            </div>
          )
        )}

        {tab === 'outcomes' && (
          <div>
            {topOutcomes.length === 0 ? (
              <div className="text-gray-500 text-center py-12">
                No outcome data yet — run scans to accumulate decision feedback
              </div>
            ) : (
              <div className="bg-gray-800/50 rounded-lg border border-gray-700 overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-gray-400 border-b border-gray-700">
                      <th className="text-left px-4 py-3">Decision</th>
                      <th className="text-right px-4 py-3">Outcome</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topOutcomes.map((o, i) => (
                      <tr key={i} className="border-b border-gray-800 hover:bg-gray-700/20">
                        <td className="px-4 py-3 text-gray-300 font-mono text-xs">{o.key}</td>
                        <td className="px-4 py-3 text-right text-xs text-gray-400">
                          {JSON.stringify(o.value ?? o).slice(0, 60)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
