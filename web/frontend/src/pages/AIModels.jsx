import React, { useState, useEffect } from 'react'
import { Bot, RefreshCw, DollarSign, Zap, BarChart2, CheckCircle2, Settings2, Play } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

const TIER_COLORS = { FAST: 'badge-running', STANDARD: 'badge-medium', PREMIUM: 'badge-high' }

export default function AIModels() {
  const { addNotification } = useStore()
  const [tab, setTab] = useState('status')
  const [status, setStatus] = useState(null)
  const [models, setModels] = useState([])
  const [budget, setBudget] = useState(null)
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(false)
  const [testPrompt, setTestPrompt] = useState('')
  const [testModel, setTestModel] = useState('')
  const [testResult, setTestResult] = useState(null)
  const [testRunning, setTestRunning] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const [s, m, b, h] = await Promise.allSettled([
        endpoints.orchestratorStatus(),
        endpoints.orchestratorModels(),
        endpoints.orchestratorBudget(),
        endpoints.orchestratorHistory(20),
      ])
      if (s.status === 'fulfilled') setStatus(s.value.data)
      // API returns array directly
      if (m.status === 'fulfilled') {
        const raw = m.value.data
        setModels(Array.isArray(raw) ? raw : (raw?.models || []))
      }
      if (b.status === 'fulfilled') setBudget(b.value.data)
      // API returns array directly
      if (h.status === 'fulfilled') {
        const raw = h.value.data
        setHistory(Array.isArray(raw) ? raw : (raw?.history || []))
      }
    } catch (e) {
      addNotification('Load error: ' + e.message, 'error')
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  const handleTest = async () => {
    if (!testPrompt.trim()) return
    setTestRunning(true)
    setTestResult(null)
    try {
      const payload = { prompt: testPrompt, description: testPrompt }
      if (testModel) payload.force_tier = null  // model override not yet supported via force_tier
      const r = await endpoints.orchestratorExecute(payload)
      setTestResult(r.data)
      addNotification('AI execution complete', 'success')
    } catch (e) {
      addNotification('Error: ' + e.message, 'error')
    } finally { setTestRunning(false) }
  }

  // Derive budget display values from actual API field names
  const todaySpend   = budget?.today_usd   ?? budget?.today_cost   ?? 0
  const monthSpend   = budget?.month_usd   ?? budget?.month_cost   ?? 0
  const dailyLimit   = budget?.daily_limit ?? 5
  const dailyPct     = budget?.daily_pct   ?? (dailyLimit > 0 ? (todaySpend / dailyLimit) * 100 : 0)
  const totalCalls   = budget?.total_calls ?? status?.recent_executions ?? 0
  const projMonthly  = budget?.projected_monthly ?? 0

  return (
    <div className="flex flex-col gap-5">
      <div className="section-header">
        <div>
          <div className="section-title flex items-center gap-2">
            <Bot size={18} className="text-purple-400" />
            AI Models &amp; Orchestration
          </div>
          <div className="section-sub">Model registry, budget tracking, and execution history</div>
        </div>
        <button className="btn-secondary" onClick={load}>
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* Budget summary cards */}
      {budget && (
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Today Spend', value: `$${todaySpend.toFixed(4)}`, icon: DollarSign, color: 'text-yellow-400' },
            { label: 'Total Calls', value: totalCalls, icon: Zap, color: 'text-cyan-400' },
            { label: 'Projected/Month', value: `$${projMonthly.toFixed(2)}`, icon: BarChart2, color: 'text-purple-400' },
            { label: 'Models Active', value: models.filter(m => m.enabled).length, icon: Bot, color: 'text-emerald-400' },
          ].map(c => (
            <div key={c.label} className="stat-card">
              <div className="flex items-center justify-between mb-1">
                <span className="stat-label">{c.label}</span>
                <c.icon size={14} className={c.color + '/50'} />
              </div>
              <div className={`text-2xl font-bold ${c.color} font-sans`}>{c.value}</div>
            </div>
          ))}
        </div>
      )}

      <div className="tab-bar">
        {[{ id: 'status', label: 'Status' }, { id: 'models', label: 'Models' }, { id: 'history', label: 'History' }, { id: 'test', label: 'Test Prompt' }].map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} className={tab === t.id ? 'tab-active' : 'tab'}>{t.label}</button>
        ))}
      </div>

      {tab === 'status' && (
        <div className="card">
          <div className="card-header"><span className="card-title">Orchestrator Status</span></div>
          <div className="card-body">
            {status ? (
              <pre className="terminal text-xs">{JSON.stringify(status, null, 2)}</pre>
            ) : <div className="text-slate-500 text-sm">No status data</div>}
          </div>
        </div>
      )}

      {tab === 'models' && (
        <div className="card">
          <div className="card-header"><span className="card-title">Registered Models</span></div>
          <table className="data-table">
            <thead><tr><th>Model ID</th><th>Tier</th><th>Capabilities</th><th>Cost/1K in+out</th><th>Status</th></tr></thead>
            <tbody>
              {models.map(m => {
                const costIn  = m.cost_per_1k_input  ?? m.cost_per_1k ?? null
                const costOut = m.cost_per_1k_output ?? null
                const costStr = costIn != null
                  ? (costOut != null ? `$${costIn}/$${costOut}` : `$${costIn}`)
                  : '—'
                return (
                  <tr key={m.model_id || m.name}>
                    <td className="font-mono text-xs text-accent-primary">{m.model_id || m.name}</td>
                    <td><span className={clsx('badge', TIER_COLORS[m.tier] || 'badge-info')}>{m.tier || '—'}</span></td>
                    <td className="text-xs text-slate-400 max-w-xs truncate">{(m.capabilities || []).join(', ') || '—'}</td>
                    <td className="text-xs text-yellow-400">{costStr}</td>
                    <td>{m.enabled ? <CheckCircle2 size={13} className="text-emerald-400" /> : <span className="text-slate-600 text-xs">disabled</span>}</td>
                  </tr>
                )
              })}
              {models.length === 0 && <tr><td colSpan={5} className="text-center text-slate-500 py-8">No models loaded — check API keys in environment</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'history' && (
        <div className="card">
          <div className="card-header"><span className="card-title">Recent Executions</span></div>
          <table className="data-table">
            <thead><tr><th>Model</th><th>Category</th><th>Tier</th><th>Cost</th><th>Tokens</th><th>Duration</th><th>Confidence</th><th>Time</th></tr></thead>
            <tbody>
              {history.map((h, i) => (
                <tr key={i}>
                  <td className="font-mono text-xs text-accent-primary">{h.model_id || h.model || '—'}</td>
                  <td><span className="badge badge-info">{h.category || h.task_type || '—'}</span></td>
                  <td><span className={clsx('badge', TIER_COLORS[h.tier] || 'badge-info')}>{h.tier || '—'}</span></td>
                  <td className="text-xs text-yellow-400">{h.cost_usd != null ? `$${h.cost_usd.toFixed(5)}` : (h.cost != null ? `$${h.cost.toFixed(5)}` : '—')}</td>
                  <td className="text-xs text-slate-400">{h.total_tokens ?? '—'}</td>
                  <td className="text-xs text-slate-400">{h.duration_ms ? `${h.duration_ms}ms` : '—'}</td>
                  <td className="text-xs text-slate-400">{h.confidence != null ? (h.confidence * 100).toFixed(0) + '%' : '—'}</td>
                  <td className="text-xs text-slate-500">{h.timestamp ? new Date(h.timestamp * 1000).toLocaleTimeString() : '—'}</td>
                </tr>
              ))}
              {history.length === 0 && <tr><td colSpan={8} className="text-center text-slate-500 py-8">No executions yet</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'test' && (
        <div className="card">
          <div className="card-header"><span className="card-title">Test AI Execution</span></div>
          <div className="card-body flex flex-col gap-4">
            <div className="grid grid-cols-3 gap-3">
              <div className="col-span-2">
                <label className="label">Prompt</label>
                <textarea className="textarea h-24" placeholder="Enter a prompt to test the AI orchestrator..." value={testPrompt} onChange={e => setTestPrompt(e.target.value)} />
              </div>
              <div>
                <label className="label">Model Override <span className="text-slate-600">(optional)</span></label>
                <select className="select" value={testModel} onChange={e => setTestModel(e.target.value)}>
                  <option value="">Auto (orchestrator picks)</option>
                  {models.filter(m => m.enabled).map(m => <option key={m.model_id} value={m.model_id}>{m.model_id}</option>)}
                </select>
              </div>
            </div>
            <button className="btn-primary justify-center" onClick={handleTest} disabled={!testPrompt.trim() || testRunning}>
              <Play size={13} />
              {testRunning ? 'Running...' : 'Execute'}
            </button>
            {testResult && (
              <div className="terminal">
                <div className="flex gap-4 text-xs mb-2 text-slate-400">
                  <span>Model: <span className="text-accent-primary">{testResult.model_id}</span></span>
                  <span>Tier: <span className={clsx('badge', TIER_COLORS[testResult.tier] || 'badge-info')}>{testResult.tier}</span></span>
                  <span>Confidence: <span className="text-emerald-400">{testResult.confidence != null ? (testResult.confidence * 100).toFixed(0) + '%' : '—'}</span></span>
                  <span>Cost: <span className="text-yellow-400">{testResult.cost_usd != null ? `$${testResult.cost_usd.toFixed(5)}` : '—'}</span></span>
                  {testResult.escalated_from && <span>Escalated from: <span className="text-orange-400">{testResult.escalated_from}</span></span>}
                </div>
                <pre className="text-xs whitespace-pre-wrap">{testResult.content || JSON.stringify(testResult, null, 2)}</pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
