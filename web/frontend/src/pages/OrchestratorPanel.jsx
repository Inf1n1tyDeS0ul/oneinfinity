import React, { useState, useEffect } from 'react'
import { Cpu, RefreshCw, Play } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import { relativeTime } from '../utils/time'
import clsx from 'clsx'

const TIER_COLORS = { FAST: 'text-green-400', STANDARD: 'text-yellow-400', PREMIUM: 'text-red-400', 1: 'text-green-400', 2: 'text-yellow-400', 3: 'text-red-400' }
const CATEGORIES = ['web_recon', 'vulnerability_scan', 'exploit', 'ai_analysis', 'report', 'general']

// ── Tab: Models ──────────────────────────────────────────────────────────────
function ModelsTab() {
  const { addNotification } = useStore()
  const [models, setModels] = useState([])
  const [loading, setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const r = await endpoints.orchestratorModels(false)
      setModels(r.data?.models || r.data || [])
      setLastUpdated(new Date().toLocaleTimeString())
    } catch (e) { 
      addNotification(`Failed to load models: ${e.message}`, 'error') 
    } finally { 
      setLoading(false) 
    }
  }

  const reload = async () => {
    setLoading(true)
    try {
      await endpoints.orchestratorReload()
      addNotification('Config reloaded', 'success')
      load()
    } catch (e) { 
      addNotification(`Reload failed: ${e.message}`, 'error') 
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  return (
    <div className="card overflow-auto">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-300">Model Configurations</span>
          <button className="btn-secondary flex items-center gap-1" onClick={load} disabled={loading}>
            <RefreshCw size={11} className={clsx(loading && 'animate-spin')} /> Refresh
          </button>
        </div>
        <div className="flex items-center gap-3">
          {lastUpdated && <span className="text-[10px] text-slate-500">Last updated: {lastUpdated}</span>}
          <button className="btn-primary flex items-center gap-1" onClick={reload} disabled={loading}>Reload Config</button>
        </div>
      </div>
      {models.length === 0 ? (
        <div className="text-xs text-slate-500 p-4">{loading ? 'Loading models...' : 'No models configured'}</div>
      ) : (
        <table className="w-full text-xs">
          <thead>
            <tr className="text-slate-500 border-b border-bg-border">
              <th className="text-left py-2 px-3">Model</th>
              <th className="text-left py-2 px-3">Provider</th>
              <th className="text-left py-2 px-3 w-24">Tier</th>
              <th className="text-left py-2 px-3 w-32">Cost / 1k tokens</th>
              <th className="text-left py-2 px-3 w-20">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-bg-border">
            {models.map((m, i) => (
              <tr key={i} className="hover:bg-white/5">
                <td className="py-1.5 px-3 font-mono text-slate-300">{m.model_id || m.name || '—'}</td>
                <td className="py-1.5 px-3 text-slate-400">{m.provider || '—'}</td>
                <td className={clsx('py-1.5 px-3 font-semibold text-[10px]', TIER_COLORS[m.tier] || 'text-slate-400')}>
                  {typeof m.tier === 'number' ? ['', 'FAST', 'STANDARD', 'PREMIUM'][m.tier] || m.tier : m.tier || '—'}
                </td>
                <td className="py-1.5 px-3 text-slate-300 font-mono">${m.cost_per_1k_tokens?.toFixed(5) || m.cost_input || '—'}</td>
                <td className="py-1.5 px-3">
                  <span className={clsx('text-[10px] px-1.5 py-0.5 rounded-full', m.enabled ? 'bg-green-900/50 text-green-400' : 'bg-slate-700 text-slate-500')}>
                    {m.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

// ── Tab: Budget ──────────────────────────────────────────────────────────────
function BudgetTab() {
  const { addNotification } = useStore()
  const [today, setToday] = useState(null)
  const [month, setMonth] = useState(null)
  const [records, setRecords] = useState([])
  const [loading, setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const [td, mo, rc] = await Promise.allSettled([
        endpoints.orchestratorBudgetSummary('today'),
        endpoints.orchestratorBudgetSummary('this_month'),
        endpoints.orchestratorRecords(50),
      ])
      if (td.status === 'fulfilled') setToday(td.value.data)
      if (mo.status === 'fulfilled') setMonth(mo.value.data)
      if (rc.status === 'fulfilled') setRecords(rc.value.data?.records || rc.value.data || [])
      setLastUpdated(new Date().toLocaleTimeString())
    } catch (err) {
      addNotification(`Budget load failed: ${err.message}`, 'error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const id = setInterval(load, 30000)
    return () => clearInterval(id)
  }, [])

  const pct = month && month.monthly_limit ? (month.total_cost / month.monthly_limit * 100).toFixed(1) : null

  return (
    <div className="flex flex-col gap-4">
      <div className="flex justify-between items-center">
        <button className="btn-secondary flex items-center gap-1" onClick={load} disabled={loading}>
          <RefreshCw size={11} className={clsx(loading && 'animate-spin')} /> Refresh
        </button>
        {lastUpdated && <span className="text-[10px] text-slate-500">Last updated: {lastUpdated}</span>}
      </div>

      <div className="grid grid-cols-4 gap-3">
        <div className="stat-card">
          <div className="stat-label">Today's Spend</div>
          <div className="stat-value text-cyan-400">${today?.total_cost?.toFixed(4) ?? '—'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Monthly Spend</div>
          <div className="stat-value text-purple-400">${month?.total_cost?.toFixed(4) ?? '—'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Monthly Limit</div>
          <div className="stat-value">${month?.monthly_limit?.toFixed(2) ?? '—'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Projected EOM</div>
          <div className="stat-value text-slate-400">${month?.projected_cost?.toFixed(4) ?? '—'}</div>
        </div>
      </div>

      {pct !== null && (
        <div className="card">
          <div className="flex justify-between text-[10px] text-slate-400 mb-1 font-semibold uppercase">
            <span>Monthly budget usage</span>
            <span>{pct}%</span>
          </div>
          <div className="w-full bg-bg-secondary rounded-full h-1.5 overflow-hidden border border-white/5">
            <div className={clsx('h-full transition-all duration-500', Number(pct) > 80 ? 'bg-red-500' : Number(pct) > 60 ? 'bg-yellow-500' : 'bg-cyan-500')}
              style={{ width: `${Math.min(100, Number(pct))}%` }} />
          </div>
        </div>
      )}

      <div className="card overflow-auto">
        <div className="text-xs font-semibold text-slate-300 mb-3 uppercase tracking-wider">Usage Records (last 50)</div>
        <table className="w-full text-xs">
          <thead>
            <tr className="text-slate-500 border-b border-bg-border">
              <th className="text-left py-2 px-3">Time</th>
              <th className="text-left py-2 px-3">Model</th>
              <th className="text-left py-2 px-3 w-20">Tokens</th>
              <th className="text-left py-2 px-3 w-20">Cost</th>
              <th className="text-left py-2 px-3">Category</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-bg-border">
            {records.map((r, i) => (
              <tr key={i} className="hover:bg-white/5">
                <td className="py-1.5 px-3 text-slate-500 whitespace-nowrap">{relativeTime(r.timestamp)}</td>
                <td className="py-1.5 px-3 font-mono text-slate-300 text-[10px]">{r.model || r.model_id || '—'}</td>
                <td className="py-1.5 px-3 text-slate-400 font-mono">{r.tokens || r.total_tokens || '—'}</td>
                <td className="py-1.5 px-3 text-slate-300 font-mono">${r.cost?.toFixed(5) || '—'}</td>
                <td className="py-1.5 px-3 text-slate-500 text-[10px] uppercase">{r.category || r.task_category || '—'}</td>
              </tr>
            ))}
            {records.length === 0 && (
              <tr><td colSpan={5} className="py-4 px-3 text-slate-500 text-center">{loading ? 'Loading records...' : 'No usage records yet'}</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}


// ── Tab: Execute ─────────────────────────────────────────────────────────────
function ExecuteTab() {
  const { addNotification } = useStore()
  const [prompt, setPrompt] = useState('')
  const [category, setCategory] = useState('general')
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState(null)

  const execute = async () => {
    if (!prompt.trim()) return addNotification('Enter a prompt', 'error')
    setRunning(true)
    setResult(null)
    try {
      const r = await endpoints.orchestratorExecute({ prompt: prompt.trim(), category })
      setResult(r.data)
      addNotification('Executed successfully', 'success')
    } catch (e) {
      addNotification(`Execution failed: ${e.message}`, 'error')
    } finally { setRunning(false) }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="card">
        <div className="text-xs font-semibold text-slate-300 mb-3">Execute AI Task</div>
        <textarea className="input w-full h-28 resize-none mb-3" placeholder="Enter task prompt..."
          value={prompt} onChange={e => setPrompt(e.target.value)} />
        <div className="flex items-center gap-3">
          <select className="select w-48" value={category} onChange={e => setCategory(e.target.value)}>
            {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
          <button className="btn-primary flex items-center gap-1.5" onClick={execute} disabled={running}>
            <Play size={12} /> {running ? 'Running...' : 'Execute'}
          </button>
        </div>
      </div>

      {result && (
        <div className="card">
          <div className="flex items-center gap-3 mb-3">
            <span className="text-xs font-semibold text-slate-300">Result</span>
            <span className="text-xs text-slate-500">Model: <span className="text-cyan-400">{result.model_used || result.model || '—'}</span></span>
            <span className="text-xs text-slate-500">Tokens: <span className="text-slate-300">{result.tokens || result.total_tokens || '—'}</span></span>
            {result.cost && <span className="text-xs text-slate-500">Cost: <span className="text-slate-300">${result.cost.toFixed(5)}</span></span>}
          </div>
          <pre className="text-xs text-slate-300 bg-black/30 rounded p-3 whitespace-pre-wrap overflow-auto max-h-64">
            {result.response || result.content || result.text || JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

// ── Main ─────────────────────────────────────────────────────────────────────
const TABS = ['Models', 'Budget', 'Execute']

export default function OrchestratorPanel() {
  const [tab, setTab] = useState(0)

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
        <Cpu size={14} className="text-accent-primary" />
        AI Orchestrator
      </h1>

      <div className="flex gap-1 border-b border-bg-border pb-1">
        {TABS.map((t, i) => (
          <button key={t} onClick={() => setTab(i)}
            className={clsx('px-3 py-1.5 text-xs rounded-t transition-colors',
              tab === i ? 'bg-accent-primary/20 text-accent-primary' : 'text-slate-400 hover:text-slate-200')}>
            {t}
          </button>
        ))}
      </div>

      {tab === 0 && <ModelsTab />}
      {tab === 1 && <BudgetTab />}
      {tab === 2 && <ExecuteTab />}
    </div>
  )
}
