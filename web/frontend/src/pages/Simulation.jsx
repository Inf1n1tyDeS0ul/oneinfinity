import React, { useState } from 'react'
import { TrendingUp, Play, RefreshCw, Target, Shield, Workflow } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

const SIM_CATEGORIES = [
  { id: 'attack_paths', label: 'Monte Carlo Attack Paths', icon: TrendingUp, desc: 'Probabilistic attack path simulation — find highest-probability exploitation routes.' },
  { id: 'workflow', label: 'Business Logic Workflow', icon: Workflow, desc: 'Simulate business logic attacks across auth, cart, API, and payment workflows.' },
  { id: 'swarm_sim', label: 'Swarm Pre-Scan Simulation', icon: Shield, desc: 'Pre-scan simulation to estimate which agents will find most findings.' },
]

const BIZ_WORKFLOWS = ['all', 'auth', 'checkout', 'api', 'account', 'admin', 'payment']
const BIZ_CATEGORIES = ['idor', 'privilege_escalation', 'race_condition', 'price_manipulation', 'auth_bypass', 'session_hijacking']

export default function Simulation() {
  const { addNotification } = useStore()
  const [simType, setSimType] = useState('attack_paths')
  const [target, setTarget] = useState('')
  const [tech, setTech] = useState('')
  const [waf, setWaf] = useState(false)
  const [topN, setTopN] = useState(10)
  const [workflow, setWorkflow] = useState('all')
  const [categories, setCategories] = useState([])
  const [cookie, setCookie] = useState('')
  const [token, setToken] = useState('')
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState(null)

  const handleRun = async () => {
    if (!target.trim()) return
    setRunning(true)
    setResult(null)
    try {
      let payload = { target: target.trim(), scan_type: 'simulate_' + simType }
      if (simType === 'attack_paths') payload = { ...payload, tech, waf, top_n: topN }
      if (simType === 'workflow') payload = { ...payload, workflow, categories: categories.join(','), cookie, token }
      const r = await endpoints.launchScan(payload)
      setResult(r.data)
      addNotification('Simulation started', 'success')
    } catch (e) {
      addNotification('Error: ' + e.response?.data?.detail || e.message, 'error')
    } finally { setRunning(false) }
  }

  const toggleCat = (c) => setCategories(prev => prev.includes(c) ? prev.filter(x => x !== c) : [...prev, c])

  return (
    <div className="flex flex-col gap-5 max-w-4xl">
      <div className="section-header">
        <div>
          <div className="section-title flex items-center gap-2">
            <TrendingUp size={18} className="text-indigo-400" />
            Attack Simulation
          </div>
          <div className="section-sub">Monte Carlo attack path simulation and business logic attack modeling</div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-3">
        {SIM_CATEGORIES.map(cat => {
          const Icon = cat.icon
          return (
            <button key={cat.id} onClick={() => setSimType(cat.id)} className={clsx(
              'text-left p-4 rounded-xl border transition-all',
              simType === cat.id ? 'border-accent-primary/40 bg-accent-primary/8 glow-cyan' : 'card hover:border-slate-600'
            )}>
              <Icon size={16} className={simType === cat.id ? 'text-accent-primary mb-2' : 'text-slate-400 mb-2'} />
              <div className={clsx('text-xs font-semibold mb-1', simType === cat.id ? 'text-accent-primary' : 'text-slate-200')}>{cat.label}</div>
              <div className="text-[10px] text-slate-500 leading-relaxed">{cat.desc}</div>
            </button>
          )
        })}
      </div>

      <div className="card">
        <div className="card-header"><span className="card-title"><Target size={14} className="text-indigo-400" />Configure Simulation</span></div>
        <div className="card-body flex flex-col gap-4">
          <div>
            <label className="label">Target</label>
            <input className="input" placeholder="example.com" value={target} onChange={e => setTarget(e.target.value)} />
          </div>

          {simType === 'attack_paths' && (
            <>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="label">Tech Stack <span className="text-slate-600">(comma-separated)</span></label>
                  <input className="input" placeholder="nginx,php,mysql" value={tech} onChange={e => setTech(e.target.value)} />
                </div>
                <div>
                  <label className="label">Top N Paths</label>
                  <input className="input" type="number" min={1} max={50} value={topN} onChange={e => setTopN(+e.target.value)} />
                </div>
              </div>
              <label className="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" checked={waf} onChange={e => setWaf(e.target.checked)} className="rounded border-bg-border bg-bg-secondary" />
                <span className="text-sm text-slate-300">WAF Detected (apply penalty)</span>
              </label>
            </>
          )}

          {simType === 'workflow' && (
            <>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="label">Workflow</label>
                  <select className="select" value={workflow} onChange={e => setWorkflow(e.target.value)}>
                    {BIZ_WORKFLOWS.map(w => <option key={w} value={w}>{w}</option>)}
                  </select>
                </div>
                <div>
                  <label className="label">Session Cookie <span className="text-slate-600">(optional)</span></label>
                  <input className="input" placeholder="session=abc123" value={cookie} onChange={e => setCookie(e.target.value)} />
                </div>
              </div>
              <div>
                <label className="label">Attack Categories</label>
                <div className="flex flex-wrap gap-2">
                  {BIZ_CATEGORIES.map(c => (
                    <button key={c} onClick={() => toggleCat(c)} className={clsx(
                      'px-2.5 py-1 rounded-lg border text-xs transition-all',
                      categories.includes(c) ? 'border-accent-primary/40 bg-accent-primary/10 text-accent-primary' : 'border-bg-border text-slate-400 hover:border-slate-500'
                    )}>
                      {c}
                    </button>
                  ))}
                </div>
              </div>
            </>
          )}

          <button className={clsx('btn-primary btn-lg justify-center', (!target.trim() || running) && 'opacity-50 cursor-not-allowed')} onClick={handleRun} disabled={!target.trim() || running}>
            <Play size={14} />
            {running ? 'Simulating...' : 'Run Simulation'}
          </button>

          {result && (
            <div className="terminal mt-2">
              <div className="text-cyan-400 mb-2 text-xs">// Simulation results</div>
              <pre className="text-xs">{JSON.stringify(result, null, 2)}</pre>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
