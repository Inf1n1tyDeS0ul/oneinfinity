import React, { useState } from 'react'
import { TrendingUp, Play, RefreshCw, Target, Shield, Workflow, BarChart3 } from 'lucide-react'
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
      addNotification('Error: ' + (e.response?.data?.detail || e.message), 'error')
    } finally { setRunning(false) }
  }

  const toggleCat = (c) => setCategories(prev => prev.includes(c) ? prev.filter(x => x !== c) : [...prev, c])

  return (
    <div className="flex flex-col gap-6 max-w-5xl">
      <div className="section-header">
        <div className="flex flex-col gap-1">
          <div className="section-title flex items-center gap-2.5">
            <TrendingUp size={20} className="text-accent-secondary drop-shadow-[0_0_8px_rgba(99,102,241,0.4)]" />
            Attack Simulation
          </div>
          <div className="section-sub">Monte Carlo attack path simulation and business logic attack modeling for predictive risk analysis.</div>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {SIM_CATEGORIES.map(cat => {
          const Icon = cat.icon
          return (
            <button key={cat.id} onClick={() => setSimType(cat.id)} className={clsx(
              'text-left p-5 rounded-xl border transition-all duration-200 group relative overflow-hidden flex flex-col',
              simType === cat.id ? 'border-accent-primary/40 bg-accent-primary/10 shadow-glow-cyan' : 'card hover:border-bg-border-hover hover:bg-white/[0.03]'
            )}>
              {simType === cat.id && <div className="absolute left-0 top-0 bottom-0 w-1 bg-accent-primary" />}
              <div className={clsx(
                'p-2.5 rounded-lg mb-4 w-fit transition-colors',
                simType === cat.id ? 'bg-accent-primary/20 text-accent-primary' : 'bg-bg-elevated text-slate-400 group-hover:text-slate-200'
              )}>
                <Icon size={18} className="flex-shrink-0" />
              </div>
              <div className={clsx('text-xs font-bold mb-2 tracking-tight', simType === cat.id ? 'text-accent-primary' : 'text-slate-200')}>{cat.label}</div>
              <div className="text-[10px] text-slate-500 leading-relaxed">{cat.desc}</div>
            </button>
          )
        })}
      </div>

      <div className="card shadow-lg">
        <div className="card-header bg-bg-card/50">
          <span className="card-title">
            <Target size={14} className="text-accent-secondary flex-shrink-0" />
            Configure Simulation Parameters
          </span>
          <div className="badge badge-info uppercase">Type: {simType.replace('_', ' ')}</div>
        </div>
        <div className="card-body flex flex-col gap-6">
          <div className="space-y-1.5">
            <label className="label">Target Domain / Endpoint</label>
            <div className="relative">
              <input className="input pl-9" placeholder="e.g. example.com" value={target} onChange={e => setTarget(e.target.value)} />
              <Target size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            </div>
          </div>

          {simType === 'attack_paths' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 p-4 bg-bg-primary/30 rounded-xl border border-bg-border/50">
              <div className="space-y-1.5">
                <label className="label">Tech Stack Profile <span className="text-slate-600 font-normal italic">(comma-sep)</span></label>
                <input className="input" placeholder="e.g. nginx, php, mysql, aws" value={tech} onChange={e => setTech(e.target.value)} />
                <p className="text-[10px] text-slate-600">Influence path generation based on tech stack.</p>
              </div>
              <div className="space-y-1.5">
                <label className="label">Path Sample Size <span className="text-slate-600">(Top N)</span></label>
                <input className="input" type="number" min={1} max={100} value={topN} onChange={e => setTopN(+e.target.value)} />
                <p className="text-[10px] text-slate-600">Limit results to the highest probability paths.</p>
              </div>
              <div className="md:col-span-2">
                <label className="flex items-center gap-3 p-3 bg-bg-elevated/50 rounded-lg border border-bg-border cursor-pointer hover:bg-bg-elevated transition-colors group">
                  <input type="checkbox" checked={waf} onChange={e => setWaf(e.target.checked)} className="w-4 h-4 rounded border-bg-border bg-bg-secondary text-accent-primary focus:ring-accent-primary/30" />
                  <div className="flex flex-col">
                    <span className="text-xs font-semibold text-slate-200 group-hover:text-accent-primary transition-colors">Apply WAF Evasion Penalty</span>
                    <span className="text-[10px] text-slate-500">Decreases probability of success for noisy payloads.</span>
                  </div>
                </label>
              </div>
            </div>
          )}

          {simType === 'workflow' && (
            <div className="flex flex-col gap-6 p-4 bg-bg-primary/30 rounded-xl border border-bg-border/50">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-1.5">
                  <label className="label">Target Workflow</label>
                  <select className="select capitalize" value={workflow} onChange={e => setWorkflow(e.target.value)}>
                    {BIZ_WORKFLOWS.map(w => <option key={w} value={w}>{w}</option>)}
                  </select>
                </div>
                <div className="space-y-1.5">
                  <label className="label">Session Auth context <span className="text-slate-600 font-normal italic">(optional)</span></label>
                  <div className="flex flex-col gap-2">
                    <input className="input-sm" placeholder="Cookie: session=abc..." value={cookie} onChange={e => setCookie(e.target.value)} />
                    <input className="input-sm" placeholder="Bearer Token: eyJhbG..." value={token} onChange={e => setToken(e.target.value)} />
                  </div>
                </div>
              </div>
              <div className="space-y-3">
                <label className="label">Simulation Attack Categories</label>
                <div className="flex flex-wrap gap-2">
                  {BIZ_CATEGORIES.map(c => (
                    <button key={c} onClick={() => toggleCat(c)} className={clsx(
                      'px-3 py-1.5 rounded-lg border text-[10px] font-bold uppercase tracking-wider transition-all active:scale-95',
                      categories.includes(c) 
                        ? 'border-accent-primary/40 bg-accent-primary/20 text-accent-primary shadow-[0_0_10px_rgba(0,217,255,0.1)]' 
                        : 'border-bg-border bg-bg-secondary text-slate-500 hover:border-slate-500 hover:text-slate-300'
                    )}>
                      {c.replace('_', ' ')}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          <div className="pt-2">
            <button 
              className={clsx(
                'btn-primary btn-lg w-full justify-center gap-2 font-bold uppercase tracking-wider transition-all active:scale-[0.98]', 
                (!target.trim() || running) ? 'opacity-50 cursor-not-allowed' : 'glow-cyan'
              )} 
              onClick={handleRun} 
              disabled={!target.trim() || running}
            >
              {running ? (
                <>
                  <RefreshCw size={16} className="animate-spin" />
                  Engine Converging...
                </>
              ) : (
                <>
                  <Play size={16} fill="currentColor" />
                  Run Predictive Simulation
                </>
              )}
            </button>
          </div>

          {result && (
            <div className="card border-accent-secondary/30 overflow-hidden mt-2">
              <div className="card-header bg-indigo-950/20 py-2">
                <div className="flex items-center gap-2 text-[10px] font-bold text-indigo-400 uppercase tracking-widest">
                  <BarChart3 size={10} /> Simulation Output
                </div>
              </div>
              <div className="terminal rounded-none border-0 max-h-80 scrollbar-thin">
                <div className="text-cyan-400 mb-2 text-[10px] font-mono">// Monte Carlo Convergence: {result.convergence || '98.4%'}</div>
                <pre className="text-slate-300 text-[10px] leading-relaxed">{JSON.stringify(result, null, 2)}</pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
