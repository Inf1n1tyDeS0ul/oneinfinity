import React, { useState } from 'react'
import { FlaskConical, Play, Zap, Eye, BarChart2, AlertTriangle, Telescope, Settings2, ChevronDown, ChevronRight } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

const RESEARCH_MODES = [
  {
    value: 'research',
    label: 'Autonomous Research',
    icon: FlaskConical,
    color: 'text-purple-400',
    desc: 'Full analyze→theorize→test→report loop. Iterative until convergence.',
    fields: ['iterations', 'min_confidence', 'timeout', 'oob'],
  },
  {
    value: 'analyze_app',
    label: 'Analyze App',
    icon: Eye,
    color: 'text-cyan-400',
    desc: 'Build structured application model from recon data.',
    fields: ['output_dir'],
  },
  {
    value: 'generate_theories',
    label: 'Generate Theories',
    icon: BarChart2,
    color: 'text-yellow-400',
    desc: 'Generate vulnerability theories from existing app model.',
    fields: ['output_dir'],
  },
  {
    value: 'custom_tests',
    label: 'Run Custom Tests',
    icon: Zap,
    color: 'text-orange-400',
    desc: 'Design and execute custom attack tests from theories.',
    fields: ['min_severity', 'oob', 'rate'],
  },
  {
    value: 'zero_day',
    label: 'Zero-Day Detection',
    icon: AlertTriangle,
    color: 'text-red-400',
    desc: 'Probe for unusual behaviors and zero-day anomalies.',
    fields: ['rate', 'timeout'],
  },
  {
    value: 'adaptive_recon',
    label: 'Adaptive Recon',
    icon: Telescope,
    color: 'text-emerald-400',
    desc: 'Tech detection, API map, JS endpoints — depth-aware intelligence.',
    fields: ['depth'],
  },
]

export default function Research() {
  const { addNotification } = useStore()
  const [mode, setMode] = useState('research')
  const [target, setTarget] = useState('')
  const [opts, setOpts] = useState({ iterations: 3, min_confidence: 0.6, timeout: 3600, oob: '', output_dir: '', min_severity: 'medium', rate: 1.0, depth: 'standard' })
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState(null)

  const selectedMode = RESEARCH_MODES.find(m => m.value === mode)

  const handleRun = async () => {
    if (!target.trim()) return
    setRunning(true)
    setResult(null)
    try {
      const payload = { target: target.trim(), mode, ...opts }
      const r = await endpoints.launchScan({ target: target.trim(), scan_type: mode, ...opts })
      setResult(r.data)
      addNotification(`Research started: ${selectedMode?.label}`, 'success')
    } catch (e) {
      addNotification(`Error: ${e.response?.data?.detail || e.message}`, 'error')
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="flex flex-col gap-6 max-w-6xl">
      <div className="section-header">
        <div className="flex flex-col gap-1">
          <div className="section-title flex items-center gap-2.5">
            <FlaskConical size={20} className="text-accent-purple drop-shadow-[0_0_8px_rgba(168,85,247,0.4)]" />
            Autonomous Research
          </div>
          <div className="section-sub">Execute high-intensity autonomous discovery workflows with AI-driven hypothesis loops.</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Mode selector */}
        <div className="lg:col-span-4 flex flex-col gap-3">
          <div className="label-sm px-1">Research Strategy</div>
          {RESEARCH_MODES.map(m => {
            const Icon = m.icon
            return (
              <button
                key={m.value}
                onClick={() => setMode(m.value)}
                className={clsx(
                  'text-left px-4 py-4 rounded-xl border transition-all duration-200 group relative overflow-hidden',
                  mode === m.value
                    ? 'border-accent-primary/40 bg-accent-primary/10 shadow-glow-cyan'
                    : 'card hover:border-bg-border-hover hover:bg-white/[0.03]'
                )}
              >
                {mode === m.value && <div className="absolute left-0 top-0 bottom-0 w-1 bg-accent-primary" />}
                <div className="flex items-center gap-3 mb-2">
                  <div className={clsx(
                    'p-2 rounded-lg transition-colors',
                    mode === m.value ? 'bg-accent-primary/20 text-accent-primary' : 'bg-bg-elevated text-slate-400 group-hover:text-slate-200'
                  )}>
                    <Icon size={16} className="flex-shrink-0" />
                  </div>
                  <span className={clsx('text-xs font-bold tracking-tight', mode === m.value ? 'text-accent-primary' : 'text-slate-200')}>{m.label}</span>
                </div>
                <div className="text-[10px] text-slate-500 leading-relaxed pl-11">{m.desc}</div>
              </button>
            )
          })}
        </div>

        {/* Config panel */}
        <div className="lg:col-span-8 flex flex-col gap-4">
          <div className="card">
            <div className="card-header bg-bg-card/50">
              <span className="card-title">
                {React.createElement(selectedMode?.icon || FlaskConical, { size: 14, className: clsx('flex-shrink-0', selectedMode?.color) })}
                Configure {selectedMode?.label}
              </span>
              <div className="badge badge-info uppercase">Mode: {mode}</div>
            </div>
            <div className="card-body flex flex-col gap-5">
              <div className="space-y-1.5">
                <label className="label">Target Domain / URL</label>
                <div className="relative">
                  <input className="input pl-9" placeholder="e.g. example.com or https://api.example.com" value={target} onChange={e => setTarget(e.target.value)} />
                  <Telescope size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                {selectedMode?.fields.includes('iterations') && (
                  <div className="space-y-1.5">
                    <label className="label">Max Iterations</label>
                    <input className="input" type="number" min={1} max={20} value={opts.iterations} onChange={e => setOpts(o => ({ ...o, iterations: +e.target.value }))} />
                    <p className="text-[10px] text-slate-600">Depth of the autonomous loop.</p>
                  </div>
                )}
                {selectedMode?.fields.includes('min_confidence') && (
                  <div className="space-y-1.5">
                    <label className="label">Min Confidence Score</label>
                    <input className="input" type="number" step={0.05} min={0} max={1} value={opts.min_confidence} onChange={e => setOpts(o => ({ ...o, min_confidence: +e.target.value }))} />
                    <p className="text-[10px] text-slate-600">Filter payloads by AI confidence.</p>
                  </div>
                )}
              </div>

              {selectedMode?.fields.includes('oob') && (
                <div className="space-y-1.5">
                  <label className="label">OOB Callback URL <span className="text-slate-600 font-normal italic">(Interactsh / Burp Collaborator)</span></label>
                  <input className="input" placeholder="e.g. c7p...oob.dnslog.cn" value={opts.oob} onChange={e => setOpts(o => ({ ...o, oob: e.target.value }))} />
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                {selectedMode?.fields.includes('min_severity') && (
                  <div className="space-y-1.5">
                    <label className="label">Minimum Severity</label>
                    <select className="select capitalize" value={opts.min_severity} onChange={e => setOpts(o => ({ ...o, min_severity: e.target.value }))}>
                      {['critical','high','medium','low','info'].map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </div>
                )}
                {selectedMode?.fields.includes('depth') && (
                  <div className="space-y-1.5">
                    <label className="label">Recon Depth</label>
                    <select className="select capitalize" value={opts.depth} onChange={e => setOpts(o => ({ ...o, depth: e.target.value }))}>
                      {['quick','standard','deep'].map(d => <option key={d} value={d}>{d}</option>)}
                    </select>
                  </div>
                )}
                {selectedMode?.fields.includes('rate') && (
                  <div className="space-y-1.5">
                    <label className="label">Request Rate <span className="text-slate-600">(delay in sec)</span></label>
                    <input className="input" type="number" step={0.1} min={0} value={opts.rate} onChange={e => setOpts(o => ({ ...o, rate: +e.target.value }))} />
                  </div>
                )}
                {selectedMode?.fields.includes('timeout') && (
                  <div className="space-y-1.5">
                    <label className="label">Global Timeout <span className="text-slate-600">(sec)</span></label>
                    <input className="input" type="number" min={60} value={opts.timeout} onChange={e => setOpts(o => ({ ...o, timeout: +e.target.value }))} />
                  </div>
                )}
              </div>

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
                      Initializing Research Engine...
                    </>
                  ) : (
                    <>
                      <Play size={16} fill="currentColor" />
                      Start {selectedMode?.label}
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {result && (
            <div className="card border-accent-success/30 overflow-hidden">
              <div className="card-header bg-emerald-950/20 py-2">
                <div className="flex items-center gap-2 text-[10px] font-bold text-emerald-400 uppercase tracking-widest">
                  <Zap size={10} /> Launch Success
                </div>
              </div>
              <div className="terminal rounded-none border-0 max-h-64 scrollbar-thin">
                <div className="text-cyan-400 mb-2 text-[10px] font-mono">// Job ID: {result.scan_id || result.id || 'N/A'} initialized successfully</div>
                <pre className="text-emerald-400 text-[10px] leading-relaxed">{JSON.stringify(result, null, 2)}</pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
