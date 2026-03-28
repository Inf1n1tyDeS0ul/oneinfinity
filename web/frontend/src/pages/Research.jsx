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
    <div className="flex flex-col gap-5 max-w-5xl">
      <div className="section-header">
        <div>
          <div className="section-title flex items-center gap-2">
            <FlaskConical size={18} className="text-purple-400" />
            Research Mode
          </div>
          <div className="section-sub">Autonomous vulnerability discovery — theorize, test, and report</div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {/* Mode selector */}
        <div className="col-span-1 flex flex-col gap-2">
          {RESEARCH_MODES.map(m => {
            const Icon = m.icon
            return (
              <button
                key={m.value}
                onClick={() => setMode(m.value)}
                className={clsx(
                  'text-left px-4 py-3.5 rounded-xl border transition-all',
                  mode === m.value
                    ? 'border-accent-primary/40 bg-accent-primary/8 shadow-glow-cyan'
                    : 'card hover:border-slate-600 hover:bg-white/[0.02]'
                )}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Icon size={13} className={mode === m.value ? 'text-accent-primary' : m.color} />
                  <span className={clsx('text-xs font-semibold', mode === m.value ? 'text-accent-primary' : 'text-slate-200')}>{m.label}</span>
                </div>
                <div className="text-[10px] text-slate-500 leading-relaxed">{m.desc}</div>
              </button>
            )
          })}
        </div>

        {/* Config panel */}
        <div className="col-span-2 card">
          <div className="card-header">
            <span className="card-title">
              {React.createElement(selectedMode?.icon || FlaskConical, { size: 14, className: selectedMode?.color })}
              {selectedMode?.label}
            </span>
          </div>
          <div className="card-body flex flex-col gap-4">
            <div>
              <label className="label">Target Domain / URL</label>
              <input className="input" placeholder="example.com" value={target} onChange={e => setTarget(e.target.value)} />
            </div>

            {selectedMode?.fields.includes('iterations') && (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="label">Max Iterations</label>
                  <input className="input" type="number" min={1} value={opts.iterations} onChange={e => setOpts(o => ({ ...o, iterations: +e.target.value }))} />
                </div>
                <div>
                  <label className="label">Min Confidence</label>
                  <input className="input" type="number" step={0.05} min={0} max={1} value={opts.min_confidence} onChange={e => setOpts(o => ({ ...o, min_confidence: +e.target.value }))} />
                </div>
              </div>
            )}

            {selectedMode?.fields.includes('oob') && (
              <div>
                <label className="label">OOB Callback URL <span className="text-slate-600">(optional)</span></label>
                <input className="input" placeholder="https://your-oob.domain" value={opts.oob} onChange={e => setOpts(o => ({ ...o, oob: e.target.value }))} />
              </div>
            )}

            {selectedMode?.fields.includes('min_severity') && (
              <div>
                <label className="label">Minimum Severity</label>
                <select className="select" value={opts.min_severity} onChange={e => setOpts(o => ({ ...o, min_severity: e.target.value }))}>
                  {['critical','high','medium','low','info'].map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
            )}

            {selectedMode?.fields.includes('depth') && (
              <div>
                <label className="label">Recon Depth</label>
                <select className="select" value={opts.depth} onChange={e => setOpts(o => ({ ...o, depth: e.target.value }))}>
                  {['quick','standard','deep'].map(d => <option key={d} value={d}>{d}</option>)}
                </select>
              </div>
            )}

            {selectedMode?.fields.includes('rate') && (
              <div>
                <label className="label">Request Rate (sec between req)</label>
                <input className="input" type="number" step={0.1} value={opts.rate} onChange={e => setOpts(o => ({ ...o, rate: +e.target.value }))} />
              </div>
            )}

            <button
              className={clsx('btn-primary btn-lg justify-center', (!target.trim() || running) && 'opacity-50 cursor-not-allowed')}
              onClick={handleRun}
              disabled={!target.trim() || running}
            >
              <Play size={14} />
              {running ? 'Running...' : `Start ${selectedMode?.label}`}
            </button>

            {result && (
              <div className="terminal mt-2">
                <div className="text-cyan-400 mb-2 text-xs">// Research job started</div>
                <pre className="text-emerald-400 text-xs">{JSON.stringify(result, null, 2)}</pre>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
