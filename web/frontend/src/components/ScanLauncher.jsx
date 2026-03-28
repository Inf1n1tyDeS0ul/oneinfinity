import React, { useState } from 'react'
import { X, Play, Zap } from 'lucide-react'
import { useStore } from '../store/useStore'
import { endpoints } from '../utils/api'

const SCAN_TYPES = [
  { value: 'recon',        label: 'Recon',           desc: 'Subdomain enum, URL discovery, port scan' },
  { value: 'vuln_scan',    label: 'Vulnerability Scan', desc: 'Nuclei, Dalfox, SQLMap, secrets' },
  { value: 'ai_test',      label: 'AI Security Test', desc: 'Garak, PyRIT, Rebuff, ART, Giskard' },
  { value: 'ai_redteam',   label: 'AI Red Team',      desc: 'Adversarial prompt campaigns at scale' },
  { value: 'ai_agent_test',label: 'AI Agent Pentest', desc: 'Tool abuse, API abuse, data exfiltration' },
  { value: 'full',         label: 'Full Autonomous',  desc: 'All phases — recon → scan → exploit → report' },
]

const PROFILES = ['quick', 'deep', 'research', 'swarm', 'stealth']

export default function ScanLauncher({ onClose }) {
  const { targets, setScans, scans, addNotification } = useStore()
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('recon')
  const [profile, setProfile] = useState('quick')
  const [auth, setAuth] = useState('')
  const [launching, setLaunching] = useState(false)
  const [errors, setErrors] = useState({})

  const validate = () => {
    const e = {}
    if (!target.trim()) e.target = 'Target domain is required'
    return e
  }

  const handleLaunch = async () => {
    const e = validate()
    if (Object.keys(e).length) { setErrors(e); return }
    setErrors({})
    setLaunching(true)
    try {
      const r = await endpoints.launchScan({ target, scan_type: scanType, profile, auth })
      setScans([r.data, ...scans])
      addNotification(`Scan launched: ${scanType} on ${target}`, 'success')
      onClose()
    } catch (e) {
      addNotification(`Failed to launch scan: ${e.message}`, 'error')
    } finally {
      setLaunching(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="card w-[520px] shadow-2xl glow-cyan">
        <div className="card-header">
          <div className="flex items-center gap-2">
            <Zap size={15} className="text-accent-primary" />
            <span className="text-sm font-semibold text-accent-primary">Launch Scan</span>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300">
            <X size={16} />
          </button>
        </div>

        <div className="p-5 flex flex-col gap-4">
          {/* Target */}
          <div>
            <label className="label">Target</label>
            <input
              className={`input ${errors.target ? 'input-error' : ''}`}
              placeholder="e.g. target.com or https://agent.target.com"
              value={target}
              onChange={e => { setTarget(e.target.value); if (errors.target) setErrors(p => ({...p, target: null})) }}
              list="target-list"
            />
            {errors.target && <p className="field-error">{errors.target}</p>}
            <datalist id="target-list">
              {targets.map(t => <option key={t.id} value={t.domain} />)}
            </datalist>
          </div>

          {/* Scan type */}
          <div>
            <label className="label">Scan Type</label>
            <div className="grid grid-cols-2 gap-2">
              {SCAN_TYPES.map(st => (
                <button
                  key={st.value}
                  onClick={() => setScanType(st.value)}
                  className={`text-left p-2.5 rounded border transition-all text-xs ${
                    scanType === st.value
                      ? 'border-accent-primary/60 bg-accent-primary/10 text-accent-primary'
                      : 'border-bg-border bg-bg-secondary text-slate-400 hover:border-slate-500'
                  }`}
                >
                  <div className="font-medium">{st.label}</div>
                  <div className="text-[11px] mt-0.5 opacity-70">{st.desc}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Profile + Auth */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label">Profile</label>
              <select className="select" value={profile} onChange={e => setProfile(e.target.value)}>
                {PROFILES.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </div>
            <div>
              <label className="label">Auth Header (optional)</label>
              <input
                className="input"
                placeholder="Bearer sk-..."
                value={auth}
                onChange={e => setAuth(e.target.value)}
              />
            </div>
          </div>

          {/* Launch */}
          <button
            className="btn-primary w-full flex items-center justify-center gap-2 py-2.5"
            onClick={handleLaunch}
            disabled={!target || launching}
          >
            <Play size={14} />
            {launching ? 'Launching...' : 'Launch Scan'}
          </button>
        </div>
      </div>
    </div>
  )
}
