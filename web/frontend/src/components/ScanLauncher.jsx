import React, { useState } from 'react'
import { X, Play, Zap, ChevronDown, ChevronRight, Settings2, Target, Shield, Bot, Smartphone, Globe, Cpu, Search, Radio } from 'lucide-react'
import { useStore } from '../store/useStore'
import { endpoints } from '../utils/api'
import clsx from 'clsx'

const SCAN_CATEGORIES = [
  {
    id: 'recon',
    label: 'Reconnaissance',
    icon: Search,
    color: 'text-cyan-400',
    types: [
      { value: 'recon',          label: 'Full Recon',          desc: 'Subdomains → HTTP probe → crawl → content discovery' },
      { value: 'adaptive_recon', label: 'Adaptive Recon',      desc: 'Tech detect, API map, JS endpoints — depth-aware' },
    ],
  },
  {
    id: 'scan',
    label: 'Vulnerability Scanning',
    icon: Shield,
    color: 'text-red-400',
    types: [
      { value: 'vuln_scan',      label: 'Vuln Scan',           desc: 'Nuclei + Dalfox + SQLMap + secrets' },
      { value: 'full',           label: 'Full Autonomous',     desc: 'All phases — recon → port scan → form discovery → credential intel → vuln scan → auth tests → exploit → report' },
      { value: 'graphql_scan',   label: 'GraphQL Scan',        desc: 'Introspection, fuzzing, mutations, IDOR' },
      { value: 'smuggling_scan', label: 'HTTP Smuggling',      desc: 'CL.TE, TE.CL, TE.TE detection' },
      { value: 'browser_scan',   label: 'Browser Scan',        desc: 'Headless DOM XSS, JS secrets, endpoint discovery' },
      { value: 'secrets',        label: 'Secrets Discovery',   desc: 'TruffleHog + Gitleaks — filesystem/git/GitHub' },
    ],
  },
  {
    id: 'ai',
    label: 'AI Security',
    icon: Bot,
    color: 'text-purple-400',
    types: [
      { value: 'ai_test',        label: 'AI Security Test',    desc: 'Garak, PyRIT, Rebuff, ART, Giskard' },
      { value: 'ai_redteam',     label: 'AI Red Team',         desc: 'Adversarial prompt campaigns at scale' },
      { value: 'ai_agent_test',  label: 'AI Agent Pentest',    desc: 'Tool abuse, API abuse, data exfiltration' },
    ],
  },
  {
    id: 'agents',
    label: 'Agent Modes',
    icon: Radio,
    color: 'text-indigo-400',
    types: [
      { value: 'agents',         label: 'Multi-Agent Pentest', desc: '6+ specialized agents in parallel' },
      { value: 'swarm',          label: 'Swarm Scan',          desc: 'All 8 swarm agents deployed simultaneously' },
      { value: 'research',       label: 'Autonomous Research', desc: 'Analyze → theorize → test → report loop' },
    ],
  },
  {
    id: 'mobile',
    label: 'Mobile',
    icon: Smartphone,
    color: 'text-emerald-400',
    types: [
      { value: 'mobile',         label: 'Mobile Analysis',     desc: 'Full 12-phase APK/IPA analysis pipeline' },
      { value: 'mobile_static',  label: 'Mobile Static',       desc: 'JADX decompilation, manifest, permissions' },
      { value: 'mobile_api',     label: 'Mobile API Scan',     desc: 'Discover and fuzz mobile API endpoints' },
    ],
  },
]

const PROFILES = [
  { value: 'quick',    label: 'Quick',    desc: 'Fast coverage, low noise' },
  { value: 'deep',     label: 'Deep',     desc: 'Thorough — all modules' },
  { value: 'research', label: 'Research', desc: 'Theory-driven, iterative' },
  { value: 'swarm',    label: 'Swarm',    desc: 'Parallel agent deployment' },
  { value: 'stealth',  label: 'Stealth',  desc: 'Rate-limited, evasive' },
]

const PLATFORMS = [
  { value: 'hackerone',  label: 'HackerOne' },
  { value: 'bugcrowd',   label: 'Bugcrowd' },
  { value: 'intigriti',  label: 'Intigriti' },
  { value: 'yeswehack',  label: 'YesWeHack' },
  { value: 'private',    label: 'Private' },
]

export default function ScanLauncher({ onClose }) {
  const { targets, setScans, scans, addNotification } = useStore()
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('recon')
  const [profile, setProfile] = useState('quick')
  const [auth, setAuth] = useState('')
  const [platform, setPlatform] = useState('hackerone')
  const [oob, setOob] = useState('')
  const [rate, setRate] = useState('')
  const [phases, setPhases] = useState('')
  const [rpcUrl, setRpcUrl] = useState('')
  const [githubRepo, setGithubRepo] = useState('')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [launching, setLaunching] = useState(false)
  const [activeCategory, setActiveCategory] = useState('recon')

  const handleLaunch = async () => {
    if (!target.trim()) return
    setLaunching(true)
    try {
      const options = {}
      if (rpcUrl.trim())    options.rpc_url     = rpcUrl.trim()
      if (githubRepo.trim()) options.github_repo = githubRepo.trim()

      const payload = {
        target: target.trim(),
        scan_type: scanType,
        profile,
        auth: auth || undefined,
        platform: platform || undefined,
        oob_url: oob || undefined,
        rate: rate ? parseInt(rate) : undefined,
        phases: phases || undefined,
        options: Object.keys(options).length ? options : undefined,
      }
      const r = await endpoints.launchScan(payload)
      setScans([r.data, ...scans])
      addNotification(`Scan launched: ${scanType} on ${target}`, 'success')
      onClose()
    } catch (e) {
      addNotification(`Failed to launch scan: ${e.response?.data?.detail || e.message}`, 'error')
    } finally {
      setLaunching(false)
    }
  }

  const selectedCat = SCAN_CATEGORIES.find(c => c.id === activeCategory)
  const selectedType = SCAN_CATEGORIES.flatMap(c => c.types).find(t => t.value === scanType)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="card glow-cyan w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col shadow-modal animate-[fade-in_0.15s_ease-out]">
        {/* Header */}
        <div className="card-header">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-accent-primary/10 border border-accent-primary/20 flex items-center justify-center">
              <Zap size={15} className="text-accent-primary" />
            </div>
            <div>
              <div className="text-sm font-semibold text-slate-100">Launch Scan</div>
              <div className="text-xs text-slate-500">Configure and execute security scan</div>
            </div>
          </div>
          <button onClick={onClose} className="btn-icon"><X size={15} /></button>
        </div>

        <div className="flex flex-col sm:flex-row flex-1 overflow-hidden">
          {/* Left: scan type picker */}
          <div className="w-full sm:w-44 border-b sm:border-b-0 sm:border-r border-bg-border bg-bg-secondary flex sm:flex-col overflow-x-auto sm:overflow-y-auto flex-shrink-0">
            {SCAN_CATEGORIES.map(cat => {
              const Icon = cat.icon
              const isActive = cat.id === activeCategory
              return (
                <button
                  key={cat.id}
                  onClick={() => { setActiveCategory(cat.id); setScanType(cat.types[0].value) }}
                  className={clsx(
                    'flex items-center gap-2.5 px-4 py-3 text-left border-r sm:border-r-0 sm:border-b border-bg-border transition-colors flex-shrink-0 sm:flex-shrink',
                    isActive ? 'bg-accent-primary/10 text-accent-primary border-l-2 border-l-accent-primary' : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                  )}
                >
                  <Icon size={13} className={isActive ? 'text-accent-primary' : cat.color} />
                  <span className="text-xs font-medium leading-tight whitespace-nowrap">{cat.label}</span>
                </button>
              )
            })}
          </div>

          {/* Right: config */}
          <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-5">
            {/* Target */}
            <div>
              <label className="label">Target</label>
              <input
                className="input"
                placeholder="example.com, https://api.target.com, or 0x... / Solana address"
                value={target}
                onChange={e => setTarget(e.target.value)}
                list="launcher-target-list"
                autoFocus
              />
              <datalist id="launcher-target-list">
                {targets.map(t => <option key={t.id} value={t.domain} />)}
              </datalist>
            </div>

            {/* Scan type within category */}
            <div>
              <label className="label">Scan Type</label>
              <div className="grid grid-cols-1 gap-1.5">
                {selectedCat?.types.map(st => (
                  <button
                    key={st.value}
                    onClick={() => setScanType(st.value)}
                    className={clsx(
                      'text-left px-3 py-2.5 rounded-lg border transition-all text-xs',
                      scanType === st.value
                        ? 'border-accent-primary/50 bg-accent-primary/10 text-accent-primary'
                        : 'border-bg-border bg-bg-secondary text-slate-400 hover:border-slate-500 hover:text-slate-300'
                    )}
                  >
                    <div className="font-medium">{st.label}</div>
                    <div className="text-[10px] mt-0.5 opacity-60 leading-relaxed">{st.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Profile */}
            <div>
              <label className="label">Scan Profile</label>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-1.5">
                {PROFILES.map(p => (
                  <button
                    key={p.value}
                    onClick={() => setProfile(p.value)}
                    className={clsx(
                      'px-2 py-2 rounded-lg border text-center transition-all',
                      profile === p.value
                        ? 'border-accent-primary/50 bg-accent-primary/10 text-accent-primary'
                        : 'border-bg-border bg-bg-secondary text-slate-400 hover:border-slate-500'
                    )}
                    title={p.desc}
                  >
                    <div className="text-xs font-medium">{p.label}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Platform + Auth */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="label">Platform</label>
                <select className="select" value={platform} onChange={e => setPlatform(e.target.value)}>
                  {PLATFORMS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
                </select>
              </div>
              <div>
                <label className="label">Auth Header <span className="text-slate-600">(optional)</span></label>
                <input
                  className="input"
                  placeholder="Bearer sk-..."
                  value={auth}
                  onChange={e => setAuth(e.target.value)}
                />
              </div>
            </div>

            {/* Advanced options */}
            <div>
              <button
                className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-300 transition-colors"
                onClick={() => setShowAdvanced(!showAdvanced)}
              >
                <Settings2 size={12} />
                Advanced options
                {showAdvanced ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              </button>

              {showAdvanced && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3">
                  <div>
                    <label className="label">OOB Callback URL</label>
                    <input className="input" placeholder="https://your-oob.domain" value={oob} onChange={e => setOob(e.target.value)} />
                  </div>
                  <div>
                    <label className="label">Rate Limit (req/min)</label>
                    <input className="input" type="number" placeholder="60" value={rate} onChange={e => setRate(e.target.value)} />
                  </div>
                  <div className="col-span-2">
                    <label className="label">Phase Range <span className="text-slate-600">(e.g. 1-4 or 2)</span></label>
                    <input className="input" placeholder="1-9" value={phases} onChange={e => setPhases(e.target.value)} />
                  </div>
                  <div className="col-span-2 border-t border-bg-border pt-3">
                    <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-2">Web3 / On-Chain</div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div>
                        <label className="label">EVM RPC URL <span className="text-slate-600">(optional)</span></label>
                        <input
                          className="input"
                          placeholder="https://mainnet.infura.io/v3/..."
                          value={rpcUrl}
                          onChange={e => setRpcUrl(e.target.value)}
                        />
                      </div>
                      <div>
                        <label className="label">GitHub Repo <span className="text-slate-600">(CI/CD scan)</span></label>
                        <input
                          className="input"
                          placeholder="owner/repo"
                          value={githubRepo}
                          onChange={e => setGithubRepo(e.target.value)}
                        />
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Launch */}
            <button
              className={clsx(
                'btn-primary btn-lg w-full justify-center mt-auto',
                (!target.trim() || launching) && 'opacity-50 cursor-not-allowed'
              )}
              onClick={handleLaunch}
              disabled={!target.trim() || launching}
            >
              <Play size={14} />
              {launching ? 'Launching...' : `Launch ${selectedType?.label || 'Scan'}`}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
