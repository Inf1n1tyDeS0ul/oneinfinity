import React, { useState, useRef } from 'react'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend
} from 'recharts'
import { ShieldAlert, Target, Scan, Bot, TrendingUp, Activity, Plus, Play, Trash2, X, Smartphone, Upload, Globe, Cpu, Lock, CheckCircle2, ChevronDown, ChevronUp } from 'lucide-react'
import { useStore } from '../store/useStore'
import { endpoints } from '../utils/api'
import { relativeTime } from '../utils/time'
import clsx from 'clsx'

const TARGET_TYPES = [
  { value: 'web',    label: 'Web',    icon: Globe },
  { value: 'api',    label: 'API',    icon: Cpu },
  { value: 'mobile', label: 'Mobile', icon: Smartphone },
]

const TYPE_ICONS = { web: Globe, api: Cpu, mobile: Smartphone, ai: Bot }

const SEV_COLORS = {
  critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#3b82f6', info: '#6b7280'
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-bg-card border border-bg-border rounded px-3 py-2 text-xs shadow-lg">
      <div className="text-slate-400 mb-1">{label}</div>
      {payload.map(p => (
        <div key={p.name} style={{ color: p.color }}>{p.name}: {p.value}</div>
      ))}
    </div>
  )
}

export default function Dashboard() {
  const { stats, scans, setScans, vulnerabilities, campaigns, targets, setTargets, addNotification } = useStore()
  const [showAddForm, setShowAddForm] = useState(false)
  const [formData, setFormData] = useState({ name: '', domain: '', platform: 'hackerone', type: 'web' })
  const [formLoading, setFormLoading] = useState(false)
  const [mobileFile, setMobileFile] = useState(null)
  const [uploadProgress, setUploadProgress] = useState(0)
  const fileInputRef = useRef(null)
  // Auth for scan launch
  const [scanAuthTarget, setScanAuthTarget] = useState(null)
  const [showScanAuth, setShowScanAuth] = useState(false)
  const [scanAuthType, setScanAuthType] = useState('none')
  const [scanAuthValue, setScanAuthValue] = useState('')

  const handleAddTarget = async (e) => {
    e.preventDefault()
    setFormLoading(true)
    try {
      if (formData.type === 'mobile') {
        // Mobile: upload APK/IPA file first, then register as target
        if (!mobileFile) {
          addNotification('Please select an APK or IPA file', 'error')
          setFormLoading(false)
          return
        }
        const fd = new FormData()
        fd.append('file', mobileFile)
        setUploadProgress(10)
        const uploadRes = await endpoints.mobileUpload(fd)
        setUploadProgress(60)
        const appInfo = uploadRes.data?.app || {}
        const appId = uploadRes.data?.app_id || appInfo.app_id || mobileFile.name
        // Register as a target using the filename as domain
        const targetData = {
          name: formData.name || mobileFile.name,
          domain: mobileFile.name,
          platform: formData.platform,
          type: 'mobile',
          app_id: appId,
        }
        const r = await endpoints.createTarget(targetData)
        setTargets([...targets, r.data])
        setUploadProgress(100)
        addNotification(`Mobile app "${mobileFile.name}" uploaded & added`, 'success')
        setMobileFile(null)
        if (fileInputRef.current) fileInputRef.current.value = ''
      } else {
        if (!formData.domain) return
        const r = await endpoints.createTarget(formData)
        setTargets([...targets, r.data])
        const { scan_id } = r.data
        addNotification(`Target added — scan ${scan_id} queued automatically`, 'success')
      }
      setFormData({ name: '', domain: '', platform: 'hackerone', type: 'web' })
      setShowAddForm(false)
      setUploadProgress(0)
    } catch (err) {
      addNotification(`Error: ${err.response?.data?.detail || err.message}`, 'error')
    } finally {
      setFormLoading(false)
    }
  }

  const handleDeleteTarget = async (id) => {
    try {
      await endpoints.deleteTarget(id)
      setTargets(targets.filter(t => t.id !== id))
      addNotification('Target deleted', 'success')
    } catch (err) {
      addNotification(`Error: ${err.message}`, 'error')
    }
  }

  const handleDeleteScan = async (id, e) => {
    e.stopPropagation()
    if (!window.confirm('Delete this scan from history?')) return
    try {
      await endpoints.deleteScan(id)
      setScans(scans.filter(s => s.id !== id))
      addNotification('Scan deleted from history', 'success')
    } catch (err) {
      addNotification(`Error: ${err.message}`, 'error')
    }
  }

  const handleScanClick = (target) => {
    setScanAuthTarget(target)
    setShowScanAuth(false)
    setScanAuthType('none')
    setScanAuthValue('')
  }

  const handleScanTarget = async (target, authType, authValue) => {
    const targetVal = target.domain || target.target_value
    const payload = { target: targetVal, scan_type: 'full' }
    if (authType === 'cookie' && authValue) payload.session_cookie = authValue
    if (authType === 'bearer' && authValue) payload.bearer_token = authValue
    if (authType === 'header' && authValue) payload.auth_header = authValue
    try {
      await endpoints.launchScan(payload)
      addNotification(`Scan launched for ${targetVal}${authType !== 'none' ? ' (authenticated)' : ''}`, 'success')
    } catch (err) {
      addNotification(`Error: ${err.message}`, 'error')
    } finally {
      setScanAuthTarget(null)
      setScanAuthValue('')
      setScanAuthType('none')
    }
  }

  const sevDist = stats?.severity_distribution || {}
  const pieData = Object.entries(sevDist)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  // Fallback for Pie chart if empty
  const displayPieData = pieData.length > 0 ? pieData : [{ name: 'none', value: 1 }]

  const recentScans = scans.slice(0, 5)
  const recentVulns = vulnerabilities.slice(0, 5)

  return (
    <div className="flex flex-col gap-5">
      {/* Page header */}
      <div className="section-header">
        <div>
          <div className="section-title">Dashboard</div>
          <div className="text-xs text-slate-500">Autonomous offensive security — realtime overview</div>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="stat-card glow-cyan">
          <div className="flex items-center justify-between mb-2">
            <span className="stat-label">Active Scans</span>
            <Scan size={15} className="text-accent-primary/40" />
          </div>
          <div className="stat-value">{stats?.active_scans ?? 0}</div>
          <div className="stat-sub">{scans.length} total runs</div>
        </div>
        <div className="stat-card">
          <div className="flex items-center justify-between mb-2">
            <span className="stat-label">Targets</span>
            <Target size={15} className="text-accent-secondary/40" />
          </div>
          <div className="stat-value text-accent-secondary">{stats?.total_targets ?? 0}</div>
          <div className="stat-sub">{stats?.attack_surface?.domains ?? 0} domains in scope</div>
        </div>
        <div className="stat-card glow-red">
          <div className="flex items-center justify-between mb-2">
            <span className="stat-label">Vulnerabilities</span>
            <ShieldAlert size={15} className="text-red-400/40" />
          </div>
          <div className="stat-value text-red-400">{stats?.total_vulnerabilities ?? 0}</div>
          <div className="stat-sub">
            <span className="text-red-400">{sevDist.critical ?? 0} crit</span> · <span className="text-orange-400">{sevDist.high ?? 0} high</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="flex items-center justify-between mb-2">
            <span className="stat-label">AI Campaigns</span>
            <Bot size={15} className="text-accent-secondary/40" />
          </div>
          <div className="stat-value text-accent-secondary">{stats?.active_campaigns ?? 0}</div>
          <div className="stat-sub">{campaigns.length} total campaigns</div>
        </div>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        {/* Scan activity */}
        <div className="card lg:col-span-2">
          <div className="card-header">
            <div className="card-title">
              <Activity size={13} className="text-accent-primary" />
              Scan Activity (7 days)
            </div>
          </div>
          <div className="p-3 h-44">
            <ResponsiveContainer width="100%" height="100%" minWidth={100} minHeight={100}>
              <AreaChart 
                data={stats?.scan_activity && stats.scan_activity.length > 0 ? stats.scan_activity : [
                  { date: '—', scans: 0, findings: 0 }
                ]}
                margin={{ top: 5, right: 5, left: -20, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorFindings" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#6b7280' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 10, fill: '#6b7280' }} axisLine={false} tickLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="scans" stroke="#00d4ff" fill="url(#colorScans)" strokeWidth={1.5} name="Scans" />
                <Area type="monotone" dataKey="findings" stroke="#ef4444" fill="url(#colorFindings)" strokeWidth={1.5} name="Findings" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity distribution */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <ShieldAlert size={13} className="text-red-400" />
              Severity Distribution
            </div>
          </div>
          <div className="p-3 h-44 flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%" minWidth={100} minHeight={100}>
              <PieChart>
                <Pie data={displayPieData} cx="50%" cy="50%" innerRadius={45} outerRadius={65}
                     dataKey="value" paddingAngle={3}>
                  {displayPieData.map(entry => (
                    <Cell key={entry.name} fill={SEV_COLORS[entry.name] || '#6b7280'} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend iconSize={8} iconType="circle" wrapperStyle={{ fontSize: '10px' }}
                        formatter={(v) => <span style={{ color: SEV_COLORS[v] }}>{v}</span>} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {/* Recent scans */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Recent Scans</span>
          </div>
          <div className="divide-y divide-bg-border">
            {recentScans.length === 0 && (
              <div className="px-4 py-8 text-center text-sm text-slate-500">No scans yet</div>
            )}
            {recentScans.map(s => (
              <div key={s.id} className="flex items-center gap-3 px-4 py-3 hover:bg-white/[0.02] transition-colors">
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-slate-200 truncate font-medium">{s.target}</div>
                  <div className="text-xs text-slate-500 mt-0.5">{s.scan_type} · {s.profile}</div>
                </div>
                <span className={`badge-${s.status}`}>{s.status}</span>
                {s.status === 'running' && (
                  <div className="progress-bar w-16">
                    <div className="progress-fill" style={{ width: `${s.progress}%` }} />
                  </div>
                )}
                <button
                  className="btn-icon text-slate-600 hover:text-red-400 p-1 ml-1"
                  onClick={(e) => handleDeleteScan(s.id, e)}
                  title="Delete scan"
                >
                  <Trash2 size={12} />
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Recent vulnerabilities */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Recent Findings</span>
          </div>
          <div className="divide-y divide-bg-border">
            {recentVulns.length === 0 && (
              <div className="px-4 py-8 text-center text-sm text-slate-500">No findings yet</div>
            )}
            {recentVulns.map(v => (
              <div key={v.id} className="flex items-center gap-3 px-4 py-3 hover:bg-white/[0.02] transition-colors">
                <span className={`badge-${v.severity} flex-shrink-0`}>{v.severity}</span>
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-slate-200 truncate font-medium">{v.title}</div>
                  <div className="text-xs text-slate-500 mt-0.5">{v.target} · {v.attack_type}</div>
                </div>
                <span className="text-xs text-slate-500 tabular-nums">{v.cvss > 0 ? v.cvss.toFixed(1) : '—'}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Attack surface */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <TrendingUp size={13} className="text-accent-primary" />
            Attack Surface
          </div>
        </div>
        <div className="p-4 grid grid-cols-2 lg:grid-cols-4 gap-3">
          {[
            { label: 'Domains', value: stats?.attack_surface?.domains ?? 0, color: 'text-accent-primary' },
            { label: 'Endpoints', value: stats?.attack_surface?.endpoints ?? 0, color: 'text-accent-secondary' },
            { label: 'Services', value: stats?.attack_surface?.services ?? 0, color: 'text-yellow-400' },
            { label: 'AI Targets', value: stats?.attack_surface?.ai_targets ?? 0, color: 'text-emerald-400' },
          ].map(item => (
            <div key={item.label} className="flex flex-col items-center p-4 rounded-xl bg-bg-secondary border border-bg-border">
              <span className={`text-2xl font-bold font-sans tabular-nums ${item.color}`}>{item.value}</span>
              <span className="text-xs text-slate-400 mt-1.5 font-medium">{item.label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Targets */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Target size={13} className="text-accent-secondary" />
            Targets ({targets.length})
          </div>
          <button
            className="btn-primary"
            onClick={() => setShowAddForm(!showAddForm)}
          >
            {showAddForm ? <X size={11} /> : <Plus size={11} />}
            {showAddForm ? 'Cancel' : 'Add Target'}
          </button>
        </div>

        {/* Inline add form */}
        {showAddForm && (
          <form onSubmit={handleAddTarget} className="px-4 py-3 border-b border-bg-border bg-bg-secondary flex flex-col gap-3">
            {/* Type toggle */}
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider w-16">Type</span>
              <div className="flex gap-1">
                {TARGET_TYPES.map(({ value, label, icon: Icon }) => (
                  <button
                    key={value}
                    type="button"
                    onClick={() => { setFormData(f => ({ ...f, type: value })); setMobileFile(null) }}
                    className={clsx(
                      'flex items-center gap-1.5 px-3 py-1.5 rounded border text-xs transition-all',
                      formData.type === value
                        ? 'bg-accent-primary/20 border-accent-primary text-accent-primary'
                        : 'border-bg-border text-slate-400 hover:border-slate-500 hover:text-slate-300'
                    )}
                  >
                    <Icon size={11} />
                    {label}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-end gap-3 flex-wrap">
              <div className="flex flex-col gap-1">
                <label className="text-[10px] text-slate-500 uppercase tracking-wider">Name</label>
                <input
                  className="input w-40"
                  placeholder={formData.type === 'mobile' ? 'App Name' : 'My Program'}
                  value={formData.name}
                  onChange={e => setFormData(f => ({ ...f, name: e.target.value }))}
                />
              </div>

              {formData.type === 'mobile' ? (
                /* ── Mobile: file upload ── */
                <div className="flex flex-col gap-1">
                  <label className="text-[10px] text-slate-500 uppercase tracking-wider">APK / IPA File *</label>
                  <div
                    className={clsx(
                      'flex items-center gap-2 px-3 py-2 rounded border text-xs cursor-pointer transition-all w-64',
                      mobileFile
                        ? 'border-accent-primary/50 bg-accent-primary/10 text-accent-primary'
                        : 'border-dashed border-bg-border text-slate-400 hover:border-slate-500'
                    )}
                    onClick={() => fileInputRef.current?.click()}
                  >
                    {mobileFile ? (
                      <>
                        <Smartphone size={12} className="flex-shrink-0" />
                        <span className="truncate">{mobileFile.name}</span>
                        <button
                          type="button"
                          className="ml-auto text-slate-500 hover:text-red-400"
                          onClick={e => { e.stopPropagation(); setMobileFile(null); if (fileInputRef.current) fileInputRef.current.value = '' }}
                        >
                          <X size={11} />
                        </button>
                      </>
                    ) : (
                      <>
                        <Upload size={12} />
                        <span>Click to select .apk or .ipa</span>
                      </>
                    )}
                  </div>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".apk,.ipa"
                    className="hidden"
                    onChange={e => setMobileFile(e.target.files?.[0] || null)}
                  />
                </div>
              ) : (
                /* ── Web / API / AI: domain text field ── */
                <div className="flex flex-col gap-1">
                  <label className="text-[10px] text-slate-500 uppercase tracking-wider">
                    {formData.type === 'api' ? 'API Base URL *' : 'Domain *'}
                  </label>
                  <input
                    className="input w-52"
                    placeholder={formData.type === 'api' ? 'https://api.example.com' : 'example.com'}
                    required
                    value={formData.domain}
                    onChange={e => setFormData(f => ({ ...f, domain: e.target.value }))}
                  />
                </div>
              )}

              <div className="flex flex-col gap-1">
                <label className="text-[10px] text-slate-500 uppercase tracking-wider">Platform</label>
                <select
                  className="select w-36"
                  value={formData.platform}
                  onChange={e => setFormData(f => ({ ...f, platform: e.target.value }))}
                >
                  <option value="hackerone">HackerOne</option>
                  <option value="bugcrowd">Bugcrowd</option>
                  <option value="intigriti">Intigriti</option>
                  <option value="private">Private</option>
                </select>
              </div>

              <button type="submit" className="btn-primary flex items-center gap-1.5" disabled={formLoading}>
                {formLoading ? (
                  <>
                    {formData.type === 'mobile' && uploadProgress > 0 && uploadProgress < 100
                      ? `Uploading ${uploadProgress}%` : 'Adding...'}
                  </>
                ) : (
                  <>{formData.type === 'mobile' ? <><Upload size={11} /> Upload & Add</> : <><Plus size={11} /> Add</>}</>
                )}
              </button>
            </div>

            {/* Upload progress bar */}
            {formData.type === 'mobile' && uploadProgress > 0 && uploadProgress < 100 && (
              <div className="w-full h-1 bg-bg-border rounded overflow-hidden">
                <div className="h-full bg-accent-primary rounded transition-all" style={{ width: `${uploadProgress}%` }} />
              </div>
            )}
          </form>
        )}

        {/* Targets table */}
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-bg-border text-slate-500 text-left">
              <th className="px-3 py-2 font-medium">Target</th>
              <th className="px-3 py-2 font-medium">Type</th>
              <th className="px-3 py-2 font-medium">Platform</th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th className="px-3 py-2 font-medium">Last Scan</th>
              <th className="px-3 py-2 font-medium">Vulns</th>
              <th className="px-3 py-2 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-bg-border">
            {targets.length === 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-6 text-center text-slate-500">
                  No targets yet. Add one above.
                </td>
              </tr>
            )}
            {targets.map(t => (
              <tr key={t.id} className="hover:bg-white/3 transition-colors">
                <td className="px-3 py-2.5">
                  <div className="text-slate-200 font-medium">{t.domain || t.target_value}</div>
                  {t.name && t.name !== (t.domain || t.target_value) && (
                    <div className="text-[11px] text-slate-500">{t.name}</div>
                  )}
                </td>
                <td className="px-3 py-2.5">
                  {(() => {
                    const ttype = t.target_type || t.type || 'web'
                    const Icon = TYPE_ICONS[ttype] || Globe
                    return (
                      <span className="flex items-center gap-1 text-slate-400 capitalize">
                        <Icon size={11} />
                        {ttype}
                      </span>
                    )
                  })()}
                </td>
                <td className="px-3 py-2.5 text-slate-400 capitalize">{t.platform || '—'}</td>
                <td className="px-3 py-2.5">
                  <span className={clsx(
                    'badge',
                    t.status === 'active' ? 'badge-running' :
                    t.status === 'scanning' ? 'badge-running' :
                    'bg-bg-secondary border border-bg-border text-slate-400'
                  )}>
                    {t.status || 'active'}
                  </span>
                </td>
                <td className="px-3 py-2.5 text-slate-500">{relativeTime(t.last_scan_time || t.last_scan)}</td>
                <td className="px-3 py-2.5 text-slate-400">{t.vuln_count ?? 0}</td>
                <td className="px-3 py-2.5">
                  <div className="flex items-center gap-1.5">
                    <button
                      className="btn-primary flex items-center gap-1 text-[11px] py-0.5 px-2"
                      onClick={() => handleScanClick(t)}
                      title="Launch full scan"
                    >
                      <Play size={10} />
                      Scan
                    </button>
                    <button
                      className="btn-icon flex items-center text-[11px] py-0.5 px-1.5 border border-bg-border text-slate-400 hover:text-accent-primary hover:border-accent-primary rounded transition-colors"
                      onClick={() => { handleScanClick(t); setShowScanAuth(true) }}
                      title="Scan with authentication"
                    >
                      <Lock size={10} />
                    </button>
                    <button
                      className="btn-danger flex items-center gap-1 text-[11px] py-0.5 px-2"
                      onClick={() => handleDeleteTarget(t.id)}
                      title="Delete target"
                    >
                      <Trash2 size={10} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Scan launch dialog */}
      {scanAuthTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-bg-card border border-bg-border rounded-xl shadow-2xl w-full max-w-md p-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="text-sm font-semibold text-slate-200">Launch Scan</div>
                <div className="text-xs text-slate-500 mt-0.5 truncate max-w-xs">{scanAuthTarget.domain}</div>
              </div>
              <button className="btn-icon text-slate-500 hover:text-slate-200" onClick={() => setScanAuthTarget(null)}>
                <X size={15} />
              </button>
            </div>

            {/* Auth toggle */}
            <button
              className="w-full flex items-center justify-between px-3 py-2 rounded border border-bg-border text-xs text-slate-400 hover:border-accent-primary/50 hover:text-accent-primary transition-colors mb-3"
              onClick={() => setShowScanAuth(v => !v)}
            >
              <span className="flex items-center gap-1.5">
                <Lock size={11} />
                Authentication (optional)
              </span>
              {showScanAuth ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
            </button>

            {showScanAuth && (
              <div className="flex flex-col gap-2 mb-3 px-1">
                <div className="text-[10px] text-slate-500">
                  Providing credentials enables authenticated scanning — tests MFA bypass, session fixation, privilege escalation, PII in authenticated responses, and more.
                </div>
                <select
                  className="select text-xs"
                  value={scanAuthType}
                  onChange={e => { setScanAuthType(e.target.value); setScanAuthValue('') }}
                >
                  <option value="none">No authentication</option>
                  <option value="cookie">Session Cookie</option>
                  <option value="bearer">Bearer Token / JWT</option>
                  <option value="header">Custom Auth Header</option>
                </select>
                {scanAuthType !== 'none' && (
                  <input
                    className="input text-xs"
                    placeholder={
                      scanAuthType === 'cookie' ? 'session=abc123; token=xyz' :
                      scanAuthType === 'bearer' ? 'eyJhbGciOiJSUzI1NiJ9...' :
                      'Authorization: Bearer token123'
                    }
                    value={scanAuthValue}
                    onChange={e => setScanAuthValue(e.target.value)}
                  />
                )}
                {scanAuthType !== 'none' && scanAuthValue && (
                  <div className="flex items-center gap-1.5 text-[10px] text-emerald-400">
                    <CheckCircle2 size={10} />
                    Authenticated scan — additional tests will run with your credentials
                  </div>
                )}
              </div>
            )}

            <div className="flex justify-end gap-2">
              <button className="btn-secondary text-xs" onClick={() => setScanAuthTarget(null)}>Cancel</button>
              <button
                className="btn-primary flex items-center gap-1.5 text-xs"
                onClick={() => handleScanTarget(scanAuthTarget, scanAuthType, scanAuthValue)}
              >
                <Play size={11} />
                Launch Scan
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
