import React, { useState, useRef } from 'react'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend
} from 'recharts'
import { ShieldAlert, Target, Scan, Bot, TrendingUp, Activity, Plus, Play, Trash2, X, Smartphone, Upload, Globe, Cpu } from 'lucide-react'
import { useStore } from '../store/useStore'
import { endpoints } from '../utils/api'
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

function relativeTime(iso) {
  if (!iso) return 'Never'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

export default function Dashboard() {
  const { stats, scans, vulnerabilities, campaigns, targets, setTargets, addNotification } = useStore()
  const [showAddForm, setShowAddForm] = useState(false)
  const [formData, setFormData] = useState({ name: '', domain: '', platform: 'hackerone', type: 'web' })
  const [formLoading, setFormLoading] = useState(false)
  const [mobileFile, setMobileFile] = useState(null)
  const [uploadProgress, setUploadProgress] = useState(0)
  const fileInputRef = useRef(null)

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

  const handleScanTarget = async (target) => {
    try {
      await endpoints.launchScan({ target: target.domain, scan_type: 'full' })
      addNotification(`Scan launched for ${target.domain}`, 'success')
    } catch (err) {
      addNotification(`Error: ${err.message}`, 'error')
    }
  }

  const sevDist = stats?.severity_distribution || {}
  const pieData = Object.entries(sevDist)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  const recentScans = scans.slice(0, 5)
  const recentVulns = vulnerabilities.slice(0, 5)

  return (
    <div className="flex flex-col gap-4">
      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-3">
        <div className="stat-card glow-cyan">
          <div className="flex items-center justify-between mb-1">
            <span className="stat-label">Active Scans</span>
            <Scan size={16} className="text-accent-primary/50" />
          </div>
          <div className="stat-value">{stats?.active_scans ?? 0}</div>
          <div className="text-xs text-slate-500">{scans.length} total</div>
        </div>
        <div className="stat-card">
          <div className="flex items-center justify-between mb-1">
            <span className="stat-label">Targets</span>
            <Target size={16} className="text-accent-secondary/50" />
          </div>
          <div className="stat-value text-accent-secondary">{stats?.total_targets ?? 0}</div>
          <div className="text-xs text-slate-500">{stats?.attack_surface?.domains ?? 0} domains</div>
        </div>
        <div className="stat-card glow-red">
          <div className="flex items-center justify-between mb-1">
            <span className="stat-label">Vulnerabilities</span>
            <ShieldAlert size={16} className="text-red-400/50" />
          </div>
          <div className="stat-value text-red-400">{stats?.total_vulnerabilities ?? 0}</div>
          <div className="text-xs text-slate-500">
            {sevDist.critical ?? 0} critical, {sevDist.high ?? 0} high
          </div>
        </div>
        <div className="stat-card">
          <div className="flex items-center justify-between mb-1">
            <span className="stat-label">AI Campaigns</span>
            <Bot size={16} className="text-accent-secondary/50" />
          </div>
          <div className="stat-value text-accent-secondary">{stats?.active_campaigns ?? 0}</div>
          <div className="text-xs text-slate-500">{campaigns.length} total</div>
        </div>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-3 gap-3">
        {/* Scan activity */}
        <div className="card col-span-2">
          <div className="card-header">
            <div className="flex items-center gap-2 text-xs text-slate-300">
              <Activity size={13} className="text-accent-primary" />
              Scan Activity (7 days)
            </div>
          </div>
          <div className="p-3 h-44">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats?.scan_activity || []}>
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
            <div className="flex items-center gap-2 text-xs text-slate-300">
              <ShieldAlert size={13} className="text-red-400" />
              Severity Distribution
            </div>
          </div>
          <div className="p-3 h-44 flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={65}
                     dataKey="value" paddingAngle={3}>
                  {pieData.map(entry => (
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
      <div className="grid grid-cols-2 gap-3">
        {/* Recent scans */}
        <div className="card">
          <div className="card-header">
            <span className="text-xs text-slate-300">Recent Scans</span>
          </div>
          <div className="divide-y divide-bg-border">
            {recentScans.length === 0 && (
              <div className="px-4 py-6 text-center text-xs text-slate-500">No scans yet</div>
            )}
            {recentScans.map(s => (
              <div key={s.id} className="flex items-center gap-3 px-4 py-2.5 hover:bg-white/3">
                <div className="flex-1 min-w-0">
                  <div className="text-xs text-slate-200 truncate">{s.target}</div>
                  <div className="text-[11px] text-slate-500">{s.scan_type} · {s.profile}</div>
                </div>
                <span className={`badge-${s.status}`}>{s.status}</span>
                {s.status === 'running' && (
                  <div className="w-16 h-1 bg-bg-border rounded overflow-hidden">
                    <div className="h-full bg-accent-primary rounded transition-all" style={{ width: `${s.progress}%` }} />
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Recent vulnerabilities */}
        <div className="card">
          <div className="card-header">
            <span className="text-xs text-slate-300">Recent Vulnerabilities</span>
          </div>
          <div className="divide-y divide-bg-border">
            {recentVulns.length === 0 && (
              <div className="px-4 py-6 text-center text-xs text-slate-500">No findings yet</div>
            )}
            {recentVulns.map(v => (
              <div key={v.id} className="flex items-center gap-3 px-4 py-2.5 hover:bg-white/3">
                <span className={`badge-${v.severity} flex-shrink-0`}>{v.severity}</span>
                <div className="flex-1 min-w-0">
                  <div className="text-xs text-slate-200 truncate">{v.title}</div>
                  <div className="text-[11px] text-slate-500">{v.target} · {v.attack_type}</div>
                </div>
                <span className="text-xs text-slate-500">{v.cvss > 0 ? v.cvss.toFixed(1) : '—'}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Attack surface */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center gap-2 text-xs text-slate-300">
            <TrendingUp size={13} className="text-accent-primary" />
            Attack Surface
          </div>
        </div>
        <div className="p-4 grid grid-cols-4 gap-3">
          {[
            { label: 'Domains', value: stats?.attack_surface?.domains ?? 0, color: 'text-accent-primary' },
            { label: 'Endpoints', value: stats?.attack_surface?.endpoints ?? 0, color: 'text-accent-secondary' },
            { label: 'Services', value: stats?.attack_surface?.services ?? 0, color: 'text-yellow-400' },
            { label: 'AI Targets', value: stats?.attack_surface?.ai_targets ?? 0, color: 'text-emerald-400' },
          ].map(item => (
            <div key={item.label} className="flex flex-col items-center p-3 rounded bg-bg-secondary border border-bg-border">
              <span className={`text-2xl font-bold ${item.color}`}>{item.value}</span>
              <span className="text-[11px] text-slate-400 mt-1">{item.label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Targets */}
      <div className="card">
        <div className="card-header flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs text-slate-300">
            <Target size={13} className="text-accent-secondary" />
            Targets ({targets.length})
          </div>
          <button
            className="btn-primary flex items-center gap-1.5"
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
                      onClick={() => handleScanTarget(t)}
                      title="Launch full scan"
                    >
                      <Play size={10} />
                      Scan
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
    </div>
  )
}
