import React, { useState, useEffect } from 'react'
import { Wrench, CheckCircle2, XCircle, RefreshCw, Package, BarChart3, Shield, ChevronDown, ChevronRight, Search } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

export default function Tools() {
  const { addNotification } = useStore()
  const [tab, setTab] = useState('toolcheck')
  const [toolStatus, setToolStatus] = useState(null)
  const [capMap, setCapMap] = useState(null)
  const [plugins, setPlugins] = useState([])
  const [loading, setLoading] = useState(false)
  const [search, setSearch] = useState('')

  const loadToolCheck = async () => {
    setLoading(true)
    try {
      const r = await endpoints.toolsStatus()
      setToolStatus(r.data)
    } catch (e) {
      addNotification('Could not load tool status: ' + e.message, 'error')
    } finally { setLoading(false) }
  }

  const loadCapMap = async () => {
    setLoading(true)
    try {
      const r = await endpoints.toolsCapmap()
      setCapMap(r.data)
    } catch (e) {
      addNotification('Could not load capability map: ' + e.message, 'error')
    } finally { setLoading(false) }
  }

  useEffect(() => {
    if (tab === 'toolcheck') loadToolCheck()
    else if (tab === 'capmap') loadCapMap()
  }, [tab])

  return (
    <div className="flex flex-col gap-5">
      <div className="section-header">
        <div>
          <div className="section-title flex items-center gap-2">
            <Wrench size={18} className="text-yellow-400" />
            Tools &amp; Plugins
          </div>
          <div className="section-sub">Tool installation status, capability map, and plugin registry</div>
        </div>
        <button className="btn-secondary" onClick={() => tab === 'toolcheck' ? loadToolCheck() : loadCapMap()}>
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      <div className="tab-bar">
        {[
          { id: 'toolcheck', label: 'Tool Check', icon: CheckCircle2 },
          { id: 'capmap', label: 'Capability Map', icon: BarChart3 },
          { id: 'plugins', label: 'Plugins', icon: Package },
        ].map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} className={tab === t.id ? 'tab-active' : 'tab'}>
            <t.icon size={12} className="inline mr-1.5" />
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'toolcheck' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title"><Shield size={14} className="text-yellow-400" />Security Tool Status</span>
          </div>
          {loading ? (
            <div className="p-10 text-center text-slate-500 text-sm">Checking tools...</div>
          ) : toolStatus ? (
            <div className="card-body">
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                {Object.entries(toolStatus?.tools || {}).map(([name, info]) => (
                  <div key={name} className={clsx(
                    'flex items-center gap-3 p-3 rounded-lg border',
                    info?.available ? 'border-emerald-500/20 bg-emerald-500/5' : 'border-red-500/20 bg-red-500/5'
                  )}>
                    {info?.available
                      ? <CheckCircle2 size={14} className="text-emerald-400 flex-shrink-0" />
                      : <XCircle size={14} className="text-red-400 flex-shrink-0" />}
                    <div className="min-w-0">
                      <div className="text-xs font-medium text-slate-200 truncate">{name}</div>
                      {info?.version && <div className="text-[10px] text-slate-500">{info.version}</div>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-icon"><Wrench size={20} /></div>
              <div className="empty-title">Click Refresh to check tools</div>
            </div>
          )}
        </div>
      )}

      {tab === 'capmap' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title"><BarChart3 size={14} className="text-cyan-400" />Vulnerability Coverage Matrix</span>
            <div className="relative">
              <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input className="input-sm pl-7 w-48" placeholder="Search vuln class..." value={search} onChange={e => setSearch(e.target.value)} />
            </div>
          </div>
          {loading ? (
            <div className="p-10 text-center text-slate-500 text-sm">Loading capability map...</div>
          ) : capMap ? (
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Tool</th>
                    <th>Vuln Classes</th>
                    <th>Coverage</th>
                    <th>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(capMap?.tools || {})
                    .filter(([name]) => !search || name.toLowerCase().includes(search.toLowerCase()))
                    .map(([name, info]) => (
                      <tr key={name}>
                        <td className="font-mono text-xs text-accent-primary">{name}</td>
                        <td className="text-xs text-slate-400">{(info?.vuln_classes || []).join(', ') || '—'}</td>
                        <td>
                          <div className="flex items-center gap-2">
                            <div className="progress-bar w-20">
                              <div className="progress-fill" style={{ width: `${(info?.coverage || 0) * 100}%` }} />
                            </div>
                            <span className="text-xs text-slate-400">{Math.round((info?.coverage || 0) * 100)}%</span>
                          </div>
                        </td>
                        <td><span className={clsx('badge', info?.confidence > 0.8 ? 'badge-completed' : 'badge-medium')}>{info?.confidence?.toFixed(1) || '—'}</span></td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-icon"><BarChart3 size={20} /></div>
              <div className="empty-title">Click Refresh to load capability map</div>
            </div>
          )}
        </div>
      )}

      {tab === 'plugins' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title"><Package size={14} className="text-indigo-400" />Plugin Registry</span>
          </div>
          <div className="empty-state">
            <div className="empty-icon"><Package size={20} /></div>
            <div className="empty-title">Plugin registry</div>
            <div className="empty-sub">Community plugins will appear here. Use the CLI to install plugins via oneinfinity plugins list</div>
          </div>
        </div>
      )}
    </div>
  )
}
