import React, { useState, useEffect } from 'react'
import { ServerCog, RefreshCw, Play, Square, Trash2, Database, Network, Users, CheckCircle2, XCircle, Plus, Settings2 } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

export default function Infrastructure() {
  const { addNotification } = useStore()
  const [tab, setTab] = useState('proxy')
  const [proxyStatus, setProxyStatus] = useState(null)
  const [proxyHost, setProxyHost] = useState('')
  const [proxyPort, setProxyPort] = useState('')
  const [cacheStats, setCacheStats] = useState(null)
  const [distTarget, setDistTarget] = useState('')
  const [distWorkers, setDistWorkers] = useState(3)
  const [distResult, setDistResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const loadProxy = async () => {
    try { const r = await endpoints.proxyStatus(); setProxyStatus(r.data) }
    catch (e) { setProxyStatus(null) }
  }

  const loadCacheStats = async () => {
    try { const r = await endpoints.cacheStats(); setCacheStats(r.data) }
    catch (e) { setCacheStats(null) }
  }

  useEffect(() => {
    loadProxy()
    loadCacheStats()
  }, [])

  const handleProxyConfigure = async () => {
    if (!proxyHost.trim()) return
    try {
      await endpoints.proxyConfigure({ 
        host: proxyHost, 
        port: proxyPort ? parseInt(proxyPort) : 8080,
        enabled: true 
      })
      addNotification('Proxy configured', 'success')
      loadProxy()
    } catch (e) { addNotification('Error: ' + e.message, 'error') }
  }

  const handleProxyDisable = async () => {
    try {
      await endpoints.proxyDisable()
      addNotification('Proxy disabled', 'success')
      loadProxy()
    } catch (e) { addNotification('Error: ' + e.message, 'error') }
  }

  const handleCacheAction = async (action) => {
    try {
      if (action === 'sweep') await endpoints.cacheSweep()
      else if (action === 'clear') await endpoints.cacheClear()
      addNotification(`Cache ${action} done`, 'success')
      loadCacheStats()
    } catch (e) { addNotification('Error: ' + e.message, 'error') }
  }

  const handleDistributed = async () => {
    if (!distTarget.trim()) return
    setLoading(true)
    try {
      const r = await endpoints.distributedScan({ target: distTarget, workers: distWorkers })
      setDistResult(r.data)
      addNotification('Distributed scan started', 'success')
    } catch (e) { addNotification('Error: ' + e.message, 'error') }
    finally { setLoading(false) }
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="section-header">
        <div>
          <div className="section-title flex items-center gap-2">
            <ServerCog size={18} className="text-slate-400" />
            Infrastructure
          </div>
          <div className="section-sub">Proxy configuration, recon cache, and distributed scanning</div>
        </div>
      </div>

      <div className="tab-bar">
        {[{ id: 'proxy', label: 'Proxy' }, { id: 'cache', label: 'Recon Cache' }, { id: 'distributed', label: 'Distributed Scan' }].map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} className={tab === t.id ? 'tab-active' : 'tab'}>{t.label}</button>
        ))}
      </div>

      {tab === 'proxy' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="card">
            <div className="card-header">
              <span className="card-title"><Network size={14} className="text-cyan-400" />Proxy Status</span>
              <button className="btn-icon" onClick={loadProxy}><RefreshCw size={12} /></button>
            </div>
            <div className="card-body">
              {proxyStatus ? (
                <div className="flex flex-col gap-3">
                  <div className="flex items-center gap-2">
                    {proxyStatus.enabled
                      ? <><span className="status-dot-online" /><span className="text-sm text-emerald-400">Active</span></>
                      : <><span className="status-dot-idle" /><span className="text-sm text-slate-400">Disabled</span></>}
                  </div>
                  {proxyStatus.enabled && (
                    <>
                      <div className="flex gap-2 text-xs">
                        <span className="text-slate-500">Host:</span>
                        <span className="text-slate-200 font-mono">{proxyStatus.host}:{proxyStatus.port}</span>
                      </div>
                      {proxyStatus.type && <div className="badge badge-info">{proxyStatus.type}</div>}
                      <button className="btn-danger" onClick={handleProxyDisable}><Square size={12} />Disable Proxy</button>
                    </>
                  )}
                </div>
              ) : (
                <div className="text-sm text-slate-500">No proxy configured</div>
              )}
            </div>
          </div>

          <div className="card">
            <div className="card-header"><span className="card-title"><Settings2 size={14} className="text-cyan-400" />Configure Proxy</span></div>
            <div className="card-body flex flex-col gap-3">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="label">Host</label>
                  <input className="input" placeholder="127.0.0.1" value={proxyHost} onChange={e => setProxyHost(e.target.value)} />
                </div>
                <div>
                  <label className="label">Port</label>
                  <input className="input" type="number" placeholder="8080" value={proxyPort} onChange={e => setProxyPort(e.target.value)} />
                </div>
              </div>
              <button className="btn-primary justify-center" onClick={handleProxyConfigure} disabled={!proxyHost.trim()}>
                <Network size={13} />Set Proxy
              </button>
            </div>
          </div>
        </div>
      )}

      {tab === 'cache' && (
        <div className="card max-w-xl">
          <div className="card-header">
            <span className="card-title"><Database size={14} className="text-yellow-400" />Recon Cache</span>
            <button className="btn-icon" onClick={loadCacheStats}><RefreshCw size={12} /></button>
          </div>
          <div className="card-body flex flex-col gap-4">
            {cacheStats && (
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {[
                  { label: 'Total Entries', value: cacheStats?.total_entries ?? 0 },
                  { label: 'Size on Disk', value: cacheStats?.size_mb ? `${cacheStats.size_mb} MB` : '—' },
                  { label: 'Hit Rate', value: cacheStats?.hit_rate ? `${(cacheStats.hit_rate * 100).toFixed(0)}%` : '—' },
                ].map(s => (
                  <div key={s.label} className="card-elevated p-3 text-center">
                    <div className="text-xl font-bold text-accent-primary">{s.value}</div>
                    <div className="text-xs text-slate-500 mt-1">{s.label}</div>
                  </div>
                ))}
              </div>
            )}
            <div className="flex gap-2">
              <button className="btn-secondary flex-1 justify-center" onClick={() => handleCacheAction('sweep')}>
                <RefreshCw size={12} />Sweep Expired
              </button>
              <button className="btn-danger flex-1 justify-center" onClick={() => handleCacheAction('clear')}>
                <Trash2 size={12} />Clear All
              </button>
            </div>
          </div>
        </div>
      )}

      {tab === 'distributed' && (
        <div className="card max-w-2xl">
          <div className="card-header"><span className="card-title"><Users size={14} className="text-indigo-400" />Distributed Scan</span></div>
          <div className="card-body flex flex-col gap-4">
            <div>
              <label className="label">Target Domain</label>
              <input className="input" placeholder="example.com" value={distTarget} onChange={e => setDistTarget(e.target.value)} />
            </div>
            <div>
              <label className="label">Number of Workers</label>
              <input className="input" type="number" min={1} max={20} value={distWorkers} onChange={e => setDistWorkers(+e.target.value)} />
            </div>
            <button
              className={clsx('btn-primary btn-lg justify-center', (!distTarget.trim() || loading) && 'opacity-50 cursor-not-allowed')}
              onClick={handleDistributed}
              disabled={!distTarget.trim() || loading}
            >
              <Play size={14} />{loading ? 'Starting...' : `Deploy ${distWorkers} Workers`}
            </button>
            {distResult && (
              <div className="terminal mt-2">
                <pre className="text-xs">{JSON.stringify(distResult, null, 2)}</pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
