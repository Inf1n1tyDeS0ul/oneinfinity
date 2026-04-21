import React, { useState, useEffect } from 'react'
import { Trophy, Play, Square, RefreshCw } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import { relativeTime } from '../utils/time'
import clsx from 'clsx'

const SEV_COLORS = { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-blue-400', info: 'text-slate-400' }
const PLATFORMS = ['hackerone', 'bugcrowd', 'intigriti', 'yeswehack']
const DEPTHS = ['shallow', 'normal', 'deep']

// ── Tab: Control ─────────────────────────────────────────────────────────────
function ControlTab({ onSessionChange }) {
  const { addNotification } = useStore()
  const [platform, setPlatform] = useState('hackerone')
  const [handle, setHandle] = useState('')
  const [depth, setDepth] = useState('normal')
  const [starting, setStarting] = useState(false)
  const [sessions, setSessions] = useState([])
  const [loading, setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const loadStatus = async () => {
    setLoading(true)
    try {
      const r = await endpoints.hunterStatus()
      const data = r.data
      const s = data?.session
      setSessions(s ? [s] : [])
      setLastUpdated(new Date().toLocaleTimeString())
    } catch (err) {
      console.error('Hunter status load failed', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadStatus()
    const id = setInterval(loadStatus, 10000)
    return () => clearInterval(id)
  }, [])

  const handleStart = async () => {
    if (!handle.trim()) return addNotification('Enter a program handle', 'error')
    setStarting(true)
    try {
      await endpoints.hunterStart({ platform, handle: handle.trim(), scan_depth: depth })
      addNotification('Hunter started', 'success')
      setHandle('')
      loadStatus()
      onSessionChange && onSessionChange()
    } catch (e) { addNotification(`Failed: ${e.message}`, 'error') }
    finally { setStarting(false) }
  }

  const handleStop = async (sessionId) => {
    try {
      await endpoints.hunterStop(sessionId)
      addNotification('Session stopped', 'success')
      loadStatus()
      onSessionChange && onSessionChange()
    } catch (e) { addNotification(`Failed: ${e.message}`, 'error') }
  }

  const activeSessions = sessions.filter(s => s.status === 'running' || s.status === 'active' || s.status === 'complete')

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-4">
        <div className="card">
          <div className="text-xs font-semibold text-slate-300 mb-3">Start Hunter</div>
          <div className="flex flex-col gap-2">
            <div className="flex gap-2">
              <select className="select flex-1" value={platform} onChange={e => setPlatform(e.target.value)}>
                {PLATFORMS.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
              <select className="select w-28" value={depth} onChange={e => setDepth(e.target.value)}>
                {DEPTHS.map(d => <option key={d} value={d}>{d}</option>)}
              </select>
            </div>
            <input className="input w-full" placeholder="Program handle (e.g. example-program)"
              value={handle} onChange={e => setHandle(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleStart()} />
            <button className="btn-primary flex items-center gap-1.5 justify-center" onClick={handleStart} disabled={starting || !handle.trim()}>
              <Play size={12} /> {starting ? 'Starting...' : 'Start Hunter'}
            </button>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Active Sessions</div>
          <div className="stat-value text-green-400">{activeSessions.length}</div>
        </div>
      </div>

      <div className="card overflow-auto">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-slate-300">Active Sessions</span>
            <button className="btn-secondary flex items-center gap-1" onClick={loadStatus} disabled={loading}>
              <RefreshCw size={11} className={clsx(loading && 'animate-spin')} /> Refresh
            </button>
          </div>
          {lastUpdated && <span className="text-[10px] text-slate-500">Last updated: {lastUpdated}</span>}
        </div>
        {sessions.length === 0 ? (
          <div className="text-xs text-slate-500 p-4 text-center">{loading ? 'Loading sessions...' : 'No active hunter sessions.'}</div>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="text-slate-500 border-b border-bg-border">
                <th className="text-left py-2 px-3">ID</th>
                <th className="text-left py-2 px-3">Platform</th>
                <th className="text-left py-2 px-3">Handle</th>
                <th className="text-left py-2 px-3 w-20">Status</th>
                <th className="text-left py-2 px-3 w-20">Started</th>
                <th className="text-left py-2 px-3 w-16"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bg-border">
              {sessions.map((s) => (
                <tr key={s.session_id || s.id} className="hover:bg-white/5">
                  <td className="py-1.5 px-3 font-mono text-slate-400 text-[10px]">{(s.session_id || s.id || '—').slice(0, 12)}...</td>
                  <td className="py-1.5 px-3 text-slate-300 uppercase text-[10px]">{s.platform || '—'}</td>
                  <td className="py-1.5 px-3 text-slate-300 font-semibold">{s.handle || s.program || '—'}</td>
                  <td className="py-1.5 px-3">
                    <span className={clsx('text-[10px] px-1.5 py-0.5 rounded-full font-bold uppercase',
                      s.status === 'running' || s.status === 'active' ? 'bg-green-900/50 text-green-400' :
                      s.status === 'completed' || s.status === 'complete' ? 'bg-blue-900/50 text-blue-400' :
                      'bg-slate-700 text-slate-400')}>
                      {s.status}
                    </span>
                  </td>
                  <td className="py-1.5 px-3 text-slate-500 whitespace-nowrap">{relativeTime(s.started_at)}</td>
                  <td className="py-1.5 px-3">
                    {(s.status === 'running' || s.status === 'active' || s.status === 'complete') && (
                      <button className="p-1 rounded hover:bg-white/10" onClick={() => handleStop(s.session_id || s.id)}>
                        <Square size={11} className="text-red-400" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

// ── Tab: Findings ─────────────────────────────────────────────────────────────
function FindingsTab() {
  const { addNotification } = useStore()
  const [sessions, setSessions] = useState([])
  const [selectedSession, setSelectedSession] = useState('')
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    endpoints.hunterSessions()
      .then(r => {
        const list = r.data?.sessions || []
        setSessions(list)
        if (list.length > 0 && !selectedSession) setSelectedSession(list[0].session_id || list[0].id)
      })
      .catch(() => {})
  }, [])

  const loadFindings = async () => {
    if (!selectedSession) return
    setLoading(true)
    try {
      const r = await endpoints.hunterFindings(selectedSession)
      setFindings(r.data?.findings || r.data || [])
    } catch (e) { 
      addNotification(`Failed to load findings: ${e.message}`, 'error') 
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadFindings() }, [selectedSession])

  return (
    <div className="flex flex-col gap-4">
      <div className="card flex items-center gap-3">
        <span className="text-xs text-slate-400 font-semibold uppercase">Session:</span>
        <select className="select flex-1" value={selectedSession} onChange={e => setSelectedSession(e.target.value)}>
          <option value="">— Select session —</option>
          {sessions.map(s => (
            <option key={s.session_id || s.id} value={s.session_id || s.id}>
              {s.platform} / {s.handle || s.program} ({s.session_id || s.id || '—'})
            </option>
          ))}
        </select>
        <button className="btn-secondary" onClick={loadFindings} disabled={loading || !selectedSession}>
          <RefreshCw size={12} className={clsx(loading && 'animate-spin')} />
        </button>
      </div>

      <div className="card overflow-auto">
        <div className="text-xs font-semibold text-slate-300 mb-3">Findings ({findings.length})</div>
        <table className="w-full text-xs">
          <thead>
            <tr className="text-slate-500 border-b border-bg-border">
              <th className="text-left py-2 px-3 w-20">Severity</th>
              <th className="text-left py-2 px-3">Type</th>
              <th className="text-left py-2 px-3">Endpoint</th>
              <th className="text-left py-2 px-3 w-24">Bounty Score</th>
              <th className="text-left py-2 px-3 w-24">Payout Est.</th>
              <th className="text-left py-2 px-3 w-20">Status</th>
              <th className="text-left py-2 px-3 w-24">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-bg-border">
            {findings.map((f, i) => (
              <tr key={i} className="hover:bg-white/5">
                <td className={clsx('py-1.5 px-3 font-semibold uppercase text-[10px]', SEV_COLORS[f.severity] || 'text-slate-400')}>{f.severity}</td>
                <td className="py-1.5 px-3 text-slate-300 font-semibold">{f.type || f.vuln_type || '—'}</td>
                <td className="py-1.5 px-3 font-mono text-slate-400 truncate max-w-xs">{f.endpoint || f.url || '—'}</td>
                <td className="py-1.5 px-3">
                  <div className="w-full bg-bg-secondary h-1.5 rounded-full overflow-hidden mt-1">
                    <div className="h-full bg-accent-primary" style={{ width: `${f.bounty_score || 0}%` }} />
                  </div>
                  <div className="text-[9px] text-slate-500 mt-0.5 text-right">{f.bounty_score || 0}/100</div>
                </td>
                <td className="py-1.5 px-3 text-green-400 font-mono font-bold">{f.estimated_payout || f.bounty_estimate || '—'}</td>
                <td className="py-1.5 px-3">
                   <span className="text-[10px] px-1.5 py-0.5 rounded bg-bg-secondary text-slate-400 border border-bg-border uppercase">{f.status || 'new'}</span>
                </td>
                <td className="py-1.5 px-3">
                  <button 
                    className="text-[10px] px-2 py-1 rounded bg-blue-900/30 text-blue-400 border border-blue-500/30 hover:bg-blue-900/50"
                    onClick={() => {
                      endpoints.generateReport(f.id).then(() => addNotification('Report generated!', 'success')).catch(e => addNotification('Failed to generate report', 'error'))
                    }}
                  >
                    Gen Report
                  </button>
                </td>
              </tr>
            ))}
            {findings.length === 0 && selectedSession && (
              <tr><td colSpan={7} className="py-8 px-3 text-slate-500 text-center">{loading ? 'Loading findings...' : 'No findings for this session yet.'}</td></tr>
            )}
            {!selectedSession && (
              <tr><td colSpan={7} className="py-8 px-3 text-slate-500 text-center">Select an active session above to view results.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Tab: Programs ─────────────────────────────────────────────────────────────
function ProgramsTab() {
  const { addNotification } = useStore()
  const [programs, setPrograms] = useState([])
  const [scanning, setScanning] = useState({})
  const [loading, setLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const r = await endpoints.hunterPrograms()
      setPrograms(r.data?.programs || r.data || [])
    } catch (e) { 
      addNotification(`Failed to load programs: ${e.message}`, 'error') 
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const scanProgram = async (prog) => {
    const key = prog.handle || prog.id
    setScanning(s => ({ ...s, [key]: true }))
    try {
      await endpoints.hunterScan(prog.handle || prog.domain || prog.target, { platform: prog.platform })
      addNotification(`Scan started for ${key}`, 'success')
    } catch (e) { addNotification(`Failed: ${e.message}`, 'error') }
    finally { setScanning(s => ({ ...s, [key]: false })) }
  }

  return (
    <div className="card overflow-auto">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-semibold text-slate-300">Bounty Programs ({programs.length})</span>
        <button className="btn-secondary flex items-center gap-1" onClick={load} disabled={loading}>
          <RefreshCw size={11} className={clsx(loading && 'animate-spin')} /> Refresh
        </button>
      </div>
      {programs.length === 0 ? (
        <div className="text-xs text-slate-500 p-8 text-center">{loading ? 'Loading programs...' : 'No programs cached. Start a hunter session first.'}</div>
      ) : (
        <table className="w-full text-xs">
          <thead>
            <tr className="text-slate-500 border-b border-bg-border">
              <th className="text-left py-2 px-3">Platform</th>
              <th className="text-left py-2 px-3">Handle</th>
              <th className="text-left py-2 px-3">Scope</th>
              <th className="text-left py-2 px-3 w-24">Last Scanned</th>
              <th className="text-left py-2 px-3 w-24"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-bg-border">
            {programs.map((p, i) => {
              const key = p.handle || p.id || i
              return (
                <tr key={i} className="hover:bg-white/5">
                  <td className="py-1.5 px-3 text-slate-400 uppercase text-[10px]">{p.platform || '—'}</td>
                  <td className="py-1.5 px-3 text-cyan-400 font-bold">{p.handle || p.name || '—'}</td>
                  <td className="py-1.5 px-3 text-slate-500 truncate max-w-xs">{
                    Array.isArray(p.scope) ? p.scope.join(', ') : (p.scope || '—')
                  }</td>
                  <td className="py-1.5 px-3 text-slate-500 whitespace-nowrap">{relativeTime(p.last_scanned)}</td>
                  <td className="py-1.5 px-3">
                    <button className="btn-secondary text-[10px] flex items-center gap-1 py-1" onClick={() => scanProgram(p)} disabled={scanning[key]}>
                      <Play size={10} /> {scanning[key] ? 'Scanning...' : 'Scan'}
                    </button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
    </div>
  )
}


// ── Main ─────────────────────────────────────────────────────────────────────
const TABS = ['Control', 'Findings', 'Programs']

export default function BountyHunter() {
  const [tab, setTab] = useState(0)
  const [sessionRefresh, setSessionRefresh] = useState(0)

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
        <Trophy size={14} className="text-accent-primary" />
        Bounty Hunter
      </h1>

      <div className="flex gap-1 border-b border-bg-border pb-1">
        {TABS.map((t, i) => (
          <button key={t} onClick={() => setTab(i)}
            className={clsx('px-3 py-1.5 text-xs rounded-t transition-colors',
              tab === i ? 'bg-accent-primary/20 text-accent-primary' : 'text-slate-400 hover:text-slate-200')}>
            {t}
          </button>
        ))}
      </div>

      {tab === 0 && <ControlTab onSessionChange={() => setSessionRefresh(n => n + 1)} />}
      {tab === 1 && <FindingsTab key={sessionRefresh} />}
      {tab === 2 && <ProgramsTab />}
    </div>
  )
}
