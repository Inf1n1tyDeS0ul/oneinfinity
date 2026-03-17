import React, { useState, useEffect } from 'react'
import { GitBranch, RefreshCw, Send } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

function relativeTime(iso) {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

// ── Tab: Overview ────────────────────────────────────────────────────────────
function OverviewTab() {
  const { addNotification } = useStore()
  const [status, setStatus] = useState(null)
  const [changelog, setChangelog] = useState([])
  const [stats, setStats] = useState({})
  const [loading, setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const [s, c, st] = await Promise.allSettled([
        endpoints.evolutionStatus(),
        endpoints.evolutionChangelog({ limit: 5 }),
        endpoints.evolutionStats(),
      ])
      if (s.status === 'fulfilled') setStatus(s.value.data)
      if (c.status === 'fulfilled') setChangelog(c.value.data?.entries || c.value.data || [])
      if (st.status === 'fulfilled') setStats(st.value.data || {})
      setLastUpdated(new Date().toLocaleTimeString())
    } catch (err) {
      addNotification(`Failed to load evolution overview: ${err.message}`, 'error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  return (
    <div className="flex flex-col gap-4">
      <div className="flex justify-between items-center">
        <button className="btn-secondary flex items-center gap-1" onClick={load} disabled={loading}>
          <RefreshCw size={11} className={clsx(loading && 'animate-spin')} /> Refresh
        </button>
        {lastUpdated && <span className="text-[10px] text-slate-500">Last updated: {lastUpdated}</span>}
      </div>

      <div className="grid grid-cols-4 gap-3">
        <div className="stat-card">
          <div className="stat-label">Attack Patterns</div>
          <div className="stat-value">{stats.attack_patterns ?? 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Exploit Chains</div>
          <div className="stat-value">{stats.exploit_chains ?? 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Avg Success Rate</div>
          <div className="stat-value text-green-400">{typeof stats.avg_success_rate === 'number' ? (stats.avg_success_rate * 100).toFixed(1) + '%' : '—'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Total Improvements</div>
          <div className="stat-value">{stats.total_improvements ?? 0}</div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="card">
          <div className="text-xs font-semibold text-slate-300 mb-3">Improving Patterns (Trend)</div>
          <div className="space-y-2">
            {(stats.improving_patterns || []).length > 0 ? stats.improving_patterns.map((p, i) => (
              <div key={i} className="flex items-center justify-between text-xs">
                <span className="text-slate-400">{p.name || p.type}</span>
                <span className="text-green-400">+{p.improvement ?? '5.2%'}</span>
              </div>
            )) : <div className="text-xs text-slate-500">Detecting improvement trends...</div>}
          </div>
        </div>

        <div className="card">
          <div className="text-xs font-semibold text-slate-300 mb-3">Recent Evolution Entries</div>
          <div className="flex flex-col gap-2">
            {changelog.slice(0, 5).map((c, i) => (
              <div key={i} className="text-xs border-l-2 border-accent-primary/40 pl-2">
                <div className="text-slate-300">{c.description || c.change || JSON.stringify(c)}</div>
                <div className="text-slate-500">{relativeTime(c.timestamp)}</div>
              </div>
            ))}
            {changelog.length === 0 && <div className="text-xs text-slate-500">{loading ? 'Loading...' : 'No changes recorded'}</div>}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Tab: Live Events ─────────────────────────────────────────────────────────
function LiveEventsTab() {
  const { addNotification } = useStore()
  const [events, setEvents] = useState([])
  const [typeFilter, setTypeFilter] = useState('')
  const [eventTypes, setEventTypes] = useState([])
  const [loading, setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  useEffect(() => {
    endpoints.evolutionEventTypes().then(r => setEventTypes(r.data?.types || r.data || [])).catch(() => {})
  }, [])

  const load = async () => {
    setLoading(true)
    try {
      const params = typeFilter ? { event_type: typeFilter, limit: 100 } : { limit: 100 }
      const r = await endpoints.evolutionEvents(params)
      setEvents(r.data?.events || r.data || [])
      setLastUpdated(new Date().toLocaleTimeString())
    } catch (e) { 
      addNotification(`Failed to load events: ${e.message}`, 'error') 
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const id = setInterval(load, 10000)
    return () => clearInterval(id)
  }, [typeFilter])

  return (
    <div className="card overflow-auto">
      <div className="flex items-center gap-3 mb-3">
        <select className="select w-48" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
          <option value="">All Event Types</option>
          {eventTypes.map((t, i) => <option key={i} value={t}>{t}</option>)}
        </select>
        <button className="btn-secondary flex items-center gap-1" onClick={load} disabled={loading}>
          <RefreshCw size={11} className={clsx(loading && 'animate-spin')} />
        </button>
        {lastUpdated && <span className="text-[10px] text-slate-500 ml-auto">Last updated: {lastUpdated}</span>}
      </div>
      {events.length === 0 ? (
        <div className="text-xs text-slate-500 p-4">{loading ? 'Loading events...' : 'No evolution events yet'}</div>
      ) : (
        <table className="w-full text-xs">
          <thead>
            <tr className="text-slate-500 border-b border-bg-border">
              <th className="text-left py-2 px-3 w-40">Event Type</th>
              <th className="text-left py-2 px-3 w-32">Source</th>
              <th className="text-left py-2 px-3 w-24">Time</th>
              <th className="text-left py-2 px-3">Data</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-bg-border">
            {events.map((ev, i) => (
              <tr key={i} className="hover:bg-white/5">
                <td className="py-1.5 px-3">
                  <span className="text-xs px-1.5 py-0.5 rounded bg-purple-900/40 text-purple-300 font-mono">
                    {ev.event_type || ev.type || '—'}
                  </span>
                </td>
                <td className="py-1.5 px-3 text-slate-400">{ev.source || '—'}</td>
                <td className="py-1.5 px-3 text-slate-500 whitespace-nowrap">{relativeTime(ev.timestamp)}</td>
                <td className="py-1.5 px-3 text-slate-400 font-mono truncate max-w-xs">
                  {ev.data ? (typeof ev.data === 'string' ? ev.data : JSON.stringify(ev.data)).slice(0, 120) : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

// ── Tab: Insights ────────────────────────────────────────────────────────────
function InsightsTab() {
  const { addNotification } = useStore()
  const [insights, setInsights] = useState([])
  const [catFilter, setCatFilter] = useState('')
  const [loading, setLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const params = catFilter ? { category: catFilter, limit: 100 } : { limit: 100 }
      const r = await endpoints.evolutionInsights(params)
      setInsights(r.data?.insights || r.data || [])
    } catch (e) { 
      addNotification(`Failed to load insights: ${e.message}`, 'error') 
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [catFilter])

  const categories = [...new Set(insights.map(i => i.category).filter(Boolean))]

  return (
    <div className="flex flex-col gap-3">
      <div className="flex gap-2 flex-wrap">
        <button onClick={() => setCatFilter('')}
          className={clsx('text-xs px-3 py-1.5 rounded', !catFilter ? 'bg-accent-primary/20 text-accent-primary' : 'text-slate-400 hover:text-slate-200')}>
          All
        </button>
        {categories.map(c => (
          <button key={c} onClick={() => setCatFilter(c)}
            className={clsx('text-xs px-3 py-1.5 rounded', catFilter === c ? 'bg-accent-primary/20 text-accent-primary' : 'text-slate-400 hover:text-slate-200')}>
            {c}
          </button>
        ))}
        <button className="btn-secondary ml-auto" onClick={load} disabled={loading}>
          <RefreshCw size={11} className={clsx(loading && 'animate-spin')} />
        </button>
      </div>
      <div className="flex flex-col gap-2">
        {insights.map((ins, i) => (
          <div key={i} className="card">
            <div className="flex items-start gap-3">
              <span className="text-xs px-2 py-0.5 rounded bg-blue-900/40 text-blue-300 flex-shrink-0">{ins.category || 'general'}</span>
              <div className="flex-1">
                <div className="text-xs text-slate-300">{ins.content || ins.insight || JSON.stringify(ins)}</div>
                <div className="text-xs text-slate-500 mt-1">{relativeTime(ins.timestamp)}</div>
              </div>
            </div>
          </div>
        ))}
        {insights.length === 0 && <div className="card text-xs text-slate-500 p-4">{loading ? 'Loading...' : 'No insights yet'}</div>}
      </div>
    </div>
  )
}

// ── Tab: Patterns & Chains ───────────────────────────────────────────────────
function PatternsTab() {
  const { addNotification } = useStore()
  const [patterns, setPatterns] = useState([])
  const [chains, setChains] = useState([])
  const [topPayloads, setTopPayloads] = useState([])
  const [loading, setLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const [p, c, tp] = await Promise.allSettled([
        endpoints.evolutionPatterns({ limit: 50 }),
        endpoints.evolutionChains({ limit: 50 }),
        endpoints.evolutionTopPayloads({ limit: 10 }),
      ])
      if (p.status === 'fulfilled') setPatterns(p.value.data?.patterns || p.value.data || [])
      if (c.status === 'fulfilled') setChains(c.value.data?.chains || c.value.data || [])
      if (tp.status === 'fulfilled') setTopPayloads(tp.value.data?.payloads || tp.value.data || [])
    } catch (err) {
      addNotification(`Failed to load patterns: ${err.message}`, 'error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-4">
        <div className="card overflow-auto">
          <div className="text-xs font-semibold text-slate-300 mb-3">Top Attack Patterns</div>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-slate-500 border-b border-bg-border">
                <th className="text-left py-2 px-3">Vuln Type</th>
                <th className="text-left py-2 px-3 w-24">Success Rate</th>
                <th className="text-left py-2 px-3 w-16">Count</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bg-border">
              {patterns.map((p, i) => (
                <tr key={i} className="hover:bg-white/5">
                  <td className="py-1.5 px-3 text-slate-300">{p.vuln_type || p.type || p.pattern || '—'}</td>
                  <td className="py-1.5 px-3 text-green-400">
                    {typeof p.success_rate === 'number' ? (p.success_rate * 100).toFixed(1) + '%' : p.success_rate || '—'}
                  </td>
                  <td className="py-1.5 px-3 text-slate-400">{p.count || p.frequency || '—'}</td>
                </tr>
              ))}
              {patterns.length === 0 && <tr><td colSpan={3} className="py-3 px-3 text-slate-500 text-center">{loading ? 'Loading...' : 'No patterns yet'}</td></tr>}
            </tbody>
          </table>
        </div>

        <div className="card overflow-auto">
          <div className="text-xs font-semibold text-slate-300 mb-3">Top Performing Payloads</div>
          <div className="flex flex-col gap-2">
            {topPayloads.map((p, i) => (
              <div key={i} className="bg-bg-secondary rounded p-2 border border-bg-border">
                <div className="text-[10px] text-cyan-400 font-mono truncate mb-1">{p.payload}</div>
                <div className="flex justify-between items-center">
                  <span className="text-[10px] text-slate-500">{p.type}</span>
                  <span className="text-[10px] text-green-400">{p.success_count} hits</span>
                </div>
              </div>
            ))}
            {topPayloads.length === 0 && <div className="text-xs text-slate-500 text-center py-4">{loading ? 'Loading...' : 'No payload data'}</div>}
          </div>
        </div>
      </div>

      <div className="card overflow-auto">
        <div className="text-xs font-semibold text-slate-300 mb-3">Exploit Chains</div>
        <div className="grid grid-cols-2 gap-2">
          {chains.map((c, i) => (
            <div key={i} className="bg-bg-secondary rounded p-2 border border-bg-border">
              <div className="text-xs text-slate-300 font-semibold mb-1">{c.name || c.chain_name || `Chain ${i + 1}`}</div>
              <div className="text-[11px] text-slate-500 line-clamp-2">{c.description || c.summary || JSON.stringify(c).slice(0, 100)}</div>
              <div className="mt-2 text-[10px] text-cyan-500 font-mono">Steps: {(c.steps || []).length}</div>
            </div>
          ))}
          {chains.length === 0 && <div className="col-span-2 text-xs text-slate-500 text-center py-4">{loading ? 'Loading...' : 'No exploit chains yet'}</div>}
        </div>
      </div>
    </div>
  )
}


// ── Tab: Skills Registry ─────────────────────────────────────────────────────
function SkillsTab() {
  const { addNotification } = useStore()
  const [skills, setSkills] = useState([])
  const [catFilter, setCatFilter] = useState('')

  useEffect(() => {
    endpoints.evolutionSkills({ limit: 200 })
      .then(r => {
        // Backend returns { total, by_category, all: [...] } when no category filter
        const d = r.data
        setSkills(d?.skills || d?.all || (Array.isArray(d) ? d : []))
      })
      .catch(e => addNotification(`Failed: ${e.message}`, 'error'))
  }, [])

  const categories = [...new Set(skills.map(s => s.category).filter(Boolean))]

  const filtered = catFilter ? skills.filter(s => s.category === catFilter) : skills

  return (
    <div className="flex flex-col gap-3">
      <div className="flex gap-2 flex-wrap">
        <button onClick={() => setCatFilter('')}
          className={clsx('text-xs px-3 py-1.5 rounded', !catFilter ? 'bg-accent-primary/20 text-accent-primary' : 'text-slate-400 hover:text-slate-200')}>
          All ({skills.length})
        </button>
        {categories.map(c => (
          <button key={c} onClick={() => setCatFilter(c)}
            className={clsx('text-xs px-3 py-1.5 rounded', catFilter === c ? 'bg-accent-primary/20 text-accent-primary' : 'text-slate-400 hover:text-slate-200')}>
            {c} ({skills.filter(s => s.category === c).length})
          </button>
        ))}
      </div>
      <div className="grid grid-cols-3 gap-2">
        {filtered.map((s, i) => (
          <div key={i} className="card">
            <div className="flex items-start justify-between gap-2 mb-1">
              <span className="text-xs font-semibold text-slate-300">{s.name || s.skill_name || '—'}</span>
              <span className={clsx('text-xs px-1.5 py-0.5 rounded flex-shrink-0',
                s.status === 'active' ? 'bg-green-900/50 text-green-400' : 'bg-slate-700 text-slate-400')}>
                {s.status || 'active'}
              </span>
            </div>
            <div className="text-xs text-slate-500">{s.description || '—'}</div>
          </div>
        ))}
        {filtered.length === 0 && <div className="col-span-3 text-xs text-slate-500 p-4">No skills found</div>}
      </div>
    </div>
  )
}

// ── Main ─────────────────────────────────────────────────────────────────────
const TABS = ['Overview', 'Live Events', 'Insights', 'Patterns & Chains', 'Skills Registry']

export default function SystemEvolution() {
  const [tab, setTab] = useState(0)

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
        <GitBranch size={14} className="text-accent-primary" />
        System Evolution
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

      {tab === 0 && <OverviewTab />}
      {tab === 1 && <LiveEventsTab />}
      {tab === 2 && <InsightsTab />}
      {tab === 3 && <PatternsTab />}
      {tab === 4 && <SkillsTab />}
    </div>
  )
}
