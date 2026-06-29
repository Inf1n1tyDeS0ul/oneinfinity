import React, { useState, useEffect } from 'react'
import { GitBranch, RefreshCw, Activity, Cpu, Shield, Zap, TrendingUp, History, List, BookOpen } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import { relativeTime } from '../utils/time'
import clsx from 'clsx'
import IntelligenceLayout from '../components/Intelligence/IntelligenceLayout'
import StatCard from '../components/Intelligence/StatCard'
import StatCardSkeleton from '../components/Intelligence/StatCardSkeleton'

// ── Tab: Overview ────────────────────────────────────────────────────────────
function OverviewTab({ stats = {}, changelog = [], loading }) {
  if (loading && !stats.attack_patterns) {
    return (
      <IntelligenceLayout>
        {[1, 2, 3, 4].map(i => <StatCardSkeleton key={i} />)}
      </IntelligenceLayout>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      <IntelligenceLayout>
        <StatCard
          label="Attack Patterns"
          value={stats?.attack_patterns ?? 0}
          icon={Cpu}
          colorClass="text-cyan-400"
        />
        <StatCard
          label="Exploit Chains"
          value={stats?.exploit_chains ?? 0}
          icon={GitBranch}
          colorClass="text-purple-400"
        />
        <StatCard
          label="Avg Success Rate"
          value={typeof stats?.avg_success_rate === 'number' ? (stats.avg_success_rate * 100).toFixed(1) + '%' : '—'}
          icon={TrendingUp}
          colorClass="text-emerald-400"
        />
        <StatCard
          label="Total Improvements"
          value={stats?.total_improvements ?? 0}
          icon={Zap}
          colorClass="text-yellow-400"
        />

        <div className="card md:col-span-2">
          <div className="card-header">
            <span className="card-title text-accent-primary"><TrendingUp size={14} /> Performance Trends</span>
          </div>
          <div className="card-body">
            {(stats?.improving_patterns || []).length > 0 ? (
              <div className="space-y-3">
                {stats.improving_patterns.map((p, i) => (
                  <div key={i} className="flex items-center justify-between p-2 rounded bg-bg-primary/30 border border-bg-border/50">
                    <span className="text-xs font-mono text-slate-300">{p?.name || p?.type || 'Vector'}</span>
                    <span className="text-xs font-bold text-emerald-400">+{p?.improvement ?? '0.0%'}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-8 opacity-40">
                <Activity size={32} className="mb-2" />
                <div className="text-xs italic">Detecting evolution patterns...</div>
              </div>
            )}
          </div>
        </div>

        <div className="card md:col-span-2">
          <div className="card-header">
            <span className="card-title text-accent-purple"><History size={14} /> Recent Architecture Changes</span>
          </div>
          <div className="card-body">
            <div className="flex flex-col gap-3">
              {(changelog || []).slice(0, 5).map((c, i) => (
                <div key={i} className="group relative pl-4 border-l-2 border-purple-500/30 hover:border-purple-500 transition-all">
                  <div className="text-xs font-bold text-slate-200 group-hover:text-purple-400 transition-colors">
                    {c?.description || c?.change || 'Architecture Update'}
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono mt-0.5">{relativeTime(c?.timestamp || c?.changed_at)}</div>
                </div>
              ))}
              {(changelog || []).length === 0 && (
                <div className="text-center py-8 text-xs text-slate-600 italic">No structural changes recorded.</div>
              )}
            </div>
          </div>
        </div>
      </IntelligenceLayout>
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

  useEffect(() => {
    endpoints.evolutionEventTypes().then(r => setEventTypes(r.data?.types || r.data || [])).catch(() => {})
  }, [])

  const load = async () => {
    setLoading(true)
    try {
      const params = typeFilter ? { event_type: typeFilter, limit: 100 } : { limit: 100 }
      const r = await endpoints.evolutionEvents(params)
      setEvents(Array.isArray(r.data?.events) ? r.data.events : Array.isArray(r.data) ? r.data : [])
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
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-3">
        <select 
          className="bg-bg-secondary border border-bg-border rounded-lg px-3 py-1.5 text-xs text-slate-300 outline-none focus:border-accent-primary transition-all" 
          value={typeFilter} 
          onChange={e => setTypeFilter(e.target.value)}
        >
          <option value="">All Event Types</option>
          {(eventTypes || []).map((t, i) => <option key={i} value={t}>{String(t).replace(/_/g, ' ').toUpperCase()}</option>)}
        </select>
        <button className="btn-secondary btn-sm" onClick={load} disabled={loading}>
          <RefreshCw size={12} className={clsx(loading && 'animate-spin')} />
        </button>
      </div>

      <div className="glass-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-[11px] border-collapse">
            <thead>
              <tr className="bg-bg-elevated/50 text-slate-500 uppercase tracking-tighter border-b border-bg-border">
                <th className="text-left p-3 font-bold">Type</th>
                <th className="text-left p-3 font-bold">Source</th>
                <th className="text-left p-3 font-bold">Time</th>
                <th className="text-left p-3 font-bold">Payload</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bg-border/30">
              {(events || []).map((ev, i) => (
                <tr key={i} className="hover:bg-accent-primary/5 transition-colors group">
                  <td className="p-3">
                    <span className="px-2 py-0.5 rounded bg-accent-purple/10 text-accent-purple font-mono font-bold border border-accent-purple/20 group-hover:border-accent-purple/40">
                      {ev?.event_type || ev?.type || '—'}
                    </span>
                  </td>
                  <td className="p-3 text-slate-400 font-medium">{ev?.source || '—'}</td>
                  <td className="p-3 text-slate-500 whitespace-nowrap">{relativeTime(ev?.timestamp)}</td>
                  <td className="p-3">
                    <div className="max-w-xs xl:max-w-md truncate font-mono text-slate-600 group-hover:text-slate-400 transition-colors">
                      {ev?.data ? (typeof ev.data === 'string' ? ev.data : JSON.stringify(ev.data)) : '—'}
                    </div>
                  </td>
                </tr>
              ))}
              {(events || []).length === 0 && !loading && (
                <tr>
                  <td colSpan={4} className="p-12 text-center text-slate-500 italic">No events streaming in this window.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
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
      setInsights(Array.isArray(r.data?.insights) ? r.data.insights : Array.isArray(r.data) ? r.data : [])
    } catch (e) { 
      addNotification(`Failed to load insights: ${e.message}`, 'error') 
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [catFilter])

  const categories = [...new Set((insights || []).map(i => i?.category).filter(Boolean))]

  return (
    <div className="flex flex-col gap-4">
      <div className="flex gap-2 flex-wrap items-center">
        <button onClick={() => setCatFilter('')}
          className={clsx('text-[10px] uppercase font-bold px-3 py-1.5 rounded-full border transition-all', 
            !catFilter ? 'bg-accent-primary border-accent-primary text-black' : 'border-bg-border text-slate-400 hover:border-slate-600')}>
          All
        </button>
        {categories.map(c => (
          <button key={c} onClick={() => setCatFilter(c)}
            className={clsx('text-[10px] uppercase font-bold px-3 py-1.5 rounded-full border transition-all', 
              catFilter === c ? 'bg-accent-primary border-accent-primary text-black' : 'border-bg-border text-slate-400 hover:border-slate-600')}>
            {c}
          </button>
        ))}
        {loading && <RefreshCw size={14} className="animate-spin text-slate-600 ml-2" />}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {(insights || []).map((ins, i) => (
          <div key={i} className="glass-card p-4 flex flex-col gap-3 group hover:border-accent-primary/30 transition-all">
            <div className="flex justify-between items-start">
              <span className="text-[10px] px-2 py-0.5 rounded bg-accent-primary/10 text-accent-primary font-bold uppercase tracking-tighter border border-accent-primary/20">
                {ins?.category || 'general'}
              </span>
              <span className="text-[9px] text-slate-600 font-mono italic">{relativeTime(ins?.timestamp)}</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed group-hover:text-white transition-colors">
              {ins?.content || ins?.insight || (typeof ins === 'object' ? JSON.stringify(ins) : String(ins))}
            </p>
          </div>
        ))}
        {(insights || []).length === 0 && !loading && (
          <div className="col-span-full py-12 text-center text-slate-600 italic text-sm">No insights analyzed in this sector.</div>
        )}
      </div>
    </div>
  )
}

// ── Tab: Patterns & Chains ───────────────────────────────────────────────────
function PatternsTab() {
  const { addNotification } = useStore()
  const [patterns, setPatterns] = useState([])
  const [chains, setChains] = useState([])
  const [loading, setLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const [p, c] = await Promise.allSettled([
        endpoints.evolutionPatterns({ limit: 50, top: true }),
        endpoints.evolutionChains({ limit: 50 }),
      ])
      if (p.status === 'fulfilled') setPatterns(Array.isArray(p.value.data?.patterns) ? p.value.data.patterns : Array.isArray(p.value.data) ? p.value.data : [])
      if (c.status === 'fulfilled') setChains(Array.isArray(c.value.data?.chains) ? c.value.data.chains : Array.isArray(c.value.data) ? c.value.data : [])
    } catch (err) {
      addNotification(`Failed to load patterns: ${err.message}`, 'error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Top Attack Patterns */}
        <div className="lg:col-span-2 card">
          <div className="card-header">
            <span className="card-title text-accent-primary"><Cpu size={14} /> Learned Attack Vectors</span>
          </div>
          <div className="card-body p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-bg-elevated/30 text-slate-500 uppercase tracking-tighter border-b border-bg-border">
                    <th className="text-left p-3">Vuln Type</th>
                    <th className="text-left p-3 w-32 text-center">Confidence</th>
                    <th className="text-left p-3 w-20 text-right">Utility</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-bg-border/30">
                  {(patterns || []).map((p, i) => (
                    <tr key={i} className="hover:bg-white/5 transition-colors">
                      <td className="p-3 text-slate-200 font-bold font-mono">{p?.vuln_type || p?.type || '—'}</td>
                      <td className="p-3">
                         <div className="flex flex-col items-center gap-1">
                            <span className="text-xs font-bold text-emerald-400">
                                {typeof p?.success_rate === 'number' ? (p.success_rate * 100).toFixed(1) + '%' : p?.success_rate || '—'}
                            </span>
                            <div className="w-20 h-1 bg-bg-primary rounded-full overflow-hidden">
                                <div className="h-full bg-emerald-500" style={{ width: `${(p?.success_rate || 0) * 100}%` }} />
                            </div>
                         </div>
                      </td>
                      <td className="p-3 text-right text-slate-500 font-mono">{p?.count || p?.frequency || '—'}</td>
                    </tr>
                  ))}
                  {(patterns || []).length === 0 && (
                    <tr>
                       <td colSpan={3} className="p-12 text-center text-slate-600 italic">No patterns recorded. Run more scans to build the intelligence database.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Exploit Chains */}
        <div className="flex flex-col gap-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500 flex items-center gap-2 px-1">
            <GitBranch size={14} className="text-accent-purple" />
            Adaptive Chains
          </h3>
          <div className="flex flex-col gap-3">
             {(chains || []).map((c, i) => (
                <div key={i} className="glass-card p-3 border-l-4 border-l-accent-purple group hover:scale-[1.02] transition-all cursor-pointer">
                   <div className="text-[11px] font-black text-slate-200 uppercase mb-1">{c?.name || c?.chain_name || 'Chain'}</div>
                   <p className="text-[10px] text-slate-500 line-clamp-2 leading-snug group-hover:text-slate-300 transition-colors">
                      {c?.description || c?.summary || 'No description.'}
                   </p>
                   <div className="mt-2 flex items-center justify-between">
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-bg-elevated text-accent-purple font-mono font-bold">STEPS: {(c?.steps || []).length}</span>
                      <Activity size={10} className="text-slate-700 group-hover:text-accent-purple transition-colors" />
                   </div>
                </div>
             ))}
             {(chains || []).length === 0 && (
                <div className="py-8 text-center text-[10px] text-slate-600 border border-dashed border-bg-border rounded-xl">
                   No cross-module chains verified yet.
                </div>
             )}
          </div>
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
  const [loading, setLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const r = await endpoints.evolutionSkills()
      const d = r.data
      setSkills(Array.isArray(d?.skills) ? d.skills : Array.isArray(d?.all) ? d.all : Array.isArray(d) ? d : [])
    } catch (e) {
      addNotification(`Failed to load skills: ${e.message}`, 'error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const categories = [...new Set((skills || []).map(s => s?.category).filter(Boolean))]
  const filtered = catFilter ? (skills || []).filter(s => s?.category === catFilter) : (skills || [])

  return (
    <div className="flex flex-col gap-5">
      <div className="flex gap-2 flex-wrap items-center">
        <button onClick={() => setCatFilter('')}
          className={clsx('text-[10px] uppercase font-bold px-3 py-1.5 rounded border transition-all', 
            !catFilter ? 'bg-bg-elevated border-slate-500 text-slate-100 shadow-glow-cyan/5' : 'border-bg-border text-slate-500 hover:border-slate-600')}>
          All ({(skills || []).length})
        </button>
        {categories.map(c => (
          <button key={c} onClick={() => setCatFilter(c)}
            className={clsx('text-[10px] uppercase font-bold px-3 py-1.5 rounded border transition-all', 
              catFilter === c ? 'bg-bg-elevated border-slate-500 text-slate-100 shadow-glow-cyan/5' : 'border-bg-border text-slate-500 hover:border-slate-600')}>
            {c} ({(skills || []).filter(s => s?.category === c).length})
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
        {filtered.map((s, i) => (
          <div key={i} className="bg-bg-secondary/40 border border-bg-border rounded-xl p-3 hover:border-slate-700 transition-all flex flex-col gap-2 relative overflow-hidden group">
            <div className="flex items-center justify-between relative z-10">
              <span className="text-[11px] font-black text-slate-200 truncate pr-4">{s?.name || s?.skill_name || 'Skill'}</span>
              <div className={clsx('w-2 h-2 rounded-full shadow-lg', s?.status === 'active' ? 'bg-emerald-500 shadow-emerald-500/20' : 'bg-slate-700')} />
            </div>
            <p className="text-[10px] text-slate-500 line-clamp-3 leading-relaxed relative z-10 group-hover:text-slate-300 transition-colors">
              {s?.description || 'No detailed documentation available for this autonomous module.'}
            </p>
            <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
               <Cpu size={48} className="text-accent-primary" />
            </div>
          </div>
        ))}
        {filtered.length === 0 && !loading && (
          <div className="col-span-full py-12 text-center text-slate-700 font-mono text-[10px]">REGISTRY EMPTY. RE-INITIALIZING TRACKER...</div>
        )}
      </div>
    </div>
  )
}

// ── Main Component ───────────────────────────────────────────────────────────
const TABS = [
  { id: 'overview', label: 'Strategic Overview', icon: Activity },
  { id: 'events',   label: 'Live Intelligence', icon: Zap },
  { id: 'insights', label: 'AI Analytics',      icon: BookOpen },
  { id: 'patterns', label: 'Learned Vectors',   icon: GitBranch },
  { id: 'skills',   label: 'Skills Registry',   icon: List },
]

export default function SystemEvolution() {
  const { addNotification } = useStore()
  const [tab, setTab] = useState('overview')
  const [stats, setStats] = useState({})
  const [changelog, setChangelog] = useState([])
  const [loading, setLoading] = useState(false)
  const [lastSync, setLastSync] = useState(null)

  const loadData = async () => {
    setLoading(true)
    try {
      const [st, c] = await Promise.allSettled([
        endpoints.evolutionStats(),
        endpoints.evolutionChangelog({ limit: 20 }),
      ])
      if (st.status === 'fulfilled') setStats(st.value.data || {})
      if (c.status === 'fulfilled') setChangelog(Array.isArray(c.value.data?.entries) ? c.value.data.entries : Array.isArray(c.value.data) ? c.value.data : [])
      setLastSync(new Date().toLocaleTimeString())
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
    const int = setInterval(loadData, 30000)
    return () => clearInterval(int)
  }, [])

  return (
    <div className="flex flex-col gap-6">
      {/* Header Area */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 px-2">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-accent-primary/10 border border-accent-primary/20">
              <GitBranch size={20} className="text-accent-primary" />
            </div>
            <div>
              <h1 className="text-xl font-black text-slate-100 tracking-tighter uppercase">Self-Evolving Architecture</h1>
              <div className="flex items-center gap-2 mt-1">
                <span className="flex items-center gap-1.5 text-[9px] font-bold text-emerald-400 uppercase tracking-widest">
                  <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                  Cognitive Engine Active
                </span>
                <span className="text-[9px] text-slate-600 font-mono font-medium opacity-50">LATEST_PASS: 09:41_SEC_SYNC</span>
              </div>
            </div>
          </div>
        </div>
        
        <div className="flex items-center gap-4">
           {lastSync && <span className="text-[10px] font-mono text-slate-600 uppercase">Synced {lastSync}</span>}
           <button 
             onClick={loadData} 
             disabled={loading}
             className="btn-secondary flex items-center gap-2 text-xs py-1.5 px-4 rounded-xl border-slate-700/50"
           >
             <RefreshCw size={14} className={clsx(loading && 'animate-spin')} />
             Refresh Intel
           </button>
        </div>
      </div>

      {/* Navigation Capsule */}
      <div className="flex p-1 bg-bg-secondary/40 rounded-2xl border border-bg-border w-fit self-center md:self-start">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={clsx(
              "flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all duration-300",
              tab === t.id 
                ? "bg-bg-elevated text-accent-primary border border-slate-700/50 shadow-glow-cyan/10" 
                : "text-slate-500 hover:text-slate-300"
            )}
          >
            <t.icon size={14} />
            <span className="hidden sm:inline">{t.label}</span>
          </button>
        ))}
      </div>

      {/* Active Tab Body */}
      <div className="mt-2 transition-all duration-500 animate-in fade-in slide-in-from-bottom-2">
        {tab === 'overview' && <OverviewTab stats={stats} changelog={changelog} loading={loading} />}
        {tab === 'events'   && <LiveEventsTab />}
        {tab === 'insights' && <InsightsTab />}
        {tab === 'patterns' && <PatternsTab />}
        {tab === 'skills'   && <SkillsTab />}
      </div>
    </div>
  )
}
