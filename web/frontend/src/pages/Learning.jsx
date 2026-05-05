import React, { useState, useEffect } from 'react'
import { BookOpen, BarChart2, RefreshCw, TrendingUp, Target, Wrench, ShieldAlert, Database, Zap } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import clsx from 'clsx'
import IntelligenceLayout from '../components/Intelligence/IntelligenceLayout'
import StatCard from '../components/Intelligence/StatCard'

export default function Learning() {
  const { addNotification } = useStore()
  const [tab, setTab]             = useState('stats')
  const [stats, setStats]         = useState(null)
  const [plan, setPlan]           = useState(null)
  const [planTarget, setPlanTarget] = useState('')
  const [planTech, setPlanTech]   = useState('')
  const [loading, setLoading]     = useState(false)
  const [planLoading, setPlanLoading] = useState(false)

  const loadStats = async () => {
    setLoading(true)
    try {
      const r = await endpoints.learningStats()
      setStats(r.data)
    } catch (e) {
      addNotification('Could not load learning stats: ' + e.message, 'error')
      setStats(null)
    } finally { setLoading(false) }
  }

  useEffect(() => { loadStats() }, [])

  const handleGetPlan = async () => {
    if (!planTarget.trim()) return
    setPlanLoading(true)
    try {
      const r = await endpoints.learningPlan(planTarget.trim(), planTech.trim())
      setPlan(r.data)
    } catch (e) {
      addNotification('Error: ' + e.message, 'error')
    } finally { setPlanLoading(false) }
  }

  // Chart data: vuln types by EMA score
  const chartData = stats?.vuln_type_stats
    ? Object.entries(stats.vuln_type_stats)
        .map(([k, v]) => ({ name: k, score: Math.round((v?.ema_score || 0) * 100), count: v?.count || 0 }))
        .sort((a, b) => b.score - a.score)
    : []

  const avgEma = chartData.length > 0
    ? Math.round(chartData.reduce((a, b) => a + b.score, 0) / chartData.length)
    : 0

  return (
    <div className="flex flex-col gap-5">
      <div className="section-header">
        <div>
          <div className="section-title flex items-center gap-2">
            <BookOpen size={18} className="text-emerald-400" />
            Learning System
          </div>
          <div className="section-sub">Continuous learning via EMA — adapts scan strategy based on past findings</div>
        </div>
        <button className="btn-secondary" onClick={loadStats} disabled={loading}>
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      <div className="tab-bar">
        {[{ id: 'stats', label: 'Statistics' }, { id: 'plan', label: 'Adaptive Plan' }].map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} className={tab === t.id ? 'tab-active' : 'tab'}>{t.label}</button>
        ))}
      </div>

      {tab === 'stats' && (
        <IntelligenceLayout>
          {/* Summary stats */}
          <StatCard
            label="Confirmed Findings"
            value={stats?.total_findings ?? 0}
            icon={ShieldAlert}
            colorClass="text-emerald-400"
          />
          <StatCard
            label="Scans Completed"
            value={stats?.sessions ?? 0}
            icon={Zap}
            colorClass="text-cyan-400"
          />
          <StatCard
            label="Unique Targets"
            value={stats?.unique_targets ?? 0}
            icon={Target}
            colorClass="text-indigo-400"
          />
          <StatCard
            label="Avg EMA Score"
            value={`${avgEma}%`}
            icon={TrendingUp}
            colorClass="text-yellow-400"
          />

          {stats ? (
            <>
              {/* EMA bar chart */}
              <div className="card md:col-span-4 lg:col-span-4">
                <div className="card-header">
                  <span className="card-title"><TrendingUp size={14} className="text-cyan-400" />EMA Score by Vulnerability Type</span>
                </div>
                {chartData.length > 0 ? (
                  <div className="p-4 h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={chartData.slice(0, 15)}>
                        <XAxis dataKey="name" tick={{ fontSize: 9, fill: '#6b7280' }} angle={-30} textAnchor="end" height={60} />
                        <YAxis tick={{ fontSize: 9, fill: '#6b7280' }} domain={[0, 100]} unit="%" />
                        <Tooltip
                          contentStyle={{ background: '#0f1523', border: '1px solid #1c2a42', borderRadius: 12, fontSize: 11, boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.5)' }}
                          itemStyle={{ color: '#e2e8f0' }}
                          cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                          formatter={(v, n, p) => [`${v}% (${p.payload.count} findings)`, 'EMA Score']}
                        />
                        <Bar dataKey="score" radius={[4, 4, 0, 0]}>
                          {chartData.slice(0, 15).map((entry, i) => (
                            <Cell
                              key={i}
                              fill={i % 3 === 0 ? '#00d9ff' : i % 3 === 1 ? '#6366f1' : '#10b981'}
                              className={entry.score > 50 ? 'neon-glow-cyan' : ''}
                            />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                ) : (
                  <div className="empty-state">
                    <div className="empty-icon"><TrendingUp size={20} /></div>
                    <div className="empty-title">No EMA data yet</div>
                    <div className="empty-sub">EMA scores build up as scans complete and findings are recorded</div>
                  </div>
                )}
              </div>

              {/* Top vuln types */}
              <div className="card md:col-span-2">
                <div className="card-header">
                  <span className="card-title"><ShieldAlert size={14} className="text-red-400" />Top Vulnerability Types</span>
                </div>
                <div className="card-body flex flex-col gap-1">
                  {(stats.top_vuln_types || []).length > 0 ? (
                    stats.top_vuln_types.map((v, i) => (
                      <div key={i} className="flex items-center gap-3 py-1.5 border-b border-bg-border last:border-0">
                        <span className="w-5 h-5 rounded-full bg-accent-primary/15 flex items-center justify-center text-[10px] text-accent-primary font-bold flex-shrink-0">{i + 1}</span>
                        <span className="flex-1 text-sm text-slate-300 font-mono">{v.vuln_type}</span>
                        <span className="badge badge-info">{v.count} findings</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-xs text-slate-600 py-4 text-center">No data yet</div>
                  )}
                </div>
              </div>

              {/* Top tools */}
              <div className="card md:col-span-2">
                <div className="card-header">
                  <span className="card-title"><Wrench size={14} className="text-orange-400" />Top Performing Tools</span>
                </div>
                <div className="card-body flex flex-col gap-1">
                  {(stats.top_tools || []).length > 0 ? (
                    stats.top_tools.map((t, i) => (
                      <div key={i} className="flex items-center gap-3 py-1.5 border-b border-bg-border last:border-0">
                        <span className="w-5 h-5 rounded-full bg-orange-500/15 flex items-center justify-center text-[10px] text-orange-400 font-bold flex-shrink-0">{i + 1}</span>
                        <span className="flex-1 text-sm text-slate-300 font-mono">{t.tool}</span>
                        <span className="badge badge-warn">{t.findings} findings</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-xs text-slate-600 py-4 text-center">No data yet</div>
                  )}
                </div>
              </div>
            </>
          ) : !loading && (
            <div className="card md:col-span-4">
              <div className="empty-state">
                <div className="empty-icon"><Database size={20} /></div>
                <div className="empty-title">No learning data yet</div>
                <div className="empty-sub">Run scans to build the learning database</div>
              </div>
            </div>
          )}
        </IntelligenceLayout>
      )}

      {tab === 'plan' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title"><Target size={14} className="text-cyan-400" />Adaptive Scan Plan</span>
          </div>
          <div className="card-body flex flex-col gap-4">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label">Target Domain</label>
                <input className="input" placeholder="example.com" value={planTarget} onChange={e => setPlanTarget(e.target.value)} />
              </div>
              <div>
                <label className="label">Tech Stack <span className="text-slate-600">(comma-separated)</span></label>
                <input className="input" placeholder="nginx,php,mysql" value={planTech} onChange={e => setPlanTech(e.target.value)} />
              </div>
            </div>
            <button className="btn-primary justify-center" onClick={handleGetPlan} disabled={!planTarget.trim() || planLoading}>
              <BarChart2 size={13} />
              {planLoading ? 'Generating...' : 'Generate Adaptive Plan'}
            </button>

            {plan && (
              <div className="flex flex-col gap-3 mt-1">
                <div className="text-xs text-slate-500 leading-relaxed whitespace-pre-wrap border border-bg-border rounded-xl p-3 bg-bg-secondary font-mono">
                  {plan.description}
                </div>
                <div className="grid grid-cols-2 gap-3">
                  {plan.priority_phases?.length > 0 && (
                    <div>
                      <div className="label mb-2">Priority Phases</div>
                      <div className="flex flex-wrap gap-1">
                        {plan.priority_phases.map(p => (
                          <span key={p} className="badge badge-info">{p}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {plan.focus_vulns?.length > 0 && (
                    <div>
                      <div className="label mb-2">Focus Vulnerabilities</div>
                      <div className="flex flex-wrap gap-1">
                        {plan.focus_vulns.map(v => (
                          <span key={v} className="badge badge-warn">{v}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {plan.skip_phases?.length > 0 && (
                    <div>
                      <div className="label mb-2">Skipped Phases</div>
                      <div className="flex flex-wrap gap-1">
                        {plan.skip_phases.map(p => (
                          <span key={p} className="badge badge-error">{p}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {Object.keys(plan.tool_overrides || {}).length > 0 && (
                    <div>
                      <div className="label mb-2">Tool Overrides</div>
                      <div className="flex flex-col gap-1">
                        {Object.entries(plan.tool_overrides).map(([k, v]) => (
                          <div key={k} className="text-xs text-slate-400"><span className="text-slate-500">{k}:</span> {v}</div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
