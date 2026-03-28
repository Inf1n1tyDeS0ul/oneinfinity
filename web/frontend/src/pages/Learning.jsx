import React, { useState, useEffect } from 'react'
import { BookOpen, BarChart2, RefreshCw, TrendingUp, Target } from 'lucide-react'
import { endpoints } from '../utils/api'
import { useStore } from '../store/useStore'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import clsx from 'clsx'

export default function Learning() {
  const { addNotification } = useStore()
  const [tab, setTab] = useState('stats')
  const [stats, setStats] = useState(null)
  const [plan, setPlan] = useState(null)
  const [planTarget, setPlanTarget] = useState('')
  const [planTech, setPlanTech] = useState('')
  const [loading, setLoading] = useState(false)
  const [planLoading, setPlanLoading] = useState(false)

  const loadStats = async () => {
    setLoading(true)
    try {
      const r = await endpoints.launchScan({ scan_type: 'learn_stats' })
      setStats(r.data)
    } catch (e) {
      // fallback placeholder
      setStats(null)
    } finally { setLoading(false) }
  }

  useEffect(() => { loadStats() }, [])

  const handleGetPlan = async () => {
    if (!planTarget.trim()) return
    setPlanLoading(true)
    try {
      const r = await endpoints.launchScan({ scan_type: 'learn_plan', target: planTarget.trim(), tech: planTech })
      setPlan(r.data)
    } catch (e) {
      addNotification('Error: ' + e.message, 'error')
    } finally { setPlanLoading(false) }
  }

  const chartData = stats?.vuln_type_stats
    ? Object.entries(stats.vuln_type_stats).map(([k, v]) => ({ name: k, score: Math.round((v?.ema_score || 0) * 100), count: v?.count || 0 }))
    : []

  return (
    <div className="flex flex-col gap-5">
      <div className="section-header">
        <div>
          <div className="section-title flex items-center gap-2">
            <BookOpen size={18} className="text-emerald-400" />
            Learning System
          </div>
          <div className="section-sub">Continuous learning stats and adaptive scan planning via EMA</div>
        </div>
        <button className="btn-secondary" onClick={loadStats}>
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
        <>
          {stats ? (
            <div className="grid grid-cols-3 gap-3">
              <div className="stat-card">
                <span className="stat-label">Total Findings</span>
                <span className="stat-value">{stats?.total_findings ?? 0}</span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Vuln Types Tracked</span>
                <span className="stat-value text-emerald-400">{Object.keys(stats?.vuln_type_stats || {}).length}</span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Avg EMA Score</span>
                <span className="stat-value text-yellow-400">
                  {chartData.length > 0 ? Math.round(chartData.reduce((a, b) => a + b.score, 0) / chartData.length) : 0}%
                </span>
              </div>
              <div className="card col-span-3">
                <div className="card-header"><span className="card-title"><TrendingUp size={14} className="text-cyan-400" />EMA Scores by Vuln Type</span></div>
                <div className="p-4 h-52">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={chartData.slice(0, 15)}>
                      <XAxis dataKey="name" tick={{ fontSize: 9, fill: '#6b7280' }} angle={-30} textAnchor="end" height={50} />
                      <YAxis tick={{ fontSize: 9, fill: '#6b7280' }} domain={[0, 100]} />
                      <Tooltip
                        contentStyle={{ background: '#0f1523', border: '1px solid #1c2a42', borderRadius: 8, fontSize: 11 }}
                        itemStyle={{ color: '#e2e8f0' }}
                      />
                      <Bar dataKey="score" name="EMA Score %">
                        {chartData.slice(0, 15).map((_, i) => (
                          <Cell key={i} fill={i % 3 === 0 ? '#00d9ff' : i % 3 === 1 ? '#6366f1' : '#10b981'} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          ) : (
            <div className="card">
              <div className="empty-state">
                <div className="empty-icon"><BookOpen size={20} /></div>
                <div className="empty-title">No learning data yet</div>
                <div className="empty-sub">Run scans to build the learning database</div>
              </div>
            </div>
          )}
        </>
      )}

      {tab === 'plan' && (
        <div className="card">
          <div className="card-header"><span className="card-title"><Target size={14} className="text-cyan-400" />Adaptive Scan Plan</span></div>
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
              <div className="terminal mt-2">
                <pre className="text-xs">{JSON.stringify(plan, null, 2)}</pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
