import React from 'react'
import { CheckCircle2, Clock, Loader2, XCircle, AlertCircle } from 'lucide-react'
import clsx from 'clsx'

const MISSION_LABELS = {
  foundation:        'Foundation',
  full_scan:         'Full Scan',
  fuzz:              'Fuzz',
  org_intel:         'Org Intel',
  research:          'Research',
  swarm:             'Swarm',
  auth_test:         'Auth Test',
  secrets_scan:      'Secrets',
  ai_redteam:        'AI RedTeam',
  ai_agent_test:     'AI Agent',
  llm_artifact_idor: 'LLM IDOR',
  business_logic:    'Biz Logic',
  custom_tests:      'Custom Tests',
  chains:            'Chains',
  report:            'Report',
  // New AI missions
  adaptive_plan:     'Adaptive Plan',
  adversarial_waf:   'Adv WAF',
  browser_reasoning: 'Browser AI',
  attack_planner:    'Attack Planner',
  api_abuse:         'API Abuse',
  graph_risk_analyzer: 'Graph Risk',
  ai_validation:     'AI Validation',
  poc_generator:     'PoC Gen',
}

const STATUS_CONFIG = {
  done:    { icon: CheckCircle2, color: 'text-accent-success', bg: 'bg-accent-success/10 border-accent-success/30', label: 'Done' },
  running: { icon: Loader2,      color: 'text-accent-primary animate-spin', bg: 'bg-accent-primary/10 border-accent-primary/50 shadow-glow-cyan', label: 'Running' },
  failed:  { icon: XCircle,      color: 'text-red-400',         bg: 'bg-red-500/10 border-red-500/30', label: 'Failed' },
  skipped: { icon: AlertCircle,  color: 'text-yellow-400',      bg: 'bg-yellow-500/10 border-yellow-500/30', label: 'Skipped' },
  pending: { icon: Clock,        color: 'text-slate-600',       bg: 'bg-bg-elevated border-bg-border', label: 'Pending' },
}

function MissionCard({ name, status }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.pending
  const Icon = cfg.icon
  const label = MISSION_LABELS[name] || name.replace(/_/g, ' ')
  return (
    <div className={clsx(
      'flex items-center gap-2 px-3 py-2 rounded-xl border text-xs font-bold transition-all duration-300',
      cfg.bg
    )}>
      <Icon size={12} className={cfg.color} />
      <span className={clsx('truncate max-w-[90px]', status === 'running' ? 'text-accent-primary' : status === 'done' ? 'text-accent-success' : 'text-slate-500')}>
        {label}
      </span>
    </div>
  )
}

export default function MissionPipeline({ missions = {}, phases_complete = [], recursionLayer = 0 }) {
  // Determine display order: foundation first (synthetic), then missions in order
  const missionEntries = Object.entries(missions)
  const runningCount  = missionEntries.filter(([, s]) => s === 'running').length
  const doneCount     = missionEntries.filter(([, s]) => s === 'done').length
  const totalCount    = missionEntries.length

  return (
    <div className="flex flex-col gap-4 p-4">
      {/* Summary bar */}
      <div className="flex items-center gap-4 text-[10px] font-bold uppercase tracking-widest text-slate-500 px-1">
        <span className="text-accent-success">{doneCount} done</span>
        <span className="text-accent-primary">{runningCount} running</span>
        <span>{totalCount - doneCount - runningCount} pending</span>
        {phases_complete.length > 0 && (
          <span className="ml-auto text-accent-success">Phases: {phases_complete.join(' · ')}</span>
        )}
      </div>

      {/* Mission grid */}
      {totalCount === 0 ? (
        <div className="text-slate-600 text-xs italic px-1">Awaiting mission initialization...</div>
      ) : (
        <div className="grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-6 xl:grid-cols-8 gap-2">
          {missionEntries.map(([name, status]) => (
            <MissionCard key={name} name={name} status={status} />
          ))}
        </div>
      )}

      {/* Recursion indicator */}
      {recursionLayer > 0 && (
        <div className="text-[10px] font-mono text-accent-secondary px-1">
          ↻ Recursion Layer {recursionLayer} active
        </div>
      )}
    </div>
  )
}
