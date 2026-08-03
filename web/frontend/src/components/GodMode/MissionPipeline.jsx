import React from 'react'
import { CheckCircle2, Clock, Loader2, XCircle, AlertCircle, StopCircle } from 'lucide-react'
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
  ai_council:        'AI Council',
}

const STATUS_CONFIG = {
  done:    { icon: CheckCircle2, color: 'text-accent-success',                          bg: 'bg-accent-success/10 border-accent-success/30',     label: 'Done' },
  running: { icon: Loader2,      color: 'text-accent-primary animate-spin',             bg: 'bg-accent-primary/10 border-accent-primary/50 shadow-glow-cyan', label: 'Running' },
  failed:  { icon: XCircle,      color: 'text-red-400',                                bg: 'bg-red-500/10 border-red-500/30',                   label: 'Failed' },
  stopped: { icon: StopCircle,   color: 'text-yellow-400',                             bg: 'bg-yellow-500/10 border-yellow-500/30',             label: 'Stopped' },
  skipped: { icon: AlertCircle,  color: 'text-yellow-400',                             bg: 'bg-yellow-500/10 border-yellow-500/30',             label: 'Skipped' },
  pending: { icon: Clock,        color: 'text-slate-600',                              bg: 'bg-bg-elevated border-bg-border',                  label: 'Pending' },
}

// A scan is "terminal" when terminated_by is any non-null value.
// In that state, any mission still showing "running" is a stale backend status —
// the scan has already stopped, so we render it as "stopped" instead.
function MissionCard({ name, status, isTerminal }) {
  const displayStatus = (isTerminal && status === 'running') ? 'stopped' : status
  const cfg = STATUS_CONFIG[displayStatus] || STATUS_CONFIG.pending
  const Icon = cfg.icon
  const label = MISSION_LABELS[name] || name.replace(/_/g, ' ')
  return (
    <div className={clsx(
      'flex items-center gap-2 px-3 py-2 rounded-xl border text-xs font-bold transition-all duration-300',
      cfg.bg
    )}>
      <Icon size={12} className={cfg.color} />
      <span className={clsx('truncate max-w-[90px]',
        displayStatus === 'running' ? 'text-accent-primary' :
        displayStatus === 'done'    ? 'text-accent-success' :
        displayStatus === 'stopped' ? 'text-yellow-400' :
        'text-slate-500'
      )}>
        {label}
      </span>
    </div>
  )
}

export default function MissionPipeline({ missions = {}, phases_complete = [], recursionLayer = 0, terminated_by = null }) {
  const isTerminal    = !!terminated_by
  const isUserStopped = terminated_by === 'stop'
  const isTimeout     = terminated_by === 'time'
  const isError       = terminated_by === 'error'
  const isComplete    = ['all_done', 'convergence'].includes(terminated_by)

  // When terminal, treat "running" missions as "stopped" for count display too
  const missionEntries = Object.entries(missions)
  const effectiveEntries = missionEntries.map(([n, s]) => [n, isTerminal && s === 'running' ? 'stopped' : s])
  const runningCount  = effectiveEntries.filter(([, s]) => s === 'running').length
  const doneCount     = effectiveEntries.filter(([, s]) => s === 'done').length
  const stoppedCount  = effectiveEntries.filter(([, s]) => s === 'stopped').length
  const totalCount    = effectiveEntries.length

  return (
    <div className="flex flex-col gap-4 p-4">
      {/* Summary bar */}
      <div className="flex items-center gap-4 text-[10px] font-bold uppercase tracking-widest text-slate-500 px-1">
        <span className="text-accent-success">{doneCount} done</span>
        {runningCount > 0 && <span className="text-accent-primary">{runningCount} running</span>}
        {stoppedCount > 0 && <span className="text-yellow-400">{stoppedCount} stopped</span>}
        {totalCount - doneCount - runningCount - stoppedCount > 0 && (
          <span>{totalCount - doneCount - runningCount - stoppedCount} pending</span>
        )}
        {/* Terminal state indicator */}
        {isUserStopped && (
          <span className="flex items-center gap-1 text-yellow-400 ml-auto">
            <StopCircle size={10} />
            Aborted by user
          </span>
        )}
        {isTimeout && (
          <span className="flex items-center gap-1 text-orange-400 ml-auto">
            <Clock size={10} />
            Time limit reached
          </span>
        )}
        {isError && (
          <span className="flex items-center gap-1 text-red-400 ml-auto">
            <XCircle size={10} />
            Terminated (error)
          </span>
        )}
        {isComplete && (
          <span className="flex items-center gap-1 text-accent-success ml-auto">
            <CheckCircle2 size={10} />
            {terminated_by === 'convergence' ? 'Converged' : 'Complete'}
          </span>
        )}
        {phases_complete.length > 0 && !terminated_by && (
          <span className="ml-auto text-accent-success">Phases: {phases_complete.join(' · ')}</span>
        )}
      </div>

      {/* Mission grid */}
      {totalCount === 0 ? (
        <div className="text-slate-600 text-xs italic px-1">Awaiting mission initialization...</div>
      ) : (
        <div className="grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-6 xl:grid-cols-8 gap-2">
          {missionEntries.map(([name, status]) => (
            <MissionCard key={name} name={name} status={status} isTerminal={isTerminal} />
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
