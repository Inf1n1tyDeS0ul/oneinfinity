import React from 'react'
import clsx from 'clsx'

/**
 * AgentHoneycomb Component
 * 
 * Renders a grid of hexagons representing swarm agents.
 * Visual states:
 * - Active: Pulsing cyan border
 * - Success: Emerald border with finding count
 * - Idle: Muted slate
 */
export default function AgentHoneycomb({ agents = [], activeAgents = [], findings = [] }) {
  const agentList = Array.isArray(agents) ? agents : []
  
  return (
    <div className="flex flex-wrap gap-3 justify-center">
      {agentList.map(agent => {
        const type = typeof agent === 'string' ? agent : agent.type
        const isActive = activeAgents.includes(type)
        const findingCount = findings.filter(f => (f.selected_agent || f.agent_type || f.agent) === type).length
        
        return (
          <div key={type} className={clsx(
            "w-16 h-20 clip-hexagon flex flex-col items-center justify-center border transition-all duration-500",
            isActive ? "bg-cyan-500/10 border-cyan-500 animate-pulse" : 
            findingCount > 0 ? "bg-emerald-500/10 border-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.3)]" :
            "bg-slate-900 border-slate-800 opacity-60"
          )}>
            <span className="text-[10px] font-bold uppercase text-slate-200">{type.slice(0, 4)}</span>
            {findingCount > 0 && (
              <span className="text-[8px] text-emerald-400 mt-0.5 font-mono">
                {findingCount} FIND
              </span>
            )}
          </div>
        )
      })}
    </div>
  )
}
