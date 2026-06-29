import React from 'react'
import { ShieldAlert, Zap, Globe, Award } from 'lucide-react'
import clsx from 'clsx'

export default function FindingCard({ finding }) {
  const { severity, type, vuln_type, endpoint, url, selected_agent, agent_type, agent, priority_score, score } = finding
  const sev = (severity || 'low').toLowerCase()
  
  return (
    <div className="group glass-card p-4 hover:border-slate-600 transition-all">
      <div className="flex justify-between items-start mb-3">
        <span className={clsx(
          "px-2 py-0.5 rounded text-[9px] font-bold uppercase border",
          sev === 'critical' ? "bg-red-500/10 text-red-400 border-red-500/30" :
          sev === 'high' ? "bg-orange-500/10 text-orange-400 border-orange-500/30" :
          sev === 'medium' ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/30" :
          "bg-blue-500/10 text-blue-400 border-blue-500/30"
        )}>
          {sev}
        </span>
        <div className="flex items-center gap-1.5 text-[9px] font-mono text-cyan-500 bg-cyan-500/5 px-2 py-0.5 rounded-full border border-cyan-500/20">
          <Zap size={10} />
          {(selected_agent || agent_type || agent || 'unknown').toUpperCase()}
        </div>
      </div>
      
      <h4 className="text-sm font-bold text-slate-100 mb-1 group-hover:text-cyan-400 transition-colors">{type || vuln_type}</h4>
      <div className="flex items-center gap-1.5 text-[10px] text-slate-500 font-mono mb-4 truncate">
        <Globe size={10} />
        {endpoint || url}
      </div>
      
      <div className="flex justify-between items-center pt-3 border-t border-slate-800/50">
        <div className="flex items-center gap-1.5 text-[9px] text-slate-600 uppercase font-bold tracking-wider">
          <Award size={10} />
          Confidence
        </div>
        <span className="text-xs font-mono text-slate-300">
          {(priority_score ?? score ?? 0).toFixed(2)}
        </span>
      </div>
    </div>
  )
}
