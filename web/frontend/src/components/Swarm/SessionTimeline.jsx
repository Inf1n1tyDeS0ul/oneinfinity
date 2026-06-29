import React from 'react'
import { relativeTime } from '../../utils/time'
import { Trash2, ShieldAlert, Cpu, Activity } from 'lucide-react'
import clsx from 'clsx'

export default function SessionTimeline({ sessions, onDelete, onExpand, expandedId }) {
  return (
    <div className="relative pl-8 space-y-8 before:absolute before:inset-0 before:left-[11px] before:w-0.5 before:bg-slate-800/60">
      {sessions.map(s => {
        const id = s.session_id || s.id
        const isExpanded = expandedId === id
        
        return (
          <div key={id} className="relative group">
            {/* Timeline Dot */}
            <div className={clsx(
              "absolute -left-[30px] mt-1.5 w-6 h-6 rounded-full bg-slate-950 border-2 flex items-center justify-center transition-all",
              s.status === 'completed' ? "border-emerald-500/50 group-hover:border-emerald-400" : "border-slate-700 group-hover:border-slate-500"
            )}>
              {s.type === 'scan' || !s.type ? <Cpu size={10} className="text-slate-400" /> : <Activity size={10} className="text-slate-400" />}
            </div>

            <div 
              className={clsx(
                "glass-card p-4 transition-all cursor-pointer border border-transparent",
                isExpanded ? "border-slate-700 bg-slate-900/40" : "hover:border-slate-700/50 hover:bg-slate-900/20"
              )} 
              onClick={() => onExpand(id)}
            >
               <div className="flex justify-between items-start mb-3">
                  <div>
                     <div className="flex items-center gap-2">
                       <span className={clsx(
                         "text-[10px] font-bold uppercase px-1.5 py-0.5 rounded",
                         s.type === 'simulation' ? "bg-indigo-500/10 text-indigo-400" : "bg-cyan-500/10 text-cyan-400"
                       )}>
                         {s.type || 'scan'}
                       </span>
                       <span className="text-[10px] text-slate-500 font-mono">ID: {id}</span>
                     </div>
                     <div className="text-sm font-mono text-slate-200 mt-2 truncate max-w-md">{s.target}</div>
                  </div>
                  <button onClick={(e) => { e.stopPropagation(); onDelete(id) }} className="p-1.5 hover:bg-red-500/10 rounded-lg text-slate-600 hover:text-red-400 transition-colors">
                     <Trash2 size={13} />
                  </button>
               </div>
               
               <div className="flex flex-wrap gap-4 text-[10px] text-slate-500 uppercase font-bold tracking-wider">
                  <span className="flex items-center gap-1.5"><Activity size={10} /> {relativeTime(s.started_at || s.created_at)}</span>
                  <span className="flex items-center gap-1.5 text-emerald-500/80"><ShieldAlert size={10} /> {s.findings_count ?? s.findings?.length ?? 0} Findings</span>
                  <span className={clsx(
                    "px-2 py-0.5 rounded-full border",
                    s.status === 'completed' ? "border-emerald-500/30 text-emerald-400 bg-emerald-500/5" : 
                    s.status === 'failed' ? "border-red-500/30 text-red-400 bg-red-500/5" :
                    "border-cyan-500/30 text-cyan-400 bg-cyan-500/5"
                  )}>{s.status}</span>
               </div>
               
               {isExpanded && (
                  <div className="mt-4 pt-4 border-t border-slate-800/50">
                     <div className="bg-black/40 rounded-xl border border-slate-800 p-3 overflow-auto max-h-64 custom-scrollbar">
                        <pre className="text-[10px] text-slate-400 font-mono">{JSON.stringify(s, null, 2)}</pre>
                     </div>
                  </div>
               )}
            </div>
          </div>
        )
      })}
    </div>
  )
}
