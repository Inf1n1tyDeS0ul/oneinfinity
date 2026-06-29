import React from 'react'
import { Brain, Lightbulb, Zap, Info } from 'lucide-react'
import clsx from 'clsx'

function InsightCard({ insight }) {
  return (
    <div className="flex gap-4 p-4 bg-bg-primary/40 backdrop-blur-xl border border-bg-border/60 rounded-xl hover:border-accent-primary/40 hover:bg-bg-primary/60 transition-all duration-300 animate-fade-in group shadow-lg">
      <div className="flex-shrink-0 mt-1">
        <div className="w-10 h-10 rounded-xl bg-accent-primary/10 flex items-center justify-center border border-accent-primary/20 group-hover:border-accent-primary/40 transition-colors">
          <Brain size={20} className="text-accent-primary drop-shadow-[0_0_8px_rgba(0,217,255,0.4)]" />
        </div>
      </div>
      
      <div className="flex-1 flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono text-slate-500 font-bold uppercase tracking-tight">
              {new Date(insight.timestamp).toLocaleTimeString()}
            </span>
            <span className="px-2 py-0.5 rounded bg-accent-primary/10 border border-accent-primary/30 text-[9px] font-black text-accent-primary uppercase tracking-widest">
              {insight.trigger}
            </span>
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <div className="flex items-start gap-2">
            <Lightbulb size={14} className="mt-1 text-accent-warn flex-shrink-0" />
            <p className="text-sm text-slate-200 leading-relaxed italic font-medium">
              "{insight.hypothesis}"
            </p>
          </div>

          <div className="flex items-start gap-2">
            <Zap size={14} className="mt-1 text-accent-secondary flex-shrink-0" />
            <div className="flex flex-col gap-1">
               <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest opacity-60">Autonomous Action</span>
               <p className="text-xs text-slate-300">
                 {insight.action}
               </p>
            </div>
          </div>
        </div>

        {insight.outcome && (
          <div className="mt-1 pt-3 border-t border-bg-border/40 flex items-center gap-2 text-accent-success">
            <div className="w-1.5 h-1.5 rounded-full bg-accent-success animate-pulse" />
            <span className="text-[10px] font-bold uppercase tracking-widest">{insight.outcome}</span>
          </div>
        )}
      </div>
    </div>
  )
}

export default function InsightFeed({ insights = [] }) {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between px-2">
        <div className="flex items-center gap-2 text-accent-primary">
          <Brain size={18} className="animate-pulse" />
          <h3 className="text-sm font-bold uppercase tracking-[0.2em]">Intelligence Stream</h3>
        </div>
        <span className="text-[10px] text-slate-500 font-mono">{insights.length} events logged</span>
      </div>

      <div className="flex flex-col gap-4 max-h-[600px] overflow-y-auto pr-2 scrollbar-thin scrollbar-thumb-bg-border">
        {insights.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-slate-600 border border-dashed border-bg-border rounded-xl">
             <Brain size={32} className="opacity-20 mb-2" />
             <p className="text-xs font-mono">Waiting for AI reasoning...</p>
          </div>
        ) : (
          insights.map((insight, idx) => (
            <InsightCard key={insight.id || idx} insight={insight} />
          ))
        )}
      </div>
    </div>
  )
}
