import React from 'react'
import { CheckCircle2, Circle } from 'lucide-react'

export default function VisualPipeline({ plan }) {
  if (!plan) return null
  return (
    <div className="flex flex-col gap-6 py-4">
      {plan.ordered_phases.map((phase, i) => {
        const isSkipped = plan.skip_phases.includes(phase)
        const override = plan.tool_overrides[phase]
        return (
          <div key={phase} className="flex items-start gap-4">
             <div className="flex flex-col items-center">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center ${isSkipped ? 'bg-slate-800 text-slate-500' : 'bg-cyan-500/20 text-cyan-400'}`}>
                   {isSkipped ? <Circle size={14} /> : <CheckCircle2 size={14} />}
                </div>
                {i < plan.ordered_phases.length - 1 && <div className="w-0.5 h-12 bg-slate-800" />}
             </div>
             <div className={`flex-1 p-3 rounded-xl border ${isSkipped ? 'border-slate-800 opacity-50' : 'border-slate-700 bg-slate-900/30'}`}>
                <div className="flex justify-between items-center">
                   <span className="font-mono text-sm uppercase">{phase}</span>
                   {override && <span className="text-[10px] bg-cyan-500/10 text-cyan-500 px-2 py-0.5 rounded-full">Tool: {override}</span>}
                </div>
                {isSkipped && <div className="text-[10px] text-slate-500 mt-1 italic">Phase skipped by adaptive planner</div>}
             </div>
          </div>
        )
      })}
    </div>
  )
}
