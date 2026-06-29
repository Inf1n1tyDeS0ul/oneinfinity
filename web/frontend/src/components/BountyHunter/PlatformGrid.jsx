import React from 'react'
import { Globe, Shield, Zap, Flame, ExternalLink } from 'lucide-react'
import clsx from 'clsx'

const PLATFORMS = [
  { id: 'hackerone', name: 'HackerOne', icon: Shield, color: 'text-blue-400', accent: '#00b4ff' },
  { id: 'bugcrowd',  name: 'Bugcrowd',  icon: Zap,    color: 'text-orange-400', accent: '#f97316' },
  { id: 'intigriti', name: 'Intigriti', icon: Flame,  color: 'text-red-400',    accent: '#ef4444' },
  { id: 'yeswehack', name: 'YesWeHack', icon: Globe,  color: 'text-emerald-400', accent: '#10b981' },
]

export default function PlatformGrid({ selected, onSelect, disabled }) {
  return (
    <div className="grid grid-cols-2 gap-3">
      {PLATFORMS.map(p => {
        const isActive = selected === p.id
        return (
          <div 
            key={p.id}
            onClick={() => !disabled && onSelect(p.id)}
            className={clsx(
              "group relative p-4 rounded-2xl border transition-all cursor-pointer overflow-hidden",
              isActive 
                ? "border-accent-primary bg-accent-primary/10 shadow-glow-cyan/5" 
                : "border-bg-border bg-bg-primary/20 hover:border-slate-700 opacity-70 hover:opacity-100",
              disabled && "cursor-not-allowed opacity-40"
            )}
          >
            <div className="flex items-center gap-3 relative z-10">
              <div className={clsx(
                "p-2 rounded-xl bg-bg-elevated border transition-all",
                isActive ? "border-accent-primary/30 text-accent-primary" : "border-bg-border text-slate-600 group-hover:text-slate-400"
              )}>
                <p.icon size={20} />
              </div>
              <div className="flex-1">
                 <div className="text-xs font-black uppercase tracking-widest text-slate-200">{p.name}</div>
                 <div className="flex items-center gap-1.5 mt-0.5">
                    <div className={clsx("w-1.5 h-1.5 rounded-full", isActive ? "bg-emerald-500 animate-pulse" : "bg-slate-700")} />
                    <span className="text-[9px] font-bold text-slate-500 uppercase">{isActive ? 'Connected' : 'Standby'}</span>
                 </div>
              </div>
              <ExternalLink size={12} className="text-slate-700 opacity-0 group-hover:opacity-100 transition-all" />
            </div>
            
            <p.icon 
              size={80} 
              className={clsx(
                "absolute -right-6 -bottom-6 opacity-[0.03] transition-all group-hover:scale-110",
                p.color
              )} 
            />
          </div>
        )
      })}
    </div>
  )
}
