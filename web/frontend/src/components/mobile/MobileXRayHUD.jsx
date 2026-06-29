import React from 'react'
import { Smartphone, Search, Cpu, Database, Network, ShieldCheck } from 'lucide-react'
import clsx from 'clsx'

const LAYERS = [
  { id: 'binary',   label: 'Binary Extraction', icon: Database, color: 'text-blue-400' },
  { id: 'static',   label: 'Static Analysis',   icon: Search,   color: 'text-cyan-400' },
  { id: 'ai',       label: 'AI Reverse Eng',    icon: Cpu,      color: 'text-purple-400' },
  { id: 'secrets',  label: 'Secret Detection',  icon: ShieldCheck, color: 'text-red-400' },
  { id: 'network',  label: 'API Discovery',     icon: Network,  color: 'text-emerald-400' },
]

export default function MobileXRayHUD({ activePhase, progress }) {
  const currentIdx = LAYERS.findIndex(l => l.id === activePhase) || 0
  
  return (
    <div className="flex flex-col gap-6 p-6 glass-card border-dashed animate-in fade-in duration-700">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="relative">
            <Smartphone size={32} className="text-accent-primary animate-pulse" />
            <div className="absolute inset-0 bg-accent-primary/20 blur-xl rounded-full" />
          </div>
          <div>
            <h2 className="text-sm font-black uppercase tracking-widest text-slate-100">Cyber-Sentinel X-Ray</h2>
            <p className="text-[10px] text-slate-500 font-mono">SCAN_IN_PROGRESS :: {activePhase?.toUpperCase()}</p>
          </div>
        </div>
        <div className="text-right">
          <span className="text-xl font-black text-accent-primary font-mono">{progress}%</span>
          <p className="text-[9px] text-slate-600 font-bold uppercase">Pipeline Depth</p>
        </div>
      </div>

      <div className="grid grid-cols-5 gap-2">
        {LAYERS.map((layer, i) => {
          const isDone = i < currentIdx
          const isActive = i === currentIdx
          return (
            <div key={layer.id} className={clsx(
              "flex flex-col items-center gap-2 p-3 rounded-xl border transition-all duration-500",
              isDone ? "border-emerald-500/30 bg-emerald-500/5 opacity-60" :
              isActive ? "border-accent-primary bg-accent-primary/10 shadow-glow-cyan/5 scale-105 z-10" :
              "border-bg-border bg-bg-primary/20 opacity-40"
            )}>
              <layer.icon size={16} className={clsx(isDone ? 'text-emerald-400' : isActive ? layer.color : 'text-slate-600')} />
              <span className="text-[8px] font-black uppercase text-center leading-tight tracking-tighter h-6 flex items-center">
                {layer.label}
              </span>
              {isActive && (
                <div className="w-full h-0.5 bg-slate-800 rounded-full mt-1 overflow-hidden">
                   <div className="h-full bg-accent-primary animate-progress-fast" style={{ width: '100%' }} />
                </div>
              )}
            </div>
          )
        })}
      </div>

      <div className="bg-black/40 border border-slate-800 rounded-lg p-3 font-mono text-[10px] text-slate-400">
         <span className="text-emerald-500">[*]</span> System initializing forensic modules...<br/>
         <span className="text-cyan-500">[*]</span> Loading ToolRegistry: APKtool, JADX, TruffleHog, APKleaks...<br/>
         <span className="text-purple-500">[*]</span> AI Neural Engine synchronized for bytecode interpretation.<br/>
         <span className="animate-pulse">_</span>
      </div>
    </div>
  )
}
