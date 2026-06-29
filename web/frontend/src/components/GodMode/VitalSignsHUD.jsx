import React from 'react'
import { ShieldAlert, Target, Activity, Zap, Brain, User } from 'lucide-react'

export default function VitalSignsHUD({ findings = 0, assets = 0, coverage = 0, confidence = 0, avgEma = 0, activePersona = null }) {
  return (
    <div className="grid grid-cols-2 lg:flex lg:items-center gap-4 lg:gap-6 px-4 lg:px-6 py-3 bg-bg-secondary/50 backdrop-blur-md border border-bg-border rounded-xl shadow-glow-cyan/5">
      {/* Findings */}
      <div className="flex flex-col">
        <div className="flex items-center gap-2 text-accent-warn">
          <ShieldAlert size={14} className="drop-shadow-[0_0_5px_rgba(245,158,11,0.5)]" />
          <span className="text-[10px] uppercase tracking-widest font-bold opacity-70">Findings</span>
        </div>
        <div className="text-xl md:text-2xl font-mono font-bold text-accent-warn drop-shadow-[0_0_8px_rgba(245,158,11,0.3)]">
          {findings.toString().padStart(3, '0')}
        </div>
      </div>

      <div className="hidden lg:block w-px h-10 bg-bg-border" />

      {/* Assets */}
      <div className="flex flex-col">
        <div className="flex items-center gap-2 text-accent-primary">
          <Target size={14} className="drop-shadow-[0_0_5px_rgba(0,217,255,0.5)]" />
          <span className="text-[10px] uppercase tracking-widest font-bold opacity-70">Assets</span>
        </div>
        <div className="text-xl md:text-2xl font-mono font-bold text-accent-primary drop-shadow-[0_0_8px_rgba(0,217,255,0.3)]">
          {assets.toString().padStart(3, '0')}
        </div>
      </div>

      <div className="hidden lg:block w-px h-10 bg-bg-border" />

      {/* EMA / Velocity */}
      <div className="flex flex-col">
        <div className="flex items-center gap-2 text-accent-secondary">
          <Zap size={14} className="drop-shadow-[0_0_5px_rgba(168,85,247,0.5)]" />
          <span className="text-[10px] uppercase tracking-widest font-bold opacity-70">Velocity</span>
        </div>
        <div className="text-xl md:text-2xl font-mono font-bold text-accent-secondary drop-shadow-[0_0_8px_rgba(168,85,247,0.3)]">
          {avgEma.toFixed(2)}
        </div>
      </div>

      <div className="hidden lg:block w-px h-10 bg-bg-border" />

      {/* Identity */}
      <div className="flex flex-col min-w-[120px]">
        <div className="flex items-center gap-2 text-cyan-400">
          <User size={14} className="drop-shadow-[0_0_5px_rgba(0,217,255,0.5)]" />
          <span className="text-[10px] uppercase tracking-widest font-bold opacity-70">Identity</span>
        </div>
        <div className="text-sm font-bold text-slate-200 truncate max-w-[140px] font-mono tracking-tighter">
          {activePersona ? (activePersona.name || activePersona.session_id.slice(0, 8)).toUpperCase() : 'ANONYMOUS'}
        </div>
      </div>

      <div className="hidden lg:block w-px h-10 bg-bg-border" />

      {/* Coverage */}
      <div className="col-span-2 lg:flex-1 flex flex-col gap-1.5 min-w-[150px]">
        <div className="flex items-center justify-between text-accent-success">
          <div className="flex items-center gap-2">
            <Activity size={14} />
            <span className="text-[10px] uppercase tracking-widest font-bold opacity-70">Coverage</span>
          </div>
          <span className="text-xs font-mono font-bold">{coverage}%</span>
        </div>
        <div className="h-1.5 w-full bg-bg-elevated rounded-full overflow-hidden border border-bg-border">
          <div 
            className="h-full bg-accent-success shadow-[0_0_10px_rgba(16,185,129,0.5)] transition-all duration-500" 
            style={{ width: `${coverage}%` }}
          />
        </div>
      </div>

      <div className="hidden lg:block w-px h-10 bg-bg-border" />

      {/* Confidence */}
      <div className="flex flex-col min-w-[100px]">
        <div className="flex items-center gap-2 text-accent-purple">
          <Brain size={14} />
          <span className="text-[10px] uppercase tracking-widest font-bold opacity-70">Confidence</span>
        </div>
        <div className="flex items-end gap-1">
          <span className="text-xl md:text-2xl font-mono font-bold text-accent-purple leading-none">
            {confidence.toFixed(2)}
          </span>
          <span className="text-[10px] text-slate-500 mb-0.5 font-mono">/1.0</span>
        </div>
      </div>
    </div>
  )
}
