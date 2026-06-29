import React from 'react'
import { DollarSign, Award, Target, Activity } from 'lucide-react'

export default function HunterHUD({ stats }) {
  return (
    <div className="grid grid-cols-2 lg:flex lg:items-center gap-4 lg:gap-6 px-4 lg:px-6 py-3 bg-bg-secondary/50 backdrop-blur-md border border-bg-border rounded-xl shadow-glow-cyan/5">
      {/* Estimated Earnings */}
      <div className="flex flex-col">
        <div className="flex items-center gap-2 text-accent-warn">
          <DollarSign size={14} className="drop-shadow-[0_0_5px_rgba(245,158,11,0.5)]" />
          <span className="text-[10px] uppercase tracking-widest font-bold opacity-70">Estimated Payout</span>
        </div>
        <div className="text-xl md:text-2xl font-mono font-bold text-accent-warn drop-shadow-[0_0_8px_rgba(245,158,11,0.3)]">
          ${(stats?.total_estimated_payout ?? 0).toLocaleString()}
        </div>
      </div>

      <div className="hidden lg:block w-px h-10 bg-bg-border" />

      {/* Reputation Points */}
      <div className="flex flex-col">
        <div className="flex items-center gap-2 text-accent-primary">
          <Award size={14} className="drop-shadow-[0_0_5px_rgba(0,217,255,0.5)]" />
          <span className="text-[10px] uppercase tracking-widest font-bold opacity-70">Reputation XP</span>
        </div>
        <div className="text-xl md:text-2xl font-mono font-bold text-accent-primary drop-shadow-[0_0_8px_rgba(0,217,255,0.3)]">
          {(stats?.total_reputation_points ?? 0).toLocaleString()}
        </div>
      </div>

      <div className="hidden lg:block w-px h-10 bg-bg-border" />

      {/* Active Hunts */}
      <div className="flex flex-col">
        <div className="flex items-center gap-2 text-accent-secondary">
          <Target size={14} className="drop-shadow-[0_0_5px_rgba(168,85,247,0.5)]" />
          <span className="text-[10px] uppercase tracking-widest font-bold opacity-70">Active Hunts</span>
        </div>
        <div className="text-xl md:text-2xl font-mono font-bold text-accent-secondary drop-shadow-[0_0_8px_rgba(168,85,247,0.3)]">
          {stats?.active_hunts ?? 0}
        </div>
      </div>

      <div className="hidden lg:block w-px h-10 bg-bg-border" />

      {/* Success Rate */}
      <div className="col-span-2 lg:flex-1 flex flex-col gap-1.5 min-w-[150px]">
        <div className="flex items-center justify-between text-accent-success">
          <div className="flex items-center gap-2">
            <Activity size={14} />
            <span className="text-[10px] uppercase tracking-widest font-bold opacity-70">Success Rate</span>
          </div>
          <span className="text-xs font-mono font-bold">{(stats?.success_rate * 100).toFixed(0)}%</span>
        </div>
        <div className="h-1.5 w-full bg-bg-elevated rounded-full overflow-hidden border border-bg-border">
          <div 
            className="h-full bg-accent-success shadow-[0_0_10px_rgba(16,185,129,0.5)] transition-all duration-500" 
            style={{ width: `${(stats?.success_rate ?? 0) * 100}%` }}
          />
        </div>
      </div>
    </div>
  )
}
